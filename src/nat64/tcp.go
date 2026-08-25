package nat64

import (
	"fmt"
	"io"
	"net"
	"strconv"
	"sync/atomic"
	"time"

	"github.com/gologme/log"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/adapters/gonet"
	"gvisor.dev/gvisor/pkg/tcpip/transport/tcp"
	"gvisor.dev/gvisor/pkg/waiter"
)

// NAT64 TCP keepalive tuning for the gVisor (Yggdrasil-facing) leg of proxied
// connections. Without keepalives, a peer that vanishes silently (crash,
// partition, radio loss) mid-idle leaves the endpoint lingering until gVisor's
// very long internal retransmit timeouts give up; with them, a dead peer is
// detected in roughly:
//
//	tcpKeepaliveIdle + tcpKeepaliveCount × tcpKeepaliveInterval
//	= 75s            + 9 × 10s                        ≈ 165s
//
// which is aggressive enough to reap dead Yggdrasil peers without risking
// false positives on the high-latency paths Yggdrasil routinely traverses.
//
// tcpKeepaliveUserTimeout additionally bounds retransmission stalls on
// *active* transfers (data outstanding but unacknowledged): if nothing is
// ACKed for that long the connection is aborted. It is deliberately ≥ the
// keepalive budget so an idle-but-alive connection probed by keepalives can
// never be aborted by the user timeout — the two knobs cover disjoint failure
// modes (idle silence vs. stalled data) and the larger value only ever fires
// after the keepalive machinery has already had ample opportunity.
const (
	tcpKeepaliveIdle        = 75 * time.Second
	tcpKeepaliveInterval    = 10 * time.Second
	tcpKeepaliveCount       = 9
	tcpKeepaliveUserTimeout = 5 * time.Minute
)

// applyTCPKeepalive enables and tunes TCP keepalives plus the user timeout on
// a freshly created gVisor endpoint (see the constant docs above). Failures
// are non-fatal: the connection is still proxied, just without dead-peer
// detection.
func applyTCPKeepalive(ep tcpip.Endpoint) tcpip.Error {
	ep.SocketOptions().SetKeepAlive(true)

	idle := tcpip.KeepaliveIdleOption(tcpKeepaliveIdle)
	if err := ep.SetSockOpt(&idle); err != nil {
		return err
	}

	interval := tcpip.KeepaliveIntervalOption(tcpKeepaliveInterval)
	if err := ep.SetSockOpt(&interval); err != nil {
		return err
	}

	if err := ep.SetSockOptInt(tcpip.KeepaliveCountOption, tcpKeepaliveCount); err != nil {
		return err
	}

	userTimeout := tcpip.TCPUserTimeoutOption(tcpKeepaliveUserTimeout)
	return ep.SetSockOpt(&userTimeout)
}

// applyTCPOSKeepalive mirrors applyTCPKeepalive's dead-peer budget on the
// OS-dialled IPv4 leg. Without it the socket runs system defaults (Go enables
// keepalives at a 15 s idle, but interval/count stay OS-dependent — roughly
// 11+ minutes on Linux), so an IPv4 peer that vanishes silently mid-idle
// would pin its global and per-source slots until Nat64TcpTimeout (2h04m at
// the default) instead of being detected in about:
//
//	tcpKeepaliveIdle + tcpKeepaliveCount × tcpKeepaliveInterval ≈ 165s
//
// net.KeepAliveConfig has no user-timeout knob, so the stalled-transfer
// coverage the gVisor leg gets from TCPUserTimeoutOption has no stdlib
// equivalent here; Count-based probing covers the idle-dead-peer case this
// exists for. Failures are non-fatal, matching applyTCPKeepalive.
func applyTCPOSKeepalive(conn *net.TCPConn) error {
	return conn.SetKeepAliveConfig(net.KeepAliveConfig{
		Enable:   true,
		Idle:     tcpKeepaliveIdle,
		Interval: tcpKeepaliveInterval,
		Count:    tcpKeepaliveCount,
	})
}

// tcpPair tracks one proxied NAT64 TCP connection (both legs) for idle
// expiry (RFC 5382 REQ-5). lastSeenNs is refreshed by every successful
// payload transfer in either direction. Pure ACKs — including the TCP
// keepalive probes each leg already runs — are consumed inside their own
// stacks and never reach the proxy goroutines' reads, so they deliberately
// do not count as activity; only real payload does. This mirrors a classic
// NAT mapping timer and prevents a chatty server's keepalives from pinning
// translator slots forever.
type tcpPair struct {
	a, b     net.Conn // a = Yggdrasil (gVisor) leg, b = IPv4 leg
	label    string   // "src → dst" for reap logging
	lastSeen atomic.Int64
}

func (p *tcpPair) touch() { p.lastSeen.Store(time.Now().UnixNano()) }

// activityConn wraps one leg of a tcpPair, refreshing the pair's shared
// last-seen stamp on every successful Read/Write.
type activityConn struct {
	net.Conn
	pair *tcpPair
}

func (c *activityConn) Read(b []byte) (int, error) {
	n, err := c.Conn.Read(b)
	if n > 0 {
		c.pair.touch()
	}
	return n, err
}

func (c *activityConn) Write(b []byte) (int, error) {
	n, err := c.Conn.Write(b)
	if n > 0 {
		c.pair.touch()
	}
	return n, err
}

// trackTCP registers a freshly dialled proxied connection for idle expiry
// and returns its pair handle.
func (s *Service) trackTCP(a, b net.Conn, label string) *tcpPair {
	pair := &tcpPair{a: a, b: b, label: label}
	pair.touch()
	s.tcpConns.Store(pair, pair)
	return pair
}

// untrackTCP deregisters a proxied connection whose proxy goroutine has
// finished (both legs are closed by its defers).
func (s *Service) untrackTCP(pair *tcpPair) { s.tcpConns.Delete(pair) }

// trackedTCPCount reports how many proxied TCP connections are currently
// tracked for idle expiry.
func (s *Service) trackedTCPCount() int {
	n := 0
	s.tcpConns.Range(func(_, _ any) bool {
		n++
		return true
	})
	return n
}

// reapIdleTCP closes both legs of every tracked connection that has been
// idle past the configured Nat64TcpTimeout (RFC 5382 REQ-5). Closing the
// legs makes the connection's io.Copy loops return promptly; its deferred
// cleanup then unregisters the pair and releases the global/per-source
// slots it was holding.
func (s *Service) reapIdleTCP() {
	t := s.tcpTimeout()
	if t <= 0 {
		return
	}
	cutoff := time.Now().Add(-t).UnixNano()
	lg := s.serviceLogger()
	s.tcpConns.Range(func(k, v any) bool {
		pair := k.(*tcpPair)
		if pair.lastSeen.Load() < cutoff {
			if lg != nil {
				lg.Debugf("NAT64 TCP reaping idle %s", pair.label)
			}
			pair.a.Close()
			pair.b.Close()
		}
		return true
	})
}

// handleTCP is called by tcp.NewForwarder for every inbound TCP SYN.
// It runs synchronously inside gVisor's packet processing path, so
// CreateEndpoint must complete here; the dial and proxy run in a goroutine.
func (s *Service) handleTCP(req *tcp.ForwarderRequest, logger *log.Logger) {
	id := req.ID()

	// Only serve pool6 destinations; RST everything else.
	dstSlice := id.LocalAddress.AsSlice()
	dstIP := net.IP(dstSlice)
	if !s.pool6Net.Contains(dstIP) {
		req.Complete(true)
		return
	}

	// Source filter.
	srcSlice := id.RemoteAddress.AsSlice()
	srcIP := net.IP(srcSlice)
	// Source address must NOT be in the pool6 subnet (RFC 6146 §3.5 / §5.4).
	if s.pool6Net.Contains(srcIP) {
		req.Complete(true)
		return
	}
	if !s.isAllowed(srcIP) {
		req.Complete(true)
		return
	}

	// Extract embedded IPv4 per the RFC 6052 §2.2 layout (length-aware;
	// non-canonical addresses — dirty u octet or suffix — are refused).
	ipv4, ok := s.pref64.Extract(dstIP)
	if !ok {
		req.Complete(true)
		return
	}
	if s.isIgnoredDst(net.IP(ipv4[:])) {
		req.Complete(true)
		return
	}
	dstAddr := net.JoinHostPort(net.IP(ipv4[:]).String(), strconv.Itoa(int(id.LocalPort)))

	// Shed, don't queue: when a limit is reached, refuse the new flow
	// immediately (Complete(true) aborts the handshake → RST) instead of
	// letting unbounded proxy goroutines pile up. The per-source ceiling
	// (RFC 6146 §5.3) is checked first so one peer cannot consume the
	// global pool; unlike UDP, TCP accounting is synchronous end-to-end.
	var srcKey [16]byte
	copy(srcKey[:], srcIP.To16())
	if l := s.perSrcTCPLimit(); l > 0 && s.srcCounts.count(srcKey, srcTCP) >= l {
		logger.Debugf("NAT64 TCP shedding %s → %s (per-source connection limit %d)", srcIP, dstAddr, l)
		req.Complete(true)
		return
	}
	if !s.tryAcquireTCP() {
		logger.Debugf("NAT64 TCP shedding %s → %s (connection limit)", srcIP, dstAddr)
		req.Complete(true)
		return
	}
	s.srcCounts.add(srcKey, srcTCP)

	// CreateEndpoint completes the three-way handshake synchronously.
	var wq waiter.Queue
	ep, tcpErr := req.CreateEndpoint(&wq)
	if tcpErr != nil {
		s.releaseTCP()
		s.srcCounts.remove(srcKey, srcTCP)
		req.Complete(true)
		return
	}
	req.Complete(false)

	if err := applyTCPKeepalive(ep); err != nil {
		logger.Debugf("NAT64 TCP keepalive setup for %s: %v", dstAddr, err)
	}

	yggConn := gonet.NewTCPConn(&wq, ep)

	s.drainWG.Add(1)
	go func() {
		defer s.drainWG.Done()
		defer s.srcCounts.remove(srcKey, srcTCP)
		defer s.releaseTCP()
		defer yggConn.Close()

		conn4, err := net.DialTimeout("tcp4", dstAddr, 10*time.Second)
		if err != nil {
			logger.Debugf("NAT64 TCP dial %s: %v", dstAddr, err)
			return
		}
		defer conn4.Close()
		if tcp4, ok := conn4.(*net.TCPConn); ok {
			if err := applyTCPOSKeepalive(tcp4); err != nil {
				logger.Debugf("NAT64 TCP keepalive setup for %s (IPv4 leg): %v", dstAddr, err)
			}
		}

		pair := s.trackTCP(yggConn, conn4, fmt.Sprintf("%s → %s", srcIP, dstAddr))
		defer s.untrackTCP(pair)

		logger.Debugf("NAT64 TCP %s → %s", srcIP, dstAddr)
		proxyTCP(&activityConn{Conn: yggConn, pair: pair}, &activityConn{Conn: conn4, pair: pair})
	}()
}

// proxyTCP copies data bidirectionally between two net.Conn until both
// directions reach EOF.  Each half-close triggers closure of that direction.
func proxyTCP(a, b net.Conn) {
	done := make(chan struct{}, 2)
	cp := func(dst, src net.Conn) {
		io.Copy(dst, src) //nolint:errcheck
		dst.Close()
		done <- struct{}{}
	}
	go cp(a, b)
	go cp(b, a)
	<-done
	<-done
}
