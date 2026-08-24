package nat64

import (
	"io"
	"net"
	"strconv"
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

	// Extract embedded IPv4 from the last 4 bytes of the pool6 destination.
	ipv4 := net.IP(dstSlice[12:16])
	if s.isIgnoredDst(ipv4) {
		req.Complete(true)
		return
	}
	dstAddr := net.JoinHostPort(ipv4.String(), strconv.Itoa(int(id.LocalPort)))

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

		logger.Debugf("NAT64 TCP %s → %s", srcIP, dstAddr)
		proxyTCP(yggConn, conn4)
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
