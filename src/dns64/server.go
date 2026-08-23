package dns64

import (
	"context"
	"fmt"
	"net"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/gologme/log"
	"github.com/miekg/dns"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/adapters/gonet"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv6"
	"gvisor.dev/gvisor/pkg/tcpip/stack"

	"github.com/DrewCyber/ydn64/src/config"
	"github.com/DrewCyber/ydn64/src/netstack"
)

const (
	// dnsTCPIdleTimeout bounds how long a DNS-over-TCP connection may sit idle
	// between queries before the server closes it — the same defense against
	// resource-exhausting idle connections that mature DNS servers (BIND,
	// Unbound, etc.) apply to their own TCP listeners.
	dnsTCPIdleTimeout = 10 * time.Second

	// legacyMaxMsgSize is the largest DNS-over-UDP message a server may
	// assume every client accepts without EDNS(0) negotiation; larger
	// responses must set TC and be retried over TCP
	// (RFC 1035 §2.3.4, RFC 6891 §6.2.5).
	legacyMaxMsgSize = 512

	// maxUDPSize caps the negotiated UDP payload size even when clients
	// advertise larger buffers — balances respecting client preferences
	// against fragmentation risks in overlay networks. Matches BIND/Unbound
	// defaults.
	maxUDPSize = 4096
)

// negotiateUDPSize returns the maximum UDP message size ydn64 may use when
// answering a query carrying the given client OPT record (nil for classic
// queries), per RFC 6891 §6.2.5:
//
//   - no OPT: legacyMaxMsgSize (512). Assuming 1232 for such clients made
//     ydn64 emit untruncated datagrams past the classic limit, which stubs
//     without EDNS support have no obligation to accept; 512+TC is the
//     interoperable choice.
//   - advertised sizes below 512 are treated as 512 ("values lower than
//     512 MUST be treated as equal to 512") rather than honoured literally.
//   - otherwise the advertisement, clamped at maxUDPSize.
func negotiateUDPSize(clientOPT *dns.OPT) int {
	size := legacyMaxMsgSize
	if clientOPT != nil {
		if s := int(clientOPT.UDPSize()); s > size {
			size = s
		}
		if size > maxUDPSize {
			size = maxUDPSize
		}
	}
	return size
}

// Service is the embedded DNS64 server.
type Service struct {
	proxy       *proxy
	listenAddr  string
	allowedNets atomic.Pointer[[]*net.IPNet]
	ns          *netstack.YggdrasilNetstack
	// lastDenyReply rate-limits REFUSED answers to denied sources.
	lastDenyReply atomic.Int64
	// wg tracks in-flight query work for graceful drain (see Drain).
	wg sync.WaitGroup
	// querySem bounds concurrent in-flight queries (UDP query goroutines +
	// DNS-over-TCP connections). When full, new work is shed immediately —
	// UDP queries get SERVFAIL, TCP connections are closed — rather than
	// queued. Sized at construction; Dns64MaxConcurrentQueries requires a
	// restart to change.
	querySem chan struct{}
}

// NewService creates a DNS64 Service from configuration.
func NewService(cfg config.DNS64Config, allowedSources []string, ignoredDstSubnets []string, ns *netstack.YggdrasilNetstack) (*Service, error) {
	ia, err := parseIA(cfg.InvalidAddress)
	if err != nil {
		return nil, fmt.Errorf("dns64: %w", err)
	}

	expDur := time.Duration(cfg.CacheExp) * time.Second
	purgeDur := time.Duration(cfg.CachePurge) * time.Second

	p := &proxy{
		cache: newCache(expDur, purgeDur, cfg.MaxCacheEntries),
		ns:    ns,
	}
	p.reload(cfg.Default, ia, buildZones(cfg.Zones), config.ParseIPNets(ignoredDstSubnets))

	allowed := config.ParseAllowedNets(allowedSources)
	s := &Service{
		proxy:      p,
		listenAddr: cfg.Listen,
		ns:         ns,
	}
	if cfg.MaxQueries > 0 {
		s.querySem = make(chan struct{}, cfg.MaxQueries)
	}
	s.allowedNets.Store(&allowed)
	return s, nil
}

// Reload atomically replaces AllowedSources, IgnoredDstSubnets, the DNS64 zone table/default
// forwarder/InvalidAddress policy, and the cache's expiration/purge
// intervals, e.g. in response to a SIGHUP-triggered config reload. Safe to
// call concurrently with in-flight queries. Dns64Listen and Dns64Enable are
// not reloadable and require a process restart to change.
func (s *Service) Reload(cfg config.DNS64Config, allowedSources []string, ignoredDstSubnets []string) error {
	ia, err := parseIA(cfg.InvalidAddress)
	if err != nil {
		return fmt.Errorf("dns64: %w", err)
	}
	allowed := config.ParseAllowedNets(allowedSources)
	s.allowedNets.Store(&allowed)
	s.proxy.reload(cfg.Default, ia, buildZones(cfg.Zones), config.ParseIPNets(ignoredDstSubnets))
	s.proxy.cache.Reload(time.Duration(cfg.CacheExp)*time.Second, time.Duration(cfg.CachePurge)*time.Second, cfg.MaxCacheEntries)
	return nil
}

// tryAcquireQuery reports whether a new query slot is available. Always true
// when no limit is configured.
func (s *Service) tryAcquireQuery() bool {
	if s.querySem == nil {
		return true
	}
	select {
	case s.querySem <- struct{}{}:
		return true
	default:
		return false
	}
}

// releaseQuery returns a previously acquired slot.
func (s *Service) releaseQuery() {
	if s.querySem != nil {
		<-s.querySem
	}
}

// shedResponse builds the SERVFAIL answer sent when a UDP query is shed at
// the concurrency limit — an immediate, cheap failure beats silence (client
// timeout + retry storm).
func shedResponse(req *dns.Msg) *dns.Msg {
	resp := new(dns.Msg)
	resp.Id = req.Id
	resp.Question = req.Question
	resp.Response = true
	resp.Rcode = dns.RcodeServerFailure
	return resp
}

// refusedResponse builds the REFUSED answer sent (rate-limited) to sources
// excluded by AllowedSources, so misconfigured clients fail over to another
// resolver immediately instead of waiting out their timeout.
func refusedResponse(req *dns.Msg) *dns.Msg {
	resp := new(dns.Msg)
	resp.Id = req.Id
	resp.Question = req.Question
	resp.Response = true
	resp.Rcode = dns.RcodeRefused
	return resp
}

// denyReplyInterval is the minimum spacing between REFUSED answers to denied
// sources; further denied traffic within the window is dropped silently so
// denials cannot be amplified into an unbounded reply stream.
const denyReplyInterval = 500 * time.Millisecond

// udpReplyWriter is the slice of *gonet.UDPConn the denial path needs;
// an interface so tests can record replies without a live stack.
type udpReplyWriter interface {
	WriteTo(b []byte, from net.Addr) (int, error)
}

// maybeRefuseDenied answers one denied UDP query with REFUSED unless a
// refusal went out too recently. Denied TCP connections are simply closed:
// no framed query exists yet to echo identifiers from.
func (s *Service) maybeRefuseDenied(conn udpReplyWriter, from net.Addr, data []byte) {
	now := time.Now().UnixNano()
	last := s.lastDenyReply.Load()
	if last != 0 && now-last < int64(denyReplyInterval) {
		return
	}
	if !s.lastDenyReply.CompareAndSwap(last, now) {
		return
	}
	req := new(dns.Msg)
	if err := req.Unpack(data); err != nil {
		return // cannot echo id/question — drop silently
	}
	if out, err := refusedResponse(req).Pack(); err == nil {
		if _, err := conn.WriteTo(out, from); err != nil {
			// Best effort by design; the next denial retries after the window.
			_ = err
		}
	}
}

// isAllowed reports whether srcIP is in one of the configured allowed-source ranges.
func (s *Service) isAllowed(ip net.IP) bool {
	for _, n := range *s.allowedNets.Load() {
		if n.Contains(ip) {
			return true
		}
	}
	return false
}

// Start binds both a UDP and a TCP socket on the gVisor stack at the
// configured listen address and begins serving DNS64 queries on both —
// mirroring how mature DNS servers listen on both transports by default:
// UDP for ordinary queries, TCP for large/truncated responses and for any
// query a client sends over TCP outright (e.g. `dig`'s own default
// transport for ANY queries).
func (s *Service) Start(ctx context.Context, logger *log.Logger) error {
	host, portStr, err := net.SplitHostPort(s.listenAddr)
	if err != nil {
		return fmt.Errorf("dns64 listen addr %q: %w", s.listenAddr, err)
	}
	ip := net.ParseIP(host)
	if ip == nil {
		return fmt.Errorf("dns64 listen addr: invalid IP %q", host)
	}
	port, err := parseListenPort(portStr)
	if err != nil {
		return fmt.Errorf("dns64 listen addr %q: %w", s.listenAddr, err)
	}

	// Register the listen IP as a local address on NIC1 so gVisor will
	// accept packets destined to it (required even in promiscuous mode for
	// outbound replies to have a valid source address).
	ipv6Addr := ip.To16()
	if tcpErr := s.ns.Stack().AddProtocolAddress(1, tcpip.ProtocolAddress{
		Protocol:          ipv6.ProtocolNumber,
		AddressWithPrefix: tcpip.AddrFromSlice(ipv6Addr).WithPrefix(),
	}, stack.AddressProperties{}); tcpErr != nil {
		// "already exists" / "duplicate address" is fine — the node IP is
		// registered in Phase 1; subnet addresses may also be pre-registered.
		msg := strings.ToLower(tcpErr.String())
		if !strings.Contains(msg, "already exists") && !strings.Contains(msg, "duplicate") {
			return fmt.Errorf("dns64: registering listen address: %s", tcpErr.String())
		}
	}

	localUDPAddr := &net.UDPAddr{IP: ipv6Addr, Port: port}
	udpConn, err := gonetListenUDP(s.ns.Stack(), localUDPAddr)
	if err != nil {
		return fmt.Errorf("dns64: binding UDP on %s: %w", s.listenAddr, err)
	}

	tcpListener, err := gonetListenTCP(s.ns.Stack(), ipv6Addr, port)
	if err != nil {
		udpConn.Close()
		return fmt.Errorf("dns64: binding TCP on %s: %w", s.listenAddr, err)
	}

	logger.Printf("DNS64 started  listen=%s (udp+tcp)  sources=%v", s.listenAddr, *s.allowedNets.Load())

	go func() {
		<-ctx.Done()
		udpConn.Close()
		tcpListener.Close()
	}()

	go s.serveUDP(udpConn, logger)
	go s.serveTCP(tcpListener, logger)
	return nil
}

// parseListenPort parses the port part of Dns64Listen ("" → 53). Unlike
// fmt.Sscan, strconv rejects signs, whitespace and out-of-range values
// instead of silently truncating them into a different port.
func parseListenPort(s string) (int, error) {
	if s == "" {
		return 53, nil
	}
	p, err := strconv.ParseUint(s, 10, 16)
	if err != nil || p == 0 {
		return 0, fmt.Errorf("invalid port %q (want 1-65535)", s)
	}
	return int(p), nil
}

// gonetListenUDP opens a UDP socket on the gVisor stack bound to addr.
func gonetListenUDP(st *stack.Stack, addr *net.UDPAddr) (*gonet.UDPConn, error) {
	fa := tcpip.FullAddress{
		NIC:  1,
		Addr: tcpip.AddrFromSlice(addr.IP.To16()),
		Port: uint16(addr.Port),
	}
	return gonet.DialUDP(st, &fa, nil, ipv6.ProtocolNumber)
}

// gonetListenTCP opens a TCP listening socket on the gVisor stack bound to
// ip:port.
func gonetListenTCP(st *stack.Stack, ip net.IP, port int) (*gonet.TCPListener, error) {
	fa := tcpip.FullAddress{
		NIC:  1,
		Addr: tcpip.AddrFromSlice(ip.To16()),
		Port: uint16(port),
	}
	return gonet.ListenTCP(st, fa, ipv6.ProtocolNumber)
}

// serveUDP reads DNS queries from conn and dispatches them in goroutines.
func (s *Service) serveUDP(conn *gonet.UDPConn, logger *log.Logger) {
	buf := make([]byte, dns.MaxMsgSize)
	for {
		n, addr, err := conn.ReadFrom(buf)
		if err != nil {
			// conn was closed (ctx cancelled) or fatal error.
			return
		}

		// Source filter.
		var srcIP net.IP
		if udpAddr, ok := addr.(*net.UDPAddr); ok {
			srcIP = udpAddr.IP
		}
		if srcIP == nil || !s.isAllowed(srcIP) {
			logger.Debugf("DNS64: denied query from %s (not in AllowedSources)", addr)
			s.maybeRefuseDenied(conn, addr, buf[:n])
			continue
		}
		logger.Debugf("DNS64: query from %s (%d bytes)", addr, n)

		pkt := make([]byte, n)
		copy(pkt, buf[:n])
		s.wg.Add(1)
		go func(data []byte, from net.Addr) {
			defer s.wg.Done()
			req := new(dns.Msg)
			if err := req.Unpack(data); err != nil {
				logger.Debugf("DNS64: unpack error from %s: %v", from, err)
				return
			}

			if !s.tryAcquireQuery() {
				logger.Debugf("DNS64: shedding query from %s (concurrency limit)", from)
				if out, err := shedResponse(req).Pack(); err == nil {
					_, _ = conn.WriteTo(out, from)
				}
				return
			}
			defer s.releaseQuery()

			clientOPT := req.IsEdns0()
			udpSize := negotiateUDPSize(clientOPT)

			resp := s.proxy.handle(req)

			if clientOPT != nil {
				filteredExtra := resp.Extra[:0]
				for _, rr := range resp.Extra {
					if rr.Header().Rrtype != dns.TypeOPT {
						filteredExtra = append(filteredExtra, rr)
					}
				}
				resp.Extra = filteredExtra
				resp.SetEdns0(maxUDPSize, clientOPT.Do())
			}

			if resp.Len() > udpSize {
				resp.Truncate(udpSize)
				logger.Debugf("DNS64: truncated response to %s (%d > %d bytes)", from, resp.Len(), udpSize)
			}

			out, err := resp.Pack()
			if err != nil {
				logger.Debugf("DNS64: pack error for %v: %v", req.Question, err)
				return
			}
			if _, err := conn.WriteTo(out, from); err != nil {
				logger.Debugf("DNS64: write error to %s: %v", from, err)
			}
		}(pkt, addr)
	}
}

// serveTCP accepts DNS-over-TCP connections and dispatches each to its own
// goroutine. Source filtering mirrors serveUDP; per-message framing (the
// 2-byte length prefix required by RFC 1035 §4.2.2) is handled by wrapping
// each connection in a dns.Conn.
func (s *Service) serveTCP(listener *gonet.TCPListener, logger *log.Logger) {
	for {
		conn, err := listener.Accept()
		if err != nil {
			// listener was closed (ctx cancelled) or fatal error.
			return
		}

		var srcIP net.IP
		if tcpAddr, ok := conn.RemoteAddr().(*net.TCPAddr); ok {
			srcIP = tcpAddr.IP
		}
		if srcIP == nil || !s.isAllowed(srcIP) {
			logger.Debugf("DNS64: denied TCP connection from %s (not in AllowedSources)", conn.RemoteAddr())
			conn.Close()
			continue
		}
		if !s.tryAcquireQuery() {
			logger.Debugf("DNS64: shedding TCP connection from %s (concurrency limit)", conn.RemoteAddr())
			conn.Close()
			continue
		}

		s.wg.Add(1)
		go func() {
			defer s.wg.Done()
			defer s.releaseQuery()
			s.serveTCPConn(conn, logger)
		}()
	}
}

// serveTCPConn serves queries for a single DNS-over-TCP connection one at a
// time (RFC 7766 permits, but does not require, pipelining), closing the
// connection once dnsTCPIdleTimeout elapses without a new query.
func (s *Service) serveTCPConn(conn net.Conn, logger *log.Logger) {
	defer conn.Close()
	dc := &dns.Conn{Conn: conn}
	for {
		_ = conn.SetReadDeadline(time.Now().Add(dnsTCPIdleTimeout))
		req, err := dc.ReadMsg()
		if err != nil {
			return
		}
		logger.Debugf("DNS64: TCP query from %s", conn.RemoteAddr())

		resp := s.proxy.handle(req)
		_ = conn.SetWriteDeadline(time.Now().Add(dnsTCPIdleTimeout))
		if err := dc.WriteMsg(resp); err != nil {
			logger.Debugf("DNS64: TCP write error to %s: %v", conn.RemoteAddr(), err)
			return
		}
	}
}

// Drain waits for all in-flight query work (UDP query goroutines and
// DNS-over-TCP connection handlers) to finish, or until d elapses — used
// during shutdown so cancellation doesn't cut answers mid-flight.
func (s *Service) Drain(d time.Duration) {
	done := make(chan struct{})
	go func() {
		s.wg.Wait()
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(d):
	}
}
