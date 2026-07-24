package dns64

import (
	"context"
	"fmt"
	"net"
	"strings"
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

// dnsTCPIdleTimeout bounds how long a DNS-over-TCP connection may sit idle
// between queries before the server closes it — the same defense against
// resource-exhausting idle connections that mature DNS servers (BIND,
// Unbound, etc.) apply to their own TCP listeners.
const dnsTCPIdleTimeout = 10 * time.Second

// Service is the embedded DNS64 server.
type Service struct {
	proxy       *proxy
	listenAddr  string
	allowedNets atomic.Pointer[[]*net.IPNet]
	ns          *netstack.YggdrasilNetstack
}

// NewService creates a DNS64 Service from configuration.
func NewService(cfg config.DNS64Config, allowedSources []string, ns *netstack.YggdrasilNetstack) (*Service, error) {
	ia, err := parseIA(cfg.InvalidAddress)
	if err != nil {
		return nil, fmt.Errorf("dns64: %w", err)
	}

	expDur := time.Duration(cfg.CacheExp) * time.Second
	purgeDur := time.Duration(cfg.CachePurge) * time.Second

	p := &proxy{
		cache: newCache(expDur, purgeDur),
		ns:    ns,
	}
	p.reload(cfg.Default, ia, buildZones(cfg.Zones))

	allowed := config.ParseAllowedNets(allowedSources)
	s := &Service{
		proxy:      p,
		listenAddr: cfg.Listen,
		ns:         ns,
	}
	s.allowedNets.Store(&allowed)
	return s, nil
}

// Reload atomically replaces AllowedSources, the DNS64 zone table/default
// forwarder/InvalidAddress policy, and the cache's expiration/purge
// intervals, e.g. in response to a SIGHUP-triggered config reload. Safe to
// call concurrently with in-flight queries. Dns64Listen and Dns64Enable are
// not reloadable and require a process restart to change.
func (s *Service) Reload(cfg config.DNS64Config, allowedSources []string) error {
	ia, err := parseIA(cfg.InvalidAddress)
	if err != nil {
		return fmt.Errorf("dns64: %w", err)
	}
	allowed := config.ParseAllowedNets(allowedSources)
	s.allowedNets.Store(&allowed)
	s.proxy.reload(cfg.Default, ia, buildZones(cfg.Zones))
	s.proxy.cache.Reload(time.Duration(cfg.CacheExp)*time.Second, time.Duration(cfg.CachePurge)*time.Second)
	return nil
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
	port := 53
	if portStr != "" {
		if _, err := fmt.Sscan(portStr, &port); err != nil {
			return fmt.Errorf("dns64 listen port %q: %w", portStr, err)
		}
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
			continue
		}
		logger.Debugf("DNS64: query from %s (%d bytes)", addr, n)

		pkt := make([]byte, n)
		copy(pkt, buf[:n])
		go func(data []byte, from net.Addr) {
			req := new(dns.Msg)
			if err := req.Unpack(data); err != nil {
				logger.Debugf("DNS64: unpack error from %s: %v", from, err)
				return
			}
			resp := s.proxy.handle(req)
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

		go s.serveTCPConn(conn, logger)
	}
}

// serveTCPConn serves queries for a single DNS-over-TCP connection one at a
// time (RFC 7766 permits, but does not require, pipelining), closing the
// connection once dnsTCPIdleTimeout elapses without a new query.
func (s *Service) serveTCPConn(conn net.Conn, logger *log.Logger) {
	defer conn.Close()
	dc := &dns.Conn{Conn: conn}
	for {
		conn.SetReadDeadline(time.Now().Add(dnsTCPIdleTimeout))
		req, err := dc.ReadMsg()
		if err != nil {
			return
		}
		logger.Debugf("DNS64: TCP query from %s", conn.RemoteAddr())

		resp := s.proxy.handle(req)
		if err := dc.WriteMsg(resp); err != nil {
			logger.Debugf("DNS64: TCP write error to %s: %v", conn.RemoteAddr(), err)
			return
		}
	}
}
