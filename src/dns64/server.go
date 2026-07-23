package dns64

import (
	"context"
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/gologme/log"
	"github.com/miekg/dns"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/adapters/gonet"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv6"
	"gvisor.dev/gvisor/pkg/tcpip/stack"

	"github.com/yggdrasil-network/ydn64/src/config"
	"github.com/yggdrasil-network/ydn64/src/netstack"
)

// Service is the embedded DNS64 server.
type Service struct {
	proxy       *proxy
	listenAddr  string
	allowedNets []*net.IPNet
	ns          *netstack.YggdrasilNetstack
}

// NewService creates a DNS64 Service from configuration.
func NewService(cfg config.DNS64Config, allowedSources []string, ns *netstack.YggdrasilNetstack) (*Service, error) {
	ia, err := parseIA(cfg.InvalidAddress)
	if err != nil {
		return nil, fmt.Errorf("dns64: %w", err)
	}

	zones := buildZones(cfg.Zones)

	expDur := time.Duration(cfg.CacheExp) * time.Second
	purgeDur := time.Duration(cfg.CachePurge) * time.Second

	p := &proxy{
		cache:          newCache(expDur, purgeDur),
		zones:          zones,
		defaultForward: cfg.Default,
		ia:             ia,
	}

	var allowed []*net.IPNet
	for _, src := range allowedSources {
		if ip := net.ParseIP(src); ip != nil {
			allowed = append(allowed, &net.IPNet{IP: ip, Mask: net.CIDRMask(128, 128)})
		} else if _, cidr, err := net.ParseCIDR(src); err == nil {
			allowed = append(allowed, cidr)
		}
	}

	return &Service{
		proxy:       p,
		listenAddr:  cfg.Listen,
		allowedNets: allowed,
		ns:          ns,
	}, nil
}

// isAllowed reports whether srcIP is in one of the configured allowed-source ranges.
func (s *Service) isAllowed(ip net.IP) bool {
	for _, n := range s.allowedNets {
		if n.Contains(ip) {
			return true
		}
	}
	return false
}

// Start binds a UDP socket on the gVisor stack at the configured listen
// address and begins serving DNS64 queries.
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
	conn, err := gonetListenUDP(s.ns.Stack(), localUDPAddr)
	if err != nil {
		return fmt.Errorf("dns64: binding UDP on %s: %w", s.listenAddr, err)
	}

	logger.Printf("DNS64 started  listen=%s  sources=%v", s.listenAddr, s.allowedNets)

	go func() {
		<-ctx.Done()
		conn.Close()
	}()

	go s.serveUDP(conn, logger)
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
				logger.Debugf("DNS64: pack error for %s: %v", req.Question, err)
				return
			}
			if _, err := conn.WriteTo(out, from); err != nil {
				logger.Debugf("DNS64: write error to %s: %v", from, err)
			}
		}(pkt, addr)
	}
}
