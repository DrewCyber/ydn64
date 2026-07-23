package nat64

import (
	"context"
	"fmt"
	"net"
	"sync"
	"time"

	"github.com/gologme/log"
	"gvisor.dev/gvisor/pkg/tcpip/transport/tcp"

	"github.com/yggdrasil-network/ydn64/src/config"
	"github.com/yggdrasil-network/ydn64/src/netstack"
)

// Service implements TUN-less NAT64: it intercepts IPv6 packets addressed to
// the pool6::/96 subnet and proxies them to real IPv4 destinations.
//
//   TCP — handled via gVisor's tcp.NewForwarder (promiscuous mode is enabled
//          on the gVisor stack so it accepts pool6::IPv4 destinations).
//   UDP — intercepted at NIC level before gVisor, replies are raw IPv6 packets
//          written directly to ipv6rwc.
type Service struct {
	pool6Net    *net.IPNet
	allowedNets []*net.IPNet
	udpTimeout  time.Duration

	ns       *netstack.YggdrasilNetstack
	sessions sync.Map // sessionKey → *udpSession
}

// NewService creates a NAT64 Service from configuration.
// allowedSources is the shared AllowedSources list from AppConfig.
func NewService(cfg config.NAT64Config, allowedSources []string, ns *netstack.YggdrasilNetstack) (*Service, error) {
	_, pool6Net, err := net.ParseCIDR(cfg.Pool6)
	if err != nil {
		return nil, fmt.Errorf("nat64: invalid pool6 %q: %w", cfg.Pool6, err)
	}

	var allowed []*net.IPNet
	for _, src := range allowedSources {
		if ip := net.ParseIP(src); ip != nil {
			// Single IP — wrap in a /128 subnet.
			allowed = append(allowed, &net.IPNet{IP: ip, Mask: net.CIDRMask(128, 128)})
		} else if _, cidr, err := net.ParseCIDR(src); err == nil {
			allowed = append(allowed, cidr)
		}
		// Invalid entries are silently skipped; config.validate() catches them.
	}

	return &Service{
		pool6Net:    pool6Net,
		allowedNets: allowed,
		udpTimeout:  time.Duration(cfg.UDPTimeout) * time.Second,
		ns:          ns,
	}, nil
}

// isAllowed reports whether srcIP is in one of the configured allowed-source ranges.
// An empty allowedNets list means "deny all".
func (s *Service) isAllowed(ip net.IP) bool {
	for _, n := range s.allowedNets {
		if n.Contains(ip) {
			return true
		}
	}
	return false
}

// Start activates the NAT64 service:
//   1. Installs a gVisor TCP forwarder (handles pool6 TCP SYNs).
//   2. Registers the UDP packet interceptor on the NIC read path.
//   3. Starts the UDP session idle-cleanup goroutine.
func (s *Service) Start(ctx context.Context, logger *log.Logger) {
	// ── TCP: gVisor tcp.NewForwarder ─────────────────────────────────────────
	tcpFwd := tcp.NewForwarder(s.ns.Stack(), 0, 65535, func(req *tcp.ForwarderRequest) {
		s.handleTCP(req, logger)
	})
	s.ns.Stack().SetTransportProtocolHandler(tcp.ProtocolNumber, tcpFwd.HandlePacket)

	// ── UDP: NIC-level packet interceptor ────────────────────────────────────
	s.ns.SetPacketInterceptor(s.interceptUDPPacket)

	// ── UDP session cleanup goroutine ────────────────────────────────────────
	go s.cleanupUDPSessions(ctx)

	logger.Printf("NAT64 started  pool6=%s  udp_timeout=%s  sources=%v",
		s.pool6Net, s.udpTimeout, s.allowedNets)
}

// cleanupUDPSessions periodically expires idle UDP sessions.
func (s *Service) cleanupUDPSessions(ctx context.Context) {
	if s.udpTimeout <= 0 {
		return
	}
	ticker := time.NewTicker(s.udpTimeout / 2)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			// Close all open outbound connections.
			s.sessions.Range(func(_, v any) bool {
				v.(*udpSession).outConn.Close()
				return true
			})
			return
		case <-ticker.C:
			cutoff := time.Now().Add(-s.udpTimeout).UnixNano()
			s.sessions.Range(func(k, v any) bool {
				sess := v.(*udpSession)
				if sess.lastSeenNs < cutoff {
					// Force-close the outConn; udpReplyLoop will exit and delete the key.
					sess.outConn.Close()
				}
				return true
			})
		}
	}
}
