package nat64

import (
	"context"
	"fmt"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/gologme/log"
	"golang.org/x/net/icmp"
	"gvisor.dev/gvisor/pkg/tcpip/transport/tcp"

	"github.com/DrewCyber/ydn64/src/config"
	"github.com/DrewCyber/ydn64/src/netstack"
)

// Service implements TUN-less NAT64: it intercepts IPv6 packets addressed to
// the pool6::/96 subnet and proxies them to real IPv4 destinations.
//
//	TCP  — handled via gVisor's tcp.NewForwarder (promiscuous mode is enabled
//	       on the gVisor stack so it accepts pool6::IPv4 destinations).
//	UDP  — intercepted at NIC level before gVisor, replies are raw IPv6 packets
//	       written directly to ipv6rwc.
//	ICMP — Echo Request/Reply only (RFC 6146 §3.1), intercepted at the same
//	       NIC level as UDP and translated via a single shared raw ICMPv4
//	       socket. Requires CAP_NET_RAW; if unavailable, ICMP translation is
//	       silently disabled (TCP/UDP are unaffected).
type Service struct {
	pool6Net    *net.IPNet
	allowedNets []*net.IPNet
	udpTimeout  time.Duration

	ns       *netstack.YggdrasilNetstack
	sessions sync.Map // sessionKey → *udpSession

	icmpConn     *icmp.PacketConn
	icmpSessions sync.Map // icmpSessionKey → *icmpSession
	icmpClosed   atomic.Bool
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
//  1. Installs a gVisor TCP forwarder (handles pool6 TCP SYNs).
//  2. Registers the combined UDP+ICMP packet interceptor on the NIC read path.
//  3. Opens a shared raw ICMPv4 socket (best-effort) and starts its reply loop.
//  4. Starts the session idle-cleanup goroutine.
func (s *Service) Start(ctx context.Context, logger *log.Logger) {
	// ── TCP: gVisor tcp.NewForwarder ─────────────────────────────────────────
	tcpFwd := tcp.NewForwarder(s.ns.Stack(), 0, 65535, func(req *tcp.ForwarderRequest) {
		s.handleTCP(req, logger)
	})
	s.ns.Stack().SetTransportProtocolHandler(tcp.ProtocolNumber, tcpFwd.HandlePacket)

	// ── UDP + ICMP: NIC-level packet interceptor ─────────────────────────────
	s.ns.SetPacketInterceptor(s.interceptPacket)

	// ── ICMP: shared raw socket for Echo Request/Reply translation ──────────
	// Best-effort: requires CAP_NET_RAW. If unavailable, NAT64 ICMP is simply
	// disabled (interceptICMPPacket drops instead of forwarding); TCP/UDP keep
	// working normally.
	if conn, err := icmp.ListenPacket("ip4:icmp", "0.0.0.0"); err != nil {
		logger.Printf("NAT64 ICMP disabled (raw socket unavailable, needs CAP_NET_RAW): %v", err)
	} else {
		s.icmpConn = conn
		go s.icmpReplyLoop()
	}

	// ── Session cleanup goroutine ────────────────────────────────────────────
	go s.cleanupSessions(ctx)

	logger.Printf("NAT64 started  pool6=%s  udp_timeout=%s  sources=%v  icmp=%v",
		s.pool6Net, s.udpTimeout, s.allowedNets, s.icmpConn != nil)
}

// interceptPacket dispatches a raw IPv6 packet from the NIC read path to the
// UDP or ICMP interceptor based on the IPv6 next-header field. Returning
// true means the packet was consumed and must not reach gVisor.
func (s *Service) interceptPacket(pkt []byte) bool {
	if len(pkt) < 40 || pkt[0]>>4 != 6 {
		return false
	}
	switch pkt[6] {
	case 17: // UDP
		return s.interceptUDPPacket(pkt)
	case 58: // ICMPv6
		return s.interceptICMPPacket(pkt)
	default:
		return false
	}
}

// cleanupSessions periodically expires idle UDP sessions and ICMP echo
// sessions, and tears down the raw ICMP socket on shutdown.
func (s *Service) cleanupSessions(ctx context.Context) {
	// ICMP sessions use a fixed timeout independent of Nat64UdpTimeout, since
	// echo request/reply exchanges are short-lived by nature.
	const icmpSessionTimeout = 30 * time.Second

	interval := icmpSessionTimeout / 2
	if s.udpTimeout > 0 && s.udpTimeout/2 < interval {
		interval = s.udpTimeout / 2
	}
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			// Close all open outbound UDP connections.
			s.sessions.Range(func(_, v any) bool {
				v.(*udpSession).outConn.Close()
				return true
			})
			if s.icmpConn != nil {
				s.icmpClosed.Store(true)
				s.icmpConn.Close()
			}
			return
		case <-ticker.C:
			if s.udpTimeout > 0 {
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
			icmpCutoff := time.Now().Add(-icmpSessionTimeout).UnixNano()
			s.icmpSessions.Range(func(k, v any) bool {
				if v.(*icmpSession).lastSeenNs < icmpCutoff {
					s.icmpSessions.Delete(k)
				}
				return true
			})
		}
	}
}
