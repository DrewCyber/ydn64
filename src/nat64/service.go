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
	"gvisor.dev/gvisor/pkg/tcpip/stack"
	"gvisor.dev/gvisor/pkg/tcpip/transport/tcp"
	"gvisor.dev/gvisor/pkg/tcpip/transport/udp"

	"github.com/DrewCyber/ydn64/src/config"
	"github.com/DrewCyber/ydn64/src/netstack"
)

// NetStack abstracts the gVisor-backed netstack surface the NAT64 service
// uses. *netstack.YggdrasilNetstack satisfies it implicitly; defining the
// interface lets unit tests supply a synthetic stack without a Yggdrasil core.
type NetStack interface {
	Stack() *stack.Stack
	MTU() uint64
	WritePacket(pkt []byte) (int, error)
	SetPacketInterceptor(fn func([]byte) bool)
}

// Compile-time check that the production netstack satisfies NetStack.
var _ NetStack = (*netstack.YggdrasilNetstack)(nil)

// Service implements TUN-less NAT64: it terminates IPv6 traffic addressed to
// the pool6::/96 subnet inside the gVisor netstack and re-originates it over
// real IPv4 OS sockets.
//
//	TCP  — handled via gVisor's tcp.NewForwarder (promiscuous mode is enabled
//	       on the gVisor stack so it accepts pool6::IPv4 destinations).
//	UDP  — handled via gVisor's udp.NewForwarder the same way; gVisor owns
//	       checksums, demuxing, IPv6 reassembly and outbound fragmentation,
//	       so fragmented datagrams and oversized replies work end-to-end.
//	ICMP — Echo Request/Reply only (RFC 6146 §3.1), intercepted at the NIC
//	       level before gVisor (raw packets injected via ipv6rwc) and
//	       translated via a single shared raw ICMPv4 socket. Requires
//	       CAP_NET_RAW; if unavailable, ICMP translation is silently disabled
//	       (TCP/UDP are unaffected).
type Service struct {
	pool6Net *net.IPNet
	settings atomic.Pointer[nat64Settings]

	ns       NetStack
	sessions sync.Map // sessionKey → *udpSession

	icmpConn     *icmp.PacketConn
	icmpSessions sync.Map // icmpSessionKey → *icmpSession
	icmpClosed   atomic.Bool
}

// nat64Settings holds the subset of NAT64 configuration that can be changed
// at runtime via Service.Reload() without restarting the service or
// touching the gVisor stack/pool6 routing (AllowedSources, Nat64UdpTimeout).
// It is swapped atomically so readers never need to take a lock.
type nat64Settings struct {
	allowedNets    []*net.IPNet
	ignoredDstNets []*net.IPNet
	udpTimeout     time.Duration
}

// NewService creates a NAT64 Service from configuration.
// allowedSources is the shared AllowedSources list from AppConfig.
// ignoredDstSubnets is the shared IgnoredDstSubnets list from AppConfig.
func NewService(cfg config.NAT64Config, allowedSources []string, ignoredDstSubnets []string, ns NetStack) (*Service, error) {
	_, pool6Net, err := net.ParseCIDR(cfg.Pool6)
	if err != nil {
		return nil, fmt.Errorf("nat64: invalid pool6 %q: %w", cfg.Pool6, err)
	}

	s := &Service{
		pool6Net: pool6Net,
		ns:       ns,
	}
	s.settings.Store(&nat64Settings{
		allowedNets:    config.ParseAllowedNets(allowedSources),
		ignoredDstNets: config.ParseIPNets(ignoredDstSubnets),
		udpTimeout:     time.Duration(cfg.UDPTimeout) * time.Second,
	})
	return s, nil
}

// Reload atomically replaces AllowedSources, IgnoredDstSubnets, and Nat64UdpTimeout
// with new values, e.g. in response to a SIGHUP-triggered config reload. Safe to call
// concurrently with in-flight traffic; other NAT64 settings (Nat64Pool,
// Nat64Enable) are not reloadable and require a process restart to change.
func (s *Service) Reload(cfg config.NAT64Config, allowedSources []string, ignoredDstSubnets []string) {
	s.settings.Store(&nat64Settings{
		allowedNets:    config.ParseAllowedNets(allowedSources),
		ignoredDstNets: config.ParseIPNets(ignoredDstSubnets),
		udpTimeout:     time.Duration(cfg.UDPTimeout) * time.Second,
	})
}

// udpTimeout returns the current NAT64 UDP session idle timeout.
func (s *Service) udpTimeout() time.Duration {
	return s.settings.Load().udpTimeout
}

// isAllowed reports whether srcIP is in one of the configured allowed-source ranges.
// An empty allowedNets list means "deny all".
func (s *Service) isAllowed(ip net.IP) bool {
	for _, n := range s.settings.Load().allowedNets {
		if n.Contains(ip) {
			return true
		}
	}
	return false
}

// isIgnoredDst reports whether dstIPv4 is in one of the configured ignored destination subnets.
func (s *Service) isIgnoredDst(ip net.IP) bool {
	for _, n := range s.settings.Load().ignoredDstNets {
		if n.Contains(ip) {
			return true
		}
	}
	return false
}

// Start activates the NAT64 service:
//  1. Installs gVisor TCP and UDP forwarders (handle pool6 flows).
//  2. Registers the ICMPv6 packet interceptor on the NIC read path.
//  3. Opens a shared raw ICMPv4 socket (best-effort) and starts its reply loop.
//  4. Starts the session idle-cleanup goroutine.
func (s *Service) Start(ctx context.Context, logger *log.Logger) {
	// ── TCP: gVisor tcp.NewForwarder ─────────────────────────────────────────
	tcpFwd := tcp.NewForwarder(s.ns.Stack(), 0, 65535, func(req *tcp.ForwarderRequest) {
		s.handleTCP(req, logger)
	})
	s.ns.Stack().SetTransportProtocolHandler(tcp.ProtocolNumber, tcpFwd.HandlePacket)

	// ── UDP: gVisor udp.NewForwarder ─────────────────────────────────────────
	udpFwd := udp.NewForwarder(s.ns.Stack(), func(req *udp.ForwarderRequest) bool {
		return s.handleUDPForward(req, logger)
	})
	s.ns.Stack().SetTransportProtocolHandler(udp.ProtocolNumber, udpFwd.HandlePacket)

	// ── ICMP: NIC-level packet interceptor ───────────────────────────────────
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

	cur := s.settings.Load()
	logger.Printf("NAT64 started  pool6=%s  udp_timeout=%s  sources=%v  icmp=%v",
		s.pool6Net, cur.udpTimeout, cur.allowedNets, s.icmpConn != nil)
}

// interceptPacket dispatches a raw IPv6 packet from the NIC read path to the
// ICMPv6 interceptor. Returning true means the packet was consumed and must
// not reach gVisor. UDP is no longer handled here: it goes through gVisor's
// udp.Forwarder (registered in Start), which gives the stack ownership of
// checksums, demuxing and fragmentation for that protocol.
func (s *Service) interceptPacket(pkt []byte) bool {
	if len(pkt) < 40 || pkt[0]>>4 != 6 {
		return false
	}
	if pkt[6] == 58 { // ICMPv6
		return s.interceptICMPPacket(pkt)
	}
	return false
}

// cleanupSessions periodically expires idle UDP sessions and ICMP echo
// sessions, and tears down the raw ICMP socket on shutdown.
func (s *Service) cleanupSessions(ctx context.Context) {
	// ICMP sessions use a fixed timeout independent of Nat64UdpTimeout, since
	// echo request/reply exchanges are short-lived by nature.
	const icmpSessionTimeout = 30 * time.Second

	interval := icmpSessionTimeout / 2
	if t := s.udpTimeout(); t > 0 && t/2 < interval {
		interval = t / 2
	}
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			// Close both legs of every open UDP session; the relay loops exit
			// on the closed conns and delete their map entries themselves.
			s.sessions.Range(func(_, v any) bool {
				sess := v.(*udpSession)
				sess.conn6.Close()
				if sess.outConn != nil {
					sess.outConn.Close()
				}
				return true
			})
			if s.icmpConn != nil {
				s.icmpClosed.Store(true)
				s.icmpConn.Close()
			}
			return
		case <-ticker.C:
			if t := s.udpTimeout(); t > 0 {
				cutoff := time.Now().Add(-t).UnixNano()
				s.sessions.Range(func(k, v any) bool {
					sess := v.(*udpSession)
					if atomic.LoadInt64(&sess.lastSeenNs) < cutoff {
						// Close the gVisor endpoint (unregisters it from the
						// demuxer, so later datagrams of this tuple start a
						// fresh session) and the udp4 socket; both relay
						// loops then exit and delete the key.
						sess.conn6.Close()
						sess.outConn.Close()
					}
					return true
				})
			}
			icmpCutoff := time.Now().Add(-icmpSessionTimeout).UnixNano()
			s.icmpSessions.Range(func(k, v any) bool {
				if atomic.LoadInt64(&v.(*icmpSession).lastSeenNs) < icmpCutoff {
					s.icmpSessions.Delete(k)
				}
				return true
			})
		}
	}
}
