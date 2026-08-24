package nat64

import (
	"context"
	"fmt"
	"math/rand"
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
	// bibs holds one Binding Information Base entry per client (address,
	// port) pair (bibKey → *udpBIB). Each entry owns ONE unconnected UDP4
	// socket shared by every destination that client talks to — this is the
	// endpoint-independent mapping of RFC 4787 REQ-1 / RFC 6146 §3.1/§5.2.
	bibs sync.Map
	// tcpConns tracks live proxied TCP connections (*tcpPair keyed by
	// itself) so the cleanup loop can expire idle ones (RFC 5382 REQ-5).
	tcpConns sync.Map
	// udpSessions counts live entries in sessions. It is incremented when an
	// entry is inserted (first store of a tuple) and decremented only when
	// that exact entry is removed, so stale/superseded relay loops can never
	// corrupt the count.
	udpSessions atomic.Int64
	// srcCounts tracks live UDP sessions and proxied TCP connections per
	// client address for the per-source anti-abuse ceilings (RFC 6146 §5.3).
	srcCounts srcTracker
	// tcpSem bounds concurrently proxied NAT64 TCP connections. Sized at
	// construction — Nat64MaxTCPConnections requires a restart to change.
	tcpSem chan struct{}

	icmpConn     icmpPacketConn
	icmpSessions sync.Map // icmpSessionKey{dstAddr, NAT-assigned id} → *icmpSession
	icmpQueries  sync.Map // icmpQueryKey{srcAddr, dstAddr, client id} → *icmpSession
	icmpNextID   atomic.Uint32
	icmpCount    atomic.Int64
	icmpClosed   atomic.Bool

	// reasm reassembles fragmented ICMPv6 Echo Requests intercepted from
	// clients (RFC 8200 §4.5); guard-rail caps bound its memory.
	reasm *reasmTable

	// errLim rate-limits every synthesised ICMPv6 error (translated v4-side
	// errors and generated Destination Unreachables alike).
	errLim errRateLimiter
	// logger is the service log target captured at Start; packet-path hooks
	// (the NIC interceptor runs without arguments) use it for debug lines.
	logger atomic.Pointer[log.Logger]

	// statsMu guards lastStatSnap, shared by the periodic stats loop and
	// on-demand dumps (SIGHUP) so their lines partition time cleanly.
	statsMu      sync.Mutex
	lastStatSnap statSnapshot

	// drainWG tracks spawned per-flow goroutines (TCP proxies, UDP session
	// relay pairs, ICMP forwards) so shutdown can wait briefly for them.
	drainWG sync.WaitGroup
}

// Drain waits until all in-flight per-flow goroutines finish (session
// cleanup closes their connections on ctx cancellation) or until d elapses.
func (s *Service) Drain(d time.Duration) {
	done := make(chan struct{})
	go func() {
		s.drainWG.Wait()
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(d):
	}
}

// nat64Settings holds the subset of NAT64 configuration that can be changed
// at runtime via Service.Reload() without restarting the service or
// touching the gVisor stack/pool6 routing (AllowedSources, Nat64UdpTimeout,
// Nat64MaxUDPSessions). It is swapped atomically so readers never need to
// take a lock.
type nat64Settings struct {
	allowedNets    []*net.IPNet
	ignoredDstNets []*net.IPNet
	udpTimeout     time.Duration
	tcpTimeout     time.Duration
	udpFiltering   udpFilterMode
	maxUDPSessions int64 // ≤0 = unlimited
	// Per-source anti-abuse ceilings (RFC 6146 §5.3); ≤0 = unlimited.
	maxUDPSessionsPerSrc int64
	maxTCPClientsPerSrc  int64
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
		pool6Net:  pool6Net,
		ns:        ns,
		srcCounts: newSrcTracker(),
		reasm:     newReasmTable(),
	}
	if cfg.MaxTCPClients > 0 {
		s.tcpSem = make(chan struct{}, cfg.MaxTCPClients)
	}
	s.icmpNextID.Store(rand.Uint32()) // unpredictable starting point for NAT-assigned ICMP identifiers
	s.settings.Store(&nat64Settings{
		allowedNets:          config.ParseAllowedNets(allowedSources),
		ignoredDstNets:       config.ParseIPNets(ignoredDstSubnets),
		udpTimeout:           time.Duration(cfg.UDPTimeout) * time.Second,
		tcpTimeout:           time.Duration(cfg.TCPTimeout) * time.Second,
		udpFiltering:         parseUDPFilterMode(cfg.UDPFiltering),
		maxUDPSessions:       int64(cfg.MaxUDPSessions),
		maxUDPSessionsPerSrc: int64(cfg.MaxUDPSessionsPerSrc),
		maxTCPClientsPerSrc:  int64(cfg.MaxTCPConnectionsPerSrc),
	})
	return s, nil
}

// Reload atomically replaces AllowedSources, IgnoredDstSubnets, Nat64UdpTimeout,
// Nat64TcpTimeout, Nat64UdpFiltering, Nat64MaxUDPSessions and the per-source
// anti-abuse ceilings with new values, e.g. in response to a SIGHUP-triggered
// config reload. Safe to call concurrently with in-flight traffic; other
// NAT64 settings (Nat64Pool, Nat64Enable, Nat64MaxTCPConnections) are not
// reloadable and require a process restart to change.
func (s *Service) Reload(cfg config.NAT64Config, allowedSources []string, ignoredDstSubnets []string) {
	s.settings.Store(&nat64Settings{
		allowedNets:          config.ParseAllowedNets(allowedSources),
		ignoredDstNets:       config.ParseIPNets(ignoredDstSubnets),
		udpTimeout:           time.Duration(cfg.UDPTimeout) * time.Second,
		tcpTimeout:           time.Duration(cfg.TCPTimeout) * time.Second,
		udpFiltering:         parseUDPFilterMode(cfg.UDPFiltering),
		maxUDPSessions:       int64(cfg.MaxUDPSessions),
		maxUDPSessionsPerSrc: int64(cfg.MaxUDPSessionsPerSrc),
		maxTCPClientsPerSrc:  int64(cfg.MaxTCPConnectionsPerSrc),
	})
}

// udpTimeout returns the current NAT64 UDP session idle timeout.
func (s *Service) udpTimeout() time.Duration {
	return s.settings.Load().udpTimeout
}

// tcpTimeout returns the current proxied-TCP idle timeout (RFC 5382 REQ-5).
func (s *Service) tcpTimeout() time.Duration {
	return s.settings.Load().tcpTimeout
}

// perSrcUDPLimit returns the per-client UDP session ceiling (≤0 = unlimited).
func (s *Service) perSrcUDPLimit() int64 {
	return s.settings.Load().maxUDPSessionsPerSrc
}

// perSrcTCPLimit returns the per-client proxied-TCP ceiling (≤0 = unlimited).
func (s *Service) perSrcTCPLimit() int64 {
	return s.settings.Load().maxTCPClientsPerSrc
}

// serviceLogger returns the log target captured at Start; nil before Start,
// which relay loops and hook paths treat as "skip debug logging".
func (s *Service) serviceLogger() *log.Logger { return s.logger.Load() }

// tryAcquireTCP reports whether a new proxied TCP connection may start.
// Always true when no limit is configured.
func (s *Service) tryAcquireTCP() bool {
	if s.tcpSem == nil {
		return true
	}
	select {
	case s.tcpSem <- struct{}{}:
		return true
	default:
		return false
	}
}

// releaseTCP returns a previously acquired TCP slot.
func (s *Service) releaseTCP() {
	if s.tcpSem != nil {
		<-s.tcpSem
	}
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

	// ── ICMP: shared raw socket for Echo Request/Reply translation ──────────
	// Best-effort: requires CAP_NET_RAW. If unavailable, NAT64 ICMP is simply
	// disabled (interceptICMPPacket drops instead of forwarding); TCP/UDP keep
	// working normally. The socket is opened and published BEFORE the packet
	// interceptor is installed, so the interceptor never observes a
	// half-initialised icmpConn.
	if conn, err := icmp.ListenPacket("ip4:icmp", "0.0.0.0"); err != nil {
		logger.Printf("NAT64 ICMP disabled (raw socket unavailable, needs CAP_NET_RAW): %v", err)
	} else {
		s.icmpConn = conn
		go s.icmpReplyLoop(logger)
	}

	s.logger.Store(logger)

	// ── ICMP: NIC-level packet interceptor ───────────────────────────────────
	s.ns.SetPacketInterceptor(s.interceptPacket)

	// ── Session cleanup goroutine ────────────────────────────────────────────
	go s.cleanupSessions(ctx)

	// ── Periodic stack-statistics logger ─────────────────────────────────────
	go s.statsLoop(ctx, logger, statsInterval)

	cur := s.settings.Load()
	logger.Printf("NAT64 started  pool6=%s  udp_timeout=%s  tcp_timeout=%s  udp_filter=%s  sources=%v  icmp=%v",
		s.pool6Net, cur.udpTimeout, cur.tcpTimeout, cur.udpFiltering, cur.allowedNets, s.icmpConn != nil)
}

// interceptPacket dispatches a raw IPv6 packet from the NIC read path to the
// ICMPv6 interceptor. Returning true means the packet was consumed and must
// not reach gVisor. UDP is no longer handled here: it goes through gVisor's
// udp.Forwarder (registered in Start), which gives the stack ownership of
// checksums, demuxing and fragmentation for that protocol. Header-chain
// discrimination (ICMPv6 vs other protocols, extension headers, fragments)
// lives in interceptICMPPacket.
func (s *Service) interceptPacket(pkt []byte) bool {
	if len(pkt) < 40 || pkt[0]>>4 != 6 {
		return false
	}
	return s.interceptICMPPacket(pkt)
}

// cleanupSessions periodically expires idle UDP sessions and proxied TCP
// connections (RFC 5382 REQ-5) and ICMP echo sessions, and tears down the
// raw ICMP socket on shutdown.
func (s *Service) cleanupSessions(ctx context.Context) {
	interval := icmpSessionTimeout / 2
	if t := s.udpTimeout(); t > 0 && t/2 < interval {
		interval = t / 2
	}
	if t := s.tcpTimeout(); t > 0 && t/2 < interval {
		interval = t / 2
	}
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			// Close the client-facing endpoint of every open UDP session and
			// every BIB socket; the relay loops exit on the closed conns and
			// delete their map entries themselves.
			s.sessions.Range(func(_, v any) bool {
				v.(*udpSession).conn6.Close()
				return true
			})
			s.bibs.Range(func(_, v any) bool {
				v.(*udpBIB).uconn.Close()
				return true
			})
			// Same for every tracked proxied TCP connection: closing both
			// legs unwinds its proxy goroutine promptly instead of leaving
			// it for Drain's timeout.
			s.tcpConns.Range(func(_, v any) bool {
				pair := v.(*tcpPair)
				pair.a.Close()
				pair.b.Close()
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
						// fresh session); the forward loop exits and deletes
						// the key (and its BIB flow entry) itself.
						sess.conn6.Close()
					}
					return true
				})
				// BIB entries live and die on the same client-activity
				// clock: every outbound datagram touches both stamps, so a
				// BIB expires within one tick of its last flow going idle.
				// Closing the socket ends the reply loop; any straggler
				// forward loops fail their next WriteToUDP and tear down.
				s.bibs.Range(func(k, v any) bool {
					bib := v.(*udpBIB)
					if atomic.LoadInt64(&bib.lastSeenNs) < cutoff {
						bib.uconn.Close()
						s.bibs.CompareAndDelete(k.(bibKey), bib)
					}
					return true
				})
			}
			s.reapIdleTCP()
			icmpCutoff := time.Now().Add(-icmpSessionTimeout).UnixNano()
			s.icmpQueries.Range(func(k, v any) bool {
				qk := k.(icmpQueryKey)
				sess := v.(*icmpSession)
				if atomic.LoadInt64(&sess.lastSeenNs) < icmpCutoff {
					// CompareAndDelete so a session refreshed (or re-registered
					// under the same query key) after we loaded it is never
					// evicted; the NAT-side slot is dropped with it.
					if s.icmpQueries.CompareAndDelete(qk, sess) {
						s.icmpSessions.Delete(icmpSessionKey{dstAddr: qk.dstAddr, id: sess.allocID})
						s.icmpCount.Add(-1)
					}
				}
				return true
			})
		}
	}
}
