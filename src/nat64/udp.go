package nat64

import (
	"errors"
	"math"
	"net"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/gologme/log"
	"gvisor.dev/gvisor/pkg/tcpip/adapters/gonet"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
	"gvisor.dev/gvisor/pkg/tcpip/transport/udp"
	"gvisor.dev/gvisor/pkg/waiter"
)

// sessionKey uniquely identifies a NAT64 UDP session: one client socket
// talking to one real IPv4 destination.
// All fields are value types so the struct is directly usable as a sync.Map key.
type sessionKey struct {
	srcAddr [16]byte // yggdrasil source IPv6 address
	srcPort uint16
	dstAddr [4]byte // real IPv4 destination
	dstPort uint16
}

// bibKey identifies a BIB entry: the client's Yggdrasil address and source
// port. Endpoint-independent mapping (RFC 4787 REQ-1, RFC 6146 §3.1/§5.2)
// keys the external IPv4 mapping on exactly this pair — the same client
// socket reaches every destination through the same allocated port.
type bibKey struct {
	srcAddr [16]byte
	srcPort uint16
}

// v4Tuple identifies one destination flow on a BIB's shared socket; it is
// the key of the BIB's per-flow table used to demux inbound datagrams.
type v4Tuple struct {
	addr [4]byte
	port uint16
}

// udpBIB is one Binding Information Base entry: the endpoint-independent
// mapping of a single client socket. It owns ONE unconnected UDP4 socket
// whose ephemeral local port is the NAT-assigned external port for ALL
// destinations that client talks to. A single reply loop reads the shared
// socket and demuxes datagrams to per-tuple sessions via flows.
//
// lastSeenNs is refreshed ONLY by the client's outbound datagrams (through
// any of its sessions), never by inbound v4 traffic — RFC 6146 §5.3 / RFC
// 4787 REQ-5 keep-alive protection: a chatty server cannot pin the mapping.
type udpBIB struct {
	uconn      *net.UDPConn // unconnected udp4 socket, ephemeral local port
	localIP    [4]byte      // outbound socket's source address on the IPv4 side
	localPort  uint16       // the NAT-assigned port shared by all its flows
	lastSeenNs int64        // Unix nanosecond timestamp, updated atomically
	flows      sync.Map     // v4Tuple → *udpSession
}

func (b *udpBIB) touch() { atomic.StoreInt64(&b.lastSeenNs, time.Now().UnixNano()) }

// udpFilterMode selects which inbound senders are relayed back to the client
// (RFC 6146 §5.2 / RFC 4787 REQ-8).
type udpFilterMode int

const (
	// filterAddressDependent is RFC 6146 §5.2's mandated default: datagrams
	// from ANY port of an IPv4 address the client has an active flow toward
	// are accepted.
	filterAddressDependent udpFilterMode = iota
	// filterAddressAndPortDependent additionally requires the exact server
	// port — the strictest behaviour, equivalent to the pre-EIM
	// connected-socket semantics.
	filterAddressAndPortDependent
	// filterEndpointIndependent delivers datagrams from ANY IPv4 sender to a
	// client that has a mapping (BIB entry), even senders it never contacted
	// — RFC 4787 REQ-8's endpoint-independent filtering. Together with REQ-1
	// endpoint-independent mapping this makes the translator transparent to
	// hole-punching protocols (STUN/ICE): once a peer learns the client's
	// external ip:port it can send in without prior contact. Unmatched
	// datagrams are synthesised as IPv6/UDP (source pool6::sender) and
	// injected onto the Yggdrasil leg via the same raw-packet path the ICMP
	// translation uses; they create no session state and refresh no timers.
	filterEndpointIndependent
)

func parseUDPFilterMode(s string) udpFilterMode {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "address-and-port-dependent":
		return filterAddressAndPortDependent
	case "endpoint-independent":
		return filterEndpointIndependent
	default:
		return filterAddressDependent
	}
}

func (m udpFilterMode) String() string {
	switch m {
	case filterAddressAndPortDependent:
		return "address-and-port-dependent"
	case filterEndpointIndependent:
		return "endpoint-independent"
	default:
		return "address-dependent"
	}
}

// portParityMode selects how a BIB's NAT-assigned external UDP port relates
// to the client's source port (RFC 4787 REQ-3).
type portParityMode int

const (
	// parityPreserve (the REQ-3 SHOULD-default) allocates an external port
	// with the SAME parity as the client's source port — even stays even,
	// odd stays odd. Real-time media stacks rely on this: RTP/RTCP endpoint
	// pairs (RFC 4961) and several games demultiplex their flows by port
	// parity, and a NAT that flips parity breaks them.
	parityPreserve portParityMode = iota
	// parityDoNotPreserve takes the first kernel-assigned ephemeral port
	// with no parity guarantee. RFC 4787 REQ-3 requires such a NAT to draw
	// from a range that is not used for parity-preserving assignments;
	// exactly one mode is ever active in a running process, so the plain
	// ephemeral pool satisfies that by construction.
	parityDoNotPreserve
)

func parsePortParity(s string) portParityMode {
	if strings.EqualFold(strings.TrimSpace(s), "do-not-preserve") {
		return parityDoNotPreserve
	}
	return parityPreserve // default, including unknown/empty values
}

func (m portParityMode) String() string {
	if m == parityDoNotPreserve {
		return "do-not-preserve"
	}
	return "preserve"
}

// udpSession tracks one client→destination flow through its BIB.
//
// The gVisor-side endpoint is registered in the stack's transport demuxer by
// CreateEndpoint, so every datagram of the client tuple — including the
// triggering one — is delivered directly to conn6. Outbound datagrams are
// written to the BIB's SHARED socket with WriteToUDP; inbound replies are
// demuxed off the same socket by the BIB reply loop.
//
// localIP/localPort are copies of the BIB's allocation at registration time,
// kept per-session so ICMPv4 error demuxing (icmperr.go) can match quoted
// tuples without dereferencing the BIB.
type udpSession struct {
	bib        *udpBIB
	conn6      *gonet.UDPConn // connected gVisor UDP endpoint on the Yggdrasil leg
	dst        *net.UDPAddr   // real IPv4 destination (precomputed for WriteToUDP)
	dstAddr    [4]byte        // copy of dst.IP for cheap comparisons
	localIP    [4]byte        // BIB's allocated IPv4 address (for ICMP err demux)
	localPort  uint16         // BIB's allocated port (for ICMP err demux)
	lastSeenNs int64          // Unix nanosecond timestamp, updated atomically
}

// udpFlow is a validated inbound UDP flow: the result of filtering one
// unmatched datagram against pool6/source/destination policy.
type udpFlow struct {
	key      sessionKey
	pool6Src [16]byte // pool6::IPv4 destination address — becomes the reply source
}

// maxUDPDatagramSize is the largest UDP payload IPv6 can carry in one
// datagram. Reads off the gVisor endpoint must use a buffer this large:
// reassembled fragments can exceed the path MTU, and gonet.UDPConn.Read
// silently truncates datagrams that do not fit (like recvmsg(2) does).
const maxUDPDatagramSize = 65535

// udpBufPool recycles the 64 KiB read buffers of the UDP relay loops.
// Every session's forward loop and every BIB's reply loop needs exactly one,
// so at the default caps (Nat64MaxUDPSessions=4096) naive per-goroutine
// allocation peaks around 256 MiB plus allocator churn from constant session
// turnover; pooling keeps resident memory at the true high-water mark and
// lets churned buffers be reused instead of collected and re-allocated.
//
// Hand-off safety: every consumer of a read (WriteToUDP toward the real
// server, conn6.Write into gVisor, injectUnsolicitedUDP's packet build)
// copies the bytes synchronously before returning, so a buffer may be reused
// as soon as its loop puts it back.
var udpBufPool = sync.Pool{
	New: func() any { return make([]byte, maxUDPDatagramSize) },
}

// parseUDPFlow filters an unmatched inbound UDP datagram reported by the
// gVisor forwarder and extracts the NAT64 flow it describes.
//
// The bool result means "flow accepted"; false means the datagram must be
// silently dropped (the caller still returns true from the forwarder handler
// — see handleUDPForward for why).
func (s *Service) parseUDPFlow(id stack.TransportEndpointID) (udpFlow, bool) {
	dstSlice := id.LocalAddress.AsSlice()
	srcSlice := id.RemoteAddress.AsSlice()
	if len(dstSlice) != 16 || len(srcSlice) != 16 {
		// Only the IPv6 protocol is registered on the stack, so both addresses
		// are always 16 bytes; guard anyway rather than risk an As16 panic in
		// the packet path.
		return udpFlow{}, false
	}
	dstIP := net.IP(dstSlice)
	// Only serve pool6 destinations. Promiscuous mode feeds us datagrams for
	// ANY destination that did not match a registered endpoint (including the
	// node's own address when no service bound the port), so this filter must
	// run before anything else.
	if !s.pool6Net.Contains(dstIP) {
		return udpFlow{}, false
	}

	srcIP := net.IP(srcSlice)
	// Source address must NOT be in the pool6 subnet (RFC 6146 §3.5 / §5.4),
	// and must be explicitly allowed.
	if s.pool6Net.Contains(srcIP) {
		return udpFlow{}, false
	}
	if !s.isAllowed(srcIP) {
		return udpFlow{}, false
	}

	flow := udpFlow{
		key: sessionKey{
			srcAddr: [16]byte(srcSlice),
			srcPort: id.RemotePort,
			dstPort: id.LocalPort,
		},
	}
	copy(flow.pool6Src[:], dstSlice)

	// Embedded IPv4 per the RFC 6052 §2.2 layout (length-aware; addresses
	// with a dirty u octet or suffix are refused as not-in-pool).
	dstV4, ok := s.pref64.Extract(net.IP(dstSlice))
	if !ok {
		return udpFlow{}, false
	}
	flow.key.dstAddr = dstV4
	if s.isIgnoredDst(net.IP(dstV4[:])) {
		return udpFlow{}, false
	}
	return flow, true
}

// admitUDPSession reports whether a new UDP session may be created under the
// configured Nat64MaxUDPSessions bound. At capacity the single
// least-recently-active session is evicted (closing its legs; its relay loops
// then unregister it) and admission is retried a bounded number of times —
// the eviction decrements the counter synchronously, so the loop converges
// without blocking. Returns false when the limit cannot be met (no sessions
// to evict and counter still at/over capacity after transient races).
func (s *Service) admitUDPSession() bool {
	max := s.settings.Load().maxUDPSessions
	if max <= 0 {
		return true
	}
	for attempt := 0; attempt < 8; attempt++ {
		if s.udpSessions.Load() < max {
			return true
		}
		s.evictOldestIdleUDPSession()
	}
	return s.udpSessions.Load() < max
}

// evictOldestIdleUDPSession tears down the tracked UDP session with the
// smallest lastSeen timestamp (nil-safe no-op when none are tracked). The
// delete inside deleteSession is what keeps udpSessions consistent.
func (s *Service) evictOldestIdleUDPSession() {
	var (
		oldestKey  sessionKey
		oldest     *udpSession
		oldestSeen int64 = math.MaxInt64
	)
	s.sessions.Range(func(k, v any) bool {
		sess := v.(*udpSession)
		if seen := atomic.LoadInt64(&sess.lastSeenNs); seen < oldestSeen {
			oldestSeen, oldest, oldestKey = seen, sess, k.(sessionKey)
		}
		return true
	})
	if oldest != nil {
		s.deleteSession(oldest, oldestKey)
	}
}

// probeRouteSourceIPv4 learns which source IPv4 address the kernel's routing
// table would pick for datagrams toward dst, without sending anything (a
// connect(2) on a throwaway UDP socket resolves the route and its preferred
// source). dstPort is part of the dial target because some platforms (macOS)
// refuse to connect() toward port 0; any real port yields the same route.
func probeRouteSourceIPv4(dst [4]byte, dstPort uint16) (net.IP, error) {
	port := int(dstPort)
	if port == 0 {
		port = 9 // discard — only the destination address shapes the route
	}
	c, err := net.DialUDP("udp4", nil, &net.UDPAddr{IP: net.IP(append([]byte(nil), dst[:]...)), Port: port})
	if err != nil {
		return nil, err
	}
	defer c.Close()
	la := c.LocalAddr().(*net.UDPAddr)
	src := make(net.IP, 4)
	copy(src, la.IP.To4())
	return src, nil
}

// bibParityAttempts bounds the parity-matching bind tries in listenBIBSocket
// before falling back to whatever port the kernel handed out. With ~50% of
// ephemeral ports matching any wanted parity, 8 tries leave a mismatch
// probability below 0.5%.
const bibParityAttempts = 8

// listenBIBSocket binds the shared outbound UDP4 socket for a new BIB entry.
// Its local port IS the NAT-assigned external port for every destination that
// client talks to (RFC 4787 REQ-1), so its allocation honours the configured
// Nat64PortParity behaviour (RFC 4787 REQ-3):
//
//   - "preserve" (the default): keep the client source port's parity. The
//     kernel hands out ephemeral ports with arbitrary parity, so up to
//     bibParityAttempts binds are made and the first parity match wins; each
//     rejected candidate is closed again immediately (UDP has no TIME_WAIT,
//     so this churns nothing). If no try matches within budget, the last
//     successfully bound socket is used as-is — trading REQ-3's SHOULD for
//     availability rather than failing the client's flow.
//
//   - "do-not-preserve": take the first kernel-assigned port.
func (s *Service) listenBIBSocket(bindIP net.IP, clientPort uint16) (*net.UDPConn, error) {
	if s.settings.Load().portParity != parityPreserve {
		return net.ListenUDP("udp4", &net.UDPAddr{IP: bindIP})
	}
	want := clientPort & 1
	var fallback *net.UDPConn
	for attempt := 0; attempt < bibParityAttempts; attempt++ {
		c, err := net.ListenUDP("udp4", &net.UDPAddr{IP: bindIP})
		if err != nil {
			if fallback != nil {
				// The probe loop hit bind errors after we already hold a
				// usable socket (e.g. the ephemeral range ran dry): serve
				// with it instead of dropping the flow over a lost parity
				// bet.
				return fallback, nil
			}
			return nil, err
		}
		port := uint16(0)
		if la, ok := c.LocalAddr().(*net.UDPAddr); ok {
			port = uint16(la.Port)
		}
		if port&1 == want {
			return c, nil
		}
		if fallback != nil {
			fallback.Close()
		}
		fallback = c
	}
	if l := s.serviceLogger(); l != nil {
		l.Debugf("NAT64 UDP: no parity-matching port after %d binds; external parity will not match client port %d", bibParityAttempts, clientPort)
	}
	return fallback, nil
}

// getOrCreateBIB returns the BIB entry for the client socket identified by
// key, creating (and starting the reply loop of) a fresh one on first use.
// Concurrent creation for the same client is resolved by LoadOrStore: the
// loser closes its surplus socket and adopts the winner's entry, so every
// destination of one client socket always shares one external port
// (RFC 4787 REQ-1).
//
// The socket is deliberately bound to the route's source address for the
// creating flow's destination rather than left wildcard: a wildcard bind
// would leave the BIB's external identity undefined (localIP = 0.0.0.0),
// which the ICMPv4 error demuxer matches against quoted packets. One BIB =
// one external source address; on a multi-homed host every flow of that
// client egresses via the interface chosen for its first destination, which
// matches the single-address external pool model NAT64 assumes anyway.
func (s *Service) getOrCreateBIB(key sessionKey) (*udpBIB, error) {
	bk := bibKey{srcAddr: key.srcAddr, srcPort: key.srcPort}
	if b, ok := s.bibs.Load(bk); ok {
		return b.(*udpBIB), nil
	}
	bindIP, err := probeRouteSourceIPv4(key.dstAddr, key.dstPort)
	if err != nil {
		return nil, err
	}
	uconn, err := s.listenBIBSocket(bindIP, key.srcPort)
	if err != nil {
		return nil, err
	}
	b := &udpBIB{uconn: uconn}
	if la, ok := uconn.LocalAddr().(*net.UDPAddr); ok && la.IP != nil {
		copy(b.localIP[:], la.IP.To4())
		b.localPort = uint16(la.Port)
	}
	b.touch()
	actual, loaded := s.bibs.LoadOrStore(bk, b)
	if loaded {
		uconn.Close()
		return actual.(*udpBIB), nil
	}
	go s.udpReplyLoop(b, bk)
	return b, nil
}

// handleUDPForward is called by udp.NewForwarder for every inbound UDP
// datagram that did not match a registered endpoint. It runs synchronously
// inside gVisor's packet processing path, so only cheap filtering and endpoint
// creation happen here; dialing and relaying run in goroutines.
func (s *Service) handleUDPForward(req *udp.ForwarderRequest, logger *log.Logger) bool {
	id := req.ID()

	flow, ok := s.parseUDPFlow(id)
	if !ok {
		// Silently consume disallowed/malformed flows. Returning false here
		// would make the stack emit an ICMPv6 port-unreachable sourced from
		// the packet's destination address, which must never happen for
		// addresses we don't own (or for sources we chose to drop silently).
		return true
	}

	// Shed before creating any endpoint: an over-limit flow costs nothing.
	// The per-source ceiling (RFC 6146 §5.3) is checked first so one peer
	// cannot evict or exhaust the global pool; the count itself is registered
	// only once a session tuple is actually stored (mirroring udpSessions),
	// so the check can overshoot by the number of concurrent session setups
	// for distinct tuples at worst. With EIM, fan-out to many destinations
	// from ONE client socket shares a single BIB but still consumes one
	// session slot per tuple — the ceiling keeps bounding total state.
	if c := s.srcCounts.count(flow.key.srcAddr, srcUDP); s.perSrcUDPLimit() > 0 && c >= s.perSrcUDPLimit() {
		logger.Debugf("NAT64 UDP shedding flow %v (per-source limit %d)", flow.key, s.perSrcUDPLimit())
		return true
	}
	if !s.admitUDPSession() {
		logger.Debugf("NAT64 UDP shedding flow %v (session limit)", flow.key)
		return true
	}

	// CreateEndpoint binds the endpoint to (pool6 dst, LocalPort), connects it
	// to the client, registers it in the demuxer, and queues the triggering
	// datagram into its receive buffer. It completes synchronously and is fast
	// (no handshake), which keeps per-tuple handling race-free: the NIC read
	// loop is single-threaded, so by the time the next datagram of this tuple
	// arrives the endpoint is already registered and the demuxer delivers to
	// it directly, bypassing this handler entirely.
	var wq waiter.Queue
	ep, tcpErr := req.CreateEndpoint(&wq)
	if tcpErr != nil {
		// A policy-valid flow whose endpoint could not be created (resource
		// exhaustion, unexpected port conflict). Returning false lets the
		// stack answer with ICMPv6 port-unreachable, which is the RFC-like
		// behavior for a genuinely unusable translation (RFC 6146 §3.5 final
		// paragraph analog for UDP); the triggering datagram is lost either way.
		logger.Debugf("NAT64 UDP endpoint create %v: %v", flow.key, tcpErr)
		return false
	}

	yggConn := gonet.NewUDPConn(&wq, ep)

	s.drainWG.Add(1)
	go func() {
		defer s.drainWG.Done()

		// Reuse (or lazily create) the client's single external mapping.
		bib, err := s.getOrCreateBIB(flow.key)
		if err != nil {
			logger.Debugf("NAT64 UDP bind %v: %v", flow.key, err)
			// Report the failure to the client as an ICMPv6 Destination
			// Unreachable (RFC 4443 §3.1) so it fails fast instead of
			// waiting for a reply that will never come.
			v6Type, v6Code := dialErrorToUnreachable(err)
			s.sendUDPFlowUnreachable(flow.pool6Src, flow.key, v6Type, v6Code, err.Error(), logger)
			yggConn.Close()
			return
		}

		dstAddr := &net.UDPAddr{
			IP:   net.IP(append([]byte(nil), flow.key.dstAddr[:]...)),
			Port: int(flow.key.dstPort),
		}

		logger.Debugf("NAT64 UDP %v.%d → %s via %s:%d",
			net.IP(flow.key.srcAddr[:]).String(), flow.key.srcPort,
			net.JoinHostPort(dstAddr.IP.String(), strconv.Itoa(dstAddr.Port)),
			net.IP(bib.localIP[:]).String(), bib.localPort)

		var dstCopy [4]byte
		copy(dstCopy[:], flow.key.dstAddr[:])
		sess := &udpSession{
			bib:       bib,
			conn6:     yggConn,
			dst:       dstAddr,
			dstAddr:   dstCopy,
			localIP:   bib.localIP,
			localPort: bib.localPort,
		}
		atomic.StoreInt64(&sess.lastSeenNs, time.Now().UnixNano())
		if _, loaded := s.sessions.LoadOrStore(flow.key, sess); loaded {
			// A stale map entry from a just-expired session of the same tuple
			// still exists (its forward loop hasn't deleted it yet). The live
			// session is always the one whose gVisor endpoint is registered in
			// the demuxer — i.e. this one — so replace the entry unconditionally.
			// The stale loops exit on their closed conn and their deletes are
			// conditional (CompareAndDelete), so they cannot clobber ours; the
			// occupancy counter is unchanged because the slot merely changes
			// which session object it points at.
			s.sessions.Store(flow.key, sess)
		} else {
			s.udpSessions.Add(1)
			s.srcCounts.add(flow.key.srcAddr, srcUDP)
		}
		// Register in the BIB's flow table BEFORE the forward loop starts so
		// a fast reply can never outrun the demux entry it needs.
		bib.flows.Store(v4Tuple{addr: dstCopy, port: flow.key.dstPort}, sess)
		bib.touch()
		go s.udpForwardLoop(sess, flow.key)
	}()

	return true
}

// udpForwardLoop pumps the client→server direction for one session: datagrams
// read off the session's gVisor endpoint are written to the BIB's SHARED
// socket with WriteToUDP. Every successful send refreshes both the session's
// and the BIB's client-activity stamps (RFC 4787 REQ-5 / RFC 6146 §5.3:
// inbound v4 traffic never extends the mapping).
//
// An ECONNREFUSED on Write means the kernel surfaced an ICMPv4 Port
// Unreachable for an earlier datagram sent on this socket. With a shared BIB
// socket it can no longer be attributed to one specific flow with certainty —
// it is reported against the CURRENT flow (almost always the right one, since
// refusals surface on the next send) as ICMPv6 Destination Unreachable /
// port-unreachable (RFC 4443 §3.1), and the loop keeps running. The precise,
// quote-based attribution path is icmperr.go, which demuxes by full tuple and
// is unaffected by sharing.
func (s *Service) udpForwardLoop(sess *udpSession, key sessionKey) {
	defer s.deleteSession(sess, key)
	buf := udpBufPool.Get().([]byte)
	defer udpBufPool.Put(buf)
	for {
		n, err := sess.conn6.Read(buf)
		if err != nil {
			return // endpoint closed by idle expiry, shutdown, or peer reset
		}
		now := time.Now().UnixNano()
		atomic.StoreInt64(&sess.lastSeenNs, now)
		sess.bib.touch()
		if _, err := sess.bib.uconn.WriteToUDP(buf[:n], sess.dst); err != nil {
			if errors.Is(err, syscall.ECONNREFUSED) {
				s.sendUDPPortRefused(sess, key, s.serviceLogger())
				continue
			}
			return
		}
	}
}

// udpReplyLoop is the single reader of a BIB's shared socket. Every datagram
// arriving on the NAT-assigned port is demuxed to a per-tuple session
// (honouring the configured filtering behaviour) and relayed into its gVisor
// endpoint, which routes it from pool6::serverIP back to the client
// (checksums and outbound IPv6 fragmentation included). Under
// endpoint-independent filtering, datagrams from senders with no matching
// flow are instead synthesised as IPv6/UDP and injected onto the client leg.
func (s *Service) udpReplyLoop(bib *udpBIB, bk bibKey) {
	defer func() {
		// If we exit because the socket was closed (idle expiry or shutdown),
		// make sure the map entry goes too; CompareAndDelete keeps a freshly
		// re-created BIB under the same key safe.
		s.bibs.CompareAndDelete(bk, bib)
	}()
	buf := udpBufPool.Get().([]byte)
	defer udpBufPool.Put(buf)
	lg := s.serviceLogger()
	for {
		n, raddr, err := bib.uconn.ReadFromUDP(buf)
		if err != nil {
			if errors.Is(err, syscall.ECONNREFUSED) {
				// Kernel-reported port unreachable with no quotable victim;
				// cannot be attributed to a flow on a shared socket.
				if lg != nil {
					lg.Debugf("NAT64 UDP port-unreachable on BIB %s:%d (unattributable)", net.IP(bib.localIP[:]), bib.localPort)
				}
				continue
			}
			return // socket closed by idle expiry, shutdown, or fatal error
		}
		sess := s.demuxUDPReply(bib, raddr, lg)
		if sess == nil {
			// No matching flow. Under endpoint-independent filtering the
			// sender is still entitled to delivery — inject the datagram as
			// a synthesised IPv6 packet rather than dropping it. This is
			// pure forwarding: no session is created, no session/BIB timer
			// is refreshed (RFC 6146 §5.3: only client outbound traffic
			// extends mappings), so unsolicited senders cannot pin state.
			if s.settings.Load().udpFiltering == filterEndpointIndependent {
				s.injectUnsolicitedUDP(bk, raddr, buf[:n], lg)
			}
			continue
		}
		if _, err := sess.conn6.Write(buf[:n]); err != nil {
			continue // endpoint gone; its forward loop performs the teardown
		}
	}
}

// injectUnsolicitedUDP delivers one datagram from a never-contacted IPv4
// sender to the client behind the BIB identified by bk (RFC 4787 REQ-8,
// endpoint-independent filtering). The per-tuple gVisor endpoint that normal
// replies flow through does not exist for this sender, so the datagram is
// rebuilt as IPv6/UDP — source pool6::senderIP, destination the client's
// Yggdrasil address/port — checksummed and injected via the same raw-packet
// path the ICMP translation uses; oversized payloads are fragmented on the
// way out exactly like synthesised echo replies.
func (s *Service) injectUnsolicitedUDP(bk bibKey, raddr *net.UDPAddr, payload []byte, lg *log.Logger) {
	var srcV4 [4]byte
	copy(srcV4[:], raddr.IP.To4())
	src6 := s.pref64.Embed(net.IP(srcV4[:])).To16()

	pkt := buildIPv6UDPDatagram(src6, bk.srcAddr[:], uint16(raddr.Port), bk.srcPort, payload)
	ident := uint32(replyFragIdent.Add(1))
	for _, p := range fragmentIPv6Packet(pkt, int(s.ns.MTU()), ident) {
		if _, err := s.ns.WritePacket(p); err != nil {
			if lg != nil {
				lg.Debugf("NAT64 UDP(EIF) inject to %s.%d from %s:%d: %v",
					net.IP(bk.srcAddr[:]).String(), bk.srcPort, raddr.IP.String(), raddr.Port, err)
			}
			return
		}
	}
	if lg != nil {
		lg.Debugf("NAT64 UDP(EIF) delivered %d bytes to %s.%d from %s:%d (no matching flow)",
			len(payload), net.IP(bk.srcAddr[:]).String(), bk.srcPort, raddr.IP.String(), raddr.Port)
	}
}

// demuxUDPReply finds the session a datagram arriving on a BIB's shared
// socket belongs to, honouring the configured filtering behaviour
// (RFC 6146 §5.2 / RFC 4787 REQ-8):
//
//   - exact match first: (server IP, server port) equal to an active flow of
//     this BIB always delivers — every mode accepts true replies.
//   - address-and-port-dependent: that is ALL that delivers; anything else
//     is dropped (the pre-EIM connected-socket semantics).
//   - address-dependent (default): a datagram from any port of an IPv4
//     address this BIB has an active flow toward is accepted and delivered
//     into that flow's session.
//
// A datagram matching no flow at all is dropped in every mode EXCEPT
// endpoint-independent filtering, where udpReplyLoop injects it onto the
// client leg directly (no per-tuple endpoint exists to relay through — see
// filterEndpointIndependent).
func (s *Service) demuxUDPReply(bib *udpBIB, raddr *net.UDPAddr, lg *log.Logger) *udpSession {
	var ip4 [4]byte
	copy(ip4[:], raddr.IP.To4())
	tuple := v4Tuple{addr: ip4, port: uint16(raddr.Port)}
	if v, ok := bib.flows.Load(tuple); ok {
		return v.(*udpSession)
	}

	if s.settings.Load().udpFiltering == filterAddressDependent {
		var candidate *udpSession
		bib.flows.Range(func(_, v any) bool {
			sess := v.(*udpSession)
			if sess.dstAddr == ip4 {
				candidate = sess
				return false
			}
			return true
		})
		if candidate != nil {
			return candidate
		}
	}

	if lg != nil {
		lg.Debugf("NAT64 UDP filtered inbound %s:%d at %s:%d (no matching flow)",
			raddr.IP.String(), raddr.Port, net.IP(bib.localIP[:]).String(), bib.localPort)
	}
	return nil
}

// deleteSession tears down a session's client-facing leg and removes its map
// entries. The sessions delete is conditional so a relay loop of a superseded
// stale session can never remove the entry (or decrement the occupancy
// counter) of the live session that replaced it; the same guard protects the
// BIB's per-flow table entry.
func (s *Service) deleteSession(sess *udpSession, key sessionKey) {
	sess.conn6.Close()
	if s.sessions.CompareAndDelete(key, sess) {
		s.udpSessions.Add(-1)
		s.srcCounts.remove(key.srcAddr, srcUDP)
		if sess.bib != nil {
			tuple := v4Tuple{addr: key.dstAddr, port: key.dstPort}
			sess.bib.flows.CompareAndDelete(tuple, sess)
		}
	}
}
