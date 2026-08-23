package nat64

import (
	"math"
	"net"
	"strconv"
	"sync/atomic"
	"time"

	"github.com/gologme/log"
	"gvisor.dev/gvisor/pkg/tcpip/adapters/gonet"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
	"gvisor.dev/gvisor/pkg/tcpip/transport/udp"
	"gvisor.dev/gvisor/pkg/waiter"
)

// sessionKey uniquely identifies a NAT64 UDP session.
// All fields are value types so the struct is directly usable as a sync.Map key.
type sessionKey struct {
	srcAddr [16]byte // yggdrasil source IPv6 address
	srcPort uint16
	dstAddr [4]byte // real IPv4 destination
	dstPort uint16
}

// udpSession tracks a single NAT64 UDP flow.
//
// Unlike the pre-forwarder implementation, the gVisor-side endpoint is
// registered in the stack's transport demuxer by CreateEndpoint, so every
// datagram of the flow — including the triggering one, which CreateEndpoint
// pre-queues — is delivered directly to conn6 without any manual demuxing
// here. The sync.Map entry only serves idle-expiry bookkeeping and gives the
// reply loop access to both legs.
type udpSession struct {
	outConn    *net.UDPConn   // connected UDP4 socket to the real IPv4 server
	conn6      *gonet.UDPConn // connected gVisor UDP endpoint on the Yggdrasil leg
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

	// Embedded IPv4 = last 4 bytes of the pool6 destination.
	copy(flow.key.dstAddr[:], dstSlice[12:16])
	if s.isIgnoredDst(net.IP(flow.key.dstAddr[:])) {
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

	go func() {
		dstUDPAddr := &net.UDPAddr{
			IP:   net.IP(flow.key.dstAddr[:]),
			Port: int(flow.key.dstPort),
		}
		conn4, err := net.DialUDP("udp4", nil, dstUDPAddr)
		if err != nil {
			logger.Debugf("NAT64 UDP dial %s: %v", dstUDPAddr, err)
			// No session was stored yet (and none counted), so closing the
			// gVisor endpoint is all the cleanup needed.
			yggConn.Close()
			return
		}

		logger.Debugf("NAT64 UDP %v.%d → %s",
			net.IP(flow.key.srcAddr[:]).String(), flow.key.srcPort,
			net.JoinHostPort(dstUDPAddr.IP.String(), strconv.Itoa(dstUDPAddr.Port)))

		sess := &udpSession{outConn: conn4, conn6: yggConn}
		atomic.StoreInt64(&sess.lastSeenNs, time.Now().UnixNano())
		if _, loaded := s.sessions.LoadOrStore(flow.key, sess); loaded {
			// A stale map entry from a just-expired session of the same tuple
			// still exists (its relay loops haven't deleted it yet). The live
			// session is always the one whose gVisor endpoint is registered in
			// the demuxer — i.e. this one — so replace the entry unconditionally.
			// The stale loops exit on their closed conns and their deletes are
			// conditional (CompareAndDelete), so they cannot clobber ours; the
			// occupancy counter is unchanged because the slot merely changes
			// which session object it points at.
			s.sessions.Store(flow.key, sess)
		} else {
			s.udpSessions.Add(1)
		}
		go s.udpReplyLoop(sess, flow.key)
		go s.udpForwardLoop(sess, flow.key)
	}()

	return true
}

// udpForwardLoop pumps the client→server direction: datagrams read off the
// gVisor endpoint are written to the connected OS udp4 socket.
func (s *Service) udpForwardLoop(sess *udpSession, key sessionKey) {
	defer s.deleteSession(sess, key)
	buf := make([]byte, maxUDPDatagramSize)
	for {
		n, err := sess.conn6.Read(buf)
		if err != nil {
			return // endpoint closed by idle expiry, shutdown, or peer reset
		}
		atomic.StoreInt64(&sess.lastSeenNs, time.Now().UnixNano())
		if _, err := sess.outConn.Write(buf[:n]); err != nil {
			return
		}
		atomic.StoreInt64(&sess.lastSeenNs, time.Now().UnixNano())
	}
}

// udpReplyLoop pumps the server→client direction: replies read off the OS
// udp4 socket are written into the gVisor endpoint, which routes them from
// pool6::IPv4 back to the client (checksums and outbound IPv6 fragmentation
// included). Oversized replies that previously could not be sent at all now
// arrive fragmented and reassemble correctly on the client.
func (s *Service) udpReplyLoop(sess *udpSession, key sessionKey) {
	defer s.deleteSession(sess, key)
	buf := make([]byte, maxUDPDatagramSize)
	for {
		// Rolling read deadline: a server gone silent for udpTimeout expires
		// the session even if client traffic keeps flowing (matches the
		// pre-forwarder behavior; RFC 4787 REQ-5 floor is deliberately not met
		// — see README "Standards conformance").
		_ = sess.outConn.SetReadDeadline(time.Now().Add(s.udpTimeout()))
		n, err := sess.outConn.Read(buf)
		if err != nil {
			return // timeout or connection closed
		}
		atomic.StoreInt64(&sess.lastSeenNs, time.Now().UnixNano())
		if _, err := sess.conn6.Write(buf[:n]); err != nil {
			return
		}
		atomic.StoreInt64(&sess.lastSeenNs, time.Now().UnixNano())
	}
}

// deleteSession tears down both legs of a session and removes its map entry.
// The delete is conditional so a relay loop of a superseded stale session can
// never remove the entry (or decrement the occupancy counter) of the live
// session that replaced it.
func (s *Service) deleteSession(sess *udpSession, key sessionKey) {
	sess.conn6.Close()
	if sess.outConn != nil {
		sess.outConn.Close()
	}
	if s.sessions.CompareAndDelete(key, sess) {
		s.udpSessions.Add(-1)
	}
}
