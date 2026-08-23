package nat64

import (
	"encoding/binary"
	"net"
	"sync/atomic"
	"time"

	"golang.org/x/net/icmp"
	"golang.org/x/net/ipv4"
)

// icmpSessionTimeout is the idle lifetime of a NAT64 ICMP query session.
// RFC 5508 REQ-2 requires an ICMP query timeout of at least 60 seconds;
// RFC 6146 §4 specifies the same 60 s default (ICMP_DEFAULT).
const icmpSessionTimeout = 60 * time.Second

// maxICMPSessions bounds how many concurrent ICMP echo sessions are tracked.
// Requests arriving while the table is full are dropped instead of growing it
// without limit (an allowed peer must not be able to pin unbounded state).
const maxICMPSessions = 4096

// maxICMPIDAllocAttempts bounds how many NAT-side identifier candidates a
// single request may probe before giving up.
const maxICMPIDAllocAttempts = 64

// icmpPacketConn is the subset of *icmp.PacketConn the NAT64 ICMP path uses.
// Declared as an interface so unit tests can inject a fake socket without
// CAP_NET_RAW or real network traffic.
type icmpPacketConn interface {
	WriteTo(b []byte, dst net.Addr) (int, error)
	ReadFrom(b []byte) (int, net.Addr, error)
	SetReadDeadline(t time.Time) error
	Close() error
}

var _ icmpPacketConn = (*icmp.PacketConn)(nil)

// icmpSessionKey identifies a NAT-allocated outbound echo slot: replies read
// off the single shared raw socket are demultiplexed by (reply source IPv4,
// NAT-assigned identifier). The identifier here is the one ydn64 put on the
// wire toward the IPv4 destination — never the client's own (RFC 6146
// §3.5.3 / §4, RFC 5508 REQ-1: clients must not be able to choose, observe,
// or collide on identifiers other sessions' replies are matched against).
type icmpSessionKey struct {
	dstAddr [4]byte
	id      uint16 // NAT-assigned identifier
}

// icmpQueryKey identifies the client-side tuple of an echo exchange:
// repeat requests from the same client toward the same destination with the
// same identifier (ping retries, subsequent sequence numbers) reuse their
// existing NAT allocation instead of minting a new one per request.
type icmpQueryKey struct {
	srcAddr [16]byte // Yggdrasil client address
	dstAddr [4]byte  // real IPv4 destination
	id      uint16   // client's echo identifier
}

// icmpSession tracks where an outstanding Echo Request's reply should be
// translated back to, plus the NAT-assigned identifier under which the
// request was sent toward the real IPv4 destination.
type icmpSession struct {
	pool6Src   [16]byte // pool6::IPv4 — becomes the ICMPv6 reply's source
	yggDst     [16]byte // original Yggdrasil sender — becomes the reply's destination
	clientID   uint16   // identifier from the Yggdrasil client's Echo Request
	allocID    uint16   // NAT-assigned identifier used on the IPv4 side
	lastSeenNs int64    // Unix nanosecond timestamp, updated atomically
}

// interceptICMPPacket is installed (via interceptPacket) as part of the
// NIC-level packet interceptor. It runs in the NIC read goroutine; pkt is
// valid only for the duration of this call.
func (s *Service) interceptICMPPacket(pkt []byte) bool {
	// Minimum: 40 (IPv6 header) + 8 (ICMPv6 echo header) = 48 bytes.
	if len(pkt) < 48 {
		return false
	}
	if pkt[0]>>4 != 6 {
		return false
	}
	if pkt[6] != 58 { // ICMPv6
		return false
	}
	if pkt[40] != 128 { // Echo Request only; everything else (NDP, etc.) passes to gVisor
		return false
	}
	dstIP := net.IP(pkt[24:40])
	if !s.pool6Net.Contains(dstIP) {
		return false
	}

	srcIP := net.IP(pkt[8:24])
	// Source address must NOT be in the pool6 subnet (RFC 6146 §3.5 / §5.4).
	if s.pool6Net.Contains(srcIP) {
		return true // consumed (dropped)
	}
	if !s.isAllowed(srcIP) {
		return true // consumed (dropped)
	}

	if s.icmpConn == nil {
		// Raw ICMP socket unavailable (e.g. missing CAP_NET_RAW) — NAT64 ICMP
		// translation is unsupported in this environment. Drop rather than
		// falling through to gVisor, which has no route for this address.
		return true
	}

	var srcAddr, pool6Src [16]byte
	copy(srcAddr[:], pkt[8:24])
	copy(pool6Src[:], pkt[24:40]) // destination = pool6::IPv4 → becomes reply source

	id := binary.BigEndian.Uint16(pkt[44:46])
	seq := binary.BigEndian.Uint16(pkt[46:48])

	var dstIPv4 [4]byte
	copy(dstIPv4[:], pkt[36:40]) // last 4 bytes of pool6 destination = embedded IPv4
	if s.isIgnoredDst(net.IP(dstIPv4[:])) {
		return true // consumed (dropped)
	}

	// Inbound validation before anything is relayed toward the IPv4
	// internet (forwarded TCP/UDP are already structurally validated by
	// gVisor; this raw path is not):
	//   1. The IPv6 payload-length header field must match the actual frame
	//      size — a mismatched frame is malformed or crafted.
	//   2. The ICMPv6 checksum must verify against the real pseudo-header;
	//      relaying unverified frames would let an allowed peer inject
	//      garbage into the v4 path under ydn64's own source address.
	plen := int(binary.BigEndian.Uint16(pkt[4:6]))
	if plen < 8 || len(pkt)-40 != plen {
		return true // consumed (dropped): malformed frame
	}
	if cs := ipv6UpperLayerChecksum(srcAddr[:], pool6Src[:], 58, pkt[40:40+plen]); cs != 0 {
		return true // consumed (dropped): invalid ICMPv6 checksum
	}

	data := make([]byte, len(pkt)-48)
	copy(data, pkt[48:])

	sess := s.registerICMPSession(srcAddr, pool6Src, dstIPv4, id)
	if sess == nil {
		return true // consumed (dropped): table full or no identifier available
	}
	go s.forwardICMP(sess, dstIPv4, seq, data)
	return true
}

// registerICMPSession records (or refreshes) the session for a client echo
// request and returns it carrying a valid NAT-assigned allocID.
//
// It must only ever run from the NIC read loop: that loop is the sole writer
// of new sessions, which makes the allocate-check-publish sequence below
// race-free without locks (the reply loop and cleanup goroutine only read,
// refresh lastSeen atomically, and delete expired entries).
//
// RFC 6146 §3.5.3 / RFC 5508 REQ-1: the outbound identifier is allocated by
// the NAT, mapped back to (client, destination, client identifier); the
// client-chosen identifier is never exposed on the IPv4 side.
func (s *Service) registerICMPSession(srcAddr, pool6Src [16]byte, dstIPv4 [4]byte, clientID uint16) *icmpSession {
	qKey := icmpQueryKey{srcAddr: srcAddr, dstAddr: dstIPv4, id: clientID}
	if v, ok := s.icmpQueries.Load(qKey); ok {
		sess := v.(*icmpSession)
		atomic.StoreInt64(&sess.lastSeenNs, time.Now().UnixNano())
		return sess
	}

	if s.icmpCount.Load() >= maxICMPSessions {
		return nil
	}

	sess := &icmpSession{
		pool6Src: pool6Src,
		yggDst:   srcAddr,
		clientID: clientID,
	}
	atomic.StoreInt64(&sess.lastSeenNs, time.Now().UnixNano())
	for i := 0; i < maxICMPIDAllocAttempts; i++ {
		cand := uint16(s.icmpNextID.Add(1)) // wraps naturally through uint16 truncation
		if cand == 0 {
			continue // never emit identifier zero
		}
		sKey := icmpSessionKey{dstAddr: dstIPv4, id: cand}
		if _, exists := s.icmpSessions.Load(sKey); exists {
			continue // wraparound collision with a live session — try next candidate
		}
		sess.allocID = cand
		s.icmpSessions.Store(sKey, sess)
		s.icmpQueries.Store(qKey, sess)
		s.icmpCount.Add(1)
		return sess
	}
	return nil
}

// forwardICMP sends a translated ICMPv4 Echo Request to the real IPv4
// destination via the shared raw socket, using the session's NAT-assigned
// identifier in place of the client's.
func (s *Service) forwardICMP(sess *icmpSession, dstIPv4 [4]byte, seq uint16, data []byte) {
	conn := s.icmpConn
	if conn == nil {
		return
	}
	msg := icmp.Message{
		Type: ipv4.ICMPTypeEcho,
		Code: 0,
		Body: &icmp.Echo{ID: int(sess.allocID), Seq: int(seq), Data: data},
	}
	b, err := msg.Marshal(nil)
	if err != nil {
		return
	}
	_, _ = conn.WriteTo(b, &net.IPAddr{IP: net.IP(dstIPv4[:])})
}

// icmpReplyLoop continuously reads ICMPv4 messages off the single shared raw
// socket and translates Echo Replies back into synthesised IPv6 ICMPv6 Echo
// Replies, looking up the originating session by (reply source IPv4,
// NAT-assigned identifier).
func (s *Service) icmpReplyLoop() {
	buf := make([]byte, int(s.ns.MTU()))
	for {
		conn := s.icmpConn
		_ = conn.SetReadDeadline(time.Now().Add(time.Second))
		n, peer, err := conn.ReadFrom(buf)
		if err != nil {
			if s.icmpClosed.Load() {
				return
			}
			continue // timeout or transient error — keep polling
		}

		ipAddr, ok := peer.(*net.IPAddr)
		if !ok {
			continue
		}
		ip4 := ipAddr.IP.To4()
		if ip4 == nil {
			continue
		}

		msg, err := icmp.ParseMessage(1 /* IANA ICMP protocol number */, buf[:n])
		if err != nil || msg.Type != ipv4.ICMPTypeEchoReply {
			continue
		}
		echo, ok := msg.Body.(*icmp.Echo)
		if !ok {
			continue
		}

		var srcAddr [4]byte
		copy(srcAddr[:], ip4)
		s.translateICMPv4Reply(srcAddr, echo)
	}
}

// translateICMPv4Reply maps one real ICMPv4 Echo Reply back to its Yggdrasil
// client: the session is looked up by (reply source, NAT-assigned
// identifier), the client's own identifier is restored into the reply, and
// the synthesised IPv6 packet is injected into the netstack. Reports whether
// the reply was translated.
func (s *Service) translateICMPv4Reply(srcV4 [4]byte, echo *icmp.Echo) bool {
	key := icmpSessionKey{dstAddr: srcV4, id: uint16(echo.ID)}
	val, ok := s.icmpSessions.Load(key)
	if !ok {
		return false // no matching session: unsolicited or expired reply
	}
	sess := val.(*icmpSession)
	atomic.StoreInt64(&sess.lastSeenNs, time.Now().UnixNano())

	reply := buildIPv6ICMPEchoReplyPacket(sess.pool6Src[:], sess.yggDst[:], sess.clientID, uint16(echo.Seq), echo.Data)
	_, err := s.ns.WritePacket(reply)
	return err == nil
}
