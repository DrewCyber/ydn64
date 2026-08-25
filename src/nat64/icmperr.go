package nat64

import (
	"encoding/binary"
	"errors"
	"net"
	"sync"
	"syscall"
	"time"

	"github.com/gologme/log"
)

// ICMP error translation (RFC 7915 §4.2/§4.3, RFC 5508 REQ-3/REQ-4, RFC 4443
// §3.1).
//
// The shared raw ICMPv4 socket receives every ICMPv4 message the host sees,
// including errors about packets ydn64 itself sent toward real IPv4
// destinations: Time Exceeded from intermediate routers, Destination
// Unreachable and Packet Too Big from routers or servers. Translating those
// into ICMPv6 errors addressed to the originating Yggdrasil client is what
// makes traceroute work through NAT64 and lets IPv6-side PMTUD converge for
// UDP flows.
//
// Demuxing is strict: an error is acted on only when its embedded (quoted)
// packet matches a live NAT64 session (UDP tuple, or the ICMP Echo slot that
// allocated the identifier); everything else the socket happens to observe —
// errors about DNS64's own upstream queries, peering traffic, unrelated host
// traffic — is ignored exactly as before.
//
// TCP is deliberately not covered: proxied TCP connections terminate twice
// (gVisor endpoint ↔ OS socket), so IPv4-side ICMP errors are consumed by
// the OS stack itself (PMTU caching, retransmission) and carry no
// information the client leg needs. See context/RFCs.txt.

const (
	// icmpErrMaxPacket caps a synthesised ICMPv6 error at the minimum IPv6
	// MTU (RFC 7915 §4.3: include only as much of the invoking packet as
	// fits), so the error itself never requires fragmentation downstream.
	icmpErrMaxPacket = 1280

	// icmpErrFixedLen is the fixed overhead of a synthesised error:
	// outer IPv6 header (40) + outer ICMPv6 header (8) + inner IPv6 header
	// (40). The rest of the budget carries the quoted transport segment.
	icmpErrFixedLen = 88

	// Synthesised-error rate limiting (RFC 7915 §4.4 recommends rate
	// limiting generated ICMP errors). Errors are rare on healthy paths;
	// these bounds only matter under a pathological IPv4 path or active
	// abuse matching live sessions.
	icmpErrRatePerSec = 50
	icmpErrBurst      = 100

	// icmpReadBufSize is the raw-socket read buffer, sized well above any
	// realistic quoted error (routers cap quotes at the path MTU) so full
	// quotes survive truncation-free reads.
	icmpReadBufSize = 9216
)

// rfc1191Plateaus is the RFC 1191 plateau-MTU table used when an IPv4 router
// reports Fragmentation Needed with MTU=0 (no RFC 1191 support): the greatest
// plateau below the offending datagram's total length estimates the likely
// path MTU (RFC 7915 §4.2).
var rfc1191Plateaus = [...]int{65535, 32000, 17914, 8166, 4352, 2002, 1492, 1006, 508, 296, 68}

// translateICMPv4ErrorType maps an ICMPv4 error (type, code) onto its
// ICMPv6 equivalent per the RFC 7915 §4.2 tables. ok=false means the message
// class is silently dropped (redirects, source quench, obsolete query types,
// codes without an IPv6 meaning, unknown types).
func translateICMPv4ErrorType(typ, code byte) (v6Type, v6Code byte, ok bool) {
	switch typ {
	case 3: // Destination Unreachable
		switch code {
		case 0, 1, 5, 6, 7, 8, 11, 12:
			return 1, 0, true // no route to destination
		case 2:
			return 4, 1, true // protocol unreachable → parameter problem (pointer = Next Header field)
		case 3:
			return 1, 4, true // port unreachable
		case 4:
			return 2, 0, true // fragmentation needed → Packet Too Big (MTU mapped separately)
		case 9, 10, 13, 15:
			return 1, 1, true // communication administratively prohibited
		default:
			return 0, 0, false // 14 (host precedence violation), other/reserved codes
		}
	case 11: // Time Exceeded → Hop Limit Exceeded, code unchanged (0 transit, 1 reassembly)
		if code > 1 {
			return 0, 0, false
		}
		return 3, code, true
	case 12: // Parameter Problem → Parameter Problem, pointer remapped separately
		switch code {
		case 0, 2:
			return 4, 0, true
		default:
			return 0, 0, false // missing-required-option and unknown codes
		}
	default:
		return 0, 0, false // redirect (5), alternative host (6), source quench (4), obsolete queries, IGMP, unknown
	}
}

// remapV4ParamProblemPointer converts an ICMPv4 Parameter Problem pointer
// (byte offset into the inner IPv4 header) to the corresponding offset into
// the reconstructed IPv6 header, per RFC 7915 Figure 3. ok=false → drop.
func remapV4ParamProblemPointer(p byte) (uint32, bool) {
	switch {
	case p == 0:
		return 0, true // version/IHL → version/traffic class
	case p == 1:
		return 1, true // TOS → traffic class/flow label
	case p >= 2 && p <= 3:
		return 4, true // total length → payload length
	case p == 8:
		return 7, true // TTL → hop limit
	case p == 9:
		return 6, true // protocol → next header
	case p >= 12 && p <= 15:
		return 8, true // source address
	case p >= 16 && p <= 19:
		return 24, true // destination address
	default:
		return 0, false // identification/flags/checksum have no IPv6 counterpart
	}
}

// ptbIPv6MTU converts the MTU advertised in an ICMPv4 Fragmentation Needed
// message into the MTU carried by the synthesised ICMPv6 Packet Too Big,
// following RFC 7915 §4.2: the IPv6 value gains 20 bytes (a 40-byte IPv6
// header vs the 20-byte IPv4 header over the same link) and MUST NOT fall
// below the minimum IPv6 MTU of 1280, nor exceed the next-hop (Yggdrasil)
// MTU.
//
// A zero advertised MTU (router without RFC 1191 support) falls back to the
// RFC 1191 plateau list — the greatest plateau strictly below the offending
// datagram's total length — then the same +20/clamp rules apply.
func ptbIPv6MTU(v4MTU, innerTotalLen int, v6NextHopMTU uint64) int {
	m := v4MTU
	if m <= 0 {
		m = 1280
		for _, p := range rfc1191Plateaus {
			if p < innerTotalLen && p >= 1280 && p > m {
				m = p
			}
		}
	}
	mtu := m + 20
	if v6NextHopMTU > 0 && int(v6NextHopMTU) < mtu {
		mtu = int(v6NextHopMTU)
	}
	if mtu < 1280 {
		mtu = 1280
	}
	return mtu
}

// icmpInnerPacket is the parsed quoted packet embedded in an ICMPv4 error.
type icmpInnerPacket struct {
	src, dst [4]byte
	proto    byte
	ttl      byte
	totalLen int    // Total Length field of the original (unquoted) datagram
	l4       []byte // transport segment available after the IP header
}

// parseICMPv4InnerPacket validates the quoted packet inside an ICMPv4 error
// and splits off its transport segment. Structural preconditions for
// translation: real IPv4, sane IHL, a protocol ydn64 has state for (UDP or
// ICMP; TCP sessions are deliberately untracked), and at least the first 8
// bytes of the transport header present (RFC 1812 quoting floor).
func parseICMPv4InnerPacket(b []byte) (icmpInnerPacket, bool) {
	if len(b) < 20 || b[0]>>4 != 4 {
		return icmpInnerPacket{}, false
	}
	ihl := int(b[0]&0x0f) * 4
	if ihl < 20 || ihl > len(b) {
		return icmpInnerPacket{}, false
	}
	p := icmpInnerPacket{
		proto:    b[9],
		ttl:      b[8],
		totalLen: int(binary.BigEndian.Uint16(b[2:4])),
	}
	copy(p.src[:], b[12:16])
	copy(p.dst[:], b[16:20])
	p.l4 = b[ihl:]
	switch p.proto {
	case 17, 1, 6: // UDP, ICMP, TCP
	default:
		return icmpInnerPacket{}, false
	}
	if len(p.l4) < 8 || p.totalLen < ihl {
		return icmpInnerPacket{}, false
	}
	return p, true
}

// buildIPv6ICMPErrorPacket assembles a complete ICMPv6 error ready for
// injection into the Yggdrasil network (the RFC 7915 §4.3 shape):
//
//	outer IPv6    src=srcIP6 dst=dstIP6 nh=58 hlim=64
//	outer ICMPv6  errType/errCode + checksum + type-specific word (extra)
//	inner IPv6    src=innerSrc6 dst=innerDst6 nh=innerProto hlim=innerTTL
//	inner L4      innerL4, truncated to the packet budget, checksum rebuilt
//
// The quoted transport segment keeps a zero checksum only if it had one
// (UDP); otherwise all inner checksums are recomputed over the reconstructed
// addresses and truncated data (RFC 7915 §4.5), and finally the outer ICMPv6
// pseudo-header checksum covers the whole message.
func buildIPv6ICMPErrorPacket(
	srcIP6, dstIP6 []byte,
	errType, errCode byte,
	extra uint32,
	innerSrc6, innerDst6 []byte,
	innerTTL, innerProto byte,
	innerL4 []byte,
) []byte {
	if len(innerL4) > icmpErrMaxPacket-icmpErrFixedLen {
		innerL4 = innerL4[:icmpErrMaxPacket-icmpErrFixedLen]
	}
	pkt := make([]byte, icmpErrFixedLen+len(innerL4))

	// Outer IPv6 header.
	pkt[0] = 0x60
	binary.BigEndian.PutUint16(pkt[4:6], uint16(len(pkt)-40))
	pkt[6] = 58
	pkt[7] = 64
	copy(pkt[8:24], srcIP6)
	copy(pkt[24:40], dstIP6)

	// Outer ICMPv6 header: type/code plus the type-specific word (Packet
	// Too Big MTU, parameter-problem pointer) in bytes 44:48.
	pkt[40] = errType
	pkt[41] = errCode
	binary.BigEndian.PutUint32(pkt[44:48], extra)

	// Inner IPv6 header — the translated quoted packet.
	in := pkt[48:]
	in[0] = 0x60
	binary.BigEndian.PutUint16(in[4:6], uint16(len(innerL4)))
	in[6] = innerProto
	in[7] = innerTTL
	copy(in[8:24], innerSrc6)
	copy(in[24:40], innerDst6)
	copy(in[40:], innerL4)

	// Inner transport checksum over the reconstructed addresses/data,
	// written into the packet's own copy of the segment.
	seg := in[40:]
	switch innerProto {
	case 17: // UDP
		// The length field reflects the truncated data, not the original
		// (possibly much larger) quoted datagram.
		binary.BigEndian.PutUint16(seg[4:6], uint16(len(seg)))
		if binary.BigEndian.Uint16(seg[6:8]) != 0 { // zero stays zero (RFC 768)
			cs := ipv6UpperLayerChecksum(innerSrc6, innerDst6, 17, seg)
			if cs == 0 {
				cs = 0xffff
			}
			binary.BigEndian.PutUint16(seg[6:8], cs)
		}
	case 58: // ICMPv6 (quoted echo request)
		binary.BigEndian.PutUint16(seg[2:4], 0)
		cs := ipv6UpperLayerChecksum(innerSrc6, innerDst6, 58, seg)
		binary.BigEndian.PutUint16(seg[2:4], cs)
	case 6: // TCP
		binary.BigEndian.PutUint16(seg[16:18], 0)
		cs := ipv6UpperLayerChecksum(innerSrc6, innerDst6, 6, seg)
		binary.BigEndian.PutUint16(seg[16:18], cs)
	}

	// Outer ICMPv6 checksum covers header + entire quoted packet.
	cs := ipv6UpperLayerChecksum(srcIP6, dstIP6, 58, pkt[40:])
	binary.BigEndian.PutUint16(pkt[42:44], cs)

	return pkt
}

// errRateLimiter is a token-bucket limiter applied to every synthesised
// ICMPv6 error before injection.
type errRateLimiter struct {
	mu     sync.Mutex
	tokens float64
	last   time.Time
}

func (r *errRateLimiter) allow(now time.Time) bool {
	return r.allowBudget(now, icmpErrRatePerSec, icmpErrBurst)
}

// allowBudget is the generic token-bucket refill-and-spend step; callers
// supply their own sustained rate and burst so one limiter shape serves every
// synthesis path (translated errors, generated unreachables, EIF injection).
// Zero-value ready: the first call seeds the bucket at its full burst.
func (r *errRateLimiter) allowBudget(now time.Time, perSec float64, burst float64) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.last.IsZero() {
		r.last = now
		r.tokens = burst
	}
	r.tokens += now.Sub(r.last).Seconds() * perSec
	r.last = now
	if r.tokens > burst {
		r.tokens = burst
	}
	if r.tokens < 1 {
		return false
	}
	r.tokens--
	return true
}

// pool6AddrFor maps an IPv4 address into the NAT64 pool prefix per the
// configured RFC 6052 §2.2 layout (u octet and suffix left zero).
func (s *Service) pool6AddrFor(v4 [4]byte) [16]byte {
	var out [16]byte
	copy(out[:], s.pref64.Embed(net.IP(v4[:])).To16())
	return out
}

// handleICMPv4Error translates one non-echo ICMPv4 message read off the raw
// socket into an ICMPv6 error for the originating Yggdrasil client.
// srcV4 is the message's IPv4 source (whoever emitted the error); raw holds
// the full ICMPv4 message bytes.
func (s *Service) handleICMPv4Error(srcV4 [4]byte, raw []byte, logger *log.Logger) {
	if len(raw) < 8 {
		return
	}
	v6Type, v6Code, ok := translateICMPv4ErrorType(raw[0], raw[1])
	if !ok {
		return
	}
	inner, ok := parseICMPv4InnerPacket(raw[8:])
	if !ok {
		logger.Debugf("NAT64 ICMPv4 error from %s: unusable quoted packet", net.IP(srcV4[:]))
		return
	}
	// NOTE: no rate-limit token is consumed here. The raw socket receives
	// every ICMPv4 error the host sees — most of it unrelated noise (other
	// processes' traceroutes, PMTUD for host traffic) that will never demux
	// to a live NAT64 session. Budget is spent at the injection point
	// (injectICMPv6), only once a session actually matched, so noise cannot
	// starve genuine PMTUD/Time-Exceeded translations for live flows.

	// Type-specific word: Packet Too Big MTU or parameter-problem pointer.
	var extra uint32
	switch {
	case v6Type == 2:
		extra = uint32(ptbIPv6MTU(int(binary.BigEndian.Uint16(raw[6:8])), inner.totalLen, s.ns.MTU()))
	case v6Type == 4 && v6Code == 1:
		extra = 6 // point at the IPv6 Next Header field
	case v6Type == 4:
		var mapped uint32
		if mapped, ok = remapV4ParamProblemPointer(raw[4]); !ok {
			return
		}
		extra = mapped
	}

	switch inner.proto {
	case 17:
		s.translateUDPQuotedError(srcV4, inner, v6Type, v6Code, extra, logger)
	case 1:
		s.translateEchoQuotedError(srcV4, inner, v6Type, v6Code, extra, logger)
	default: // 6 (TCP): no NAT64-side flow state — see file comment
	}
}

// translateUDPQuotedError maps an ICMPv4 error whose quoted packet belongs to
// one of our outbound UDP sockets back to the owning client. The inner
// destination is restored from session state to the client's original
// address/port — what the client kernel matches its socket against; the
// inner source becomes pool6::<our egress IPv4> with the NAT-assigned port
// preserved, exactly the shape a conformant stateful NAT64 produces.
func (s *Service) translateUDPQuotedError(srcV4 [4]byte, inner icmpInnerPacket, v6Type, v6Code byte, extra uint32, logger *log.Logger) {
	quotedSport := binary.BigEndian.Uint16(inner.l4[0:2])
	quotedDport := binary.BigEndian.Uint16(inner.l4[2:4])

	var (
		sess *udpSession
		key  sessionKey
	)
	s.sessions.Range(func(k, v any) bool {
		sk := k.(sessionKey)
		ss := v.(*udpSession)
		if ss.localPort == quotedSport && ss.localIP == inner.src &&
			sk.dstAddr == inner.dst && sk.dstPort == quotedDport {
			sess, key = ss, sk
			return false
		}
		return true
	})
	if sess == nil {
		n := 0
		s.sessions.Range(func(k, v any) bool {
			sk := k.(sessionKey)
			ss := v.(*udpSession)
			logger.Debugf("NAT64 ICMP err demux miss: live %v.%d local=%s:%d vs quoted %s:%d → %s:%d",
				net.IP(sk.srcAddr[:]), sk.srcPort,
				net.IP(ss.localIP[:]), ss.localPort,
				net.IP(inner.src[:]), quotedSport, net.IP(inner.dst[:]), quotedDport)
			n++
			return true
		})
		if n == 0 {
			logger.Debugf("NAT64 ICMP err demux miss: no live UDP sessions (quoted %s:%d → %s:%d)",
				net.IP(inner.src[:]), quotedSport, net.IP(inner.dst[:]), quotedDport)
		}
		return
	}

	l4 := make([]byte, len(inner.l4))
	binary.BigEndian.PutUint16(l4[0:2], quotedSport)     // NAT-assigned source port preserved
	binary.BigEndian.PutUint16(l4[2:4], key.srcPort)     // client's original source port restored as destination
	binary.BigEndian.PutUint16(l4[4:6], uint16(len(l4))) // UDP length over the truncated data
	binary.BigEndian.PutUint16(l4[6:8], 0xffff)          // non-zero placeholder forces checksum rebuild
	copy(l4[8:], inner.l4[8:])                           // quoted payload, further truncated by the builder

	innerSrc := s.pool6AddrFor(inner.src)
	outerSrc := s.pool6AddrFor(srcV4)
	pkt := buildIPv6ICMPErrorPacket(
		outerSrc[:], key.srcAddr[:],
		v6Type, v6Code, extra,
		innerSrc[:], key.srcAddr[:],
		inner.ttl, 17,
		l4,
	)
	s.injectICMPv6(pkt, logger, "UDP", key, v6Type, v6Code, srcV4)
}

// translateEchoQuotedError maps an ICMPv4 error whose quoted packet is an
// Echo Request we forwarded (matched via its NAT-assigned identifier slot)
// back to the client with its own identifier restored.
func (s *Service) translateEchoQuotedError(srcV4 [4]byte, inner icmpInnerPacket, v6Type, v6Code byte, extra uint32, logger *log.Logger) {
	if inner.l4[0] != 8 { // ydn64 only ever emits Echo Requests toward IPv4
		return
	}
	allocID := binary.BigEndian.Uint16(inner.l4[4:6])
	v, ok := s.icmpSessions.Load(icmpSessionKey{dstAddr: inner.dst, id: allocID})
	if !ok {
		return
	}
	sess := v.(*icmpSession)

	seq := binary.BigEndian.Uint16(inner.l4[6:8])
	l4 := make([]byte, len(inner.l4))
	l4[0], l4[1] = 128, 0                              // Echo Request, as the client originally sent it
	binary.BigEndian.PutUint16(l4[4:6], sess.clientID) // client identifier restored
	binary.BigEndian.PutUint16(l4[6:8], seq)
	copy(l4[8:], inner.l4[8:])

	innerSrc := s.pool6AddrFor(inner.src)
	outerSrc := s.pool6AddrFor(srcV4)
	pkt := buildIPv6ICMPErrorPacket(
		outerSrc[:], sess.yggDst[:],
		v6Type, v6Code, extra,
		innerSrc[:], sess.yggDst[:],
		inner.ttl, 58,
		l4,
	)
	qKey := icmpQueryKey{srcAddr: sess.yggDst, dstAddr: inner.dst, id: sess.clientID}
	s.injectICMPv6(pkt, logger, "ICMP", qKey, v6Type, v6Code, srcV4)
}

// injectICMPv6 writes a synthesised error into the Yggdrasil network. The
// errLim budget is consumed here — after demux matched a live session — so
// unrelated host ICMP noise on the raw socket cannot drain the tokens meant
// for genuine translations of live flows.
func (s *Service) injectICMPv6(pkt []byte, logger *log.Logger, kind string, key any, v6Type, v6Code byte, srcV4 [4]byte) {
	if !s.errLim.allow(time.Now()) {
		if logger != nil {
			logger.Debugf("NAT64 ICMPv6 error inject (%s) rate-limited (%d/%d)", kind, v6Type, v6Code)
		}
		return
	}
	if _, err := s.ns.WritePacket(pkt); err != nil {
		if logger != nil {
			logger.Debugf("NAT64 ICMPv6 error inject (%s): %v", kind, err)
		}
		return
	}
	if logger != nil {
		logger.Debugf("NAT64 ICMPv4 %s → ICMPv6 %d/%d delivered (%s %v)", net.IP(srcV4[:]), v6Type, v6Code, kind, key)
	}
}

// sendUDPFlowUnreachable notifies the client that a UDP flow could not be
// established toward the IPv4 side (RFC 4443 §3.1 generation): v6Type/v6Code
// describe the failure; the quoted packet reconstructs the client's original
// datagram header (its payload was never seen on the IPv4 side, so the quote
// carries none).
func (s *Service) sendUDPFlowUnreachable(pool6Src [16]byte, key sessionKey, v6Type, v6Code byte, reason string, logger *log.Logger) {
	if !s.errLim.allow(time.Now()) {
		return
	}
	l4 := make([]byte, 8)
	binary.BigEndian.PutUint16(l4[0:2], key.srcPort)
	binary.BigEndian.PutUint16(l4[2:4], key.dstPort)
	binary.BigEndian.PutUint16(l4[4:6], 8)
	binary.BigEndian.PutUint16(l4[6:8], 0xffff)

	pkt := buildIPv6ICMPErrorPacket(
		pool6Src[:], key.srcAddr[:],
		v6Type, v6Code, 0,
		key.srcAddr[:], pool6Src[:],
		64, 17,
		l4,
	)
	if _, err := s.ns.WritePacket(pkt); err != nil {
		logger.Debugf("NAT64 UDP unreachable inject %v: %v", key, err)
		return
	}
	logger.Debugf("NAT64 UDP %v unreachable (%d/%d): %s", key, v6Type, v6Code, reason)
}

// sendUDPPortRefused surfaces an asynchronous ECONNREFUSED from the OS udp4
// socket — the kernel received a real ICMPv4 Port Unreachable for a datagram
// we sent — as an ICMPv6 Destination Unreachable/port-unreachable for the
// client, quoting the translated v4-side view of the flow.
func (s *Service) sendUDPPortRefused(sess *udpSession, key sessionKey, logger *log.Logger) {
	if !s.errLim.allow(time.Now()) {
		return
	}
	l4 := make([]byte, 8)
	binary.BigEndian.PutUint16(l4[0:2], sess.localPort)
	binary.BigEndian.PutUint16(l4[2:4], key.srcPort)
	binary.BigEndian.PutUint16(l4[4:6], 8)
	binary.BigEndian.PutUint16(l4[6:8], 0xffff)

	innerSrc := s.pool6AddrFor(sess.localIP)
	outerSrc := s.pool6AddrFor(key.dstAddr)
	pkt := buildIPv6ICMPErrorPacket(
		outerSrc[:], key.srcAddr[:],
		1, 4, 0,
		innerSrc[:], key.srcAddr[:],
		64, 17,
		l4,
	)
	if _, err := s.ns.WritePacket(pkt); err != nil {
		logger.Debugf("NAT64 UDP port-refused inject %v: %v", key, err)
		return
	}
	logger.Debugf("NAT64 UDP %v port unreachable reported to client", key)
}

// dialErrorToUnreachable maps a failed outbound dial onto an ICMPv6
// Destination Unreachable type/code (RFC 4443 §3.1 semantics).
func dialErrorToUnreachable(err error) (byte, byte) {
	var errno syscall.Errno
	if errors.As(err, &errno) {
		switch errno {
		case syscall.EACCES, syscall.EPERM:
			return 1, 1 // administratively prohibited
		case syscall.ENETUNREACH, syscall.EHOSTUNREACH, syscall.ENETDOWN:
			return 1, 0 // no route to destination
		}
	}
	return 1, 3 // address unreachable (generic)
}
