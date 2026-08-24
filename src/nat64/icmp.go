package nat64

import (
	"encoding/binary"
	"net"
	"sync/atomic"
	"time"

	"github.com/gologme/log"
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
// NIC read path. It consumes Echo Requests addressed to pool6 destinations —
// including those arriving behind IPv6 extension headers or as fragments
// (RFC 8200 §4.5, RFC 6146 §3.4) — and lets everything else reach gVisor.
func (s *Service) interceptICMPPacket(pkt []byte) bool {
	// Minimum: 40 (IPv6 header) + 8 (ICMPv6 echo header) = 48 bytes.
	if len(pkt) < 48 {
		return false
	}
	info, status := parseIPv6HeaderChain(pkt)
	if status != chainICMPv6 {
		// Other protocols belong to their own forwarders; malformed chains
		// are dropped by the same fall-through (gVisor discards them).
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

	var dstIPv4 [4]byte
	copy(dstIPv4[:], pkt[36:40]) // last 4 bytes of pool6 destination = embedded IPv4
	if s.isIgnoredDst(net.IP(dstIPv4[:])) {
		return true // consumed (dropped)
	}

	// Structural validation of each frame: the IPv6 payload-length header
	// field must match the actual frame size — a mismatched frame is
	// malformed or crafted.
	plen := int(binary.BigEndian.Uint16(pkt[4:6]))
	if plen < 8 || len(pkt)-40 != plen {
		return true // consumed (dropped): malformed frame
	}

	key := reasmKey{src: srcAddr, dst: pool6Src, ident: info.fragIdent}
	if logger := s.serviceLogger(); logger != nil {
		logger.Debugf("NAT64 ICMP chain: status=%d l4off=%d frag=%v units=%d more=%v ident=%#x plen=%d framelen=%d",
			status, info.l4Offset, info.isFrag, info.fragOffset, info.fragMore, info.fragIdent, plen, len(pkt))
	}
	if !info.isFrag {
		msg := pkt[info.l4Offset:]
		if msg[0] != 128 { // Echo Request only; everything else passes to gVisor
			return false
		}
		// Checksum over the whole datagram's pseudo-header; relaying
		// unverified frames would let an allowed peer inject garbage into
		// the v4 path under ydn64's own source address.
		if cs := ipv6UpperLayerChecksum(srcAddr[:], pool6Src[:], 58, msg); cs != 0 {
			return true // consumed (dropped): invalid checksum
		}
		return s.handleEchoRequest(msg, srcAddr, pool6Src)
	}

	// Fragmented datagram (RFC 8200 §4.5). The first fragment reveals the
	// upper-layer type; non-echo datagrams stay with gVisor — but if later
	// fragments were already buffered here, dropping the datagram entirely
	// beats handing gVisor a half-datagram it can never complete.
	frag := pkt[info.l4Offset:]
	if info.fragOffset == 0 && frag[0] != 128 {
		if s.reasm.cancel(key) {
			return true
		}
		return false
	}

	complete := s.reasm.add(key, info.fragOffset, info.fragMore, frag, time.Now())
	if logger := s.serviceLogger(); logger != nil {
		if complete == nil {
			logger.Debugf("NAT64 ICMP frag buffered/shed (pending=%d bytes=%d)", s.reasm.pending(), s.reasm.buffered())
		} else {
			logger.Debugf("NAT64 ICMP frag complete: %d-byte PDU", len(complete))
		}
	}
	if complete == nil {
		return true // still incomplete, or shed by the guard rails
	}
	if complete[0] != 128 {
		return true
	}
	// Checksum verification happens here, on the reassembled PDU: fragments
	// carry pieces of one checksummed datagram, not checksums of their own.
	if cs := ipv6UpperLayerChecksum(srcAddr[:], pool6Src[:], 58, complete); cs != 0 {
		return true // consumed (dropped): invalid reassembled checksum
	}
	return s.handleEchoRequest(complete, srcAddr, pool6Src)
}

// handleEchoRequest processes one complete ICMPv6 Echo Request message
// (bytes starting at the type field): it registers/refreshes the session,
// allocates the NAT identifier and forwards the translated request toward
// the real IPv4 host. Runs on the NIC read loop.
func (s *Service) handleEchoRequest(msg []byte, srcAddr, pool6Src [16]byte) bool {
	id := binary.BigEndian.Uint16(msg[4:6])
	seq := binary.BigEndian.Uint16(msg[6:8])

	data := make([]byte, len(msg)-8)
	copy(data, msg[8:])

	dstIPv4, ok := s.pref64.Extract(net.IP(pool6Src[:]))
	if !ok {
		return true // consumed (dropped): non-canonical pool6 destination
	}

	sess := s.registerICMPSession(srcAddr, pool6Src, dstIPv4, id)
	if sess == nil {
		return true // consumed (dropped): table full or no identifier available
	}
	s.drainWG.Add(1)
	go func() {
		defer s.drainWG.Done()
		s.forwardICMP(sess, dstIPv4, seq, data)
	}()
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
// identifier in place of the client's. A local-level send failure (no route,
// permissions) is reported back to the client as an ICMPv6 Destination
// Unreachable (RFC 4443 §3.1) quoting the original request.
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
	if _, err := conn.WriteTo(b, &net.IPAddr{IP: net.IP(dstIPv4[:])}); err == nil {
		return
	} else if logger := s.logger.Load(); logger != nil && s.errLim.allow(time.Now()) {
		l4 := make([]byte, 8+len(data))
		l4[0], l4[1] = 128, 0 // the client's original Echo Request header
		binary.BigEndian.PutUint16(l4[4:6], sess.clientID)
		binary.BigEndian.PutUint16(l4[6:8], seq)
		copy(l4[8:], data)
		pkt := buildIPv6ICMPErrorPacket(
			sess.pool6Src[:], sess.yggDst[:],
			1, 0, 0,
			sess.yggDst[:], sess.pool6Src[:],
			64, 58,
			l4,
		)
		if _, err := s.ns.WritePacket(pkt); err == nil {
			logger.Debugf("NAT64 ICMP echo toward %s undeliverable (%v); client notified", net.IP(dstIPv4[:]), err)
		}
	}
}

// icmpReplyLoop continuously reads ICMPv4 messages off the single shared raw
// socket. Echo Replies are translated back into ICMPv6 Echo Replies for the
// originating client; error classes (Destination Unreachable, Time Exceeded,
// Parameter Problem, ...) go through handleICMPv4Error, which demuxes them
// against live NAT64 sessions (RFC 7915 §4.2/§4.3). Messages that match
// neither — including errors about unrelated host traffic the raw socket
// observes — are ignored.
func (s *Service) icmpReplyLoop(logger *log.Logger) {
	buf := make([]byte, icmpReadBufSize)
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
		if n < 8 {
			continue
		}

		ipAddr, ok := peer.(*net.IPAddr)
		if !ok {
			continue
		}
		ip4 := ipAddr.IP.To4()
		if ip4 == nil {
			continue
		}
		var srcAddr [4]byte
		copy(srcAddr[:], ip4)

		if buf[0] == byte(ipv4.ICMPTypeEchoReply) {
			msg, err := icmp.ParseMessage(1 /* IANA ICMP protocol number */, buf[:n])
			if err != nil {
				continue
			}
			echo, ok := msg.Body.(*icmp.Echo)
			if !ok {
				continue
			}
			s.translateICMPv4Reply(srcAddr, echo)
			continue
		}
		s.handleICMPv4Error(srcAddr, buf[:n], logger)
	}
}

// translateICMPv4Reply maps one real ICMPv4 Echo Reply back to its Yggdrasil
// client: the session is looked up by (reply source, NAT-assigned
// identifier), the client's own identifier is restored into the reply, and
// the synthesised IPv6 packet is injected into the netstack. Replies larger
// than the Yggdrasil MTU — possible only for reassembled oversized requests
// (RFC 6146 §3.4) — are emitted as proper IPv6 fragments so they survive the
// peer's MTU enforcement. Reports whether the reply was translated.
func (s *Service) translateICMPv4Reply(srcV4 [4]byte, echo *icmp.Echo) bool {
	key := icmpSessionKey{dstAddr: srcV4, id: uint16(echo.ID)}
	val, ok := s.icmpSessions.Load(key)
	if !ok {
		return false // no matching session: unsolicited or expired reply
	}
	sess := val.(*icmpSession)
	atomic.StoreInt64(&sess.lastSeenNs, time.Now().UnixNano())

	reply := buildIPv6ICMPEchoReplyPacket(sess.pool6Src[:], sess.yggDst[:], sess.clientID, uint16(echo.Seq), echo.Data)
	ident := uint32(replyFragIdent.Add(1))
	ok2 := true
	for _, p := range fragmentIPv6Packet(reply, int(s.ns.MTU()), ident) {
		if _, err := s.ns.WritePacket(p); err != nil {
			ok2 = false
			break
		}
	}
	return ok2
}
