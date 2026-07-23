package nat64

import (
	"encoding/binary"
	"net"
	"sync/atomic"
	"time"

	"golang.org/x/net/icmp"
	"golang.org/x/net/ipv4"
)

// icmpSessionKey identifies an in-flight NAT64 ICMP echo exchange. ICMP has
// no ports, so (destination IPv4, echo ID) is the closest analogue of a UDP
// 4-tuple for demultiplexing replies read off the single shared raw socket.
type icmpSessionKey struct {
	dstAddr [4]byte
	id      uint16
}

// icmpSession tracks where an outstanding Echo Request's reply should be
// translated back to.
type icmpSession struct {
	pool6Src   [16]byte // pool6::IPv4 — becomes the ICMPv6 reply's source
	yggDst     [16]byte // original Yggdrasil sender — becomes the reply's destination
	lastSeenNs int64
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

	data := make([]byte, len(pkt)-48)
	copy(data, pkt[48:])

	go s.forwardICMP(srcAddr, pool6Src, dstIPv4, id, seq, data)
	return true
}

// forwardICMP records the session and sends a translated ICMPv4 Echo
// Request to the real IPv4 destination via the shared raw socket.
func (s *Service) forwardICMP(srcAddr, pool6Src [16]byte, dstIPv4 [4]byte, id, seq uint16, data []byte) {
	key := icmpSessionKey{dstAddr: dstIPv4, id: id}
	sess := &icmpSession{pool6Src: pool6Src, yggDst: srcAddr}
	atomic.StoreInt64(&sess.lastSeenNs, time.Now().UnixNano())
	s.icmpSessions.Store(key, sess)

	msg := icmp.Message{
		Type: ipv4.ICMPTypeEcho,
		Code: 0,
		Body: &icmp.Echo{ID: int(id), Seq: int(seq), Data: data},
	}
	b, err := msg.Marshal(nil)
	if err != nil {
		return
	}
	_, _ = s.icmpConn.WriteTo(b, &net.IPAddr{IP: net.IP(dstIPv4[:])})
}

// icmpReplyLoop continuously reads ICMPv4 Echo Replies off the single
// shared raw socket and translates each one back into a synthesised IPv6
// ICMPv6 Echo Reply, looking up the originating session by (source IPv4,
// echo ID).
func (s *Service) icmpReplyLoop() {
	buf := make([]byte, int(s.ns.MTU()))
	for {
		_ = s.icmpConn.SetReadDeadline(time.Now().Add(time.Second))
		n, peer, err := s.icmpConn.ReadFrom(buf)
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
		key := icmpSessionKey{dstAddr: srcAddr, id: uint16(echo.ID)}
		val, ok := s.icmpSessions.Load(key)
		if !ok {
			continue
		}
		sess := val.(*icmpSession)
		atomic.StoreInt64(&sess.lastSeenNs, time.Now().UnixNano())

		reply := buildIPv6ICMPEchoReplyPacket(sess.pool6Src[:], sess.yggDst[:], uint16(echo.ID), uint16(echo.Seq), echo.Data)
		_, _ = s.ns.WritePacket(reply)
	}
}
