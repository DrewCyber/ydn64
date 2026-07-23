package nat64

import (
	"encoding/binary"
	"net"
	"sync/atomic"
	"time"
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
type udpSession struct {
	outConn    *net.UDPConn // connected UDP4 socket to the real IPv4 server
	pool6Src   [16]byte     // pool6::IPv4 — used as source address in IPv6 replies
	srcAddr    [16]byte     // yggdrasil source — used as destination address in replies
	srcPort    uint16       // yggdrasil source port
	dstPort    uint16       // real IPv4 destination port
	lastSeenNs int64        // Unix nanosecond timestamp, updated atomically
}

// interceptUDPPacket is installed as the NIC-level packet interceptor.
// It runs in the NIC read goroutine; pkt is valid only for the duration of
// this call — all needed bytes are copied before any goroutine is spawned.
func (s *Service) interceptUDPPacket(pkt []byte) bool {
	// Minimum: 40 (IPv6 header) + 8 (UDP header) = 48 bytes.
	if len(pkt) < 48 {
		return false
	}
	// Version must be 6.
	if pkt[0]>>4 != 6 {
		return false
	}
	// Next header must be UDP (17).
	if pkt[6] != 17 {
		return false
	}
	// Destination must be in the pool6 subnet.
	dstIP := net.IP(pkt[24:40])
	if !s.pool6Net.Contains(dstIP) {
		return false
	}

	// Source check — silently drop disallowed sources.
	srcIP := net.IP(pkt[8:24])
	if !s.isAllowed(srcIP) {
		return true // consumed (dropped)
	}

	// Copy all data we need before returning (pkt is the NIC's reused buffer).
	var srcAddr, pool6Src [16]byte
	copy(srcAddr[:], pkt[8:24])
	copy(pool6Src[:], pkt[24:40]) // destination = pool6::IPv4 → becomes reply source

	srcPort := binary.BigEndian.Uint16(pkt[40:42])
	dstPort := binary.BigEndian.Uint16(pkt[42:44])

	var dstIPv4 [4]byte
	copy(dstIPv4[:], pkt[36:40]) // last 4 bytes of pool6 destination = embedded IPv4

	payload := make([]byte, len(pkt)-48)
	copy(payload, pkt[48:])

	go s.forwardUDP(srcAddr, srcPort, pool6Src, dstIPv4, dstPort, payload)
	return true
}

// forwardUDP looks up (or creates) a UDP session and forwards the payload to
// the real IPv4 destination.
func (s *Service) forwardUDP(
	srcAddr [16]byte, srcPort uint16,
	pool6Src [16]byte,
	dstIPv4 [4]byte, dstPort uint16,
	payload []byte,
) {
	key := sessionKey{
		srcAddr: srcAddr,
		srcPort: srcPort,
		dstAddr: dstIPv4,
		dstPort: dstPort,
	}

	val, ok := s.sessions.Load(key)
	if !ok {
		// Create new outbound UDP4 connection.
		dstUDPAddr := &net.UDPAddr{IP: net.IP(dstIPv4[:]), Port: int(dstPort)}
		conn, err := net.DialUDP("udp4", nil, dstUDPAddr)
		if err != nil {
			return
		}
		sess := &udpSession{
			outConn:  conn,
			pool6Src: pool6Src,
			srcAddr:  srcAddr,
			srcPort:  srcPort,
			dstPort:  dstPort,
		}
		atomic.StoreInt64(&sess.lastSeenNs, time.Now().UnixNano())

		actual, loaded := s.sessions.LoadOrStore(key, sess)
		if loaded {
			// Another goroutine raced and created the session first.
			conn.Close()
			val = actual
		} else {
			go s.udpReplyLoop(sess, key)
			val = sess
		}
	}

	sess := val.(*udpSession)
	atomic.StoreInt64(&sess.lastSeenNs, time.Now().UnixNano())
	_, _ = sess.outConn.Write(payload)
}

// udpReplyLoop reads replies from the real IPv4 server and sends them back
// into the Yggdrasil network as synthesised IPv6 UDP packets.
func (s *Service) udpReplyLoop(sess *udpSession, key sessionKey) {
	defer func() {
		s.sessions.Delete(key)
		sess.outConn.Close()
	}()

	buf := make([]byte, int(s.ns.MTU()))
	for {
		// Set a rolling read deadline; reset on each successful read.
		_ = sess.outConn.SetReadDeadline(time.Now().Add(s.udpTimeout))
		n, err := sess.outConn.Read(buf)
		if err != nil {
			return // timeout or connection closed
		}
		atomic.StoreInt64(&sess.lastSeenNs, time.Now().UnixNano())

		// Reply: src = pool6Src:dstPort, dst = yggdrasil srcAddr:srcPort.
		pkt := buildIPv6UDPPacket(
			sess.pool6Src[:], sess.srcAddr[:],
			sess.dstPort, sess.srcPort,
			buf[:n],
		)
		_, _ = s.ns.WritePacket(pkt)
	}
}
