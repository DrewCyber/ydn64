package nat64

import "encoding/binary"

// buildIPv6UDPPacket constructs a raw IPv6 + UDP packet ready to be injected
// into the Yggdrasil network via YggdrasilNetstack.WritePacket.
//
//	srcIP, dstIP  — 16-byte IPv6 addresses
//	srcPort       — source UDP port (network byte order semantics handled here)
//	dstPort       — destination UDP port
//	payload       — UDP payload
func buildIPv6UDPPacket(srcIP, dstIP []byte, srcPort, dstPort uint16, payload []byte) []byte {
	udpLen := 8 + len(payload)
	pkt := make([]byte, 40+udpLen)

	// ── IPv6 fixed header (40 bytes) ─────────────────────────────────────────
	pkt[0] = 0x60                                        // Version=6, Traffic Class=0, Flow Label=0 (bytes 1-3 already 0)
	binary.BigEndian.PutUint16(pkt[4:6], uint16(udpLen)) // Payload length
	pkt[6] = 17                                          // Next header = UDP
	pkt[7] = 64                                          // Hop limit
	copy(pkt[8:24], srcIP)
	copy(pkt[24:40], dstIP)

	// ── UDP header (8 bytes at offset 40) ────────────────────────────────────
	binary.BigEndian.PutUint16(pkt[40:42], srcPort)
	binary.BigEndian.PutUint16(pkt[42:44], dstPort)
	binary.BigEndian.PutUint16(pkt[44:46], uint16(udpLen))
	// pkt[46:48] = checksum — filled in below

	// ── UDP payload ───────────────────────────────────────────────────────────
	copy(pkt[48:], payload)

	// ── UDP checksum over IPv6 pseudo-header (mandatory per RFC 2460) ─────────
	cs := ipv6UpperLayerChecksum(pkt[8:24], pkt[24:40], 17, pkt[40:40+udpLen])
	binary.BigEndian.PutUint16(pkt[46:48], cs)

	return pkt
}

// buildIPv6ICMPEchoReplyPacket constructs a raw IPv6 + ICMPv6 Echo Reply
// packet ready to be injected into the Yggdrasil network, used by NAT64 to
// translate a real ICMPv4 Echo Reply back into ICMPv6.
//
//	srcIP, dstIP  — 16-byte IPv6 addresses (srcIP is pool6::embeddedIPv4)
//	id, seq       — echo identifier/sequence, copied from the ICMPv4 reply
//	data          — echo payload, copied from the ICMPv4 reply
func buildIPv6ICMPEchoReplyPacket(srcIP, dstIP []byte, id, seq uint16, data []byte) []byte {
	icmpLen := 8 + len(data) // type(1) + code(1) + checksum(2) + id(2) + seq(2) + data
	pkt := make([]byte, 40+icmpLen)

	// ── IPv6 fixed header (40 bytes) ─────────────────────────────────────────
	pkt[0] = 0x60
	binary.BigEndian.PutUint16(pkt[4:6], uint16(icmpLen))
	pkt[6] = 58 // Next header = ICMPv6
	pkt[7] = 64 // Hop limit
	copy(pkt[8:24], srcIP)
	copy(pkt[24:40], dstIP)

	// ── ICMPv6 Echo Reply header (8 bytes at offset 40) ──────────────────────
	pkt[40] = 129 // Type = Echo Reply
	pkt[41] = 0   // Code
	// pkt[42:44] = checksum — filled in below
	binary.BigEndian.PutUint16(pkt[44:46], id)
	binary.BigEndian.PutUint16(pkt[46:48], seq)

	// ── Echo payload ──────────────────────────────────────────────────────────
	copy(pkt[48:], data)

	// ── ICMPv6 checksum over IPv6 pseudo-header (mandatory per RFC 4443) ─────
	cs := ipv6UpperLayerChecksum(pkt[8:24], pkt[24:40], 58, pkt[40:40+icmpLen])
	binary.BigEndian.PutUint16(pkt[42:44], cs)

	return pkt
}

// ipv6UpperLayerChecksum computes the one's-complement checksum over the
// IPv6 pseudo-header and an upper-layer segment (header + payload). Used for
// both UDP (nextHeader=17) and ICMPv6 (nextHeader=58) — both use the same
// IPv6 pseudo-header checksum construction.
//
// Pseudo-header layout (RFC 2460 §8.1):
//
//	src addr        (16 B)
//	dst addr        (16 B)
//	upper-layer len (4 B, big-endian)
//	zeros           (3 B)
//	next hdr        (1 B)
func ipv6UpperLayerChecksum(src, dst []byte, nextHeader byte, upperLayer []byte) uint16 {
	var sum uint32

	// Pseudo-header
	addBytes := func(b []byte) {
		for i := 0; i+1 < len(b); i += 2 {
			sum += uint32(binary.BigEndian.Uint16(b[i:]))
		}
		if len(b)%2 != 0 {
			sum += uint32(b[len(b)-1]) << 8
		}
	}

	addBytes(src)
	addBytes(dst)
	var lenBuf [4]byte
	binary.BigEndian.PutUint32(lenBuf[:], uint32(len(upperLayer)))
	addBytes(lenBuf[:])
	sum += uint32(nextHeader) // no shift needed; upper byte of 2-byte word = 0

	addBytes(upperLayer)

	// Fold carry into 16 bits
	for sum > 0xffff {
		sum = (sum >> 16) + (sum & 0xffff)
	}
	return ^uint16(sum)
}
