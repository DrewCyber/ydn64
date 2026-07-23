package nat64

import "encoding/binary"

// buildIPv6UDPPacket constructs a raw IPv6 + UDP packet ready to be injected
// into the Yggdrasil network via YggdrasilNetstack.WritePacket.
//
//   srcIP, dstIP  — 16-byte IPv6 addresses
//   srcPort       — source UDP port (network byte order semantics handled here)
//   dstPort       — destination UDP port
//   payload       — UDP payload
func buildIPv6UDPPacket(srcIP, dstIP []byte, srcPort, dstPort uint16, payload []byte) []byte {
	udpLen := 8 + len(payload)
	pkt := make([]byte, 40+udpLen)

	// ── IPv6 fixed header (40 bytes) ─────────────────────────────────────────
	pkt[0] = 0x60 // Version=6, Traffic Class=0, Flow Label=0 (bytes 1-3 already 0)
	binary.BigEndian.PutUint16(pkt[4:6], uint16(udpLen)) // Payload length
	pkt[6] = 17                                           // Next header = UDP
	pkt[7] = 64                                           // Hop limit
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
	cs := ipv6UDPChecksum(pkt[8:24], pkt[24:40], pkt[40:40+udpLen])
	binary.BigEndian.PutUint16(pkt[46:48], cs)

	return pkt
}

// ipv6UDPChecksum computes the one's-complement checksum over the IPv6
// pseudo-header and the UDP segment (header + payload).
//
// Pseudo-header layout (RFC 2460 §8.1):
//
//	src addr  (16 B)
//	dst addr  (16 B)
//	UDP length (4 B, big-endian)
//	zeros      (3 B)
//	next hdr   (1 B) = 17
func ipv6UDPChecksum(src, dst, udpSegment []byte) uint16 {
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
	binary.BigEndian.PutUint32(lenBuf[:], uint32(len(udpSegment)))
	addBytes(lenBuf[:])
	sum += 17 // next header = UDP (no shift needed; upper byte of 2-byte word = 0)

	addBytes(udpSegment)

	// Fold carry into 16 bits
	for sum > 0xffff {
		sum = (sum >> 16) + (sum & 0xffff)
	}
	return ^uint16(sum)
}
