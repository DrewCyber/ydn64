package nat64

import (
	"encoding/binary"
	"net"
	"testing"
)

func TestIpv6UpperLayerChecksum(t *testing.T) {
	// Let's test standard checksumming with a basic UDP-like layout
	src := net.ParseIP("2001:db8::1")
	dst := net.ParseIP("2001:db8::2")
	nextHeader := byte(17) // UDP

	upperLayer := []byte{
		0x12, 0x34, // Src port
		0x56, 0x78, // Dst port
		0x00, 0x0c, // Length (12)
		0x00, 0x00, // Checksum placeholder
		0xaa, 0xbb, 0xcc, 0xdd, // Payload
	}

	cs := ipv6UpperLayerChecksum(src, dst, nextHeader, upperLayer)
	if cs == 0 {
		t.Errorf("expected non-zero checksum for arbitrary data, got 0")
	}

	// Double checksum validation: verifying the checksum by computing it with
	// the computed checksum in place, which should result in 0xffff (when inverted, i.e., 0 after inversion?
	// Actually, the sum of words including the one's complement checksum is 0xffff,
	// so the inverted checksum of that should be 0x0000).
	binary.BigEndian.PutUint16(upperLayer[6:8], cs)
	csVerify := ipv6UpperLayerChecksum(src, dst, nextHeader, upperLayer)
	if csVerify != 0 {
		t.Errorf("expected verification checksum to be 0, got 0x%04x", csVerify)
	}
}

// TestBuildIPv6UDPPacketZeroChecksum checks that buildIPv6UDPPacket correctly converts a computed
// UDP checksum of 0x0000 to 0xFFFF.
func TestBuildIPv6UDPPacketZeroChecksum(t *testing.T) {
	// We need to engineer src, dst, ports and payload such that the checksum comes out to exactly 0x0000.
	// In one's-complement arithmetic, ^sum == 0 means sum == 0xffff (after folding).
	// Let's design a packet where everything sums up to a multiple of 0xffff.

	src := make([]byte, 16)
	dst := make([]byte, 16)

	// Since we are free to set payload and port, we can construct the sum step-by-step.
	// IPv6 Pseudo-header fields:
	//   src (16 bytes of 0) => sum = 0
	//   dst (16 bytes of 0) => sum = 0
	//   length (4 bytes): udpLen is 8 + payloadLen. Let's make payloadLen = 4. Total upperLayer length = 12 (0x000c).
	//                     binary.BigEndian.PutUint32(lenBuf, 12) => sum contribution = 0x000c
	//   nextHeader (17 = 0x0011) => sum contribution = 0x0011
	// At this point, pseudo-header sum = 0x000c + 0x0011 = 0x001d.
	//
	// UDP Header fields (offset 40):
	//   srcPort, dstPort, udpLen (12 = 0x000c)
	// Let's set srcPort = 0x0000, dstPort = 0x0000.
	// Sum contribution from UDP header (excluding checksum placeholder):
	//   0x000c (udpLen)
	// Total sum so far = 0x001d + 0x000c = 0x0029.
	//
	// We want the total sum of all words to fold to 0xffff, so ^sum will be 0x0000.
	// Remaining we need: 0xffff - 0x0029 = 0xffd6.
	// Since payload is 4 bytes, we can represent it as two 16-bit words.
	// Let's put 0xffd6 in the first 16-bit word, and 0x0000 in the second 16-bit word.
	// Then total sum = 0x0029 + 0xffd6 + 0x0000 = 0xffff.
	// When folded, sum = 0xffff.
	// ^sum = ^0xffff = 0x0000.
	// Thus, the computed checksum is 0x0000.
	// With the fix, buildIPv6UDPPacket must rewrite this to 0xFFFF.

	payload := []byte{0xff, 0xd6, 0x00, 0x00}
	pkt := buildIPv6UDPPacket(src, dst, 0, 0, payload)

	// The checksum field in the UDP header of the generated IPv6 packet is at offset 46 (pkt[46:48]).
	cs := binary.BigEndian.Uint16(pkt[46:48])
	if cs != 0xFFFF {
		t.Errorf("Expected checksum to be 0xFFFF, got 0x%04x", cs)
	}
}

// TestBuildIPv6ICMPEchoReplyPacketZeroChecksum checks that buildIPv6ICMPEchoReplyPacket
// does NOT convert a computed ICMPv6 checksum of 0x0000 to 0xFFFF, because 0x0000 is a valid
// ICMPv6 checksum.
func TestBuildIPv6ICMPEchoReplyPacketZeroChecksum(t *testing.T) {
	src := make([]byte, 16)
	dst := make([]byte, 16)

	// ICMPv6 pseudo-header contribution:
	//   src (16 B of 0) => sum = 0
	//   dst (16 B of 0) => sum = 0
	//   length (4 B): let's make data length = 4. icmpLen = 8 + 4 = 12 (0x000c).
	//                 sum contribution = 0x000c
	//   nextHeader (58 = 0x003a) => sum contribution = 0x003a
	// Total pseudo-header sum = 0x000c + 0x003a = 0x0046.
	//
	// ICMPv6 header contribution:
	//   type = 129, code = 0 => 0x8100
	//   checksum placeholder => 0x0000
	//   id = 0, seq = 0 => 0x0000
	// Total so far = 0x0046 + 0x8100 = 0x8146.
	//
	// We want the total sum of all words to fold to 0xffff, so ^sum will be 0x0000.
	// Remaining needed: 0xffff - 0x8146 = 0x7eb9.
	// Payload of 4 bytes: 0x7eb9 and 0x0000.
	// Total sum = 0x8146 + 0x7eb9 = 0xffff.
	// ^sum = 0x0000.
	// Let's verify that the output packet keeps 0x0000.

	payload := []byte{0x7e, 0xb9, 0x00, 0x00}
	pkt := buildIPv6ICMPEchoReplyPacket(src, dst, 0, 0, payload)

	// ICMPv6 checksum is at offset 42 (pkt[42:44]).
	cs := binary.BigEndian.Uint16(pkt[42:44])
	if cs != 0x0000 {
		t.Errorf("Expected ICMPv6 checksum to remain 0x0000, got 0x%04x", cs)
	}
}
