package nat64

import (
	"encoding/binary"
	"net"
	"testing"
	"time"
)

// buildTruncatedICMPv6Frame crafts a frame whose IPv6 header chain ends
// exactly at end-of-frame: a 40-byte fixed header plus one 8-byte extension
// header whose NextHeader is ICMPv6, with no upper-layer bytes following.
// The payload-length field is consistent with the frame (plen = 8), so every
// structural check in interceptICMPPacket passes; the upper-layer slice at
// l4Offset is empty. Regression frames for code-review-2026-08-24 #1.
func buildTruncatedICMPv6Frame(t *testing.T, extHeader byte, fragWord uint16, ident uint32) []byte {
	t.Helper()
	pkt := make([]byte, 48)
	pkt[0] = 0x60 // version 6
	binary.BigEndian.PutUint16(pkt[4:6], 8) // plen covers exactly the ext header
	pkt[6] = extHeader                      // first Next Header
	pkt[7] = 64                             // hop limit
	copy(pkt[8:24], net.ParseIP("200:a:b:c::1").To16())          // allowed source
	copy(pkt[24:40], net.ParseIP("300:1:2:3::192.0.2.5").To16()) // pool6 destination
	// Extension header at offset 40 announces ICMPv6 as the next protocol.
	switch extHeader {
	case 60: // Destination Options: HdrExtLen = 0 → exactly 8 bytes
		pkt[40] = 58
		pkt[41] = 0
	case 44: // Fragment: word at [42:44] (offset|M), identification at [44:48]
		pkt[40] = 58
		binary.BigEndian.PutUint16(pkt[42:44], fragWord)
		binary.BigEndian.PutUint32(pkt[44:48], ident)
	default:
		t.Fatalf("unsupported extension header %d", extHeader)
	}
	return pkt
}

// TestInterceptTruncatedUpperLayerFrames locks in the code-review-2026-08-24
// #1 fix: frames whose header chain terminates exactly at end-of-frame used
// to panic with index-out-of-range (msg[0]/frag[0]) inside the single NIC
// read-loop goroutine — an allowed peer could kill the whole process with one
// crafted frame. Each must be consumed (dropped) and never forwarded.
func TestInterceptTruncatedUpperLayerFrames(t *testing.T) {
	cases := []struct {
		name     string
		ext      byte
		fragWord uint16
	}{
		{"dst-options chain ends at end-of-frame", 60, 0},
		{"first fragment header, no L4 bytes, M clear", 44, 0},
		{"first fragment header, no L4 bytes, M set", 44, 1},
		{"non-first fragment header, no payload", 44, 1<<3 | 1}, // offset unit 1, M set
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			env := newICMPTestEnv(t)
			pkt := buildTruncatedICMPv6Frame(t, tc.ext, tc.fragWord, 0xdeadbeef)

			if !env.svc.interceptICMPPacket(append([]byte(nil), pkt...)) {
				t.Fatal("truncated datagram should be consumed (dropped), not passed to gVisor")
			}
			time.Sleep(150 * time.Millisecond)
			if got := len(env.conn.written()); got != 0 {
				t.Fatalf("truncated datagram was forwarded to the raw socket (%d frames)", got)
			}
		})
	}
}

// TestInterceptValidatesInboundEchoRequest covers the R16 inbound checks on
// the raw-socket path: the IPv6 payload length must match the frame exactly,
// and the ICMPv6 checksum must verify before anything is relayed toward the
// IPv4 internet.
func TestInterceptValidatesInboundEchoRequest(t *testing.T) {
	env := newICMPTestEnv(t)

	req := buildIPv6EchoRequest(
		net.ParseIP("200:a:b:c::1"),
		net.ParseIP("300:1:2:3::192.0.2.5"),
		0x1234, 7, []byte("validate-me"),
	)

	if !env.svc.interceptICMPPacket(append([]byte(nil), req...)) {
		t.Fatal("valid echo request was not consumed")
	}
	// Wait for the forwarded copy so the positive control is proven end to end.
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) && len(env.conn.written()) == 0 {
		time.Sleep(5 * time.Millisecond)
	}
	if len(env.conn.written()) == 0 {
		t.Fatal("valid echo request was not forwarded to the raw socket")
	}

	tests := []struct {
		name   string
		mutate func(pkt []byte)
	}{
		{
			name: "corrupted ICMPv6 checksum",
			mutate: func(pkt []byte) {
				pkt[42] ^= 0xFF // ICMPv6 checksum, first byte
			},
		},
		{
			name: "zeroed ICMPv6 checksum",
			mutate: func(pkt []byte) {
				binary.BigEndian.PutUint16(pkt[42:44], 0)
			},
		},
		{
			name: "payload length shorter than frame",
			mutate: func(pkt []byte) {
				binary.BigEndian.PutUint16(pkt[4:6], uint16(len(pkt)-40-8))
			},
		},
		{
			name: "payload length longer than frame",
			mutate: func(pkt []byte) {
				binary.BigEndian.PutUint16(pkt[4:6], uint16(len(pkt)-40+16))
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			pkt := append([]byte(nil), req...)
			tc.mutate(pkt)

			before := len(env.conn.written())
			if !env.svc.interceptICMPPacket(pkt) {
				t.Fatal("malformed echo request should still be consumed (dropped), not passed to gVisor")
			}
			time.Sleep(150 * time.Millisecond)
			if got := len(env.conn.written()); got != before {
				t.Fatalf("malformed request was forwarded (%d new frames on the raw socket)", got-before)
			}
		})
	}
}
