package nat64

import (
	"encoding/binary"
	"net"
	"testing"
	"time"
)

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
