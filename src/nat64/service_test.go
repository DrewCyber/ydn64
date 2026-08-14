package nat64

import (
	"net"
	"testing"

	"github.com/DrewCyber/ydn64/src/config"
)

func TestNAT64InboundSourceAndDstCheck(t *testing.T) {
	cfg := config.NAT64Config{
		Pool6:      "300:1:2:3::/64",
		UDPTimeout: 300,
	}
	allowedSources := []string{"200:a:b:c::/64"}
	ignoredSubnets := []string{"10.0.0.0/8", "127.0.0.1/32"}

	s, err := NewService(cfg, allowedSources, ignoredSubnets, nil)
	if err != nil {
		t.Fatalf("failed to create NAT64 service: %v", err)
	}

	// Helpers to construct IPv6 addresses
	allowedSrcIP := net.ParseIP("200:a:b:c::1").To16()
	disallowedSrcIP := net.ParseIP("200:e:f::1").To16()
	spoofedSrcIP := net.ParseIP("300:1:2:3::5678").To16() // inside pool6
	outsideDstIP := net.ParseIP("400::1").To16()

	// Pool6 addresses (/64 prefix "300:1:2:3::", last 4 bytes at index 12:16 is IPv4)
	// 300:1:2:3:0:0:0102:0304 -> last 4 bytes: 01 02 03 04 -> 1.2.3.4
	pool6PublicDstIP := net.ParseIP("300:1:2:3::0102:0304").To16()
	// 300:1:2:3:0:0:0a00:0001 -> last 4 bytes: 0a 00 00 01 -> 10.0.0.1
	pool6PrivateDstIP := net.ParseIP("300:1:2:3::0a00:0001").To16()
	// 300:1:2:3:0:0:7f00:0001 -> last 4 bytes: 7f 00 00 01 -> 127.0.0.1
	pool6LoopbackDstIP := net.ParseIP("300:1:2:3::7f00:0001").To16()

	t.Run("UDP interceptor", func(t *testing.T) {
		// Test Case 1: Destination not in pool6
		pkt := make([]byte, 100)
		pkt[0] = 0x60
		pkt[6] = 17 // Next header = UDP
		copy(pkt[8:24], allowedSrcIP)
		copy(pkt[24:40], outsideDstIP)
		if s.interceptUDPPacket(pkt) {
			t.Errorf("expected interceptUDPPacket to return false for outside destination, got true")
		}

		// Test Case 2: Destination in pool6, source allowed, public destination IPv4
		pkt = make([]byte, 100)
		pkt[0] = 0x60
		pkt[6] = 17 // Next header = UDP
		copy(pkt[8:24], allowedSrcIP)
		copy(pkt[24:40], pool6PublicDstIP)
		if !s.interceptUDPPacket(pkt) {
			t.Errorf("expected interceptUDPPacket to return true for allowed source, got false")
		}

		// Test Case 2b: Destination in pool6, source allowed, but destination IPv4 is ignored private (10.0.0.1)
		pkt = make([]byte, 100)
		pkt[0] = 0x60
		pkt[6] = 17 // Next header = UDP
		copy(pkt[8:24], allowedSrcIP)
		copy(pkt[24:40], pool6PrivateDstIP)
		if !s.interceptUDPPacket(pkt) {
			t.Errorf("expected interceptUDPPacket to return true (consumed/dropped) for ignored private destination, got false")
		}

		// Test Case 2c: Destination in pool6, source allowed, but destination IPv4 is loopback (127.0.0.1)
		pkt = make([]byte, 100)
		pkt[0] = 0x60
		pkt[6] = 17 // Next header = UDP
		copy(pkt[8:24], allowedSrcIP)
		copy(pkt[24:40], pool6LoopbackDstIP)
		if !s.interceptUDPPacket(pkt) {
			t.Errorf("expected interceptUDPPacket to return true (consumed/dropped) for loopback destination, got false")
		}

		// Test Case 3: Destination in pool6, source not allowed
		pkt = make([]byte, 100)
		pkt[0] = 0x60
		pkt[6] = 17 // Next header = UDP
		copy(pkt[8:24], disallowedSrcIP)
		copy(pkt[24:40], pool6PublicDstIP)
		if !s.interceptUDPPacket(pkt) {
			t.Errorf("expected interceptUDPPacket to return true for disallowed source, got false")
		}

		// Test Case 4: Destination in pool6, source is in pool6 (spoofed)
		pkt = make([]byte, 100)
		pkt[0] = 0x60
		pkt[6] = 17 // Next header = UDP
		copy(pkt[8:24], spoofedSrcIP)
		copy(pkt[24:40], pool6PublicDstIP)
		if !s.interceptUDPPacket(pkt) {
			t.Errorf("expected interceptUDPPacket to return true for spoofed source, got false")
		}
	})

	t.Run("ICMPv6 interceptor", func(t *testing.T) {
		// Test Case 1: Destination not in pool6
		pkt := make([]byte, 100)
		pkt[0] = 0x60
		pkt[6] = 58  // Next header = ICMPv6
		pkt[40] = 128 // Type = Echo Request
		copy(pkt[8:24], allowedSrcIP)
		copy(pkt[24:40], outsideDstIP)
		if s.interceptICMPPacket(pkt) {
			t.Errorf("expected interceptICMPPacket to return false for outside destination, got true")
		}

		// Test Case 2: Destination in pool6, source is in pool6 (spoofed)
		pkt = make([]byte, 100)
		pkt[0] = 0x60
		pkt[6] = 58  // Next header = ICMPv6
		pkt[40] = 128 // Type = Echo Request
		copy(pkt[8:24], spoofedSrcIP)
		copy(pkt[24:40], pool6PublicDstIP)
		if !s.interceptICMPPacket(pkt) {
			t.Errorf("expected interceptICMPPacket to return true for spoofed source, got false")
		}

		// Test Case 3: Destination in pool6, source allowed, but private IPv4 destination
		pkt = make([]byte, 100)
		pkt[0] = 0x60
		pkt[6] = 58  // Next header = ICMPv6
		pkt[40] = 128 // Type = Echo Request
		copy(pkt[8:24], allowedSrcIP)
		copy(pkt[24:40], pool6PrivateDstIP)
		if !s.interceptICMPPacket(pkt) {
			t.Errorf("expected interceptICMPPacket to return true (consumed/dropped) for ignored private destination, got false")
		}
	})
}
