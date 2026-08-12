package nat64

import (
	"net"
	"testing"

	"github.com/DrewCyber/ydn64/src/config"
)

func TestNAT64InboundSourceCheck(t *testing.T) {
	cfg := config.NAT64Config{
		Pool6:      "300:1:2:3::/64",
		UDPTimeout: 30,
	}
	allowedSources := []string{"200:a:b:c::/64"}

	s, err := NewService(cfg, allowedSources, nil)
	if err != nil {
		t.Fatalf("failed to create NAT64 service: %v", err)
	}

	// Helpers to construct IPv6 addresses
	pool6IP := net.ParseIP("300:1:2:3::1234").To16()
	allowedSrcIP := net.ParseIP("200:a:b:c::1").To16()
	disallowedSrcIP := net.ParseIP("200:e:f::1").To16()
	spoofedSrcIP := net.ParseIP("300:1:2:3::5678").To16() // inside pool6
	outsideDstIP := net.ParseIP("400::1").To16()

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

		// Test Case 2: Destination in pool6, source allowed and valid
		pkt = make([]byte, 100)
		pkt[0] = 0x60
		pkt[6] = 17 // Next header = UDP
		copy(pkt[8:24], allowedSrcIP)
		copy(pkt[24:40], pool6IP)
		if !s.interceptUDPPacket(pkt) {
			t.Errorf("expected interceptUDPPacket to return true for allowed source, got false")
		}

		// Test Case 3: Destination in pool6, source not allowed
		pkt = make([]byte, 100)
		pkt[0] = 0x60
		pkt[6] = 17 // Next header = UDP
		copy(pkt[8:24], disallowedSrcIP)
		copy(pkt[24:40], pool6IP)
		if !s.interceptUDPPacket(pkt) {
			t.Errorf("expected interceptUDPPacket to return true for disallowed source, got false")
		}

		// Test Case 4: Destination in pool6, source is in pool6 (spoofed)
		pkt = make([]byte, 100)
		pkt[0] = 0x60
		pkt[6] = 17 // Next header = UDP
		copy(pkt[8:24], spoofedSrcIP)
		copy(pkt[24:40], pool6IP)
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
		copy(pkt[24:40], pool6IP)
		if !s.interceptICMPPacket(pkt) {
			t.Errorf("expected interceptICMPPacket to return true for spoofed source, got false")
		}
	})
}
