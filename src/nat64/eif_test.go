package nat64

import (
	"encoding/binary"
	"net"
	"sync/atomic"
	"testing"
	"time"
)

// TestBuildIPv6UDPDatagram verifies the synthesised unsolicited-delivery
// packet: framing, address/port placement, and a pseudo-header checksum that
// actually verifies to zero.
func TestBuildIPv6UDPDatagram(t *testing.T) {
	src := net.ParseIP("300:1:2:3::7f00:1").To16()
	dst := net.ParseIP("200:a:b:c::9").To16()
	payload := []byte("unsolicited hello")

	pkt := buildIPv6UDPDatagram(src, dst, 5353, 41234, payload)
	if len(pkt) != 40+8+len(payload) {
		t.Fatalf("packet length = %d, want %d", len(pkt), 40+8+len(payload))
	}
	if pkt[0]>>4 != 6 || pkt[6] != 17 {
		t.Fatalf("version/nh = %d/%d, want 6/17", pkt[0]>>4, pkt[6])
	}
	if got := binary.BigEndian.Uint16(pkt[4:6]); int(got) != 8+len(payload) {
		t.Errorf("payload length field = %d, want %d", got, 8+len(payload))
	}
	if got := net.IP(pkt[8:24]); !got.Equal(src) {
		t.Errorf("src = %v, want %v", got, src)
	}
	if got := net.IP(pkt[24:40]); !got.Equal(dst) {
		t.Errorf("dst = %v, want %v", got, dst)
	}
	if got := binary.BigEndian.Uint16(pkt[40:42]); got != 5353 {
		t.Errorf("sport = %d, want 5353", got)
	}
	if got := binary.BigEndian.Uint16(pkt[42:44]); got != 41234 {
		t.Errorf("dport = %d, want 41234", got)
	}
	udpSeg := pkt[40:]
	if cs := ipv6UpperLayerChecksum(pkt[8:24], pkt[24:40], 17, udpSeg); cs != 0 {
		t.Errorf("checksum does not verify (verification sum = 0x%04x)", cs)
	}
}

// TestBuildIPv6UDPDatagramZeroChecksumRule pins RFC 768 §3.2 / RFC 8200 §8.1:
// a computed checksum of 0x0000 is transmitted as 0xFFFF (zero would mean
// "no checksum", which IPv6 forbids). A payload whose checksum genuinely
// computes to zero is found by brute force so the rule is exercised on the
// real code path rather than mocked.
func TestBuildIPv6UDPDatagramZeroChecksumRule(t *testing.T) {
	src := net.ParseIP("300:1:2:3::7f00:1").To16()
	dst := net.ParseIP("200:a:b:c::9").To16()

	segBase := func(payload []byte) []byte {
		seg := make([]byte, 8+len(payload))
		binary.BigEndian.PutUint16(seg[0:2], 5353)
		binary.BigEndian.PutUint16(seg[2:4], 41234)
		binary.BigEndian.PutUint16(seg[4:6], uint16(len(seg)))
		copy(seg[8:], payload)
		return seg
	}

	var found []byte
	for b := 0; b < 256 && found == nil; b++ {
		payload := []byte{byte(b)}
		if ipv6UpperLayerChecksum(src, dst, 17, segBase(payload)) == 0 {
			found = payload
		}
	}
	if found == nil {
		for v := 0; v < 65536 && found == nil; v++ {
			payload := []byte{byte(v >> 8), byte(v)}
			if ipv6UpperLayerChecksum(src, dst, 17, segBase(payload)) == 0 {
				found = payload
			}
		}
	}
	if found == nil {
		t.Fatal("no payload with a zero checksum found; cannot exercise the rule")
	}

	pkt := buildIPv6UDPDatagram(src, dst, 5353, 41234, found)
	if got := binary.BigEndian.Uint16(pkt[46:48]); got != 0xffff {
		t.Fatalf("transmitted checksum = 0x%04x, want 0xffff for computed-zero case", got)
	}
}

// TestEndpointIndependentFiltering drives REQ-8 end to end against a live
// BIB: under the default address-dependent filtering a never-contacted
// sender is dropped, but after reloading to endpoint-independent the same
// sender's datagram is delivered — synthesised as IPv6/UDP from
// pool6::sender — WITHOUT creating session state or refreshing any timer.
func TestEndpointIndependentFiltering(t *testing.T) {
	env := newUDPTestEnv(t, 30)
	client := net.ParseIP("200:a:b:c::1").To16()

	// Establish the mapping: one client socket → echo server on 127.0.0.1.
	env.inject(t, client, 48000, env.echoPort, []byte("setup"))
	if got := parseOutboundUDP(t, env.readOutbound(t),
		net.ParseIP("300:1:2:3::7f00:0001"), client, env.echoPort, 48000); string(got) != "setup" {
		t.Fatalf("setup reply = %q, want %q", got, "setup")
	}
	bib := firstBIB(t, env.svc)

	// Rogue sender from an IPv4 address the client never contacted. Bound to
	// an explicit port so the injected source port is assertable.
	rogue, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.ParseIP("127.0.0.2"), Port: 0})
	if err != nil {
		t.Fatalf("rogue ListenUDP: %v", err)
	}
	defer rogue.Close()
	roguePort := uint16(rogue.LocalAddr().(*net.UDPAddr).Port)
	target := &net.UDPAddr{IP: net.IP(append([]byte(nil), bib.localIP[:]...)), Port: int(bib.localPort)}

	t.Run("address-dependent drops the unknown sender", func(t *testing.T) {
		if _, err := rogue.WriteToUDP([]byte("eif-must-drop"), target); err != nil {
			t.Fatalf("rogue send: %v", err)
		}
		env.assertNoOutbound(t, 400*time.Millisecond)
		if n := len(env.cap.packets()); n != 0 {
			t.Fatalf("%d packet(s) injected under address-dependent filtering", n)
		}
	})

	t.Run("endpoint-independent delivers it without state", func(t *testing.T) {
		env.svc.Reload(nat64CfgWithFiltering("endpoint-independent"), []string{"200:a:b:c::/64"}, nil)
		sessionsBefore := countSessions(env.svc)
		bibsBefore := countBIBs(env.svc)
		lastSeenBefore := atomic.LoadInt64(&bib.lastSeenNs)

		const payload = "eif-unsolicited"
		if _, err := rogue.WriteToUDP([]byte(payload), target); err != nil {
			t.Fatalf("rogue send: %v", err)
		}

		deadline := time.Now().Add(5 * time.Second)
		var pkt []byte
		for pkt == nil {
			pkts := env.cap.packets()
			if len(pkts) > 0 {
				pkt = pkts[len(pkts)-1]
				break
			}
			if time.Now().After(deadline) {
				t.Fatal("timed out waiting for the EIF-injected datagram")
			}
			time.Sleep(20 * time.Millisecond)
		}

		got := parseOutboundUDP(t, pkt,
			net.ParseIP("300:1:2:3::7f00:0002"), client, roguePort, 48000)
		if string(got) != payload {
			t.Errorf("injected payload = %q, want %q", got, payload)
		}

		// Pure forwarding: no new sessions or BIBs, and the BIB's
		// client-activity clock was NOT advanced by inbound traffic
		// (RFC 6146 §5.3 / RFC 4787 REQ-5).
		if n := countSessions(env.svc); n != sessionsBefore {
			t.Errorf("sessions = %d, want unchanged (%d)", n, sessionsBefore)
		}
		if n := countBIBs(env.svc); n != bibsBefore {
			t.Errorf("bibs = %d, want unchanged (%d)", n, bibsBefore)
		}
		if after := atomic.LoadInt64(&bib.lastSeenNs); after != lastSeenBefore {
			t.Error("BIB lastSeen refreshed by an unsolicited inbound datagram")
		}
	})

	t.Run("exact-tuple replies still deliver under endpoint-independent", func(t *testing.T) {
		env.inject(t, client, 48000, env.echoPort, []byte("still-alive"))
		got := parseOutboundUDP(t, env.readOutbound(t),
			net.ParseIP("300:1:2:3::7f00:0001"), client, env.echoPort, 48000)
		if string(got) != "still-alive" {
			t.Errorf("exact-tuple reply = %q, want %q", got, "still-alive")
		}
	})
}
