package nat64

import (
	"context"
	"net"
	"testing"
	"time"

	"github.com/DrewCyber/ydn64/src/config"
)

// nat64CfgWithFiltering returns a minimal NAT64Config carrying the given
// Nat64UdpFiltering value, for driving Service.Reload in tests.
func nat64CfgWithFiltering(filtering string) config.NAT64Config {
	return config.NAT64Config{
		Pool6:        "300:1:2:3::/96",
		UDPTimeout:   30,
		UDPFiltering: filtering,
	}
}

// startEchoOn starts an additional UDP echo server bound to a specific
// loopback IP, returning its port. Used to prove endpoint-independent
// mapping across DIFFERENT destinations.
func startEchoOn(t *testing.T, ip string) uint16 {
	t.Helper()
	conn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.ParseIP(ip), Port: 0})
	if err != nil {
		t.Fatalf("ListenUDP(%s): %v", ip, err)
	}
	t.Cleanup(func() { conn.Close() })
	go func() {
		buf := make([]byte, 65535)
		for {
			n, addr, err := conn.ReadFromUDP(buf)
			if err != nil {
				return
			}
			if _, err := conn.WriteToUDP(buf[:n], addr); err != nil {
				return
			}
		}
	}()
	return uint16(conn.LocalAddr().(*net.UDPAddr).Port)
}

func countBIBs(s *Service) int {
	n := 0
	s.bibs.Range(func(_, _ any) bool {
		n++
		return true
	})
	return n
}

// firstBIB returns the service's only BIB entry (test helper; fails the test
// unless exactly one exists).
func firstBIB(t *testing.T, s *Service) *udpBIB {
	t.Helper()
	if n := countBIBs(s); n != 1 {
		t.Fatalf("bibs = %d, want exactly 1", n)
	}
	var bib *udpBIB
	s.bibs.Range(func(_, v any) bool {
		bib = v.(*udpBIB)
		return false
	})
	return bib
}

// TestEIMSameExternalPortAcrossDestinations is the core RFC 4787 REQ-1 /
// RFC 6146 §3.1 assertion: one client socket talking to TWO different IPv4
// destinations must use the SAME external (IPv4, port) mapping for both.
func TestEIMSameExternalPortAcrossDestinations(t *testing.T) {
	env := newUDPTestEnv(t, 30)
	port2 := startEchoOn(t, "127.0.0.2")
	client := net.ParseIP("200:a:b:c::1").To16()

	// Flow 1: client:45000 → 127.0.0.1:echoPort
	env.injectTo(t, client, 45000, "127.0.0.1", env.echoPort, []byte("one"))
	got1 := parseOutboundUDP(t, env.readOutbound(t),
		net.ParseIP("300:1:2:3::7f00:0001"), client, env.echoPort, 45000)
	if string(got1) != "one" {
		t.Fatalf("reply 1 payload = %q, want %q", got1, "one")
	}

	// Flow 2: the SAME client socket → a different destination.
	env.injectTo(t, client, 45000, "127.0.0.2", port2, []byte("two"))
	got2 := parseOutboundUDP(t, env.readOutbound(t),
		net.ParseIP("300:1:2:3::7f00:0002"), client, port2, 45000)
	if string(got2) != "two" {
		t.Fatalf("reply 2 payload = %q, want %q", got2, "two")
	}

	// Both flows must share ONE BIB and ONE allocated external port.
	if got := countBIBs(env.svc); got != 1 {
		t.Fatalf("bibs = %d, want 1", got)
	}
	bib := firstBIB(t, env.svc)
	if bib.localPort == 0 {
		t.Fatal("BIB has no allocated port")
	}
	ports := map[uint16]bool{}
	n := 0
	env.svc.sessions.Range(func(_, v any) bool {
		sess := v.(*udpSession)
		ports[sess.localPort] = true
		n++
		return true
	})
	if n != 2 {
		t.Errorf("sessions = %d, want 2", n)
	}
	if len(ports) != 1 || !ports[bib.localPort] {
		t.Errorf("flows use external ports %v; want exactly the single BIB port %d (endpoint-independent mapping)",
			ports, bib.localPort)
	}
}

// TestUDPFilteringModes drives the Nat64UdpFiltering matrix against a live
// BIB: exact-tuple replies always deliver, same-IP-different-port depends on
// the mode (accepted under the RFC 6146 §5.2 default address-dependent
// filtering, dropped under address-and-port-dependent), and unknown source
// addresses are always dropped.
func TestUDPFilteringModes(t *testing.T) {
	env := newUDPTestEnv(t, 30)
	client := net.ParseIP("200:a:b:c::1").To16()
	pool6Src := net.ParseIP("300:1:2:3::7f00:0001").To16()

	// Establish a flow so a BIB with one active entry exists.
	env.inject(t, client, 46000, env.echoPort, []byte("hello"))
	if got := parseOutboundUDP(t, env.readOutbound(t), pool6Src, client, env.echoPort, 46000); string(got) != "hello" {
		t.Fatalf("baseline reply = %q, want %q", got, "hello")
	}
	var sess *udpSession
	env.svc.sessions.Range(func(_, v any) bool {
		sess = v.(*udpSession)
		return false
	})
	target := &net.UDPAddr{IP: net.IP(append([]byte(nil), sess.localIP[:]...)), Port: int(sess.localPort)}

	sendRogue := func(tb testing.TB, srcIP string, srcPort int, payload string) {
		tb.Helper()
		conn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.ParseIP(srcIP), Port: 0})
		if err != nil {
			tb.Fatalf("rogue ListenUDP(%s): %v", srcIP, err)
		}
		defer conn.Close()
		if _, err := conn.WriteToUDP([]byte(payload), target); err != nil {
			tb.Fatalf("rogue send: %v", err)
		}
	}

	t.Run("address-dependent accepts same-IP different-port", func(t *testing.T) {
		sendRogue(t, "127.0.0.1", 0, "adf-same-ip")
		got := parseOutboundUDP(t, env.readOutbound(t), pool6Src, client, env.echoPort, 46000)
		if string(got) != "adf-same-ip" {
			t.Errorf("delivered payload = %q, want %q", got, "adf-same-ip")
		}
	})

	t.Run("address-dependent still drops unknown IPs", func(t *testing.T) {
		// A loopback address with NO active flow toward it (this test only
		// ever talks to 127.0.0.1).
		sendRogue(t, "127.0.0.2", 0, "should-drop-unknown-ip")
		env.assertNoOutbound(t, 400*time.Millisecond)
	})

	t.Run("address-and-port-dependent drops same-IP different-port", func(t *testing.T) {
		env.svc.Reload(nat64CfgWithFiltering("address-and-port-dependent"), []string{"200:a:b:c::/64"}, nil)
		sendRogue(t, "127.0.0.1", 0, "apdf-must-drop")
		env.assertNoOutbound(t, 400*time.Millisecond)
	})

	t.Run("exact-tuple replies still deliver under address-and-port-dependent", func(t *testing.T) {
		env.inject(t, client, 46000, env.echoPort, []byte("still-alive"))
		got := parseOutboundUDP(t, env.readOutbound(t), pool6Src, client, env.echoPort, 46000)
		if string(got) != "still-alive" {
			t.Errorf("exact-tuple reply = %q, want %q", got, "still-alive")
		}
	})
}

// TestBIBIdleExpiry verifies that BIB entries live and die on the same
// client-activity clock as their sessions: after the idle timeout both the
// session and its BIB are gone, and new traffic re-creates both cleanly.
func TestBIBIdleExpiry(t *testing.T) {
	env := newUDPTestEnv(t, 1) // 1s idle timeout
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go env.svc.cleanupSessions(ctx)

	client := net.ParseIP("200:a:b:c::1").To16()
	pool6Src := net.ParseIP("300:1:2:3::7f00:0001").To16()

	env.inject(t, client, 47000, env.echoPort, []byte("first"))
	if got := parseOutboundUDP(t, env.readOutbound(t), pool6Src, client, env.echoPort, 47000); string(got) != "first" {
		t.Fatalf("reply = %q, want %q", got, "first")
	}
	if countBIBs(env.svc) != 1 {
		t.Fatalf("bibs = %d, want 1 after first flow", countBIBs(env.svc))
	}

	deadline := time.Now().Add(6 * time.Second)
	for countSessions(env.svc) != 0 || countBIBs(env.svc) != 0 {
		if time.Now().After(deadline) {
			t.Fatalf("idle expiry did not clean up: sessions=%d bibs=%d",
				countSessions(env.svc), countBIBs(env.svc))
		}
		time.Sleep(100 * time.Millisecond)
	}

	env.inject(t, client, 47000, env.echoPort, []byte("after expiry"))
	got := parseOutboundUDP(t, env.readOutbound(t), pool6Src, client, env.echoPort, 47000)
	if string(got) != "after expiry" {
		t.Errorf("reply after expiry = %q, want %q", got, "after expiry")
	}
}

// TestParseUDPFilterMode pins the config-string parsing (case-insensitive,
// unknown values fall back to the conformant default).
func TestParseUDPFilterMode(t *testing.T) {
	cases := []struct {
		in   string
		want udpFilterMode
	}{
		{"", filterAddressDependent},
		{"address-dependent", filterAddressDependent},
		{"ADDRESS-DEPENDENT", filterAddressDependent},
		{" address-and-port-dependent ", filterAddressAndPortDependent},
		{"Endpoint-Independent", filterEndpointIndependent},
		{"garbage", filterAddressDependent},
	}
	for _, tc := range cases {
		if got := parseUDPFilterMode(tc.in); got != tc.want {
			t.Errorf("parseUDPFilterMode(%q) = %v, want %v", tc.in, got, tc.want)
		}
	}
}
