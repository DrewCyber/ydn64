package nat64

import (
	"bytes"
	"fmt"
	"net"
	"testing"

	"github.com/DrewCyber/ydn64/src/config"
)

// pool6ForLoopback1 is the synthesised source address of replies from the
// test env's 127.0.0.1 echo server (pool6 prefix + embedded IPv4, /96 form).
var pool6ForLoopback1 = net.ParseIP("300:1:2:3::7f00:0001").To16()

// assertParityRoundTrip drives one client datagram through the forwarder
// path and verifies its echo reply arrives intact — proving the flow's BIB
// was created and is relaying.
func assertParityRoundTrip(t *testing.T, env *udpTestEnv, client net.IP, clientPort uint16) {
	t.Helper()
	payload := []byte(fmt.Sprintf("parity-probe-%d", clientPort))
	env.inject(t, client, clientPort, env.echoPort, payload)
	got := parseOutboundUDP(t, env.readOutbound(t), pool6ForLoopback1, client, env.echoPort, clientPort)
	if !bytes.Equal(got, payload) {
		t.Fatalf("reply payload = %q, want %q", got, payload)
	}
}

// TestUDPPortParityPreserved is the RFC 4787 REQ-3 core assertion (default
// Nat64PortParity=preserve): the NAT-assigned external port of a BIB keeps
// its client socket's even/odd parity. One even-port and one odd-port client
// are driven through the forwarder path; each ends up with exactly one BIB
// whose allocated port matches the client's parity.
func TestUDPPortParityPreserved(t *testing.T) {
	env := newUDPTestEnv(t, 30) // PortParity unset → parsePortParity("") = preserve

	clients := []struct {
		ip   net.IP
		port uint16
	}{
		{net.ParseIP("200:a:b:c::1").To16(), 45000}, // even
		{net.ParseIP("200:a:b:c::2").To16(), 45001}, // odd
	}
	for _, c := range clients {
		assertParityRoundTrip(t, env, c.ip, c.port)
	}

	if n := countBIBs(env.svc); n != len(clients) {
		t.Fatalf("bibs = %d, want %d", n, len(clients))
	}
	env.svc.bibs.Range(func(k, v any) bool {
		bk := k.(bibKey)
		bib := v.(*udpBIB)
		if bib.localPort&1 != bk.srcPort&1 {
			t.Errorf("client port %d mapped to external port %d: parity not preserved",
				bk.srcPort, bib.localPort)
		}
		return true
	})
}

// TestUDPPortParityAcrossManyClients exercises the allocator repeatedly:
// 24 clients with alternating even/odd source ports must all land on
// same-parity external ports. The probe budget in listenBIBSocket makes a
// single mismatch <0.5% likely; 24 simultaneous mismatches would indicate a
// broken allocator rather than bad luck.
func TestUDPPortParityAcrossManyClients(t *testing.T) {
	env := newUDPTestEnv(t, 30)

	const n = 24
	for i := 0; i < n; i++ {
		client := net.ParseIP(fmt.Sprintf("200:a:b:c::%x", i+1)).To16()
		assertParityRoundTrip(t, env, client, uint16(51000+i))
	}

	if got := countBIBs(env.svc); got != n {
		t.Fatalf("bibs = %d, want %d", got, n)
	}
	mismatched := 0
	env.svc.bibs.Range(func(k, v any) bool {
		bk := k.(bibKey)
		bib := v.(*udpBIB)
		if bib.localPort&1 != bk.srcPort&1 {
			mismatched++
			t.Errorf("client port %d mapped to external port %d: parity not preserved",
				bk.srcPort, bib.localPort)
		}
		return true
	})
	if mismatched > bibParityAttempts/2 {
		t.Errorf("%d/%d allocations lost parity — allocator fallback engaged too often", mismatched, n)
	}
}

// TestUDPPortParityDoNotPreserveStillRelays switches the service to
// Nat64PortParity=do-not-preserve and verifies relaying keeps working end to
// end. No parity assertion is possible by definition; the point is that the
// mode switch neither breaks flows nor falls back to preserve behaviour.
func TestUDPPortParityDoNotPreserveStillRelays(t *testing.T) {
	env := newUDPTestEnv(t, 30)
	env.svc.Reload(
		config.NAT64Config{Pool6: "300:1:2:3::/96", UDPTimeout: 30, PortParity: "do-not-preserve"},
		[]string{"200:a:b:c::/64"},
		nil,
	)
	if env.svc.settings.Load().portParity != parityDoNotPreserve {
		t.Fatal("Reload did not switch the port parity mode")
	}

	client := net.ParseIP("200:a:b:c::9").To16()
	assertParityRoundTrip(t, env, client, 45000)

	if n := countBIBs(env.svc); n != 1 {
		t.Fatalf("bibs = %d, want 1", n)
	}
}

// TestParsePortParity pins the config-string parsing: empty and unknown
// values fall back to REQ-3's conformant "preserve" default.
func TestParsePortParity(t *testing.T) {
	cases := []struct {
		in   string
		want portParityMode
	}{
		{"", parityPreserve},
		{"preserve", parityPreserve},
		{"PRESERVE", parityPreserve},
		{" do-not-preserve ", parityDoNotPreserve},
		{"DO-NOT-PRESERVE", parityDoNotPreserve},
		{"garbage", parityPreserve},
	}
	for _, tc := range cases {
		if got := parsePortParity(tc.in); got != tc.want {
			t.Errorf("parsePortParity(%q) = %v, want %v", tc.in, got, tc.want)
		}
	}
}
