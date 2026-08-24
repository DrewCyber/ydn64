package nat64

import (
	"net"
	"testing"
	"time"

	"github.com/DrewCyber/ydn64/src/config"
)

// TestSrcTrackerLifecycle pins the tracker semantics: counts per kind,
// pruning when a source drops to zero, and defensive no-ops that keep the
// bookkeeping from going negative.
func TestSrcTrackerLifecycle(t *testing.T) {
	tr := newSrcTracker()
	src := [16]byte{1, 2, 3}

	tr.add(src, srcUDP)
	tr.add(src, srcUDP)
	tr.add(src, srcTCP)
	if got := tr.count(src, srcUDP); got != 2 {
		t.Errorf("udp count = %d, want 2", got)
	}
	if got := tr.count(src, srcTCP); got != 1 {
		t.Errorf("tcp count = %d, want 1", got)
	}
	other := [16]byte{9}
	if got := tr.count(other, srcUDP); got != 0 {
		t.Errorf("unrelated source counted: %d", got)
	}

	// Removing only the TCP entries must not prune the source (UDP remains).
	tr.remove(src, srcTCP)
	if _, ok := tr.counts[src]; !ok {
		t.Fatal("source pruned while UDP sessions are still live")
	}

	tr.remove(src, srcUDP)
	tr.remove(src, srcUDP)
	if _, ok := tr.counts[src]; ok {
		t.Fatal("source not pruned after dropping to zero")
	}

	// Defensive: removing below zero must be a no-op.
	tr.remove(src, srcUDP)
	if got := tr.count(src, srcUDP); got != 0 {
		t.Errorf("count went negative: %d", got)
	}
}

// TestNAT64UDPSessionPerSourceCap drives real flows through the synthetic
// stack with Nat64MaxUDPSessionsPerSource = 1: a second tuple from the same
// client is shed before any state is created, while other clients are
// unaffected — and releasing the session restores the budget.
func TestNAT64UDPSessionPerSourceCapShedsFlow(t *testing.T) {
	env := newUDPTestEnv(t, 30)
	env.svc.Reload(
		config.NAT64Config{
			Pool6: "300:1:2:3::/96", UDPTimeout: 30,
			MaxUDPSessionsPerSrc: 1,
		},
		[]string{"200:a:b:c::/64"},
		nil,
	)

	clientA := net.ParseIP("200:a:b:c::1").To16()
	clientB := net.ParseIP("200:a:b:c::2").To16()
	keyOf := func(client []byte, srcPort uint16) sessionKey {
		var k sessionKey
		copy(k.srcAddr[:], client)
		k.srcPort = srcPort
		k.dstAddr = [4]byte{127, 0, 0, 1}
		k.dstPort = env.echoPort
		return k
	}

	// Client A's first flow goes through normally.
	env.inject(t, clientA, 40000, env.echoPort, []byte("a"))
	parseOutboundUDP(t, env.readOutbound(t), net.ParseIP("300:1:2:3::7f00:0001"), clientA, env.echoPort, 40000)

	// Client B is a different source: unaffected by A's usage.
	env.inject(t, clientB, 40000, env.echoPort, []byte("b"))
	parseOutboundUDP(t, env.readOutbound(t), net.ParseIP("300:1:2:3::7f00:0001"), clientB, env.echoPort, 40000)

	// A second simultaneous tuple from A must be shed: no session, no reply.
	env.inject(t, clientA, 40001, env.echoPort, []byte("c"))
	env.assertNoOutbound(t, 200*time.Millisecond)
	if _, ok := env.svc.sessions.Load(keyOf(clientA, 40001)); ok {
		t.Fatal("shed flow still created a session")
	}
	if got := env.svc.udpSessions.Load(); got != 2 {
		t.Errorf("udpSessions = %d, want 2", got)
	}
	if got := env.svc.srcCounts.count([16]byte(clientA), srcUDP); got != 1 {
		t.Errorf("per-source count for A = %d, want 1", got)
	}

	// Releasing A's live session frees the per-source budget again.
	v, _ := env.svc.sessions.Load(keyOf(clientA, 40000))
	env.svc.deleteSession(v.(*udpSession), keyOf(clientA, 40000))
	if got := env.svc.srcCounts.count([16]byte(clientA), srcUDP); got != 0 {
		t.Errorf("per-source count after release = %d, want 0", got)
	}
	if _, ok := env.svc.srcCounts.counts[[16]byte(clientB)]; !ok {
		t.Error("client B's entry was pruned while its session is live")
	}

	env.inject(t, clientA, 40002, env.echoPort, []byte("d"))
	parseOutboundUDP(t, env.readOutbound(t), net.ParseIP("300:1:2:3::7f00:0001"), clientA, env.echoPort, 40002)
}
