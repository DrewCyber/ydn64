package nat64

import (
	"net"
	"sync/atomic"
	"testing"
	"time"

	"github.com/DrewCyber/ydn64/src/config"
)

// TestNAT64UDPSessionCapEvictsOldestIdle drives real flows through the
// synthetic stack: with Nat64MaxUDPSessions = 2, opening a third tuple must
// evict the least-recently-active session and keep the counter consistent.
func TestNAT64UDPSessionCapEvictsOldestIdle(t *testing.T) {
	env := newUDPTestEnv(t, 30)
	env.svc.Reload(
		config.NAT64Config{Pool6: "300:1:2:3::/96", UDPTimeout: 30, MaxUDPSessions: 2},
		[]string{"200:a:b:c::/64"},
		nil,
	)

	client := net.ParseIP("200:a:b:c::1").To16()
	keyOf := func(srcPort uint16) sessionKey {
		var k sessionKey
		copy(k.srcAddr[:], client)
		k.srcPort = srcPort
		k.dstAddr = [4]byte{127, 0, 0, 1}
		k.dstPort = env.echoPort
		return k
	}

	// Establish two sessions (the reply proves the session is stored).
	env.inject(t, client, 40000, env.echoPort, []byte("a"))
	parseOutboundUDP(t, env.readOutbound(t), net.ParseIP("300:1:2:3::7f00:0001"), client, env.echoPort, 40000)
	env.inject(t, client, 40001, env.echoPort, []byte("b"))
	parseOutboundUDP(t, env.readOutbound(t), net.ParseIP("300:1:2:3::7f00:0001"), client, env.echoPort, 40001)

	if got := env.svc.udpSessions.Load(); got != 2 {
		t.Fatalf("udpSessions = %d, want 2", got)
	}

	// Make tuple 40000 unambiguously the least-recently-active one.
	if v, ok := env.svc.sessions.Load(keyOf(40000)); ok {
		atomic.StoreInt64(&v.(*udpSession).lastSeenNs, time.Now().Add(-time.Minute).UnixNano())
	} else {
		t.Fatal("session for port 40000 not tracked")
	}

	// Third flow: admission must evict 40000 and let this one through.
	env.inject(t, client, 40002, env.echoPort, []byte("c"))
	parseOutboundUDP(t, env.readOutbound(t), net.ParseIP("300:1:2:3::7f00:0001"), client, env.echoPort, 40002)

	if _, ok := env.svc.sessions.Load(keyOf(40000)); ok {
		t.Error("least-recently-active session was not evicted")
	}
	for _, p := range []uint16{40001, 40002} {
		if _, ok := env.svc.sessions.Load(keyOf(p)); !ok {
			t.Errorf("session for port %d missing after eviction", p)
		}
	}
	if got := env.svc.udpSessions.Load(); got != 2 {
		t.Errorf("udpSessions = %d, want 2 after eviction + admission", got)
	}
}

func TestAdmitUDPSessionUnlimitedWhenDisabled(t *testing.T) {
	s := &Service{}
	s.settings.Store(&nat64Settings{maxUDPSessions: 0})
	for i := 0; i < 100; i++ {
		if !s.admitUDPSession() {
			t.Fatalf("admission refused at i=%d although no limit is configured", i)
		}
	}
}

func TestAdmitUDPSessionDropsWhenNothingToEvict(t *testing.T) {
	s := &Service{}
	s.settings.Store(&nat64Settings{maxUDPSessions: 1})
	s.udpSessions.Store(5) // over capacity, but the session map is empty
	if s.admitUDPSession() {
		t.Fatal("admission succeeded although the bound cannot be met")
	}
}

func TestTryAcquireTCPShedsAtLimit(t *testing.T) {
	s := &Service{tcpSem: make(chan struct{}, 1)}
	if !s.tryAcquireTCP() {
		t.Fatal("first acquire refused against empty semaphore")
	}
	if s.tryAcquireTCP() {
		t.Fatal("second acquire succeeded against limit of 1")
	}
	s.releaseTCP()
	if !s.tryAcquireTCP() {
		t.Fatal("acquire after release failed")
	}

	unlimited := &Service{}
	for i := 0; i < 10; i++ {
		if !unlimited.tryAcquireTCP() {
			t.Fatalf("acquire %d refused without a configured limit", i)
		}
	}
}
