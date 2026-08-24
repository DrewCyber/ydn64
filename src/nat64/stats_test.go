package nat64

import (
	"bytes"
	"context"
	"net"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/gologme/log"
	"gvisor.dev/gvisor/pkg/tcpip"
)

// incCounter returns a StatCounter advanced by n, for building snapshots.
func incCounter(n uint64) *tcpip.StatCounter {
	c := &tcpip.StatCounter{}
	for i := uint64(0); i < n; i++ {
		c.Increment()
	}
	return c
}

// testStats builds a fully-populated tcpip.Stats with every counter
// takeStatSnapshot reads. Stack-provided Stats are always non-nil; the test
// mirrors that invariant.
func testStats() *tcpip.Stats {
	st := &tcpip.Stats{}
	fill := func(c **tcpip.StatCounter, n uint64) { *c = incCounter(n) }

	fill(&st.IP.PacketsReceived, 100)
	fill(&st.IP.PacketsSent, 90)
	fill(&st.TCP.ActiveConnectionOpenings, 3)
	fill(&st.TCP.PassiveConnectionOpenings, 2)
	fill(&st.TCP.CurrentEstablished, 2)
	fill(&st.TCP.ValidSegmentsReceived, 50)
	fill(&st.TCP.SegmentsSent, 45)
	fill(&st.TCP.ResetsSent, 1)
	fill(&st.TCP.Retransmits, 4)
	fill(&st.TCP.EstablishedTimedout, 1)
	fill(&st.UDP.PacketsReceived, 200)
	fill(&st.UDP.PacketsSent, 190)
	fill(&st.UDP.UnknownPortErrors, 5)
	fill(&st.UDP.ReceiveBufferErrors, 6)
	fill(&st.ICMP.V6.PacketsReceived.EchoRequest, 7)
	fill(&st.ICMP.V6.PacketsSent.EchoReply, 7)
	return st
}

func TestTakeStatSnapshot(t *testing.T) {
	snap := takeStatSnapshot(*testStats())

	if snap.ipRx != 100 || snap.ipTx != 90 {
		t.Errorf("ip rx/tx = %d/%d, want 100/90", snap.ipRx, snap.ipTx)
	}
	if snap.tcpActive != 3 || snap.tcpPassive != 2 || snap.tcpEst != 2 {
		t.Errorf("tcp openings/est = %d/%d/%d, want 3/2/2", snap.tcpActive, snap.tcpPassive, snap.tcpEst)
	}
	if snap.tcpSegRx != 50 || snap.tcpSegTx != 45 {
		t.Errorf("tcp segs = %d/%d, want 50/45", snap.tcpSegRx, snap.tcpSegTx)
	}
	if snap.tcpResets != 1 || snap.tcpRetransmits != 4 || snap.tcpTimedout != 1 {
		t.Errorf("tcp rst/re/to = %d/%d/%d, want 1/4/1", snap.tcpResets, snap.tcpRetransmits, snap.tcpTimedout)
	}
	if snap.udpRx != 200 || snap.udpTx != 190 {
		t.Errorf("udp rx/tx = %d/%d, want 200/190", snap.udpRx, snap.udpTx)
	}
	if snap.udpUnknownPort != 5 || snap.udpBufErr != 6 {
		t.Errorf("udp errors = %d/%d, want 5/6", snap.udpUnknownPort, snap.udpBufErr)
	}
	if snap.icmp6EchoReqRx != 7 || snap.icmp6EchoRepTx != 7 {
		t.Errorf("icmp echo = %d/%d, want 7/7", snap.icmp6EchoReqRx, snap.icmp6EchoRepTx)
	}
}

func TestFormatStatsDelta(t *testing.T) {
	prev := takeStatSnapshot(*testStats())

	cur := prev
	cur.ipRx += 10    // delta counter
	cur.tcpSegTx += 3 // delta counter
	cur.udpUnknownPort += 2
	cur.tcpEst++ // gauge: logged as absolute value

	line := formatStatsDelta(prev, cur, 4, 2, 1)

	if !strings.HasPrefix(line, "netstack stats:") {
		t.Errorf("stats line lacks prefix: %q", line)
	}
	for _, want := range []string{
		" ipRx=10",
		" ipTx=0", // unchanged counter → zero delta
		" tcpSegTx=3",
		" tcpRst=0",
		" tcpEst=3", // absolute gauge, not delta
		" udpNoPort=2",
		" icmp6EchoReqRx=0",
		" sessUdp=4",
		" sessIcmp=1",
	} {
		if !strings.Contains(line, want) {
			t.Errorf("stats line %q missing %q", line, want)
		}
	}
}

func TestCountSyncMap(t *testing.T) {
	var m sync.Map
	m.Store("a", 1)
	m.Store("b", 2)
	if got := countSyncMap(&m); got != 2 {
		t.Errorf("countSyncMap = %d, want 2", got)
	}
}

// lastUDPRx reports whether ANY stats line recorded a positive udpRx delta.
// Deltas reset to zero on the tick after traffic, so scanning every line —
// not just the newest — is what makes this race-free under scheduler load:
// once a positive delta is logged it stays visible in the buffer.
func lastUDPRx(buf string) (int, bool) {
	best := 0
	rest := buf
	for {
		idx := strings.Index(rest, " udpRx=")
		if idx < 0 {
			return best, best > 0
		}
		rest = rest[idx+len(" udpRx="):]
		end := strings.IndexAny(rest, " \n")
		if end < 0 {
			end = len(rest)
		}
		if n, err := strconv.Atoi(rest[:end]); err == nil && n > best {
			best = n
		}
	}
}

// syncBuf is a mutex-guarded buffer: the stats loop logs into it from its
// own goroutine while the test reads it concurrently.
type syncBuf struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *syncBuf) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *syncBuf) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}

// TestStatsLoopLogsDeltas runs the real loop against a live gVisor stack with
// a short interval and asserts greppable debug lines come out, then pushes a
// UDP datagram through the NAT64 relay and confirms the stack-level UDP
// receive counter moves in a subsequent tick.
func TestStatsLoopLogsDeltas(t *testing.T) {
	env := newUDPTestEnv(t, 30) // provides Service + real gVisor stack via fakeNetStack

	var out syncBuf
	logger := log.New(&out, "", 0)
	logger.EnableLevel("debug")

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan struct{})
	go func() {
		env.svc.statsLoop(ctx, logger, 20*time.Millisecond)
		close(done)
	}()
	defer func() { cancel(); <-done }()

	waitForLines := func(min int) bool {
		deadline := time.Now().Add(3 * time.Second)
		for time.Now().Before(deadline) {
			if strings.Count(out.String(), "netstack stats:") >= min {
				return true
			}
			time.Sleep(10 * time.Millisecond)
		}
		return false
	}
	if !waitForLines(2) {
		t.Fatalf("expected at least 2 stats lines, got %q", out.String())
	}
	for _, l := range strings.Split(strings.TrimSpace(out.String()), "\n") {
		if !strings.HasPrefix(l, "netstack stats:") ||
			!strings.Contains(l, "sessUdp=") ||
			!strings.Contains(l, "tcpSegRx=") {
			t.Errorf("malformed stats line: %q", l)
		}
	}

	// Push one UDP exchange through the relay and wait for a tick whose
	// udpRx delta reflects it.
	client := net.ParseIP("200:a:b:c::1").To16()
	env.inject(t, client, 45000, env.echoPort, []byte("stats"))
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if n, ok := lastUDPRx(out.String()); ok && n > 0 {
			return // observed non-zero UDP received delta
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("udpRx never became positive after traffic; log=%q", out.String())
}
