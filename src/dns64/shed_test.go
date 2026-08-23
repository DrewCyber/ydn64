package dns64

import (
	"net"
	"sync"
	"testing"
	"time"

	"github.com/miekg/dns"
)

// denyTestConn records REFUSED replies sent to denied sources.
type denyTestConn struct {
	mu   sync.Mutex
	sent [][]byte
}

func (c *denyTestConn) WriteTo(b []byte, _ net.Addr) (int, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.sent = append(c.sent, append([]byte(nil), b...))
	return len(b), nil
}

func TestQuerySlotShedding(t *testing.T) {
	s := &Service{querySem: make(chan struct{}, 1)}
	if !s.tryAcquireQuery() {
		t.Fatal("first acquire refused against empty semaphore")
	}
	if s.tryAcquireQuery() {
		t.Fatal("second acquire succeeded against limit of 1")
	}
	s.releaseQuery()
	if !s.tryAcquireQuery() {
		t.Fatal("acquire after release failed")
	}

	unlimited := &Service{}
	for i := 0; i < 10; i++ {
		if !unlimited.tryAcquireQuery() {
			t.Fatalf("acquire %d refused without a configured limit", i)
		}
	}
}

func TestShedResponseIsSERVFAIL(t *testing.T) {
	req := new(dns.Msg)
	req.SetQuestion("example.com.", dns.TypeAAAA)
	resp := shedResponse(req)
	out, err := resp.Pack()
	if err != nil {
		t.Fatalf("Pack: %v", err)
	}
	parsed := new(dns.Msg)
	if err := parsed.Unpack(out); err != nil {
		t.Fatalf("Unpack: %v", err)
	}
	if !parsed.Response || parsed.Rcode != dns.RcodeServerFailure {
		t.Errorf("shed response = response=%v rcode=%v, want response=true SERVFAIL", parsed.Response, parsed.Rcode)
	}
	if len(parsed.Question) != 1 || parsed.Question[0].Name != "example.com." {
		t.Errorf("shed response question = %v, want echoed question", parsed.Question)
	}
	if parsed.Id != req.Id {
		t.Errorf("shed response id = %d, want %d", parsed.Id, req.Id)
	}
}

// TestDenyReplyRateLimited: the first denied query gets a REFUSED reply
// through maybeRefuseDenied; a second one inside the window is dropped.
func TestDenyReplyRateLimited(t *testing.T) {
	s := &Service{}
	conn := &denyTestConn{}
	written := func() int {
		conn.mu.Lock()
		defer conn.mu.Unlock()
		return len(conn.sent)
	}

	denied := "200:dead:beef::1"
	data := func(id uint16) []byte {
		m := new(dns.Msg)
		m.Id = id
		m.SetQuestion("example.com.", dns.TypeAAAA)
		b, err := m.Pack()
		if err != nil {
			t.Fatal(err)
		}
		return b
	}

	from := &net.UDPAddr{IP: net.ParseIP(denied), Port: 5353}
	s.maybeRefuseDenied(conn, from, data(1))
	if got := written(); got != 1 {
		t.Fatalf("replies = %d, want 1 (first denial answered)", got)
	}

	s.maybeRefuseDenied(conn, from, data(2))
	if got := written(); got != 1 {
		t.Fatalf("replies = %d, want still 1 (rate limited within window)", got)
	}
}

// TestServiceDrainBoundedWait: Drain returns as soon as in-flight work
// finishes, but never waits past the deadline.
func TestServiceDrainBoundedWait(t *testing.T) {
	s := &Service{}

	s.wg.Add(1)
	go func() {
		time.Sleep(50 * time.Millisecond)
		s.wg.Done()
	}()
	start := time.Now()
	s.Drain(2 * time.Second)
	if elapsed := time.Since(start); elapsed < 40*time.Millisecond {
		t.Errorf("Drain returned after %v, before in-flight work finished", elapsed)
	}

	s.wg.Add(1) // never released
	start = time.Now()
	s.Drain(30 * time.Millisecond)
	if elapsed := time.Since(start); elapsed < 25*time.Millisecond {
		t.Errorf("Drain returned after %v despite unfinished work and %v deadline", elapsed, 30*time.Millisecond)
	}
}
