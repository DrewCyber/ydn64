package dns64

import (
	"net"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/miekg/dns"
)

// x20Upstream is a loopback fake forwarder with switchable 0x20 behaviour:
// "echo" answers with the query's exact case (a correct server), "canonical"
// always answers all-lowercase (an RFC 5452 §9.1-incapable one).
type x20Upstream struct {
	pc       net.PacketConn
	server   *dns.Server
	addr     string
	mu       sync.Mutex
	mode     string // "echo" | "canonical"
	lastSeen chan string
}

func newX20Upstream(t *testing.T) *x20Upstream {
	t.Helper()
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("ListenPacket: %v", err)
	}
	u := &x20Upstream{pc: pc, addr: pc.LocalAddr().String(), mode: "echo", lastSeen: make(chan string, 16)}
	u.server = &dns.Server{
		PacketConn: pc,
		Handler: dns.HandlerFunc(func(w dns.ResponseWriter, req *dns.Msg) {
			q := req.Copy().Question[0]
			select {
			case u.lastSeen <- q.Name:
			default:
			}
			resp := new(dns.Msg)
			u.mu.Lock()
			mode := u.mode
			u.mu.Unlock()
			if mode == "canonical" {
				req.Question[0].Name = strings.ToLower(req.Question[0].Name)
			}
			rr, _ := dns.NewRR(req.Question[0].Name + " 300 IN A 192.0.2.1")
			resp.SetReply(req)
			resp.Answer = append(resp.Answer, rr)
			_ = w.WriteMsg(resp)
		}),
	}
	go func() { _ = u.server.ActivateAndServe() }()
	t.Cleanup(func() { _ = u.server.Shutdown(); pc.Close() })
	time.Sleep(50 * time.Millisecond)
	return u
}

func (u *x20Upstream) setMode(mode string) {
	u.mu.Lock()
	defer u.mu.Unlock()
	u.mode = mode
}

func x20Req(name string) *dns.Msg {
	req := new(dns.Msg)
	req.SetQuestion(name, dns.TypeA)
	return req
}

// TestRandomizeNameCase pins the helper's contract: same length, same labels,
// only letter case flips, and it is case-insensitively identical.
func TestRandomizeNameCase(t *testing.T) {
	in := "MiXeD.Case.Example.COM."
	sawFlip := false
	for i := 0; i < 64; i++ {
		got := randomizeNameCase(in)
		if len(got) != len(in) {
			t.Fatalf("length changed: %q -> %q", in, got)
		}
		if got != in && strings.EqualFold(got, in) {
			sawFlip = true
		} else if !strings.EqualFold(got, in) {
			t.Fatalf("non-case change: %q -> %q", in, got)
		}
	}
	if !sawFlip {
		t.Fatal("64 randomisations never flipped a single character")
	}
}

// TestX20MismatchedAnswerRejected drives lookup against a canonicalising
// upstream: with randomisation active, an answer that does not echo the
// randomised case must be discarded even though its ID matches.
func TestX20MismatchedAnswerRejected(t *testing.T) {
	u := newX20Upstream(t)
	u.setMode("canonical")
	p := &proxy{}

	// The name carries many letters so the odds of the randomised query
	// coincidentally being all-lowercase are ~2^-21 — deterministic enough.
	errs := 0
	for i := 0; i < 3; i++ {
		if _, err := p.lookup(u.addr, x20Req("FORGERY.CaseCheck.Example.COM."), viaUDP); err == nil {
			t.Fatal("canonicalised answer accepted despite 0x20 mismatch")
		} else {
			errs++
		}
	}
	if errs != 3 {
		t.Fatalf("expected 3 rejections, got %d", errs)
	}
}

// TestX20EchoedAnswerAcceptedAndRestored verifies the happy path end to end:
// a correct (case-echoing) upstream yields a successful lookup whose returned
// question section carries the CLIENT's original case, while the upstream
// actually received a differently-cased query.
func TestX20EchoedAnswerAcceptedAndRestored(t *testing.T) {
	u := newX20Upstream(t)
	p := &proxy{}
	const orig = "Client.Case.Example.COM."

	resp, err := p.lookup(u.addr, x20Req(orig), viaUDP)
	if err != nil {
		t.Fatalf("lookup against echoing upstream failed: %v", err)
	}
	if len(resp.Question) != 1 || resp.Question[0].Name != orig {
		t.Fatalf("response question = %q, want client's original %q", resp.Question[0].Name, orig)
	}
	select {
	case seen := <-u.lastSeen:
		if !strings.EqualFold(seen, orig) {
			t.Fatalf("upstream saw %q, want case-variant of %q", seen, orig)
		}
		if seen == orig {
			t.Fatalf("upstream saw the un-randomised name %q (randomisation inactive?)", seen)
		}
	default:
		t.Fatal("upstream never received the query")
	}
}

// TestX20DisablesAfterStrikesAndRecovers exercises the graceful degradation:
// after x20MaxConsecutiveFailures consecutive mismatches, lookups toward that
// forwarder succeed again (unrandomised), stay working for the disable window
// (a successful lookup must not re-enable randomisation early), and
// randomisation resumes once the window elapses.
//
// The window's edges are pinned directly on the state instead of derived
// from a short artificial duration: an 80 ms-style fake window made the
// mid-window probes race the wall clock — under -race with the full suite
// running, the round trips following the strike loop could legitimately
// outlive the window and spuriously fail.
func TestX20DisablesAfterStrikesAndRecovers(t *testing.T) {
	u := newX20Upstream(t)
	u.setMode("canonical")
	p := &proxy{}

	for i := 0; i < x20MaxConsecutiveFailures; i++ {
		if _, err := p.lookup(u.addr, x20Req("Strike.Out.EXAMPLE.COM."), viaUDP); err == nil {
			t.Fatalf("strike %d unexpectedly succeeded", i+1)
		}
	}
	st := p.x20StateFor(u.addr)

	// Inside the window (pinned wide open): no randomisation, canonical
	// answer accepted.
	st.mu.Lock()
	st.disabledUntil = time.Now().Add(time.Minute)
	st.mu.Unlock()
	if _, err := p.lookup(u.addr, x20Req("While.Disabled.EXAMPLE.COM."), viaUDP); err != nil {
		t.Fatalf("lookup during disable window failed: %v", err)
	}
	// The success above must NOT re-enable randomisation early.
	st.mu.Lock()
	reEnabled := time.Now().After(st.disabledUntil)
	st.mu.Unlock()
	if reEnabled {
		t.Fatal("a successful unrandomised lookup re-enabled 0x20 randomisation inside the disable window")
	}

	// Window elapsed: randomisation resumes; a correct echo server passes.
	st.mu.Lock()
	st.disabledUntil = time.Now().Add(-time.Second)
	st.mu.Unlock()
	u.setMode("echo")
	if _, err := p.lookup(u.addr, x20Req("Back.On.ECHO.COM."), viaUDP); err != nil {
		t.Fatalf("lookup after disable window failed: %v", err)
	}
}
