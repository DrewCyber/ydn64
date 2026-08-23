package dns64

import (
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/miekg/dns"
)

// capturedQuery records one query observed by the mock upstream.
type capturedQuery struct {
	name  string
	qtype uint16
}

// dnssecTestEnv wires a proxy against a mock upstream that records every
// question it receives and answers signed.example.com with a "validated"
// (AD-asserted) real AAAA plus a corresponding A record.
type dnssecTestEnv struct {
	p       *proxy
	mu      sync.Mutex
	queries []capturedQuery
}

func newDNSTestEnvWithSignedRecord(t *testing.T) *dnssecTestEnv {
	t.Helper()
	env := &dnssecTestEnv{}

	addr, _ := startTestDNSServer(t, dns.HandlerFunc(func(w dns.ResponseWriter, req *dns.Msg) {
		resp := new(dns.Msg)
		resp.SetReply(req)
		resp.AuthenticatedData = true // pretend upstream validated everything
		if len(req.Question) == 1 {
			env.mu.Lock()
			env.queries = append(env.queries,
				capturedQuery{name: req.Question[0].Name, qtype: req.Question[0].Qtype})
			env.mu.Unlock()

			q := req.Question[0]
			switch {
			case strings.EqualFold(q.Name, "signed.example.com.") && q.Qtype == dns.TypeAAAA:
				rr, _ := dns.NewRR("signed.example.com. 300 IN AAAA 2001:db8::1")
				resp.Answer = append(resp.Answer, rr)
			case strings.EqualFold(q.Name, "signed.example.com.") && q.Qtype == dns.TypeA:
				rr, _ := dns.NewRR("signed.example.com. 300 IN A 192.0.2.55")
				resp.Answer = append(resp.Answer, rr)
			case strings.EqualFold(q.Name, "missing.example.com."):
				resp.SetRcode(req, dns.RcodeNameError)
				soaRR, _ := dns.NewRR("example.com. 300 IN SOA ns1.example.com. admin.example.com. 1 7200 3600 1209600 3600")
				if soaRR != nil {
					resp.Ns = append(resp.Ns, soaRR)
				}
			}
		}
		w.WriteMsg(resp)
	}))

	env.p = newTestProxy(addr)
	time.Sleep(20 * time.Millisecond)
	return env
}

func (e *dnssecTestEnv) seen() []capturedQuery {
	e.mu.Lock()
	defer e.mu.Unlock()
	out := make([]capturedQuery, len(e.queries))
	copy(out, e.queries)
	return out
}

// newValidatingQuery builds a request with CD=1 and DO=1 (DNSSEC OK set),
// i.e. what a security-aware validating stub sends.
func newValidatingQuery(name string, qtype uint16) *dns.Msg {
	req := new(dns.Msg)
	req.SetQuestion(name, qtype)
	req.CheckingDisabled = true
	req.SetEdns0(1232, true)
	return req
}

// TestRFC6147S5_5CDandDODisablesSynthesis verifies RFC 6147 §5.5 / RFC
// 4033–4035 handling: a validating client (CD=1 && DO=1) receives the
// untouched upstream answer, while either bit alone still gets synthesis.
func TestRFC6147S5_5CDandDODisablesSynthesis(t *testing.T) {
	const expectedSynth = "64:ff9b::c000:237" // 192.0.2.55

	t.Run("CD1_DO1_passthrough_without_synthesis", func(t *testing.T) {
		env := newDNSTestEnvWithSignedRecord(t)

		req := newValidatingQuery("signed.example.com.", dns.TypeAAAA)
		resp := env.p.handle(req)

		if resp.Rcode != dns.RcodeSuccess {
			t.Fatalf("expected success, got %d", resp.Rcode)
		}
		if len(resp.Answer) != 1 {
			t.Fatalf("expected exactly the upstream answer (1 RR), got %d", len(resp.Answer))
		}
		aaaa, ok := resp.Answer[0].(*dns.AAAA)
		if !ok {
			t.Fatalf("expected AAAA record, got %T", resp.Answer[0])
		}
		if got := aaaa.AAAA.String(); got != "2001:db8::1" {
			t.Fatalf("expected untouched upstream AAAA 2001:db8::1, got %s", got)
		}

		seen := env.seen()
		if len(seen) != 1 || seen[0].qtype != dns.TypeAAAA {
			t.Fatalf("validating query must trigger exactly one upstream AAAA query (no A fallback), got %+v", seen)
		}
	})

	t.Run("CD1_DO1_preserves_upstream_AD", func(t *testing.T) {
		env := newDNSTestEnvWithSignedRecord(t)
		resp := env.p.handle(newValidatingQuery("signed.example.com.", dns.TypeAAAA))
		if !resp.AuthenticatedData {
			t.Fatal("proxied response must preserve the validating upstream's AD bit")
		}
	})

	t.Run("CD0_DO1_still_synthesises", func(t *testing.T) {
		env := newDNSTestEnvWithSignedRecord(t)

		req := new(dns.Msg)
		req.SetQuestion("signed.example.com.", dns.TypeAAAA)
		req.SetEdns0(1232, true) // DO only
		resp := env.p.handle(req)

		found := false
		for _, rr := range resp.Answer {
			if aaaa, ok := rr.(*dns.AAAA); ok && aaaa.AAAA.String() == expectedSynth {
				found = true
			}
		}
		if !found {
			t.Fatalf("DO-only query must still synthesise %s, got %d answers", expectedSynth, len(resp.Answer))
		}
		if n := len(env.seen()); n != 2 {
			t.Fatalf("synthesis path should issue AAAA+A upstream queries, got %d", n)
		}
	})

	t.Run("CD1_DO0_still_synthesises", func(t *testing.T) {
		env := newDNSTestEnvWithSignedRecord(t)

		req := new(dns.Msg)
		req.SetQuestion("signed.example.com.", dns.TypeAAAA)
		req.CheckingDisabled = true // CD only, no EDNS/DO
		resp := env.p.handle(req)

		found := false
		for _, rr := range resp.Answer {
			if aaaa, ok := rr.(*dns.AAAA); ok && aaaa.AAAA.String() == expectedSynth {
				found = true
			}
		}
		if !found {
			t.Fatalf("CD-only query must still synthesise %s, got %d answers", expectedSynth, len(resp.Answer))
		}
	})
}

// TestRFC6147S5_5ADNeverAssertedOnGeneratedResponses pins the rule that
// ydn64 — which never validates — never asserts AD on any response it
// generates or modifies, including cache hits, NXDOMAIN relays, and echoes
// of a query's own AD flag.
func TestRFC6147S5_5ADNeverAssertedOnGeneratedResponses(t *testing.T) {
	t.Run("synthesised_answer", func(t *testing.T) {
		env := newDNSTestEnvWithSignedRecord(t)
		req := new(dns.Msg)
		req.SetQuestion("signed.example.com.", dns.TypeAAAA)
		if resp := env.p.handle(req); resp.AuthenticatedData {
			t.Fatal("synthesised response asserted AD")
		}
	})

	t.Run("cache_hit", func(t *testing.T) {
		env := newDNSTestEnvWithSignedRecord(t)
		req := new(dns.Msg)
		req.SetQuestion("signed.example.com.", dns.TypeAAAA)
		env.p.handle(req) // populate cache
		if resp := env.p.handle(req); resp.AuthenticatedData {
			t.Fatal("cache-hit response asserted AD")
		}
	})

	t.Run("query_AD_flag_not_echoed", func(t *testing.T) {
		env := newDNSTestEnvWithSignedRecord(t)
		req := new(dns.Msg)
		req.SetQuestion("signed.example.com.", dns.TypeAAAA)
		req.AuthenticatedData = true // bogus/broken client flag
		if resp := env.p.handle(req); resp.AuthenticatedData {
			t.Fatal("query's own AD flag was echoed back instead of cleared")
		}
	})

	t.Run("nxdomain_relay", func(t *testing.T) {
		env := newDNSTestEnvWithSignedRecord(t)
		req := new(dns.Msg)
		req.SetQuestion("missing.example.com.", dns.TypeAAAA)
		resp := env.p.handle(req)
		if resp.Rcode != dns.RcodeNameError {
			t.Fatalf("expected NXDOMAIN, got %d", resp.Rcode)
		}
		if resp.AuthenticatedData {
			t.Fatal("rewritten negative response asserted AD")
		}
	})
}

// TestRFC6147S5_5ValidatingANYRelayedVerbatim verifies that a validating
// client's ANY query is relayed as ANY upstream rather than being rewritten
// into the AAAA synthesis path.
func TestRFC6147S5_5ValidatingANYRelayedVerbatim(t *testing.T) {
	env := newDNSTestEnvWithSignedRecord(t)

	resp := env.p.handle(newValidatingQuery("signed.example.com.", dns.TypeANY))

	if resp.Question[0].Qtype != dns.TypeANY {
		t.Fatalf("client question rewritten to qtype %d", resp.Question[0].Qtype)
	}
	seen := env.seen()
	if len(seen) != 1 || seen[0].qtype != dns.TypeANY {
		t.Fatalf("upstream must receive the ANY query itself, got %+v", seen)
	}
	if !resp.AuthenticatedData {
		t.Fatal("proxied ANY response must preserve upstream AD")
	}
}

// TestRFC6147S5_5SynthesisStillWorksForPlainQueries guards against regressions:
// ordinary queries keep receiving synthesised AAAAs after the DNSSEC gating.
func TestRFC6147S5_5SynthesisStillWorksForPlainQueries(t *testing.T) {
	env := newDNSTestEnvWithSignedRecord(t)

	req := new(dns.Msg)
	req.SetQuestion(fmt.Sprintf("%s", "signed.example.com."), dns.TypeAAAA)
	resp := env.p.handle(req)

	expected := "64:ff9b::c000:237"
	found := false
	for _, rr := range resp.Answer {
		if aaaa, ok := rr.(*dns.AAAA); ok && aaaa.AAAA.String() == expected {
			found = true
		}
	}
	if !found {
		t.Fatalf("plain query lost synthesis, want %s in %v", expected, resp.Answer)
	}
}
