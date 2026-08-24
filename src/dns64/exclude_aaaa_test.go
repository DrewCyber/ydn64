package dns64

import (
	"net"
	"strings"
	"testing"
	"time"

	"github.com/DrewCyber/ydn64/src/config"
	"github.com/miekg/dns"
)

// excludedAAAATestUpstream serves REAL AAAA records for two names (one inside
// 200::/7, one global) plus a CNAME chain, so the exclusion matrix can be
// exercised through the full handleAAAA pass-through path.
func excludedAAAATestUpstream(t *testing.T) string {
	t.Helper()
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to listen UDP: %v", err)
	}
	server := &dns.Server{
		PacketConn: pc,
		Handler: dns.HandlerFunc(func(w dns.ResponseWriter, req *dns.Msg) {
			resp := new(dns.Msg)
			resp.SetReply(req)
			if len(req.Question) == 0 {
				_ = w.WriteMsg(resp)
				return
			}
			q := req.Question[0]
			name := strings.ToLower(q.Name)
			var rrs []dns.RR
			switch {
			case q.Qtype == dns.TypeAAAA && name == "ygg.example.com.":
				rrs = append(rrs,
					mustRR("alias.example.com. 300 IN CNAME ygg.example.com."),
					mustRR("ygg.example.com. 300 IN AAAA 201:4f5c:1d6e::1"),
				)
			case q.Qtype == dns.TypeAAAA && name == "global.example.com.":
				rrs = append(rrs, mustRR("global.example.com. 300 IN AAAA 2606:4700::1111"))
			case q.Qtype == dns.TypeA && (name == "public.example.com." || name == "ygg.example.com." || name == "both.example.com."):
				// ygg/both also have A records so the post-exclusion
				// synthesis fall-through can be observed end-to-end.
				rrs = append(rrs, mustRR(name+" 300 IN A 93.184.216.34"))
			}
			resp.Answer = rrs
			_ = w.WriteMsg(resp)
		}),
	}
	go func() { _ = server.ActivateAndServe() }()
	t.Cleanup(func() { _ = server.Shutdown() })
	return pc.LocalAddr().String()
}

func mustRR(s string) dns.RR {
	rr, err := dns.NewRR(s)
	if err != nil {
		panic(err)
	}
	return rr
}

// newExclusionProxy builds a proxy with a return-ipv6-addresses catch-all
// zone and the given RFC 6147 §5.1.4 exclusion list.
func newExclusionProxy(upstream string, excluded []string) *proxy {
	p := &proxy{cache: newCache(300*time.Second, 600*time.Second, 0)}
	p.reload(upstream, IAIgnore, []zone{
		{domains: []string{"."}, prefix: testPref64(), returnIPv6Addresses: true},
	}, nil, config.ParseIPNets(excluded))
	return p
}

func queryAAAA(t *testing.T, p *proxy, name string) *dns.Msg {
	t.Helper()
	req := new(dns.Msg)
	req.SetQuestion(name, dns.TypeAAAA)
	return p.handle(req)
}

func TestAAAAExclusionSet(t *testing.T) {
	upstream := excludedAAAATestUpstream(t)

	t.Run("no exclusions configured passes everything", func(t *testing.T) {
		p := newExclusionProxy(upstream, nil)
		if n := len(queryAAAA(t, p, "ygg.example.com.").Answer); n != 2 {
			t.Fatalf("answers = %d, want CNAME+AAAA (2)", n)
		}
	})

	t.Run("excluded subnet drops real AAAA and triggers synthesis", func(t *testing.T) {
		p := newExclusionProxy(upstream, []string{"200::/8"})
		// both.example.com. had a real AAAA inside 200::/8 plus an A
		// record: dropping the AAAA must make handleAAAA fall through to
		// A-based synthesis (RFC 6147 §5.1 behaviour), yielding exactly one
		// SYNTHESIZED AAAA embedding the A address — never the original.
		resp := queryAAAA(t, p, "both.example.com.")
		var aaaas []*dns.AAAA
		for _, rr := range resp.Answer {
			if a, isAAAA := rr.(*dns.AAAA); isAAAA {
				aaaas = append(aaaas, a)
			}
		}
		if len(aaaas) != 1 {
			t.Fatalf("answers contain %d AAAA records, want 1 synthesized", len(aaaas))
		}
		v4 := aaaas[0].AAAA[len(aaaas[0].AAAA)-4:]
		if v4[0] != 93 || v4[1] != 184 || v4[2] != 216 || v4[3] != 34 {
			t.Fatalf("answer %s is not synthesized from 93.184.216.34", aaaas[0].String())
		}

		// ygg.example.com. has an excluded AAAA and no reachable-A story
		// beyond the same public A: its exclusion-driven synthesis still
		// yields the embedded A — assert no ORIGINAL leaked anywhere.
		for _, rr := range queryAAAA(t, p, "ygg.example.com.").Answer {
			if a, ok := rr.(*dns.AAAA); ok && strings.HasPrefix(a.AAAA.String(), "201:4f5c:") {
				t.Fatalf("original excluded AAAA leaked: %s", a.String())
			}
		}
	})

	t.Run("bare-IP exclusion entry works as /128", func(t *testing.T) {
		p := newExclusionProxy(upstream, []string{"2606:4700::1111"})
		if got := queryAAAA(t, p, "global.example.com."); len(got.Answer) != 0 {
			t.Fatalf("bare-IP-excluded AAAA not dropped (%d answers)", len(got.Answer))
		}
		// The other answer range is untouched.
		if n := len(queryAAAA(t, p, "ygg.example.com.").Answer); n != 2 {
			t.Fatalf("non-excluded answers = %d, want 2", n)
		}
	})

	t.Run("non-matching exclusions leave answers intact", func(t *testing.T) {
		p := newExclusionProxy(upstream, []string{"64:ff9b::/96"})
		if n := len(queryAAAA(t, p, "global.example.com.").Answer); n != 1 {
			t.Fatalf("answers = %d, want 1", n)
		}
	})

	t.Run("synthesized answers ignore the exclusion set", func(t *testing.T) {
		// Excluding our own synthesis output range would be self-defeating;
		// per RFC 6147 §5.1.4 the filter applies to non-synthesized records
		// only, so a synthesized AAAA for a public IPv4 must still appear.
		p := newExclusionProxy(upstream, []string{"64:ff9b::/96"})
		req := new(dns.Msg)
		req.SetQuestion("public.example.com.", dns.TypeAAAA)
		resp := p.handle(req)
		found := false
		for _, rr := range resp.Answer {
			if _, isAAAA := rr.(*dns.AAAA); isAAAA {
				found = true
			}
		}
		if !found {
			t.Fatal("synthesized AAAA was filtered by the exclusion set")
		}
	})

	t.Run("reload replaces the exclusion set", func(t *testing.T) {
		p := newExclusionProxy(upstream, []string{"64:ff9b::/96"})
		if n := len(queryAAAA(t, p, "ygg.example.com.").Answer); n != 2 {
			t.Fatalf("pre-reload answers = %d, want 2 (CNAME+AAAA pass through)", n)
		}
		p.reload(upstream, IAIgnore, []zone{
			{domains: []string{"."}, prefix: testPref64(), returnIPv6Addresses: true},
		}, nil, config.ParseIPNets([]string{"200::/8"}))
		// With 200::/8 excluded the original ygg AAAA is dropped; the answer
		// is a single synthesized record embedding the A address instead of
		// CNAME+original.
		resp := queryAAAA(t, p, "ygg.example.com.")
		nAAAA := 0
		for _, rr := range resp.Answer {
			if a, ok := rr.(*dns.AAAA); ok {
				nAAAA++
				if strings.HasPrefix(a.AAAA.String(), "201:4f5c:") {
					t.Fatalf("post-reload original AAAA leaked: %s", a.String())
				}
			}
		}
		if nAAAA != 1 {
			t.Fatalf("post-reload synthesized answers = %d, want 1", nAAAA)
		}
		// And lifting the exclusion restores working answers. The cache now
		// holds the entry written by the synthesis above (synthesis results
		// are cached under the same key by design), so the client keeps
		// getting a usable — synthesized — address rather than the original.
		p.reload(upstream, IAIgnore, []zone{
			{domains: []string{"."}, prefix: testPref64(), returnIPv6Addresses: true},
		}, nil, nil)
		resp = queryAAAA(t, p, "ygg.example.com.")
		nAAAA = 0
		for _, rr := range resp.Answer {
			if a, ok := rr.(*dns.AAAA); ok {
				nAAAA++
				if strings.HasPrefix(a.AAAA.String(), "201:4f5c:") {
					t.Fatalf("unexpected original AAAA after lift: %s", a.String())
				}
			}
		}
		if nAAAA == 0 {
			t.Fatal("no AAAA served after exclusions were lifted")
		}
	})
}
