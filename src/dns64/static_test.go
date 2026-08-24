package dns64

import (
	"net"
	"sync/atomic"
	"testing"
	"time"

	"github.com/miekg/dns"
)

// countingUpstream is a loopback fake forwarder that answers every query
// with one A record and counts how many times it was contacted — used to
// prove that static entries and blocked zones NEVER reach a forwarder.
type countingUpstream struct {
	pc     net.PacketConn
	server *dns.Server
	addr   string
	hits   atomic.Int64
}

func newCountingUpstream(t *testing.T) *countingUpstream {
	t.Helper()
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("ListenPacket: %v", err)
	}
	u := &countingUpstream{pc: pc, addr: pc.LocalAddr().String()}
	u.server = &dns.Server{
		PacketConn: pc,
		Handler: dns.HandlerFunc(func(w dns.ResponseWriter, req *dns.Msg) {
			u.hits.Add(1)
			resp := new(dns.Msg)
			resp.SetReply(req)
			rr, _ := dns.NewRR(req.Question[0].Name + " 60 IN A 192.0.2.99")
			resp.Answer = append(resp.Answer, rr)
			_ = w.WriteMsg(resp)
		}),
	}
	go func() { _ = u.server.ActivateAndServe() }()
	t.Cleanup(func() { _ = u.server.Shutdown(); pc.Close() })
	time.Sleep(50 * time.Millisecond)
	return u
}

func (u *countingUpstream) mustBeUntouched(t *testing.T, what string) {
	t.Helper()
	if n := u.hits.Load(); n != 0 {
		t.Fatalf("%s contacted the upstream %d time(s)", what, n)
	}
}

func queryReq(name string, qtype uint16) *dns.Msg {
	req := new(dns.Msg)
	req.SetQuestion(name, qtype)
	return req
}

// TestStaticLiteralAnswers pins the Dns64Static contract: exact-name local
// authoritative answers with the literal configured value — A records for
// IPv4 values, AAAA records for IPv6 values, no synthesis — and the forwarder
// is never contacted.
func TestStaticLiteralAnswers(t *testing.T) {
	up := newCountingUpstream(t)
	p := &proxy{cache: newCache(300*time.Second, 600*time.Second, 0)}
	p.reload(up.addr, IAIgnore, []zone{
		{domains: []string{"."}, prefix: testPref64()},
	}, nil, nil)
	p.setStatic(map[string]string{
		"v4.test.": "198.51.100.7",
		"v6.test.": "2001:db8::42",
	})

	cases := []struct {
		name     string
		qtype    uint16
		wantType uint16
		wantIP   string
	}{
		{"v4.test.", dns.TypeA, dns.TypeA, "198.51.100.7"},
		{"v6.test.", dns.TypeAAAA, dns.TypeAAAA, "2001:db8::42"},
	}
	for _, tc := range cases {
		resp := p.handle(queryReq(tc.name, tc.qtype))
		if resp.Rcode != dns.RcodeSuccess {
			t.Fatalf("%s/%d: rcode %d, want NOERROR", tc.name, tc.qtype, resp.Rcode)
		}
		if len(resp.Answer) != 1 {
			t.Fatalf("%s/%d: answers = %d, want 1", tc.name, tc.qtype, len(resp.Answer))
		}
		switch rr := resp.Answer[0].(type) {
		case *dns.A:
			if tc.wantType != dns.TypeA || rr.A.String() != tc.wantIP {
				t.Errorf("%s: got A %s", tc.name, rr.A)
			}
			if rr.Header().Ttl != staticRecordTTL {
				t.Errorf("%s: TTL = %d, want %d", tc.name, rr.Header().Ttl, staticRecordTTL)
			}
		case *dns.AAAA:
			if tc.wantType != dns.TypeAAAA || rr.AAAA.String() != tc.wantIP {
				t.Errorf("%s: got AAAA %s", tc.name, rr.AAAA)
			}
		default:
			t.Errorf("%s: unexpected record type %T", tc.name, resp.Answer[0])
		}
		if !resp.Response || !resp.RecursionAvailable {
			t.Errorf("%s: response flags wrong (Response=%v RA=%v)", tc.name, resp.Response, resp.RecursionAvailable)
		}
	}
	up.mustBeUntouched(t, "static lookups")
}

// TestStaticWrongFamilyNODATA verifies that querying a static name for the
// family it does not have yields empty NOERROR (NODATA) — the name exists,
// it just has no record of that type — and never synthesises nor forwards.
func TestStaticWrongFamilyNODATA(t *testing.T) {
	up := newCountingUpstream(t)
	p := &proxy{cache: newCache(300*time.Second, 600*time.Second, 0)}
	p.reload(up.addr, IAIgnore, []zone{
		{domains: []string{"."}, prefix: testPref64()},
	}, nil, nil)
	p.setStatic(map[string]string{"only4.test.": "203.0.113.5", "only6.test.": "2001:db8::1"})

	for _, tc := range []struct {
		name  string
		qtype uint16
	}{{"only4.test.", dns.TypeAAAA}, {"only6.test.", dns.TypeA}} {
		resp := p.handle(queryReq(tc.name, tc.qtype))
		if resp.Rcode != dns.RcodeSuccess {
			t.Errorf("%s/%d: rcode %d, want NOERROR (NODATA)", tc.name, tc.qtype, resp.Rcode)
		}
		if len(resp.Answer) != 0 {
			t.Errorf("%s/%d: answers = %d, want 0", tc.name, tc.qtype, len(resp.Answer))
		}
	}
	up.mustBeUntouched(t, "wrong-family static lookups")
}

// TestStaticExactMatchOnly checks name normalisation: case-insensitive and
// trailing-dot-insensitive exact matches hit; subdomains do not inherit.
func TestStaticExactMatchOnly(t *testing.T) {
	p := &proxy{}
	p.setStatic(map[string]string{"Host.Example": "192.0.2.10"}) // no trailing dot, mixed case

	if _, ok := p.lookupStatic("host.example."); !ok {
		t.Error("normalised exact match failed (case/trailing dot)")
	}
	if _, ok := p.lookupStatic("sub.host.example."); ok {
		t.Error("subdomain wrongly inherited the static entry")
	}
	if _, ok := p.lookupStatic("other.example."); ok {
		t.Error("unrelated name wrongly matched")
	}
}

// TestStaticOverridesBlockedZoneAndDefaultZone proves static data wins over
// zone rules — including over a BLOCKED catch-all zone that would otherwise
// NXDOMAIN everything — because it is local authoritative data.
func TestStaticOverridesBlockedZoneAndDefaultZone(t *testing.T) {
	up := newCountingUpstream(t)
	p := &proxy{cache: newCache(300*time.Second, 600*time.Second, 0)}
	p.reload(up.addr, IAIgnore, []zone{
		{domains: []string{"blocked.example"}, returnIPv6Addresses: true},
		{domains: []string{"."}}, // blocked catch-all: no prefix, no flags
	}, nil, nil)
	p.setStatic(map[string]string{"pin.blocked.example": "192.0.2.20", "plain.name": "192.0.2.21"})

	for _, name := range []string{"pin.blocked.example.", "plain.name."} {
		resp := p.handle(queryReq(name, dns.TypeA))
		if resp.Rcode != dns.RcodeSuccess || len(resp.Answer) != 1 {
			t.Fatalf("%s: static entry not served over blocked zone (rcode %d, %d answers)",
				name, resp.Rcode, len(resp.Answer))
		}
	}
	// The same resolver's BLOCKED CATCH-ALL still hard-blocks everything
	// that isn't static and isn't covered by an earlier zone.
	if resp := p.handle(queryReq("other.unrelated.", dns.TypeA)); resp.Rcode != dns.RcodeNameError {
		t.Errorf("non-static name under blocked catch-all: rcode %d, want NXDOMAIN", resp.Rcode)
	}
	up.mustBeUntouched(t, "static/blocked-zone queries")
}

// TestReloadSwapsStaticEntries verifies SIGHUP-style reload semantics: a
// swapped Dns64Static table fully replaces the previous one.
func TestReloadSwapsStaticEntries(t *testing.T) {
	p := &proxy{}
	p.setStatic(map[string]string{"old.name": "192.0.2.1"})
	if _, ok := p.lookupStatic("old.name"); !ok {
		t.Fatal("initial static entry missing")
	}
	p.setStatic(map[string]string{"new.name": "192.0.2.2"})
	if _, ok := p.lookupStatic("old.name"); ok {
		t.Error("old entry survived the swap")
	}
	if _, ok := p.lookupStatic("new.name"); !ok {
		t.Error("new entry missing after swap")
	}
}

// TestBlockedZoneNXDOMAINAllTypes pins the empty-zone rule: a zone without
// NAT64 synthesis or pass-through answers EVERY query type with a local
// authoritative NXDOMAIN and never contacts any forwarder.
func TestBlockedZoneNXDOMAINAllTypes(t *testing.T) {
	up := newCountingUpstream(t)
	p := &proxy{cache: newCache(300*time.Second, 600*time.Second, 0)}
	p.reload(up.addr, IAIgnore, []zone{
		{domains: []string{"empty.test"}}, // no prefix, no flags → blocked
		{domains: []string{"."}, prefix: testPref64()},
	}, nil, nil)

	for _, qtype := range []uint16{dns.TypeA, dns.TypeAAAA, dns.TypeANY, dns.TypeTXT, dns.TypeMX, dns.TypePTR} {
		resp := p.handle(queryReq("anything.empty.test.", qtype))
		if resp.Rcode != dns.RcodeNameError {
			t.Errorf("type %d: rcode %d, want NXDOMAIN from blocked zone", qtype, resp.Rcode)
		}
		if len(resp.Answer) != 0 {
			t.Errorf("type %d: %d answers, want none", qtype, len(resp.Answer))
		}
	}
	up.mustBeUntouched(t, "blocked-zone queries")

	// Control: the SAME resolver still serves other zones normally.
	resp := p.handle(queryReq("live.other.", dns.TypeAAAA))
	if resp.Rcode == dns.RcodeNameError {
		t.Error("catch-all zone was wrongly treated as blocked")
	}
}

// TestParseStaticEntriesSkipsGarbage keeps parse-time behaviour pinned even
// though config validation rejects invalid values earlier: garbage rows are
// skipped, not fatal.
func TestParseStaticEntriesSkipsGarbage(t *testing.T) {
	m := parseStaticEntries(map[string]string{
		"good.test": "192.0.2.1",
		"bad.test":  "not-an-ip",
		"":          "192.0.2.2",
	})
	if len(m) != 1 {
		t.Fatalf("entries = %d (%v), want only the valid one", len(m), m)
	}
	if ip := m["good.test"]; ip == nil || ip.String() != "192.0.2.1" {
		t.Errorf("good.test = %v", ip)
	}
}
