package dns64

import (
	"fmt"
	"net"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/DrewCyber/ydn64/src/config"
	"github.com/miekg/dns"
)

// testPref64 returns the Well-Known-Prefix-shaped /96 Pref64 used by the
// proxy tests.
func testPref64() *config.Pref64 {
	p, err := config.ParsePref64Addr("64:ff9b::")
	if err != nil {
		panic(err)
	}
	return p
}

func TestDNS64IgnoredDstSubnets(t *testing.T) {
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to listen UDP: %v", err)
	}
	defer pc.Close()

	serverAddr := pc.LocalAddr().String()

	dnsServer := &dns.Server{
		PacketConn: pc,
		Handler: dns.HandlerFunc(func(w dns.ResponseWriter, req *dns.Msg) {
			resp := new(dns.Msg)
			resp.SetReply(req)
			if len(req.Question) == 0 {
				w.WriteMsg(resp)
				return
			}
			q := req.Question[0]
			name := strings.ToLower(q.Name)

			switch name {
			case "public.example.com.":
				if q.Qtype == dns.TypeA {
					rr, _ := dns.NewRR("public.example.com. 300 IN A 1.1.1.1")
					resp.Answer = append(resp.Answer, rr)
				}
			case "private.example.com.":
				if q.Qtype == dns.TypeA {
					rr, _ := dns.NewRR("private.example.com. 300 IN A 10.0.0.1")
					resp.Answer = append(resp.Answer, rr)
				}
			case "loopback.example.com.":
				if q.Qtype == dns.TypeA {
					rr, _ := dns.NewRR("loopback.example.com. 300 IN A 127.0.0.1")
					resp.Answer = append(resp.Answer, rr)
				}
			}
			w.WriteMsg(resp)
		}),
	}

	go func() {
		_ = dnsServer.ActivateAndServe()
	}()
	defer dnsServer.Shutdown()

	time.Sleep(50 * time.Millisecond)

	p := &proxy{
		cache: newCache(300*time.Second, 600*time.Second, 0),
	}

	prefix := testPref64()
	ignoredNets := config.ParseIPNets([]string{"10.0.0.0/8", "127.0.0.0/8"})

	p.reload(serverAddr, IAIgnore, []zone{
		{
			domains:             []string{"."},
			prefix:              prefix,
			returnIPv4Addresses: false,
			returnIPv6Addresses: false,
		},
	}, ignoredNets, nil)

	// Test public IP synthesis -> should succeed
	{
		req := new(dns.Msg)
		req.SetQuestion("public.example.com.", dns.TypeAAAA)
		resp := p.handle(req)
		if resp.Rcode != dns.RcodeSuccess || len(resp.Answer) != 1 {
			t.Fatalf("expected 1 synthetic AAAA answer for public IP, got rcode %d, len %d", resp.Rcode, len(resp.Answer))
		}
	}

	// Test private IP synthesis (10.0.0.1) -> should be filtered out (0 answers)
	{
		req := new(dns.Msg)
		req.SetQuestion("private.example.com.", dns.TypeAAAA)
		resp := p.handle(req)
		if resp.Rcode != dns.RcodeSuccess {
			t.Fatalf("expected RcodeSuccess, got %d", resp.Rcode)
		}
		if len(resp.Answer) != 0 {
			t.Errorf("expected 0 answers for private IP 10.0.0.1, got %d", len(resp.Answer))
		}
	}

	// Test loopback IP synthesis (127.0.0.1) -> should be filtered out (0 answers)
	{
		req := new(dns.Msg)
		req.SetQuestion("loopback.example.com.", dns.TypeAAAA)
		resp := p.handle(req)
		if resp.Rcode != dns.RcodeSuccess {
			t.Fatalf("expected RcodeSuccess, got %d", resp.Rcode)
		}
		if len(resp.Answer) != 0 {
			t.Errorf("expected 0 answers for loopback IP 127.0.0.1, got %d", len(resp.Answer))
		}
	}
}

func TestDNS64ErrorRcodeHandling(t *testing.T) {
	// 1. Start a mock DNS server on a random port.
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to listen UDP: %v", err)
	}
	defer pc.Close()

	serverAddr := pc.LocalAddr().String()

	dnsServer := &dns.Server{
		PacketConn: pc,
		Handler: dns.HandlerFunc(func(w dns.ResponseWriter, req *dns.Msg) {
			resp := new(dns.Msg)
			resp.SetReply(req)
			if len(req.Question) == 0 {
				w.WriteMsg(resp)
				return
			}
			q := req.Question[0]
			name := strings.ToLower(q.Name)

			switch name {
			case "nxdomain.example.com.":
				resp.SetRcode(req, dns.RcodeNameError)
			case "servfail.example.com.":
				resp.SetRcode(req, dns.RcodeServerFailure)
			case "empty.example.com.":
				resp.SetRcode(req, dns.RcodeSuccess)
			case "synth.example.com.":
				resp.SetRcode(req, dns.RcodeSuccess)
				if q.Qtype == dns.TypeA {
					rr, _ := dns.NewRR(fmt.Sprintf("%s 300 IN A 1.2.3.4", q.Name))
					if rr != nil {
						resp.Answer = append(resp.Answer, rr)
					}
				}
			default:
				resp.SetRcode(req, dns.RcodeNameError)
			}
			w.WriteMsg(resp)
		}),
	}

	go func() {
		_ = dnsServer.ActivateAndServe()
	}()
	defer dnsServer.Shutdown()

	// Wait briefly for the server to be active
	time.Sleep(50 * time.Millisecond)

	// 2. Set up our proxy instance.
	p := &proxy{
		cache: newCache(300*time.Second, 600*time.Second, 0),
	}

	prefix := testPref64()
	if prefix == nil {
		t.Fatal("failed to parse prefix")
	}

	p.reload(serverAddr, IAIgnore, []zone{
		{
			domains:             []string{"."},
			prefix:              prefix,
			returnIPv4Addresses: false,
			returnIPv6Addresses: false,
		},
	}, nil, nil)

	// 3. Test Cases.
	tests := []struct {
		name         string
		expectedR    int
		expectedAns  int
		expectSynth  bool
		synthAddress string
	}{
		{
			name:        "nxdomain.example.com.",
			expectedR:   dns.RcodeNameError,
			expectedAns: 0,
		},
		{
			name:        "servfail.example.com.",
			expectedR:   dns.RcodeServerFailure,
			expectedAns: 0,
		},
		{
			name:        "empty.example.com.",
			expectedR:   dns.RcodeSuccess,
			expectedAns: 0,
		},
		{
			name:         "synth.example.com.",
			expectedR:    dns.RcodeSuccess,
			expectedAns:  1,
			expectSynth:  true,
			synthAddress: "64:ff9b::102:304", // 1.2.3.4 embedded in 64:ff9b::
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			req := new(dns.Msg)
			req.SetQuestion(tc.name, dns.TypeAAAA)
			resp := p.handle(req)

			if resp.Rcode != tc.expectedR {
				t.Errorf("expected Rcode %d (%s), got %d (%s)",
					tc.expectedR, dns.RcodeToString[tc.expectedR],
					resp.Rcode, dns.RcodeToString[resp.Rcode],
				)
			}

			if len(resp.Answer) != tc.expectedAns {
				t.Errorf("expected %d answers, got %d", tc.expectedAns, len(resp.Answer))
			}

			if tc.expectSynth {
				if len(resp.Answer) > 0 {
					aaaa, ok := resp.Answer[0].(*dns.AAAA)
					if !ok {
						t.Errorf("expected AAAA record, got %T", resp.Answer[0])
					} else {
						gotIP := aaaa.AAAA.String()
						expectedIP := net.ParseIP(tc.synthAddress).String()
						if gotIP != expectedIP {
							t.Errorf("expected synthesised IP %s, got %s", expectedIP, gotIP)
						}
					}
				}
			}
		})
	}
}

func TestIPv4OnlyARPALocalAnswering(t *testing.T) {
	p := &proxy{
		cache: newCache(300*time.Second, 600*time.Second, 0),
	}

	prefix := testPref64()
	if prefix == nil {
		t.Fatal("failed to parse prefix")
	}

	// We set up two zones: one with a prefix, and one without.
	p.reload("127.0.0.1:53", IAIgnore, []zone{
		{
			domains:             []string{"."},
			prefix:              prefix,
			returnIPv4Addresses: false,
			returnIPv6Addresses: false,
		},
	}, nil, nil)

	// Test case 1: AAAA query on catch-all zone with prefix
	{
		req := new(dns.Msg)
		req.SetQuestion("ipv4only.arpa.", dns.TypeAAAA)
		resp := p.handle(req)

		if resp.Rcode != dns.RcodeSuccess {
			t.Errorf("expected RcodeSuccess, got %d", resp.Rcode)
		}
		if len(resp.Answer) != 2 {
			t.Errorf("expected 2 answers, got %d", len(resp.Answer))
		}
		for i, expectedIP := range []string{"64:ff9b::c000:aa", "64:ff9b::c000:ab"} { // 192.0.0.170 and 192.0.0.171
			if i < len(resp.Answer) {
				aaaa, ok := resp.Answer[i].(*dns.AAAA)
				if !ok {
					t.Fatalf("expected AAAA record, got %T", resp.Answer[i])
				}
				if aaaa.AAAA.String() != net.ParseIP(expectedIP).String() {
					t.Errorf("expected %s, got %s", expectedIP, aaaa.AAAA.String())
				}
				if aaaa.Header().Ttl != 60 {
					t.Errorf("expected TTL 60, got %d", aaaa.Header().Ttl)
				}
			}
		}
	}

	// Test case 2: A query on catch-all zone
	{
		req := new(dns.Msg)
		req.SetQuestion("ipv4only.arpa.", dns.TypeA)
		resp := p.handle(req)

		if resp.Rcode != dns.RcodeSuccess {
			t.Errorf("expected RcodeSuccess, got %d", resp.Rcode)
		}
		if len(resp.Answer) != 2 {
			t.Errorf("expected 2 answers, got %d", len(resp.Answer))
		}
		for i, expectedIP := range []string{"192.0.0.170", "192.0.0.171"} {
			if i < len(resp.Answer) {
				a, ok := resp.Answer[i].(*dns.A)
				if !ok {
					t.Fatalf("expected A record, got %T", resp.Answer[i])
				}
				if a.A.String() != expectedIP {
					t.Errorf("expected %s, got %s", expectedIP, a.A.String())
				}
				if a.Header().Ttl != 60 {
					t.Errorf("expected TTL 60, got %d", a.Header().Ttl)
				}
			}
		}
	}

	// Test case 3: Zone with prefix == nil
	// A zone with no prefix and no return flags is BLOCKED (the "empty-zone"
	// rule, see README's "Local answers" section): it answers every query
	// type with a local authoritative NXDOMAIN without contacting any
	// forwarder — including locally intercepted names like ipv4only.arpa,
	// which are only reachable through zones that can actually serve data.
	p.reload("127.0.0.1:53", IAIgnore, []zone{
		{
			domains:             []string{"."},
			prefix:              nil,
			returnIPv4Addresses: false,
			returnIPv6Addresses: false,
		},
	}, nil, nil)

	{
		req := new(dns.Msg)
		req.SetQuestion("ipv4only.arpa.", dns.TypeAAAA)
		resp := p.handle(req)

		if resp.Rcode != dns.RcodeNameError {
			t.Errorf("expected RcodeNameError from a blocked zone, got %d", resp.Rcode)
		}
		if len(resp.Answer) != 0 {
			t.Errorf("expected 0 answers, got %d", len(resp.Answer))
		}
	}
}

func TestDNS64NonINQClassAndSyntheticTTL(t *testing.T) {
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to listen UDP: %v", err)
	}
	defer pc.Close()

	serverAddr := pc.LocalAddr().String()

	dnsServer := &dns.Server{
		PacketConn: pc,
		Handler: dns.HandlerFunc(func(w dns.ResponseWriter, req *dns.Msg) {
			resp := new(dns.Msg)
			resp.SetReply(req)
			if len(req.Question) == 0 {
				w.WriteMsg(resp)
				return
			}
			q := req.Question[0]
			name := strings.ToLower(q.Name)

			// Handle non-IN qclass pass-through mock answer
			if q.Qclass == dns.ClassCHAOS {
				rr, _ := dns.NewRR(fmt.Sprintf("%s 100 CH TXT \"chaos-data\"", q.Name))
				if rr != nil {
					resp.Answer = append(resp.Answer, rr)
				}
				w.WriteMsg(resp)
				return
			}

			switch name {
			case "soa120.example.com.":
				if q.Qtype == dns.TypeAAAA {
					resp.SetRcode(req, dns.RcodeSuccess)
					soaRR, _ := dns.NewRR("soa120.example.com. 120 IN SOA ns1.example.com. admin.example.com. 1 7200 3600 1209600 3600")
					if soaRR != nil {
						resp.Ns = append(resp.Ns, soaRR)
					}
				} else if q.Qtype == dns.TypeA {
					resp.SetRcode(req, dns.RcodeSuccess)
					aRR, _ := dns.NewRR("soa120.example.com. 300 IN A 1.1.1.1")
					if aRR != nil {
						resp.Answer = append(resp.Answer, aRR)
					}
				}
			case "soa900.example.com.":
				if q.Qtype == dns.TypeAAAA {
					resp.SetRcode(req, dns.RcodeSuccess)
					soaRR, _ := dns.NewRR("soa900.example.com. 900 IN SOA ns1.example.com. admin.example.com. 1 7200 3600 1209600 3600")
					if soaRR != nil {
						resp.Ns = append(resp.Ns, soaRR)
					}
				} else if q.Qtype == dns.TypeA {
					resp.SetRcode(req, dns.RcodeSuccess)
					aRR, _ := dns.NewRR("soa900.example.com. 300 IN A 1.1.1.2")
					if aRR != nil {
						resp.Answer = append(resp.Answer, aRR)
					}
				}
			case "nosoa1200.example.com.":
				if q.Qtype == dns.TypeAAAA {
					resp.SetRcode(req, dns.RcodeSuccess) // No SOA in Ns section
				} else if q.Qtype == dns.TypeA {
					resp.SetRcode(req, dns.RcodeSuccess)
					aRR, _ := dns.NewRR("nosoa1200.example.com. 1200 IN A 1.1.1.3")
					if aRR != nil {
						resp.Answer = append(resp.Answer, aRR)
					}
				}
			default:
				resp.SetRcode(req, dns.RcodeNameError)
			}
			w.WriteMsg(resp)
		}),
	}

	go func() {
		_ = dnsServer.ActivateAndServe()
	}()
	defer dnsServer.Shutdown()

	time.Sleep(50 * time.Millisecond)

	p := &proxy{
		cache: newCache(300*time.Second, 600*time.Second, 0),
	}

	prefix := testPref64()
	p.reload(serverAddr, IAIgnore, []zone{
		{
			domains:             []string{"."},
			prefix:              prefix,
			returnIPv4Addresses: false,
			returnIPv6Addresses: false,
		},
	}, nil, nil)

	// Test 1: non-IN Qclass pass-through
	t.Run("Non-IN Qclass pass-through", func(t *testing.T) {
		req := new(dns.Msg)
		req.SetQuestion("version.bind.", dns.TypeTXT)
		req.Question[0].Qclass = dns.ClassCHAOS
		resp := p.handle(req)

		if resp.Rcode != dns.RcodeSuccess {
			t.Fatalf("expected RcodeSuccess, got %d", resp.Rcode)
		}
		if len(resp.Answer) != 1 {
			t.Fatalf("expected 1 answer, got %d", len(resp.Answer))
		}
		txt, ok := resp.Answer[0].(*dns.TXT)
		if !ok {
			t.Fatalf("expected TXT record, got %T", resp.Answer[0])
		}
		if len(txt.Txt) == 0 || txt.Txt[0] != "chaos-data" {
			t.Errorf("expected TXT 'chaos-data', got %v", txt.Txt)
		}
	})

	// Test 2: Synthetic AAAA TTL = min(A TTL 300, SOA TTL 120) -> 120
	t.Run("Synthetic TTL capped by SOA TTL", func(t *testing.T) {
		req := new(dns.Msg)
		req.SetQuestion("soa120.example.com.", dns.TypeAAAA)
		resp := p.handle(req)

		if resp.Rcode != dns.RcodeSuccess || len(resp.Answer) != 1 {
			t.Fatalf("expected success with 1 answer, got rcode %d, len %d", resp.Rcode, len(resp.Answer))
		}
		aaaa, ok := resp.Answer[0].(*dns.AAAA)
		if !ok {
			t.Fatalf("expected AAAA record, got %T", resp.Answer[0])
		}
		if aaaa.Header().Ttl != 120 {
			t.Errorf("expected TTL 120, got %d", aaaa.Header().Ttl)
		}
	})

	// Test 3: Synthetic AAAA TTL = min(A TTL 300, SOA TTL 900) -> 300
	t.Run("Synthetic TTL capped by A TTL", func(t *testing.T) {
		req := new(dns.Msg)
		req.SetQuestion("soa900.example.com.", dns.TypeAAAA)
		resp := p.handle(req)

		if resp.Rcode != dns.RcodeSuccess || len(resp.Answer) != 1 {
			t.Fatalf("expected success with 1 answer, got rcode %d, len %d", resp.Rcode, len(resp.Answer))
		}
		aaaa, ok := resp.Answer[0].(*dns.AAAA)
		if !ok {
			t.Fatalf("expected AAAA record, got %T", resp.Answer[0])
		}
		if aaaa.Header().Ttl != 300 {
			t.Errorf("expected TTL 300, got %d", aaaa.Header().Ttl)
		}
	})

	// Test 4: Synthetic AAAA TTL = min(A TTL 1200, fallback 600) -> 600 when no SOA present
	t.Run("Synthetic TTL capped by 600s fallback when no SOA", func(t *testing.T) {
		req := new(dns.Msg)
		req.SetQuestion("nosoa1200.example.com.", dns.TypeAAAA)
		resp := p.handle(req)

		if resp.Rcode != dns.RcodeSuccess || len(resp.Answer) != 1 {
			t.Fatalf("expected success with 1 answer, got rcode %d, len %d", resp.Rcode, len(resp.Answer))
		}
		aaaa, ok := resp.Answer[0].(*dns.AAAA)
		if !ok {
			t.Fatalf("expected AAAA record, got %T", resp.Answer[0])
		}
		if aaaa.Header().Ttl != 600 {
			t.Errorf("expected TTL 600, got %d", aaaa.Header().Ttl)
		}
	})
}

// newTestProxy builds a proxy with a catch-all synthesis zone pointing at
// serverAddr, matching the setup used by the other handler tests.
func newTestProxy(serverAddr string) *proxy {
	p := &proxy{
		cache: newCache(300*time.Second, 600*time.Second, 0),
	}
	prefix := testPref64()
	if prefix == nil {
		panic("failed to parse prefix")
	}
	p.reload(serverAddr, IAIgnore, []zone{
		{
			domains:             []string{"."},
			prefix:              prefix,
			returnIPv4Addresses: false,
			returnIPv6Addresses: false,
		},
	}, nil, nil)
	return p
}

func startTestDNSServer(t *testing.T, handler dns.HandlerFunc) (string, net.PacketConn) {
	t.Helper()
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to listen UDP: %v", err)
	}
	server := &dns.Server{PacketConn: pc, Handler: handler}
	done := make(chan struct{})
	go func() {
		_ = server.ActivateAndServe()
		close(done)
	}()
	t.Cleanup(func() {
		_ = server.Shutdown()
		<-done
	})
	return pc.LocalAddr().String(), pc
}

// TestRFC5452UpstreamTXIDRandomized verifies that ydn64 picks its own random
// transaction ID for upstream queries instead of relaying the client's ID,
// and that the client still receives its response under its original ID.
func TestRFC5452UpstreamTXIDRandomized(t *testing.T) {
	const clientID uint16 = 0xBEEF

	var mu sync.Mutex
	var upstreamIDs []uint16

	addr, _ := startTestDNSServer(t, dns.HandlerFunc(func(w dns.ResponseWriter, req *dns.Msg) {
		// Only the final A query of each synthesis pair is counted; the
		// preceding AAAA query doubles the total traffic otherwise.
		if len(req.Question) == 1 && req.Question[0].Qtype == dns.TypeA {
			mu.Lock()
			upstreamIDs = append(upstreamIDs, req.Id)
			mu.Unlock()
		}
		resp := new(dns.Msg)
		resp.SetReply(req)
		if len(req.Question) == 1 && req.Question[0].Qtype == dns.TypeA {
			rr, _ := dns.NewRR(fmt.Sprintf("%s 300 IN A 192.0.2.10", req.Question[0].Name))
			if rr != nil {
				resp.Answer = append(resp.Answer, rr)
			}
		}
		w.WriteMsg(resp)
	}))

	p := newTestProxy(addr)

	const queries = 24
	for i := 0; i < queries; i++ {
		req := new(dns.Msg)
		// Unique names per iteration so the cache never serves a repeat.
		name := fmt.Sprintf("t%d.txid.example.com.", i)
		req.SetQuestion(name, dns.TypeAAAA)
		req.Id = clientID // set AFTER SetQuestion, which generates a fresh ID
		resp := p.handle(req)

		if resp.Rcode != dns.RcodeSuccess || len(resp.Answer) != 1 {
			t.Fatalf("query %d: expected success with 1 synthetic answer, got rcode %d, %d answers",
				i, resp.Rcode, len(resp.Answer))
		}
		if resp.Id != clientID {
			t.Fatalf("query %d: client-facing response must carry the client's ID 0x%04X, got 0x%04X",
				i, clientID, resp.Id)
		}
	}

	mu.Lock()
	defer mu.Unlock()
	if len(upstreamIDs) != queries {
		t.Fatalf("expected %d upstream queries, server saw %d", queries, len(upstreamIDs))
	}
	distinct := make(map[uint16]bool)
	for _, id := range upstreamIDs {
		distinct[id] = true
		if id == clientID {
			t.Errorf("client-supplied ID 0x%04X was relayed upstream verbatim", clientID)
		}
	}
	// With a per-query random ID, 24 queries collapsing to a single distinct
	// ID has probability ~24·(1/65536)^23 — effectively impossible.
	if len(distinct) < 2 {
		t.Errorf("upstream transaction IDs show no variation (%d distinct in %d queries)", len(distinct), queries)
	}
}

// TestRFC5452ForgedAnswerRejected verifies that an upstream reply carrying a
// transaction ID other than the one ydn64 sent is not accepted: the query
// fails closed with SERVFAIL rather than returning spoofed data.
//
// The ~5 s duration is inherent to what is being verified: after discarding a
// mismatched ID, the DNS library keeps waiting for the genuine answer until
// its timeout expires — an attacker must hold that whole window. The mock
// server never sends a matching reply, so ydn64 surfaces the timeout as
// SERVFAIL.
func TestRFC5452ForgedAnswerRejected(t *testing.T) {
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to listen UDP: %v", err)
	}
	serverAddr := pc.LocalAddr().String()

	dnsServer := &dns.Server{
		PacketConn: pc,
		Handler: dns.HandlerFunc(func(w dns.ResponseWriter, req *dns.Msg) {
			resp := new(dns.Msg)
			resp.SetReply(req)
			resp.Id = req.Id ^ 0xFFFF // forged: any ID but the one sent
			if len(req.Question) == 1 && req.Question[0].Qtype == dns.TypeA {
				rr, _ := dns.NewRR(fmt.Sprintf("%s 300 IN A 6.6.6.6", req.Question[0].Name))
				if rr != nil {
					resp.Answer = append(resp.Answer, rr)
				}
			}
			w.WriteMsg(resp)
			// Close the socket so the DNS library's read loop (which
			// discards mismatched IDs and keeps waiting for a match)
			// errors out promptly instead of sitting out its full timeout.
			pc.Close()
		}),
	}
	go func() {
		_ = dnsServer.ActivateAndServe()
	}()
	t.Cleanup(func() {
		_ = dnsServer.Shutdown()
	})

	p := newTestProxy(serverAddr)

	req := new(dns.Msg)
	req.SetQuestion("forged.example.com.", dns.TypeAAAA)
	resp := p.handle(req)

	if resp.Rcode != dns.RcodeServerFailure {
		t.Fatalf("forged-ID answer must fail closed as SERVFAIL, got rcode %d", resp.Rcode)
	}
	for _, rr := range resp.Answer {
		if aaaa, ok := rr.(*dns.AAAA); ok && aaaa.AAAA.String() == "64:ff9b::606:606" {
			t.Fatal("spoofed A record was synthesised into the client answer")
		}
	}
}

// TestRFC5452PassThroughRestoresClientID covers the handlers that forward the
// upstream response object itself (pass-through, A, PTR): even there the
// client must receive its own transaction ID back.
func TestRFC5452PassThroughRestoresClientID(t *testing.T) {
	const clientID uint16 = 0x1234

	addr, _ := startTestDNSServer(t, dns.HandlerFunc(func(w dns.ResponseWriter, req *dns.Msg) {
		resp := new(dns.Msg)
		resp.SetReply(req)
		w.WriteMsg(resp)
	}))

	p := newTestProxy(addr)

	for _, tc := range []struct {
		name  string
		qtype uint16
	}{
		{"passthrough.example.com.", dns.TypeTXT},
		{"direct-a.example.com.", dns.TypeA},
	} {
		req := new(dns.Msg)
		req.SetQuestion(tc.name, tc.qtype)
		req.Id = clientID // set AFTER SetQuestion, which generates a fresh ID
		resp := p.handle(req)
		if resp.Id != clientID {
			t.Errorf("%s: expected client ID 0x%04X in response, got 0x%04X", tc.name, clientID, resp.Id)
		}
	}
}

func TestDNS64CNAMEChainPreservationAndOwnerName(t *testing.T) {
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to listen UDP: %v", err)
	}
	defer pc.Close()

	serverAddr := pc.LocalAddr().String()

	dnsServer := &dns.Server{
		PacketConn: pc,
		Handler: dns.HandlerFunc(func(w dns.ResponseWriter, req *dns.Msg) {
			resp := new(dns.Msg)
			resp.SetReply(req)
			if len(req.Question) == 0 {
				w.WriteMsg(resp)
				return
			}
			q := req.Question[0]
			name := strings.ToLower(q.Name)

			if name == "alias.example.com." {
				if q.Qtype == dns.TypeAAAA {
					// No AAAA record, return CNAME
					cnameRR, _ := dns.NewRR("alias.example.com. 300 IN CNAME target.example.com.")
					resp.Answer = append(resp.Answer, cnameRR)
					resp.SetRcode(req, dns.RcodeSuccess)
				} else if q.Qtype == dns.TypeA {
					// Return CNAME chain + A record
					cnameRR, _ := dns.NewRR("alias.example.com. 300 IN CNAME target.example.com.")
					aRR, _ := dns.NewRR("target.example.com. 300 IN A 192.0.2.1")
					resp.Answer = append(resp.Answer, cnameRR, aRR)
					resp.SetRcode(req, dns.RcodeSuccess)
				}
			} else {
				resp.SetRcode(req, dns.RcodeNameError)
			}
			w.WriteMsg(resp)
		}),
	}

	go func() {
		_ = dnsServer.ActivateAndServe()
	}()
	defer dnsServer.Shutdown()

	time.Sleep(50 * time.Millisecond)

	p := &proxy{
		cache: newCache(300*time.Second, 600*time.Second, 0),
	}

	prefix := testPref64()
	p.reload(serverAddr, IAIgnore, []zone{
		{
			domains:             []string{"."},
			prefix:              prefix,
			returnIPv4Addresses: false,
			returnIPv6Addresses: false,
		},
	}, nil, nil)

	req := new(dns.Msg)
	req.SetQuestion("alias.example.com.", dns.TypeAAAA)
	resp := p.handle(req)

	if resp.Rcode != dns.RcodeSuccess {
		t.Fatalf("expected RcodeSuccess, got %d", resp.Rcode)
	}

	// Should preserve CNAME and synthetic AAAA record
	if len(resp.Answer) != 2 {
		t.Fatalf("expected 2 answers (CNAME + synthetic AAAA), got %d", len(resp.Answer))
	}

	cname, ok := resp.Answer[0].(*dns.CNAME)
	if !ok {
		t.Fatalf("expected answer[0] to be CNAME, got %T", resp.Answer[0])
	}
	if cname.Header().Name != "alias.example.com." {
		t.Errorf("expected CNAME owner name alias.example.com., got %s", cname.Header().Name)
	}
	if cname.Target != "target.example.com." {
		t.Errorf("expected CNAME target target.example.com., got %s", cname.Target)
	}

	aaaa, ok := resp.Answer[1].(*dns.AAAA)
	if !ok {
		t.Fatalf("expected answer[1] to be AAAA, got %T", resp.Answer[1])
	}
	// Per RFC 6147 §5.1.5/5.1.7: owner name of synthetic AAAA must be target.example.com.
	if aaaa.Header().Name != "target.example.com." {
		t.Errorf("expected synthetic AAAA owner name target.example.com., got %s", aaaa.Header().Name)
	}
	expectedIP := net.ParseIP("64:ff9b::192.0.2.1").String()
	if aaaa.AAAA.String() != expectedIP {
		t.Errorf("expected synthetic AAAA IP %s, got %s", expectedIP, aaaa.AAAA.String())
	}
}
