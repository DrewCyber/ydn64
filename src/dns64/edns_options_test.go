package dns64

import (
	"fmt"
	"net"
	"testing"
	"time"

	"github.com/miekg/dns"
)

const (
	testClientCookie = "a1b2c3d4e5f60718"
	testServerCookie = testClientCookie + "9999999988776655"
)

// newEdnsReq builds a client query; bufsize 0 means a classic non-EDNS
// query. Otherwise the OPT carries a COOKIE and an ECS option when
// withOptions is set.
func newEdnsReq(name string, bufsize uint16, do bool, withOptions bool) *dns.Msg {
	req := new(dns.Msg)
	req.SetQuestion(name, dns.TypeAAAA)
	if bufsize == 0 {
		return req
	}
	req.SetEdns0(bufsize, do)
	if withOptions {
		opt := req.IsEdns0()
		opt.Option = append(opt.Option,
			&dns.EDNS0_COOKIE{Code: dns.EDNS0COOKIE, Cookie: testClientCookie},
			&dns.EDNS0_SUBNET{
				Code:          dns.EDNS0SUBNET,
				Family:        1,
				SourceNetmask: 24,
				Address:       net.ParseIP("192.0.2.0").To4(),
			},
			&dns.EDNS0_NSID{Code: dns.EDNS0NSID},
		)
	}
	return req
}

// upstreamOPTWith builds an OPT record as an upstream resolver would send
// back: echoed client cookie + appended server cookie, an ECS response, NSID.
func upstreamOPTWith(options ...dns.EDNS0) *dns.OPT {
	opt := new(dns.OPT)
	opt.Hdr.Name = "."
	opt.Hdr.Rrtype = dns.TypeOPT
	opt.SetUDPSize(1232)
	opt.Option = append(opt.Option, options...)
	return opt
}

func findCookie(rrs []dns.RR) *dns.EDNS0_COOKIE {
	if opt := findOPT(rrs); opt != nil {
		for _, o := range opt.Option {
			if c, ok := o.(*dns.EDNS0_COOKIE); ok {
				return c
			}
		}
	}
	return nil
}

func findSubnet(rrs []dns.RR) *dns.EDNS0_SUBNET {
	if opt := findOPT(rrs); opt != nil {
		for _, o := range opt.Option {
			if s, ok := o.(*dns.EDNS0_SUBNET); ok {
				return s
			}
		}
	}
	return nil
}

func findOPT(rrs []dns.RR) *dns.OPT {
	var found *dns.OPT
	for _, rr := range rrs {
		if opt, ok := rr.(*dns.OPT); ok {
			found = opt // keep last to detect duplicates below
		}
	}
	return found
}

func countOPT(rrs []dns.RR) int {
	n := 0
	for _, rr := range rrs {
		if rr.Header().Rrtype == dns.TypeOPT {
			n++
		}
	}
	return n
}

// TestFinalizeResponseEdnsRelaysUpstreamOptions is the RFC 6891/RFC 7873
// passthrough core: when the response carries an upstream OPT, its options
// are relayed verbatim inside ydn64's own OPT (size advertisement and DO bit
// stay ydn64-owned), and exactly one OPT reaches the client.
func TestFinalizeResponseEdnsRelaysUpstreamOptions(t *testing.T) {
	req := newEdnsReq("example.com.", 4096, true, true)
	resp := new(dns.Msg)
	resp.SetReply(req)
	resp.Extra = append(resp.Extra, upstreamOPTWith(
		&dns.EDNS0_COOKIE{Code: dns.EDNS0COOKIE, Cookie: testServerCookie},
		&dns.EDNS0_SUBNET{
			Code:          dns.EDNS0SUBNET,
			Family:        1,
			SourceNetmask: 24,
			SourceScope:   0,
			Address:       net.ParseIP("192.0.2.0").To4(),
		},
		&dns.EDNS0_NSID{Code: dns.EDNS0NSID, Nsid: "7570646e34"},
	))

	size := finalizeResponseEdns(resp, req)
	if size != maxUDPSize {
		t.Errorf("negotiated size = %d, want %d", size, maxUDPSize)
	}

	if n := countOPT(resp.Extra); n != 1 {
		t.Fatalf("OPT records in response = %d, want 1", n)
	}
	out := resp.IsEdns0()
	if out == nil {
		t.Fatal("response lost its OPT")
	}
	if got := out.UDPSize(); got != maxUDPSize {
		t.Errorf("response advertises UDPSize %d, want %d", got, maxUDPSize)
	}
	if !out.Do() {
		t.Error("DO bit not propagated from the query")
	}
	if c := findCookie(resp.Extra); c == nil || c.Cookie != testServerCookie {
		t.Errorf("upstream server cookie not relayed: %+v", c)
	}
	if s := findSubnet(resp.Extra); s == nil || s.SourceNetmask != 24 {
		t.Errorf("upstream ECS response not relayed: %+v", s)
	}
}

// TestFinalizeResponseEdnsLocalAnswerEchoesCookie covers locally generated
// answers (no upstream OPT): only the client's COOKIE is echoed — required of
// the responding server by RFC 7873 §5.2 — while other request options are
// ignored per RFC 7871 §6 rather than reflected.
func TestFinalizeResponseEdnsLocalAnswerEchoesCookie(t *testing.T) {
	req := newEdnsReq("ipv4only.arpa.", 1232, false, true)
	resp := new(dns.Msg)
	resp.SetReply(req) // no upstream OPT anywhere in Extra

	finalizeResponseEdns(resp, req)

	if n := countOPT(resp.Extra); n != 1 {
		t.Fatalf("OPT records in response = %d, want 1", n)
	}
	if c := findCookie(resp.Extra); c == nil || c.Cookie != testClientCookie {
		t.Errorf("client cookie not echoed on local answer: %+v", c)
	}
	if s := findSubnet(resp.Extra); s != nil {
		t.Error("unsupported request option CLIENT-SUBNET was echoed back")
	}
}

// TestFinalizeResponseEdnsClassicClient pins RFC 6891 §6.1.1 behaviour for
// non-EDNS queries: no OPT may appear in the response even when one was
// relayed from upstream.
func TestFinalizeResponseEdnsClassicClient(t *testing.T) {
	req := newEdnsReq("example.com.", 0, false, false)
	resp := new(dns.Msg)
	resp.SetReply(req)
	resp.Extra = append(resp.Extra, upstreamOPTWith(
		&dns.EDNS0_COOKIE{Code: dns.EDNS0COOKIE, Cookie: testServerCookie},
	))

	size := finalizeResponseEdns(resp, req)
	if size != legacyMaxMsgSize {
		t.Errorf("negotiated size = %d, want legacy %d", size, legacyMaxMsgSize)
	}
	if n := countOPT(resp.Extra); n != 0 {
		t.Errorf("classic client received %d OPT record(s), want 0", n)
	}
}

// TestFinalizeResponseEdnsTruncationKeepsOptions verifies that attaching
// options before truncation does not lose them: the OPT must survive
// Truncate alongside the TC bit (RFC 6891 §6.1.2 truncation rules).
func TestFinalizeResponseEdnsTruncationKeepsOptions(t *testing.T) {
	req := newEdnsReq("big.example.com.", 512, false, true)
	resp := new(dns.Msg)
	resp.SetReply(req)
	for i := 0; i < 50; i++ {
		rr, err := dns.NewRR(fmt.Sprintf("big.example.com. 300 IN AAAA 2001:db8::%x", i))
		if err != nil {
			t.Fatalf("NewRR: %v", err)
		}
		resp.Answer = append(resp.Answer, rr)
	}
	resp.Extra = append(resp.Extra, upstreamOPTWith(
		&dns.EDNS0_COOKIE{Code: dns.EDNS0COOKIE, Cookie: testServerCookie},
	))

	size := finalizeResponseEdns(resp, req)
	if resp.Len() > size {
		resp.Truncate(size)
	}
	if !resp.Truncated {
		t.Fatal("expected TC bit for an oversized response")
	}
	if c := findCookie(resp.Extra); c == nil || c.Cookie != testServerCookie {
		t.Errorf("relayed cookie lost during truncation: %+v", c)
	}
}

// TestEDNSOptionsEndToEndThroughProxy drives proxy.handle against a fake
// upstream that attaches COOKIE+ECS options to both the (empty) AAAA answer
// and the A answer used for synthesis, then runs the same finalize step
// serveUDP performs. It asserts both directions: the client's options reach
// the upstream verbatim, and the upstream's options come back through the
// synthesised response.
func TestEDNSOptionsEndToEndThroughProxy(t *testing.T) {
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to listen UDP: %v", err)
	}
	defer pc.Close()

	// The AAAA miss triggers a second (A) upstream query, so collect every
	// captured query through a channel instead of a shared variable.
	queries := make(chan *dns.Msg, 8)
	dnsServer := &dns.Server{
		PacketConn: pc,
		Handler: dns.HandlerFunc(func(w dns.ResponseWriter, req *dns.Msg) {
			queries <- req.Copy()
			resp := new(dns.Msg)
			resp.SetReply(req)
			resp.Extra = append(resp.Extra, upstreamOPTWith(
				&dns.EDNS0_COOKIE{Code: dns.EDNS0COOKIE, Cookie: testServerCookie},
				&dns.EDNS0_SUBNET{
					Code:          dns.EDNS0SUBNET,
					Family:        1,
					SourceNetmask: 24,
					Address:       net.ParseIP("192.0.2.0").To4(),
				},
			))
			if len(req.Question) == 1 && req.Question[0].Qtype == dns.TypeA {
				rr, _ := dns.NewRR(req.Question[0].Name + " 300 IN A 198.51.100.7")
				resp.Answer = append(resp.Answer, rr)
			}
			_ = w.WriteMsg(resp)
		}),
	}
	go func() { _ = dnsServer.ActivateAndServe() }()
	defer dnsServer.Shutdown()
	time.Sleep(50 * time.Millisecond)

	p := &proxy{cache: newCache(300*time.Second, 600*time.Second, 0)}
	p.reload(pc.LocalAddr().String(), IAIgnore, []zone{
		{domains: []string{"."}, prefix: testPref64()},
	}, nil, nil)

	req := newEdnsReq("opts.example.com.", 4096, false, true)
	resp := p.handle(req)
	if resp.Rcode != dns.RcodeSuccess || len(resp.Answer) == 0 {
		t.Fatalf("synthesis failed: rcode %d, answers %d", resp.Rcode, len(resp.Answer))
	}

	// Query side: the client's own options must have reached the upstream
	// untouched (ydn64 forwards the OPT verbatim). Drain every captured
	// query; both exchanges must carry them.
	for {
		select {
		case capturedQuery := <-queries:
			upQ := findOPT(capturedQuery.Extra)
			if upQ == nil {
				t.Fatal("upstream query carried no OPT")
			}
			var sawCookie, sawSubnet bool
			for _, o := range upQ.Option {
				switch v := o.(type) {
				case *dns.EDNS0_COOKIE:
					sawCookie = v.Cookie == testClientCookie
				case *dns.EDNS0_SUBNET:
					sawSubnet = v.SourceNetmask == 24
				}
			}
			if !sawCookie || !sawSubnet {
				t.Errorf("client options not forwarded verbatim (cookie=%v subnet=%v)", sawCookie, sawSubnet)
			}
			continue
		default:
		}
		break
	}

	// Response side: same composition serveUDP uses.
	finalizeResponseEdns(resp, req)
	if c := findCookie(resp.Extra); c == nil || c.Cookie != testServerCookie {
		t.Errorf("server cookie did not survive the synthesised response: %+v", c)
	}
	if s := findSubnet(resp.Extra); s == nil {
		t.Error("upstream ECS response dropped by the synthesised response")
	}
}
