package dns64

import (
	"net"
	"strconv"
	"testing"
	"time"

	"github.com/miekg/dns"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/adapters/gonet"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv6"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
	"gvisor.dev/gvisor/pkg/tcpip/transport/tcp"
	"gvisor.dev/gvisor/pkg/tcpip/transport/udp"

	"gvisor.dev/gvisor/pkg/tcpip/link/loopback"
)

// startDualTransportUpstream starts a fake upstream DNS server answering on
// BOTH UDP and TCP on 127.0.0.1:<ephemeral>, recording the transport network
// ("udp"/"tcp") of every query it receives. respond runs after the recording.
type dualUpstream struct {
	addr     string
	networks chan string
}

func startDualTransportUpstream(t *testing.T, respond func(w dns.ResponseWriter, req *dns.Msg)) *dualUpstream {
	t.Helper()
	up := &dualUpstream{networks: make(chan string, 32)}
	handler := dns.HandlerFunc(func(w dns.ResponseWriter, req *dns.Msg) {
		select {
		case up.networks <- w.RemoteAddr().Network():
		default:
		}
		respond(w, req)
	})

	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen udp: %v", err)
	}
	ln, err := net.Listen("tcp", pc.LocalAddr().String())
	if err != nil {
		t.Fatalf("listen tcp: %v", err)
	}
	up.addr = pc.LocalAddr().String()

	udpServer := &dns.Server{PacketConn: pc, Handler: handler}
	tcpServer := &dns.Server{Listener: ln, Handler: handler}
	go func() { _ = udpServer.ActivateAndServe() }()
	go func() { _ = tcpServer.ActivateAndServe() }()
	t.Cleanup(func() {
		_ = udpServer.Shutdown()
		_ = tcpServer.Shutdown()
	})
	time.Sleep(50 * time.Millisecond)
	return up
}

// networksSeen drains exactly n recorded transport names, failing early on
// timeout with whatever arrived.
func (u *dualUpstream) networksSeen(t *testing.T, n int) []string {
	t.Helper()
	out := make([]string, 0, n)
	deadline := time.After(2 * time.Second)
	for len(out) < n {
		select {
		case netw := <-u.networks:
			out = append(out, netw)
		case <-deadline:
			t.Fatalf("only %d of %d upstream exchanges observed within 2s", len(out), n)
		}
	}
	return out
}

func newPassthroughProxy(upstream string) *proxy {
	p := &proxy{cache: newCache(300*time.Second, 600*time.Second, 0)}
	p.reload(upstream, IAIgnore, []zone{
		{domains: []string{"."}, returnIPv4Addresses: true},
	}, nil, nil)
	return p
}

// TestTCPClientQueryProxiedOverTCPPins finding #2 of code-review-2026-08-24:
// a query served over TCP must reach the upstream over TCP too (RFC 7766
// §8.2), yielding a complete answer instead of a UDP-sized or TC-flagged one.
func TestTCPClientQueryProxiedOverTCP(t *testing.T) {
	up := startDualTransportUpstream(t, func(w dns.ResponseWriter, req *dns.Msg) {
		resp := new(dns.Msg)
		resp.SetReply(req)
		rr, _ := dns.NewRR(req.Question[0].Name + " 300 IN A 198.51.100.7")
		resp.Answer = append(resp.Answer, rr)
		_ = w.WriteMsg(resp)
	})
	p := newPassthroughProxy(up.addr)

	req := new(dns.Msg)
	req.SetQuestion("t.example.com.", dns.TypeA)
	resp := p.handleVia(req, viaTCP)

	if resp.Rcode != dns.RcodeSuccess || len(resp.Answer) != 1 {
		t.Fatalf("rcode=%d answers=%d, want NOERROR with 1 A record", resp.Rcode, len(resp.Answer))
	}
	nets := up.networksSeen(t, 1)
	if nets[0] != viaTCP {
		t.Fatalf("upstream exchange used %q, want %q (RFC 7766 §8.2)", nets[0], viaTCP)
	}
}

// TestUDPClientQueryStillProxiedOverUDP pins the unchanged behaviour for
// UDP-originated queries: ordinary lookups stay on the cheaper transport.
func TestUDPClientQueryStillProxiedOverUDP(t *testing.T) {
	up := startDualTransportUpstream(t, func(w dns.ResponseWriter, req *dns.Msg) {
		resp := new(dns.Msg)
		resp.SetReply(req)
		rr, _ := dns.NewRR(req.Question[0].Name + " 300 IN A 198.51.100.7")
		resp.Answer = append(resp.Answer, rr)
		_ = w.WriteMsg(resp)
	})
	p := newPassthroughProxy(up.addr)

	req := new(dns.Msg)
	req.SetQuestion("u.example.com.", dns.TypeA)
	resp := p.handleVia(req, viaUDP)

	if resp.Rcode != dns.RcodeSuccess || len(resp.Answer) != 1 {
		t.Fatalf("rcode=%d answers=%d, want NOERROR with 1 A record", resp.Rcode, len(resp.Answer))
	}
	nets := up.networksSeen(t, 1)
	if nets[0] != viaUDP {
		t.Fatalf("upstream exchange used %q, want %q", nets[0], viaUDP)
	}
}

// TestTruncatedUDPAnswerRetriedOverTCP covers the second half of finding #2:
// when the upstream's UDP answer carries TC=1, ydn64 retries once over TCP
// and serves the COMPLETE answer (the caller truncates to the client's own
// negotiated limits afterwards). Without this, large answers (DNSKEY, big
// TXT sets) are dead ends for clients whose buffers exceed the upstream's
// UDP view.
func TestTruncatedUDPAnswerRetriedOverTCP(t *testing.T) {
	const nAnswers = 30
	up := startDualTransportUpstream(t, func(w dns.ResponseWriter, req *dns.Msg) {
		resp := new(dns.Msg)
		resp.SetReply(req)
		if w.RemoteAddr().Network() == viaUDP {
			// Upstream cannot fit its reply into one datagram.
			resp.Truncated = true
		} else {
			for i := 0; i < nAnswers; i++ {
				rr, _ := dns.NewRR(req.Question[0].Name + ` 300 IN TXT "chunk-of-a-large-answer-record-number-` + strconv.Itoa(i) + `"`)
				resp.Answer = append(resp.Answer, rr)
			}
		}
		_ = w.WriteMsg(resp)
	})
	p := newPassthroughProxy(up.addr)

	req := new(dns.Msg)
	req.SetQuestion("big.example.com.", dns.TypeTXT)
	resp, err := p.lookup(up.addr, req, viaUDP)
	if err != nil {
		t.Fatalf("lookup: %v", err)
	}
	if resp.Truncated {
		t.Fatal("TC-fallback did not clear the truncated flag")
	}
	if len(resp.Answer) != nAnswers {
		t.Fatalf("answers = %d, want the %d from the TCP retry", len(resp.Answer), nAnswers)
	}
	nets := up.networksSeen(t, 2)
	if nets[0] != viaUDP || nets[1] != viaTCP {
		t.Fatalf("exchanges = %v, want [%s %s]", nets, viaUDP, viaTCP)
	}
	if resp.Id != req.Id {
		t.Fatalf("response id %#x, want client id %#x restored", resp.Id, req.Id)
	}
}

// TestTCFallbackKeepsUDPAnswerWhenTCPFails pins the availability guarantee:
// if the TCP retry cannot be completed (here: the upstream has no TCP
// listener at all), the original truncated UDP answer is still relayed rather
// than turned into SERVFAIL.
func TestTCFallbackKeepsUDPAnswerWhenTCPFails(t *testing.T) {
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen udp: %v", err)
	}
	udpOnly := &dns.Server{
		PacketConn: pc,
		Handler: dns.HandlerFunc(func(w dns.ResponseWriter, req *dns.Msg) {
			resp := new(dns.Msg)
			resp.SetReply(req)
			resp.Truncated = true // always truncated, never completable
			_ = w.WriteMsg(resp)
		}),
	}
	go func() { _ = udpOnly.ActivateAndServe() }()
	t.Cleanup(func() { _ = udpOnly.Shutdown() })
	time.Sleep(50 * time.Millisecond)

	p := newPassthroughProxy(pc.LocalAddr().String())

	req := new(dns.Msg)
	req.SetQuestion("tc.example.com.", dns.TypeA)
	resp, err := p.lookup(pc.LocalAddr().String(), req, viaUDP)
	if err != nil {
		t.Fatalf("lookup: %v", err)
	}
	if !resp.Truncated {
		t.Fatal("truncated flag lost although no complete answer was obtainable")
	}
	if resp.Rcode != dns.RcodeSuccess {
		t.Fatalf("rcode=%d, want NOERROR relayed from the UDP answer", resp.Rcode)
	}
}

// stubDialer wraps a bare *stack.Stack as the proxy's netstackDialer, letting
// the Yggdrasil-native forwarder paths be exercised without an attached
// Yggdrasil core.
type stubDialer struct{ st *stack.Stack }

func (d stubDialer) Stack() *stack.Stack { return d.st }

// startYggForwarderInStack builds a gVisor stack with a loopback NIC owning
// 200:db8::53 (inside the 200::/7 Yggdrasil range), then runs a DNS server
// INSIDE that stack on both transports at port 5353 — the stand-in for a
// Yggdrasil-native forwarder reachable only via the embedded netstack.
func startYggForwarderInStack(t *testing.T) (*proxy, *dualUpstream) {
	t.Helper()
	st := stack.New(stack.Options{
		NetworkProtocols:   []stack.NetworkProtocolFactory{ipv6.NewProtocol},
		TransportProtocols: []stack.TransportProtocolFactory{tcp.NewProtocolCUBIC, udp.NewProtocol},
	})
	if err := st.CreateNIC(1, loopback.New()); err != nil {
		t.Fatalf("CreateNIC: %s", err)
	}
	fwdIP := tcpip.AddrFromSlice(net.ParseIP("200:db8::53").To16())
	if tcpErr := st.AddProtocolAddress(1, tcpip.ProtocolAddress{
		Protocol:          ipv6.ProtocolNumber,
		AddressWithPrefix: fwdIP.WithPrefix(),
	}, stack.AddressProperties{}); tcpErr != nil {
		t.Fatalf("AddProtocolAddress: %s", tcpErr)
	}
	// Without a route entry gVisor's FindRoute reports "network is
	// unreachable" even for addresses owned by the NIC itself — mirror what
	// production installs for the pool6 range.
	st.AddRoute(tcpip.Route{
		Destination: fwdIP.WithPrefix().Subnet(),
		NIC:         1,
	})

	up := &dualUpstream{networks: make(chan string, 16)}
	handler := dns.HandlerFunc(func(w dns.ResponseWriter, req *dns.Msg) {
		select {
		case up.networks <- w.RemoteAddr().Network():
		default:
		}
		resp := new(dns.Msg)
		resp.SetReply(req)
		rr, _ := dns.NewRR(req.Question[0].Name + " 300 IN A 203.0.113.99")
		resp.Answer = append(resp.Answer, rr)
		_ = w.WriteMsg(resp)
	})

	ln, tcpErr := gonet.ListenTCP(st, tcpip.FullAddress{NIC: 1, Addr: fwdIP, Port: 5353}, ipv6.ProtocolNumber)
	if tcpErr != nil {
		t.Fatalf("in-stack listen tcp: %s", tcpErr)
	}
	pc, tcpErr := gonet.DialUDP(st, &tcpip.FullAddress{NIC: 1, Addr: fwdIP, Port: 5353}, nil, ipv6.ProtocolNumber)
	if tcpErr != nil {
		t.Fatalf("in-stack bind udp: %s", tcpErr)
	}
	tcpServer := &dns.Server{Listener: ln, Handler: handler}
	udpServer := &dns.Server{PacketConn: pc, Handler: handler}
	go func() { _ = tcpServer.ActivateAndServe() }()
	go func() { _ = udpServer.ActivateAndServe() }()
	t.Cleanup(func() {
		_ = tcpServer.Shutdown()
		_ = udpServer.Shutdown()
	})

	p := &proxy{cache: newCache(300*time.Second, 600*time.Second, 0), ns: stubDialer{st}}
	p.reload("[200:db8::53]:5353", IAIgnore, []zone{
		{domains: []string{"."}, returnIPv4Addresses: true},
	}, nil, nil)
	return p, up
}

// TestYggdrasilNativeForwarderRespectsTransport drives lookupViaNetstack in
// both directions: a TCP-via query must arrive at the in-stack forwarder over
// TCP (finding #2 explicitly called out this path), a UDP-via one over UDP.
func TestYggdrasilNativeForwarderRespectsTransport(t *testing.T) {
	cases := []struct {
		via     string
		wantNet string
	}{
		{viaTCP, viaTCP},
		{viaUDP, viaUDP},
	}
	for _, tc := range cases {
		t.Run(tc.via, func(t *testing.T) {
			p, up := startYggForwarderInStack(t)

			req := new(dns.Msg)
			req.SetQuestion("ygg.example.com.", dns.TypeA)
			resp, err := p.lookup("[200:db8::53]:5353", req, tc.via)
			if err != nil {
				t.Fatalf("lookup via %s: %v", tc.via, err)
			}
			if resp.Rcode != dns.RcodeSuccess || len(resp.Answer) != 1 {
				t.Fatalf("rcode=%d answers=%d, want NOERROR with 1 A record", resp.Rcode, len(resp.Answer))
			}
			nets := up.networksSeen(t, 1)
			if nets[0] != tc.wantNet {
				t.Fatalf("forwarder saw %q, want %q", nets[0], tc.wantNet)
			}
		})
	}
}
