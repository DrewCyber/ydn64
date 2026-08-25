package dns64

import (
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/gologme/log"
	"github.com/miekg/dns"
)

// pipelineLogger swallows the service's debug output; gologme loggers only
// write what their level permits and this one permits nothing.
func pipelineLogger() *log.Logger {
	return log.New(io.Discard, "", 0)
}

// startPipelineTestUpstream runs a mock upstream DNS server on loopback
// answering on BOTH UDP and TCP (RFC 7766 §8.2: ydn64 mirrors a TCP client
// query's transport toward upstreams, so the mock must accept both) whose
// answers are instant except for names carrying a "slow." first label,
// which are delayed by slowDelay before replying (both for the AAAA query
// handleAAAA issues first and for its follow-up A lookup). A queries get a
// deterministic A record derived from the name so synthesis results are
// assertable; AAAA queries get an empty NOERROR, forcing the DNS64
// fall-through to A-based synthesis.
func startPipelineTestUpstream(t *testing.T, slowDelay time.Duration) string {
	t.Helper()
	handler := dns.HandlerFunc(func(w dns.ResponseWriter, req *dns.Msg) {
		resp := new(dns.Msg)
		resp.SetReply(req)
		if len(req.Question) == 1 && strings.HasPrefix(strings.ToLower(req.Question[0].Name), "slow.") {
			time.Sleep(slowDelay)
		}
		if len(req.Question) == 1 && req.Question[0].Qtype == dns.TypeA {
			// Stable per-name address in TEST-NET-3 (203.0.113/24).
			sum := byte(0)
			for _, c := range []byte(strings.ToLower(req.Question[0].Name)) {
				sum += c
			}
			rr, _ := dns.NewRR(fmt.Sprintf("%s 300 IN A 203.0.113.%d", req.Question[0].Name, sum))
			resp.Answer = append(resp.Answer, rr)
		}
		_ = w.WriteMsg(resp)
	})

	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to listen UDP: %v", err)
	}
	ln, err := net.Listen("tcp", pc.LocalAddr().String())
	if err != nil {
		t.Fatalf("failed to listen TCP: %v", err)
	}
	udpServer := &dns.Server{PacketConn: pc, Handler: handler}
	tcpServer := &dns.Server{Listener: ln, Handler: handler}
	go func() { _ = udpServer.ActivateAndServe() }()
	go func() { _ = tcpServer.ActivateAndServe() }()
	t.Cleanup(func() {
		_ = udpServer.Shutdown()
		_ = tcpServer.Shutdown()
	})
	return pc.LocalAddr().String()
}

// newPipelineTestService builds a Service wired to the given upstream
// forwarder with a catch-all synthesising zone and unlimited rate limiting —
// the same shape NewService produces, minus the gVisor stack (the mock
// upstream is on loopback, never in Yggdrasil space).
func newPipelineTestService(upstream string) *Service {
	p := &proxy{cache: newCache(300*time.Second, 600*time.Second, 0)}
	p.reload(upstream, IAIgnore, []zone{
		{domains: []string{"."}, prefix: testPref64()},
	}, nil, nil)
	return &Service{proxy: p, rateLimit: newSrcRateLimiter(0)}
}

// serveTCPConnForTest accepts exactly one TCP connection on a fresh loopback
// listener and serves it with s.serveTCPConn. The returned channel closes
// when serveTCPConn returns.
func serveTCPConnForTest(t *testing.T, s *Service) (net.Listener, <-chan struct{}) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen tcp: %v", err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	done := make(chan struct{})
	go func() {
		defer close(done)
		c, err := ln.Accept()
		if err != nil {
			return
		}
		s.serveTCPConn(c, pipelineLogger())
	}()
	return ln, done
}

// frameQuery writes m to conn framed with the two-byte length prefix of
// RFC 1035 §4.2.2.
func frameQuery(t *testing.T, conn net.Conn, m *dns.Msg) {
	t.Helper()
	b, err := m.Pack()
	if err != nil {
		t.Fatalf("Pack: %v", err)
	}
	var hdr [2]byte
	binary.BigEndian.PutUint16(hdr[:], uint16(len(b)))
	if _, err := conn.Write(hdr[:]); err != nil {
		t.Fatalf("write length prefix: %v", err)
	}
	if _, err := conn.Write(b); err != nil {
		t.Fatalf("write message: %v", err)
	}
}

// readFramedMsg reads one length-prefixed DNS message from conn.
func readFramedMsg(t *testing.T, conn net.Conn, timeout time.Duration) *dns.Msg {
	t.Helper()
	_ = conn.SetReadDeadline(time.Now().Add(timeout))
	var hdr [2]byte
	if _, err := io.ReadFull(conn, hdr[:]); err != nil {
		t.Fatalf("read length prefix: %v", err)
	}
	buf := make([]byte, binary.BigEndian.Uint16(hdr[:]))
	if _, err := io.ReadFull(conn, buf); err != nil {
		t.Fatalf("read message body: %v", err)
	}
	m := new(dns.Msg)
	if err := m.Unpack(buf); err != nil {
		t.Fatalf("Unpack: %v", err)
	}
	return m
}

// TestTCPPipelinedQueriesProcessedConcurrently is the RFC 7766 §6.2.1.1
// conformance probe: two queries are written back-to-back on one connection,
// the first targeting a deliberately slow upstream name and the second an
// instant one. Under concurrent processing the fast response overtakes the
// slow one; a serialising server always answers the first-sent query first,
// so this test fails deterministically if pipelining regresses to serial
// handling.
func TestTCPPipelinedQueriesProcessedConcurrently(t *testing.T) {
	const slowDelay = 500 * time.Millisecond
	upstream := startPipelineTestUpstream(t, slowDelay)
	s := newPipelineTestService(upstream)

	ln, _ := serveTCPConnForTest(t, s)
	client, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer client.Close()

	// Msg.SetQuestion overwrites Id with a fresh random value, so the
	// deterministic IDs are assigned after it, not before.
	qSlow := new(dns.Msg)
	qSlow.SetQuestion("slow.example.com.", dns.TypeAAAA)
	qSlow.Id = 0x1111
	qFast := new(dns.Msg)
	qFast.SetQuestion("fast.example.com.", dns.TypeAAAA)
	qFast.Id = 0x2222

	frameQuery(t, client, qSlow)
	start := time.Now() // qFast must be pipelined before any reply is read
	frameQuery(t, client, qFast)

	first := readFramedMsg(t, client, 10*time.Second)
	if first.Id != qFast.Id {
		t.Fatalf("first response id=%#x after %v, want fast query %#x first — queries were not processed concurrently", first.Id, time.Since(start), qFast.Id)
	}

	second := readFramedMsg(t, client, 10*time.Second)
	if second.Id != qSlow.Id {
		t.Fatalf("second response id=%#x, want slow query %#x", second.Id, qSlow.Id)
	}

	// The slow answer must be real DNS64 output: a synthetic AAAA embedding
	// the upstream A record (203.0.113.x) via the zone prefix. The IPv4 sits
	// in the last four address bytes for a /96 prefix (To4() is only for
	// IPv4-mapped forms and would wrongly report nil here).
	for _, rr := range second.Answer {
		if aaaa, ok := rr.(*dns.AAAA); ok {
			v4 := aaaa.AAAA[len(aaaa.AAAA)-4:]
			if v4[0] != 203 || v4[1] != 0 || v4[2] != 113 {
				t.Fatalf("synthetic AAAA does not embed a 203.0.113/24 address: %s", aaaa.String())
			}
			return
		}
	}
	t.Fatalf("slow response carries no AAAA record (%d answers)", len(second.Answer))
}

// TestTCPPipelinedAllQueriesAnswered pipelines more queries than
// maxTCPQueriesInFlight on a single connection and requires every response
// back with its original ID. This exercises the backpressure path of the
// in-flight cap: the read loop pauses once the cap is exhausted and resumes
// as handlers release slots — nothing may be dropped or mismatched.
func TestTCPPipelinedAllQueriesAnswered(t *testing.T) {
	upstream := startPipelineTestUpstream(t, 0)
	s := newPipelineTestService(upstream)

	ln, _ := serveTCPConnForTest(t, s)
	client, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer client.Close()

	n := maxTCPQueriesInFlight + 8
	sentIDs := make(map[uint16]bool)
	for i := 0; i < n; i++ {
		q := new(dns.Msg)
		q.SetQuestion(fmt.Sprintf("q%03d.fast.example.com.", i), dns.TypeAAAA)
		id := uint16(i*7 + 3) // arbitrary unique IDs away from 0/0xffff edges
		q.Id = id
		frameQuery(t, client, q)
		sentIDs[id] = true
	}

	for i := 0; i < n; i++ {
		resp := readFramedMsg(t, client, 30*time.Second)
		if !sentIDs[resp.Id] {
			t.Fatalf("response %d has unexpected/duplicate id %#x", i, resp.Id)
		}
		delete(sentIDs, resp.Id)
		if resp.Rcode != dns.RcodeSuccess {
			t.Fatalf("response for id %#x rcode=%d, want NOERROR", resp.Id, resp.Rcode)
		}
	}
	if len(sentIDs) != 0 {
		t.Fatalf("%d pipelined queries were never answered (ids %v)", len(sentIDs), sentIDs)
	}
}

// TestTCPClientDisconnectAbandonsHandlers verifies §6.2.4 teardown: when the
// client vanishes mid-flight, serveTCPConn returns promptly instead of
// hanging on handlers that can no longer deliver their responses, and no
// panic escapes from writes to the dead connection.
func TestTCPClientDisconnectAbandonsHandlers(t *testing.T) {
	upstream := startPipelineTestUpstream(t, 800*time.Millisecond)
	s := newPipelineTestService(upstream)

	ln, serverDone := serveTCPConnForTest(t, s)
	client, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatalf("dial: %v", err)
	}

	q := new(dns.Msg)
	q.SetQuestion("slow.example.com.", dns.TypeAAAA)
	q.Id = 0x3333
	frameQuery(t, client, q)
	_ = client.Close()

	select {
	case <-serverDone:
	case <-time.After(5 * time.Second):
		t.Fatal("serveTCPConn did not return within 5s of client disconnect")
	}
}

// TestTCPRateLimitStillClosesConnection pins the pre-existing behaviour that
// motivated keeping the read loop sequential: each pipelined query consumes
// its per-source rate token as it arrives, so an over-budget source's
// connection is closed by the reader regardless of how much work is already
// in flight (here: limiter burst is 10, client sends 12 back-to-back).
func TestTCPRateLimitStillClosesConnection(t *testing.T) {
	upstream := startPipelineTestUpstream(t, 0)
	s := newPipelineTestService(upstream)
	s.rateLimit = newSrcRateLimiter(1) // rate 1/s → burst floored at 10

	ln, serverDone := serveTCPConnForTest(t, s)
	client, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer client.Close()

	n := 12
	for i := 0; i < n; i++ {
		q := new(dns.Msg)
		q.SetQuestion(fmt.Sprintf("r%02d.fast.example.com.", i), dns.TypeAAAA)
		q.Id = uint16(i*11 + 5)
		frameQuery(t, client, q)
	}

	answered := make(map[uint16]bool)
	closedByServer := false
	for i := 0; i < n; i++ {
		_ = client.SetReadDeadline(time.Now().Add(10 * time.Second))
		var hdr [2]byte
		if _, err := io.ReadFull(client, hdr[:]); err != nil {
			closedByServer = true // expected: reader hit the rate limit
			break
		}
		buf := make([]byte, binary.BigEndian.Uint16(hdr[:]))
		if _, err := io.ReadFull(client, buf); err != nil {
			closedByServer = true
			break
		}
		m := new(dns.Msg)
		if err := m.Unpack(buf); err != nil {
			t.Fatalf("Unpack: %v", err)
		}
		answered[m.Id] = true
	}

	if !closedByServer {
		t.Fatalf("server kept the connection open past the rate limit (answered all %d)", n)
	}
	if len(answered) >= n {
		t.Fatalf("all %d queries answered despite burst limit of %d", n, len(answered)+2)
	}
	// The reader closes the socket on refusal; serveTCPConn exits once its
	// in-flight handlers have unwound — give that teardown a moment.
	select {
	case <-serverDone:
	case <-time.After(5 * time.Second):
		t.Fatal("serveTCPConn did not exit after rate-limit close")
	}
}

// TestTCPConcurrentWritesStayFramed hammers one connection with many slow and
// fast queries interleaved and asserts every response parses as a complete,
// correctly-framed message with a known ID — guarding the shared-writer
// mutex against interleaved/corrupt length prefixes under concurrency.
func TestTCPConcurrentWritesStayFramed(t *testing.T) {
	upstream := startPipelineTestUpstream(t, 50*time.Millisecond)
	s := newPipelineTestService(upstream)

	ln, serverDone := serveTCPConnForTest(t, s)
	client, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer client.Close()

	const n = 20
	want := make(map[uint16]bool, n)
	var mu sync.Mutex
	for i := 0; i < n; i++ {
		name := fmt.Sprintf("w%02d.fast.example.com.", i)
		if i%2 == 0 {
			name = fmt.Sprintf("slow.w%02d.example.com.", i) // mixed durations scramble completion order
		}
		q := new(dns.Msg)
		q.SetQuestion(name, dns.TypeAAAA)
		id := uint16(i*13 + 1)
		q.Id = id
		frameQuery(t, client, q)
		mu.Lock()
		want[id] = true
		mu.Unlock()
	}

	for i := 0; i < n; i++ {
		resp := readFramedMsg(t, client, 30*time.Second)
		mu.Lock()
		ok := want[resp.Id]
		delete(want, resp.Id)
		mu.Unlock()
		if !ok {
			t.Fatalf("response %d: unknown or duplicate id %#x", i, resp.Id)
		}
	}
	select {
	case <-serverDone:
		t.Fatal("serveTCPConn exited while queries were still being served")
	default:
	}
}
