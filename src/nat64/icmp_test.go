package nat64

import (
	"encoding/binary"
	"errors"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/net/icmp"
	"golang.org/x/net/ipv4"

	"github.com/DrewCyber/ydn64/src/config"
)

// capturingNetStack wraps fakeNetStack and records every packet injected via
// WritePacket (the synthesised ICMPv6 replies).
type capturingNetStack struct {
	fakeNetStack
	mu       sync.Mutex
	outbound [][]byte
}

func (c *capturingNetStack) WritePacket(pkt []byte) (int, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	b := make([]byte, len(pkt))
	copy(b, pkt)
	c.outbound = append(c.outbound, b)
	return len(pkt), nil
}

func (c *capturingNetStack) packets() [][]byte {
	c.mu.Lock()
	defer c.mu.Unlock()
	out := make([][]byte, len(c.outbound))
	copy(out, c.outbound)
	return out
}

// fakeICMPConn stands in for the shared raw ICMPv4 socket: it records the
// messages written toward real IPv4 destinations and never delivers inbound
// traffic (replies are fed to translateICMPv4Reply directly in tests).
type fakeICMPConn struct {
	mu     sync.Mutex
	sent   [][]byte
	dsts   []net.Addr
	closed atomic.Bool
}

func (f *fakeICMPConn) WriteTo(b []byte, dst net.Addr) (int, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	cp := make([]byte, len(b))
	copy(cp, b)
	f.sent = append(f.sent, cp)
	f.dsts = append(f.dsts, dst)
	return len(b), nil
}

func (f *fakeICMPConn) ReadFrom(b []byte) (int, net.Addr, error) {
	for !f.closed.Load() {
		time.Sleep(10 * time.Millisecond)
	}
	return 0, nil, errors.New("closed")
}

func (f *fakeICMPConn) SetReadDeadline(t time.Time) error { return nil }
func (f *fakeICMPConn) Close() error                      { f.closed.Store(true); return nil }

func (f *fakeICMPConn) written() [][]byte {
	f.mu.Lock()
	defer f.mu.Unlock()
	out := make([][]byte, len(f.sent))
	copy(out, f.sent)
	return out
}

// icmpTestEnv wires a NAT64 service with a capturing stack and a fake raw
// ICMP socket.
type icmpTestEnv struct {
	svc  *Service
	ns   *capturingNetStack
	conn *fakeICMPConn
}

func newICMPTestEnv(t *testing.T) *icmpTestEnv {
	t.Helper()
	ns := &capturingNetStack{fakeNetStack: fakeNetStack{}}
	svc, err := NewService(
		config.NAT64Config{Pool6: "300:1:2:3::/96", UDPTimeout: 300},
		[]string{"200::/7"},
		nil,
		ns,
	)
	if err != nil {
		t.Fatalf("NewService: %v", err)
	}
	conn := &fakeICMPConn{}
	svc.icmpConn = conn
	return &icmpTestEnv{svc: svc, ns: ns, conn: conn}
}

// buildIPv6EchoRequest crafts an IPv6+ICMPv6 Echo Request with a correct
// pseudo-header checksum, as a Yggdrasil client would emit it.
func buildIPv6EchoRequest(srcIP, dstIP net.IP, id, seq uint16, payload []byte) []byte {
	icmpLen := 8 + len(payload)
	pkt := make([]byte, 40+icmpLen)
	pkt[0] = 0x60
	binary.BigEndian.PutUint16(pkt[4:6], uint16(icmpLen))
	pkt[6] = 58 // Next header = ICMPv6
	pkt[7] = 64 // Hop limit
	copy(pkt[8:24], srcIP.To16())
	copy(pkt[24:40], dstIP.To16())
	pkt[40] = 128 // Echo Request
	pkt[41] = 0   // Code
	binary.BigEndian.PutUint16(pkt[44:46], id)
	binary.BigEndian.PutUint16(pkt[46:48], seq)
	copy(pkt[48:], payload)
	cs := ipv6UpperLayerChecksum(pkt[8:24], pkt[24:40], 58, pkt[40:40+icmpLen])
	binary.BigEndian.PutUint16(pkt[42:44], cs)
	return pkt
}

// buildICMPv4EchoReply marshals a real-world-form ICMPv4 Echo Reply.
func buildICMPv4EchoReply(srcV4 net.IP, id, seq uint16, payload []byte) []byte {
	msg := icmp.Message{
		Type: ipv4.ICMPTypeEchoReply,
		Code: 0,
		Body: &icmp.Echo{ID: int(id), Seq: int(seq), Data: payload},
	}
	b, err := msg.Marshal(nil)
	if err != nil {
		panic(err)
	}
	return b
}

func parseWrittenICMPv4(t *testing.T, raw []byte) (*icmp.Message, *icmp.Echo) {
	t.Helper()
	msg, err := icmp.ParseMessage(1, raw)
	if err != nil {
		t.Fatalf("parsing outbound ICMPv4 message: %v", err)
	}
	echo, ok := msg.Body.(*icmp.Echo)
	if !ok {
		t.Fatalf("outbound ICMPv4 body is %T, want *icmp.Echo", msg.Body)
	}
	return msg, echo
}

// TestRFC5508NATAssignedEchoIdentifier covers the full echo round trip:
// the request toward the IPv4 destination must carry a NAT-assigned
// identifier (never the client's own), and the reply must be translated back
// to the client under its original identifier (RFC 6146 §3.5.3/§4,
// RFC 5508 REQ-1).
func TestRFC5508NATAssignedEchoIdentifier(t *testing.T) {
	env := newICMPTestEnv(t)
	const clientID uint16 = 0x1234

	payload := []byte("ydn64-icmp-test")
	req := buildIPv6EchoRequest(
		net.ParseIP("200:a:b:c::1"),
		net.ParseIP("300:1:2:3::192.0.2.5"),
		clientID, 7, payload,
	)
	if !env.svc.interceptICMPPacket(req) {
		t.Fatal("echo request was not consumed by the interceptor")
	}

	// forwardICMP runs in a goroutine; wait for the translated v4 request.
	var sent []byte
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if w := env.conn.written(); len(w) > 0 {
			sent = w[0]
			break
		}
		time.Sleep(5 * time.Millisecond)
	}
	if sent == nil {
		t.Fatal("no ICMPv4 request was written to the raw socket")
	}
	msg, echo := parseWrittenICMPv4(t, sent)
	if msg.Type != ipv4.ICMPTypeEcho {
		t.Fatalf("outbound type = %v, want Echo", msg.Type)
	}
	if uint16(echo.ID) == clientID {
		t.Fatalf("client identifier 0x%04X was exposed verbatim on the IPv4 side", clientID)
	}
	assignedID := uint16(echo.ID)
	if assignedID == 0 {
		t.Fatal("NAT-assigned identifier must never be zero")
	}
	if echo.Seq != 7 || string(echo.Data) != string(payload) {
		t.Fatalf("seq/payload not preserved: seq=%d data=%q", echo.Seq, echo.Data)
	}

	// The reply arrives from the IPv4 host carrying the NAT-assigned ID;
	// it must be translated back with the client's own identifier restored.
	reply := buildICMPv4EchoReply(net.ParseIP("192.0.2.5"), assignedID, 7, payload)
	parsedReply, err := icmp.ParseMessage(1, reply)
	if err != nil {
		t.Fatalf("parsing crafted reply: %v", err)
	}
	replyEcho := parsedReply.Body.(*icmp.Echo)
	var srcV4 [4]byte
	copy(srcV4[:], net.ParseIP("192.0.2.5").To4())
	if !env.svc.translateICMPv4Reply(srcV4, replyEcho) {
		t.Fatal("reply was not translated (session lookup failed)")
	}

	pkts := env.ns.packets()
	if len(pkts) != 1 {
		t.Fatalf("expected exactly 1 injected v6 packet, got %d", len(pkts))
	}
	v6pkt := pkts[0]
	if len(v6pkt) < 48 || v6pkt[6] != 58 || v6pkt[40] != 129 {
		t.Fatalf("injected packet is not an ICMPv6 Echo Reply: len=%d nh=%d type=%d",
			len(v6pkt), v6pkt[6], v6pkt[40])
	}
	if got := binary.BigEndian.Uint16(v6pkt[44:46]); got != clientID {
		t.Fatalf("reply identifier = 0x%04X, want client's 0x%04X restored", got, clientID)
	}
	if got := binary.BigEndian.Uint16(v6pkt[46:48]); got != 7 {
		t.Fatalf("reply sequence = %d, want 7", got)
	}
	if string(v6pkt[48:]) != string(payload) {
		t.Fatalf("reply payload mismatch: %q", v6pkt[48:])
	}
	// Source = pool6::embedded IPv4, destination = original Yggdrasil sender.
	if src := net.IP(v6pkt[8:24]); !src.Equal(net.ParseIP("300:1:2:3::192.0.2.5")) {
		t.Errorf("IPv6 source = %v, want 300:1:2:3::192.0.2.5", src)
	}
	if dst := net.IP(v6pkt[24:40]); !dst.Equal(net.ParseIP("200:a:b:c::1")) {
		t.Errorf("IPv6 destination = %v, want 200:a:b:c::1", dst)
	}
	// Checksum over pseudo-header must verify: zero the field, recompute,
	// compare with the transmitted value.
	stored := binary.BigEndian.Uint16(v6pkt[42:44])
	v6pkt[42], v6pkt[43] = 0, 0
	if cs := ipv6UpperLayerChecksum(v6pkt[8:24], v6pkt[24:40], 58, v6pkt[40:]); stored != cs {
		t.Fatalf("reply checksum = 0x%04X, want 0x%04X", stored, cs)
	}
}

// TestRFC5508SameClientIDDifferentPeersNoCrossTalk verifies that two clients
// using the same echo identifier get distinct NAT-assigned identifiers and
// that replies cannot leak between sessions.
func TestRFC5508SameClientIDDifferentPeersNoCrossTalk(t *testing.T) {
	env := newICMPTestEnv(t)
	const clientID uint16 = 0x42

	srcA := net.ParseIP("200:a:b:c::a")
	srcB := net.ParseIP("200:a:b:c::b")
	dst6 := net.ParseIP("300:1:2:3::198.51.100.9")

	reqA := buildIPv6EchoRequest(srcA, dst6, clientID, 1, []byte("from-a"))
	reqB := buildIPv6EchoRequest(srcB, dst6, clientID, 1, []byte("from-b"))
	if !env.svc.interceptICMPPacket(reqA) || !env.svc.interceptICMPPacket(reqB) {
		t.Fatal("requests were dropped by policy filters")
	}

	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) && len(env.conn.written()) < 2 {
		time.Sleep(5 * time.Millisecond)
	}
	written := env.conn.written()
	if len(written) != 2 {
		t.Fatalf("expected 2 outbound requests, got %d", len(written))
	}
	// The two forward goroutines may write in either order; identify each
	// request by its preserved payload rather than by arrival order.
	ids := make(map[string]int, 2)
	for _, w := range written {
		_, echo := parseWrittenICMPv4(t, w)
		ids[string(echo.Data)] = echo.ID
	}
	idA, okA := ids["from-a"]
	idB, okB := ids["from-b"]
	if !okA || !okB {
		t.Fatalf("outbound requests missing expected payloads: %v", ids)
	}
	if idA == idB {
		t.Fatalf("both clients were assigned the same identifier %d; replies could cross", idA)
	}
	if uint16(idA) == clientID || uint16(idB) == clientID {
		t.Fatal("a client-chosen identifier leaked onto the wire")
	}

	// Reply addressed to B's allocation must reach only client B.
	replyB := buildICMPv4EchoReply(net.ParseIP("198.51.100.9"), uint16(idB), 1, []byte("from-b"))
	parsedB, _ := icmp.ParseMessage(1, replyB)
	var srcV4 [4]byte
	copy(srcV4[:], net.ParseIP("198.51.100.9").To4())
	if !env.svc.translateICMPv4Reply(srcV4, parsedB.Body.(*icmp.Echo)) {
		t.Fatal("reply for allocation B failed lookup")
	}
	pkts := env.ns.packets()
	if len(pkts) != 1 {
		t.Fatalf("expected exactly 1 injected packet after B's reply, got %d", len(pkts))
	}
	if dst := net.IP(pkts[0][24:40]); !dst.Equal(srcB) {
		t.Fatalf("reply for B's allocation went to %v, want %v", dst, srcB)
	}

	// A's identifier still routes to A, proving allocations stayed independent.
	replyA := buildICMPv4EchoReply(net.ParseIP("198.51.100.9"), uint16(idA), 1, []byte("from-a"))
	parsedA, _ := icmp.ParseMessage(1, replyA)
	if !env.svc.translateICMPv4Reply(srcV4, parsedA.Body.(*icmp.Echo)) {
		t.Fatal("reply for allocation A failed lookup")
	}
	pkts = env.ns.packets()
	if last := pkts[len(pkts)-1]; !net.IP(last[24:40]).Equal(srcA) {
		t.Fatalf("reply for A's allocation went to %v, want %v", net.IP(last[24:40]), srcA)
	}
}

// TestRFC6146ICMPRetransmitReusesAllocation verifies that ping retries from
// the same client toward the same destination reuse their NAT-assigned
// identifier instead of minting one per request.
func TestRFC6146ICMPRetransmitReusesAllocation(t *testing.T) {
	env := newICMPTestEnv(t)
	const clientID uint16 = 0x7777

	src := net.ParseIP("200:a:b:c::1")
	dst := net.ParseIP("300:1:2:3::203.0.113.1")

	first := buildIPv6EchoRequest(src, dst, clientID, 1, []byte("seq1"))
	second := buildIPv6EchoRequest(src, dst, clientID, 2, []byte("seq2"))
	if !env.svc.interceptICMPPacket(first) || !env.svc.interceptICMPPacket(second) {
		t.Fatal("requests were dropped by policy filters")
	}

	qKey := icmpQueryKey{srcAddr: [16]byte(src.To16()), dstAddr: [4]byte(net.ParseIP("203.0.113.1").To4()), id: clientID}
	v, ok := env.svc.icmpQueries.Load(qKey)
	if !ok {
		t.Fatal("no session registered for the query tuple")
	}
	sess := v.(*icmpSession)
	if sess.clientID != clientID {
		t.Fatalf("session clientID = 0x%04X, want 0x%04X", sess.clientID, clientID)
	}
	if n := countSyncMap(&env.svc.icmpQueries); n != 1 {
		t.Fatalf("expected 1 query-key session after retry, got %d", n)
	}
	if n := countSyncMap(&env.svc.icmpSessions); n != 1 {
		t.Fatalf("expected 1 NAT-side session slot after retry, got %d", n)
	}

	// Both forwarded requests carry the same assigned identifier.
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) && len(env.conn.written()) < 2 {
		time.Sleep(5 * time.Millisecond)
	}
	written := env.conn.written()
	if len(written) != 2 {
		t.Fatalf("expected 2 outbound requests, got %d", len(written))
	}
	_, e1 := parseWrittenICMPv4(t, written[0])
	_, e2 := parseWrittenICMPv4(t, written[1])
	if e1.ID != e2.ID || uint16(e1.ID) != sess.allocID {
		t.Fatalf("retry did not reuse the allocation: first=%d second=%d session=%d",
			e1.ID, e2.ID, sess.allocID)
	}
}

// TestRFC6146ICMPQueryTimeoutFloor pins the session idle timeout at or above
// the RFC 5508 REQ-2 / RFC 6146 §4 floor of 60 seconds.
func TestRFC6146ICMPQueryTimeoutFloor(t *testing.T) {
	if icmpSessionTimeout < 60*time.Second {
		t.Fatalf("icmpSessionTimeout = %v, RFC 5508 REQ-2 requires >= 60s", icmpSessionTimeout)
	}
}

// TestRFC5508SessionCapDropsWhenFull verifies the anti-DoS bound: requests
// arriving while the table is full are dropped instead of growing state.
func TestRFC5508SessionCapDropsWhenFull(t *testing.T) {
	env := newICMPTestEnv(t)
	dst := [4]byte(net.ParseIP("203.0.113.9").To4())

	for i := 0; i < maxICMPSessions; i++ {
		src := [16]byte(net.ParseIP("200::1").To16())
		src[15] = byte(i >> 8)
		src[14] = byte(i)
		sess := env.svc.registerICMPSession(src, [16]byte{}, dst, uint16(i))
		if sess == nil {
			t.Fatalf("session %d rejected before cap reached", i)
		}
	}
	if got := env.svc.icmpCount.Load(); got != maxICMPSessions {
		t.Fatalf("table holds %d sessions, want %d", got, maxICMPSessions)
	}
	if sess := env.svc.registerICMPSession([16]byte(net.ParseIP("200::ffff").To16()), [16]byte{}, dst, 9999); sess != nil {
		t.Fatal("session accepted beyond maxICMPSessions cap")
	}
}
