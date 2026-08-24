package nat64

import (
	"bytes"
	"encoding/binary"
	"net"
	"testing"
	"time"

	"golang.org/x/net/icmp"
	"golang.org/x/net/ipv4"
)

// ── builders ────────────────────────────────────────────────────────────────

// buildFragmentedEchoRequest splits an Echo Request into IPv6 fragments the
// way a kernel would (fragmentable part = the entire ICMPv6 message),
// returning fragments each within fragCap bytes total.
func buildFragmentedEchoRequest(srcIP, dstIP net.IP, id, seq uint16, payload []byte, fragCap int) [][]byte {
	msg := make([]byte, 8+len(payload))
	msg[0], msg[1] = 128, 0
	binary.BigEndian.PutUint16(msg[4:6], id)
	binary.BigEndian.PutUint16(msg[6:8], seq)
	copy(msg[8:], payload)
	// The checksum covers the WHOLE datagram (fragments carry pieces of one
	// checksummed PDU), so it is computed here, pre-split.
	cs := ipv6UpperLayerChecksum(srcIP.To16(), dstIP.To16(), 58, msg)
	binary.BigEndian.PutUint16(msg[2:4], cs)

	perFrag := ((fragCap - 40 - 8) / 8) * 8
	ident := uint32(0xABCD0011)
	var frags [][]byte
	for sent := 0; sent < len(msg); {
		end := sent + perFrag
		if end > len(msg) {
			end = len(msg)
		}
		more := end < len(msg)

		p := make([]byte, 40+8+end-sent)
		p[0] = 0x60
		binary.BigEndian.PutUint16(p[4:6], uint16(len(p)-40))
		p[6] = 44 // Next Header = Fragment
		p[7] = 64
		copy(p[8:24], srcIP.To16())
		copy(p[24:40], dstIP.To16())
		p[40] = 58 // last next-header: ICMPv6
		word := uint16(sent/8) << 3
		if more {
			word |= 1 // M flag: bit 0 of the fragment word (RFC 8200 §4.5)
		}
		binary.BigEndian.PutUint16(p[42:44], word)
		binary.BigEndian.PutUint32(p[44:48], ident)
		copy(p[48:], msg[sent:end])
		frags = append(frags, p)
		sent = end
	}
	return frags
}

// assembleFragments reassembles captured IPv6 fragments back into their
// upper-layer PDU (test-side mirror of the kernel's job).
func assembleFragments(t *testing.T, frags [][]byte) []byte {
	t.Helper()
	type part struct {
		start int
		data  []byte
	}
	var parts []part
	total := -1
	ident := uint32(0xffffffff)
	for _, f := range frags {
		if f[6] != 44 || f[40] != 58 {
			t.Fatalf("not an ICMPv6 fragment: nh=%d", f[6])
		}
		if id := binary.BigEndian.Uint32(f[44:48]); ident == 0xffffffff {
			ident = id
		} else if id != ident {
			t.Fatalf("mixed identification values %d vs %d", ident, id)
		}
		more := f[43]&1 != 0 // M flag: bit 0 of the fragment word
		start := int(binary.BigEndian.Uint16(f[42:44]) >> 3 * 8)
		body := append([]byte(nil), f[48:]...)
		parts = append(parts, part{start, body})
		if !more {
			total = start + len(body)
		}
	}
	if total < 0 {
		t.Fatal("no final fragment among captures")
	}
	out := make([]byte, total)
	for _, p := range parts {
		copy(out[p.start:], p.data)
	}
	return out
}

// ── chain walker ────────────────────────────────────────────────────────────

func TestRFC8200HeaderChainWalking(t *testing.T) {
	src := net.ParseIP("200:a:b:c::1")
	dst := net.ParseIP("300:1:2:3::192.0.2.5")
	base := buildIPv6EchoRequest(src, dst, 7, 1, []byte("payload"))

	// Plain ICMPv6: l4 at offset 40, not a fragment.
	info, st := parseIPv6HeaderChain(base)
	if st != chainICMPv6 || info.l4Offset != 40 || info.isFrag {
		t.Fatalf("plain packet parsed as %+v/%v", info, st)
	}

	// Hop-by-Hop options header before ICMPv6.
	hbh := base
	{
		ext := make([]byte, 8)
		ext[0] = 58
		ext[1] = 0 // 8 bytes total
		p := append(append([]byte{}, base[:40]...), append(ext, base[40:]...)...)
		p[6] = 0 // Next Header = Hop-by-Hop
		binary.BigEndian.PutUint16(p[4:6], uint16(len(p)-40))
		hbh = p
	}
	info, st = parseIPv6HeaderChain(hbh)
	if st != chainICMPv6 || info.l4Offset != 48 {
		t.Fatalf("hbh-wrapped packet parsed as offset=%d/%v", info.l4Offset, st)
	}

	// Fragment header: first and subsequent fragments.
	frags := buildFragmentedEchoRequest(src, dst, 9, 2, make([]byte, 400), 128)
	first := frags[0]
	info, st = parseIPv6HeaderChain(first)
	if st != chainICMPv6 || !info.isFrag || info.fragOffset != 0 || !info.fragMore {
		t.Fatalf("first fragment parsed as %+v/%v", info, st)
	}
	if got := binary.BigEndian.Uint32([]byte{0xAB, 0xCD, 0x00, 0x11}); info.fragIdent != got {
		t.Errorf("ident = %#x, want %#x", info.fragIdent, got)
	}

	mid := frags[len(frags)-1]
	infoM, _ := parseIPv6HeaderChain(mid)
	if !infoM.isFrag || infoM.fragMore {
		t.Fatalf("final fragment parsed as %+v", infoM)
	}
	if int(infoM.fragOffset)*8+len(mid)-48 != 400+8 {
		t.Errorf("final fragment offset/length mismatch: off=%d units", infoM.fragOffset)
	}

	// Non-ICMPv6 payload (TCP) must be classified as pass-through.
	tcp := append([]byte{}, base[:40]...)
	tcp[6] = 6
	tcp = append(tcp, make([]byte, 20)...)
	if _, st := parseIPv6HeaderChain(tcp); st != chainOther {
		t.Fatalf("TCP packet classified %v, want chainOther", st)
	}

	// Truncated extension header is invalid, never mis-parsed.
	trunc := append([]byte{}, hbh[:46]...)
	if _, st := parseIPv6HeaderChain(trunc); st != chainInvalid {
		t.Fatalf("truncated hbh classified %v, want chainInvalid", st)
	}

	// Nested fragment headers are illegal: the first header's Next Header
	// field points at another Fragment header.
	double := buildFragmentedEchoRequest(src, dst, 1, 1, []byte("x"), 128)[0]
	nested := append([]byte{}, double...)
	nested[40] = 44
	if _, st := parseIPv6HeaderChain(nested); st != chainInvalid {
		t.Fatalf("nested fragment classified %v, want chainInvalid", st)
	}
}

// ── reply-side fragmentation ────────────────────────────────────────────────

func TestFragmentIPv6PacketSplitsAndReassembles(t *testing.T) {
	small := make([]byte, 100)
	small[6] = 58
	if out := fragmentIPv6Packet(small, 1500, 42); len(out) != 1 || !bytes.Equal(out[0], small) {
		t.Fatal("small packet was modified by fragmentIPv6Packet")
	}

	body := make([]byte, 3000)
	for i := range body {
		body[i] = byte(i ^ 0xA5)
	}
	pkt := make([]byte, 40+len(body))
	copy(pkt, small[:40])
	copy(pkt[40:], body)

	frags := fragmentIPv6Packet(pkt, 1500, 77)
	if len(frags) < 2 {
		t.Fatalf("expected ≥2 fragments, got %d", len(frags))
	}
	var (
		assembled []byte
		seenLast  bool
	)
	for i, f := range frags {
		if len(f) > 1500 {
			t.Fatalf("fragment %d is %d bytes, exceeds MTU", i, len(f))
		}
		if f[6] != 44 {
			t.Fatalf("fragment %d NH = %d, want 44", i, f[6])
		}
		if f[40] != 58 {
			t.Fatalf("fragment %d frag-NH = %d, want 58", i, f[40])
		}
		more := f[43]&1 != 0 // M flag: bit 0 of the fragment word
		if i < len(frags)-1 && !more {
			t.Fatalf("fragment %d should carry M=1", i)
		}
		if i == len(frags)-1 && more {
			t.Fatal("final fragment carries M=1")
		}
		if got := int(binary.BigEndian.Uint16(f[4:6])); got != len(f)-40 {
			t.Fatalf("fragment %d plen = %d, frame implies %d", i, got, len(f)-40)
		}
		assembled = append(assembled, f[48:]...)
		if !more {
			seenLast = true
		}
	}
	if !seenLast || !bytes.Equal(assembled, body) {
		t.Fatal("reassembled body differs from original")
	}
	if ident := binary.BigEndian.Uint32(frags[0][44:48]); ident != 77 {
		t.Errorf("identification = %d, want 77", ident)
	}
}

// ── reassembly table ────────────────────────────────────────────────────────

func reasmTestKey(b byte) reasmKey {
	var k reasmKey
	k.src[15] = b
	k.dst[14] = 0xEE
	k.ident = 1234
	return k
}

func TestReasmCompletionAndOverlap(t *testing.T) {
	tr := newReasmTable()
	now := time.Now()
	key := reasmTestKey(1)

	first := bytes.Repeat([]byte{0x11}, 24) // 3 units
	final := bytes.Repeat([]byte{0x22}, 12) // 12 bytes, ends datagram
	if got := tr.add(key, 0, true, first, now); got != nil {
		t.Fatalf("incomplete datagram returned data: %d bytes", len(got))
	}
	if tr.pending() != 1 {
		t.Fatalf("pending = %d, want 1", tr.pending())
	}

	// Out-of-order completion still assembles.
	if got := tr.add(key, 3, false, final, now); got == nil {
		t.Fatal("datagram did not complete after final fragment")
	} else if !bytes.Equal(got, append(append([]byte{}, first...), final...)) {
		t.Fatal("reassembled PDU differs from the fragments")
	}
	if tr.pending() != 0 {
		t.Fatalf("entry not released after completion: pending=%d", tr.pending())
	}

	// Overlapping fragment cancels the whole datagram (RFC 5722).
	if tr.add(key, 0, true, first, now); tr.add(key, 1, false, final, now) != nil {
		t.Fatal("overlap produced a completed datagram")
	}
	if tr.pending() != 0 {
		t.Fatal("overlapping datagram was not cancelled")
	}
}

func TestReasmExpiryAndCaps(t *testing.T) {
	tr := newReasmTable()
	now := time.Now()

	// Lazy expiry: an aged entry is swept by the NEXT add, so after adding
	// one aged and one fresh entry only the fresh one remains.
	oldKey := reasmTestKey(2)
	tr.add(oldKey, 0, true, make([]byte, 16), now.Add(-maxReasmAge-time.Second))
	freshKey := reasmTestKey(3)
	tr.add(freshKey, 0, true, make([]byte, 16), now)
	if tr.pending() != 1 {
		t.Fatalf("pending after aged+fresh = %d, want 1 (aged entry swept)", tr.pending())
	}
	if tr.cancel(freshKey) != true {
		t.Fatal("fresh entry missing after sweep")
	}

	// Two live entries survive a sweep triggered by another add.
	tr.add(freshKey, 0, true, make([]byte, 16), now)
	third := reasmTestKey(4)
	tr.add(third, 0, true, make([]byte, 16), now)
	if tr.pending() != 2 {
		t.Fatalf("pending = %d, want 2 (both entries fresh)", tr.pending())
	}

	// Per-datagram fragment cap sheds the datagram entirely.
	capTr := newReasmTable()
	capKey := reasmTestKey(5)
	for i := 0; i < maxFragmentsPerDgram; i++ {
		if capTr.add(capKey, uint16(i*2), true, make([]byte, 16), now) != nil {
			t.Fatal("unexpected completion during cap fill")
		}
	}
	if capTr.add(capKey, uint16(maxFragmentsPerDgram*2), false, make([]byte, 16), now) != nil {
		t.Fatal("fragment beyond per-datagram cap was accepted")
	}
	if capTr.cancel(capKey) {
		t.Fatal("over-cap datagram still buffered (shedding did not cancel it)")
	}

	// Table cap sheds NEW datagrams while old ones are held.
	fullTr := newReasmTable()
	for i := 0; i < maxReassemblies; i++ {
		var k reasmKey
		k.src[15] = byte(i)
		k.src[14] = byte(i >> 8)
		k.ident = uint32(i)
		fullTr.add(k, 0, true, make([]byte, 16), now)
	}
	if got := fullTr.add(reasmTestKey(0xEE), 0, true, make([]byte, 16), now); got != nil {
		t.Fatal("new datagram admitted into a full table")
	}
	if fullTr.pending() != maxReassemblies {
		t.Fatalf("pending = %d, want %d", fullTr.pending(), maxReassemblies)
	}

	// Global byte budget sheds rather than growing without bound.
	byteTr := newReasmTable()
	bigKey := reasmTestKey(6)
	if byteTr.add(bigKey, 0, true, make([]byte, maxReasmBytes-8), now) != nil {
		t.Fatal("budget-sized fragment rejected")
	}
	if byteTr.add(bigKey, (maxReasmBytes-8)/8, false, make([]byte, 64), now) != nil {
		t.Fatal("fragment beyond global byte budget was accepted")
	}

	// cancel reports existence so callers can avoid half-delivery.
	k := reasmTestKey(7)
	if tr.cancel(k) {
		t.Fatal("cancel returned true for unknown key")
	}
	tr.add(k, 0, true, make([]byte, 8), now)
	if !tr.cancel(k) {
		t.Fatal("cancel did not remove the buffered datagram")
	}
	if tr.cancel(k) {
		t.Fatal("second cancel still found the datagram")
	}
}

// ── interceptor end-to-end with fragments ───────────────────────────────────

// TestRFC6146FragmentedEchoRoundTrip drives a fragmented oversized ping
// through the interceptor: both fragments are consumed, ONE translated v4
// request carries the full payload, and the oversized reply comes back as
// IPv6 fragments that reassemble into exactly the client's expected answer.
func TestRFC6146FragmentedEchoRoundTrip(t *testing.T) {
	env := newICMPTestEnv(t)
	const clientID uint16 = 0x77AA

	payload := make([]byte, 2600)
	for i := range payload {
		payload[i] = byte(i * 7)
	}
	src := net.ParseIP("200:a:b:c::1")
	dst := net.ParseIP("300:1:2:3::198.51.100.9")

	frags := buildFragmentedEchoRequest(src, dst, clientID, 42, payload, 1500)
	if len(frags) < 2 {
		t.Fatalf("test setup produced %d fragments, want ≥2", len(frags))
	}
	for i, f := range frags {
		if !env.svc.interceptICMPPacket(f) {
			t.Fatalf("fragment %d was not consumed by the interceptor", i)
		}
	}

	// Exactly one translated v4 request with the complete payload.
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
		t.Fatal("no translated v4 request appeared")
	}
	msg, echo := parseWrittenICMPv4(t, sent)
	if msg.Type != ipv4.ICMPTypeEcho {
		t.Fatalf("outbound type = %v", msg.Type)
	}
	if string(echo.Data) != string(payload) {
		t.Fatalf("translated request lost payload: got %d bytes, want %d", len(echo.Data), len(payload))
	}
	assignedID := uint16(echo.ID)
	if assignedID == clientID || assignedID == 0 {
		t.Fatalf("identifier mapping wrong: %d", assignedID)
	}

	// The v4 side answers with an equally oversized reply; it must reach the
	// client as IPv6 fragments that reassemble to the exact original answer.
	reply := buildICMPv4EchoReply(net.ParseIP("198.51.100.9"), assignedID, 42, payload)
	parsed, err := icmp.ParseMessage(1, reply)
	if err != nil {
		t.Fatalf("parsing crafted reply: %v", err)
	}
	if !env.svc.translateICMPv4Reply([4]byte{198, 51, 100, 9}, parsed.Body.(*icmp.Echo)) {
		t.Fatal("oversized reply translation failed")
	}

	pkts := env.ns.packets()
	if len(pkts) < 2 {
		t.Fatalf("oversized reply emitted %d packets, want ≥2 fragments", len(pkts))
	}
	// assembleFragments yields the upper-layer PDU (no IPv6 header), so the
	// expectation is built the same way: Echo Reply message with restored
	// client identifier and valid checksum.
	rebuilt := assembleFragments(t, pkts)
	wantMsg := make([]byte, 8+len(payload))
	wantMsg[0], wantMsg[1] = 129, 0
	binary.BigEndian.PutUint16(wantMsg[4:6], clientID)
	binary.BigEndian.PutUint16(wantMsg[6:8], 42)
	copy(wantMsg[8:], payload)
	cs := ipv6UpperLayerChecksum(dst.To16(), src.To16(), 58, wantMsg)
	binary.BigEndian.PutUint16(wantMsg[2:4], cs)
	if !bytes.Equal(rebuilt, wantMsg) {
		t.Fatalf("reassembled reply differs from expected (%d vs %d bytes)", len(rebuilt), len(wantMsg))
	}
}

// TestInterceptorPassesNonEchoThrough pins the fall-through semantics that
// the chain walker must preserve: NDP-style messages and other protocols
// still reach gVisor even when wrapped in extension headers.
func TestInterceptorPassesNonEchoThrough(t *testing.T) {
	env := newICMPTestEnv(t)
	src := net.ParseIP("200:a:b:c::1")
	dst := net.ParseIP("300:1:2:3::192.0.2.5")

	// Plain ICMPv6 Packet Too Big toward pool6: gVisor's business.
	ptb := buildIPv6EchoRequest(src, dst, 1, 1, nil)
	ptb[40] = 2 // Packet Too Big type
	cs := ipv6UpperLayerChecksum(ptb[8:24], ptb[24:40], 58, ptb[40:])
	binary.BigEndian.PutUint16(ptb[42:44], cs)
	if env.svc.interceptICMPPacket(ptb) {
		t.Fatal("non-echo ICMPv6 was consumed instead of passed through")
	}

	// First fragment of a non-echo datagram likewise passes through.
	frags := buildFragmentedEchoRequest(src, dst, 5, 5, []byte("data"), 128)
	frags[0][40] = 129 // pretend Echo Reply inside a fragment stream
	if env.svc.interceptICMPPacket(frags[0]) {
		t.Fatal("non-echo first fragment was consumed")
	}
}
