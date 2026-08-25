package nat64

import (
	"encoding/binary"
	"errors"
	"io"
	"net"
	"syscall"
	"testing"

	"github.com/gologme/log"

	"github.com/DrewCyber/ydn64/src/config"
)

// ── helpers ─────────────────────────────────────────────────────────────────

var errTestLogger = log.New(io.Discard, "", 0)

// buildIPv4Quoted crafts the inner IPv4 packet of an ICMPv4 error message
// (the datagram "in error"): fixed 20-byte header + transport segment.
func buildIPv4Quoted(t *testing.T, src, dst net.IP, proto byte, ttl byte, l4 []byte) []byte {
	t.Helper()
	b := make([]byte, 20+len(l4))
	b[0] = 0x40 | 5 // version 4, IHL 5
	binary.BigEndian.PutUint16(b[2:4], uint16(len(b)))
	b[8] = ttl
	b[9] = proto
	copy(b[12:16], src.To4())
	copy(b[16:20], dst.To4())
	copy(b[20:], l4)
	return b
}

// buildUDPHeader crafts an 8-byte UDP header (checksum left zero).
func buildUDPHeader(srcPort, dstPort uint16) []byte {
	b := make([]byte, 8)
	binary.BigEndian.PutUint16(b[0:2], srcPort)
	binary.BigEndian.PutUint16(b[2:4], dstPort)
	return b
}

// buildICMPv4Error assembles a full ICMPv4 error message: 8-byte header
// (type/code/checksum/unused-or-MTU word) + quoted packet.
func buildICMPv4Error(typ, code byte, mtuWord uint16, quoted []byte) []byte {
	b := make([]byte, 8+len(quoted))
	b[0], b[1] = typ, code
	if typ == 3 && code == 4 {
		binary.BigEndian.PutUint16(b[6:8], mtuWord)
	}
	copy(b[8:], quoted)
	return b
}

// registerFakeUDPSession plants a session entry shaped like one created by
// handleUDPForward, without real sockets (error translation never touches
// them).
func registerFakeUDPSession(svc *Service, client6 net.IP, clientPort uint16, dstV4 [4]byte, dstPort uint16, localIP [4]byte, localPort uint16) sessionKey {
	key := sessionKey{srcAddr: [16]byte(client6.To16()), srcPort: clientPort, dstAddr: dstV4, dstPort: dstPort}
	svc.sessions.Store(key, &udpSession{localIP: localIP, localPort: localPort})
	return key
}

// verifyICMPv6Packet checks outer/inner structure and both checksums of a
// synthesised error packet and returns its parts.
type icmpv6ErrorParts struct {
	outerSrc, outerDst net.IP
	typ, code          byte
	extra              uint32
	innerSrc, innerDst net.IP
	innerNH, innerTTL  byte
	innerL4            []byte
}

func parseSynthICMPv6Error(t *testing.T, pkt []byte) icmpv6ErrorParts {
	t.Helper()
	if len(pkt) < icmpErrFixedLen {
		t.Fatalf("synthesised packet too short: %d bytes", len(pkt))
	}
	if pkt[0] != 0x60 || pkt[6] != 58 {
		t.Fatalf("not an IPv6 ICMPv6 packet: ver=%x nh=%d", pkt[0]>>4, pkt[6])
	}
	p := icmpv6ErrorParts{
		outerSrc: net.IP(pkt[8:24]),
		outerDst: net.IP(pkt[24:40]),
		typ:      pkt[40],
		code:     pkt[41],
		extra:    binary.BigEndian.Uint32(pkt[44:48]),
	}
	plen := int(binary.BigEndian.Uint16(pkt[4:6]))
	if plen != len(pkt)-40 {
		t.Fatalf("outer payload length field = %d, actual %d", plen, len(pkt)-40)
	}
	in := pkt[48:]
	p.innerSrc = net.IP(in[8:24])
	p.innerDst = net.IP(in[24:40])
	p.innerNH = in[6]
	p.innerTTL = in[7]
	p.innerL4 = in[40:]
	if got := int(binary.BigEndian.Uint16(in[4:6])); got != len(p.innerL4) {
		t.Fatalf("inner payload length field = %d, actual %d", got, len(p.innerL4))
	}
	// Outer ICMPv6 checksum must verify over the pseudo-header.
	stored := binary.BigEndian.Uint16(pkt[42:44])
	pkt[42], pkt[43] = 0, 0
	if cs := ipv6UpperLayerChecksum(pkt[8:24], pkt[24:40], 58, pkt[40:]); stored != cs {
		t.Fatalf("outer ICMPv6 checksum = 0x%04X, want 0x%04X", stored, cs)
	}
	// Inner transport checksum must verify against the inner pseudo-header.
	switch p.innerNH {
	case 17:
		if cs := binary.BigEndian.Uint16(p.innerL4[6:8]); cs != 0 {
			p.innerL4[6], p.innerL4[7] = 0, 0
			want := ipv6UpperLayerChecksum(p.innerSrc, p.innerDst, 17, p.innerL4)
			if want == 0 {
				want = 0xffff
			}
			if cs != want {
				t.Fatalf("inner UDP checksum = 0x%04X, want 0x%04X", cs, want)
			}
		}
	case 58:
		cs := binary.BigEndian.Uint16(p.innerL4[2:4])
		p.innerL4[2], p.innerL4[3] = 0, 0
		if want := ipv6UpperLayerChecksum(p.innerSrc, p.innerDst, 58, p.innerL4); cs != want {
			t.Fatalf("inner ICMPv6 checksum = 0x%04X, want 0x%04X", cs, want)
		}
	}
	return p
}

// ── pure-function tables ────────────────────────────────────────────────────

// TestRFC7915TranslateErrorTypeTable pins every mapping of RFC 7915 §4.2
// that ydn64 implements, including the silent-drop classes.
func TestRFC7915TranslateErrorTypeTable(t *testing.T) {
	cases := []struct {
		typ, code byte
		wantType  byte
		wantCode  byte
		wantOK    bool
	}{
		{3, 0, 1, 0, true},
		{3, 1, 1, 0, true},
		{3, 2, 4, 1, true}, // protocol unreachable → parameter problem
		{3, 3, 1, 4, true},
		{3, 4, 2, 0, true}, // fragmentation needed → Packet Too Big
		{3, 5, 1, 0, true},
		{3, 6, 1, 0, true},
		{3, 7, 1, 0, true},
		{3, 8, 1, 0, true},
		{3, 9, 1, 1, true},
		{3, 10, 1, 1, true},
		{3, 11, 1, 0, true},
		{3, 12, 1, 0, true},
		{3, 13, 1, 1, true},
		{3, 14, 0, 0, false}, // host precedence violation: drop
		{3, 15, 1, 1, true},
		{3, 16, 0, 0, false},
		{11, 0, 3, 0, true},
		{11, 1, 3, 1, true},
		{11, 2, 0, 0, false},
		{12, 0, 4, 0, true},
		{12, 1, 0, 0, false},
		{12, 2, 4, 0, true},
		{12, 3, 0, 0, false},
		{5, 1, 0, 0, false},  // redirect
		{4, 0, 0, 0, false},  // source quench
		{6, 0, 0, 0, false},  // alternative host address
		{13, 0, 0, 0, false}, // timestamp (obsolete query)
		{9, 0, 0, 0, false},  // router advertisement
	}
	for _, c := range cases {
		gotType, gotCode, ok := translateICMPv4ErrorType(c.typ, c.code)
		if ok != c.wantOK || (ok && (gotType != c.wantType || gotCode != c.wantCode)) {
			t.Errorf("translateICMPv4ErrorType(%d,%d) = (%d,%d,%v), want (%d,%d,%v)",
				c.typ, c.code, gotType, gotCode, ok, c.wantType, c.wantCode, c.wantOK)
		}
	}
}

// TestRFC7915ParamProblemPointerRemap checks the Figure 3 pointer table.
func TestRFC7915ParamProblemPointerRemap(t *testing.T) {
	valid := map[byte]uint32{0: 0, 1: 1, 2: 4, 3: 4, 8: 7, 9: 6, 12: 8, 15: 8, 16: 24, 19: 24}
	for in, want := range valid {
		got, ok := remapV4ParamProblemPointer(in)
		if !ok || got != want {
			t.Errorf("remapV4ParamProblemPointer(%d) = (%d,%v), want (%d,true)", in, got, ok, want)
		}
	}
	for _, in := range []byte{4, 5, 6, 7, 10, 11, 20, 255} {
		if _, ok := remapV4ParamProblemPointer(in); ok {
			t.Errorf("remapV4ParamProblemPointer(%d) unexpectedly mapped", in)
		}
	}
}

// TestRFC7915PTBMTUAdjustment covers the Packet Too Big MTU arithmetic:
// +20 for the IPv6 header difference, clamped to [1280, next-hop MTU], with
// RFC 1191 plateau fallback when the v4 router reported MTU=0.
func TestRFC7915PTBMTUAdjustment(t *testing.T) {
	tests := []struct {
		v4MTU, totalLen int
		yggMTU          uint64
		want            int
	}{
		{1000, 1400, 1500, 1280},  // min(1020,1500) < floor → 1280
		{1400, 1400, 65535, 1420}, // plain +20
		{1450, 1400, 1500, 1470},  // min(1470, 1500)
		{9000, 9000, 1500, 1500},  // clamped by Yggdrasil next-hop MTU
		{68, 100, 65535, 1280},    // absurdly small advertisement → floor
		{0, 1500, 65535, 1512},    // plateau 1492 (< total length 1500) + 20
		{0, 1300, 65535, 1300},    // no plateau fits below the length → base 1280 + 20
		{0, 20000, 1500, 1500},    // plateau 1492 + 20, then next-hop clamp
	}
	for _, tc := range tests {
		if got := ptbIPv6MTU(tc.v4MTU, tc.totalLen, tc.yggMTU); got != tc.want {
			t.Errorf("ptbIPv6MTU(%d,%d,%d) = %d, want %d", tc.v4MTU, tc.totalLen, tc.yggMTU, got, tc.want)
		}
	}
}

// TestRFC7915InnerPacketParsing covers validation of the quoted packet.
func TestRFC7915InnerPacketParsing(t *testing.T) {
	good := buildIPv4Quoted(t, net.IPv4(192, 0, 2, 7), net.IPv4(8, 8, 8, 8), 17, 61, buildUDPHeader(44444, 53))
	p, ok := parseICMPv4InnerPacket(good)
	if !ok {
		t.Fatal("valid quoted UDP packet rejected")
	}
	if net.IP(p.src[:]).String() != "192.0.2.7" || net.IP(p.dst[:]).String() != "8.8.8.8" || p.proto != 17 || p.ttl != 61 {
		t.Fatalf("parsed fields wrong: %+v", p)
	}
	if p.totalLen != len(good) {
		t.Fatalf("totalLen = %d, want %d", p.totalLen, len(good))
	}

	// IPv4 options (IHL=6) are skipped; the L4 segment starts after them.
	withOpt := append([]byte{}, good...)
	withOpt[0] = 0x46
	withOpt = append(withOpt[:20], append(make([]byte, 4), withOpt[20:]...)...)
	binary.BigEndian.PutUint16(withOpt[2:4], uint16(len(withOpt)))
	if _, ok := parseICMPv4InnerPacket(withOpt); !ok {
		t.Fatal("quoted packet with IPv4 options rejected")
	}

	bad := [][]byte{
		nil,
		make([]byte, 19),                  // shorter than a fixed header
		append([]byte{0x60}, good[1:]...), // not IPv4
		append([]byte{0x41}, good[1:]...), // IHL claims 4 bytes
		append([]byte{0x4f}, good[1:]...), // IHL 60 > available bytes
		func() []byte { // unknown protocol
			q := append([]byte{}, good...)
			q[9] = 47
			return q
		}(),
		good[:27], // fewer than 8 L4 bytes
		func() []byte { // total length field smaller than IHL
			q := append([]byte{}, good...)
			binary.BigEndian.PutUint16(q[2:4], 4)
			return q
		}(),
	}
	for i, b := range bad {
		if _, ok := parseICMPv4InnerPacket(b); ok {
			t.Errorf("malformed quote %d accepted", i)
		}
	}
}

// ── end-to-end translation through a fake service ───────────────────────────

const (
	testClient6    = "200:a:b:c::1"
	testPool6      = "300:1:2:3::/96"
	testLocalIP4   = "192.0.2.7"
	testServerV4   = "8.8.8.8"
	testErrRouter4 = "10.9.9.1"
)

// newICMPErrTestEnv builds the shared echo-test environment (capturing stack,
// fake raw socket) plus a discard logger.
func newICMPErrTestEnv(t *testing.T) *icmpTestEnv {
	t.Helper()
	env := newICMPTestEnv(t)
	env.svc.logger.Store(errTestLogger)
	return env
}

// TestRFC7915UDPTimeExceededTracedToClient is the traceroute scenario: a
// Time Exceeded from an intermediate router quoting our outbound probe is
// translated into an ICMPv6 Hop Limit Exceeded whose inner destination is
// restored to the client's original tuple.
func TestRFC7915UDPTimeExceededTracedToClient(t *testing.T) {
	env := newICMPErrTestEnv(t)
	client6 := net.ParseIP(testClient6)
	localIP := [4]byte(net.ParseIP(testLocalIP4).To4())
	dstV4 := [4]byte(net.ParseIP(testServerV4).To4())
	registerFakeUDPSession(env.svc, client6, 5000, dstV4, 33435, localIP, 44444)

	payload := []byte("traceroute-probe-payload")
	quoted := buildIPv4Quoted(t, net.ParseIP(testLocalIP4), net.ParseIP(testServerV4), 17, 61,
		append(buildUDPHeader(44444, 33435), payload...))
	errMsg := buildICMPv4Error(11, 0, 0, quoted)

	var errSrc [4]byte
	copy(errSrc[:], net.ParseIP(testErrRouter4).To4())
	env.svc.handleICMPv4Error(errSrc, errMsg, errTestLogger)

	pkts := env.ns.packets()
	if len(pkts) != 1 {
		t.Fatalf("expected exactly 1 injected error, got %d", len(pkts))
	}
	p := parseSynthICMPv6Error(t, pkts[0])
	if p.typ != 3 || p.code != 0 {
		t.Fatalf("translated type/code = %d/%d, want 3/0", p.typ, p.code)
	}
	if want := net.ParseIP("300:1:2:3::" + testErrRouter4); !p.outerSrc.Equal(want) {
		t.Errorf("outer source = %v, want %v", p.outerSrc, want)
	}
	if !p.outerDst.Equal(client6) {
		t.Errorf("outer destination = %v, want %v", p.outerDst, client6)
	}
	if p.innerNH != 17 || p.innerTTL != 61 {
		t.Errorf("inner NH/TTL = %d/%d, want 17/61", p.innerNH, p.innerTTL)
	}
	if want := net.ParseIP("300:1:2:3::" + testLocalIP4); !p.innerSrc.Equal(want) {
		t.Errorf("inner source = %v, want %v", p.innerSrc, want)
	}
	if !p.innerDst.Equal(client6) {
		t.Errorf("inner destination = %v, want client %v", p.innerDst, client6)
	}
	if got := binary.BigEndian.Uint16(p.innerL4[0:2]); got != 44444 {
		t.Errorf("inner NAT-assigned source port = %d, want 44444", got)
	}
	if got := binary.BigEndian.Uint16(p.innerL4[2:4]); got != 5000 {
		t.Errorf("inner restored destination port = %d, want 5000", got)
	}
	if string(p.innerL4[8:]) != string(payload) {
		t.Errorf("quoted payload damaged: %q", p.innerL4[8:])
	}
}

// TestRFC7915UDPPacketTooBigDeliveredToClient verifies PMTUD plumbing: an
// ICMPv4 Fragmentation Needed becomes an ICMPv6 Packet Too Big with the MTU
// adjusted (+20) and floored at the minimum IPv6 MTU.
func TestRFC7915UDPPacketTooBigDeliveredToClient(t *testing.T) {
	env := newICMPErrTestEnv(t) // fakeNetStack.MTU() = 1500
	client6 := net.ParseIP(testClient6)
	localIP := [4]byte(net.ParseIP(testLocalIP4).To4())
	dstV4 := [4]byte(net.ParseIP(testServerV4).To4())
	registerFakeUDPSession(env.svc, client6, 5000, dstV4, 443, localIP, 40001)

	quoted := buildIPv4Quoted(t, net.ParseIP(testLocalIP4), net.ParseIP(testServerV4), 17, 64,
		buildUDPHeader(40001, 443))
	binary.BigEndian.PutUint16(quoted[2:4], 1400) // offending datagram was 1400 bytes
	errMsg := buildICMPv4Error(3, 4, 1000, quoted)

	var errSrc [4]byte
	copy(errSrc[:], net.ParseIP(testServerV4).To4())
	env.svc.handleICMPv4Error(errSrc, errMsg, errTestLogger)

	pkts := env.ns.packets()
	if len(pkts) != 1 {
		t.Fatalf("expected exactly 1 injected error, got %d", len(pkts))
	}
	p := parseSynthICMPv6Error(t, pkts[0])
	if p.typ != 2 || p.code != 0 {
		t.Fatalf("translated type/code = %d/%d, want 2/0", p.typ, p.code)
	}
	// min(1000+20, 1500) but ≥ 1280.
	if p.extra != 1280 {
		t.Errorf("advertised MTU = %d, want 1280", p.extra)
	}
	if !p.outerDst.Equal(client6) || !p.outerSrc.Equal(net.ParseIP("300:1:2:3::"+testServerV4)) {
		t.Errorf("outer addresses = %v → %v, wrong", p.outerSrc, p.outerDst)
	}
}

// TestRFC5508ICMPTimeExceededRestoresClientID verifies that errors quoting
// our NAT-assigned Echo Requests reach the right client with its original
// identifier — including errors emitted by intermediate routers rather than
// the destination itself.
func TestRFC5508ICMPTimeExceededRestoresClientID(t *testing.T) {
	env := newICMPErrTestEnv(t)
	src6 := [16]byte(net.ParseIP("200:a:b:c::9").To16())
	pool6Src := [16]byte(net.ParseIP("300:1:2:3::198.51.100.4").To16())
	dstV4 := [4]byte(net.ParseIP("198.51.100.4").To4())

	sess := env.svc.registerICMPSession(src6, pool6Src, dstV4, 0xBEEF)
	if sess == nil {
		t.Fatal("session registration failed")
	}

	payload := []byte("echo-data")
	quoted := buildIPv4Quoted(t, net.ParseIP(testLocalIP4), net.IP(dstV4[:]), 1, 55,
		func() []byte {
			b := make([]byte, 8+len(payload))
			b[0] = 8 // Echo Request we sent
			binary.BigEndian.PutUint16(b[4:6], sess.allocID)
			binary.BigEndian.PutUint16(b[6:8], 3)
			copy(b[8:], payload)
			return b
		}())
	errMsg := buildICMPv4Error(11, 0, 0, quoted)

	var hopV4 [4]byte
	copy(hopV4[:], net.ParseIP("203.0.113.77").To4()) // intermediate router, not the server
	env.svc.handleICMPv4Error(hopV4, errMsg, errTestLogger)

	pkts := env.ns.packets()
	if len(pkts) != 1 {
		t.Fatalf("expected exactly 1 injected error, got %d", len(pkts))
	}
	p := parseSynthICMPv6Error(t, pkts[0])
	if p.typ != 3 || p.code != 0 {
		t.Fatalf("translated type/code = %d/%d, want 3/0", p.typ, p.code)
	}
	if !p.outerSrc.Equal(net.ParseIP("300:1:2:3::203.0.113.77")) {
		t.Errorf("outer source = %v, want pool-mapped router", p.outerSrc)
	}
	if !p.outerDst.Equal(src6[:]) || !p.innerDst.Equal(src6[:]) {
		t.Errorf("client address not restored: outer dst=%v inner dst=%v", p.outerDst, p.innerDst)
	}
	if p.innerNH != 58 {
		t.Fatalf("inner protocol = %d, want 58 (ICMPv6)", p.innerNH)
	}
	if p.innerL4[0] != 128 {
		t.Fatalf("inner type = %d, want 128 (Echo Request)", p.innerL4[0])
	}
	if got := binary.BigEndian.Uint16(p.innerL4[4:6]); got != 0xBEEF {
		t.Errorf("client identifier not restored: got 0x%04X, want 0xBEEF", got)
	}
	if got := binary.BigEndian.Uint16(p.innerL4[6:8]); got != 3 {
		t.Errorf("sequence = %d, want 3", got)
	}
	if string(p.innerL4[8:]) != string(payload) {
		t.Errorf("payload damaged: %q", p.innerL4[8:])
	}
}

// TestRFC7915ForeignErrorsIgnored ensures the strict demux: errors quoting
// tuples ydn64 has no session for (other host traffic, DNS64's own queries,
// nested errors, TCP flows) produce no injected packets.
func TestRFC7915ForeignErrorsIgnored(t *testing.T) {
	env := newICMPErrTestEnv(t)
	client6 := net.ParseIP(testClient6)
	dstV4 := [4]byte(net.ParseIP(testServerV4).To4())
	registerFakeUDPSession(env.svc, client6, 5000, dstV4, 53, [4]byte(net.ParseIP(testLocalIP4).To4()), 40000)

	mkErr := func(typ, code byte, l4 []byte, quotedSrc, quotedDst net.IP, proto byte) []byte {
		return buildICMPv4Error(typ, code, 0, buildIPv4Quoted(t, quotedSrc, quotedDst, proto, 64, l4))
	}
	local := net.ParseIP(testLocalIP4)
	server := net.ParseIP(testServerV4)

	foreign := [][]byte{
		// Right ports, wrong quoted source address (not our socket).
		mkErr(11, 0, buildUDPHeader(40000, 53), net.ParseIP("198.51.100.1"), server, 17),
		// Right addresses, wrong ports.
		mkErr(11, 0, buildUDPHeader(1111, 54), local, server, 17),
		// TCP quotes have no tracked sessions (deliberate).
		mkErr(11, 0, buildUDPHeader(40000, 80), local, server, 6),
		// Nested error: only Echo Requests are ever quoted from our ICMP path.
		mkErr(11, 0, func() []byte {
			b := make([]byte, 8)
			b[0] = 3 // someone else's Destination Unreachable
			return b
		}(), local, server, 1),
		// Redirect class is dropped outright.
		mkErr(5, 1, buildUDPHeader(40000, 53), local, server, 17),
	}
	var hopV4 [4]byte
	copy(hopV4[:], net.ParseIP(testErrRouter4).To4())
	for i, msg := range foreign {
		env.svc.handleICMPv4Error(hopV4, msg, errTestLogger)
		if n := len(env.ns.packets()); n != 0 {
			t.Fatalf("foreign/mismatched error %d produced %d injected packet(s)", i, n)
		}
	}
}

// TestRFC7915QuoteTruncatedToMinMTU pins the 1280-byte budget: oversized
// quotes are truncated, never dropped, and stay internally consistent.
func TestRFC7915QuoteTruncatedToMinMTU(t *testing.T) {
	env := newICMPErrTestEnv(t)
	client6 := net.ParseIP(testClient6)
	dstV4 := [4]byte(net.ParseIP(testServerV4).To4())
	registerFakeUDPSession(env.svc, client6, 5000, dstV4, 53, [4]byte(net.ParseIP(testLocalIP4).To4()), 40000)

	bigPayload := make([]byte, 4000)
	for i := range bigPayload {
		bigPayload[i] = byte(i)
	}
	quoted := buildIPv4Quoted(t, net.ParseIP(testLocalIP4), net.ParseIP(testServerV4), 17, 64,
		append(buildUDPHeader(40000, 53), bigPayload...))
	errMsg := buildICMPv4Error(11, 0, 0, quoted)

	var hopV4 [4]byte
	copy(hopV4[:], net.ParseIP(testErrRouter4).To4())
	env.svc.handleICMPv4Error(hopV4, errMsg, errTestLogger)

	pkts := env.ns.packets()
	if len(pkts) != 1 {
		t.Fatalf("expected 1 injected error, got %d", len(pkts))
	}
	if len(pkts[0]) != icmpErrMaxPacket {
		t.Fatalf("packet size = %d, want exactly %d", len(pkts[0]), icmpErrMaxPacket)
	}
	p := parseSynthICMPv6Error(t, pkts[0]) // checksums verified post-truncation
	if len(p.innerL4) != icmpErrMaxPacket-icmpErrFixedLen {
		t.Fatalf("truncated quote length = %d, want %d", len(p.innerL4), icmpErrMaxPacket-icmpErrFixedLen)
	}
	if got := binary.BigEndian.Uint16(p.innerL4[4:6]); got != icmpErrMaxPacket-icmpErrFixedLen {
		t.Errorf("UDP length field = %d, want %d", got, icmpErrMaxPacket-icmpErrFixedLen)
	}
}

// TestICMPv4ErrorRateLimited verifies the synthesised-error token bucket:
// a burst beyond icmpErrBurst is shed, protecting clients and the link.
func TestICMPv4ErrorRateLimited(t *testing.T) {
	env := newICMPErrTestEnv(t)
	client6 := net.ParseIP(testClient6)
	dstV4 := [4]byte(net.ParseIP(testServerV4).To4())
	registerFakeUDPSession(env.svc, client6, 5000, dstV4, 53, [4]byte(net.ParseIP(testLocalIP4).To4()), 40000)

	quoted := buildIPv4Quoted(t, net.ParseIP(testLocalIP4), net.ParseIP(testServerV4), 17, 64,
		buildUDPHeader(40000, 53))
	errMsg := buildICMPv4Error(11, 0, 0, quoted)
	var hopV4 [4]byte
	copy(hopV4[:], net.ParseIP(testErrRouter4).To4())

	for i := 0; i < icmpErrBurst+50; i++ {
		env.svc.handleICMPv4Error(hopV4, errMsg, errTestLogger)
	}
	// The refill during a microsecond-scale loop is far below one token.
	if got := len(env.ns.packets()); got != icmpErrBurst {
		t.Fatalf("injected %d errors, want burst cap %d", got, icmpErrBurst)
	}
}

// TestUDPPortRefusedSynthesisShape checks the ECONNREFUSED surfacing packet:
// ICMPv6 1/4 quoting the translated v4-side view of the flow.
func TestUDPPortRefusedSynthesisShape(t *testing.T) {
	env := newICMPErrTestEnv(t)
	client6 := net.ParseIP(testClient6)
	localIP := [4]byte(net.ParseIP(testLocalIP4).To4())
	dstV4 := [4]byte(net.ParseIP(testServerV4).To4())
	key := registerFakeUDPSession(env.svc, client6, 5000, dstV4, 53, localIP, 40000)
	sess := &udpSession{localIP: localIP, localPort: 40000}

	env.svc.sendUDPPortRefused(sess, key, errTestLogger)

	pkts := env.ns.packets()
	if len(pkts) != 1 {
		t.Fatalf("expected 1 injected error, got %d", len(pkts))
	}
	p := parseSynthICMPv6Error(t, pkts[0])
	if p.typ != 1 || p.code != 4 {
		t.Fatalf("type/code = %d/%d, want 1/4 (port unreachable)", p.typ, p.code)
	}
	if !p.outerSrc.Equal(net.ParseIP("300:1:2:3::" + testServerV4)) {
		t.Errorf("outer source = %v, want pool-mapped server", p.outerSrc)
	}
	if got := binary.BigEndian.Uint16(p.innerL4[0:2]); got != 40000 {
		t.Errorf("inner source port = %d, want NAT-assigned 40000", got)
	}
	if got := binary.BigEndian.Uint16(p.innerL4[2:4]); got != 5000 {
		t.Errorf("inner destination port = %d, want client 5000", got)
	}
}

// TestSendUDPFlowUnreachableShape checks dial-failure notification: ICMPv6
// 1/x quoting the client's original datagram shape.
func TestSendUDPFlowUnreachableShape(t *testing.T) {
	env := newICMPErrTestEnv(t)
	client6 := net.ParseIP(testClient6)
	key := sessionKey{
		srcAddr: [16]byte(client6.To16()),
		srcPort: 5000,
		dstAddr: [4]byte(net.ParseIP(testServerV4).To4()),
		dstPort: 53,
	}
	pool6Src := env.svc.pool6AddrFor(key.dstAddr)

	env.svc.sendUDPFlowUnreachable(pool6Src, key, 1, 0, "no route", errTestLogger)

	pkts := env.ns.packets()
	if len(pkts) != 1 {
		t.Fatalf("expected 1 injected error, got %d", len(pkts))
	}
	p := parseSynthICMPv6Error(t, pkts[0])
	if p.typ != 1 || p.code != 0 {
		t.Fatalf("type/code = %d/%d, want 1/0", p.typ, p.code)
	}
	if !p.outerSrc.Equal(pool6Src[:]) || !p.outerDst.Equal(client6) {
		t.Errorf("outer addresses %v → %v wrong", p.outerSrc, p.outerDst)
	}
	// Generated-error shape: the quote reconstructs the client's own
	// datagram (src = client, dst = pool6 target).
	if !p.innerSrc.Equal(client6) || !p.innerDst.Equal(pool6Src[:]) {
		t.Errorf("inner addresses %v → %v wrong", p.innerSrc, p.innerDst)
	}
	if got := binary.BigEndian.Uint16(p.innerL4[0:2]); got != 5000 {
		t.Errorf("inner source port = %d, want 5000", got)
	}
	if got := binary.BigEndian.Uint16(p.innerL4[2:4]); got != 53 {
		t.Errorf("inner destination port = %d, want 53", got)
	}
}

// TestDialErrorToUnreachableMapping pins the errno → ICMPv6 code mapping.
func TestDialErrorToUnreachableMapping(t *testing.T) {
	syscallErr := func(errno error) error {
		return &net.OpError{Op: "dial", Err: errno}
	}
	cases := []struct {
		err      error
		wantType byte
		wantCode byte
	}{
		{syscallErr(syscall.EACCES), 1, 1},
		{syscallErr(syscall.ENETUNREACH), 1, 0},
		{syscallErr(syscall.EHOSTUNREACH), 1, 0},
		{syscallErr(errors.New("weird")), 1, 3}, // non-errno wrapped: generic
		{errors.New("plain"), 1, 3},
	}
	for _, c := range cases {
		gotType, gotCode := dialErrorToUnreachable(c.err)
		if gotType != c.wantType || gotCode != c.wantCode {
			t.Errorf("dialErrorToUnreachable(%v) = %d/%d, want %d/%d", c.err, gotType, gotCode, c.wantType, c.wantCode)
		}
	}
}

// TestPool6AddrForEmbedding sanity-checks the /96 embedding helper against
// the canonical RFC 6052 layout used everywhere else in this package.
func TestPool6AddrForEmbedding(t *testing.T) {
	svc, err := NewService(config.NAT64Config{Pool6: testPool6, UDPTimeout: 300}, []string{"200::/7"}, nil, &fakeNetStack{})
	if err != nil {
		t.Fatalf("NewService: %v", err)
	}
	got := svc.pool6AddrFor([4]byte{192, 0, 2, 1})
	want := net.ParseIP("300:1:2:3::192.0.2.1")
	if !net.IP(got[:]).Equal(want) {
		t.Fatalf("pool6AddrFor = %v, want %v", net.IP(got[:]), want)
	}
}

// TestICMPv4ErrorNoiseDoesNotDrainBudget pins the code-review-2026-08-24 #5
// fix: the raw socket receives every ICMPv4 error the host sees, and most of
// it is unrelated noise that demuxes to no live NAT64 session. Such noise
// must not consume errLim tokens — after any amount of it, a genuine
// translation for a live flow still goes out at full burst strength.
func TestICMPv4ErrorNoiseDoesNotDrainBudget(t *testing.T) {
	env := newICMPErrTestEnv(t)
	var hopV4 [4]byte
	copy(hopV4[:], net.ParseIP(testErrRouter4).To4())

	// Structurally valid Time Exceeded whose quoted UDP flow matches no
	// live session: pure host noise.
	noiseQuoted := buildIPv4Quoted(t, net.ParseIP("192.0.2.7"), net.ParseIP("198.51.100.77"), 17, 64,
		buildUDPHeader(54321, 12345))
	noise := buildICMPv4Error(11, 0, 0, noiseQuoted)
	for i := 0; i < icmpErrBurst+10; i++ {
		env.svc.handleICMPv4Error(hopV4, noise, errTestLogger)
	}
	if got := len(env.ns.packets()); got != 0 {
		t.Fatalf("noise injected %d packets, want 0", got)
	}

	// A live flow's translation must still be delivered at full burst strength.
	client6 := net.ParseIP(testClient6)
	dstV4 := [4]byte(net.ParseIP(testServerV4).To4())
	registerFakeUDPSession(env.svc, client6, 5000, dstV4, 53,
		[4]byte(net.ParseIP(testLocalIP4).To4()), 40000)

	liveQuoted := buildIPv4Quoted(t, net.ParseIP(testLocalIP4), net.ParseIP(testServerV4), 17, 64,
		buildUDPHeader(40000, 53))
	live := buildICMPv4Error(11, 0, 0, liveQuoted)
	for i := 0; i < icmpErrBurst; i++ {
		env.svc.handleICMPv4Error(hopV4, live, errTestLogger)
	}
	if got := len(env.ns.packets()); got != icmpErrBurst {
		t.Fatalf("live translations after noise = %d, want full burst %d", got, icmpErrBurst)
	}
}
