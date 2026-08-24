package config

import (
	"bytes"
	"net"
	"testing"
)

// TestPref64Offsets pins the byte layout of Figure 1 (RFC 6052 §2.2) for
// every supported prefix length: where the four embedded IPv4 octets live,
// and that the u octet sits at byte 8 for every length below /96.
func TestPref64Offsets(t *testing.T) {
	tests := []struct {
		bits int
		offs [4]int
		hasU bool
	}{
		{32, [4]int{4, 5, 6, 7}, true},
		{40, [4]int{5, 6, 7, 9}, true},
		{48, [4]int{6, 7, 9, 10}, true},
		{56, [4]int{7, 9, 10, 11}, true},
		{64, [4]int{9, 10, 11, 12}, true},
		{96, [4]int{12, 13, 14, 15}, false},
	}
	for _, tc := range tests {
		offs, ok := pref64V4Offsets(tc.bits)
		if !ok || offs != tc.offs {
			t.Errorf("pref64V4Offsets(/%d) = %v (ok=%v), want %v", tc.bits, offs, ok, tc.offs)
		}
	}
	if _, ok := pref64V4Offsets(24); ok {
		t.Error("/24 unexpectedly accepted")
	}
	if _, ok := pref64V4Offsets(112); ok {
		t.Error("/112 unexpectedly accepted")
	}
}

func TestParsePref64(t *testing.T) {
	valid := []string{
		"300:1:2:3::/96",
		"64:ff9b::/96",
		"2001:db8::/32",
		"2001:db8:1::/40",
		"2001:db8:1:2::/48",
		"2001:db8:1:2:3::/56",
		"2001:db8::/64",
		// The embedded-IPv4 region may legitimately be non-zero in the
		// configured network address (here bytes 4..7 for /32).
		"2001:db8:c000:201::/32",
	}
	for _, s := range valid {
		if _, err := ParsePref64(s); err != nil {
			t.Errorf("ParsePref64(%q) = %v, want nil", s, err)
		}
	}

	invalid := []struct {
		s    string
		want string // substring of the expected error
	}{
		{"300:1:2:3::/24", "unsupported prefix length"},
		{"300:1:2:3::/128", "unsupported prefix length"},
		{"300:1:2:3::1/64", "non-zero bits"},          // dirty suffix
		{"300:1:2:3::c000:201:0/32", "non-zero bits"}, // dirty u octet
		{"10.0.0.0/8", "IPv6"},
		{"not-a-prefix/96", "valid CIDR"},
		{"300:1:2:3::", "valid CIDR"}, // bare address, no /n
	}
	for _, tc := range invalid {
		_, err := ParsePref64(tc.s)
		if err == nil {
			t.Errorf("ParsePref64(%q) = nil, want error containing %q", tc.s, tc.want)
		} else if !bytes.Contains([]byte(err.Error()), []byte(tc.want)) {
			t.Errorf("ParsePref64(%q) error = %v, want it to contain %q", tc.s, err, tc.want)
		}
	}
}

// TestPref64EmbedExtractRoundTrip covers Embed→Extract identity for one
// prefix per supported length, including a split-octet length (/40–/56).
func TestPref64EmbedExtractRoundTrip(t *testing.T) {
	v4in := net.IPv4(192, 0, 2, 1).To4()
	prefixes := []string{
		"2001:db8::/32",
		"2001:db8:1::/40",
		"2001:db8:1:2::/48",
		"2001:db8:1:2:3::/56",
		"2001:db8:aaaa:bbbb::/64",
		"300:1:2:3::/96",
		"64:ff9b::/96",
	}
	for _, ps := range prefixes {
		p, err := ParsePref64(ps)
		if err != nil {
			t.Fatalf("ParsePref64(%q): %v", ps, err)
		}
		emb := p.Embed(v4in)
		if emb.To4() != nil {
			t.Errorf("Embed(%q) produced an IPv4-mapped result %s", ps, emb)
		}
		if !p.Net.Contains(emb) {
			t.Errorf("Embed(%q) = %s, not inside its own pool", ps, emb)
		}
		got, ok := p.Extract(emb)
		if !ok {
			t.Fatalf("Extract(%s under %q) failed", emb, ps)
		}
		if !bytes.Equal(got[:], v4in) {
			t.Errorf("round trip under %q gave %v, want 192.0.2.1", ps, got)
		}
	}
}

// TestPref64KnownAnswers checks two hand-computed embeddings against the
// RFC 6052 §2.2 figure: the classic /96 form and the split-octet /56 form.
func TestPref64KnownAnswers(t *testing.T) {
	// /96: 64:ff9b:: + 192.0.2.1 → 64:ff9b::c000:201 (verbatim tail).
	p96, _ := ParsePref64("64:ff9b::/96")
	want96 := net.ParseIP("64:ff9b::c000:201").To16()
	if got := p96.Embed(net.IPv4(192, 0, 2, 1)); !got.Equal(want96) {
		t.Errorf("/96 embed = %s, want %s", got, want96)
	}

	// /56: prefix bytes 0..6, v4 octet 1 in byte 7, u octet 8 zero,
	// v4 octets 2..4 in bytes 9..11.
	p56, err := ParsePref64("2001:db8:0:ab00::/56")
	if err != nil {
		t.Fatalf("ParsePref64(/56): %v", err)
	}
	got56 := []byte(p56.Embed(net.IPv4(192, 0, 2, 1)))
	wantBytes := []byte{
		0x20, 0x01, 0x0d, 0xb8, 0x00, 0x00, 0xab, // prefix bytes 0..6
		0xc0,             // v4 octet 1 @ byte 7
		0x00,             // u octet @ byte 8
		0x00, 0x02, 0x01, // v4 octets 2..4 @ bytes 9..11
		0x00, 0x00, 0x00, 0x00, // suffix
	}
	if !bytes.Equal(got56, wantBytes) {
		t.Errorf("/56 embed = % x, want % x", got56, wantBytes)
	}
	back, ok := p56.Extract(got56)
	if !ok || !bytes.Equal(back[:], net.IPv4(192, 0, 2, 1).To4()) {
		t.Errorf("/56 extract(% x) = %v (ok=%v), want 192.0.2.1", got56, back, ok)
	}
}

// TestPref64ExtractRejectsNonCanonical verifies Extract refuses addresses
// inside the pool whose u octet or suffix bits are set — they are not
// unambiguous members of an RFC 6052 pool.
func TestPref64ExtractRejectsNonCanonical(t *testing.T) {
	p, _ := ParsePref64("2001:db8::/64") // v4 lives at bytes 9..12

	// Canonical /64 embedding of 192.0.2.1:
	//   20 01 0d b8 | 00 00 00 00 | 00(u) | c0 00 02 01 | 00 00 00
	// = 2001:db8::c0:2:100:0
	cases := []struct {
		name string
		addr net.IP
	}{
		{"dirty u octet", net.ParseIP("2001:db8::1c0:2:100:0")},
		{"dirty suffix", net.ParseIP("2001:db8::c0:2:100:1")},
		{"outside pool", net.ParseIP("2001:db9::c0:2:100:0")},
		{"ipv4-mapped input", net.IPv4(192, 0, 2, 1)},
	}
	for _, tc := range cases {
		if got, ok := p.Extract(tc.addr); ok {
			t.Errorf("%s: Extract(%s) = %v, want rejection", tc.name, tc.addr, got)
		}
	}

	// The same address with clean u/suffix extracts correctly.
	v4, ok := p.Extract(net.ParseIP("2001:db8::c0:2:100:0"))
	if !ok || !bytes.Equal(v4[:], net.IPv4(192, 0, 2, 1).To4()) {
		t.Errorf("canonical /64 extract = %v (ok=%v), want 192.0.2.1", v4, ok)
	}
}

func TestParsePref64Addr(t *testing.T) {
	// Bare address → implied /96 (the historical ydn64 zone form).
	p, err := ParsePref64Addr("301:ca27:1d6e:6d2f::")
	if err != nil || p.Bits != 96 {
		t.Errorf("ParsePref64Addr(bare /96) = (%v, %v), want 96 bits, nil error", p, err)
	}

	// Explicit length switches to the variable formats.
	p, err = ParsePref64Addr("2001:db8::/48")
	if err != nil || p.Bits != 48 {
		t.Errorf("ParsePref64Addr(/48) = (%v, %v), want 48 bits, nil error", p, err)
	}

	invalid := []string{
		"",                      // empty
		"192.0.2.1",             // IPv4
		"::c0a8:101",            // bare but last four bytes dirty
		"301:ca27:1d6e:6d2f::1", // host bit set under implied /96
		"nonsense",
		"2001:db8::1/36", // unsupported length
		"2001:db8::1/64", // dirty suffix under explicit /64
	}
	for _, s := range invalid {
		if _, err := ParsePref64Addr(s); err == nil {
			t.Errorf("ParsePref64Addr(%q) = nil error, want rejection", s)
		}
	}
}
