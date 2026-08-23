package dns64

import (
	"testing"

	"github.com/miekg/dns"
)

func mkZones(lists ...[]string) []zone {
	out := make([]zone, 0, len(lists))
	for _, domains := range lists {
		out = append(out, zone{domains: domains})
	}
	return out
}

// TestMatchZoneConfigOrderPrecedence pins the actual matching semantics:
// zones win in CONFIG ORDER (first suffix/exact hit), and the "." catch-all
// is only consulted after every configured zone.
func TestMatchZonePrecedence(t *testing.T) {
	specificFirst := mkZones(
		[]string{"a.example"},
		[]string{"example", "ygg"},
		[]string{"."},
	)
	if z := matchZone(specificFirst, "host.a.example."); z == nil || !containsDomain(z, "a.example") {
		t.Errorf("host.a.example. matched %v, want the a.example zone", z)
	}
	if z := matchZone(specificFirst, "other.example."); z == nil || !containsDomain(z, "example") {
		t.Errorf("other.example. matched %v, want the example zone", z)
	}
	if z := matchZone(specificFirst, "foo.ygg"); z == nil || !containsDomain(z, "ygg") {
		t.Errorf("foo.ygg matched %v, want the ygg zone", z)
	}
	if z := matchZone(specificFirst, "unrelated.org."); z == nil || !containsDomain(z, ".") {
		t.Errorf("unrelated.org. matched %v, want the catch-all zone", z)
	}
	if matchZone(mkZones([]string{"example"}), "unrelated.org.") != nil {
		t.Error("expected nil zone for a name no configured domain matches")
	}
}

// TestMatchZoneOrderBeatsSpecificity documents that a broader zone listed
// FIRST shadows a more specific one listed later — config order is the
// contract, not automatic most-specific-first selection.
func TestMatchZoneOrderBeatsSpecificity(t *testing.T) {
	broadFirst := mkZones([]string{"example"}, []string{"specific.example"})
	z := matchZone(broadFirst, "host.specific.example.")
	if z == nil || !containsDomain(z, "example") {
		t.Errorf("broad-first zones: matched %v, want the first-listed example zone", z)
	}
}

func containsDomain(z *zone, want string) bool {
	for _, d := range z.domains {
		if d == want {
			return true
		}
	}
	return false
}

// TestParseListenPort: strconv semantics — signs, whitespace, out-of-range
// and non-numeric values are rejected instead of silently truncated
// (fmt.Sscan used to accept "+53" / "-1" / "70000" with surprising results).
func TestParseListenPort(t *testing.T) {
	tests := []struct {
		in      string
		want    int
		wantErr bool
	}{
		{"", 53, false}, // default
		{"53", 53, false},
		{"65535", 65535, false},
		{"0", 0, true},
		{"-1", 0, true},
		{"+53", 0, true},
		{"70000", 0, true},
		{"abc", 0, true},
		{"53 ", 0, true},
		{"1 2", 0, true},
	}
	for _, tc := range tests {
		got, err := parseListenPort(tc.in)
		if tc.wantErr && err == nil {
			t.Errorf("parseListenPort(%q) = %d, nil error; want error", tc.in, got)
		}
		if !tc.wantErr && (err != nil || got != tc.want) {
			t.Errorf("parseListenPort(%q) = (%d, %v); want (%d, nil)", tc.in, got, err, tc.want)
		}
	}
}

// TestRefusedResponseShape verifies the DENIED-source answer is a proper
// REFUSED echoing id and question.
func TestRefusedResponseShape(t *testing.T) {
	req := new(dns.Msg)
	req.SetQuestion("example.com.", dns.TypeAAAA)
	resp := refusedResponse(req)
	out, err := resp.Pack()
	if err != nil {
		t.Fatalf("Pack: %v", err)
	}
	parsed := new(dns.Msg)
	if err := parsed.Unpack(out); err != nil {
		t.Fatalf("Unpack: %v", err)
	}
	if !parsed.Response || parsed.Rcode != dns.RcodeRefused {
		t.Errorf("response=%v rcode=%v, want response=true REFUSED", parsed.Response, parsed.Rcode)
	}
	if parsed.Id != req.Id || len(parsed.Question) != 1 || parsed.Question[0].Name != "example.com." {
		t.Errorf("id/question not echoed: id=%d question=%v", parsed.Id, parsed.Question)
	}
}
