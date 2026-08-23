package dns64

import (
	"testing"

	"github.com/miekg/dns"
)

func TestQuerySlotShedding(t *testing.T) {
	s := &Service{querySem: make(chan struct{}, 1)}
	if !s.tryAcquireQuery() {
		t.Fatal("first acquire refused against empty semaphore")
	}
	if s.tryAcquireQuery() {
		t.Fatal("second acquire succeeded against limit of 1")
	}
	s.releaseQuery()
	if !s.tryAcquireQuery() {
		t.Fatal("acquire after release failed")
	}

	unlimited := &Service{}
	for i := 0; i < 10; i++ {
		if !unlimited.tryAcquireQuery() {
			t.Fatalf("acquire %d refused without a configured limit", i)
		}
	}
}

func TestShedResponseIsSERVFAIL(t *testing.T) {
	req := new(dns.Msg)
	req.SetQuestion("example.com.", dns.TypeAAAA)
	resp := shedResponse(req)
	out, err := resp.Pack()
	if err != nil {
		t.Fatalf("Pack: %v", err)
	}
	parsed := new(dns.Msg)
	if err := parsed.Unpack(out); err != nil {
		t.Fatalf("Unpack: %v", err)
	}
	if !parsed.Response || parsed.Rcode != dns.RcodeServerFailure {
		t.Errorf("shed response = response=%v rcode=%v, want response=true SERVFAIL", parsed.Response, parsed.Rcode)
	}
	if len(parsed.Question) != 1 || parsed.Question[0].Name != "example.com." {
		t.Errorf("shed response question = %v, want echoed question", parsed.Question)
	}
	if parsed.Id != req.Id {
		t.Errorf("shed response id = %d, want %d", parsed.Id, req.Id)
	}
}
