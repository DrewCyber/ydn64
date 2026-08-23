package dns64

import (
	"strconv"
	"testing"
	"time"

	"github.com/miekg/dns"
)

// aTestRR builds an AAAA RR with the given TTL for cache tests.
func aTestRR(t *testing.T, name string, ttl uint32) *dns.AAAA {
	t.Helper()
	rr, err := dns.NewRR(name + " " + strconv.FormatUint(uint64(ttl), 10) + " IN AAAA 2001:db8::1")
	if err != nil || rr == nil {
		t.Fatalf("dns.NewRR: %v (%v)", rr, err)
	}
	return rr.(*dns.AAAA)
}

func TestCacheExpiresByUpstreamTTL(t *testing.T) {
	// R4b: an upstream TTL shorter than Dns64CacheExpiration must bound the
	// entry's lifetime — previously entries lived exactly the configured
	// expiration regardless of upstream TTL.
	c := newCache(time.Hour, 0) // config says 1h
	c.set("short.example.", []dns.RR{aTestRR(t, "short.example.", 1)})

	if _, ok := c.get("short.example."); !ok {
		t.Fatal("entry missing immediately after set")
	}

	time.Sleep(1300 * time.Millisecond)
	if _, ok := c.get("short.example."); ok {
		t.Error("entry with 1s upstream TTL still alive after 1.3s (config expiration is 1h)")
	}
}

func TestCacheClampsLongUpstreamTTLToConfig(t *testing.T) {
	c := newCache(300*time.Millisecond, 0)
	c.set("long.example.", []dns.RR{aTestRR(t, "long.example.", 120)})

	if _, ok := c.get("long.example."); !ok {
		t.Fatal("entry missing immediately after set")
	}

	time.Sleep(450 * time.Millisecond)
	if _, ok := c.get("long.example."); ok {
		t.Error("entry still alive past configured 300ms expiration despite 120s upstream TTL")
	}
}

func TestCacheHitDecrementsTTLAndReturnsCopies(t *testing.T) {
	// R4b: hits must serve decremented TTLs instead of re-serving the
	// original value forever.
	c := newCache(time.Hour, 0)
	c.set("dec.example.", []dns.RR{aTestRR(t, "dec.example.", 60)})

	first, ok := c.get("dec.example.")
	if !ok {
		t.Fatal("entry missing immediately after set")
	}
	if got := first[0].Header().Ttl; got < 58 || got > 60 {
		t.Fatalf("first hit TTL = %d, want 58..60", got)
	}

	// Mutate the returned copy; the stored entry must be unaffected.
	first[0].Header().Ttl = 9999

	time.Sleep(1200 * time.Millisecond)
	second, ok := c.get("dec.example.")
	if !ok {
		t.Fatal("entry expired too early (TTL was 60s)")
	}
	if got := second[0].Header().Ttl; got < 55 || got > 59 {
		t.Fatalf("hit after ~1.2s has TTL %d, want decremented value in 55..59", got)
	}
	if got := second[0].Header().Ttl; got == 9999 {
		t.Error("mutation of a previous get() result leaked into the cached entry")
	}
}

func TestCacheDisabledNeverExpires(t *testing.T) {
	// Preserved legacy behaviour: defaultExp <= 0 means entries never expire.
	c := newCache(0, 0)
	c.set("off.example.", []dns.RR{aTestRR(t, "off.example.", 1)})
	time.Sleep(1300 * time.Millisecond)
	if rrs, ok := c.get("off.example."); !ok {
		t.Error("entry expired although cache expiration is disabled (defaultExp=0)")
	} else if rrs[0].Header().Ttl != 1 {
		t.Errorf("TTL = %d, want undecremented 1 when entry has no effective TTL", rrs[0].Header().Ttl)
	}
}
