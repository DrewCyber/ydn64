package dns64

import (
	"strconv"
	"testing"
	"time"

	"github.com/miekg/dns"
)

// k builds a cacheKey for AAAA answers in cache tests.
func k(name string) cacheKey {
	return cacheKey{name: name, qtype: dns.TypeAAAA}
}

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
	c := newCache(time.Hour, 0, 0) // config says 1h
	c.set(k("short.example."), []dns.RR{aTestRR(t, "short.example.", 1)})

	if _, ok := c.get(k("short.example.")); !ok {
		t.Fatal("entry missing immediately after set")
	}

	time.Sleep(1300 * time.Millisecond)
	if _, ok := c.get(k("short.example.")); ok {
		t.Error("entry with 1s upstream TTL still alive after 1.3s (config expiration is 1h)")
	}
}

func TestCacheClampsLongUpstreamTTLToConfig(t *testing.T) {
	c := newCache(300*time.Millisecond, 0, 0)
	c.set(k("long.example."), []dns.RR{aTestRR(t, "long.example.", 120)})

	if _, ok := c.get(k("long.example.")); !ok {
		t.Fatal("entry missing immediately after set")
	}

	time.Sleep(450 * time.Millisecond)
	if _, ok := c.get(k("long.example.")); ok {
		t.Error("entry still alive past configured 300ms expiration despite 120s upstream TTL")
	}
}

func TestCacheHitDecrementsTTLAndReturnsCopies(t *testing.T) {
	// R4b: hits must serve decremented TTLs instead of re-serving the
	// original value forever.
	c := newCache(time.Hour, 0, 0)
	c.set(k("dec.example."), []dns.RR{aTestRR(t, "dec.example.", 60)})

	first, ok := c.get(k("dec.example."))
	if !ok {
		t.Fatal("entry missing immediately after set")
	}
	if got := first[0].Header().Ttl; got < 58 || got > 60 {
		t.Fatalf("first hit TTL = %d, want 58..60", got)
	}

	// Mutate the returned copy; the stored entry must be unaffected.
	first[0].Header().Ttl = 9999

	time.Sleep(1200 * time.Millisecond)
	second, ok := c.get(k("dec.example."))
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
	c := newCache(0, 0, 0)
	c.set(k("off.example."), []dns.RR{aTestRR(t, "off.example.", 1)})
	time.Sleep(1300 * time.Millisecond)
	if rrs, ok := c.get(k("off.example.")); !ok {
		t.Error("entry expired although cache expiration is disabled (defaultExp=0)")
	} else if rrs[0].Header().Ttl != 1 {
		t.Errorf("TTL = %d, want undecremented 1 when entry has no effective TTL", rrs[0].Header().Ttl)
	}
}

func TestCacheKeyIncludesQtype(t *testing.T) {
	// R4 stage 1: the same name under different qtypes must not collide (the
	// name-only key was a latent collision if A/PTR caching is ever added).
	c := newCache(time.Hour, 0, 0)
	aQ := cacheKey{name: "dual.example.", qtype: dns.TypeA}
	c.set(aQ, []dns.RR{mustNewRR(t, "dual.example. 30 IN A 192.0.2.1")})
	aaaa := []dns.RR{aTestRR(t, "dual.example.", 30)}
	c.set(k("dual.example."), aaaa)

	gotA, ok := c.get(aQ)
	if !ok {
		t.Fatal("A entry missing")
	}
	if _, isA := gotA[0].(*dns.A); !isA {
		t.Errorf("key (name,A) returned %T, want *dns.A", gotA[0])
	}
	gotAAAA, ok := c.get(k("dual.example."))
	if !ok {
		t.Fatal("AAAA entry missing")
	}
	if _, isAAAA := gotAAAA[0].(*dns.AAAA); !isAAAA {
		t.Errorf("key (name,AAAA) returned %T, want *dns.AAAA", gotAAAA[0])
	}
}

func TestCacheEvictsExpiredBeforeRandomAtCapacity(t *testing.T) {
	c := newCache(time.Hour, 0, 3)

	// Fill the cache: one long-lived entry plus two whose upstream TTLs (1s)
	// fall far below the configured hour.
	fresh := []dns.RR{aTestRR(t, "fresh.example.", 3600)}
	short1 := []dns.RR{aTestRR(t, "short1.example.", 1)}
	short2 := []dns.RR{aTestRR(t, "short2.example.", 1)}
	c.set(k("fresh.example."), fresh)
	c.set(k("short1.example."), short1)
	c.set(k("short2.example."), short2)

	time.Sleep(1300 * time.Millisecond)

	// Cache is full of expired entries; a new insert must purge them rather
	// than evict the live entry.
	c.set(k("new.example."), fresh)

	for _, name := range []string{"short1.example.", "short2.example."} {
		if _, ok := c.items[k(name)]; ok {
			t.Errorf("expired entry %q survived eviction", name)
		}
	}
	if _, ok := c.items[k("fresh.example.")]; !ok {
		t.Error("live entry was evicted although expired entries had priority")
	}
	if len(c.items) != 2 {
		t.Errorf("len(items) = %d, want 2", len(c.items))
	}
}

func TestCacheRandomEvictionWhenFullOfLiveEntries(t *testing.T) {
	c := newCache(time.Hour, 0, 2)
	c.set(k("a.example."), []dns.RR{aTestRR(t, "a.example.", 3600)})
	c.set(k("b.example."), []dns.RR{aTestRR(t, "b.example.", 3600)})

	c.set(k("c.example."), []dns.RR{aTestRR(t, "c.example.", 3600)})

	if len(c.items) != 2 {
		t.Fatalf("len(items) = %d, want 2", len(c.items))
	}
	if _, ok := c.items[k("c.example.")]; !ok {
		t.Error("most recently inserted entry missing after eviction")
	}
	// Exactly one of the two older entries was evicted at random.
	var survivors int
	for _, name := range []string{"a.example.", "b.example."} {
		if _, ok := c.items[k(name)]; ok {
			survivors++
		}
	}
	if survivors != 1 {
		t.Errorf("%d older entries survived, want exactly 1", survivors)
	}
}

func TestCacheOverwriteExistingKeyDoesNotEvict(t *testing.T) {
	c := newCache(time.Hour, 0, 2)
	c.set(k("a.example."), []dns.RR{aTestRR(t, "a.example.", 3600)})
	c.set(k("b.example."), []dns.RR{aTestRR(t, "b.example.", 3600)})

	// Refreshing an existing entry at capacity must keep all entries.
	c.set(k("a.example."), []dns.RR{aTestRR(t, "a.example.", 1800)})

	if len(c.items) != 2 {
		t.Fatalf("len(items) = %d, want 2", len(c.items))
	}
	if _, ok := c.items[k("b.example.")]; !ok {
		t.Error("unrelated entry was evicted when updating an existing key")
	}
}

func mustNewRR(t *testing.T, s string) dns.RR {
	t.Helper()
	rr, err := dns.NewRR(s)
	if err != nil || rr == nil {
		t.Fatalf("dns.NewRR(%q): %v (%v)", s, rr, err)
	}
	return rr
}
