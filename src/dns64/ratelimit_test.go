package dns64

import (
	"testing"
	"time"
)

func src16(b byte) [16]byte {
	var s [16]byte
	s[15] = b
	return s
}

// TestSrcRateLimiterBurstAndRefill pins the token-bucket semantics: a full
// burst passes instantly, the next query is shed, and tokens regenerate at
// the configured rate.
func TestSrcRateLimiterBurstAndRefill(t *testing.T) {
	l := newSrcRateLimiter(10) // 10 qps → burst 20
	now := time.Now()
	src := src16(1)

	allowed := 0
	for i := 0; i < 25; i++ {
		if l.allow(src, now) {
			allowed++
		}
	}
	if allowed != 20 {
		t.Fatalf("burst allowed %d queries, want exactly 20", allowed)
	}

	// 100 ms of refill at 10 qps = one token.
	if l.allow(src, now.Add(50*time.Millisecond)) {
		t.Fatal("query allowed before any meaningful refill")
	}
	if !l.allow(src, now.Add(150*time.Millisecond)) {
		t.Fatal("refilled token not granted after 150 ms")
	}
}

// TestSrcRateLimiterPerSourceIsolation ensures exhausting one source's
// budget never affects another source.
func TestSrcRateLimiterPerSourceIsolation(t *testing.T) {
	l := newSrcRateLimiter(5)
	now := time.Now()

	for i := 0; i < 100; i++ { // far beyond the burst
		l.allow(src16(9), now)
	}
	if l.allow(src16(9), now) {
		t.Fatal("exhausted source still admitted")
	}
	if !l.allow(src16(10), now) {
		t.Fatal("independent source affected by another's exhaustion")
	}
}

// TestSrcRateLimiterDisabledAndReload covers the two lifecycle rules: a zero
// rate disables limiting entirely, and updating re-caps stored bursts.
func TestSrcRateLimiterDisabledAndReload(t *testing.T) {
	l := newSrcRateLimiter(5)
	now := time.Now()
	src := src16(3)

	for i := 0; i < 100; i++ {
		l.allow(src, now)
	}
	if l.allow(src, now) {
		t.Fatal("expected exhaustion before disabling")
	}

	l.update(0) // disabled
	for i := 0; i < 100; i++ {
		if !l.allow(src, now) {
			t.Fatalf("disabled limiter refused query %d", i)
		}
	}

	l.update(2) // re-enabled with burst floor 10
	b := l.buckets[src]
	if b.tokens > l.burst {
		t.Errorf("stored tokens %v exceed new burst %v", b.tokens, l.burst)
	}
	if !l.allow(src, now.Add(time.Second)) {
		t.Fatal("re-enabled limiter did not grant a token")
	}
}

// TestSrcRateLimiterMapBounded exercises the eviction sweep: once the bucket
// map reaches its cap, idle buckets are dropped to make room while fresh
// ones are kept.
func TestSrcRateLimiterMapBounded(t *testing.T) {
	l := newSrcRateLimiter(5)
	now := time.Now()

	for i := 0; i < maxRateBuckets; i++ {
		var s [16]byte
		s[13] = 0xEE
		s[14] = byte(i >> 8)
		s[15] = byte(i)
		l.allow(s, now)
	}
	// Age every bucket past rateBucketIdle.
	l.mu.Lock()
	for _, b := range l.buckets {
		b.last = now.Add(-rateBucketIdle - time.Minute)
	}
	n := len(l.buckets)
	l.mu.Unlock()
	if n < maxRateBuckets-256 {
		t.Fatalf("setup unexpectedly small: %d buckets", n)
	}

	// One more source triggers the sweep and must be admitted afterwards.
	if !l.allow(src16(0xAA), now.Add(time.Minute)) {
		t.Fatal("fresh source denied during sweep")
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	if got := len(l.buckets); got != 1 {
		t.Errorf("bucket map holds %d entries after sweep, want 1 (the fresh source)", got)
	}
}
