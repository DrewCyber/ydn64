package dns64

import (
	"sync"
	"time"
)

// Per-source token-bucket rate limiting (RFC 5358, BCP 140): ydn64's
// AllowedSources typically trusts a wide slice of the Yggdrasil network, so
// any peer could otherwise turn the embedded resolver into a query engine
// for reflection/amplification attacks or simply starve everyone else.
//
// The limiter is deliberately hand-rolled instead of pulled from
// golang.org/x/time/rate: it is ~60 lines in the shape of nat64's own
// errRateLimiter, needs no external dependency, and its map stays bounded
// by lazy eviction (sources stop bucketing themselves once idle long
// enough), which matters because this runs on every inbound datagram.

const (
	// rateLimitBurstFactor scales each source's burst allowance relative to
	// its sustained rate; short spikes from busy stub resolvers must not
	// trip the limiter.
	rateLimitBurstFactor = 2

	// rateLimitMinBurst floors the burst so very low configured rates still
	// tolerate ordinary retry behaviour.
	rateLimitMinBurst = 10

	// maxRateBuckets bounds the live-bucket map. Yggdrasil source addresses
	// are cryptographically bound to nodes (spoofing is not routable), so
	// this is generous headroom rather than a hard security line.
	maxRateBuckets = 8192

	// rateBucketIdle is how long an untouched bucket survives eviction
	// sweeps triggered once the map reaches maxRateBuckets.
	rateBucketIdle = 5 * time.Minute
)

type srcBucket struct {
	tokens float64
	last   time.Time
}

// srcRateLimiter is a bounded per-source token bucket. A nil limiter allows
// everything (rate limiting disabled).
type srcRateLimiter struct {
	mu      sync.Mutex
	buckets map[[16]byte]*srcBucket
	rate    float64 // tokens added per second
	burst   float64 // maximum storable tokens
}

func newSrcRateLimiter(ratePerSec int) *srcRateLimiter {
	l := &srcRateLimiter{buckets: make(map[[16]byte]*srcBucket)}
	l.update(ratePerSec)
	return l
}

// update replaces the rate (e.g. on SIGHUP reload); 0 or negative disables
// limiting entirely. Existing buckets keep their current token counts but
// are immediately re-capped against the new burst.
func (l *srcRateLimiter) update(ratePerSec int) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if ratePerSec <= 0 {
		l.rate = 0
		return
	}
	l.rate = float64(ratePerSec)
	l.burst = float64(2 * ratePerSec)
	if l.burst < rateLimitMinBurst {
		l.burst = rateLimitMinBurst
	}
	for _, b := range l.buckets {
		if b.tokens > l.burst {
			b.tokens = l.burst
		}
	}
}

// allow consumes one token for src at time now, refilling first. Sources
// over their budget are rejected without allocating state beyond their
// existing bucket.
func (l *srcRateLimiter) allow(src [16]byte, now time.Time) bool {
	if l == nil || l.rate <= 0 {
		return true
	}
	l.mu.Lock()
	defer l.mu.Unlock()

	b, ok := l.buckets[src]
	if !ok {
		if len(l.buckets) >= maxRateBuckets {
			l.sweepLocked(now)
		}
		b = &srcBucket{tokens: l.burst, last: now}
		l.buckets[src] = b
	}

	elapsed := now.Sub(b.last).Seconds()
	b.last = now
	b.tokens += elapsed * l.rate
	if b.tokens > l.burst {
		b.tokens = l.burst
	}
	if b.tokens < 1 {
		return false
	}
	b.tokens--
	return true
}

// sweepLocked evicts buckets idle longer than rateBucketIdle. Callers must
// hold l.mu. Buckets newer than that are kept even under pressure — they
// represent active sources whose next datagram would recreate them anyway,
// so dropping fresh entries achieves nothing.
func (l *srcRateLimiter) sweepLocked(now time.Time) {
	cutoff := now.Add(-rateBucketIdle)
	for k, b := range l.buckets {
		if b.last.Before(cutoff) {
			delete(l.buckets, k)
		}
	}
}
