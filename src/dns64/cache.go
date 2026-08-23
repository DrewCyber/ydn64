package dns64

import (
	"sync"
	"sync/atomic"
	"time"

	"github.com/miekg/dns"
)

// dnsCache is a TTL cache for DNS answer RR slices.
// Keys are DNS question names (FQDN strings). Each entry expires after
// min(smallest RR TTL in the answer, configured default expiration), so a
// short-lived upstream record cannot outlive its TTL just because
// Dns64CacheExpiration is large. Cache hits return copies whose TTLs are
// decremented by the time spent in the cache — re-serving an undecremented
// TTL would let clients pin stale records forever (RFC 2181 §8).
type dnsCache struct {
	mu            sync.RWMutex
	items         map[string]cacheItem
	defaultExp    atomic.Int64 // nanoseconds; read/written via Reload for live config reload
	purgeInterval time.Duration
	ticker        *time.Ticker // nil if purgeInterval was 0 at construction (no janitor)
}

type cacheItem struct {
	value      []dns.RR
	expiration int64 // Unix nanoseconds; 0 = never expires
	ttl        time.Duration
}

func newCache(defaultExp, purgeInterval time.Duration) *dnsCache {
	c := &dnsCache{
		items:         make(map[string]cacheItem),
		purgeInterval: purgeInterval,
	}
	c.defaultExp.Store(int64(defaultExp))
	if purgeInterval > 0 {
		c.ticker = time.NewTicker(purgeInterval)
		go c.janitor()
	}
	return c
}

// Reload atomically updates the default expiration (applied to entries
// cached from now on) and, if a janitor is running, resets its purge
// interval. It also flushes all currently cached entries: cached AAAA
// answers are stored post zone-filtering (see proxy.handleAAAA), so a stale
// entry would otherwise keep serving a pre-reload zone's answer (e.g. a
// zone's return-ipv6-addresses/prefix) after Dns64Zones or Dns64Default has
// changed, silently bypassing the new config until the old TTL expired. If
// the cache was created with purgeInterval == 0 (no janitor), a nonzero
// purgeInterval here has no effect — starting a janitor after the fact
// isn't supported, since that's only a config reload nicety, not a
// correctness requirement.
func (c *dnsCache) Reload(defaultExp, purgeInterval time.Duration) {
	c.defaultExp.Store(int64(defaultExp))
	if c.ticker != nil && purgeInterval > 0 {
		c.purgeInterval = purgeInterval
		c.ticker.Reset(purgeInterval)
	}
	c.mu.Lock()
	c.items = make(map[string]cacheItem)
	c.mu.Unlock()
}

func (c *dnsCache) set(k string, rrs []dns.RR) {
	var exp int64
	var eff time.Duration
	if d := c.defaultExp.Load(); d > 0 {
		eff = time.Duration(d)
		if minTTL := minRRTTL(rrs); minTTL > 0 && minTTL < eff {
			eff = minTTL
		}
		exp = time.Now().Add(eff).UnixNano()
	}
	c.mu.Lock()
	c.items[k] = cacheItem{value: rrs, expiration: exp, ttl: eff}
	c.mu.Unlock()
}

// get returns a copy of the cached RRs with TTLs decremented by their time
// in the cache (clamped at zero). Callers may mutate the result freely; the
// stored entry stays untouched.
func (c *dnsCache) get(k string) ([]dns.RR, bool) {
	c.mu.RLock()
	item, ok := c.items[k]
	c.mu.RUnlock()
	if !ok {
		return nil, false
	}
	now := time.Now().UnixNano()
	if item.expiration > 0 && now > item.expiration {
		return nil, false
	}
	if item.ttl <= 0 || item.expiration <= 0 {
		return item.value, true
	}
	elapsed := item.ttl - time.Duration(item.expiration-now)
	if elapsed < 0 {
		elapsed = 0
	}
	out := make([]dns.RR, len(item.value))
	for i, rr := range item.value {
		cp := dns.Copy(rr)
		if dec := uint32(elapsed / time.Second); dec >= cp.Header().Ttl {
			cp.Header().Ttl = 0
		} else {
			cp.Header().Ttl -= dec
		}
		out[i] = cp
	}
	return out, true
}

func (c *dnsCache) janitor() {
	defer c.ticker.Stop()
	for range c.ticker.C {
		now := time.Now().UnixNano()
		c.mu.Lock()
		for k, item := range c.items {
			if item.expiration > 0 && now > item.expiration {
				delete(c.items, k)
			}
		}
		c.mu.Unlock()
	}
}

// minRRTTL returns the smallest TTL among rrs (0 when the slice is empty).
func minRRTTL(rrs []dns.RR) time.Duration {
	var min uint32
	for i, rr := range rrs {
		ttl := rr.Header().Ttl
		if i == 0 || ttl < min {
			min = ttl
		}
	}
	return time.Duration(min) * time.Second
}
