package dns64

import (
	"sync"
	"sync/atomic"
	"time"
)

// dnsCache is a simple TTL cache for DNS answers.
// Keys are DNS question names (FQDN strings), values are []dns.RR slices.
type dnsCache struct {
	mu            sync.RWMutex
	items         map[string]cacheItem
	defaultExp    atomic.Int64 // nanoseconds; read/written via Reload for live config reload
	purgeInterval time.Duration
	ticker        *time.Ticker // nil if purgeInterval was 0 at construction (no janitor)
}

type cacheItem struct {
	value      interface{}
	expiration int64 // Unix nanoseconds; 0 = never expires
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

func (c *dnsCache) set(k string, v interface{}) {
	var exp int64
	if d := c.defaultExp.Load(); d > 0 {
		exp = time.Now().Add(time.Duration(d)).UnixNano()
	}
	c.mu.Lock()
	c.items[k] = cacheItem{value: v, expiration: exp}
	c.mu.Unlock()
}

func (c *dnsCache) get(k string) (interface{}, bool) {
	c.mu.RLock()
	item, ok := c.items[k]
	c.mu.RUnlock()
	if !ok {
		return nil, false
	}
	if item.expiration > 0 && time.Now().UnixNano() > item.expiration {
		return nil, false
	}
	return item.value, true
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
