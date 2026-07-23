package dns64

import (
	"sync"
	"time"
)

// dnsCache is a simple TTL cache for DNS answers.
// Keys are DNS question names (FQDN strings), values are []dns.RR slices.
type dnsCache struct {
	mu            sync.RWMutex
	items         map[string]cacheItem
	defaultExp    time.Duration
	purgeInterval time.Duration
}

type cacheItem struct {
	value      interface{}
	expiration int64 // Unix nanoseconds; 0 = never expires
}

func newCache(defaultExp, purgeInterval time.Duration) *dnsCache {
	c := &dnsCache{
		items:         make(map[string]cacheItem),
		defaultExp:    defaultExp,
		purgeInterval: purgeInterval,
	}
	if purgeInterval > 0 {
		go c.janitor()
	}
	return c
}

func (c *dnsCache) set(k string, v interface{}) {
	var exp int64
	if c.defaultExp > 0 {
		exp = time.Now().Add(c.defaultExp).UnixNano()
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
	ticker := time.NewTicker(c.purgeInterval)
	defer ticker.Stop()
	for range ticker.C {
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
