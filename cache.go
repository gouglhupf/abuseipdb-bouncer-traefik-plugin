package abuseipdb_bouncer_traefik_plugin

import (
	"container/list"
	"sync"
	"time"
)

type decision struct {
	blocked  bool
	source   string
	score    int
	hasScore bool
}

type cacheEntry struct {
	key     string
	value   decision
	expires time.Time
}

type flight struct {
	done  chan struct{}
	value decision
}

// lookupCache owns both LRU entries and in-flight calls, making miss registration atomic.
type lookupCache struct {
	mu       sync.Mutex
	capacity int
	entries  map[string]*list.Element
	order    *list.List
	flights  map[string]*flight
}

func newLookupCache(capacity int) *lookupCache {
	return &lookupCache{capacity: capacity, entries: make(map[string]*list.Element), order: list.New(), flights: make(map[string]*flight)}
}

func (c *lookupCache) start(key string, now time.Time) (decision, *flight, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if el, ok := c.entries[key]; ok {
		entry := el.Value.(cacheEntry)
		if now.Before(entry.expires) {
			c.order.MoveToFront(el)
			return entry.value, nil, false
		}
		c.order.Remove(el)
		delete(c.entries, key)
	}
	if f, ok := c.flights[key]; ok {
		return decision{}, f, false
	}
	f := &flight{done: make(chan struct{})}
	c.flights[key] = f
	return decision{}, f, true
}

func (c *lookupCache) finish(key string, f *flight, value decision, expires time.Time) {
	c.mu.Lock()
	defer c.mu.Unlock()
	el := c.order.PushFront(cacheEntry{key: key, value: value, expires: expires})
	c.entries[key] = el
	if c.order.Len() > c.capacity {
		old := c.order.Back()
		delete(c.entries, old.Value.(cacheEntry).key)
		c.order.Remove(old)
	}
	f.value = value
	delete(c.flights, key)
	close(f.done)
}
