package abuseipdb_traefik_bouncer

import (
	"testing"
	"time"
)

func TestCacheLRUExpiryAndFlights(t *testing.T) {
	c := newLookupCache(2)
	now := time.Now()
	_, f, leader := c.start("a", now)
	if !leader {
		t.Fatal("missing leader")
	}
	_, same, leader := c.start("a", now)
	if leader || same != f {
		t.Fatal("flight not coalesced")
	}
	c.finish("a", f, decision{source: "a"}, now.Add(time.Minute))
	_, f, _ = c.start("b", now)
	c.finish("b", f, decision{source: "b"}, now.Add(time.Minute))
	if d, f, _ := c.start("a", now); f != nil || d.source != "a" {
		t.Fatal("cache miss")
	}
	_, f, _ = c.start("c", now)
	c.finish("c", f, decision{source: "c"}, now.Add(time.Minute))
	if _, f, leader := c.start("b", now); f == nil || !leader {
		t.Fatal("LRU not evicted")
	}
	if _, f, leader := c.start("a", now.Add(time.Minute)); f == nil || !leader {
		t.Fatal("TTL not expired at boundary")
	}
}
