// Package abuseipdb_traefik_bouncer implements a cache-backed AbuseIPDB middleware for Traefik.
package abuseipdb_traefik_bouncer

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"os"
	"strconv"
	"time"
)

type bouncer struct {
	next                                  http.Handler
	ctx                                   context.Context
	config                                Config
	allow, deny, trusted                  []*net.IPNet
	client                                *apiClient
	cache                                 *lookupCache
	cacheTTL, blockTTL, errorTTL, timeout time.Duration
}

// New constructs a middleware instance. It performs no network I/O at startup.
func New(ctx context.Context, next http.Handler, config *Config, name string) (http.Handler, error) {
	if err := config.Validate(); err != nil {
		return nil, err
	}
	// Copy slices so caller mutations after New cannot race with request processing.
	c := *config
	c.AllowCIDRs = append([]string(nil), config.AllowCIDRs...)
	c.DenyCIDRs = append([]string(nil), config.DenyCIDRs...)
	c.TrustedProxies = append([]string(nil), config.TrustedProxies...)
	c.BlockCategories = append([]int(nil), config.BlockCategories...)
	c.AllowCountries = append([]string(nil), config.AllowCountries...)
	c.DenyCountries = append([]string(nil), config.DenyCountries...)
	b := &bouncer{next: next, ctx: ctx, config: c,
		allow: parseNetworks(c.AllowCIDRs), deny: parseNetworks(c.DenyCIDRs), trusted: parseNetworks(c.TrustedProxies),
		client: newAPIClient(&c), cache: newLookupCache(c.CacheSize),
	}
	b.cacheTTL, _ = time.ParseDuration(c.CacheTTL)
	b.blockTTL, _ = time.ParseDuration(c.BlockTTL)
	b.errorTTL, _ = time.ParseDuration(c.ErrorTTL)
	b.timeout, _ = time.ParseDuration(c.RequestTimeout)
	if c.LogDecision {
		fmt.Fprintln(os.Stdout, "abuseipdb: hello; live check middleware ready")
		if c.UseBlacklist {
			fmt.Fprintln(os.Stdout, "abuseipdb: blacklist snapshots are deferred to M3; using live checks with cache")
		}
	}
	return b, nil
}

func (b *bouncer) fallback() decision { return decision{blocked: b.config.FailClosed, source: "error"} }

func (b *bouncer) lookup(ctx context.Context, ip string) decision {
	d, f, leader := b.cache.start(ip, time.Now())
	if f == nil {
		return d
	}
	if leader {
		// One canceled downstream request must not cancel the lookup for all its waiters.
		go func() {
			lookupCtx, cancel := context.WithTimeout(b.ctx, b.timeout)
			defer cancel()
			result, err := b.client.check(lookupCtx, ip)
			ttl := b.cacheTTL
			value := b.fallback()
			if err != nil {
				if b.config.LogDecision {
					// Client errors are deliberately sanitized; never log raw HTTP errors or bodies.
					fmt.Fprintf(os.Stderr, "abuseipdb: ip=%s lookup=%s\n", ip, err.Error())
				}
				ttl = b.errorTTL
			} else {
				value = evaluate(&b.config, result)
				if value.blocked {
					ttl = b.blockTTL
				}
			}
			b.cache.finish(ip, f, value, time.Now().Add(ttl))
		}()
	}
	select {
	case <-ctx.Done():
		return b.fallback()
	case <-b.ctx.Done():
		return b.fallback()
	case <-f.done:
		return f.value
	}
}

func (b *bouncer) ServeHTTP(rw http.ResponseWriter, req *http.Request) {
	ip, err := resolveIP(req, b.trusted)
	d := b.fallback()
	ipText := "invalid"
	if err == nil {
		ipText = ip.String()
		switch {
		case containsIP(b.allow, ip):
			d = decision{source: "allow-cidr"}
		case containsIP(b.deny, ip):
			d = decision{blocked: true, source: "deny-cidr"}
		case b.config.SkipPrivateRanges && nonPublic(ip):
			d = decision{source: "private"}
		default:
			d = b.lookup(req.Context(), ipText)
		}
	}
	verdict := "allow"
	if d.blocked {
		verdict = "deny"
	}
	if b.config.LogDecision {
		fmt.Fprintf(os.Stdout, "abuseipdb: ip=%s decision=%s source=%s\n", ipText, verdict, d.source)
	}
	if !d.blocked {
		b.next.ServeHTTP(rw, req)
		return
	}
	rw.Header().Set("X-AbuseIPDB-Decision", verdict)
	rw.Header().Set("X-AbuseIPDB-Source", d.source)
	if d.hasScore {
		rw.Header().Set("X-AbuseIPDB-Score", strconv.Itoa(d.score))
	}
	http.Error(rw, "Forbidden", b.config.ResponseStatus)
}
