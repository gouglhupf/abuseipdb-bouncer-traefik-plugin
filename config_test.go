package abuseipdb_bouncer_traefik_plugin

import (
	"context"
	"strings"
	"testing"
)

func testConfig() *Config {
	c := CreateConfig()
	c.APIKey = "secret-test-key"
	c.LogDecision = "none"
	return c
}

func TestConfig(t *testing.T) {
	if err := testConfig().Validate(); err != nil {
		t.Fatal(err)
	}
	if err := CreateConfig().Validate(); err == nil {
		t.Fatal("empty key accepted")
	}
	var missing *Config
	if _, err := New(context.Background(), nil, missing, "test"); err == nil {
		t.Fatal("nil config accepted")
	}
	cases := []struct {
		name   string
		mutate func(*Config)
	}{
		{"threshold", func(c *Config) { c.Threshold = 101 }},
		{"age", func(c *Config) { c.MaxAgeInDays = 0 }},
		{"ttl", func(c *Config) { c.CacheTTL = "bad" }},
		{"block ttl", func(c *Config) { c.BlockTTL = "0s" }},
		{"error ttl", func(c *Config) { c.ErrorTTL = "-1s" }},
		{"timeout", func(c *Config) { c.RequestTimeout = "0" }},
		{"cache", func(c *Config) { c.CacheSize = 0 }},
		{"retries", func(c *Config) { c.MaxRetries = 2 }},
		{"status", func(c *Config) { c.ResponseStatus = 200 }},
		{"log decision", func(c *Config) { c.LogDecision = "sometimes" }},
		{"allow", func(c *Config) { c.AllowCIDRs = []string{"bad"} }},
		{"deny", func(c *Config) { c.DenyCIDRs = []string{"bad"} }},
		{"trusted", func(c *Config) { c.TrustedProxies = []string{"1.2.3.4"} }},
		{"country", func(c *Config) { c.AllowCountries = []string{"USA"} }},
		{"category", func(c *Config) { c.BlockCategories = []int{24} }},
		{"header", func(c *Config) { c.APIKey += "\n" }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			c := testConfig()
			tc.mutate(c)
			if err := c.Validate(); err == nil || strings.Contains(err.Error(), c.APIKey) {
				t.Fatalf("unsafe or absent validation: %v", err)
			}
		})
	}
	c := testConfig()
	c.APIKey = ""
	c.Threshold = -1
	c.CacheSize = 0
	if err := c.Validate(); err == nil || !strings.Contains(err.Error(), "apiKey") || !strings.Contains(err.Error(), "threshold") || !strings.Contains(err.Error(), "cacheSize") {
		t.Fatalf("not aggregated: %v", err)
	}
}
