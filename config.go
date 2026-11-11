package abuseipdb_bouncer_traefik_plugin

import (
	"fmt"
	"net"
	"strings"
	"time"
)

// Config is the data-only configuration decoded by Traefik.
type Config struct {
	APIKey            string   `json:"apiKey,omitempty"`
	Threshold         int      `json:"threshold,omitempty"`
	MaxAgeInDays      int      `json:"maxAgeInDays,omitempty"`
	Verbose           bool     `json:"verbose,omitempty"`
	CacheTTL          string   `json:"cacheTTL,omitempty"`
	BlockTTL          string   `json:"blockTTL,omitempty"`
	ErrorTTL          string   `json:"errorTTL,omitempty"`
	CacheSize         int      `json:"cacheSize,omitempty"`
	RequestTimeout    string   `json:"requestTimeout,omitempty"`
	MaxRetries        int      `json:"maxRetries,omitempty"`
	FailClosed        bool     `json:"failClosed,omitempty"`
	AllowCIDRs        []string `json:"allowCIDRs,omitempty"`
	DenyCIDRs         []string `json:"denyCIDRs,omitempty"`
	SkipPrivateRanges bool     `json:"skipPrivateRanges,omitempty"`
	TrustedProxies    []string `json:"trustedProxies,omitempty"`
	BlockCategories   []int    `json:"blockCategories,omitempty"`
	AllowCountries    []string `json:"allowCountries,omitempty"`
	DenyCountries     []string `json:"denyCountries,omitempty"`
	ResponseStatus    int      `json:"responseStatus,omitempty"`
	LogDecision       string   `json:"logDecision,omitempty"`
}

// CreateConfig supplies defaults before Traefik decodes user settings.
func CreateConfig() *Config {
	return &Config{
		Threshold: 90, MaxAgeInDays: 90,
		CacheTTL: "12h", BlockTTL: "1h", ErrorTTL: "1m", CacheSize: 50000,
		RequestTimeout: "1500ms", MaxRetries: 1, SkipPrivateRanges: true,
		ResponseStatus: 403, LogDecision: "all",
	}
}

// Validate returns all configuration errors together, without exposing the API key.
func (c *Config) Validate() error {
	if c == nil {
		return fmt.Errorf("configuration is required")
	}
	var errs []string
	add := func(ok bool, message string) {
		if !ok {
			errs = append(errs, message)
		}
	}
	add(strings.TrimSpace(c.APIKey) != "", "apiKey is required")
	add(!strings.ContainsAny(c.APIKey, "\r\n"), "apiKey must not contain newlines")
	add(c.Threshold >= 0 && c.Threshold <= 100, "threshold must be 0..100")
	add(c.MaxAgeInDays >= 1 && c.MaxAgeInDays <= 365, "maxAgeInDays must be 1..365")
	add(c.CacheSize > 0, "cacheSize must be positive")
	add(c.MaxRetries >= 0 && c.MaxRetries <= 1, "maxRetries must be 0 or 1")
	add(c.ResponseStatus >= 400 && c.ResponseStatus <= 599, "responseStatus must be 400..599")
	add(c.LogDecision == "none" || c.LogDecision == "block" || c.LogDecision == "all", `logDecision must be "none", "block" or "all"`)
	for _, field := range []struct {
		name, value string
		min         time.Duration
	}{
		{"cacheTTL", c.CacheTTL, 1}, {"blockTTL", c.BlockTTL, 1},
		{"errorTTL", c.ErrorTTL, 1}, {"requestTimeout", c.RequestTimeout, 1},
	} {
		d, err := time.ParseDuration(field.value)
		add(err == nil && d >= field.min, field.name+" is invalid or below its minimum")
	}
	for _, field := range []struct {
		name   string
		values []string
	}{
		{"allowCIDRs", c.AllowCIDRs}, {"denyCIDRs", c.DenyCIDRs}, {"trustedProxies", c.TrustedProxies},
	} {
		for _, value := range field.values {
			_, _, err := net.ParseCIDR(value)
			add(err == nil, field.name+" contains an invalid CIDR")
		}
	}
	for _, countries := range [][]string{c.AllowCountries, c.DenyCountries} {
		for _, country := range countries {
			country = strings.ToUpper(country)
			add(len(country) == 2 && country[0] >= 'A' && country[0] <= 'Z' && country[1] >= 'A' && country[1] <= 'Z', "countries must be two-letter codes")
		}
	}
	for _, category := range c.BlockCategories {
		add(category >= 1 && category <= 23, "blockCategories must contain IDs 1..23")
	}
	if len(errs) > 0 {
		return fmt.Errorf("invalid configuration: %s", strings.Join(errs, "; "))
	}
	return nil
}

func parseNetworks(values []string) []*net.IPNet {
	var result []*net.IPNet
	for _, value := range values {
		_, network, err := net.ParseCIDR(value)
		if err == nil {
			result = append(result, network)
		}
	}
	return result
}
