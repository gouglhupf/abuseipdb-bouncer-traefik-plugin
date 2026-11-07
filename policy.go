package abuseipdb_traefik_bouncer

import "strings"

func countryIn(countries []string, country string) bool {
	for _, candidate := range countries {
		if strings.EqualFold(candidate, country) {
			return true
		}
	}
	return false
}

func evaluate(c *Config, result checkResult) decision {
	d := decision{source: "check", score: result.AbuseConfidenceScore, hasScore: true}
	if result.IsWhitelisted || countryIn(c.AllowCountries, result.CountryCode) {
		return d
	}
	if countryIn(c.DenyCountries, result.CountryCode) {
		d.blocked = true
		return d
	}
	if result.AbuseConfidenceScore < c.Threshold {
		return d
	}
	if len(c.BlockCategories) == 0 {
		d.blocked = true
		return d
	}
	for _, report := range result.Reports {
		for _, category := range report.Categories {
			for _, blocked := range c.BlockCategories {
				if category == blocked {
					d.blocked = true
					return d
				}
			}
		}
	}
	return d
}
