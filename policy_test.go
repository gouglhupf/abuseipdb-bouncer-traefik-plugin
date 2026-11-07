package abuseipdb_traefik_bouncer

import "testing"

func TestPolicy(t *testing.T) {
	for _, tc := range []struct {
		name        string
		score       int
		white       bool
		country     string
		categories  []int
		allow, deny []string
		block       []int
		want        bool
	}{
		{name: "clean", score: 0},
		{name: "below", score: 89},
		{name: "boundary", score: 90, want: true},
		{name: "high", score: 100, want: true},
		{name: "whitelisted", score: 100, white: true},
		{name: "allow country", score: 100, country: "DE", allow: []string{"de"}},
		{name: "deny country", country: "US", deny: []string{"us"}, want: true},
		{name: "allow wins", country: "US", allow: []string{"US"}, deny: []string{"US"}},
		{name: "whitelist wins", white: true, country: "US", deny: []string{"US"}},
		{name: "category match", score: 100, categories: []int{14, 18}, block: []int{18}, want: true},
		{name: "category miss", score: 100, categories: []int{14}, block: []int{18}},
		{name: "category missing", score: 100, block: []int{18}},
		{name: "category low score", score: 50, categories: []int{18}, block: []int{18}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c := testConfig()
			c.AllowCountries = tc.allow
			c.DenyCountries = tc.deny
			c.BlockCategories = tc.block
			r := checkResult{AbuseConfidenceScore: tc.score, IsWhitelisted: tc.white, CountryCode: tc.country}
			if tc.categories != nil {
				r.Reports = append(r.Reports, struct {
					Categories []int `json:"categories"`
				}{tc.categories})
			}
			if d := evaluate(c, r); d.blocked != tc.want || !d.hasScore || d.score != tc.score {
				t.Fatalf("got %+v", d)
			}
		})
	}
}
