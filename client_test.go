package abuseipdb_bouncer_traefik_plugin

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func apiFixture(w http.ResponseWriter, ip string, score int) {
	fmt.Fprintf(w, `{"data":{"ipAddress":%q,"abuseConfidenceScore":%d,"isWhitelisted":false,"countryCode":"DE","totalReports":1}}`, ip, score)
}

func TestCheckRequest(t *testing.T) {
	for _, ip := range []string{"8.8.8.8", "2606:4700:4700::1111"} {
		t.Run(ip, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.Method != "GET" || r.URL.Path != "/api/v2/check" || r.URL.Query().Get("ipAddress") != ip || r.URL.Query().Get("maxAgeInDays") != "90" || r.URL.Query().Get("verbose") != "" {
					t.Errorf("bad request: %s", r.URL)
				}
				if r.Header.Get("Key") != "secret-test-key" || r.Header.Get("Accept") != "application/json" || r.Header.Get("User-Agent") == "" || strings.Contains(r.URL.String(), "secret-test-key") {
					t.Error("bad headers or leaked key")
				}
				apiFixture(w, ip, 100)
			}))
			defer server.Close()
			a := newAPIClient(testConfig())
			a.endpoint = server.URL + "/api/v2/check"
			r, err := a.check(context.Background(), ip)
			if err != nil || r.AbuseConfidenceScore != 100 || r.CountryCode != "DE" {
				t.Fatalf("%+v %v", r, err)
			}
		})
	}
}

func TestDecodeFixtures(t *testing.T) {
	for _, tc := range []struct {
		name, body string
		valid      bool
		white      bool
	}{
		{"clean", `{"data":{"ipAddress":"8.8.8.8","abuseConfidenceScore":0,"isWhitelisted":null}}`, true, false},
		{"white", `{"data":{"ipAddress":"8.8.8.8","abuseConfidenceScore":100,"isWhitelisted":true,"reports":[{"categories":[18]}]}}`, true, true},
		{"missing", `{}`, false, false},
		{"null", `{"data":null}`, false, false},
		{"missing score", `{"data":{"ipAddress":"8.8.8.8"}}`, false, false},
		{"wrong ip", `{"data":{"ipAddress":"1.1.1.1","abuseConfidenceScore":10}}`, false, false},
		{"wrong score", `{"data":{"ipAddress":"8.8.8.8","abuseConfidenceScore":101}}`, false, false},
		{"reports shape", `{"data":{"results":[]}}`, false, false},
		{"html", `<html>bad</html>`, false, false},
		{"trailing", `{"data":{}} {}`, false, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r, err := decodeCheck(strings.NewReader(tc.body), "8.8.8.8")
			if (err == nil) != tc.valid || r.IsWhitelisted != tc.white {
				t.Fatalf("%+v %v", r, err)
			}
		})
	}
	if _, err := decodeCheck(io.LimitReader(infiniteReader{}, maxCheckBody+1), "8.8.8.8"); err == nil {
		t.Fatal("oversized body accepted")
	}
}

type infiniteReader struct{}

func (infiniteReader) Read(p []byte) (int, error) {
	for i := range p {
		p[i] = ' '
	}
	return len(p), nil
}

func TestClientFailuresAndRetries(t *testing.T) {
	for _, status := range []int{400, 402, 403, 422, 429, 500, 503} {
		t.Run(fmt.Sprint(status), func(t *testing.T) {
			var calls int32
			s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				atomic.AddInt32(&calls, 1)
				w.Header().Set("Retry-After", "60")
				w.WriteHeader(status)
				fmt.Fprint(w, "secret-test-key")
			}))
			defer s.Close()
			a := newAPIClient(testConfig())
			a.endpoint = s.URL
			ctx, cancel := context.WithTimeout(context.Background(), time.Second)
			defer cancel()
			_, err := a.check(ctx, "8.8.8.8")
			want := int32(1)
			if status >= 500 {
				want = 2
			}
			if err == nil || strings.Contains(err.Error(), "secret-test-key") || atomic.LoadInt32(&calls) != want {
				t.Fatalf("calls=%d err=%v", calls, err)
			}
			if status == 429 {
				a.check(ctx, "1.1.1.1")
				if atomic.LoadInt32(&calls) != 1 {
					t.Fatal("rate limit cooldown ignored")
				}
			}
		})
	}
	t.Run("retry succeeds", func(t *testing.T) {
		var calls int32
		s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if atomic.AddInt32(&calls, 1) == 1 {
				w.WriteHeader(500)
				return
			}
			apiFixture(w, "8.8.8.8", 0)
		}))
		defer s.Close()
		a := newAPIClient(testConfig())
		a.endpoint = s.URL
		if _, err := a.check(context.Background(), "8.8.8.8"); err != nil || calls != 2 {
			t.Fatal(err, calls)
		}
	})
	t.Run("429 retry", func(t *testing.T) {
		var calls int32
		s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if atomic.AddInt32(&calls, 1) == 1 {
				w.Header().Set("Retry-After", "0")
				w.WriteHeader(429)
				return
			}
			apiFixture(w, "8.8.8.8", 0)
		}))
		defer s.Close()
		a := newAPIClient(testConfig())
		a.endpoint = s.URL
		if _, err := a.check(context.Background(), "8.8.8.8"); err != nil || calls != 2 {
			t.Fatal(err, calls)
		}
	})
	t.Run("timeout", func(t *testing.T) {
		s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { <-r.Context().Done() }))
		defer s.Close()
		a := newAPIClient(testConfig())
		a.endpoint = s.URL
		ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
		defer cancel()
		if _, err := a.check(ctx, "8.8.8.8"); err == nil {
			t.Fatal("no timeout")
		}
	})
	t.Run("redirect forbidden", func(t *testing.T) {
		var leaked int32
		target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { atomic.AddInt32(&leaked, 1) }))
		defer target.Close()
		s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { http.Redirect(w, r, target.URL, 302) }))
		defer s.Close()
		a := newAPIClient(testConfig())
		a.endpoint = s.URL
		if _, err := a.check(context.Background(), "8.8.8.8"); err == nil || leaked != 0 {
			t.Fatal("followed redirect")
		}
	})
}

func TestRetryAfter(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	for _, tc := range []struct {
		value string
		want  time.Duration
	}{
		{"10", 10 * time.Second}, {"0", 0}, {now.Add(30 * time.Second).Format(http.TimeFormat), 30 * time.Second}, {"bad", time.Minute}, {"-1", time.Minute},
	} {
		if got := retryAfter(tc.value, now); got != tc.want {
			t.Errorf("%q: %s", tc.value, got)
		}
	}
}
