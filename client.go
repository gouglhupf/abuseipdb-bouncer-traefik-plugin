package abuseipdb_bouncer_traefik_plugin

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"
)

const checkEndpoint = "https://api.abuseipdb.com/api/v2/check"
const maxCheckBody = 4 * 1024 * 1024

type checkResult struct {
	IPAddress            string `json:"ipAddress"`
	AbuseConfidenceScore int    `json:"abuseConfidenceScore"`
	IsWhitelisted        bool   `json:"isWhitelisted"`
	CountryCode          string `json:"countryCode"`
	TotalReports         int    `json:"totalReports"`
	Reports              []struct {
		Categories []int `json:"categories"`
	} `json:"reports"`
}

type apiClient struct {
	http     *http.Client
	endpoint string
	key      string
	maxAge   int
	verbose  bool
	retries  int
	mu       sync.Mutex
	cooldown time.Time
}

func newAPIClient(c *Config) *apiClient {
	// A shared per-instance transport reuses connections without changing global HTTP state.
	dialer := &net.Dialer{Timeout: 5 * time.Second, KeepAlive: 30 * time.Second}
	transport := &http.Transport{
		Proxy: http.ProxyFromEnvironment,
		// An explicit closure avoids Yaegi's bound-method typing limitation.
		DialContext: func(ctx context.Context, network, address string) (net.Conn, error) {
			return dialer.DialContext(ctx, network, address)
		},
		MaxIdleConns: 16, MaxIdleConnsPerHost: 8, IdleConnTimeout: 90 * time.Second,
		TLSHandshakeTimeout: 5 * time.Second, ForceAttemptHTTP2: true,
	}
	return &apiClient{
		http:     &http.Client{Transport: transport, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }},
		endpoint: checkEndpoint, key: c.APIKey, maxAge: c.MaxAgeInDays,
		verbose: c.Verbose || len(c.BlockCategories) > 0, retries: c.MaxRetries,
	}
}

func retryAfter(value string, now time.Time) time.Duration {
	if seconds, err := strconv.ParseInt(strings.TrimSpace(value), 10, 32); err == nil && seconds >= 0 {
		return time.Duration(seconds) * time.Second
	}
	if at, err := http.ParseTime(value); err == nil && at.After(now) {
		return at.Sub(now)
	}
	return time.Minute
}

func (a *apiClient) check(ctx context.Context, ip string) (checkResult, error) {
	var zero checkResult
	u, err := url.Parse(a.endpoint)
	if err != nil {
		return zero, fmt.Errorf("invalid API endpoint")
	}
	query := u.Query()
	query.Set("ipAddress", ip)
	query.Set("maxAgeInDays", strconv.Itoa(a.maxAge))
	if a.verbose {
		query.Set("verbose", "true")
	}
	u.RawQuery = query.Encode()
	for attempt := 0; attempt <= a.retries; attempt++ {
		a.mu.Lock()
		wait := time.Until(a.cooldown)
		a.mu.Unlock()
		if wait > 0 {
			return zero, fmt.Errorf("API rate limited")
		}
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
		if err != nil {
			return zero, fmt.Errorf("cannot create API request")
		}
		req.Header.Set("Key", a.key)
		req.Header.Set("Accept", "application/json")
		req.Header.Set("User-Agent", "abuseipdb-bouncer-traefik-plugin/0.1")
		resp, requestErr := a.http.Do(req)
		delay := 100 * time.Millisecond
		if requestErr == nil {
			if resp.StatusCode == http.StatusOK {
				result, parseErr := decodeCheck(resp.Body, ip)
				resp.Body.Close()
				return result, parseErr
			}
			status := resp.StatusCode
			if status == http.StatusTooManyRequests {
				delay = retryAfter(resp.Header.Get("Retry-After"), time.Now())
				a.mu.Lock()
				until := time.Now().Add(delay)
				if until.After(a.cooldown) {
					a.cooldown = until
				}
				a.mu.Unlock()
			}
			// Never parse or include error bodies: upstream can echo credentials or PII.
			io.Copy(io.Discard, io.LimitReader(resp.Body, 4096))
			resp.Body.Close()
			if status != http.StatusTooManyRequests && (status < 500 || status > 599) {
				return zero, fmt.Errorf("API returned HTTP %d", status)
			}
			if attempt == a.retries {
				return zero, fmt.Errorf("API returned HTTP %d", status)
			}
		} else if ctx.Err() != nil {
			return zero, fmt.Errorf("API request canceled or timed out")
		}
		if attempt == a.retries {
			break
		}
		// Do not tie up a request when the provider asks for a longer cooldown than its budget.
		if deadline, ok := ctx.Deadline(); ok && time.Until(deadline) <= delay {
			return zero, fmt.Errorf("API retry exceeds request timeout")
		}
		timer := time.NewTimer(delay)
		select {
		case <-ctx.Done():
			timer.Stop()
			return zero, fmt.Errorf("API request canceled or timed out")
		case <-timer.C:
		}
	}
	return zero, fmt.Errorf("API request failed")
}

func decodeCheck(body io.Reader, requestedIP string) (checkResult, error) {
	var zero checkResult
	data, err := io.ReadAll(io.LimitReader(body, maxCheckBody+1))
	if err != nil || len(data) > maxCheckBody {
		return zero, fmt.Errorf("cannot read API response or response too large")
	}
	// Pointers distinguish missing data/score from a legitimate zero score.
	var envelope struct {
		// Do not embed an unexported struct: Yaegi's reflected JSON type loses
		// promoted fields even though compiled Go decodes them correctly.
		Data *struct {
			IPAddress     string `json:"ipAddress"`
			Score         *int   `json:"abuseConfidenceScore"`
			IsWhitelisted bool   `json:"isWhitelisted"`
			CountryCode   string `json:"countryCode"`
			TotalReports  int    `json:"totalReports"`
			Reports       []struct {
				Categories []int `json:"categories"`
			} `json:"reports"`
		} `json:"data"`
	}
	if json.Unmarshal(data, &envelope) != nil || envelope.Data == nil || envelope.Data.Score == nil {
		return zero, fmt.Errorf("invalid API response")
	}
	wire := envelope.Data
	result := checkResult{
		IPAddress: wire.IPAddress, AbuseConfidenceScore: *wire.Score,
		IsWhitelisted: wire.IsWhitelisted, CountryCode: wire.CountryCode,
		TotalReports: wire.TotalReports, Reports: wire.Reports,
	}
	ip := net.ParseIP(result.IPAddress)
	if ip == nil || !ip.Equal(net.ParseIP(requestedIP)) || result.AbuseConfidenceScore < 0 || result.AbuseConfidenceScore > 100 {
		return zero, fmt.Errorf("invalid API response data")
	}
	return result, nil
}
