package abuseipdb_traefik_bouncer

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func newTestBouncer(t *testing.T, c *Config, ctx context.Context, upstream http.HandlerFunc) (*bouncer, *httptest.Server) {
	t.Helper()
	s := httptest.NewServer(upstream)
	t.Cleanup(s.Close)
	h, err := New(ctx, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(204) }), c, "test")
	if err != nil {
		t.Fatal(err)
	}
	b := h.(*bouncer)
	b.client.endpoint = s.URL
	t.Cleanup(func() { b.client.http.CloseIdleConnections() })
	return b, s
}

func serve(b *bouncer, ip string) *httptest.ResponseRecorder {
	r := httptest.NewRequest("POST", "/private?secret=value", strings.NewReader("untouched body"))
	r.RemoteAddr = ip
	w := httptest.NewRecorder()
	b.ServeHTTP(w, r)
	return w
}

func TestStaticPaths(t *testing.T) {
	c := testConfig()
	c.AllowCIDRs = []string{"203.0.113.1/32"}
	c.DenyCIDRs = []string{"203.0.113.0/24"}
	b, _ := newTestBouncer(t, c, context.Background(), func(w http.ResponseWriter, r *http.Request) { t.Error("unexpected API call") })
	for _, tc := range []struct {
		ip     string
		status int
		source string
	}{
		{"203.0.113.1:80", 204, ""}, {"203.0.113.2:80", 403, "deny-cidr"}, {"10.0.0.1:80", 204, ""}, {"[::1]:80", 204, ""}, {"bad", 204, ""},
	} {
		w := serve(b, tc.ip)
		if w.Code != tc.status || w.Header().Get("X-AbuseIPDB-Source") != tc.source {
			t.Fatalf("%s: %d %v", tc.ip, w.Code, w.Header())
		}
	}
	b.config.FailClosed = true
	if w := serve(b, "bad"); w.Code != 403 {
		t.Fatal(w.Code)
	}
}

func TestLiveVerdictsAndTTL(t *testing.T) {
	for _, score := range []int{0, 100} {
		t.Run(fmt.Sprint(score), func(t *testing.T) {
			c := testConfig()
			c.CacheTTL = "15ms"
			c.BlockTTL = "15ms"
			c.ResponseStatus = 451
			var calls int32
			b, _ := newTestBouncer(t, c, context.Background(), func(w http.ResponseWriter, r *http.Request) {
				atomic.AddInt32(&calls, 1)
				apiFixture(w, "8.8.8.8", score)
			})
			w := serve(b, "8.8.8.8:80")
			want := 204
			if score == 100 {
				want = 451
			}
			if w.Code != want {
				t.Fatal(w.Code, w.Body.String())
			}
			if score == 100 && (w.Header().Get("X-AbuseIPDB-Score") != "100" || w.Header().Get("X-AbuseIPDB-Decision") != "deny" || strings.Contains(w.Body.String(), c.APIKey)) {
				t.Fatal(w.Header())
			}
			serve(b, "8.8.8.8:80")
			if atomic.LoadInt32(&calls) != 1 {
				t.Fatal("cache miss")
			}
			time.Sleep(25 * time.Millisecond)
			serve(b, "8.8.8.8:80")
			if atomic.LoadInt32(&calls) != 2 {
				t.Fatal("TTL did not expire")
			}
		})
	}
}

func TestFailurePolicyAndErrorTTL(t *testing.T) {
	for _, closed := range []bool{false, true} {
		t.Run(fmt.Sprint(closed), func(t *testing.T) {
			c := testConfig()
			c.FailClosed = closed
			c.MaxRetries = 0
			c.ErrorTTL = "15ms"
			var calls int32
			b, _ := newTestBouncer(t, c, context.Background(), func(w http.ResponseWriter, r *http.Request) {
				atomic.AddInt32(&calls, 1)
				w.WriteHeader(403)
				fmt.Fprint(w, c.APIKey)
			})
			want := 204
			if closed {
				want = 403
			}
			if w := serve(b, "8.8.8.8:80"); w.Code != want || strings.Contains(w.Body.String(), c.APIKey) {
				t.Fatal(w)
			}
			serve(b, "8.8.8.8:80")
			if atomic.LoadInt32(&calls) != 1 {
				t.Fatal("error not cached")
			}
			time.Sleep(25 * time.Millisecond)
			serve(b, "8.8.8.8:80")
			if atomic.LoadInt32(&calls) != 2 {
				t.Fatal("error TTL did not expire")
			}
		})
	}
}

func TestConcurrentSingleflight(t *testing.T) {
	c := testConfig()
	var mu sync.Mutex
	calls := make(map[string]int)
	b, _ := newTestBouncer(t, c, context.Background(), func(w http.ResponseWriter, r *http.Request) {
		ip := r.URL.Query().Get("ipAddress")
		mu.Lock()
		calls[ip]++
		mu.Unlock()
		time.Sleep(20 * time.Millisecond)
		apiFixture(w, ip, 100)
	})
	var wg sync.WaitGroup
	for i := 0; i < 200; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			ip := fmt.Sprintf("8.8.8.%d", i%10+1)
			if w := serve(b, ip+":80"); w.Code != 403 {
				t.Errorf("status %d", w.Code)
			}
		}(i)
	}
	wg.Wait()
	mu.Lock()
	defer mu.Unlock()
	if len(calls) != 10 {
		t.Fatal(calls)
	}
	for ip, n := range calls {
		if n != 1 {
			t.Errorf("%s: %d upstream calls", ip, n)
		}
	}
}

func TestCanceledWaiterDoesNotCancelSharedLookup(t *testing.T) {
	started := make(chan struct{})
	release := make(chan struct{})
	b, _ := newTestBouncer(t, testConfig(), context.Background(), func(w http.ResponseWriter, r *http.Request) { close(started); <-release; apiFixture(w, "8.8.8.8", 100) })
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan decision, 1)
	go func() { done <- b.lookup(ctx, "8.8.8.8") }()
	<-started
	cancel()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("waiter did not cancel")
	}
	close(release)
	if d := b.lookup(context.Background(), "8.8.8.8"); !d.blocked || d.source != "check" {
		t.Fatal(d)
	}
}

func TestInstanceCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	started := make(chan struct{})
	stopped := make(chan struct{})
	b, _ := newTestBouncer(t, testConfig(), ctx, func(w http.ResponseWriter, r *http.Request) { close(started); <-r.Context().Done(); close(stopped) })
	done := make(chan struct{})
	go func() { b.lookup(context.Background(), "8.8.8.8"); close(done) }()
	<-started
	cancel()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("instance did not cancel")
	}
	select {
	case <-stopped:
	case <-time.After(time.Second):
		t.Fatal("API request not canceled")
	}
}

func TestCategoryRequestsVerboseAndPreservesBody(t *testing.T) {
	c := testConfig()
	c.BlockCategories = []int{18}
	b, _ := newTestBouncer(t, c, context.Background(), func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("verbose") != "true" {
			t.Error("category filter needs reports")
		}
		apiFixture(w, "8.8.8.8", 100)
	})
	b.next = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		buf := make([]byte, 32)
		n, _ := r.Body.Read(buf)
		if string(buf[:n]) != "untouched body" {
			t.Error("body changed")
		}
		w.WriteHeader(204)
	})
	if w := serve(b, "8.8.8.8:80"); w.Code != 204 {
		t.Fatal(w.Code)
	}
}
