package cloudflareip

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

const (
	// edges stands in for Cloudflare's answer; the tests' "Cloudflare" peers live in it.
	edges = `{"success":true,"result":{"ipv4_cidrs":["173.245.48.0/20","104.16.0.0/13"],"ipv6_cidrs":["2606:4700::/32"]}}`
	other = `{"success":true,"result":{"ipv4_cidrs":["198.51.100.0/24"],"ipv6_cidrs":["2001:db8::/32"]}}`
)

// api is a fake Cloudflare API whose answer can change mid-test.
type api struct {
	mu     sync.Mutex
	status int
	body   string
	hits   atomic.Int32
	block  chan struct{} // when set, every request waits until it is closed
}

func (a *api) answer(status int, body string) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.status, a.body = status, body
}

// startAPI serves answer from a fake API, with fresh shared ranges pointing at it.
func startAPI(t *testing.T, status int, body string) *api {
	t.Helper()
	a := &api{status: status, body: body}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		a.hits.Add(1)
		if a.block != nil {
			<-a.block
		}
		a.mu.Lock()
		status, body := a.status, a.body
		a.mu.Unlock()
		w.WriteHeader(status)
		fmt.Fprint(w, body)
	}))
	t.Cleanup(srv.Close)
	useAPI(t, srv.URL)
	return a
}

func useAPI(t *testing.T, url string) {
	t.Helper()
	shared = &ranges{}
	old := ipsURL
	ipsURL = url
	t.Cleanup(func() {
		ipsURL = old
		shared = &ranges{}
	})
}

// newMiddleware builds the middleware, which starts the first fetch, and waits for that fetch.
func newMiddleware(t *testing.T, next http.Handler) http.Handler {
	t.Helper()
	h, err := New(context.Background(), next, &Config{RefreshInterval: "24h"}, "test")
	if err != nil {
		t.Fatal(err)
	}
	waitIdle(t)
	return h
}

// seen is what the next handler received.
type seen struct {
	remoteAddr string
	header     http.Header
}

func serve(t *testing.T, req *http.Request) seen {
	t.Helper()
	var got seen
	h := newMiddleware(t, http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		got = seen{remoteAddr: r.RemoteAddr, header: r.Header.Clone()}
	}))
	h.ServeHTTP(httptest.NewRecorder(), req)
	return got
}

func request(remoteAddr string, header map[string]string) *http.Request {
	req := httptest.NewRequest(http.MethodGet, "http://example.com/", nil)
	req.RemoteAddr = remoteAddr
	for k, v := range header {
		req.Header.Set(k, v)
	}
	return req
}

func waitIdle(t *testing.T) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for {
		shared.mu.RLock()
		fetching := shared.fetching
		shared.mu.RUnlock()
		if !fetching {
			return
		}
		if time.Now().After(deadline) {
			t.Fatal("refresh never finished")
		}
		time.Sleep(5 * time.Millisecond)
	}
}

// refreshNow makes a refresh due, runs it and waits for it.
func refreshNow(t *testing.T) {
	t.Helper()
	shared.mu.Lock()
	shared.fetchedAt, shared.retryAt = time.Time{}, time.Time{}
	shared.mu.Unlock()
	shared.refreshIfDue(24 * time.Hour)
	waitIdle(t)
}

func trusted(s string) bool {
	_, contained := shared.lookup(net.ParseIP(s))
	return contained
}

func failures() int {
	shared.mu.RLock()
	defer shared.mu.RUnlock()
	return shared.failures
}

func TestFromCloudflare(t *testing.T) {
	startAPI(t, http.StatusOK, edges)
	tests := []struct {
		name, remoteAddr, visitor, want string
	}{
		{"ipv4", "173.245.48.10:4444", "203.0.113.9", "203.0.113.9:4444"},
		{"ipv6 edge, ipv4 visitor", "[2606:4700::1]:443", "203.0.113.9", "203.0.113.9:443"},
		{"ipv6 visitor", "104.16.0.1:80", "2001:db8::7", "[2001:db8::7]:80"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := serve(t, request(tt.remoteAddr, map[string]string{
				"CF-Connecting-IP": tt.visitor,
				"X-Forwarded-For":  "6.6.6.6, " + tt.visitor,
				"Forwarded":        "for=6.6.6.6",
				"X-Real-Ip":        "6.6.6.6",
			}))
			if got.remoteAddr != tt.want {
				t.Errorf("RemoteAddr = %q, want %q", got.remoteAddr, tt.want)
			}
			if v := got.header.Get("X-Forwarded-For"); v != "" {
				t.Errorf("X-Forwarded-For = %q, want it removed", v)
			}
			if v := got.header.Get("Forwarded"); v != "" {
				t.Errorf("Forwarded = %q, want it removed", v)
			}
			if v := got.header.Get("X-Real-Ip"); v != tt.visitor {
				t.Errorf("X-Real-Ip = %q, want %q", v, tt.visitor)
			}
		})
	}
}

func TestFromCloudflareWithoutVisitor(t *testing.T) {
	startAPI(t, http.StatusOK, edges)
	for _, visitor := range []string{"", "not-an-ip", "203.0.113.9:80", "203.0.113.9, 6.6.6.6"} {
		got := serve(t, request("173.245.48.10:4444", map[string]string{
			"CF-Connecting-IP": visitor,
			"X-Forwarded-For":  "6.6.6.6",
		}))
		if got.remoteAddr != "173.245.48.10:4444" {
			t.Errorf("visitor %q: RemoteAddr = %q, want it untouched", visitor, got.remoteAddr)
		}
		if v := got.header.Get("X-Forwarded-For"); v != "6.6.6.6" {
			t.Errorf("visitor %q: X-Forwarded-For = %q, want it untouched", visitor, v)
		}
	}
}

func TestNotFromCloudflare(t *testing.T) {
	startAPI(t, http.StatusOK, edges)
	for _, remoteAddr := range []string{"198.51.100.4:1234", "[2001:db8::1]:1234", "10.0.1.57:80", "garbage"} {
		got := serve(t, request(remoteAddr, map[string]string{
			"CF-Connecting-IP": "203.0.113.9",
			// A Cloudflare address in the chain must not earn trust: only the TCP peer counts.
			"X-Forwarded-For": "173.245.48.10",
		}))
		if got.remoteAddr != remoteAddr {
			t.Errorf("%s: RemoteAddr = %q, want it untouched", remoteAddr, got.remoteAddr)
		}
		if v := got.header.Get("CF-Connecting-IP"); v != "" {
			t.Errorf("%s: CF-Connecting-IP = %q, want it removed", remoteAddr, v)
		}
		if v := got.header.Get("X-Forwarded-For"); v != "173.245.48.10" {
			t.Errorf("%s: X-Forwarded-For = %q, want it untouched", remoteAddr, v)
		}
	}
}

func TestPassThroughBeforeFirstFetch(t *testing.T) {
	startAPI(t, http.StatusInternalServerError, `{}`)
	for _, remoteAddr := range []string{"173.245.48.10:4444", "198.51.100.4:1234"} {
		got := serve(t, request(remoteAddr, map[string]string{
			"CF-Connecting-IP": "203.0.113.9",
			"X-Forwarded-For":  "6.6.6.6",
		}))
		if got.remoteAddr != remoteAddr {
			t.Errorf("%s: RemoteAddr = %q, want it untouched", remoteAddr, got.remoteAddr)
		}
		if v := got.header.Get("CF-Connecting-IP"); v != "203.0.113.9" {
			t.Errorf("%s: CF-Connecting-IP = %q, want it untouched", remoteAddr, v)
		}
		if v := got.header.Get("X-Forwarded-For"); v != "6.6.6.6" {
			t.Errorf("%s: X-Forwarded-For = %q, want it untouched", remoteAddr, v)
		}
	}
	if n := failures(); n != 1 {
		t.Errorf("failures = %d, want 1", n)
	}
}

func TestNewStartsFetch(t *testing.T) {
	a := startAPI(t, http.StatusOK, edges)
	newMiddleware(t, http.NotFoundHandler())
	if n := a.hits.Load(); n != 1 {
		t.Errorf("API hit %d times, want 1 without any request", n)
	}
	if !trusted("173.245.48.10") {
		t.Error("ranges not loaded")
	}
}

func TestIntervalChangeAppliesOnReload(t *testing.T) {
	a := startAPI(t, http.StatusOK, edges)
	newMiddleware(t, http.NotFoundHandler())

	shared.mu.Lock()
	shared.fetchedAt = time.Now().Add(-2 * time.Minute)
	shared.mu.Unlock()

	// A reload with the same 24h interval doesn't fetch; one with 1m does, straight away.
	newMiddleware(t, http.NotFoundHandler())
	if n := a.hits.Load(); n != 1 {
		t.Errorf("API hit %d times, want 1 with a 24h interval", n)
	}
	if _, err := New(context.Background(), http.NotFoundHandler(), &Config{RefreshInterval: "1m"}, "test"); err != nil {
		t.Fatal(err)
	}
	waitIdle(t)
	if n := a.hits.Load(); n != 2 {
		t.Errorf("API hit %d times, want 2 once the interval drops to 1m", n)
	}
}

func TestNewRejectsBadInterval(t *testing.T) {
	for _, interval := range []string{"", "soon", "-1h", "0", "30s"} {
		if _, err := New(context.Background(), http.NotFoundHandler(), &Config{RefreshInterval: interval}, "test"); err == nil {
			t.Errorf("refreshInterval %q: want an error", interval)
		}
	}
}

func TestRefresh(t *testing.T) {
	a := startAPI(t, http.StatusOK, edges)
	h := newMiddleware(t, http.NotFoundHandler())

	// Within the interval, requests don't fetch again.
	h.ServeHTTP(httptest.NewRecorder(), request("192.0.2.1:1", nil))
	waitIdle(t)
	if n := a.hits.Load(); n != 1 {
		t.Errorf("API hit %d times, want 1 within the interval", n)
	}

	a.answer(http.StatusOK, other)
	refreshNow(t)
	if !trusted("198.51.100.7") || !trusted("2001:db8::7") {
		t.Error("new ranges are not trusted")
	}
	if trusted("173.245.48.10") {
		t.Error("old range is still trusted after a refresh")
	}
}

func TestRefreshFailureKeepsRanges(t *testing.T) {
	tests := []struct {
		name   string
		status int
		body   string
	}{
		{"server error", http.StatusInternalServerError, `{}`},
		{"not json", http.StatusOK, `<html>`},
		{"unsuccessful", http.StatusOK, `{"success":false,"result":{"ipv4_cidrs":["198.51.100.0/24"],"ipv6_cidrs":["2001:db8::/32"]}}`},
		{"no ipv6", http.StatusOK, `{"success":true,"result":{"ipv4_cidrs":["198.51.100.0/24"],"ipv6_cidrs":[]}}`},
		{"bad range", http.StatusOK, `{"success":true,"result":{"ipv4_cidrs":["198.51.100.0/24","nope"],"ipv6_cidrs":["2001:db8::/32"]}}`},
		{"everything", http.StatusOK, `{"success":true,"result":{"ipv4_cidrs":["0.0.0.0/0"],"ipv6_cidrs":["::/0"]}}`},
		{"every ipv4 as ipv6", http.StatusOK, `{"success":true,"result":{"ipv4_cidrs":["198.51.100.0/24"],"ipv6_cidrs":["::ffff:0:0/96"]}}`},
		{"ipv6 written ipv4", http.StatusOK, `{"success":true,"result":{"ipv4_cidrs":["::ffff:0:0/100"],"ipv6_cidrs":["2001:db8::/32"]}}`},
		{"swapped families", http.StatusOK, `{"success":true,"result":{"ipv4_cidrs":["2001:db8::/32"],"ipv6_cidrs":["198.51.100.0/24"]}}`},
		{"trailing data", http.StatusOK, other + `BROKEN`},
		{"too large", http.StatusOK, other + strings.Repeat(" ", maxAnswer)},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			a := startAPI(t, http.StatusOK, edges)
			h := newMiddleware(t, http.NotFoundHandler())

			a.answer(tt.status, tt.body)
			refreshNow(t)
			if !trusted("173.245.48.10") || trusted("198.51.100.7") || trusted("192.0.2.1") {
				t.Error("ranges changed after a failed refresh")
			}

			// The next attempt waits for the backoff, not the next request.
			h.ServeHTTP(httptest.NewRecorder(), request("192.0.2.1:1", nil))
			waitIdle(t)
			if n := a.hits.Load(); n != 2 {
				t.Errorf("API hit %d times, want 2 before the backoff ends", n)
			}
		})
	}
}

func TestRefreshUnreachable(t *testing.T) {
	useAPI(t, "http://127.0.0.1:1")
	newMiddleware(t, http.NotFoundHandler())
	if loaded, _ := shared.lookup(net.ParseIP("173.245.48.10")); loaded {
		t.Error("ranges loaded without any answer from the API")
	}
	if n := failures(); n != 1 {
		t.Errorf("failures = %d, want 1", n)
	}
}

func TestRefreshRunsOnce(t *testing.T) {
	a := startAPI(t, http.StatusOK, edges)
	a.block = make(chan struct{})

	h, err := New(context.Background(), http.NotFoundHandler(), &Config{RefreshInterval: "24h"}, "test")
	if err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	for i := 0; i < 50; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			h.ServeHTTP(httptest.NewRecorder(), request("173.245.48.10:1", map[string]string{"CF-Connecting-IP": "203.0.113.9"}))
		}()
	}
	// Requests don't wait for the fetch: they all finish while the API is still blocked.
	wg.Wait()
	close(a.block)
	waitIdle(t)

	if n := a.hits.Load(); n != 1 {
		t.Errorf("API hit %d times, want 1", n)
	}
}

func TestBackoff(t *testing.T) {
	tests := []struct {
		failures int
		want     time.Duration
	}{
		{1, time.Minute},
		{2, 2 * time.Minute},
		{6, 32 * time.Minute},
		{7, time.Hour},
		{1000, time.Hour},
	}
	for _, tt := range tests {
		if got := backoff(tt.failures); got != tt.want {
			t.Errorf("backoff(%d) = %s, want %s", tt.failures, got, tt.want)
		}
	}
}

func TestBackoffResetsOnSuccess(t *testing.T) {
	a := startAPI(t, http.StatusInternalServerError, `{}`)
	newMiddleware(t, http.NotFoundHandler())

	next := func() time.Duration {
		shared.mu.RLock()
		defer shared.mu.RUnlock()
		return time.Until(shared.retryAt)
	}
	for i, want := range []time.Duration{time.Minute, 2 * time.Minute, 4 * time.Minute} {
		if i > 0 {
			refreshNow(t)
		}
		if n, wait := failures(), next(); n != i+1 || wait > want || wait < want-time.Second {
			t.Errorf("failure %d: failures = %d, next try in %s, want %s", i+1, n, wait, want)
		}
	}

	a.answer(http.StatusOK, edges)
	refreshNow(t)
	shared.mu.RLock()
	retryAt, fetchedAt := shared.retryAt, shared.fetchedAt
	shared.mu.RUnlock()
	if n := failures(); n != 0 || !retryAt.IsZero() || time.Since(fetchedAt) > time.Minute {
		t.Errorf("after success: failures = %d, retryAt = %s, fetchedAt = %s; want a clean slate", n, retryAt, fetchedAt)
	}
	if !trusted("173.245.48.10") {
		t.Error("ranges not trusted after recovering")
	}
}
