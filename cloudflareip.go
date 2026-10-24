// Package cloudflareip is a Traefik middleware that restores the visitor IP of requests proxied by
// Cloudflare. A request is trusted only when the TCP peer is a Cloudflare address; its
// CF-Connecting-IP then becomes the request's remote address, so Traefik forwards exactly one
// X-Forwarded-For entry and later middlewares (rate limits, IP allow lists) see the visitor.
// Requests from anywhere else lose their CF-Connecting-IP and pass through untouched.
//
// Cloudflare's ranges come from its API only. Until a first fetch succeeds the middleware does
// nothing at all, and every failed attempt is logged as an error.
package cloudflareip

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"sync"
	"time"
)

const (
	// retryDelay is the wait after a first failed fetch; it doubles with each further failure,
	// up to maxRetryDelay.
	retryDelay    = time.Minute
	maxRetryDelay = time.Hour
	// minInterval keeps the refresh from hammering Cloudflare's API.
	minInterval = time.Minute
	// maxAnswer bounds the API's answer, which is about 1 KiB.
	maxAnswer = 1 << 20
)

var (
	ipsURL = "https://api.cloudflare.com/client/v4/ips"
	client = &http.Client{Timeout: 10 * time.Second}
)

// Config of the middleware.
type Config struct {
	// RefreshInterval is how often to fetch Cloudflare's ranges, as a Go duration of at least 1m.
	RefreshInterval string `json:"refreshInterval,omitempty"`
}

// CreateConfig returns the default configuration.
func CreateConfig() *Config {
	return &Config{RefreshInterval: "24h"}
}

// CloudflareIP is the middleware.
type CloudflareIP struct {
	next     http.Handler
	interval time.Duration
}

// New builds the middleware and starts fetching the ranges in the background. Traefik builds one
// per router, so the ranges live in shared. New never fails on the network: an error here would
// take down every router using the middleware.
func New(_ context.Context, next http.Handler, config *Config, name string) (http.Handler, error) {
	interval, err := time.ParseDuration(config.RefreshInterval)
	if err != nil || interval < minInterval {
		return nil, fmt.Errorf("%s: refreshInterval must be a duration of at least %s, got %q",
			name, minInterval, config.RefreshInterval)
	}
	shared.refreshIfDue(interval)
	return &CloudflareIP{next: next, interval: interval}, nil
}

func (c *CloudflareIP) ServeHTTP(rw http.ResponseWriter, req *http.Request) {
	shared.refreshIfDue(c.interval)

	peer, port, _ := net.SplitHostPort(req.RemoteAddr)
	loaded, fromCloudflare := shared.lookup(net.ParseIP(peer))
	switch {
	case !loaded:
		// Without Cloudflare's ranges nothing can be told apart: behave as if absent.
	case !fromCloudflare:
		// Only Cloudflare may vouch for a visitor.
		req.Header.Del("CF-Connecting-IP")
	default:
		restoreVisitor(req, port)
	}
	c.next.ServeHTTP(rw, req)
}

// restoreVisitor makes CF-Connecting-IP the remote address of a request from Cloudflare.
func restoreVisitor(req *http.Request, port string) {
	visitor := net.ParseIP(req.Header.Get("CF-Connecting-IP"))
	if visitor == nil {
		return
	}
	// Cloudflare appends to whatever X-Forwarded-For the visitor sent, so drop it: Traefik
	// rebuilds the header from the remote address.
	req.RemoteAddr = net.JoinHostPort(visitor.String(), port)
	req.Header.Del("X-Forwarded-For")
	req.Header.Del("Forwarded")
	req.Header.Set("X-Real-Ip", visitor.String())
}

// ranges are Cloudflare's networks, shared by every instance of the middleware. nets stays empty
// until a fetch succeeds, and then holds the last answer Cloudflare gave.
type ranges struct {
	mu        sync.RWMutex
	nets      []*net.IPNet
	fetchedAt time.Time // last successful fetch
	retryAt   time.Time // earliest next attempt after a failure
	failures  int       // consecutive failed fetches
	fetching  bool
}

var shared = &ranges{}

// lookup reports whether any ranges are loaded, and whether ip is in them.
func (r *ranges) lookup(ip net.IP) (loaded, contained bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	if ip == nil {
		return len(r.nets) > 0, false
	}
	for _, n := range r.nets {
		if n.Contains(ip) {
			return true, true
		}
	}
	return len(r.nets) > 0, false
}

// due reports whether a fetch should start, given the caller's refresh interval. It reads the
// interval at each call, so a changed configuration applies on the next request. Callers hold mu.
func (r *ranges) due(interval time.Duration) bool {
	now := time.Now()
	if r.fetching || now.Before(r.retryAt) {
		return false
	}
	return r.fetchedAt.IsZero() || !now.Before(r.fetchedAt.Add(interval))
}

// refreshIfDue starts a background fetch when one is due. Requests never wait for it, and only
// one runs at a time.
func (r *ranges) refreshIfDue(interval time.Duration) {
	r.mu.RLock()
	due := r.due(interval)
	r.mu.RUnlock()
	if !due {
		return
	}

	r.mu.Lock()
	if !r.due(interval) {
		r.mu.Unlock()
		return
	}
	r.fetching = true
	r.mu.Unlock()

	go r.refresh()
}

func (r *ranges) refresh() {
	nets, err := fetch()

	r.mu.Lock()
	defer r.mu.Unlock()
	r.fetching = false
	if err != nil {
		r.failures++
		wait := backoff(r.failures)
		r.retryAt = time.Now().Add(wait)
		if len(r.nets) == 0 {
			fmt.Fprintf(os.Stderr, "cloudflareip: no Cloudflare ranges yet, requests pass through unchanged; fetch failed (retry in %s): %v\n", wait, err)
		} else {
			fmt.Fprintf(os.Stderr, "cloudflareip: keeping the last %d ranges, refresh failed (retry in %s): %v\n", len(r.nets), wait, err)
		}
		return
	}
	r.nets = nets
	r.fetchedAt = time.Now()
	r.retryAt = time.Time{}
	r.failures = 0
	fmt.Fprintf(os.Stdout, "cloudflareip: refreshed, %d ranges\n", len(nets))
}

// backoff is the wait after the given number of consecutive failures: 1m, 2m, 4m, and so on,
// up to 1h.
func backoff(failures int) time.Duration {
	wait := retryDelay
	for i := 1; i < failures && wait < maxRetryDelay; i++ {
		wait *= 2
	}
	if wait > maxRetryDelay {
		wait = maxRetryDelay
	}
	return wait
}

// fetch returns Cloudflare's current ranges, or an error unless the whole answer looks right.
func fetch() ([]*net.IPNet, error) {
	resp, err := client.Get(ipsURL)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("unexpected status %s", resp.Status)
	}
	data, err := io.ReadAll(io.LimitReader(resp.Body, maxAnswer+1))
	if err != nil {
		return nil, err
	}
	if len(data) > maxAnswer {
		return nil, fmt.Errorf("answer larger than %d bytes", maxAnswer)
	}

	var answer struct {
		Success bool `json:"success"`
		Result  struct {
			IPv4 []string `json:"ipv4_cidrs"`
			IPv6 []string `json:"ipv6_cidrs"`
		} `json:"result"`
	}
	if err := json.Unmarshal(data, &answer); err != nil {
		return nil, err
	}
	if !answer.Success || len(answer.Result.IPv4) == 0 || len(answer.Result.IPv6) == 0 {
		return nil, fmt.Errorf("incomplete answer: success=%t, %d IPv4 and %d IPv6 ranges",
			answer.Success, len(answer.Result.IPv4), len(answer.Result.IPv6))
	}
	v4, err := parseCIDRs(answer.Result.IPv4, true)
	if err != nil {
		return nil, err
	}
	v6, err := parseCIDRs(answer.Result.IPv6, false)
	if err != nil {
		return nil, err
	}
	return append(v4, v6...), nil
}

// parseCIDRs parses ranges of one address family. It refuses ranges wider than /8, and IPv4 ranges
// written as IPv6 (::ffff:0:0/96 contains every IPv4 address), so a bad answer can't trust everyone.
func parseCIDRs(cidrs []string, ipv4 bool) ([]*net.IPNet, error) {
	family := "IPv6"
	if ipv4 {
		family = "IPv4"
	}
	nets := make([]*net.IPNet, 0, len(cidrs))
	for _, s := range cidrs {
		_, n, err := net.ParseCIDR(s)
		if err != nil {
			return nil, err
		}
		ones, bits := n.Mask.Size()
		isIPv4 := bits == 8*net.IPv4len
		if isIPv4 != ipv4 || (!isIPv4 && n.IP.To4() != nil) {
			return nil, fmt.Errorf("range %s is not a plain %s range", s, family)
		}
		if ones < 8 {
			return nil, fmt.Errorf("range %s is too wide", s)
		}
		nets = append(nets, n)
	}
	return nets, nil
}
