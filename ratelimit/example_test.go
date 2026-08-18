package ratelimit_test

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"time"

	"github.com/JonasBorgesLM/moat/ratelimit"
)

func ExampleNew() {
	// A burst of 3 requests. The refill rate is deliberately glacial here so
	// that the output is deterministic no matter how the test machine is
	// scheduled -- an example that depends on wall-clock timing is a flaky
	// test, and a flaky test teaches people to ignore red CI.
	limiter := ratelimit.New(3, 0.0001)
	defer limiter.Close()

	handler := limiter.Middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintln(w, "ok")
	}))

	// The fourth request from the same address is rejected.
	var codes []int
	for range 4 {
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		req.RemoteAddr = "203.0.113.10:12345"
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)
		codes = append(codes, rec.Code)
	}

	fmt.Println(codes)
	// Output: [200 200 200 429]
}

// ExampleWithKeyFunc shows the only safe way to use a forwarded header: verify
// that the immediate peer is a proxy you control, and only then trust what it
// appended. Reading X-Forwarded-For without that check makes the limiter a
// no-op, because the client chooses its own value.
func ExampleWithKeyFunc() {
	// The addresses of your own load balancers.
	trustedProxies := []net.IP{net.ParseIP("10.0.0.1")}

	isTrusted := func(addr string) bool {
		host, _, err := net.SplitHostPort(addr)
		if err != nil {
			host = addr
		}
		ip := net.ParseIP(host)
		for _, p := range trustedProxies {
			if ip != nil && ip.Equal(p) {
				return true
			}
		}
		return false
	}

	keyFunc := func(r *http.Request) (string, error) {
		if !isTrusted(r.RemoteAddr) {
			// Not our proxy: the forwarded header is unverified input. Refuse
			// rather than falling back to a shared bucket, which one attacker
			// could drain on everyone else's behalf.
			return "", fmt.Errorf("%w: peer %q is not a trusted proxy", ratelimit.ErrNoKey, r.RemoteAddr)
		}
		// Take the right-most entry: the one our own proxy appended. Everything
		// to its left was supplied by the client.
		xff := r.Header.Values("X-Forwarded-For")
		if len(xff) == 0 {
			return "", ratelimit.ErrNoKey
		}
		last := xff[len(xff)-1]
		for i := len(last) - 1; i >= 0; i-- {
			if last[i] == ',' {
				return trimSpace(last[i+1:]), nil
			}
		}
		return trimSpace(last), nil
	}

	limiter := ratelimit.New(20, 5, ratelimit.WithKeyFunc(keyFunc))
	defer limiter.Close()

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.RemoteAddr = "10.0.0.1:4444"
	req.Header.Set("X-Forwarded-For", "198.51.100.7, 203.0.113.9")

	key, err := keyFunc(req)
	fmt.Println(key, err)
	// Output: 203.0.113.9 <nil>
}

func trimSpace(s string) string {
	for len(s) > 0 && (s[0] == ' ' || s[0] == '\t') {
		s = s[1:]
	}
	for len(s) > 0 && (s[len(s)-1] == ' ' || s[len(s)-1] == '\t') {
		s = s[:len(s)-1]
	}
	return s
}

// ExampleWithOnError shows how a backend outage becomes visible. The library
// never logs; without a hook, a fail-closed limiter in front of a dead store
// rejects everything with no signal to operators.
func ExampleWithOnError() {
	limiter := ratelimit.New(20, 5,
		ratelimit.WithOnError(func(err error) {
			// Route into your own logger and metrics. Runs on the request path,
			// so it must not block.
			_ = err
		}),
		// Availability matters more than enforcement on this endpoint.
		ratelimit.WithFailureMode(ratelimit.FailOpen),
	)
	defer limiter.Close()

	fmt.Println(limiter.Config().Burst)
	// Output: 20
}

// ExampleNewMemoryStore configures the store's memory bound explicitly. The cap
// is what keeps an attacker minting unlimited distinct keys from exhausting the
// limiter's own memory.
func ExampleNewMemoryStore() {
	store := ratelimit.NewMemoryStore(
		ratelimit.WithMaxKeys(50_000),
		ratelimit.WithIdleTTL(15*time.Minute),
	)
	defer store.Close()

	limiter := ratelimit.New(20, 5, ratelimit.WithStore(store))
	defer limiter.Close()

	fmt.Println(store.Len())
	// Output: 0
}

// ExampleLimiter_Take applies the same limit outside HTTP — a queue consumer, a
// background job — without a second configuration to keep in sync.
// This example is compile-only: it depends on the wall clock.
func ExampleLimiter_Take() {
	limiter := ratelimit.New(5, 1)
	defer limiter.Close()

	res, err := limiter.Take(context.Background(), "tenant-42")
	if err != nil {
		// The store failed; decide for yourself what that means here — Take
		// applies no failure policy of its own.
		return
	}
	if !res.Allowed {
		time.Sleep(res.RetryAfter)
	}
}
