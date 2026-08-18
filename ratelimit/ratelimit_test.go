package ratelimit

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strconv"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// clock is a deterministic, race-safe clock so that refill behavior can be
// tested without sleeping.
type clock struct {
	mu sync.Mutex
	t  time.Time
}

func newClock() *clock { return &clock{t: time.Unix(1_700_000_000, 0)} }

func (c *clock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.t
}

func (c *clock) Advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.t = c.t.Add(d)
}

// failingStore always reports a backend outage.
type failingStore struct{ err error }

func (s failingStore) Take(context.Context, string, Config, time.Time) (Result, error) {
	return Result{}, s.err
}
func (s failingStore) Close() error { return nil }

func okHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
}

func request(remoteAddr string) *http.Request {
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	r.RemoteAddr = remoteAddr
	return r
}

func TestConfigNormalized(t *testing.T) {
	nan := func() float64 { var z float64; return z / z }() //nolint:staticcheck // deliberate NaN

	tests := []struct {
		name          string
		in            Config
		wantBurst     int
		wantPerSecond float64
	}{
		{"valid passes through", Config{Burst: 10, PerSecond: 2}, 10, 2},
		{"zero burst clamps to one", Config{Burst: 0, PerSecond: 1}, 1, 1},
		{"negative burst clamps to one", Config{Burst: -5, PerSecond: 1}, 1, 1},
		{"negative rate becomes never-refill", Config{Burst: 3, PerSecond: -1}, 3, 0},
		{"NaN rate becomes never-refill", Config{Burst: 3, PerSecond: nan}, 3, 0},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := tc.in.normalized()
			if got.Burst != tc.wantBurst || got.PerSecond != tc.wantPerSecond {
				t.Errorf("normalized() = %+v, want burst %d rate %v", got, tc.wantBurst, tc.wantPerSecond)
			}
		})
	}
}

func TestMemoryStoreTokenBucket(t *testing.T) {
	ctx := context.Background()
	cfg := Config{Burst: 3, PerSecond: 1}
	c := newClock()
	s := NewMemoryStore()
	t.Cleanup(func() { _ = s.Close() })

	// The burst is spendable back to back.
	for i := range 3 {
		res, err := s.Take(ctx, "k", cfg, c.Now())
		if err != nil {
			t.Fatalf("take %d: %v", i, err)
		}
		if !res.Allowed {
			t.Fatalf("take %d denied within burst", i)
		}
		if want := 2 - i; res.Remaining != want {
			t.Errorf("take %d: remaining = %d, want %d", i, res.Remaining, want)
		}
	}

	// The next one is denied and reports a usable wait.
	res, err := s.Take(ctx, "k", cfg, c.Now())
	if err != nil {
		t.Fatal(err)
	}
	if res.Allowed {
		t.Fatal("request past the burst was allowed")
	}
	if res.RetryAfter <= 0 || res.RetryAfter > time.Second {
		t.Errorf("RetryAfter = %v, want (0s, 1s]", res.RetryAfter)
	}

	// Waiting the advertised time makes exactly one token available, not more.
	c.Advance(time.Second)
	if res, err = s.Take(ctx, "k", cfg, c.Now()); err != nil || !res.Allowed {
		t.Fatalf("after refill: allowed=%v err=%v", res.Allowed, err)
	}
	if res, err = s.Take(ctx, "k", cfg, c.Now()); err != nil || res.Allowed {
		t.Fatalf("second request after a single token refilled: allowed=%v err=%v", res.Allowed, err)
	}
}

// TestMemoryStoreNoFixedWindowBoundaryBurst is the reason for choosing a token
// bucket: a fixed-window counter would allow 2*burst requests across a window
// boundary. Spending the burst, waiting a full "window", and spending it again
// must take the full refill time, not one instant.
func TestMemoryStoreNoDoubleRateAcrossBoundary(t *testing.T) {
	ctx := context.Background()
	cfg := Config{Burst: 5, PerSecond: 5} // a fixed window would be 1s wide
	c := newClock()
	s := NewMemoryStore()
	t.Cleanup(func() { _ = s.Close() })

	allowed := 0
	// Drain the bucket at t=0.
	for range 5 {
		res, _ := s.Take(ctx, "k", cfg, c.Now())
		if res.Allowed {
			allowed++
		}
	}
	// Step to just past a nominal window boundary and try to drain it again.
	c.Advance(time.Second - time.Millisecond)
	for range 5 {
		res, _ := s.Take(ctx, "k", cfg, c.Now())
		if res.Allowed {
			allowed++
		}
	}
	// Over ~1s at 5/s with a burst of 5, at most 10 could be allowed only if the
	// second window reset the counter. The bucket refills continuously, so ~4
	// extra tokens have accrued.
	if allowed > 9 {
		t.Errorf("allowed %d requests across the boundary; a token bucket must not permit a full second burst", allowed)
	}
	if allowed < 5 {
		t.Errorf("allowed %d requests, want at least the burst of 5", allowed)
	}
}

func TestMemoryStoreKeysAreIndependent(t *testing.T) {
	ctx := context.Background()
	cfg := Config{Burst: 1, PerSecond: 1}
	c := newClock()
	s := NewMemoryStore()
	t.Cleanup(func() { _ = s.Close() })

	for _, key := range []string{"a", "b", "c"} {
		res, err := s.Take(ctx, key, cfg, c.Now())
		if err != nil || !res.Allowed {
			t.Fatalf("key %q: allowed=%v err=%v", key, res.Allowed, err)
		}
	}
	res, _ := s.Take(ctx, "a", cfg, c.Now())
	if res.Allowed {
		t.Error("key \"a\" was refilled by traffic on other keys")
	}
}

// TestMemoryStoreConcurrentTakeIsAtomic exercises the race the Store contract
// forbids: without atomic read-modify-write, concurrent requests each observe
// the same pre-decrement state and all get admitted.
func TestMemoryStoreConcurrentTakeIsAtomic(t *testing.T) {
	ctx := context.Background()
	const burst = 50
	cfg := Config{Burst: burst, PerSecond: 0} // no refill: the count must be exact
	c := newClock()
	s := NewMemoryStore()
	t.Cleanup(func() { _ = s.Close() })

	var allowed atomic.Int64
	var wg sync.WaitGroup
	for range burst * 8 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if res, err := s.Take(ctx, "shared", cfg, c.Now()); err == nil && res.Allowed {
				allowed.Add(1)
			}
		}()
	}
	wg.Wait()

	if got := allowed.Load(); got != burst {
		t.Errorf("allowed %d concurrent requests, want exactly %d", got, burst)
	}
}

// TestMemoryStoreBoundedKeys covers the memory-exhaustion vector: an attacker
// minting unlimited distinct keys must not grow the store without bound.
func TestMemoryStoreBoundedKeys(t *testing.T) {
	ctx := context.Background()
	cfg := Config{Burst: 1, PerSecond: 1}
	c := newClock()
	s := NewMemoryStore(WithMaxKeys(100))
	t.Cleanup(func() { _ = s.Close() })

	for i := range 10_000 {
		if _, err := s.Take(ctx, "attacker-"+strconv.Itoa(i), cfg, c.Now()); err != nil {
			t.Fatal(err)
		}
	}
	if got := s.Len(); got > 100 {
		t.Errorf("tracked keys = %d, want at most 100", got)
	}
}

// TestMemoryStoreDoesNotForgetUnrefilledBuckets is the counterpart to eviction:
// idle expiry must never hand a throttled client a fresh allowance early.
func TestMemoryStoreDoesNotForgetUnrefilledBuckets(t *testing.T) {
	ctx := context.Background()
	// Refilling this bucket takes 100s, far longer than the 1s idle TTL.
	cfg := Config{Burst: 10, PerSecond: 0.1}
	c := newClock()
	s := NewMemoryStore(WithIdleTTL(time.Second))
	t.Cleanup(func() { _ = s.Close() })

	for range 10 {
		if res, _ := s.Take(ctx, "victim", cfg, c.Now()); !res.Allowed {
			t.Fatal("denied within the burst")
		}
	}
	// Past the TTL, but nowhere near a full refill.
	c.Advance(5 * time.Second)
	if res, _ := s.Take(ctx, "victim", cfg, c.Now()); res.Allowed {
		t.Error("bucket was discarded before it refilled: the limit can be bypassed by idling")
	}

	// Once fully refilled, forgetting it is equivalent to keeping it.
	c.Advance(200 * time.Second)
	if res, _ := s.Take(ctx, "victim", cfg, c.Now()); !res.Allowed {
		t.Error("fully refilled bucket denied")
	}
}

func TestMemoryStoreClockGoingBackwardsGrantsNothing(t *testing.T) {
	ctx := context.Background()
	cfg := Config{Burst: 2, PerSecond: 1}
	c := newClock()
	s := NewMemoryStore()
	t.Cleanup(func() { _ = s.Close() })

	for range 2 {
		_, _ = s.Take(ctx, "k", cfg, c.Now())
	}
	// An NTP step backwards must not credit tokens.
	c.Advance(-time.Hour)
	if res, _ := s.Take(ctx, "k", cfg, c.Now()); res.Allowed {
		t.Error("a backwards clock refilled the bucket")
	}
}

func TestMemoryStoreClosed(t *testing.T) {
	s := NewMemoryStore()
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	if err := s.Close(); err != nil {
		t.Fatalf("second Close: %v", err)
	}
	if _, err := s.Take(context.Background(), "k", Config{Burst: 1, PerSecond: 1}, time.Now()); !errors.Is(err, ErrClosed) {
		t.Errorf("Take after Close: err = %v, want ErrClosed", err)
	}
}

func TestMemoryStoreCancelledContext(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	s := NewMemoryStore()
	t.Cleanup(func() { _ = s.Close() })

	if _, err := s.Take(ctx, "k", Config{Burst: 1, PerSecond: 1}, time.Now()); !errors.Is(err, context.Canceled) {
		t.Errorf("err = %v, want context.Canceled", err)
	}
	if s.Len() != 0 {
		t.Error("a cancelled request created bucket state")
	}
}

func TestRemoteAddrKey(t *testing.T) {
	tests := []struct {
		name    string
		addr    string
		want    string
		wantErr bool
	}{
		{"ipv4 with port", "203.0.113.7:54321", "203.0.113.7", false},
		{"ipv6 with port", "[2001:db8::1]:54321", "2001:db8::1", false},
		{"bare ipv4", "203.0.113.7", "203.0.113.7", false},
		{"bare bracketed ipv6", "[2001:db8::1]", "2001:db8::1", false},
		{"empty is an error, not a shared bucket", "", "", true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := RemoteAddrKey(request(tc.addr))
			if tc.wantErr {
				if !errors.Is(err, ErrNoKey) {
					t.Fatalf("err = %v, want ErrNoKey", err)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if got != tc.want {
				t.Errorf("key = %q, want %q", got, tc.want)
			}
		})
	}
}

// TestDefaultKeyIgnoresForwardedHeaders is the spoofing attack case: a client
// that sets X-Forwarded-For per request must not get a fresh bucket per request.
func TestDefaultKeyIgnoresForwardedHeaders(t *testing.T) {
	c := newClock()
	l := New(2, 0, withClock(c.Now))
	t.Cleanup(func() { _ = l.Close() })
	h := l.Middleware(okHandler())

	statuses := make([]int, 0, 5)
	for i := range 5 {
		r := request("198.51.100.9:1234")
		// Every request claims a different origin.
		r.Header.Set("X-Forwarded-For", "10.0.0."+strconv.Itoa(i))
		r.Header.Set("X-Real-IP", "10.0.1."+strconv.Itoa(i))
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, r)
		statuses = append(statuses, rec.Code)
	}

	want := []int{200, 200, 429, 429, 429}
	for i := range want {
		if statuses[i] != want[i] {
			t.Fatalf("statuses = %v, want %v (spoofed forwarded headers bypassed the limit)", statuses, want)
		}
	}
}

func TestMiddlewareDenialResponse(t *testing.T) {
	c := newClock()
	l := New(1, 1, withClock(c.Now))
	t.Cleanup(func() { _ = l.Close() })
	h := l.Middleware(okHandler())

	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, request("203.0.113.1:1"))
	if rec.Code != http.StatusOK {
		t.Fatalf("first request: status = %d", rec.Code)
	}

	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, request("203.0.113.1:1"))
	if rec.Code != http.StatusTooManyRequests {
		t.Fatalf("second request: status = %d, want 429", rec.Code)
	}
	if got := rec.Header().Get("Retry-After"); got != "1" {
		t.Errorf("Retry-After = %q, want %q", got, "1")
	}
	for _, key := range []string{"X-RateLimit-Limit", "X-RateLimit-Remaining", "RateLimit-Limit", "RateLimit-Remaining"} {
		if rec.Header().Get(key) == "" {
			t.Errorf("header %s missing", key)
		}
	}
	if got := rec.Header().Get("RateLimit-Remaining"); got != "0" {
		t.Errorf("RateLimit-Remaining = %q, want 0", got)
	}
}

func TestHeaderModes(t *testing.T) {
	legacy := []string{"X-RateLimit-Limit", "X-RateLimit-Remaining", "X-RateLimit-Reset"}
	standard := []string{"RateLimit-Limit", "RateLimit-Remaining", "RateLimit-Reset"}

	tests := []struct {
		name    string
		mode    HeaderMode
		present []string
		absent  []string
	}{
		{"both by default", HeaderBoth, append(append([]string{}, legacy...), standard...), nil},
		{"legacy only", HeaderLegacy, legacy, standard},
		{"standard only", HeaderStandard, standard, legacy},
		{"none", HeaderNone, nil, append(append([]string{}, legacy...), standard...)},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			l := New(5, 1, WithHeaders(tc.mode))
			t.Cleanup(func() { _ = l.Close() })
			rec := httptest.NewRecorder()
			l.Middleware(okHandler()).ServeHTTP(rec, request("203.0.113.2:1"))

			for _, k := range tc.present {
				if rec.Header().Get(k) == "" {
					t.Errorf("header %s missing", k)
				}
			}
			for _, k := range tc.absent {
				if v := rec.Header().Get(k); v != "" {
					t.Errorf("header %s = %q, want absent", k, v)
				}
			}
		})
	}
}

func TestFailureModes(t *testing.T) {
	outage := errors.New("redis: connection refused")

	tests := []struct {
		name       string
		mode       FailureMode
		wantStatus int
		wantServed bool
	}{
		{"fail closed is the default and rejects", FailClosed, http.StatusServiceUnavailable, false},
		{"fail open admits", FailOpen, http.StatusOK, true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			var reported error
			served := false
			l := New(10, 1,
				WithStore(failingStore{err: outage}),
				WithFailureMode(tc.mode),
				WithOnError(func(err error) { reported = err }),
			)
			h := l.Middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				served = true
			}))

			rec := httptest.NewRecorder()
			h.ServeHTTP(rec, request("203.0.113.3:1"))

			if rec.Code != tc.wantStatus {
				t.Errorf("status = %d, want %d", rec.Code, tc.wantStatus)
			}
			if served != tc.wantServed {
				t.Errorf("inner handler served = %v, want %v", served, tc.wantServed)
			}
			if !errors.Is(reported, outage) {
				t.Errorf("OnError got %v, want %v; a backend outage must be observable", reported, outage)
			}
		})
	}
}

// TestStoreOutageIsNotA429 covers the audit finding that an outage answered
// with 429 is indistinguishable from real throttling.
func TestStoreOutageIsNotA429(t *testing.T) {
	l := New(10, 1, WithStore(failingStore{err: errors.New("down")}))
	rec := httptest.NewRecorder()
	l.Middleware(okHandler()).ServeHTTP(rec, request("203.0.113.4:1"))
	if rec.Code == http.StatusTooManyRequests {
		t.Error("store outage answered with 429; it must be distinguishable from a genuine denial")
	}
}

func TestUnidentifiableClientIsNotBucketedTogether(t *testing.T) {
	var reported error
	l := New(10, 1,
		WithKeyFunc(func(*http.Request) (string, error) { return "", nil }),
		WithOnError(func(err error) { reported = err }),
	)
	t.Cleanup(func() { _ = l.Close() })

	served := false
	rec := httptest.NewRecorder()
	l.Middleware(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { served = true })).
		ServeHTTP(rec, request("203.0.113.5:1"))

	if served {
		t.Error("request with no derivable key was served under the default fail-closed policy")
	}
	if !errors.Is(reported, ErrNoKey) {
		t.Errorf("OnError got %v, want ErrNoKey", reported)
	}
}

func TestKeyFuncErrorFailsClosed(t *testing.T) {
	untrusted := fmt.Errorf("%w: peer is not the trusted proxy", ErrNoKey)
	l := New(10, 1, WithKeyFunc(func(*http.Request) (string, error) { return "", untrusted }))
	t.Cleanup(func() { _ = l.Close() })

	rec := httptest.NewRecorder()
	l.Middleware(okHandler()).ServeHTTP(rec, request("203.0.113.6:1"))
	if rec.Code == http.StatusOK {
		t.Error("a KeyFunc that refused to identify the client was served anyway")
	}
}

func TestCustomHandlers(t *testing.T) {
	c := newClock()
	l := New(1, 1,
		withClock(c.Now),
		WithDeniedHandler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusTeapot)
		})),
	)
	t.Cleanup(func() { _ = l.Close() })
	h := l.Middleware(okHandler())

	h.ServeHTTP(httptest.NewRecorder(), request("203.0.113.7:1"))
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, request("203.0.113.7:1"))

	if rec.Code != http.StatusTeapot {
		t.Errorf("status = %d, want %d", rec.Code, http.StatusTeapot)
	}
	// Headers are still set for a custom handler to reuse.
	if rec.Header().Get("Retry-After") == "" {
		t.Error("Retry-After missing for the custom denied handler")
	}
}

func TestNilOptionsAndNilStoreAreIgnored(t *testing.T) {
	l := New(1, 1, nil, WithStore(nil), WithKeyFunc(nil), WithDeniedHandler(nil), WithStoreErrorHandler(nil))
	t.Cleanup(func() { _ = l.Close() })

	rec := httptest.NewRecorder()
	l.Middleware(okHandler()).ServeHTTP(rec, request("203.0.113.8:1"))
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	rec = httptest.NewRecorder()
	l.Middleware(okHandler()).ServeHTTP(rec, request("203.0.113.8:1"))
	if rec.Code != http.StatusTooManyRequests {
		t.Error("a nil store option disabled rate limiting")
	}
}

func TestCloseOnlyClosesOwnedStores(t *testing.T) {
	shared := NewMemoryStore()
	l := New(1, 1, WithStore(shared))
	if err := l.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := shared.Take(context.Background(), "k", Config{Burst: 1, PerSecond: 1}, time.Now()); err != nil {
		t.Errorf("closing the limiter closed a store it does not own: %v", err)
	}

	owned := New(1, 1)
	if err := owned.Close(); err != nil {
		t.Fatal(err)
	}
	rec := httptest.NewRecorder()
	owned.Middleware(okHandler()).ServeHTTP(rec, request("203.0.113.9:1"))
	if rec.Code == http.StatusOK {
		t.Error("requests were served after the limiter's own store was closed")
	}
}

func TestRetryAfterSeconds(t *testing.T) {
	tests := []struct {
		in   time.Duration
		want int
	}{
		{0, 0},
		{-time.Second, 0},
		{time.Nanosecond, 1}, // never advertise 0 when there is a wait
		{900 * time.Millisecond, 1},
		{time.Second, 1},
		{1500 * time.Millisecond, 2}, // round up, never into another rejection
		{90 * time.Second, 90},
	}
	for _, tc := range tests {
		if got := retryAfterSeconds(tc.in); got != tc.want {
			t.Errorf("retryAfterSeconds(%v) = %d, want %d", tc.in, got, tc.want)
		}
	}
}

func TestZeroRateNeverRefills(t *testing.T) {
	ctx := context.Background()
	cfg := Config{Burst: 1, PerSecond: 0}
	s := NewMemoryStore()
	t.Cleanup(func() { _ = s.Close() })
	now := time.Unix(0, 0)

	if res, _ := s.Take(ctx, "k", cfg, now); !res.Allowed {
		t.Fatal("first request denied")
	}
	if res, _ := s.Take(ctx, "k", cfg, now.Add(365*24*time.Hour)); res.Allowed {
		t.Error("a zero rate refilled; misconfiguration must fail closed")
	}
}
