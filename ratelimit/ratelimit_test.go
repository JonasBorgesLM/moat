package ratelimit

import (
	"context"
	"errors"
	"fmt"
	"math/rand/v2"
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

func (s failingStore) TakeN(context.Context, string, int, Config, time.Time) (Result, error) {
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
		res, err := s.TakeN(ctx, "k", 1, cfg, c.Now())
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
	res, err := s.TakeN(ctx, "k", 1, cfg, c.Now())
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
	if res, err = s.TakeN(ctx, "k", 1, cfg, c.Now()); err != nil || !res.Allowed {
		t.Fatalf("after refill: allowed=%v err=%v", res.Allowed, err)
	}
	if res, err = s.TakeN(ctx, "k", 1, cfg, c.Now()); err != nil || res.Allowed {
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
		res, _ := s.TakeN(ctx, "k", 1, cfg, c.Now())
		if res.Allowed {
			allowed++
		}
	}
	// Step to just past a nominal window boundary and try to drain it again.
	c.Advance(time.Second - time.Millisecond)
	for range 5 {
		res, _ := s.TakeN(ctx, "k", 1, cfg, c.Now())
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
		res, err := s.TakeN(ctx, key, 1, cfg, c.Now())
		if err != nil || !res.Allowed {
			t.Fatalf("key %q: allowed=%v err=%v", key, res.Allowed, err)
		}
	}
	res, _ := s.TakeN(ctx, "a", 1, cfg, c.Now())
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
			if res, err := s.TakeN(ctx, "shared", 1, cfg, c.Now()); err == nil && res.Allowed {
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
		if _, err := s.TakeN(ctx, "attacker-"+strconv.Itoa(i), 1, cfg, c.Now()); err != nil {
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
		if res, _ := s.TakeN(ctx, "victim", 1, cfg, c.Now()); !res.Allowed {
			t.Fatal("denied within the burst")
		}
	}
	// Past the TTL, but nowhere near a full refill.
	c.Advance(5 * time.Second)
	if res, _ := s.TakeN(ctx, "victim", 1, cfg, c.Now()); res.Allowed {
		t.Error("bucket was discarded before it refilled: the limit can be bypassed by idling")
	}

	// Once fully refilled, forgetting it is equivalent to keeping it.
	c.Advance(200 * time.Second)
	if res, _ := s.TakeN(ctx, "victim", 1, cfg, c.Now()); !res.Allowed {
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
		_, _ = s.TakeN(ctx, "k", 1, cfg, c.Now())
	}
	// An NTP step backwards must not credit tokens.
	c.Advance(-time.Hour)
	if res, _ := s.TakeN(ctx, "k", 1, cfg, c.Now()); res.Allowed {
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
	if _, err := s.TakeN(context.Background(), "k", 1, Config{Burst: 1, PerSecond: 1}, time.Now()); !errors.Is(err, ErrClosed) {
		t.Errorf("Take after Close: err = %v, want ErrClosed", err)
	}
}

func TestMemoryStoreCancelledContext(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	s := NewMemoryStore()
	t.Cleanup(func() { _ = s.Close() })

	if _, err := s.TakeN(ctx, "k", 1, Config{Burst: 1, PerSecond: 1}, time.Now()); !errors.Is(err, context.Canceled) {
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
	if _, err := shared.TakeN(context.Background(), "k", 1, Config{Burst: 1, PerSecond: 1}, time.Now()); err != nil {
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

	if res, _ := s.TakeN(ctx, "k", 1, cfg, now); !res.Allowed {
		t.Fatal("first request denied")
	}
	if res, _ := s.TakeN(ctx, "k", 1, cfg, now.Add(365*24*time.Hour)); res.Allowed {
		t.Error("a zero rate refilled; misconfiguration must fail closed")
	}
}

var errBackendDown = errors.New("backend down")

// --- Allow / AllowN / TakeN -------------------------------------------------

func TestAllowConsumesAndDenies(t *testing.T) {
	ctx := context.Background()
	l := New(2, 0) // two tokens, never refills
	defer l.Close()

	if !l.Allow(ctx, "acct-1") {
		t.Error("first call denied")
	}
	if !l.Allow(ctx, "acct-1") {
		t.Error("second call denied")
	}
	if l.Allow(ctx, "acct-1") {
		t.Error("third call allowed past a burst of 2")
	}
	// A different key has its own bucket.
	if !l.Allow(ctx, "acct-2") {
		t.Error("a different key was denied")
	}
}

func TestAllowNChargesTheFullCost(t *testing.T) {
	ctx := context.Background()
	l := New(10, 0)
	defer l.Close()

	if !l.AllowN(ctx, "k", 7) {
		t.Fatal("a cost of 7 against a burst of 10 was denied")
	}
	// 3 left: a cost of 4 must be refused, and must not partially deduct.
	if l.AllowN(ctx, "k", 4) {
		t.Error("a cost of 4 was allowed with 3 tokens left")
	}
	if !l.AllowN(ctx, "k", 3) {
		t.Error("a cost of 3 was denied with 3 tokens left; the failed call deducted anyway")
	}
	if l.AllowN(ctx, "k", 1) {
		t.Error("the bucket was not empty after spending all 10")
	}
}

func TestAllowNCostAboveBurstIsAlwaysDenied(t *testing.T) {
	ctx := context.Background()
	l := New(5, 1000) // refills fast, but can never hold more than 5
	defer l.Close()

	if l.AllowN(ctx, "k", 6) {
		t.Error("a cost above Burst was allowed")
	}
	// And it must not have drained the bucket on its way to refusing.
	if !l.AllowN(ctx, "k", 5) {
		t.Error("a denied oversized call consumed tokens")
	}
}

func TestAllowNTreatsSubUnitCostAsOne(t *testing.T) {
	ctx := context.Background()

	// A miscomputed weight must not buy a free request.
	for _, n := range []int{0, -1, -1000} {
		l := New(1, 0)
		if !l.AllowN(ctx, "k", n) {
			t.Errorf("AllowN(n=%d) denied on a full bucket", n)
		}
		if l.AllowN(ctx, "k", n) {
			t.Errorf("AllowN(n=%d) did not consume a token; it is free", n)
		}
		_ = l.Close()
	}
}

func TestTakeNReportsRemainingAndRetry(t *testing.T) {
	ctx := context.Background()
	l := New(10, 1)
	defer l.Close()

	res, err := l.TakeN(ctx, "k", 4)
	if err != nil {
		t.Fatal(err)
	}
	if !res.Allowed || res.Remaining != 6 {
		t.Errorf("TakeN(4) = %+v, want allowed with 6 remaining", res)
	}

	// Denied weighted call: Remaining reports what is actually left, not zero,
	// and RetryAfter covers the whole cost rather than a single token.
	res, err = l.TakeN(ctx, "k", 9)
	if err != nil {
		t.Fatal(err)
	}
	if res.Allowed {
		t.Fatal("a cost of 9 was allowed with 6 tokens left")
	}
	if res.Remaining != 6 {
		t.Errorf("Remaining = %d, want 6; a denial must not report an empty bucket", res.Remaining)
	}
	// Just under 3s: the bucket refills a sliver between the two calls.
	if res.RetryAfter < 2900*time.Millisecond || res.RetryAfter > 3100*time.Millisecond {
		t.Errorf("RetryAfter = %v, want about 3s (3 tokens at 1/s)", res.RetryAfter)
	}
}

// TestTakeIsTakeNOfOne pins that the single-token entry point is a wrapper and
// not a second implementation that could drift.
func TestTakeIsTakeNOfOne(t *testing.T) {
	ctx := context.Background()
	l := New(3, 0)
	defer l.Close()

	a, err := l.Take(ctx, "k")
	if err != nil {
		t.Fatal(err)
	}
	b, err := l.TakeN(ctx, "k", 1)
	if err != nil {
		t.Fatal(err)
	}
	if a.Remaining-b.Remaining != 1 {
		t.Errorf("Take and TakeN(1) disagree: %+v then %+v", a, b)
	}
}

// TestAllowAppliesTheFailurePolicy is the difference between Allow and TakeN:
// Allow resolves a store outage through FailureMode, TakeN hands back the error.
func TestAllowAppliesTheFailurePolicy(t *testing.T) {
	ctx := context.Background()

	t.Run("fail closed denies and reports", func(t *testing.T) {
		var reported error
		l := New(10, 1,
			WithStore(failingStore{err: errBackendDown}),
			WithFailureMode(FailClosed),
			WithOnError(func(err error) { reported = err }),
		)
		defer l.Close()

		if l.Allow(ctx, "k") {
			t.Error("Allow returned true during a store outage under FailClosed")
		}
		if l.AllowN(ctx, "k", 5) {
			t.Error("AllowN returned true during a store outage under FailClosed")
		}
		if reported == nil {
			t.Error("the store error never reached OnError")
		}
	})

	t.Run("fail open admits and still reports", func(t *testing.T) {
		var reported error
		l := New(10, 1,
			WithStore(failingStore{err: errBackendDown}),
			WithFailureMode(FailOpen),
			WithOnError(func(err error) { reported = err }),
		)
		defer l.Close()

		if !l.Allow(ctx, "k") {
			t.Error("Allow returned false during a store outage under FailOpen")
		}
		if reported == nil {
			t.Error("the store error never reached OnError under FailOpen")
		}
	})

	t.Run("TakeN surfaces the error instead", func(t *testing.T) {
		l := New(10, 1, WithStore(failingStore{err: errBackendDown}), WithFailureMode(FailClosed))
		defer l.Close()

		if _, err := l.TakeN(ctx, "k", 2); err == nil {
			t.Error("TakeN swallowed the store error; the caller cannot tell an outage from a denial")
		}
	})
}

// TestMiddlewareAndAllowShareOneBucket is the point of exposing the callable
// API: middleware traffic and in-handler accounting must charge the same
// bucket, not two parallel ones.
func TestMiddlewareAndAllowShareOneBucket(t *testing.T) {
	l := New(2, 0, WithKeyFunc(func(r *http.Request) (string, error) { return "shared", nil }))
	defer l.Close()

	if !l.Allow(context.Background(), "shared") {
		t.Fatal("the first in-handler call was denied")
	}

	ok := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusOK) })
	rec := httptest.NewRecorder()
	l.Middleware(ok).ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("the middleware request was denied: %d", rec.Code)
	}

	// Two tokens are gone; the third attempt must fail through either door.
	rec = httptest.NewRecorder()
	l.Middleware(ok).ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/", nil))
	if rec.Code != http.StatusTooManyRequests {
		t.Errorf("middleware status = %d, want 429; the two APIs are not sharing a bucket", rec.Code)
	}
	if l.Allow(context.Background(), "shared") {
		t.Error("Allow returned true after the bucket was drained through the middleware")
	}
}

// TestFailOpenWritesNoRateLimitHeaders pins the outcome the refactor made
// explicit: when the store is down and the policy is FailOpen there is no
// Result, so publishing a zeroed allowance would tell clients they are
// throttled when in truth no decision was made.
func TestFailOpenWritesNoRateLimitHeaders(t *testing.T) {
	l := New(10, 1, WithStore(failingStore{err: errBackendDown}), WithFailureMode(FailOpen))
	defer l.Close()

	rec := httptest.NewRecorder()
	l.Middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})).ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/", nil))

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	for _, h := range []string{"RateLimit-Limit", "RateLimit-Remaining", "X-RateLimit-Remaining"} {
		if got := rec.Header().Get(h); got != "" {
			t.Errorf("%s = %q, want it unset when no decision was made", h, got)
		}
	}
}

// TestRetryAfterSurvivesHeaderNone pins a promise the HeaderNone doc comment
// makes and nothing was checking: suppressing the rate-limit headers must not
// suppress Retry-After, because a client that has just been rejected still
// needs to know when to come back. Without it a 429 is a dead end and the
// client's only strategy is to keep retrying.
func TestRetryAfterSurvivesHeaderNone(t *testing.T) {
	l := New(1, 1, WithHeaders(HeaderNone))
	defer l.Close()

	// Spend the single token, then get denied.
	l.Middleware(okHandler()).ServeHTTP(httptest.NewRecorder(), request("203.0.113.9:1"))

	rec := httptest.NewRecorder()
	l.Middleware(okHandler()).ServeHTTP(rec, request("203.0.113.9:1"))

	if rec.Code != http.StatusTooManyRequests {
		t.Fatalf("status = %d, want 429", rec.Code)
	}
	if got := rec.Header().Get("Retry-After"); got != "1" {
		t.Errorf("Retry-After = %q, want %q even under HeaderNone", got, "1")
	}
	for _, h := range []string{"RateLimit-Limit", "X-RateLimit-Limit"} {
		if got := rec.Header().Get(h); got != "" {
			t.Errorf("%s = %q, want absent under HeaderNone", h, got)
		}
	}
}

// TestRetryAfterTracksTheRefillRate pins that the value is derived from the
// configured rate rather than being a constant: at 0.5 tokens/sec one token
// takes two seconds, and advertising anything less invites the client back into
// another rejection.
func TestRetryAfterTracksTheRefillRate(t *testing.T) {
	for _, tc := range []struct {
		perSecond float64
		want      string
	}{
		{perSecond: 1, want: "1"},
		{perSecond: 0.5, want: "2"},
		{perSecond: 0.25, want: "4"},
	} {
		l := New(1, tc.perSecond)
		l.Middleware(okHandler()).ServeHTTP(httptest.NewRecorder(), request("203.0.113.10:1"))

		rec := httptest.NewRecorder()
		l.Middleware(okHandler()).ServeHTTP(rec, request("203.0.113.10:1"))
		if got := rec.Header().Get("Retry-After"); got != tc.want {
			t.Errorf("at %v tokens/sec: Retry-After = %q, want %q", tc.perSecond, got, tc.want)
		}
		_ = l.Close()
	}
}

// TestMemoryStoreEvictionSparesExhaustedBuckets pins M-1, the property that
// separates a memory bound from a rate-limit bypass.
//
// A client that has just spent its burst stops making requests, so its bucket
// stops being touched. Under a least-recently-used policy that is exactly what
// nominates it for eviction, and the eviction hands it a fresh full burst — so
// the effective limit stops being PerSecond and becomes the rate at which the
// store turns over. Ordering by refill level inverts that: the exhausted bucket
// is the last thing eligible to go, and it only becomes eligible once it has
// refilled, at which point dropping it grants nothing.
//
// NEGATIVE CONTROL: this test must fail under the old policy. Restore it by
// making fullAtNanos ignore the debt, so that the heap is keyed on the last
// touch instead --
//
//	func fullAtNanos(now time.Time, debt float64, cfg Config) int64 {
//		return now.UnixNano()
//	}
//
// -- which orders buckets by recency and so selects the least recently used one,
// exactly as the container/list tail did, in both eviction and reclaim. The
// victim is then evicted on the first insertion that hits the cap and its
// follow-up request is allowed, failing the assertion below. Verified red.
func TestMemoryStoreEvictionSparesExhaustedBuckets(t *testing.T) {
	ctx := context.Background()
	// A 5s refill window, so a drained bucket stays visibly in debt for the
	// whole test while a bucket that spent one token is nearly full.
	cfg := Config{Burst: 5, PerSecond: 1}
	c := newClock()

	const maxKeys = 4
	s := NewMemoryStore(WithMaxKeys(maxKeys))
	t.Cleanup(func() { _ = s.Close() })

	// The victim exhausts its burst on /login and goes quiet.
	for range cfg.Burst {
		if res, _ := s.TakeN(ctx, "victim", 1, cfg, c.Now()); !res.Allowed {
			t.Fatal("denied within the burst")
		}
	}

	// Eviction pressure: many distinct keys, each spending a single token, so
	// every one of them is more refilled than the victim. The clock advances a
	// little per key so that "least recently used" is unambiguous and the
	// victim is its oldest, most obvious candidate.
	for i := range 200 {
		if _, err := s.TakeN(ctx, "flood-"+strconv.Itoa(i), 1, cfg, c.Now()); err != nil {
			t.Fatal(err)
		}
		c.Advance(time.Millisecond)
		if got := s.Len(); got > maxKeys {
			t.Fatalf("after %d keys, tracked = %d, want at most %d", i+1, got, maxKeys)
		}
	}

	// 200ms of refill is 0.2 tokens: the victim is still throttled unless its
	// bucket was thrown away.
	if res, _ := s.TakeN(ctx, "victim", 1, cfg, c.Now()); res.Allowed {
		t.Error("the victim's exhausted bucket was evicted under key pressure and its limit reset: eviction is granting allowance")
	}
}

// TestMemoryStoreEvictionPrefersTheFullestBucket checks the choice directly
// rather than through its consequence: given a store at capacity holding one
// drained bucket and one nearly-full one, the nearly-full one is what goes.
func TestMemoryStoreEvictionPrefersTheFullestBucket(t *testing.T) {
	ctx := context.Background()
	cfg := Config{Burst: 4, PerSecond: 1}
	c := newClock()
	s := NewMemoryStore(WithMaxKeys(2))
	t.Cleanup(func() { _ = s.Close() })

	for range cfg.Burst { // drained
		_, _ = s.TakeN(ctx, "drained", 1, cfg, c.Now())
	}
	c.Advance(time.Millisecond)
	_, _ = s.TakeN(ctx, "nearly-full", 1, cfg, c.Now()) // 3 of 4 tokens left

	c.Advance(time.Millisecond)
	_, _ = s.TakeN(ctx, "newcomer", 1, cfg, c.Now()) // forces one out

	if s.Len() != 2 {
		t.Fatalf("tracked = %d, want 2", s.Len())
	}
	if _, ok := s.byKey["drained"]; !ok {
		t.Error("the drained bucket was evicted while a fuller one was available")
	}
	if _, ok := s.byKey["nearly-full"]; ok {
		t.Error("the fullest bucket survived; something else was evicted instead")
	}
	// And the newcomer was not the one thrown out: a fresh bucket is at
	// capacity, so a policy that discards the fullest must be stopped from
	// discarding the entry it was just asked to create.
	if _, ok := s.byKey["newcomer"]; !ok {
		t.Error("the newly created bucket evicted itself, leaving its key untracked")
	}
}

// TestMemoryStoreBoundHoldsWhenNoBucketHasRefilled covers the extreme the
// eviction policy cannot make free, and documents the decision taken there.
//
// With a burst of one, every key is drained by the request that creates it, so
// no bucket in the store is ever refilled and there is no cost-free eviction
// available. The memory bound wins anyway: growing the map without limit would
// reinstate the denial-of-service vector the cap exists to close, which is worse
// than the grant. The bucket dropped is still the closest to full.
func TestMemoryStoreBoundHoldsWhenNoBucketHasRefilled(t *testing.T) {
	ctx := context.Background()
	cfg := Config{Burst: 1, PerSecond: 0.01} // a 100s refill window: nothing recovers
	c := newClock()

	const maxKeys = 32
	s := NewMemoryStore(WithMaxKeys(maxKeys))
	t.Cleanup(func() { _ = s.Close() })

	for i := range 5_000 {
		if _, err := s.TakeN(ctx, "k"+strconv.Itoa(i), 1, cfg, c.Now()); err != nil {
			t.Fatal(err)
		}
		if got := s.Len(); got > maxKeys {
			t.Fatalf("after %d keys, tracked = %d, want at most %d", i+1, got, maxKeys)
		}
	}
	if got := s.Len(); got != maxKeys {
		t.Errorf("tracked = %d, want the store held at its cap of %d", got, maxKeys)
	}
}

// TestMemoryStoreReclaimsRefilledBuckets pins the memory-hygiene half: buckets
// that have refilled and gone idle are dropped without waiting for the key cap
// to bind. It is the path that changed structure along with eviction, so it is
// checked on the store's size rather than only through Take's answer.
func TestMemoryStoreReclaimsRefilledBuckets(t *testing.T) {
	ctx := context.Background()
	cfg := Config{Burst: 2, PerSecond: 1} // a 2s refill window
	c := newClock()
	s := NewMemoryStore(WithIdleTTL(time.Second))
	t.Cleanup(func() { _ = s.Close() })

	for i := range 20 {
		_, _ = s.TakeN(ctx, "idle-"+strconv.Itoa(i), 1, cfg, c.Now())
	}
	if s.Len() != 20 {
		t.Fatalf("tracked = %d, want 20", s.Len())
	}

	// Well past both the TTL and the refill window, so every bucket is full and
	// forgetting it grants nothing. One Take drives the reclaim.
	c.Advance(time.Minute)
	_, _ = s.TakeN(ctx, "trigger", 1, cfg, c.Now())
	if got := s.Len(); got != 1 {
		t.Errorf("tracked = %d after reclaim, want only the triggering key", got)
	}
}

// BenchmarkMemoryStoreTakeN measures the hot path at a realistic key count.
// Ordering by refill level costs a heap fix per call where recency ordering
// needed only a list splice, so the difference is the price of the fix.
func BenchmarkMemoryStoreTakeN(b *testing.B) {
	ctx := context.Background()
	cfg := Config{Burst: 100, PerSecond: 100}
	now := time.Now()
	s := NewMemoryStore(WithMaxKeys(DefaultMaxKeys))
	b.Cleanup(func() { _ = s.Close() })

	keys := make([]string, 100_000)
	for i := range keys {
		keys[i] = "client-" + strconv.Itoa(i)
		_, _ = s.TakeN(ctx, keys[i], 1, cfg, now)
	}

	b.ResetTimer()
	for i := 0; b.Loop(); i++ {
		now = now.Add(time.Microsecond)
		_, _ = s.TakeN(ctx, keys[i%len(keys)], 1, cfg, now)
	}
}

// TestRefillHeapMaintainsItsInvariant checks the hand-written heap directly.
//
// The eviction policy is only as good as the claim that h[0] is the least
// fullAt in the store: if the ordering is subtly wrong, eviction quietly goes
// back to picking arbitrary buckets and every test above still passes for the
// wrong reason. So the structure is exercised on its own, with the invariant and
// the recorded indices checked after every operation.
func TestRefillHeapMaintainsItsInvariant(t *testing.T) {
	// #nosec G404 -- a fixed-seed PRNG is the point: the operation sequence must
	// be reproducible so that a failure can be replayed. Nothing here is a key,
	// a token, or otherwise security-sensitive.
	rnd := rand.New(rand.NewPCG(1, 2))
	var h refillHeap
	live := map[*bucket]bool{}

	check := func(step int) {
		t.Helper()
		for i := range h {
			if h[i].index != i {
				t.Fatalf("step %d: h[%d].index = %d", step, i, h[i].index)
			}
			if i > 0 {
				if parent := (i - 1) / 2; h[parent].fullAt > h[i].fullAt {
					t.Fatalf("step %d: heap invariant broken: h[%d]=%d > h[%d]=%d",
						step, parent, h[parent].fullAt, i, h[i].fullAt)
				}
			}
		}
		if len(h) != len(live) {
			t.Fatalf("step %d: heap holds %d, expected %d", step, len(h), len(live))
		}
	}

	for step := range 20_000 {
		switch {
		case len(h) == 0 || rnd.IntN(3) == 0:
			b := &bucket{key: strconv.Itoa(step), fullAt: rnd.Int64N(1_000)}
			h.push(b)
			live[b] = true
		case rnd.IntN(2) == 0:
			// An in-place update, the operation every Take performs.
			i := rnd.IntN(len(h))
			h[i].fullAt = rnd.Int64N(1_000)
			h.fix(i)
		default:
			// popRoot must hand back the true minimum, not merely some element.
			want := h[0].fullAt
			for _, b := range h {
				if b.fullAt < want {
					t.Fatalf("step %d: h[0]=%d is not the minimum (%d present)", step, h[0].fullAt, b.fullAt)
				}
			}
			got := h.popRoot()
			if got.fullAt != want {
				t.Fatalf("step %d: popRoot returned %d, want the root %d", step, got.fullAt, want)
			}
			if got.index != -1 {
				t.Fatalf("step %d: popped bucket kept index %d", step, got.index)
			}
			delete(live, got)
		}
		check(step)
	}
}
