//go:build integration

package redisstore_test

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strconv"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/JonasBorgesLM/moat/ratelimit"
	"github.com/JonasBorgesLM/moat/redisstore"
	"github.com/redis/go-redis/v9"
	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/wait"
)

// startRedis brings up a real Redis and returns a client for it, plus a
// function that stops the container so that failure behavior can be tested
// against a genuinely unreachable backend rather than a mock.
//
// A real server is not optional for this suite. The central claim of this
// package — that the token-bucket decision is atomic — is a claim about how
// Redis executes a script, and no fake can substantiate it.
func startRedis(t *testing.T) (client *redis.Client, stop func()) {
	t.Helper()

	ctx := context.Background()
	req := testcontainers.ContainerRequest{
		Image:        "redis:7-alpine",
		ExposedPorts: []string{"6379/tcp"},
		WaitingFor:   wait.ForListeningPort("6379/tcp").WithStartupTimeout(60 * time.Second),
	}
	container, err := testcontainers.GenericContainer(ctx, testcontainers.GenericContainerRequest{
		ContainerRequest: req,
		Started:          true,
	})
	if err != nil {
		t.Skipf("cannot start Redis (is Docker running?): %v", err)
	}

	endpoint, err := container.Endpoint(ctx, "")
	if err != nil {
		t.Fatalf("container endpoint: %v", err)
	}

	client = redis.NewClient(&redis.Options{Addr: endpoint})
	t.Cleanup(func() {
		_ = client.Close()
		_ = testcontainers.TerminateContainer(container)
	})

	if err := client.Ping(ctx).Err(); err != nil {
		t.Fatalf("Redis did not answer a ping: %v", err)
	}

	return client, func() {
		// Stop rather than terminate, so the test controls exactly when the
		// backend becomes unreachable.
		timeout := 5 * time.Second
		_ = container.Stop(context.Background(), &timeout)
	}
}

func newStore(t *testing.T, client *redis.Client, opts ...redisstore.Option) *redisstore.Store {
	t.Helper()
	// A distinct prefix per test keeps concurrent tests from sharing buckets.
	opts = append([]redisstore.Option{redisstore.WithKeyPrefix(t.Name() + ":")}, opts...)
	store, err := redisstore.New(client, opts...)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })
	return store
}

func TestBurstThenBlock(t *testing.T) {
	client, _ := startRedis(t)
	store := newStore(t, client)

	ctx := context.Background()
	cfg := ratelimit.Config{Burst: 5, PerSecond: 1}
	now := time.Now()

	for i := range 5 {
		res, err := store.TakeN(ctx, "client-a", 1, cfg, now)
		if err != nil {
			t.Fatalf("take %d: %v", i, err)
		}
		if !res.Allowed {
			t.Fatalf("take %d denied within the burst", i)
		}
		if want := 4 - i; res.Remaining != want {
			t.Errorf("take %d: remaining = %d, want %d", i, res.Remaining, want)
		}
	}

	res, err := store.TakeN(ctx, "client-a", 1, cfg, now)
	if err != nil {
		t.Fatal(err)
	}
	if res.Allowed {
		t.Error("a request past the burst was allowed")
	}
	if res.RetryAfter <= 0 || res.RetryAfter > time.Second {
		t.Errorf("RetryAfter = %v, want (0s, 1s]", res.RetryAfter)
	}
}

// TestRefill drives time through the now parameter rather than sleeping, which
// is the reason ratelimit.Store takes one.
func TestRefill(t *testing.T) {
	client, _ := startRedis(t)
	store := newStore(t, client)

	ctx := context.Background()
	cfg := ratelimit.Config{Burst: 2, PerSecond: 1}
	start := time.Now()

	for range 2 {
		if res, err := store.TakeN(ctx, "k", 1, cfg, start); err != nil || !res.Allowed {
			t.Fatalf("within burst: allowed=%v err=%v", res.Allowed, err)
		}
	}
	if res, _ := store.TakeN(ctx, "k", 1, cfg, start); res.Allowed {
		t.Fatal("past the burst was allowed")
	}

	// One second later, exactly one token has accrued.
	if res, err := store.TakeN(ctx, "k", 1, cfg, start.Add(time.Second)); err != nil || !res.Allowed {
		t.Errorf("after 1s: allowed=%v err=%v, want allowed", res.Allowed, err)
	}
	if res, _ := store.TakeN(ctx, "k", 1, cfg, start.Add(time.Second)); res.Allowed {
		t.Error("a second token appeared after only one refill period")
	}

	// A clock that moves backwards must not credit anything.
	if res, _ := store.TakeN(ctx, "k", 1, cfg, start.Add(-time.Hour)); res.Allowed {
		t.Error("a backwards clock refilled the bucket")
	}
}

func TestKeysAreIndependent(t *testing.T) {
	client, _ := startRedis(t)
	store := newStore(t, client)

	ctx := context.Background()
	cfg := ratelimit.Config{Burst: 1, PerSecond: 0.01}
	now := time.Now()

	for _, key := range []string{"a", "b", "c"} {
		if res, err := store.TakeN(ctx, key, 1, cfg, now); err != nil || !res.Allowed {
			t.Fatalf("key %q: allowed=%v err=%v", key, res.Allowed, err)
		}
	}
	for _, key := range []string{"a", "b", "c"} {
		if res, _ := store.TakeN(ctx, key, 1, cfg, now); res.Allowed {
			t.Errorf("key %q was refilled by traffic on another key", key)
		}
	}
}

// TestConcurrencyIsAtomic is the test that actually proves the Lua script does
// its job. A read-modify-write split across round trips would let many of
// these goroutines observe the same pre-decrement state and all be admitted.
//
// Capacity is deliberately kept small (single digits) and the goroutine count
// large relative to it, so that a broken, non-atomic implementation has many
// chances to over-admit against very few tokens rather than a few chances
// against many. The assertion is exact -- not "approximately capacity", not
// "at least capacity" -- because a bucket that leaks even one extra token
// under contention is exactly the bug this test exists to catch, and a fuzzy
// assertion would let it through.
//
// This test has been verified to actually fail when the atomicity it checks
// is removed: with the Lua script temporarily replaced by a naive two-round-
// trip HGET-then-HSET (see the commit history for this file -- the naive path
// was never merged), this test reliably reported more than `capacity` allowed
// requests. That confirms the test can catch the bug it is guarding against,
// not merely that it passes today.
func TestConcurrencyIsAtomic(t *testing.T) {
	client, _ := startRedis(t)
	store := newStore(t, client)

	const capacity = 8     // small and single-digit, so a leaked token is easy to see
	const goroutines = 200 // >> capacity: heavy contention on very few tokens

	ctx := context.Background()
	// No refill, so the count is exact rather than approximately right.
	cfg := ratelimit.Config{Burst: capacity, PerSecond: 0}
	now := time.Now()

	var allowed atomic.Int64
	var failures atomic.Int64
	var wg sync.WaitGroup
	start := make(chan struct{})

	for range goroutines {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start // release everything at once, to maximize overlap
			res, err := store.TakeN(ctx, "hot-key", 1, cfg, now)
			if err != nil {
				failures.Add(1)
				return
			}
			if res.Allowed {
				allowed.Add(1)
			}
		}()
	}
	close(start)
	wg.Wait()

	if n := failures.Load(); n > 0 {
		t.Fatalf("%d requests failed against Redis", n)
	}
	if got := allowed.Load(); got != capacity {
		t.Fatalf("allowed %d of %d concurrent requests against a bucket of capacity %d, want exactly %d; the decision is not atomic",
			got, goroutines, capacity, capacity)
	}
}

// TestKeysExpire checks that Redis reclaims idle buckets, which is what
// replaces an in-process janitor.
func TestKeysExpire(t *testing.T) {
	client, _ := startRedis(t)
	store := newStore(t, client, redisstore.WithIdleTTL(time.Second))

	ctx := context.Background()
	cfg := ratelimit.Config{Burst: 3, PerSecond: 10} // refills in 300ms
	if _, err := store.TakeN(ctx, "ephemeral", 1, cfg, time.Now()); err != nil {
		t.Fatal(err)
	}

	key := t.Name() + ":ephemeral"
	ttl, err := client.PTTL(ctx, key).Result()
	if err != nil {
		t.Fatal(err)
	}
	if ttl <= 0 {
		t.Fatalf("PTTL = %v; the bucket has no expiry and would leak", ttl)
	}
	if ttl > 2*time.Second {
		t.Errorf("PTTL = %v, want about 1s", ttl)
	}
}

// TestTTLCoversTheRefillWindow: expiring a bucket before it has refilled would
// hand its client a fresh allowance, which is a bypass rather than a cache miss.
func TestTTLCoversTheRefillWindow(t *testing.T) {
	client, _ := startRedis(t)
	store := newStore(t, client, redisstore.WithIdleTTL(time.Second))

	ctx := context.Background()
	// Refilling takes 100s, far longer than the 1s idle floor.
	cfg := ratelimit.Config{Burst: 100, PerSecond: 1}
	if _, err := store.TakeN(ctx, "slow", 1, cfg, time.Now()); err != nil {
		t.Fatal(err)
	}

	ttl, err := client.PTTL(ctx, t.Name()+":slow").Result()
	if err != nil {
		t.Fatal(err)
	}
	if ttl < 90*time.Second {
		t.Errorf("PTTL = %v, want at least the refill window of 100s", ttl)
	}
}

// TestEvalShaAfterScriptFlush covers the cold-start path against a real server:
// SCRIPT FLUSH invalidates the cached hash, and the store must recover.
func TestEvalShaAfterScriptFlush(t *testing.T) {
	client, _ := startRedis(t)
	store := newStore(t, client)

	ctx := context.Background()
	cfg := ratelimit.Config{Burst: 5, PerSecond: 1}

	if _, err := store.TakeN(ctx, "k", 1, cfg, time.Now()); err != nil {
		t.Fatal(err)
	}
	if err := client.ScriptFlush(ctx).Err(); err != nil {
		t.Fatal(err)
	}
	if _, err := store.TakeN(ctx, "k", 1, cfg, time.Now()); err != nil {
		t.Errorf("Take after SCRIPT FLUSH: %v; the EVAL fallback did not fire", err)
	}
}

// TestFailClosedWhenRedisIsDown is the whole reason ratelimit.Store returns an
// error: an outage must be distinguishable from a denial, and must not silently
// disable the limiter.
//
// It stops the container mid-run -- not a mock, a real backend that becomes
// really unreachable -- and checks three things at
// once: the store returns an error rather than hanging or silently allowing,
// that error surfaces through the real ratelimit middleware as a 503 (not a
// hang, not a 429 indistinguishable from ordinary throttling), and it reaches
// OnError, which is the only way an outage is visible to an operator, since
// this library never logs.
func TestFailClosedWhenRedisIsDown(t *testing.T) {
	const timeout = 500 * time.Millisecond

	client, stop := startRedis(t)
	store := newStore(t, client, redisstore.WithTimeout(timeout))

	var reported atomic.Value
	limiter := ratelimit.New(100, 100,
		ratelimit.WithStore(store),
		ratelimit.WithOnError(func(err error) { reported.Store(err) }),
	)
	t.Cleanup(func() { _ = limiter.Close() })

	handler := limiter.Middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	request := func() *http.Request {
		r := httptest.NewRequest(http.MethodGet, "/", nil)
		r.RemoteAddr = "203.0.113.1:1234"
		return r
	}

	// Healthy: served.
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, request())
	if rec.Code != http.StatusOK {
		t.Fatalf("with Redis up: status = %d, want 200", rec.Code)
	}

	stop()

	// Down: rejected, and the error is surfaced through the hook rather than
	// logged by the library. Timed, so that "returns an error" is distinguished
	// from "eventually returns an error after something else timed out" -- the
	// configured store timeout is what must bound this, not a client default or
	// an OS-level TCP timeout that happens to be generous.
	requestStart := time.Now()
	rec = httptest.NewRecorder()
	handler.ServeHTTP(rec, request())
	elapsed := time.Since(requestStart)

	// A generous multiple of the configured timeout: enough slack for
	// scheduling jitter and the container-stop teardown itself, but an order
	// of magnitude below what an actual hang would look like. A stopped
	// container usually refuses the connection immediately rather than making
	// the client wait out the full timeout, so this is not a tight race against
	// the deadline -- it exists to catch the failure mode where the store
	// blocks instead of erroring at all.
	if max := 5 * timeout; elapsed > max {
		t.Errorf("request took %v with Redis down, want at most %v (the configured store timeout is %v): the store hung instead of erroring", elapsed, max, timeout)
	}

	if rec.Code == http.StatusOK {
		t.Error("requests were served with Redis unreachable; the limiter failed open")
	}
	if rec.Code == http.StatusTooManyRequests {
		t.Error("an outage was answered with 429, which is indistinguishable from real throttling")
	}
	if rec.Code != http.StatusServiceUnavailable {
		t.Errorf("status = %d, want 503", rec.Code)
	}

	err, _ := reported.Load().(error)
	if err == nil {
		t.Fatal("the outage was not reported to OnError; operators would have no signal")
	}
	if errors.Is(err, ratelimit.ErrNoKey) {
		t.Errorf("reported error = %v, want a backend failure", err)
	}
}

// TestFailOpenWhenRedisIsDown covers the opt-in trade-off in the same
// conditions, so that the choice is demonstrably real rather than documented.
func TestFailOpenWhenRedisIsDown(t *testing.T) {
	client, stop := startRedis(t)
	store := newStore(t, client, redisstore.WithTimeout(500*time.Millisecond))

	var reported atomic.Value
	limiter := ratelimit.New(100, 100,
		ratelimit.WithStore(store),
		ratelimit.WithFailureMode(ratelimit.FailOpen),
		ratelimit.WithOnError(func(err error) { reported.Store(err) }),
	)
	t.Cleanup(func() { _ = limiter.Close() })

	handler := limiter.Middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	stop()

	r := httptest.NewRequest(http.MethodGet, "/", nil)
	r.RemoteAddr = "203.0.113.2:1234"
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, r)

	if rec.Code != http.StatusOK {
		t.Errorf("status = %d, want 200 under FailOpen", rec.Code)
	}
	if err, _ := reported.Load().(error); err == nil {
		t.Error("failing open must still report the outage")
	}
}

// TestSharedAcrossInstances is the reason this package exists: two independent
// limiters, standing in for two application instances, must enforce one limit.
func TestSharedAcrossInstances(t *testing.T) {
	client, _ := startRedis(t)
	store := newStore(t, client)

	const burst = 4
	newLimiter := func() *ratelimit.Limiter {
		l := ratelimit.New(burst, 0.001, ratelimit.WithStore(store))
		t.Cleanup(func() { _ = l.Close() })
		return l
	}
	a, b := newLimiter(), newLimiter()

	ok := func(l *ratelimit.Limiter) bool {
		res, err := l.Take(context.Background(), "shared-client")
		if err != nil {
			t.Fatal(err)
		}
		return res.Allowed
	}

	allowed := 0
	for i := range burst * 2 {
		limiter := a
		if i%2 == 1 {
			limiter = b
		}
		if ok(limiter) {
			allowed++
		}
	}

	if allowed != burst {
		t.Errorf("allowed %d requests across two instances, 1, want %d; the limit is not shared", allowed, burst)
	}
}

// TestKeyPrefixIsolation checks that two applications sharing one Redis do not
// count each other's traffic.
func TestKeyPrefixIsolation(t *testing.T) {
	client, _ := startRedis(t)

	appA, err := redisstore.New(client, redisstore.WithKeyPrefix("appA:"))
	if err != nil {
		t.Fatal(err)
	}
	appB, err := redisstore.New(client, redisstore.WithKeyPrefix("appB:"))
	if err != nil {
		t.Fatal(err)
	}

	ctx := context.Background()
	cfg := ratelimit.Config{Burst: 1, PerSecond: 0.001}
	now := time.Now()

	if res, _ := appA.TakeN(ctx, "same-key", 1, cfg, now); !res.Allowed {
		t.Fatal("app A's first request was denied")
	}
	if res, _ := appB.TakeN(ctx, "same-key", 1, cfg, now); !res.Allowed {
		t.Error("app B was throttled by app A's traffic; prefixes do not isolate")
	}
}

// TestKeysWithHostileContent confirms a client-controlled key is only ever a
// key name and can never alter what the script does.
func TestKeysWithHostileContent(t *testing.T) {
	client, _ := startRedis(t)
	store := newStore(t, client)

	ctx := context.Background()
	cfg := ratelimit.Config{Burst: 2, PerSecond: 1}
	now := time.Now()

	keys := []string{
		"'; return 1 --",
		`" or 1==1 --`,
		"\r\nFLUSHALL\r\n",
		"key with spaces",
		"unicode-é世界",
		string([]byte{0x00, 0x01, 0xff}),
		"",
	}
	for _, key := range keys {
		t.Run(strconv.Quote(key), func(t *testing.T) {
			res, err := store.TakeN(ctx, key, 1, cfg, now)
			if err != nil {
				t.Fatalf("Take(%q): %v", key, err)
			}
			if !res.Allowed || res.Remaining != 1 {
				t.Errorf("Take(%q) = %+v, want a normal first-request result", key, res)
			}
		})
	}

	// Nothing above may have flushed the database.
	if n, err := client.DBSize(ctx).Result(); err != nil || n == 0 {
		t.Errorf("DBSize = %d (err %v); a crafted key affected the server", n, err)
	}
}

// TestContextCancellation checks that a caller's cancellation is honored rather
// than silently consuming a token.
func TestContextCancellation(t *testing.T) {
	client, _ := startRedis(t)
	store := newStore(t, client)

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	_, err := store.TakeN(ctx, "k", 1, ratelimit.Config{Burst: 5, PerSecond: 1}, time.Now())
	if err == nil {
		t.Fatal("Take succeeded with a cancelled context")
	}
	if !errors.Is(err, context.Canceled) {
		t.Errorf("error = %v, want it to wrap context.Canceled", err)
	}
}

// TestWeightedCost drives the cost argument against a real server, which is the
// only place the Lua arithmetic is actually executed -- the unit tests use a
// fake scripter and can only check that the argument is passed.
func TestWeightedCost(t *testing.T) {
	client, _ := startRedis(t)
	store := newStore(t, client)

	ctx := context.Background()
	cfg := ratelimit.Config{Burst: 10, PerSecond: 1}
	now := time.Now()

	res, err := store.TakeN(ctx, "weighted", 7, cfg, now)
	if err != nil {
		t.Fatal(err)
	}
	if !res.Allowed || res.Remaining != 3 {
		t.Fatalf("TakeN(7) = %+v, want allowed with 3 remaining", res)
	}

	// All or nothing: a cost of 4 against 3 tokens must be refused and must not
	// deduct partially, or the caller has paid for work it was denied.
	res, err = store.TakeN(ctx, "weighted", 4, cfg, now)
	if err != nil {
		t.Fatal(err)
	}
	if res.Allowed {
		t.Fatal("a cost of 4 was allowed with 3 tokens left")
	}
	if res.Remaining != 3 {
		t.Errorf("remaining = %d after a denied call, want 3; the denial deducted", res.Remaining)
	}
	// The advertised retry must cover the whole cost, not one token: a client
	// that comes back then must succeed rather than be rejected again.
	if res.RetryAfter < time.Second {
		t.Errorf("RetryAfter = %v, want at least 1s for the missing token", res.RetryAfter)
	}

	// Exactly the remaining balance succeeds.
	res, err = store.TakeN(ctx, "weighted", 3, cfg, now)
	if err != nil {
		t.Fatal(err)
	}
	if !res.Allowed || res.Remaining != 0 {
		t.Errorf("TakeN(3) = %+v, want allowed with 0 remaining", res)
	}
}

// TestCostAboveBurstIsDeniedNotErrored pins the Store contract: a cost the
// bucket can never hold is a decision, not a malfunction, and it must not drain
// what is there on its way to refusing.
func TestCostAboveBurstIsDeniedNotErrored(t *testing.T) {
	client, _ := startRedis(t)
	store := newStore(t, client)

	ctx := context.Background()
	cfg := ratelimit.Config{Burst: 5, PerSecond: 1}
	now := time.Now()

	res, err := store.TakeN(ctx, "oversized", 6, cfg, now)
	if err != nil {
		t.Fatalf("an impossible cost returned an error rather than a denial: %v", err)
	}
	if res.Allowed {
		t.Error("a cost above Burst was allowed")
	}
	if res.Remaining != 5 {
		t.Errorf("remaining = %d, want 5; the refused call consumed tokens", res.Remaining)
	}
	if full, err := store.TakeN(ctx, "oversized", 5, cfg, now); err != nil || !full.Allowed {
		t.Errorf("the bucket was not left intact: %+v, %v", full, err)
	}
}

// TestCostBelowOneIsClamped pins that a miscomputed weight cannot buy a free
// request through the script.
func TestCostBelowOneIsClamped(t *testing.T) {
	client, _ := startRedis(t)
	store := newStore(t, client)

	ctx := context.Background()
	cfg := ratelimit.Config{Burst: 2, PerSecond: 0}
	now := time.Now()

	for i, n := range []int{0, -5} {
		res, err := store.TakeN(ctx, "clamped", n, cfg, now)
		if err != nil {
			t.Fatal(err)
		}
		if !res.Allowed {
			t.Fatalf("call %d denied on a bucket with tokens left", i)
		}
		if want := 1 - i; res.Remaining != want {
			t.Errorf("call %d: remaining = %d, want %d; the call was free", i, res.Remaining, want)
		}
	}
	if res, _ := store.TakeN(ctx, "clamped", 1, cfg, now); res.Allowed {
		t.Error("the bucket was not drained by two sub-unit calls")
	}
}

// TestWeightedConcurrencyIsAtomic is the weighted version of the atomicity
// property: twenty concurrent calls of cost 5 against a burst of 50 must admit
// exactly ten, never eleven, no matter how the round trips interleave.
func TestWeightedConcurrencyIsAtomic(t *testing.T) {
	client, _ := startRedis(t)
	store := newStore(t, client)

	ctx := context.Background()
	cfg := ratelimit.Config{Burst: 50, PerSecond: 0}
	now := time.Now()

	const goroutines = 20
	var wg sync.WaitGroup
	allowed := make(chan bool, goroutines)

	for range goroutines {
		wg.Add(1)
		go func() {
			defer wg.Done()
			res, err := store.TakeN(ctx, "concurrent-weighted", 5, cfg, now)
			if err != nil {
				allowed <- false
				return
			}
			allowed <- res.Allowed
		}()
	}
	wg.Wait()
	close(allowed)

	granted := 0
	for ok := range allowed {
		if ok {
			granted++
		}
	}
	if granted != 10 {
		t.Errorf("granted = %d, want exactly 10 (50 tokens / cost 5)", granted)
	}
}
