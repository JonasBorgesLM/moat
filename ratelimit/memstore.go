package ratelimit

import (
	"container/list"
	"context"
	"math"
	"sync"
	"time"
)

// Default bounds for [MemoryStore]. See [WithMaxKeys] and [WithIdleTTL] for the
// reasoning behind each.
const (
	DefaultMaxKeys = 100_000
	DefaultIdleTTL = 10 * time.Minute
)

// MemoryStore is a bounded in-process [Store].
//
// # Why it is bounded
//
// The obvious implementation, a map from key to bucket, is itself a
// denial-of-service vector: memory grows with the number of distinct keys, and
// with an IP-based key a single host controlling an IPv6 /64 can mint
// effectively unlimited distinct addresses. MemoryStore therefore caps the
// number of tracked buckets and evicts the least recently used entry when the
// cap is reached, in addition to discarding buckets that have been idle long
// enough to be irrelevant.
//
// Eviction is not free of consequences, and the trade-off is stated plainly:
// discarding a bucket gives that client a fresh full allowance. To keep that
// from being a bypass, a bucket is only ever discarded once enough time has
// passed that it would have refilled completely anyway — so evicting it and
// keeping it are equivalent. Under a flood of unique keys the cap can still
// force out a bucket that has not refilled; the entries at the eviction end are
// the least recently used, which under such a flood are the attacker's own
// short-lived keys, but a determined attacker can use the pressure to reset
// another client's bucket. Sizing MaxKeys above your realistic distinct-client
// count is what keeps that theoretical.
//
// # Lifetime
//
// MemoryStore runs no background goroutine. Expired buckets are reclaimed
// during Take, amortized over the calls that follow them. A janitor goroutine
// would be a lifetime hazard for every caller who forgets to Close, and a store
// that leaks goroutines is a poor foundation for a library that is supposed to
// be safe by default.
//
// State is per process. Behind a load balancer with N instances the effective
// limit is N times the configured one; use a shared store when that matters.
//
// MemoryStore is safe for concurrent use. Create it with [NewMemoryStore]; the
// zero value is not usable.
type MemoryStore struct {
	maxKeys int
	idleTTL time.Duration

	mu sync.Mutex
	// order is a recency list, most recently used at the front. Because entries
	// are moved to the front on every Take, the tail is exactly the set of
	// candidates for expiry, which makes reclaiming them O(expired) rather than
	// O(tracked keys).
	order  *list.List
	byKey  map[string]*list.Element
	closed bool
}

// bucket is one client's token-bucket state.
type bucket struct {
	key    string
	tokens float64
	last   time.Time
}

// MemoryOption configures a [MemoryStore].
type MemoryOption func(*MemoryStore)

// NewMemoryStore returns an in-process store bounded by [DefaultMaxKeys] and
// [DefaultIdleTTL] unless overridden.
func NewMemoryStore(opts ...MemoryOption) *MemoryStore {
	s := &MemoryStore{
		maxKeys: DefaultMaxKeys,
		idleTTL: DefaultIdleTTL,
		order:   list.New(),
		byKey:   make(map[string]*list.Element),
	}
	for _, opt := range opts {
		if opt != nil {
			opt(s)
		}
	}
	return s
}

// WithMaxKeys caps how many buckets are tracked at once.
//
// The cap is the store's own memory bound, so set it from the memory you are
// willing to spend rather than from the number of clients you expect: roughly
// 100 bytes per tracked key plus the key itself. Set it comfortably above your
// realistic distinct-client count, because eviction under pressure is what lets
// a flood of unique keys reset a legitimate client's bucket.
//
// Values below 1 are ignored.
func WithMaxKeys(n int) MemoryOption {
	return func(s *MemoryStore) {
		if n >= 1 {
			s.maxKeys = n
		}
	}
}

// WithIdleTTL sets how long an untouched bucket is kept.
//
// The TTL is a floor, not a ceiling: a bucket is never discarded before it
// would have refilled to full, regardless of this setting, because discarding a
// partially refilled bucket hands its client a fresh allowance. Shortening the
// TTL below the refill window therefore saves no memory and creates no bypass —
// it is simply ignored for buckets that are still meaningful.
//
// Values below or equal to zero are ignored.
func WithIdleTTL(d time.Duration) MemoryOption {
	return func(s *MemoryStore) {
		if d > 0 {
			s.idleTTL = d
		}
	}
}

// Take implements [Store].
//
// It is atomic under a mutex: refill, decision and write-back happen without
// another Take on the same key interleaving, so concurrent requests cannot each
// observe the same pre-decrement state and all be admitted.
//
// The supplied now is used as the clock; the store never reads the wall clock
// itself. Because the elapsed time is derived from the stored timestamp, a now
// that moves backwards (an NTP step, a test) refills nothing rather than
// crediting tokens.
func (s *MemoryStore) Take(ctx context.Context, key string, cfg Config, now time.Time) (Result, error) {
	if err := ctx.Err(); err != nil {
		// A cancelled request must not silently consume a token: report the
		// cancellation and let the limiter's failure mode decide.
		return Result{}, err
	}
	cfg = cfg.normalized()

	s.mu.Lock()
	defer s.mu.Unlock()

	if s.closed {
		return Result{}, ErrClosed
	}

	s.reclaim(cfg, now)

	var b *bucket
	if el, ok := s.byKey[key]; ok {
		b = el.Value.(*bucket)
		s.order.MoveToFront(el)
		b.tokens = refill(b.tokens, b.last, now, cfg)
	} else {
		b = &bucket{key: key, tokens: float64(cfg.Burst)}
		s.byKey[key] = s.order.PushFront(b)
		s.evictOverCap()
	}
	b.last = now

	return decide(b, cfg), nil
}

// Close discards all state. Subsequent calls to Take return [ErrClosed] rather
// than silently allowing traffic. It is safe to call more than once.
func (s *MemoryStore) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.closed = true
	s.order.Init()
	s.byKey = make(map[string]*list.Element)
	return nil
}

// Len reports how many buckets are currently tracked. It exists for tests and
// for exporting a gauge; it is not part of the [Store] contract.
func (s *MemoryStore) Len() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.byKey)
}

// reclaim drops buckets from the least-recently-used end that have been idle
// long enough to be indistinguishable from a fresh bucket.
//
// The cutoff is the larger of the configured TTL and the bucket's full refill
// window: dropping a bucket that has not refilled would reset its client's
// allowance, which is a rate-limit bypass.
func (s *MemoryStore) reclaim(cfg Config, now time.Time) {
	cutoff := s.idleTTL
	if w := cfg.refillWindow(); w > cutoff {
		cutoff = w
	}
	for {
		el := s.order.Back()
		if el == nil {
			return
		}
		b := el.Value.(*bucket)
		if now.Sub(b.last) < cutoff {
			return
		}
		s.order.Remove(el)
		delete(s.byKey, b.key)
	}
}

// evictOverCap enforces the memory bound by dropping least-recently-used
// buckets. It runs after an insertion, so it removes at most one entry per call
// in steady state.
func (s *MemoryStore) evictOverCap() {
	for len(s.byKey) > s.maxKeys {
		el := s.order.Back()
		if el == nil {
			return
		}
		b := el.Value.(*bucket)
		s.order.Remove(el)
		delete(s.byKey, b.key)
	}
}

// refill credits the tokens accrued between last and now, capped at the bucket
// capacity. Elapsed time that would overflow the float arithmetic simply fills
// the bucket, which is the same result a very long idle period gives.
func refill(tokens float64, last, now time.Time, cfg Config) float64 {
	elapsed := now.Sub(last).Seconds()
	if elapsed > 0 && cfg.PerSecond > 0 {
		tokens += elapsed * cfg.PerSecond
	}
	capacity := float64(cfg.Burst)
	if tokens > capacity || math.IsNaN(tokens) {
		tokens = capacity
	}
	if tokens < 0 {
		tokens = 0
	}
	return tokens
}

// decide consumes a token if one is available and reports the outcome.
func decide(b *bucket, cfg Config) Result {
	if b.tokens >= 1 {
		b.tokens--
		res := Result{Allowed: true, Remaining: int(b.tokens)}
		if b.tokens < 1 {
			// Allowed, but the next request will have to wait: tell the client
			// when, so it can pace itself instead of retrying into a rejection.
			res.RetryAfter = waitFor(1-b.tokens, cfg)
		}
		return res
	}
	return Result{Allowed: false, Remaining: 0, RetryAfter: waitFor(1-b.tokens, cfg)}
}

// waitFor reports how long it takes to accrue the given number of tokens.
// A bucket that never refills reports the maximum duration rather than
// infinity, so that callers formatting a Retry-After always have a real value.
func waitFor(tokens float64, cfg Config) time.Duration {
	if tokens <= 0 {
		return 0
	}
	if cfg.PerSecond <= 0 {
		return time.Duration(math.MaxInt64)
	}
	secs := tokens / cfg.PerSecond
	if secs > float64(math.MaxInt64/int64(time.Second)) {
		return time.Duration(math.MaxInt64)
	}
	d := time.Duration(secs * float64(time.Second))
	if d < time.Nanosecond {
		return time.Nanosecond
	}
	return d
}
