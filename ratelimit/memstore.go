package ratelimit

import (
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
// number of tracked buckets and discards entries to stay under the cap, in
// addition to reclaiming buckets that have been idle long enough to be
// irrelevant.
//
// # Discarding a bucket is granting an allowance
//
// This is the property the whole design turns on: forgetting a bucket gives its
// client a fresh full burst. So a discarded bucket must be one whose loss grants
// nothing, which means a bucket that had already refilled to capacity — for such
// a bucket, keeping it and forgetting it are the same thing.
//
// The store therefore orders buckets by *how refilled they are* and always
// discards from the most-refilled end, never from the least-recently-used end.
// The distinction is the difference between a bound and a bypass. Recency is
// anti-correlated with safety here: a client that has just exhausted its burst
// stops being able to make requests, so its bucket stops being touched and
// drifts toward the least-recently-used end — an LRU policy therefore selects,
// by construction, the bucket whose loss grants the most. Refill order selects
// the opposite, and an exhausted bucket only becomes a candidate once it has
// refilled, at which point it is free to drop.
//
// Under enough pressure — every tracked bucket still in debt, none refilled —
// something must still go, because the memory bound is not negotiable. The store
// discards the bucket closest to full, which is the smallest grant available.
// See [WithMaxKeys] for what that costs and how to size around it.
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
	// order is a min-heap on bucket.fullAt, so order[0] is always the bucket
	// closest to being refilled: the cheapest one to forget, and the only kind
	// that may be forgotten without granting an allowance.
	order  refillHeap
	byKey  map[string]*bucket
	closed bool
}

// bucket is one client's token-bucket state.
type bucket struct {
	key    string
	tokens float64
	last   time.Time

	// fullAt is the instant this bucket reaches capacity, in Unix nanoseconds,
	// recomputed on every Take from the tokens left and the rate in force. It
	// is the sort key.
	//
	// It is stored rather than derived on demand because it is *static* between
	// Takes, while the token count it stands for is not: tokens grow with the
	// clock, so ordering by tokens would mean re-sorting the whole store on
	// every call. Ordering by fullAt is equivalent — at any instant now, a
	// bucket holds burst-(fullAt-now)*rate tokens, which is decreasing in
	// fullAt — and it only changes when the bucket is touched.
	//
	// It is an integer rather than a time.Time so that ordering two buckets on
	// the heap's hot path is one machine comparison rather than a call into
	// package time.
	fullAt int64

	// index is this bucket's position in the heap, maintained by refillHeap.set
	// so that an updated bucket can be repositioned without searching for it.
	index int
}

// refillHeap is a min-heap of buckets ordered by fullAt, so h[0] is always the
// bucket closest to being refilled.
//
// It is written out rather than driven through container/heap because this is
// the store's hot path: every Take repositions one bucket, and container/heap
// reaches Less and Swap through an interface, so a single Fix at a hundred
// thousand keys costs some thirty-odd calls that cannot be inlined. On
// BenchmarkMemoryStoreTakeN that dispatch cost about 115ns per Take, roughly
// half the total. The algorithm below is the one container/heap implements;
// only the dispatch is gone.
//
// The ordering is not free even so. Against the recency list this replaced,
// which repositioned a bucket with an O(1) splice, that benchmark moved from
// about 67ns to about 125ns per Take at a hundred thousand tracked keys. The
// difference is the O(log n) sift, and it buys the property that eviction
// cannot reset a throttled client — see [MemoryStore].
type refillHeap []*bucket

// set places b at index i and records the position in the bucket, which is what
// lets fix reposition an updated bucket without searching for it.
func (h refillHeap) set(i int, b *bucket) {
	h[i] = b
	b.index = i
}

func (h refillHeap) up(j int) {
	b := h[j]
	for j > 0 {
		parent := (j - 1) / 2
		if h[parent].fullAt <= b.fullAt {
			break
		}
		h.set(j, h[parent])
		j = parent
	}
	h.set(j, b)
}

// down sifts the bucket at i towards the leaves and reports whether it moved.
func (h refillHeap) down(i int) bool {
	start := i
	b := h[i]
	n := len(h)
	for {
		child := 2*i + 1
		if child >= n {
			break
		}
		if right := child + 1; right < n && h[right].fullAt < h[child].fullAt {
			child = right
		}
		if b.fullAt <= h[child].fullAt {
			break
		}
		h.set(i, h[child])
		i = child
	}
	h.set(i, b)
	return i > start
}

func (h *refillHeap) push(b *bucket) {
	*h = append(*h, b)
	h.up(len(*h) - 1)
}

// fix restores the ordering after b.fullAt changed in place. A Take usually
// pushes fullAt later (the bucket just spent tokens), so down is tried first
// and up is only reached when the supplied clock ran backwards.
func (h refillHeap) fix(i int) {
	if !h.down(i) {
		h.up(i)
	}
}

// popRoot removes and returns the most-refilled bucket.
func (h *refillHeap) popRoot() *bucket {
	old := *h
	n := len(old) - 1
	root := old[0]
	if n > 0 {
		old.set(0, old[n])
	}
	old[n] = nil // do not pin the evicted bucket through the backing array
	*h = old[:n]
	if n > 0 {
		_ = h.down(0)
	}
	root.index = -1
	return root
}

// MemoryOption configures a [MemoryStore].
type MemoryOption func(*MemoryStore)

// NewMemoryStore returns an in-process store bounded by [DefaultMaxKeys] and
// [DefaultIdleTTL] unless overridden.
func NewMemoryStore(opts ...MemoryOption) *MemoryStore {
	s := &MemoryStore{
		maxKeys: DefaultMaxKeys,
		idleTTL: DefaultIdleTTL,
		byKey:   make(map[string]*bucket),
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
// 130 bytes per tracked key plus the key itself.
//
// # What the cap costs when it binds
//
// Reaching the cap forces a bucket out, and forgetting a bucket grants its
// client a fresh burst. That is a rate-limit bypass, not a fairness problem: the
// effective limit for the client whose bucket is dropped stops being the rate
// you configured and becomes the rate at which the store turns over. Saying so
// plainly matters, because the two readings call for different sizing — a
// fairness glitch is something you tolerate, and a bypass of the limiter on
// /login is not.
//
// The store keeps that from being reachable in the ordinary case by discarding
// the most-refilled bucket rather than the least recently used one: a bucket
// that has refilled to capacity grants nothing when dropped, so as long as any
// refilled bucket exists, the cap costs exactly nothing. See [MemoryStore].
//
// The residual case is a store in which *every* tracked bucket is still in debt.
// Then the bound wins — the map does not grow past the cap — and the bucket
// closest to full is dropped, which is the smallest grant on offer. Getting
// there means keeping maxKeys distinct clients simultaneously below capacity,
// which costs an attacker maxKeys x PerSecond requests per second sustained,
// every one of them already counted against a bucket. Sizing MaxKeys above your
// realistic distinct-client count keeps it out of reach.
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
// The TTL is a floor, not a ceiling: a bucket is never reclaimed before it would
// have refilled to full, regardless of this setting, because discarding a
// partially refilled bucket hands its client a fresh allowance. Shortening the
// TTL below the refill window therefore saves no memory and creates no bypass —
// it is simply ignored for buckets that are still meaningful.
//
// Reclaiming may lag the TTL by up to one refill window, because buckets are
// ordered by when they refill rather than by when they were last touched. The
// TTL is a memory-hygiene threshold, not a deadline, and lagging it costs a
// bounded amount of memory that the key cap already limits.
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
func (s *MemoryStore) TakeN(ctx context.Context, key string, n int, cfg Config, now time.Time) (Result, error) {
	if err := ctx.Err(); err != nil {
		// A cancelled request must not silently consume a token: report the
		// cancellation and let the limiter's failure mode decide.
		return Result{}, err
	}
	cfg = cfg.normalized()
	n = normalizeCost(n)

	s.mu.Lock()
	defer s.mu.Unlock()

	if s.closed {
		return Result{}, ErrClosed
	}

	s.reclaim(cfg, now)

	b, tracked := s.byKey[key]
	if tracked {
		b.tokens = refill(b.tokens, b.last, now, cfg)
	} else {
		// Room is made before the insertion, not after, so that the bucket
		// being created can never be the one discarded. A brand-new bucket is
		// at capacity and would otherwise sit at the most-refilled end of the
		// heap and evict itself, leaving the key untracked and its next request
		// starting from a full burst again.
		s.makeRoom()
		b = &bucket{key: key, tokens: float64(cfg.Burst)}
	}
	b.last = now

	res := decide(b, cfg, n)

	b.fullAt = fullAtNanos(now, float64(cfg.Burst)-b.tokens, cfg)
	if tracked {
		s.order.fix(b.index)
	} else {
		s.byKey[key] = b
		s.order.push(b)
	}
	return res, nil
}

// Close discards all state. Subsequent calls to Take return [ErrClosed] rather
// than silently allowing traffic. It is safe to call more than once.
func (s *MemoryStore) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.closed = true
	s.order = nil
	s.byKey = make(map[string]*bucket)
	return nil
}

// Len reports how many buckets are currently tracked. It exists for tests and
// for exporting a gauge; it is not part of the [Store] contract.
func (s *MemoryStore) Len() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.byKey)
}

// reclaim drops buckets that have been idle long enough to be indistinguishable
// from a fresh bucket.
//
// The cutoff is the larger of the configured TTL and the bucket's full refill
// window: dropping a bucket that has not refilled would reset its client's
// allowance, which is a rate-limit bypass.
//
// It reads the same heap eviction uses, which is sound because fullAt is never
// earlier than the last touch: now-fullAt >= cutoff implies now-last >= cutoff,
// so nothing is reclaimed early. It is not exact in the other direction — a
// bucket that was in debt when last touched carries a fullAt later than its last
// touch, so it can outlive the TTL by up to one refill window. That is a memory
// question, not a correctness one, and the key cap bounds it.
func (s *MemoryStore) reclaim(cfg Config, now time.Time) {
	cutoff := s.idleTTL
	if w := cfg.refillWindow(); w > cutoff {
		cutoff = w
	}
	nowNanos := now.UnixNano()
	for len(s.order) > 0 {
		if !refilledFor(nowNanos, s.order[0].fullAt, cutoff) {
			return
		}
		s.dropMostRefilled()
	}
}

// makeRoom frees a slot so a new bucket can be inserted without exceeding the
// key cap.
//
// It discards the most-refilled bucket, which is the one whose loss grants its
// client the least. Ordinarily that bucket is at capacity and the grant is zero.
// When the store is saturated with buckets that are all still in debt there is
// no free choice left, and the cap is enforced anyway: the memory bound is what
// keeps the store from being a denial-of-service vector of its own, so it is not
// something to trade away. [WithMaxKeys] documents what that state costs an
// attacker to reach.
func (s *MemoryStore) makeRoom() {
	for len(s.byKey) >= s.maxKeys && len(s.order) > 0 {
		s.dropMostRefilled()
	}
}

// dropMostRefilled removes the heap root, the bucket closest to full.
func (s *MemoryStore) dropMostRefilled() {
	b := s.order.popRoot()
	delete(s.byKey, b.key)
}

// fullAtNanos converts a token debt into the Unix-nanosecond instant at which
// the bucket reaches capacity, saturating rather than wrapping. A bucket that
// never refills lands at the far end of the ordering, so it is never chosen
// while any bucket that does refill is available.
func fullAtNanos(now time.Time, debt float64, cfg Config) int64 {
	base := now.UnixNano()
	d := waitFor(debt, cfg)
	if d <= 0 {
		return base
	}
	if sum := base + int64(d); sum > base {
		return sum
	}
	return math.MaxInt64
}

// refilledFor reports whether a bucket has been sitting at capacity for at
// least d. It subtracts only once the instant is known to be in the past, so
// the far-future values fullAtNanos saturates to cannot underflow it.
func refilledFor(nowNanos, fullAt int64, d time.Duration) bool {
	if fullAt > nowNanos {
		return false
	}
	return nowNanos-fullAt >= int64(d)
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
func decide(b *bucket, cfg Config, n int) Result {
	cost := float64(n)
	if b.tokens >= cost {
		b.tokens -= cost
		res := Result{Allowed: true, Remaining: remaining(b.tokens)}
		if b.tokens < 1 {
			// Allowed, but the next request will have to wait: tell the client
			// when, so it can pace itself instead of retrying into a rejection.
			res.RetryAfter = waitFor(1-b.tokens, cfg)
		}
		return res
	}
	// Denied. Remaining is what is actually left, which for a weighted call may
	// be well above zero -- the client has tokens, just not this many -- and
	// RetryAfter is the wait for the full cost rather than for one token, so a
	// client that retries at the advertised time is not rejected again.
	return Result{Allowed: false, Remaining: remaining(b.tokens), RetryAfter: waitFor(cost-b.tokens, cfg)}
}

// remaining converts a fractional token count into the whole tokens a client
// can still spend, never reporting a negative allowance.
func remaining(tokens float64) int {
	if tokens < 0 {
		return 0
	}
	return int(tokens)
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
