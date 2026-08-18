// Package redisstore implements ratelimit.Store on top of Redis, so that every
// instance of an application enforces one shared limit.
//
// # Why a separate module
//
// Go resolves dependencies per module, not per package. If this lived in the
// core module, github.com/redis/go-redis/v9 would appear in the go.sum of every
// consumer — and in their SBOM, their Dependabot alerts and their govulncheck
// output — even for someone who only imports secureheaders. Keeping it in its
// own module makes the core's zero-dependency claim literally true and
// machine-verifiable.
//
// The dependency arrow points one way: this module imports the core, and the
// core never imports this one.
//
// # Why the decision runs inside Redis
//
// The bucket update is a read-modify-write. Performed from Go it takes two
// round trips, and between them another request on the same key reads the same
// pre-decrement state. Under concurrency every one of those requests sees a
// token available and every one is admitted, so the effective limit becomes
// "burst per round trip" rather than "burst" — and opening several connections
// at once is precisely what an abusive client does.
//
// The whole decision therefore runs as one Lua script, in one round trip, with
// Redis's single-threaded execution providing the atomicity. The script lives
// in token_bucket.lua as a standalone file rather than a Go string, so that it
// can be linted, read with syntax highlighting, and run directly against a
// server with redis-cli --eval while debugging.
//
// Scripts are sent with EVALSHA and fall back to EVAL when the server reports
// NOSCRIPT, which happens after a restart or a SCRIPT FLUSH. That keeps the
// steady state to a hash on the wire without a cold start failing.
//
// # Failure behavior
//
// Every failure — a connection error, a timeout, a malformed reply — is
// returned as an error. This store never invents an "allowed" result to paper
// over an outage. What happens next is the middleware's decision, made through
// ratelimit.WithFailureMode, which defaults to rejecting; without an error
// here, that choice could not exist and an outage would look exactly like
// ordinary throttling.
//
// # Expiry
//
// Each bucket carries a TTL, so Redis reclaims idle buckets and no janitor
// goroutine is needed on the application side. The TTL is never shorter than
// the time the bucket takes to refill completely: dropping a partially
// refilled bucket would hand its client a fresh allowance, which is a
// rate-limit bypass rather than a cache miss.
//
// # Threat model notes
//
//   - Redis is trusted infrastructure here. Anyone who can write to it can set
//     any client's bucket to full. Put it on a private network, require
//     authentication, and use TLS.
//   - Bucket keys are derived from the ratelimit.KeyFunc, so they can contain
//     client-controlled data. They are namespaced with a prefix and used only
//     as key names, never interpolated into the script, so a crafted key cannot
//     change what the script does.
//   - Clock skew between application instances shifts refill slightly. The
//     script credits nothing for negative elapsed time, so skew errs toward
//     over-restricting rather than toward free allowance.
package redisstore

import (
	"context"
	_ "embed"
	"errors"
	"fmt"
	"math"
	"time"

	"github.com/JonasBorgesLM/moat/ratelimit"
	"github.com/redis/go-redis/v9"
)

// script is the token-bucket implementation, embedded from its own file so that
// it stays lintable and debuggable. See token_bucket.lua for the algorithm and
// the reasoning behind each step.
//
//go:embed token_bucket.lua
var script string

// tokenBucket wraps the script with go-redis's EVALSHA-then-EVAL handling.
var tokenBucket = redis.NewScript(script)

// Defaults for a [Store].
const (
	// DefaultKeyPrefix namespaces bucket keys so that they are recognizable in
	// a shared Redis and cannot collide with other data.
	DefaultKeyPrefix = "moat:ratelimit:"

	// DefaultIdleTTL is the floor for how long an untouched bucket is kept. The
	// effective TTL is never shorter than the bucket's full refill time.
	DefaultIdleTTL = 10 * time.Minute

	// DefaultTimeout bounds a single Redis round trip when the caller's context
	// has no earlier deadline. Without a bound, a hung backend turns a rate
	// limiter into a request-stalling denial of service — the limiter would be
	// the outage.
	DefaultTimeout = 250 * time.Millisecond
)

// ErrUnexpectedReply reports a reply from the script that does not have the
// documented shape. It indicates a version mismatch or a tampered script, and
// is deliberately an error rather than a best-effort interpretation.
var ErrUnexpectedReply = errors.New("redisstore: unexpected reply from token bucket script")

// Store is a Redis-backed [ratelimit.Store].
//
// It is safe for concurrent use. Create it with [New]; the zero value is not
// usable.
type Store struct {
	client    redis.Scripter
	keyPrefix string
	idleTTL   time.Duration
	timeout   time.Duration
}

// Option configures a [Store].
type Option func(*Store)

// New returns a Store that keeps bucket state in the given client.
//
// client is any go-redis client implementing redis.Scripter, which includes
// *redis.Client, *redis.ClusterClient and *redis.Ring, so the same store works
// against a single server, a cluster or a sharded ring.
//
// The Store does not take ownership of the client: [Store.Close] leaves it
// open, because the client is normally shared with the rest of the application
// and closing it from here would break everything else using it.
//
// In cluster mode every operation touches a single key, so no cross-slot
// operation is ever attempted.
func New(client redis.Scripter, opts ...Option) (*Store, error) {
	if client == nil {
		return nil, errors.New("redisstore: client is nil")
	}
	s := &Store{
		client:    client,
		keyPrefix: DefaultKeyPrefix,
		idleTTL:   DefaultIdleTTL,
		timeout:   DefaultTimeout,
	}
	for _, opt := range opts {
		if opt != nil {
			opt(s)
		}
	}
	return s, nil
}

// WithKeyPrefix sets the namespace for bucket keys. The default is
// [DefaultKeyPrefix].
//
// Give each application its own prefix when they share a Redis, or one
// application's traffic will be counted against another's buckets.
func WithKeyPrefix(prefix string) Option {
	return func(s *Store) { s.keyPrefix = prefix }
}

// WithIdleTTL sets the floor for how long an untouched bucket is kept in Redis.
//
// It is a floor, not a ceiling: a bucket is never expired before it would have
// refilled completely, whatever this is set to, because expiring a partially
// refilled bucket resets its client's allowance. Values of zero or less are
// ignored.
func WithIdleTTL(d time.Duration) Option {
	return func(s *Store) {
		if d > 0 {
			s.idleTTL = d
		}
	}
}

// WithTimeout bounds a single Redis round trip. The default is
// [DefaultTimeout]. A value of zero or less removes the bound and relies
// entirely on the caller's context.
//
// Keep it short. This call sits in front of every request, so its latency is
// added to every request; and with the middleware failing closed, a backend
// that hangs rather than refusing takes the whole endpoint down with it. A
// timeout converts that into a fast, visible error that the failure mode can
// act on.
//
// The shorter of this timeout and the caller's existing deadline wins.
func WithTimeout(d time.Duration) Option {
	return func(s *Store) { s.timeout = d }
}

// Take implements [ratelimit.Store].
//
// It runs the whole token-bucket decision in Redis in one round trip. The
// supplied now is the clock: this store never reads the local wall clock, so
// callers and tests control time exactly as the interface promises.
//
// Any transport or protocol failure is returned. Nothing here converts a
// failure into an allow.
func (s *Store) Take(ctx context.Context, key string, cfg ratelimit.Config, now time.Time) (ratelimit.Result, error) {
	burst := cfg.Burst
	if burst < 1 {
		burst = 1
	}
	rate := cfg.PerSecond
	if math.IsNaN(rate) || rate < 0 || math.IsInf(rate, 0) {
		rate = 0
	}

	if s.timeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, s.timeout)
		defer cancel()
	}

	args := []any{
		burst,
		rate,
		now.UnixMilli(),
		s.ttlMillis(burst, rate),
	}

	raw, err := tokenBucket.Run(ctx, s.client, []string{s.keyPrefix + key}, args...).Result()
	if err != nil {
		return ratelimit.Result{}, fmt.Errorf("redisstore: taking a token for %q: %w", key, err)
	}
	return parseReply(raw)
}

// Close releases resources held by the Store.
//
// It does not close the Redis client. The client belongs to whoever created it
// and is usually shared with the rest of the application; closing it here would
// take out every other user of the connection pool.
func (s *Store) Close() error { return nil }

// ttlMillis returns the bucket TTL in milliseconds: the configured idle floor,
// or the bucket's full refill time when that is longer.
//
// A bucket that never refills is kept for the idle floor only. Keeping it
// forever would let an attacker minting distinct keys fill Redis, and unlike
// the in-process store there is no LRU cap here to bound that.
func (s *Store) ttlMillis(burst int, rate float64) int64 {
	ttl := s.idleTTL
	if rate > 0 {
		refill := time.Duration(float64(burst) / rate * float64(time.Second))
		if refill > ttl {
			ttl = refill
		}
	}
	ms := ttl.Milliseconds()
	if ms < 1 {
		ms = 1 // PEXPIRE rejects a non-positive TTL.
	}
	return ms
}

// parseReply converts the script's reply into a [ratelimit.Result].
//
// A reply that does not match the documented shape is an error rather than a
// best guess: silently reading a malformed reply as "allowed" would be exactly
// the fail-open behavior this package refuses to have.
func parseReply(raw any) (ratelimit.Result, error) {
	values, ok := raw.([]any)
	if !ok || len(values) != 3 {
		return ratelimit.Result{}, fmt.Errorf("%w: %#v", ErrUnexpectedReply, raw)
	}
	allowed, ok1 := values[0].(int64)
	remaining, ok2 := values[1].(int64)
	retryMillis, ok3 := values[2].(int64)
	if !ok1 || !ok2 || !ok3 {
		return ratelimit.Result{}, fmt.Errorf("%w: %#v", ErrUnexpectedReply, raw)
	}

	if remaining < 0 {
		remaining = 0
	}
	res := ratelimit.Result{
		Allowed:   allowed == 1,
		Remaining: int(remaining),
	}
	switch {
	case retryMillis < 0:
		// The bucket never refills. Report the maximum rather than a negative
		// duration, so a caller formatting Retry-After always has a real value.
		res.RetryAfter = time.Duration(math.MaxInt64)
	case retryMillis > 0:
		res.RetryAfter = time.Duration(retryMillis) * time.Millisecond
	}
	return res, nil
}

// compile-time assertion that Store satisfies the interface it exists to
// implement. A mismatch is then a build failure here rather than a puzzling
// error in someone else's application.
var _ ratelimit.Store = (*Store)(nil)
