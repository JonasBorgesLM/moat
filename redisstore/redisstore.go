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
// # Redis must be configured with maxmemory-policy noeviction
//
// That TTL reasoning is enforceable only as far as Redis lets it be. A server
// running under maxmemory with any eviction policy discards keys to reclaim
// memory whenever it is under pressure, and it does not know that these
// particular keys are rate-limit state — so it will drop a bucket that has not
// refilled, which is exactly the allowance grant the TTL floor exists to
// prevent.
//
// Worse, it drops the wrong one. Recency is anti-correlated with safety here: a
// client that has just exhausted its burst cannot make requests, so its bucket
// stops being touched and becomes the *best* eviction candidate, while the
// bucket that has actually refilled — free to drop — was touched recently and is
// spared. The eviction lands on the one client whose limit it resets.
//
// noeviction is the only safe setting, and the volatile-* family is not the
// narrower alternative it looks like. Every bucket carries a TTL, so "volatile"
// excludes nothing here; in a Redis shared with a cache whose entries do not all
// expire, it makes the rate-limit buckets the *preferred* victims. volatile-ttl
// is not an escape either: bucket TTLs are all refreshed to the same value on
// every call, so "nearest expiry" is "longest idle" restated — the same recency
// ordering, with the same anti-correlation.
//
// Under noeviction, Redis rejects writes at the memory ceiling rather than
// silently discarding limits. This store then returns an error and
// ratelimit.WithFailureMode decides what happens, which is a visible outage
// instead of an invisible bypass — the trade this library makes everywhere else
// too. Give rate-limit state an instance or logical database that is not shared
// with a general-purpose cache; memory stays bounded by the TTLs regardless,
// since every bucket carries one.
//
// [New] checks this at construction where the server will answer, and returns
// [ErrUnsafeEvictionPolicy] if it can see that eviction is on. The check is
// best-effort — managed Redis usually disables CONFIG — so it closes the case of
// an operator who never knew, without being something to rely on. This mirrors
// the choice ratelimit.MemoryStore makes in-process, where the same reasoning
// ruled out an LRU cap.
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
	"strconv"
	"strings"
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

// ErrUnsafeEvictionPolicy reports that the Redis server is configured to evict
// keys under memory pressure, which silently defeats this store's limit.
//
// # Why this is not merely a tuning preference
//
// Every bucket carries a TTL chosen so that a bucket is never dropped before it
// would have refilled completely — dropping a partially refilled bucket hands
// its client a fresh allowance, which is a bypass rather than a cache miss. A
// server running under maxmemory with an eviction policy discards keys whenever
// it is short of memory, and it has no idea these particular keys are
// rate-limit state. The TTL reasoning is then decorative.
//
// Worse, the policies evict in the wrong order. Redis evicts by approximate
// idle time (the lru policies) or by nearest expiry (volatile-ttl); because
// every bucket's TTL is refreshed to the same value on every call, nearest
// expiry is idle time restated, so both come to the same ordering. And idle time
// is anti-correlated with safety here: a client that has just exhausted its
// burst cannot make requests, so its bucket stops being touched and becomes the
// most attractive eviction candidate — while the bucket that has actually
// refilled, and could be dropped for free, was touched recently and is spared.
// The eviction therefore lands on the one client whose limit it resets. This is
// the same failure ratelimit.MemoryStore fixed in-process by ordering on refill
// level instead of recency; here the ordering belongs to Redis and cannot be
// changed from Go.
//
// # Only noeviction is safe
//
// Every volatile-* policy targets keys that have a TTL, and every bucket has
// one, so "volatile" is not a narrower blast radius — in a Redis shared with a
// cache whose entries do not all expire, it makes the rate-limit buckets the
// *preferred* victims. volatile-ttl is not an escape either, for the reason
// above. That leaves noeviction, under which Redis rejects writes at the
// memory ceiling instead of silently discarding limits; the store then returns
// an error and ratelimit.WithFailureMode decides, which is a visible outage
// rather than an invisible bypass.
//
// If eviction is genuinely acceptable for your deployment, say so with
// [InsecureAllowKeyEviction].
var ErrUnsafeEvictionPolicy = errors.New("redisstore: Redis is configured to evict keys under memory pressure, which silently resets rate limits; set maxmemory-policy to noeviction, or pass redisstore.InsecureAllowKeyEviction if that is genuinely intended")

// Store is a Redis-backed [ratelimit.Store].
//
// It is safe for concurrent use. Create it with [New]; the zero value is not
// usable.
type Store struct {
	client    redis.Scripter
	keyPrefix string
	idleTTL   time.Duration
	timeout   time.Duration

	// allowEviction records an explicit [InsecureAllowKeyEviction]. It is read
	// during construction only; nothing on the request path consults it.
	allowEviction bool

	// evictionCheck records what the construction-time check established, so
	// that a skipped check is reportable rather than silent. Written once by
	// [New] before the Store escapes; read-only afterwards.
	evictionCheck EvictionCheck
}

// EvictionCheck reports what [New] was able to establish about the server's
// eviction configuration.
//
// The eviction check is best-effort by design (see [Store.EvictionCheck]), and
// every reason it can come back unestablished is a reason that is *more* likely
// on managed Redis than on a local container. This type exists so that "the
// store checks this for you" can be turned into a question with an answer,
// rather than an assumption.
type EvictionCheck int

const (
	// EvictionCheckUnknown is the zero value, and asserts nothing. A Store
	// returned by [New] never carries it; a zero-value Store is not usable.
	EvictionCheckUnknown EvictionCheck = iota

	// EvictionCheckVerified means every server reached reported a configuration
	// under which it will not evict: either no memory ceiling, or
	// maxmemory-policy noeviction.
	//
	// It is a statement about the moment the Store was built, not a standing
	// guarantee. See [Store.EvictionCheck].
	EvictionCheckVerified

	// EvictionCheckNoConfigSupport means the client value passed to [New] does
	// not expose CONFIG GET at all, so nothing was asked. A test double or a
	// custom redis.Scripter implementation lands here.
	EvictionCheckNoConfigSupport

	// EvictionCheckReplyNotUnderstood means the server answered, but the reply
	// did not carry a usable maxmemory or maxmemory-policy value.
	EvictionCheckReplyNotUnderstood

	// EvictionCheckServerSilent means CONFIG GET returned an error: the command
	// is disabled or renamed — the normal case on ElastiCache, MemoryDB, Upstash
	// and Azure Cache — or the server was not reachable when [New] ran.
	//
	// This is the common outcome in production and the rare one in local
	// development, which is the inversion worth knowing about: the check is
	// loudest where the stakes are lowest.
	EvictionCheckServerSilent

	// EvictionCheckOptedOut means [InsecureAllowKeyEviction] was passed, so no
	// check was attempted and no round trip was made.
	EvictionCheckOptedOut
)

// Verified reports whether the check positively established a safe
// configuration. Every other value means the check was skipped, not that it
// passed.
func (c EvictionCheck) Verified() bool { return c == EvictionCheckVerified }

// String implements [fmt.Stringer].
func (c EvictionCheck) String() string {
	switch c {
	case EvictionCheckVerified:
		return "verified: no eviction configured"
	case EvictionCheckNoConfigSupport:
		return "skipped: the client cannot issue CONFIG GET"
	case EvictionCheckReplyNotUnderstood:
		return "skipped: the server's CONFIG reply was not understood"
	case EvictionCheckServerSilent:
		return "skipped: CONFIG is disabled, renamed, or the server was unreachable"
	case EvictionCheckOptedOut:
		return "skipped: InsecureAllowKeyEviction was passed"
	default:
		return "unknown: no check was performed"
	}
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
	check, err := s.checkEvictionPolicy()
	if err != nil {
		return nil, err
	}
	s.evictionCheck = check
	return s, nil
}

// EvictionCheck reports what the construction-time eviction check established.
//
// [New] refuses to build a Store against a server it can see is configured to
// evict keys, because eviction silently resets rate limits (see
// [ErrUnsafeEvictionPolicy]). What it cannot do is establish the answer
// everywhere, and when it cannot, it proceeds. That is the right trade — a
// library that guessed would reject working deployments it cannot inspect — but
// it means a Store built without error is not the same thing as a Store built
// against a server known to be safe.
//
// This method is the difference, made available rather than left implicit:
//
//	store, err := redisstore.New(client)
//	if err != nil {
//		return err
//	}
//	if c := store.EvictionCheck(); !c.Verified() {
//		log.Printf("redisstore: eviction policy unverified (%s); confirm maxmemory-policy is noeviction", c)
//	}
//
// Two gaps it will not close, both worth knowing before relying on a verified
// result:
//
//   - A verified result is a snapshot. It describes the server's mutable runtime
//     state at construction. `CONFIG SET maxmemory-policy allkeys-lru` is one
//     command away, and the moment it is most likely to be run is a memory
//     incident — exactly when the bypass matters. Nothing re-checks afterwards.
//
//   - In cluster or ring mode, every master reachable at construction is asked,
//     and only then. A node that joins later, or a replica promoted by failover
//     with a different configuration, is not covered. Failover is also a thing
//     that happens during memory incidents.
//
// The honest summary is that this check closes the case of an operator who never
// knew, and does not make a deployment permanently safe. An operator who needs
// the stronger property should assert `maxmemory-policy noeviction` from
// configuration management, where it is an invariant rather than an observation.
func (s *Store) EvictionCheck() EvictionCheck { return s.evictionCheck }

// checkEvictionPolicy asks the server whether it is configured to evict keys,
// and refuses to build a Store if it positively determines that it is.
//
// # Best effort, and deliberately so
//
// The check is skipped, silently, whenever the answer cannot be established:
// the client type exposes no CONFIG command, CONFIG is disabled or renamed (the
// normal case on managed Redis — ElastiCache, MemoryDB, Upstash and Azure Cache
// all restrict it), the server is not reachable yet, or the reply is not
// understood. Only a definite "yes, this server evicts" produces an error.
//
// That asymmetry is the point. A library that guesses would either reject
// working deployments it cannot inspect, or claim an assurance it does not have.
// Refusing only what it can actually see keeps the error trustworthy: if it
// fires, it is right.
//
// # What a passing check does and does not mean
//
// It means this server reported a safe configuration at the moment the Store was
// built. It is a snapshot of another system's mutable runtime state, not an
// invariant: `CONFIG SET maxmemory-policy allkeys-lru` is one command away, and
// the moment it is most likely to be run is a memory incident — exactly when the
// bypass matters. A cluster node that joins later is not covered either. So this
// closes the case of an operator who never knew; it does not make the deployment
// permanently safe, and the documentation on [ErrUnsafeEvictionPolicy] is still
// the thing an operator has to have read.
//
// It costs one round trip at construction, bounded by the store's timeout. New
// still does not fail because Redis is down — an unreachable server is a case
// the check cannot establish, so it is skipped.
//
// The returned [EvictionCheck] records which of those it was, so that a skipped
// check is reportable through [Store.EvictionCheck] rather than indistinguishable
// from a passing one.
func (s *Store) checkEvictionPolicy() (EvictionCheck, error) {
	if s.allowEviction {
		return EvictionCheckOptedOut, nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), s.timeout)
	defer cancel()

	// A cluster or a ring answers per node, and a single node's configuration
	// says nothing about its peers, so every reachable one is asked.
	// A multi-node sweep is only as good as its weakest node, so the reported
	// outcome is the least-established one seen. EvictionCheck's constants are
	// ordered from most to least established for exactly this.
	sweep := func(each func(context.Context, func(context.Context, *redis.Client) error) error) (EvictionCheck, error) {
		worst := EvictionCheckVerified
		var unsafe error
		// A per-node transport failure must not abort the sweep, so the closure
		// only ever returns nil and the verdict is carried out separately.
		_ = each(ctx, func(ctx context.Context, node *redis.Client) error {
			check, err := evictionPolicyOf(ctx, node)
			if check > worst {
				worst = check
			}
			if err != nil && unsafe == nil {
				unsafe = err
			}
			return nil
		})
		return worst, unsafe
	}

	switch c := s.client.(type) {
	case interface {
		ForEachMaster(context.Context, func(context.Context, *redis.Client) error) error
	}:
		return sweep(c.ForEachMaster)
	case interface {
		ForEachShard(context.Context, func(context.Context, *redis.Client) error) error
	}:
		return sweep(c.ForEachShard)
	case configReader:
		return evictionPolicyOf(ctx, c)
	}
	return EvictionCheckNoConfigSupport, nil
}

// configReader is the sliver of a go-redis client needed to read server
// configuration. It is matched by type assertion rather than required by [New],
// so that a client which cannot answer — including a test double — is skipped
// instead of rejected.
type configReader interface {
	ConfigGet(ctx context.Context, parameter string) *redis.MapStringStringCmd
}

// evictionPolicyOf returns [ErrUnsafeEvictionPolicy] when one server is known to
// evict, and a nil error in every case where that cannot be established.
//
// The [EvictionCheck] it returns alongside distinguishes "this server reported a
// safe configuration" from "this server did not tell us" — a distinction the
// error return cannot carry, since both are a nil error.
func evictionPolicyOf(ctx context.Context, c configReader) (EvictionCheck, error) {
	// One glob rather than two parameters: CONFIG GET took a single parameter
	// until Redis 7, and both values are needed together anyway.
	cfg, err := c.ConfigGet(ctx, "maxmemory*").Result()
	if err != nil {
		// CONFIG is disabled, renamed, or the server is not reachable. The
		// library genuinely cannot know, and cannot tell those apart either:
		// managed Redis reports a disabled command as an ordinary error.
		return EvictionCheckServerSilent, nil
	}

	// Without a memory ceiling Redis never evicts, whatever the policy says, so
	// a non-default policy on an uncapped server is not a finding. A server that
	// reports no ceiling at all has answered the question, so this is verified
	// rather than skipped.
	limit, ok := cfg["maxmemory"]
	if !ok {
		return EvictionCheckReplyNotUnderstood, nil
	}
	bytes, convErr := strconv.ParseInt(strings.TrimSpace(limit), 10, 64)
	if convErr != nil {
		return EvictionCheckReplyNotUnderstood, nil
	}
	if bytes == 0 {
		return EvictionCheckVerified, nil
	}

	policy, ok := cfg["maxmemory-policy"]
	if !ok {
		return EvictionCheckReplyNotUnderstood, nil
	}
	// Compared case-folded, but reported verbatim: an operator matching the
	// error against their own config file wants the string the server gave.
	normalized := strings.ToLower(strings.TrimSpace(policy))
	if normalized == "" {
		return EvictionCheckReplyNotUnderstood, nil
	}
	if normalized == "noeviction" {
		return EvictionCheckVerified, nil
	}
	return EvictionCheckVerified, fmt.Errorf("%w (server reports maxmemory-policy %q with maxmemory set)", ErrUnsafeEvictionPolicy, policy)
}

// InsecureAllowKeyEviction lets [New] build a Store against a Redis server that
// is configured to evict keys under memory pressure.
//
// Read the name literally. It does not relax a check; it accepts that the server
// may discard rate-limit state at any moment, and that each discarded bucket
// hands its client a fresh full burst — landing, for the reasons in
// [ErrUnsafeEvictionPolicy], on whichever client has most recently been
// throttled. The limit becomes advisory under memory pressure.
//
// It exists because the refusal would otherwise be a lie about deployments where
// eviction is a considered trade: a shared cache instance where an approximate
// limit is worth more than an outage at the memory ceiling, or a staging
// environment where nobody cares. It also skips the round trip, which suits a
// process that builds its store before Redis is reachable.
//
// It is deliberately not spelled With..., and deliberately not a bool field. It
// should be impossible to read a call site containing it and not notice.
func InsecureAllowKeyEviction() Option {
	return func(s *Store) { s.allowEviction = true }
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
func (s *Store) TakeN(ctx context.Context, key string, n int, cfg ratelimit.Config, now time.Time) (ratelimit.Result, error) {
	if n < 1 {
		// Clamped here as well as in the script: a store is required to do it
		// by the ratelimit.Store contract, and it must hold even if the script
		// is ever replaced.
		n = 1
	}
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
		n,
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
