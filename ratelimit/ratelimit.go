// Package ratelimit provides token-bucket rate limiting as net/http middleware,
// with a pluggable storage backend.
//
// # Algorithm
//
// A token bucket, not a fixed window. A fixed-window counter permits up to
// twice the intended rate across a window boundary: a client can spend its
// whole quota in the last instant of one window and its whole quota again in
// the first instant of the next. A token bucket has no boundary to exploit,
// while still allowing the short bursts that user-facing APIs want.
//
// # Threat model
//
// Rate limiting mitigates credential stuffing, scraping, and brute force. It is
// only as good as its key, and the two ways it is most often defeated are:
//
//   - Spoofed client identity. The default key is the request's RemoteAddr,
//     never X-Forwarded-For. Forwarded headers are set by the client and are
//     trivially forged; a limiter keyed on an unverified X-Forwarded-For is not
//     a limiter at all, because every request can claim a fresh identity.
//     Behind a trusted proxy, use [WithKeyFunc] with a function that reads the
//     forwarded header only after confirming the peer really is that proxy.
//   - Memory exhaustion of the limiter itself. A map keyed by client address
//     grows with the number of distinct sources, and a single host with an IPv6
//     /64 can mint effectively unlimited addresses. [MemoryStore] therefore caps
//     the number of tracked keys, discarding the most refilled bucket rather
//     than the least recently used one — see [MemoryStore] for why that
//     distinction is the difference between a bound and a bypass.
//
// A per-process [MemoryStore] enforces its limit per instance. Behind a load
// balancer with N instances, the effective limit is N times the configured one;
// use a shared store (see the redisstore module) when that matters.
//
// # Failure policy
//
// When the store returns an error the limiter fails closed by default: the
// request is rejected and the [WithOnError] hook is invoked. Fail-closed is a
// deliberate and debatable choice — for pure abuse mitigation, availability is
// often worth more than enforcement — so it is configurable through
// [WithFailureMode]. It is the default so that failing to make a decision
// leaves you with the safer behavior.
//
// A genuine denial and a backend outage are answered with different status
// codes (429 and 503 respectively), so that an outage is not silently
// indistinguishable from ordinary throttling in your metrics.
//
// The package never logs or prints. Errors reach the application only through
// [WithOnError] and through returned values.
package ratelimit

import (
	"context"
	"math"
	"net/http"
	"strconv"
	"time"
)

// Config describes the shape of a bucket: how many requests may arrive at once
// and how quickly the allowance is replenished.
//
// It is passed to [Store.Take] on every call rather than held by the store, so
// that a single shared store can serve limiters with different limits, and so
// that a network-backed store stays stateless with respect to configuration.
type Config struct {
	// Burst is the bucket capacity: the maximum number of requests that may be
	// made back to back after an idle period. Values below 1 are treated as 1.
	Burst int

	// PerSecond is the sustained rate at which tokens are replenished.
	// Zero, negative, and NaN are treated as zero, which means the bucket never
	// refills: once Burst requests are spent, everything is denied. That is the
	// fail-closed reading of a misconfiguration, and it is deliberate.
	PerSecond float64
}

// normalized returns cfg with out-of-range values clamped to their safe
// equivalents, so that stores and arithmetic never see a negative capacity or a
// NaN rate.
func (c Config) normalized() Config {
	if c.Burst < 1 {
		c.Burst = 1
	}
	if math.IsNaN(c.PerSecond) || c.PerSecond < 0 || math.IsInf(c.PerSecond, -1) {
		c.PerSecond = 0
	}
	return c
}

// refillWindow reports how long a bucket takes to go from empty to full.
//
// Stores use it to decide when a bucket may be forgotten: discarding a bucket
// before it would have refilled hands the client a fresh allowance, which is a
// rate-limit bypass. A bucket that never refills therefore reports the maximum
// duration — it is never safe to forget, and its memory is bounded by the
// store's key cap instead.
func (c Config) refillWindow() time.Duration {
	if c.PerSecond <= 0 {
		return time.Duration(math.MaxInt64)
	}
	secs := float64(c.Burst) / c.PerSecond
	if math.IsInf(secs, 1) || secs > float64(math.MaxInt64/int64(time.Second)) {
		return time.Duration(math.MaxInt64)
	}
	return time.Duration(secs * float64(time.Second))
}

// Result is the outcome of one [Store.Take].
type Result struct {
	// Allowed reports whether a token was available and consumed.
	Allowed bool

	// Remaining is the whole number of tokens left after this call. It is never
	// negative.
	Remaining int

	// RetryAfter is how long until at least one token is available. It is zero
	// when a token is available now, and is the value reported to clients in
	// Retry-After and in the reset headers.
	RetryAfter time.Duration
}

// Store holds bucket state. Implementations must be safe for concurrent use.
//
// # Contract
//
// Take must be atomic: read, refill, decide, and write back without
// interleaving with another Take on the same key. A read-modify-write split
// across round trips races, and the race is exploitable — concurrent requests
// each read the same pre-decrement state and all get admitted, which is exactly
// the burst an attacker wants.
//
// The context is mandatory rather than optional because any network-backed
// store needs a deadline: without one, a hung backend converts a rate limiter
// into a request-stalling denial of service. The error is mandatory so that
// "the backend is down" is distinguishable from "this client is over its
// limit"; returning a plain denial for an outage leaves operators blind.
//
// now is supplied by the caller so that tests can drive time deterministically.
// Implementations must not substitute their own clock for it.
type Store interface {
	// TakeN consumes n tokens from the bucket identified by key, creating a
	// full bucket if it does not exist.
	//
	// All n are taken or none are: a partial deduction would charge a caller
	// for work it was not allowed to do. n below 1 must be treated as 1, so
	// that a miscomputed weight cannot turn into a free request.
	//
	// An n larger than cfg.Burst can never be satisfied, and must be reported
	// as a denial rather than as an error — it is a request that costs more
	// than the bucket can ever hold, which is a decision, not a malfunction.
	TakeN(ctx context.Context, key string, n int, cfg Config, now time.Time) (Result, error)

	// Close releases any resources held by the store. It must be safe to call
	// more than once.
	Close() error
}

// normalizeCost clamps a weight to the smallest value a bucket may be charged.
//
// A cost below 1 is treated as 1 rather than as zero: a weight that arrives
// miscomputed — an empty list, an integer division that truncated — must not
// produce a request that passes through the limiter without paying for itself.
func normalizeCost(n int) int {
	if n < 1 {
		return 1
	}
	return n
}

// KeyFunc derives the rate-limit bucket key for a request.
//
// Returning an error rejects the request without consulting the store, and is
// the correct response to a request whose identity cannot be established — for
// example a forwarded header arriving from an untrusted peer. Do not return a
// constant fallback key in that situation: it merges every unidentifiable
// client into one bucket, so a single attacker can exhaust the allowance of
// everyone who shares it.
//
// An empty key with a nil error is treated as an error, for the same reason.
type KeyFunc func(*http.Request) (string, error)

// FailureMode selects what happens when the [Store] returns an error.
type FailureMode int

// Failure modes. FailClosed is the zero value, so a Limiter that is never told
// what to do about a store outage does the safer thing.
const (
	// FailClosed rejects the request when the store errors. This is the default:
	// an outage must not silently disable the control that protects the
	// endpoints behind it.
	FailClosed FailureMode = iota

	// FailOpen admits the request when the store errors, trading enforcement for
	// availability. Choose it deliberately, for endpoints where being
	// unreachable is worse than being unthrottled.
	FailOpen
)

// HeaderMode selects which rate-limit headers are written to responses.
//
// Publishing limit state helps well-behaved clients back off, and marginally
// helps an attacker tune their request rate to stay just under the threshold.
// That is a trade-off worth making consciously, so it is configurable and can
// be switched off entirely.
type HeaderMode int

// Header modes. HeaderBoth is the zero value.
const (
	// HeaderBoth emits the widely deployed X-RateLimit-* headers and the
	// standardized RateLimit-* form. This is the default.
	HeaderBoth HeaderMode = iota

	// HeaderLegacy emits only X-RateLimit-Limit, X-RateLimit-Remaining and
	// X-RateLimit-Reset.
	HeaderLegacy

	// HeaderStandard emits only RateLimit-Limit, RateLimit-Remaining and
	// RateLimit-Reset.
	HeaderStandard

	// HeaderNone emits no rate-limit headers. Retry-After is still sent on a
	// denial, since a client that has just been rejected needs to know when to
	// come back.
	HeaderNone
)

// Limiter applies a token-bucket limit to HTTP requests.
//
// A Limiter is safe for concurrent use and is intended to be created once at
// startup and shared. Create it with [New]; the zero value is not usable.
type Limiter struct {
	cfg          Config
	store        Store
	ownsStore    bool
	key          KeyFunc
	failure      FailureMode
	headers      HeaderMode
	onError      func(error)
	denied       http.Handler
	storeErrored http.Handler
	now          func() time.Time
}

// Option configures a [Limiter].
type Option func(*Limiter)

// New returns a Limiter allowing bursts of burst requests, replenished at
// perSecond requests per second.
//
// With no options it uses a bounded in-process [MemoryStore], keys buckets by
// [RemoteAddrKey], fails closed on store errors, and emits both families of
// rate-limit headers.
//
// burst below 1 is treated as 1, and a perSecond that is zero, negative or NaN
// is treated as zero, meaning the bucket never refills. Misconfiguration
// therefore over-restricts rather than silently disabling the limiter.
//
// If the Limiter created the store itself, [Limiter.Close] shuts it down; a
// store supplied through [WithStore] is left to its owner.
func New(burst int, perSecond float64, opts ...Option) *Limiter {
	l := &Limiter{
		cfg:     Config{Burst: burst, PerSecond: perSecond}.normalized(),
		key:     RemoteAddrKey,
		failure: FailClosed,
		headers: HeaderBoth,
		now:     time.Now,
	}
	for _, opt := range opts {
		if opt != nil {
			opt(l)
		}
	}
	if l.store == nil {
		l.store = NewMemoryStore()
		l.ownsStore = true
	}
	return l
}

// WithStore makes the Limiter use store instead of the default in-process one.
//
// Use it to share limit state across instances — a per-process store enforces
// its limit once per instance, so N instances behind a load balancer allow N
// times the configured rate. The caller keeps ownership: [Limiter.Close] does
// not close a store supplied here, because one store is normally shared by
// several limiters.
//
// A nil store is ignored, leaving the default in place, so that a failed store
// constructor cannot accidentally disable limiting.
func WithStore(store Store) Option {
	return func(l *Limiter) {
		if store != nil {
			l.store = store
			l.ownsStore = false
		}
	}
}

// WithKeyFunc replaces the function that derives a bucket key from a request.
//
// This is the single most security-sensitive knob in the package. The default
// deliberately ignores X-Forwarded-For and X-Real-IP because those are supplied
// by the client: keying on them lets an attacker present a new identity with
// every request and bypass the limit entirely. Only read a forwarded header
// after verifying that r.RemoteAddr belongs to a proxy you control, and prefer
// taking a fixed number of hops from the right-hand end of the header, which is
// the part your own proxy appended.
//
// A nil fn is ignored.
func WithKeyFunc(fn KeyFunc) Option {
	return func(l *Limiter) {
		if fn != nil {
			l.key = fn
		}
	}
}

// WithFailureMode selects whether a store error rejects or admits the request.
// The default is [FailClosed].
func WithFailureMode(mode FailureMode) Option {
	return func(l *Limiter) { l.failure = mode }
}

// WithHeaders selects which rate-limit headers are published. The default is
// [HeaderBoth].
func WithHeaders(mode HeaderMode) Option {
	return func(l *Limiter) { l.headers = mode }
}

// WithOnError registers a hook invoked when the store fails or a key cannot be
// derived.
//
// This library never logs; the hook is how store outages, which are otherwise
// invisible behind a generic rejection, reach your logger, metrics and alerts.
// Without it, a fail-closed limiter in front of a dead backend rejects every
// request with no signal to operators.
//
// The hook runs synchronously on the request path, so it must not block. It
// must not panic; a panic in the hook propagates to the server.
func WithOnError(fn func(error)) Option {
	return func(l *Limiter) { l.onError = fn }
}

// WithDeniedHandler replaces the response written when a client is over its
// limit. The default writes 429 with a Retry-After header.
//
// The rate-limit headers, including Retry-After, are already set on the
// ResponseWriter when the handler runs, so a custom handler can render any body
// it likes without recomputing them. A nil handler is ignored.
func WithDeniedHandler(h http.Handler) Option {
	return func(l *Limiter) {
		if h != nil {
			l.denied = h
		}
	}
}

// WithStoreErrorHandler replaces the response written when the store fails and
// the failure mode is [FailClosed]. The default writes 503.
//
// It is deliberately distinct from the denied handler: answering an outage with
// 429 tells clients to slow down when the truth is that the limiter cannot make
// a decision, and makes the outage indistinguishable from real throttling. A
// nil handler is ignored.
func WithStoreErrorHandler(h http.Handler) Option {
	return func(l *Limiter) {
		if h != nil {
			l.storeErrored = h
		}
	}
}

// withClock overrides the clock. It is unexported because production code has
// no reason to lie about the time; tests use it for determinism.
func withClock(fn func() time.Time) Option {
	return func(l *Limiter) {
		if fn != nil {
			l.now = fn
		}
	}
}

// RemoteAddrKey keys buckets by the IP portion of r.RemoteAddr, which is the
// peer of the TCP connection and cannot be forged by the client without
// controlling the routing between you.
//
// The port is stripped, because it changes on every connection and would give
// each request its own bucket.
//
// Behind a reverse proxy every request appears to come from the proxy, so all
// clients share one bucket. That is a availability problem, not a security
// hole, and the fix is a [KeyFunc] that reads the forwarded header after
// verifying the peer — see [WithKeyFunc].
func RemoteAddrKey(r *http.Request) (string, error) {
	host := r.RemoteAddr
	// net.SplitHostPort allocates and errors on unusual inputs; scanning for the
	// last colon handles "ip:port", "[v6]:port" and a bare address uniformly.
	if i := lastIndexByte(host, ':'); i >= 0 {
		if j := lastIndexByte(host, ']'); j < i {
			host = host[:i]
		}
	}
	host = trimBrackets(host)
	if host == "" {
		return "", errNoRemoteAddr
	}
	return host, nil
}

// Take consumes one token for key, bypassing HTTP entirely.
//
// It is equivalent to TakeN(ctx, key, 1). It applies no failure policy: the
// caller decides what a non-nil error means. For the common case where the
// answer wanted is a yes or no with the configured failure policy already
// applied, use [Limiter.Allow].
func (l *Limiter) Take(ctx context.Context, key string) (Result, error) {
	return l.TakeN(ctx, key, 1)
}

// TakeN consumes n tokens for key, bypassing HTTP entirely.
//
// It is exported so that the same limit can cover non-HTTP work — a background
// job, a gRPC call, a queue consumer — without a second configuration to keep
// in sync, and so that expensive operations can cost more than cheap ones.
//
// n below 1 is treated as 1. An n above [Config.Burst] can never be satisfied
// and is always denied, with a RetryAfter that reflects a wait that will never
// end; a weight larger than the bucket is a configuration error, and reporting
// it as a permanent denial is the fail-closed reading of one.
//
// The whole deduction is atomic: n tokens are taken or none are, in a single
// indivisible store operation. Calling Take in a loop is not equivalent, and is
// racy — see [Store] on why.
//
// It applies no failure policy: the caller decides what a non-nil error means.
func (l *Limiter) TakeN(ctx context.Context, key string, n int) (Result, error) {
	return l.store.TakeN(ctx, key, normalizeCost(n), l.cfg, l.now())
}

// Allow reports whether a request for key may proceed, consuming one token if
// it may.
//
// It is equivalent to AllowN(ctx, key, 1).
func (l *Limiter) Allow(ctx context.Context, key string) bool {
	return l.AllowN(ctx, key, 1)
}

// AllowN reports whether an operation for key costing n tokens may proceed,
// consuming them if it may.
//
// This is the form to use inside a handler, where the identity that should be
// limited — an account ID, an API key, a tenant — is known only after
// authentication and so cannot be derived by the middleware from the request
// alone:
//
//	if !limiter.AllowN(r.Context(), account.ID, report.Cost()) {
//	    writeError(w, http.StatusTooManyRequests, "rate limit exceeded")
//	    return
//	}
//
// Unlike [Limiter.TakeN] it applies the configured [FailureMode]: a store
// outage returns false under [FailClosed] and true under [FailOpen], and either
// way the error reaches [WithOnError]. That is the whole difference between the
// two — use TakeN when you want to see the error and decide yourself.
//
// It deliberately returns a bare bool rather than a Result. A caller that wants
// the remaining allowance or a retry hint is asking a different question and
// should call TakeN, whose answer includes both; folding them into this
// signature would make the common case carry values it does not use.
//
// n below 1 is treated as 1, and n above [Config.Burst] is always denied.
func (l *Limiter) AllowN(ctx context.Context, key string, n int) bool {
	_, out := l.evaluate(ctx, key, n)
	return out == outcomeAllowed || out == outcomeFailedOpen
}

// outcome is the decision after the failure policy has been applied. It exists
// so that the middleware and [Limiter.AllowN] share one copy of that policy
// instead of each interpreting a (Result, error) pair their own way.
type outcome int

const (
	// outcomeAllowed: the store granted the tokens.
	outcomeAllowed outcome = iota
	// outcomeDenied: the store refused; the client is over its limit.
	outcomeDenied
	// outcomeStoreError: the store failed and the policy is FailClosed.
	outcomeStoreError
	// outcomeFailedOpen: the store failed and the policy is FailOpen. It is
	// distinct from outcomeAllowed because there is no Result to report, so a
	// caller must not publish rate-limit headers derived from one.
	outcomeFailedOpen
)

// evaluate takes n tokens and applies the failure policy. It is the single
// place that policy lives.
func (l *Limiter) evaluate(ctx context.Context, key string, n int) (Result, outcome) {
	res, err := l.TakeN(ctx, key, n)
	if err != nil {
		l.report(err)
		if l.failure == FailOpen {
			return Result{}, outcomeFailedOpen
		}
		return Result{}, outcomeStoreError
	}
	if !res.Allowed {
		return res, outcomeDenied
	}
	return res, outcomeAllowed
}

// Config returns the limits this Limiter enforces.
func (l *Limiter) Config() Config { return l.cfg }

// Close releases the Limiter's store if the Limiter created it. A store passed
// to [WithStore] is left untouched, since its lifetime belongs to whoever
// created it. Close is safe to call more than once.
func (l *Limiter) Close() error {
	if !l.ownsStore || l.store == nil {
		return nil
	}
	return l.store.Close()
}

// Middleware applies the limit to every request reaching next.
//
// It is a plain func(http.Handler) http.Handler, so it can be used directly or
// placed in a middleware.Chain. Put it early in the pipeline: a limiter that
// runs after expensive work has already paid for the request it was meant to
// reject.
//
// The middleware never reads the request body, so it is safe to place before
// body-reading middleware and handlers.
func (l *Limiter) Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		key, err := l.key(r)
		if err == nil && key == "" {
			err = errEmptyKey
		}
		if err != nil {
			// An underivable key means the client is unidentifiable. Bucketing
			// such requests together would let one attacker drain a shared
			// allowance, so the failure mode decides instead.
			l.report(err)
			if l.failure == FailOpen {
				next.ServeHTTP(w, r)
				return
			}
			l.writeStoreError(w, r)
			return
		}

		res, out := l.evaluate(r.Context(), key, 1)
		switch out {
		case outcomeStoreError:
			l.writeStoreError(w, r)
		case outcomeFailedOpen:
			// No Result to report, so no headers: publishing a zeroed
			// allowance would tell clients they are throttled when the truth
			// is that the limiter could not decide.
			next.ServeHTTP(w, r)
		case outcomeDenied:
			l.writeHeaders(w, res)
			w.Header().Set("Retry-After", strconv.Itoa(retryAfterSeconds(res.RetryAfter)))
			l.writeDenied(w, r)
		default:
			l.writeHeaders(w, res)
			next.ServeHTTP(w, r)
		}
	})
}

// writeHeaders publishes limit state according to the configured HeaderMode.
func (l *Limiter) writeHeaders(w http.ResponseWriter, res Result) {
	if l.headers == HeaderNone {
		return
	}
	limit := strconv.Itoa(l.cfg.Burst)
	remaining := strconv.Itoa(res.Remaining)
	reset := strconv.Itoa(retryAfterSeconds(res.RetryAfter))

	h := w.Header()
	if l.headers == HeaderBoth || l.headers == HeaderLegacy {
		h.Set("X-RateLimit-Limit", limit)
		h.Set("X-RateLimit-Remaining", remaining)
		h.Set("X-RateLimit-Reset", reset)
	}
	if l.headers == HeaderBoth || l.headers == HeaderStandard {
		h.Set("RateLimit-Limit", limit)
		h.Set("RateLimit-Remaining", remaining)
		h.Set("RateLimit-Reset", reset)
	}
}

func (l *Limiter) writeDenied(w http.ResponseWriter, r *http.Request) {
	if l.denied != nil {
		l.denied.ServeHTTP(w, r)
		return
	}
	http.Error(w, "Too Many Requests", http.StatusTooManyRequests)
}

func (l *Limiter) writeStoreError(w http.ResponseWriter, r *http.Request) {
	if l.storeErrored != nil {
		l.storeErrored.ServeHTTP(w, r)
		return
	}
	http.Error(w, "Service Unavailable", http.StatusServiceUnavailable)
}

func (l *Limiter) report(err error) {
	if l.onError != nil {
		l.onError(err)
	}
}

// retryAfterSeconds rounds d up to whole seconds, with a floor of 1 whenever
// there is anything to wait for. Rounding down would advertise a retry time at
// which the token is not yet available, inviting a client to retry into another
// rejection.
func retryAfterSeconds(d time.Duration) int {
	if d <= 0 {
		return 0
	}
	secs := (d + time.Second - 1) / time.Second
	if secs < 1 {
		return 1
	}
	if secs > math.MaxInt32 {
		return math.MaxInt32
	}
	return int(secs)
}

// lastIndexByte reports the index of the last b in s, or -1. It exists so that
// RemoteAddrKey can split "host:port" without the allocation and the error
// handling that net.SplitHostPort brings, on a path that runs per request.
func lastIndexByte(s string, b byte) int {
	for i := len(s) - 1; i >= 0; i-- {
		if s[i] == b {
			return i
		}
	}
	return -1
}

// trimBrackets removes the square brackets an IPv6 literal carries in a
// host:port pair, so that "[2001:db8::1]" and "2001:db8::1" key the same bucket
// rather than two.
func trimBrackets(s string) string {
	if len(s) >= 2 && s[0] == '[' && s[len(s)-1] == ']' {
		return s[1 : len(s)-1]
	}
	return s
}
