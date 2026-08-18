package redisstore

import (
	"context"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/JonasBorgesLM/moat/ratelimit"
	"github.com/redis/go-redis/v9"
)

// fakeScripter stands in for a Redis client so that the Go side of this store —
// argument marshalling, the EVALSHA/EVAL fallback, reply parsing, timeouts and
// error propagation — can be tested without a server. The script itself is
// exercised against real Redis in the integration suite, because only a real
// Redis can prove the atomicity claim.
type fakeScripter struct {
	mu sync.Mutex

	// reply is returned by whichever Eval variant is reached.
	reply any
	// err is returned instead of reply, if set.
	err error
	// noScript makes EvalSha fail the way a server does after a restart,
	// which is what drives the fallback to EVAL.
	noScript bool

	evalShaCalls int
	evalCalls    int
	lastKeys     []string
	lastArgs     []any
	lastDeadline time.Time
	hadDeadline  bool
}

func (f *fakeScripter) record(ctx context.Context, keys []string, args []any) {
	f.lastKeys = append([]string(nil), keys...)
	f.lastArgs = append([]any(nil), args...)
	f.lastDeadline, f.hadDeadline = ctx.Deadline()
}

func (f *fakeScripter) EvalSha(ctx context.Context, sha1 string, keys []string, args ...any) *redis.Cmd {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.evalShaCalls++
	f.record(ctx, keys, args)
	if f.noScript {
		return redis.NewCmdResult(nil, errNoScript)
	}
	return redis.NewCmdResult(f.reply, f.err)
}

func (f *fakeScripter) Eval(ctx context.Context, script string, keys []string, args ...any) *redis.Cmd {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.evalCalls++
	f.record(ctx, keys, args)
	return redis.NewCmdResult(f.reply, f.err)
}

func (f *fakeScripter) EvalRO(ctx context.Context, script string, keys []string, args ...any) *redis.Cmd {
	return f.Eval(ctx, script, keys, args...)
}

func (f *fakeScripter) EvalShaRO(ctx context.Context, sha1 string, keys []string, args ...any) *redis.Cmd {
	return f.EvalSha(ctx, sha1, keys, args...)
}

func (f *fakeScripter) ScriptExists(ctx context.Context, hashes ...string) *redis.BoolSliceCmd {
	return redis.NewBoolSliceResult(make([]bool, len(hashes)), nil)
}

func (f *fakeScripter) ScriptLoad(ctx context.Context, script string) *redis.StringCmd {
	return redis.NewStringResult("", nil)
}

// redisError implements redis.Error, the interface go-redis uses to recognize
// an error reported by the server rather than by the transport. A plain error
// value would not be recognized as NOSCRIPT, and the fallback would never fire
// -- which is exactly the bug this fake needs to be able to catch.
type redisError string

func (e redisError) Error() string { return string(e) }
func (e redisError) RedisError()   {}

// errNoScript is what a server answers after a restart or SCRIPT FLUSH, when
// the cached hash from a previous EVALSHA is no longer loaded.
var errNoScript = redisError("NOSCRIPT No matching script. Please use EVAL.")

func TestNew(t *testing.T) {
	if _, err := New(nil); err == nil {
		t.Error("New(nil) returned no error")
	}
	s, err := New(&fakeScripter{})
	if err != nil {
		t.Fatal(err)
	}
	if s.keyPrefix != DefaultKeyPrefix || s.idleTTL != DefaultIdleTTL || s.timeout != DefaultTimeout {
		t.Errorf("defaults not applied: %+v", s)
	}
	if err := s.Close(); err != nil {
		t.Errorf("Close: %v", err)
	}
}

// TestCloseDoesNotCloseTheClient pins the ownership rule: the client is shared
// with the rest of the application and must survive the store.
func TestCloseDoesNotCloseTheClient(t *testing.T) {
	fake := &fakeScripter{reply: []any{int64(1), int64(4), int64(0)}}
	s, err := New(fake)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Take(context.Background(), "k", ratelimit.Config{Burst: 5, PerSecond: 1}, time.Now()); err != nil {
		t.Errorf("the client stopped working after Close: %v", err)
	}
}

func TestTakeArguments(t *testing.T) {
	fake := &fakeScripter{reply: []any{int64(1), int64(9), int64(0)}}
	s, err := New(fake, WithKeyPrefix("app1:"))
	if err != nil {
		t.Fatal(err)
	}

	now := time.Unix(1_700_000_000, 0)
	if _, err := s.Take(context.Background(), "203.0.113.7", ratelimit.Config{Burst: 10, PerSecond: 2.5}, now); err != nil {
		t.Fatal(err)
	}

	if len(fake.lastKeys) != 1 || fake.lastKeys[0] != "app1:203.0.113.7" {
		t.Errorf("keys = %v, want [app1:203.0.113.7]", fake.lastKeys)
	}
	if len(fake.lastArgs) != 4 {
		t.Fatalf("args = %v, want 4 of them", fake.lastArgs)
	}
	if fake.lastArgs[0] != 10 {
		t.Errorf("burst arg = %v, want 10", fake.lastArgs[0])
	}
	if fake.lastArgs[1] != 2.5 {
		t.Errorf("rate arg = %v, want 2.5", fake.lastArgs[1])
	}
	if fake.lastArgs[2] != now.UnixMilli() {
		t.Errorf("now arg = %v, want %v; the store must use the caller's clock", fake.lastArgs[2], now.UnixMilli())
	}
}

// TestTakeUsesASingleKey matters for cluster mode: a script touching two keys
// in different slots is refused outright.
func TestTakeUsesASingleKey(t *testing.T) {
	fake := &fakeScripter{reply: []any{int64(1), int64(1), int64(0)}}
	s, _ := New(fake)
	if _, err := s.Take(context.Background(), "k", ratelimit.Config{Burst: 2, PerSecond: 1}, time.Now()); err != nil {
		t.Fatal(err)
	}
	if len(fake.lastKeys) != 1 {
		t.Errorf("the script touched %d keys; cluster mode requires exactly one", len(fake.lastKeys))
	}
}

// TestEvalShaFallsBackToEval covers the cold-start path: after a server restart
// or SCRIPT FLUSH the cached hash is gone, and the store must recover rather
// than fail every request.
func TestEvalShaFallsBackToEval(t *testing.T) {
	fake := &fakeScripter{reply: []any{int64(1), int64(3), int64(0)}, noScript: true}
	s, _ := New(fake)

	res, err := s.Take(context.Background(), "k", ratelimit.Config{Burst: 5, PerSecond: 1}, time.Now())
	if err != nil {
		t.Fatalf("Take: %v", err)
	}
	if !res.Allowed {
		t.Error("the fallback path produced a denial")
	}
	if fake.evalShaCalls != 1 {
		t.Errorf("EvalSha calls = %d, want 1 (the steady-state path must be tried first)", fake.evalShaCalls)
	}
	if fake.evalCalls != 1 {
		t.Errorf("Eval calls = %d, want 1 (NOSCRIPT must fall back)", fake.evalCalls)
	}
}

func TestTakeTimeout(t *testing.T) {
	tests := []struct {
		name        string
		timeout     time.Duration
		wantDeadine bool
	}{
		{"the default timeout bounds the round trip", 0, true}, // 0 means "leave the default"
		{"an explicit timeout is applied", 50 * time.Millisecond, true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			fake := &fakeScripter{reply: []any{int64(1), int64(1), int64(0)}}
			opts := []Option{}
			if tc.timeout > 0 {
				opts = append(opts, WithTimeout(tc.timeout))
			}
			s, _ := New(fake, opts...)
			if _, err := s.Take(context.Background(), "k", ratelimit.Config{Burst: 2, PerSecond: 1}, time.Now()); err != nil {
				t.Fatal(err)
			}
			if fake.hadDeadline != tc.wantDeadine {
				t.Errorf("deadline present = %v, want %v", fake.hadDeadline, tc.wantDeadine)
			}
		})
	}

	t.Run("a non-positive timeout removes the bound", func(t *testing.T) {
		fake := &fakeScripter{reply: []any{int64(1), int64(1), int64(0)}}
		s, _ := New(fake, WithTimeout(0))
		if _, err := s.Take(context.Background(), "k", ratelimit.Config{Burst: 2, PerSecond: 1}, time.Now()); err != nil {
			t.Fatal(err)
		}
		if fake.hadDeadline {
			t.Error("a deadline was set despite WithTimeout(0)")
		}
	})
}

// TestCallerDeadlineWins: a caller with a tighter deadline than the store's
// timeout must keep it, or a per-request budget is silently overridden.
func TestCallerDeadlineWins(t *testing.T) {
	fake := &fakeScripter{reply: []any{int64(1), int64(1), int64(0)}}
	s, _ := New(fake, WithTimeout(time.Hour))

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Millisecond)
	defer cancel()
	if _, err := s.Take(ctx, "k", ratelimit.Config{Burst: 2, PerSecond: 1}, time.Now()); err != nil {
		t.Fatal(err)
	}
	if time.Until(fake.lastDeadline) > time.Minute {
		t.Error("the store's timeout overrode a tighter caller deadline")
	}
}

// TestErrorsAreNeverConvertedToAnAllow is the core failure-policy guarantee:
// this store must never invent a permissive result.
func TestErrorsAreNeverConvertedToAnAllow(t *testing.T) {
	tests := []struct {
		name  string
		reply any
		err   error
	}{
		{"a connection error", nil, errors.New("dial tcp: connection refused")},
		{"a timeout", nil, context.DeadlineExceeded},
		{"a nil reply", nil, nil},
		{"a reply of the wrong type", "OK", nil},
		{"a reply with too few values", []any{int64(1), int64(2)}, nil},
		{"a reply with too many values", []any{int64(1), int64(2), int64(3), int64(4)}, nil},
		{"a reply with non-integer members", []any{"1", "2", "3"}, nil},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			s, _ := New(&fakeScripter{reply: tc.reply, err: tc.err})
			res, err := s.Take(context.Background(), "k", ratelimit.Config{Burst: 5, PerSecond: 1}, time.Now())
			if err == nil {
				t.Fatalf("Take returned no error; result %+v", res)
			}
			if res.Allowed {
				t.Error("a failure produced Allowed = true")
			}
		})
	}
}

func TestErrorMentionsTheKeyButWrapsTheCause(t *testing.T) {
	cause := errors.New("connection refused")
	s, _ := New(&fakeScripter{err: cause})

	_, err := s.Take(context.Background(), "203.0.113.7", ratelimit.Config{Burst: 5, PerSecond: 1}, time.Now())
	if !errors.Is(err, cause) {
		t.Errorf("error = %v, want it to wrap %v so callers can inspect the cause", err, cause)
	}
	if !strings.Contains(err.Error(), "203.0.113.7") {
		t.Errorf("error = %v, want it to name the key for operators", err)
	}
}

func TestParseReply(t *testing.T) {
	tests := []struct {
		name    string
		raw     any
		want    ratelimit.Result
		wantErr bool
	}{
		{
			name: "allowed with tokens left",
			raw:  []any{int64(1), int64(4), int64(0)},
			want: ratelimit.Result{Allowed: true, Remaining: 4},
		},
		{
			name: "allowed but the next request must wait",
			raw:  []any{int64(1), int64(0), int64(500)},
			want: ratelimit.Result{Allowed: true, Remaining: 0, RetryAfter: 500 * time.Millisecond},
		},
		{
			name: "denied",
			raw:  []any{int64(0), int64(0), int64(1200)},
			want: ratelimit.Result{Allowed: false, Remaining: 0, RetryAfter: 1200 * time.Millisecond},
		},
		{
			name: "a bucket that never refills reports the maximum wait, not a negative one",
			raw:  []any{int64(0), int64(0), int64(-1)},
			want: ratelimit.Result{Allowed: false, Remaining: 0, RetryAfter: time.Duration(1<<63 - 1)},
		},
		{
			name: "a negative remaining is clamped",
			raw:  []any{int64(0), int64(-3), int64(100)},
			want: ratelimit.Result{Allowed: false, Remaining: 0, RetryAfter: 100 * time.Millisecond},
		},
		{name: "a non-array reply", raw: int64(1), wantErr: true},
		{name: "a short array", raw: []any{int64(1)}, wantErr: true},
		{name: "string members", raw: []any{"1", "1", "1"}, wantErr: true},
		{name: "nil", raw: nil, wantErr: true},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := parseReply(tc.raw)
			if tc.wantErr {
				if err == nil {
					t.Fatalf("parseReply(%#v) = %+v, want an error", tc.raw, got)
				}
				if !errors.Is(err, ErrUnexpectedReply) {
					t.Errorf("error = %v, want it to wrap ErrUnexpectedReply", err)
				}
				return
			}
			if err != nil {
				t.Fatalf("parseReply(%#v): %v", tc.raw, err)
			}
			if got != tc.want {
				t.Errorf("parseReply(%#v) = %+v, want %+v", tc.raw, got, tc.want)
			}
		})
	}
}

func TestTTL(t *testing.T) {
	tests := []struct {
		name    string
		idleTTL time.Duration
		burst   int
		rate    float64
		wantMs  int64
	}{
		{
			name:    "the idle floor applies when refill is quick",
			idleTTL: 10 * time.Minute,
			burst:   10,
			rate:    10, // refills in 1s
			wantMs:  600_000,
		},
		{
			// Expiring a bucket before it refills would hand its client a fresh
			// allowance, so the refill window wins.
			name:    "a slow refill extends the TTL past the idle floor",
			idleTTL: time.Second,
			burst:   100,
			rate:    1, // refills in 100s
			wantMs:  100_000,
		},
		{
			name:    "a bucket that never refills keeps the idle floor",
			idleTTL: 30 * time.Second,
			burst:   5,
			rate:    0,
			wantMs:  30_000,
		},
		{
			name:    "the TTL is never non-positive",
			idleTTL: time.Nanosecond,
			burst:   1,
			rate:    0,
			wantMs:  1,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			s := &Store{idleTTL: tc.idleTTL}
			if got := s.ttlMillis(tc.burst, tc.rate); got != tc.wantMs {
				t.Errorf("ttlMillis(%d, %v) = %d ms, want %d ms", tc.burst, tc.rate, got, tc.wantMs)
			}
		})
	}
}

// TestConfigIsNormalized: a misconfigured limiter must reach Redis as
// restrictive values, never as a NaN or a negative capacity the script would
// misinterpret.
func TestConfigIsNormalized(t *testing.T) {
	nan := func() float64 { var z float64; return z / z }()

	tests := []struct {
		name      string
		cfg       ratelimit.Config
		wantBurst any
		wantRate  any
	}{
		{"valid values pass through", ratelimit.Config{Burst: 7, PerSecond: 3}, 7, 3.0},
		{"a zero burst becomes one", ratelimit.Config{Burst: 0, PerSecond: 1}, 1, 1.0},
		{"a negative burst becomes one", ratelimit.Config{Burst: -4, PerSecond: 1}, 1, 1.0},
		{"a negative rate becomes never-refill", ratelimit.Config{Burst: 3, PerSecond: -2}, 3, 0.0},
		{"NaN becomes never-refill", ratelimit.Config{Burst: 3, PerSecond: nan}, 3, 0.0},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			fake := &fakeScripter{reply: []any{int64(1), int64(1), int64(0)}}
			s, _ := New(fake)
			if _, err := s.Take(context.Background(), "k", tc.cfg, time.Now()); err != nil {
				t.Fatal(err)
			}
			if fake.lastArgs[0] != tc.wantBurst {
				t.Errorf("burst = %v, want %v", fake.lastArgs[0], tc.wantBurst)
			}
			if fake.lastArgs[1] != tc.wantRate {
				t.Errorf("rate = %v, want %v", fake.lastArgs[1], tc.wantRate)
			}
		})
	}
}

// TestScriptIsEmbedded guards the go:embed wiring: an empty script would fail
// only at runtime, against a real server, which is the worst place to find out.
func TestScriptIsEmbedded(t *testing.T) {
	if len(script) < 500 {
		t.Fatalf("embedded script is %d bytes; token_bucket.lua did not load", len(script))
	}
	for _, needed := range []string{"HMGET", "HSET", "PEXPIRE", "KEYS[1]", "ARGV[4]"} {
		if !strings.Contains(script, needed) {
			t.Errorf("embedded script does not contain %q", needed)
		}
	}
	// The script must be a single atomic decision: no client round trip in the
	// middle, and no reliance on the server clock, which would break the
	// caller-supplied-time contract of ratelimit.Store.
	if strings.Contains(script, "redis.call('TIME'") || strings.Contains(script, `redis.call("TIME"`) {
		t.Error("the script reads the server clock; ratelimit.Store requires the caller's now")
	}
}

func TestStoreSatisfiesTheInterface(t *testing.T) {
	var _ ratelimit.Store = (*Store)(nil)
}
