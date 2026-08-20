package redisstore

import (
	"context"
	"errors"
	"testing"

	"github.com/redis/go-redis/v9"
)

// configuredScripter is a fakeScripter that can also answer CONFIG GET, which
// is what makes New's eviction check reachable. Clients that cannot answer are
// covered by fakeScripter itself.
type configuredScripter struct {
	fakeScripter
	config map[string]string
	err    error
	calls  int
}

func (c *configuredScripter) ConfigGet(_ context.Context, _ string) *redis.MapStringStringCmd {
	c.calls++
	return redis.NewMapStringStringResult(c.config, c.err)
}

// TestNewRejectsAnEvictingServer pins the check.
//
// Every policy other than noeviction is refused, and the volatile-* family is
// refused for the same reason as allkeys-*: every bucket carries a TTL, so
// "volatile" excludes nothing here. volatile-ttl deserves its own line because
// it is the one that reads like a safe compromise — it is not. Bucket TTLs are
// all refreshed to the same value on every call, so "nearest expiry" is
// "longest idle" restated, which is the recency ordering that lands the eviction
// on whichever client was most recently throttled.
func TestNewRejectsAnEvictingServer(t *testing.T) {
	for _, policy := range []string{
		"allkeys-lru", "allkeys-lfu", "allkeys-random",
		"volatile-lru", "volatile-lfu", "volatile-random", "volatile-ttl",
		"ALLKEYS-LRU", // the reply is not required to be lowercase
	} {
		t.Run(policy, func(t *testing.T) {
			c := &configuredScripter{config: map[string]string{
				"maxmemory":        "1073741824",
				"maxmemory-policy": policy,
			}}
			s, err := New(c)
			if !errors.Is(err, ErrUnsafeEvictionPolicy) {
				t.Fatalf("New error = %v, want ErrUnsafeEvictionPolicy", err)
			}
			if s != nil {
				t.Error("New returned a Store alongside its error")
			}
			// The message has to name the policy, or an operator cannot act on
			// it without going to look the setting up themselves.
			if !contains(err.Error(), policy) {
				t.Errorf("error does not name the offending policy: %v", err)
			}
		})
	}
}

// TestNewAcceptsASafeServer is the false-positive guard: the check must cost
// nothing to a correctly configured deployment, and must not fire on a server
// that has no memory ceiling at all, where the policy is inert whatever it says.
func TestNewAcceptsASafeServer(t *testing.T) {
	tests := []struct {
		name   string
		config map[string]string
	}{
		{"noeviction with a ceiling", map[string]string{"maxmemory": "1073741824", "maxmemory-policy": "noeviction"}},
		{"no ceiling, so the policy never fires", map[string]string{"maxmemory": "0", "maxmemory-policy": "allkeys-lru"}},
		{"no ceiling reported at all", map[string]string{"maxmemory-policy": "allkeys-lru"}},
		{"no policy reported", map[string]string{"maxmemory": "1073741824"}},
		{"an unparsable ceiling is not a verdict", map[string]string{"maxmemory": "lots", "maxmemory-policy": "allkeys-lru"}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := New(&configuredScripter{config: tc.config}); err != nil {
				t.Errorf("New = %v, want no error", err)
			}
		})
	}
}

// TestNewStaysSilentWhenItCannotKnow pins the best-effort half of the contract.
// Managed Redis usually disables or renames CONFIG, and an unreachable server
// answers nothing at all. In both cases the library genuinely cannot tell, and
// guessing would either reject working deployments or claim an assurance it does
// not have — so construction proceeds.
func TestNewStaysSilentWhenItCannotKnow(t *testing.T) {
	t.Run("CONFIG is disabled", func(t *testing.T) {
		c := &configuredScripter{err: errors.New("ERR unknown command 'CONFIG'")}
		if _, err := New(c); err != nil {
			t.Errorf("New = %v, want no error when CONFIG cannot be read", err)
		}
		if c.calls != 1 {
			t.Errorf("ConfigGet called %d times, want 1", c.calls)
		}
	})

	t.Run("the client cannot answer CONFIG at all", func(t *testing.T) {
		// fakeScripter implements redis.Scripter and nothing more, which is the
		// case for a custom client or a test double.
		if _, err := New(&fakeScripter{}); err != nil {
			t.Errorf("New = %v, want no error for a client with no CONFIG", err)
		}
	})
}

// TestInsecureAllowKeyEvictionIsTheOnlyWayPast mirrors realip's opt-out: the
// dangerous deployment stays reachable, but only by naming it. It also skips the
// round trip, which is what makes it usable when Redis is not up yet.
func TestInsecureAllowKeyEvictionIsTheOnlyWayPast(t *testing.T) {
	c := &configuredScripter{config: map[string]string{
		"maxmemory":        "1073741824",
		"maxmemory-policy": "allkeys-lru",
	}}
	s, err := New(c, InsecureAllowKeyEviction())
	if err != nil {
		t.Fatalf("New with InsecureAllowKeyEviction: %v", err)
	}
	if s == nil {
		t.Fatal("New returned no Store")
	}
	if c.calls != 0 {
		t.Errorf("ConfigGet called %d times, want 0: the opt-out should skip the round trip", c.calls)
	}
}

func contains(haystack, needle string) bool {
	for i := 0; i+len(needle) <= len(haystack); i++ {
		if haystack[i:i+len(needle)] == needle {
			return true
		}
	}
	return false
}
