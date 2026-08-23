package redisstore_test

import (
	"log"
	"net/http"
	"time"

	"github.com/JonasBorgesLM/moat/ratelimit"
	"github.com/JonasBorgesLM/moat/redisstore"
	"github.com/redis/go-redis/v9"
)

// ExampleNew wires a shared, Redis-backed limit across every instance of an
// application.
//
// This example is compile-only: it needs a reachable Redis, so there is no
// deterministic output to assert. A flaky example teaches contributors to
// ignore red CI, which is a worse outcome than an unverified snippet.
func ExampleNew() {
	client := redis.NewClient(&redis.Options{
		Addr: "localhost:6379",
		// Bound the dial and the round trip. This sits in front of every
		// request, and with the limiter failing closed, a backend that hangs
		// rather than refusing takes the endpoint down with it.
		DialTimeout:  200 * time.Millisecond,
		ReadTimeout:  200 * time.Millisecond,
		WriteTimeout: 200 * time.Millisecond,
	})
	defer client.Close()

	store, err := redisstore.New(client, redisstore.WithKeyPrefix("myapp:ratelimit:"))
	if err != nil {
		return
	}
	// Close releases the store; the client stays open, since it belongs to the
	// application and is usually shared.
	defer store.Close()

	limiter := ratelimit.New(20, 5,
		ratelimit.WithStore(store),
		ratelimit.WithOnError(func(err error) {
			// A Redis outage is invisible without this: the limiter fails
			// closed, and every request is rejected with no signal to
			// operators. Route it into your logger and alerting.
			_ = err
		}),
	)
	defer limiter.Close()

	mux := http.NewServeMux()

	// Timeouts, because net/http has none by default. Without them a slow
	// client holds a connection open indefinitely -- a denial of service that
	// no middleware in this library can see, let alone prevent.
	srv := &http.Server{
		Addr:              ":8080",
		Handler:           limiter.Middleware(mux),
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       15 * time.Second,
		WriteTimeout:      30 * time.Second,
		IdleTimeout:       60 * time.Second,
	}
	_ = srv.ListenAndServe()
}

// ExampleNew_failOpen shows the availability trade-off. The default rejects
// requests when Redis is unreachable, on the grounds that a limiter which
// silently stops limiting during an outage is not a control. For an endpoint
// where being unreachable is worse than being unthrottled, say so explicitly.
//
// Compile-only: it needs a reachable Redis.
func ExampleNew_failOpen() {
	client := redis.NewClient(&redis.Options{Addr: "localhost:6379"})
	defer client.Close()

	store, err := redisstore.New(client)
	if err != nil {
		return
	}
	defer store.Close()

	limiter := ratelimit.New(100, 50,
		ratelimit.WithStore(store),
		ratelimit.WithFailureMode(ratelimit.FailOpen),
		ratelimit.WithOnError(func(err error) { _ = err }),
	)
	defer limiter.Close()
}

// ExampleStore_EvictionCheck surfaces a check that was skipped.
//
// [redisstore.New] refuses to build a Store against a server it can see will
// evict keys, because eviction silently resets rate limits. What it cannot do is
// establish that everywhere: on ElastiCache, MemoryDB, Upstash and Azure Cache,
// CONFIG is disabled or renamed, so the check is skipped and construction
// proceeds. Those are also where most production deployments run — the check is
// loudest in local Docker and quietest in production.
//
// So a Store that constructed without error has not necessarily been verified.
// Asking is one line, and belongs in startup logging next to the other
// configuration a deployment cannot infer for itself.
//
// This example is compile-only: it needs a reachable Redis.
func ExampleStore_EvictionCheck() {
	client := redis.NewClient(&redis.Options{
		Addr:         "localhost:6379",
		DialTimeout:  200 * time.Millisecond,
		ReadTimeout:  200 * time.Millisecond,
		WriteTimeout: 200 * time.Millisecond,
	})
	defer client.Close()

	store, err := redisstore.New(client)
	if err != nil {
		// Includes redisstore.ErrUnsafeEvictionPolicy: the server was asked and
		// answered that it evicts.
		log.Fatalf("redis store: %v", err)
	}
	defer store.Close()

	// Not an error, and not necessarily a problem — but it is the difference
	// between "this server will not evict" and "nobody asked". Only the operator
	// can close that gap, and only if they are told it is open.
	if check := store.EvictionCheck(); !check.Verified() {
		log.Printf("redisstore: eviction policy unverified (%s); "+
			"confirm maxmemory-policy is noeviction on every node", check)
	}
}
