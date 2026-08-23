// Package realip_test holds the package's runnable examples.
//
// They live in the external test package rather than in realip itself for one
// specific reason: ExampleExtractor_KeyFunc has to show the extractor wired into
// ratelimit, and realip deliberately imports nothing outside the standard
// library — that is why [realip.Extractor.KeyFunc] returns a bare function type
// instead of a ratelimit.KeyFunc. Test files in package realip_test are compiled
// separately and are not part of the package's own import graph, so importing
// ratelimit here adds nothing to what a consumer of realip pulls in.
package realip_test

import (
	"fmt"
	"log"
	"net/http"
	"net/http/httptest"

	"github.com/JonasBorgesLM/moat/csrf"
	"github.com/JonasBorgesLM/moat/preset"
	"github.com/JonasBorgesLM/moat/ratelimit"
	"github.com/JonasBorgesLM/moat/realip"
)

// ExampleNew derives the client address behind a load balancer.
//
// The CIDRs are the balancer's, not the client's — this is the one parameter
// people get backwards, and getting it backwards is what the package exists to
// prevent. Trusting a range means "an address in here is allowed to tell me who
// the client is", so trusting too much lets a client forge its own identity by
// setting the header itself.
//
// The ranges below are the shape of a real deployment: an AWS VPC's private
// range for an internal ALB, plus the link-local range some managed proxies
// source from. Take yours from your infrastructure, not from a snippet.
func ExampleNew() {
	extractor, err := realip.New([]string{
		"10.0.0.0/8",       // the VPC the load balancer sits in
		"172.16.0.0/12",    // a second VPC, peered
		"169.254.169.0/24", // link-local, used by some managed proxies
	})
	if err != nil {
		log.Fatal(err)
	}

	// A request that arrived from the balancer at 10.0.1.7, which appended the
	// address it saw. The chain is walked right-to-left and stops at the first
	// address that is not a trusted proxy, so the untrusted values a client can
	// prepend are never reached.
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	r.RemoteAddr = "10.0.1.7:54321"
	r.Header.Set("X-Forwarded-For", "192.0.2.44, 203.0.113.9, 10.0.1.7")

	addr, err := extractor.ClientIP(r)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println(addr)

	// A client that forges the header on a direct connection gains nothing: its
	// own peer address is not trusted, so nothing in the header is read.
	direct := httptest.NewRequest(http.MethodGet, "/", nil)
	direct.RemoteAddr = "198.51.100.23:44444"
	direct.Header.Set("X-Forwarded-For", "10.0.0.1")

	forged, err := extractor.ClientIP(direct)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println(forged)

	// Output:
	// 203.0.113.9
	// 198.51.100.23
}

// ExampleExtractor_KeyFunc gives the rate limiter the client address to count.
//
// This is the pairing the package exists for. A limiter is only as good as the
// identity it counts, and behind a proxy http.Request.RemoteAddr is the proxy
// for every client — so without this the entire service shares one bucket, and
// any single client can hold everyone else at the limit. That is a denial of
// service that looks exactly like ordinary throttling from the outside, which is
// what makes it worth a mechanism rather than a warning.
func ExampleExtractor_KeyFunc() {
	extractor, err := realip.New([]string{"10.0.0.0/8"})
	if err != nil {
		log.Fatal(err)
	}

	limiter := ratelimit.New(20, 5, ratelimit.WithKeyFunc(extractor.KeyFunc()))

	mux := http.NewServeMux()
	mux.HandleFunc("/api/", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	})
	handler := limiter.Middleware(mux)

	// Two requests through the same proxy, from different clients: different
	// keys, so different buckets.
	for _, client := range []string{"203.0.113.9", "198.51.100.23"} {
		r := httptest.NewRequest(http.MethodGet, "/api/thing", nil)
		r.RemoteAddr = "10.0.1.7:54321"
		r.Header.Set("X-Forwarded-For", client+", 10.0.1.7")

		key, err := extractor.KeyFunc()(r)
		if err != nil {
			log.Fatal(err)
		}

		w := httptest.NewRecorder()
		handler.ServeHTTP(w, r)
		fmt.Printf("%s -> bucket %q, status %d\n", client, key, w.Code)
	}

	// Output:
	// 203.0.113.9 -> bucket "203.0.113.9", status 204
	// 198.51.100.23 -> bucket "198.51.100.23", status 204
}

// ExampleNew_viaPreset reaches the same wiring through preset.Config.
//
// preset.API builds the extractor and hands its KeyFunc to the limiter for you,
// so TrustedProxies here is the same list you would pass to realip.New. Prefer
// this when a preset already fits; drop to realip.New when you need a non-default
// source order, or the client address for something other than rate limiting.
//
// preset.API returns preset.ErrProxyTopologyUnspecified rather than build a
// chain whose limiter counts every client as one client, so the topology is not
// something you can leave unstated — DirectlyExposed is the answer when nothing
// fronts the server, and it is an answer, not a way to skip the question.
func ExampleNew_viaPreset() {
	key, err := csrf.GenerateSecret()
	if err != nil {
		log.Fatal(err)
	}

	chain, err := preset.API(preset.Config{
		CSRFSecret:      key,
		RateLimitBurst:  20,
		RateLimitPerSec: 5,
		TrustedProxies:  []string{"10.0.0.0/8"}, // your balancer, not your clients
	})
	if err != nil {
		log.Fatal(err)
	}
	_ = chain

	// Omitting both TrustedProxies and DirectlyExposed is refused.
	_, err = preset.API(preset.Config{
		CSRFSecret:      key,
		RateLimitBurst:  20,
		RateLimitPerSec: 5,
	})
	fmt.Println(err != nil)

	// Output:
	// true
}
