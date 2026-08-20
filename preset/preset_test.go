package preset_test

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/JonasBorgesLM/moat/csrf"
	"github.com/JonasBorgesLM/moat/preset"
	"github.com/JonasBorgesLM/moat/ratelimit"
	"github.com/JonasBorgesLM/moat/realip"
	"github.com/JonasBorgesLM/moat/secret"
	"github.com/JonasBorgesLM/moat/secureheaders"
	"github.com/JonasBorgesLM/moat/validate"
)

const host = "app.example.com"

func testSecret(t *testing.T) secret.Value {
	t.Helper()
	v, err := csrf.GenerateSecret()
	if err != nil {
		t.Fatal(err)
	}
	return v
}

func okHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, "ok")
	})
}

// TestAPIRefusesToOmitAProtection is the reason API returns an error at all.
func TestAPIRefusesToOmitAProtection(t *testing.T) {
	valid := testSecret(t)

	tests := []struct {
		name    string
		cfg     preset.Config
		wantErr error
	}{
		{
			name:    "a missing CSRF secret is an error, not a silent omission",
			cfg:     preset.Config{RateLimitBurst: 10, RateLimitPerSec: 5},
			wantErr: preset.ErrMissingCSRFSecret,
		},
		{
			name:    "a missing rate limit is an error",
			cfg:     preset.Config{CSRFSecret: valid},
			wantErr: preset.ErrMissingRateLimit,
		},
		{
			name:    "a zero burst is not a rate limit",
			cfg:     preset.Config{CSRFSecret: valid, RateLimitBurst: 0, RateLimitPerSec: 5},
			wantErr: preset.ErrMissingRateLimit,
		},
		{
			name:    "a zero rate is not a rate limit",
			cfg:     preset.Config{CSRFSecret: valid, RateLimitBurst: 10, RateLimitPerSec: 0},
			wantErr: preset.ErrMissingRateLimit,
		},
		{
			name:    "an entirely zero config is refused",
			cfg:     preset.Config{},
			wantErr: preset.ErrMissingCSRFSecret,
		},
		{
			name:    "a short CSRF secret is refused",
			cfg:     preset.Config{CSRFSecret: secret.New([]byte("too-short")), RateLimitBurst: 10, RateLimitPerSec: 5, DirectlyExposed: true},
			wantErr: csrf.ErrSecretTooShort,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			chain, err := preset.API(tc.cfg)
			if !errors.Is(err, tc.wantErr) {
				t.Fatalf("error = %v, want one wrapping %v", err, tc.wantErr)
			}
			// The returned chain must not be usable: handing back a working
			// chain alongside an error is how a caller ends up ignoring the
			// error and shipping the omission.
			if chain.Len() != 0 {
				t.Errorf("a chain with %d middleware was returned alongside an error", chain.Len())
			}
		})
	}
}

// TestAPIAcceptsDeliberateOmissions: the opt-out has to actually work, or
// people will route around the preset entirely.
func TestAPIAcceptsDeliberateOmissions(t *testing.T) {
	tests := []struct {
		name string
		cfg  preset.Config
	}{
		{
			name: "CSRF disabled explicitly",
			cfg:  preset.Config{DisableCSRF: true, RateLimitBurst: 10, RateLimitPerSec: 5, DirectlyExposed: true},
		},
		{
			name: "rate limiting disabled explicitly",
			cfg:  preset.Config{CSRFSecret: testSecret(t), DisableRateLimit: true},
		},
		{
			name: "both disabled explicitly",
			cfg:  preset.Config{DisableCSRF: true, DisableRateLimit: true},
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			chain, err := preset.API(tc.cfg)
			if err != nil {
				t.Fatalf("API: %v", err)
			}
			rec := httptest.NewRecorder()
			r := httptest.NewRequest(http.MethodGet, "https://"+host+"/", nil)
			r.Host = host
			chain.Then(okHandler()).ServeHTTP(rec, r)
			if rec.Code != http.StatusOK {
				t.Errorf("status = %d, want 200", rec.Code)
			}
			// Headers and the body limit are unconditional.
			if rec.Header().Get("Content-Security-Policy") == "" {
				t.Error("security headers missing")
			}
		})
	}
}

// TestAPIRejectsContradictoryConfig: guessing which half of a contradiction was
// meant would silently enable or disable a control.
func TestAPIRejectsContradictoryConfig(t *testing.T) {
	tests := []struct {
		name string
		cfg  preset.Config
	}{
		{
			name: "a secret alongside DisableCSRF",
			cfg:  preset.Config{CSRFSecret: testSecret(t), DisableCSRF: true, RateLimitBurst: 10, RateLimitPerSec: 5},
		},
		{
			name: "limits alongside DisableRateLimit",
			cfg:  preset.Config{CSRFSecret: testSecret(t), DisableRateLimit: true, RateLimitBurst: 10, RateLimitPerSec: 5},
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := preset.API(tc.cfg); err == nil {
				t.Error("a contradictory configuration was accepted")
			}
		})
	}
}

// TestMiddlewareOrder is the ordering contract, asserted one adjacent pair at a
// time: for each pair, a request that trips both must be answered by the
// earlier one.
func TestMiddlewareOrder(t *testing.T) {
	sec := testSecret(t)

	// Burst of 1 so the second request is over the limit.
	newChain := func(t *testing.T) http.Handler {
		t.Helper()
		chain, err := preset.API(preset.Config{
			DirectlyExposed: true,
			CSRFSecret:      sec,
			RateLimitBurst:  1,
			RateLimitPerSec: 1,
			MaxBodyBytes:    32,
		})
		if err != nil {
			t.Fatal(err)
		}
		return chain.Then(okHandler())
	}

	// oversized POST with no CSRF token: trips both the body limit and CSRF.
	oversizedNoToken := func() *http.Request {
		body := "field=" + strings.Repeat("A", 500)
		r := httptest.NewRequest(http.MethodPost, "https://"+host+"/", strings.NewReader(body))
		r.Host = host
		r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		r.Header.Set("Origin", "https://"+host)
		return r
	}

	t.Run("the body limit runs before CSRF", func(t *testing.T) {
		// If CSRF ran first it would answer 403, having already parsed a
		// 500-byte form body that no limit had bounded.
		rec := httptest.NewRecorder()
		newChain(t).ServeHTTP(rec, oversizedNoToken())
		if rec.Code != http.StatusRequestEntityTooLarge {
			t.Errorf("status = %d, want 413: the size limit must be in place before CSRF parses a form", rec.Code)
		}
	})

	t.Run("rate limiting runs before the body limit", func(t *testing.T) {
		h := newChain(t)
		// Spend the burst.
		h.ServeHTTP(httptest.NewRecorder(), oversizedNoToken())
		// The next request trips the limiter and the body limit; the limiter
		// must win.
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, oversizedNoToken())
		if rec.Code != http.StatusTooManyRequests {
			t.Errorf("status = %d, want 429: the limiter must reject before any other work", rec.Code)
		}
	})

	t.Run("security headers are set before the body limit rejects", func(t *testing.T) {
		rec := httptest.NewRecorder()
		newChain(t).ServeHTTP(rec, oversizedNoToken())
		if rec.Code != http.StatusRequestEntityTooLarge {
			t.Fatalf("status = %d, want 413", rec.Code)
		}
		if rec.Header().Get("X-Content-Type-Options") != "nosniff" {
			t.Error("a 413 was written without security headers")
		}
	})

	// Security headers run outermost, ahead of the rate limiter, specifically
	// so that a rejection never ships unprotected: an error response is still
	// a response, and is exactly as capable of being framed, sniffed as a
	// different content type, or rendered without a CSP as a 200 is. This
	// used to be a documented gap -- a 429 carried none of these headers --
	// and was fixed rather than shipped; this test asserts the fix, not the
	// old behavior it replaced.
	t.Run("a 429 carries the security headers", func(t *testing.T) {
		h := newChain(t)
		r := func() *http.Request {
			req := httptest.NewRequest(http.MethodGet, "https://"+host+"/", nil)
			req.Host = host
			return req
		}
		h.ServeHTTP(httptest.NewRecorder(), r())
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, r())

		if rec.Code != http.StatusTooManyRequests {
			t.Fatalf("status = %d, want 429", rec.Code)
		}
		if rec.Header().Get("Content-Security-Policy") == "" {
			t.Error("a 429 was written without a Content-Security-Policy header; security headers must run outermost")
		}
		if rec.Header().Get("X-Content-Type-Options") != "nosniff" {
			t.Error("a 429 was written without X-Content-Type-Options: nosniff")
		}
		if rec.Header().Get("Strict-Transport-Security") == "" {
			t.Error("a 429 was written without Strict-Transport-Security")
		}
	})
}

// TestEndToEnd walks the flow a browser actually performs.
func TestEndToEnd(t *testing.T) {
	chain, err := preset.API(preset.Config{
		DirectlyExposed: true,
		CSRFSecret:      testSecret(t),
		RateLimitBurst:  20,
		RateLimitPerSec: 10,
	})
	if err != nil {
		t.Fatal(err)
	}

	var issued string
	handler := chain.Then(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if tok, ok := csrf.Token(r); ok {
			issued = tok
		}
		fmt.Fprint(w, "ok")
	}))

	// 1. GET the form: headers set, cookie and token issued.
	rec := httptest.NewRecorder()
	get := httptest.NewRequest(http.MethodGet, "https://"+host+"/form", nil)
	get.Host = host
	handler.ServeHTTP(rec, get)

	if rec.Code != http.StatusOK {
		t.Fatalf("GET status = %d", rec.Code)
	}
	for _, h := range []string{"Content-Security-Policy", "Strict-Transport-Security", "X-Frame-Options", "X-Content-Type-Options", "Referrer-Policy"} {
		if rec.Header().Get(h) == "" {
			t.Errorf("GET response missing %s", h)
		}
	}
	if rec.Header().Get("RateLimit-Limit") == "" {
		t.Error("GET response missing rate-limit headers")
	}
	cookies := rec.Result().Cookies()
	if len(cookies) != 1 || issued == "" {
		t.Fatalf("GET issued %d cookies and token %q", len(cookies), issued)
	}

	post := func(token string) *httptest.ResponseRecorder {
		body := url.Values{csrf.DefaultFieldName: {token}, "amount": {"1"}}.Encode()
		r := httptest.NewRequest(http.MethodPost, "https://"+host+"/transfer", strings.NewReader(body))
		r.Host = host
		r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		r.Header.Set("Origin", "https://"+host)
		r.AddCookie(cookies[0])
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, r)
		return rec
	}

	// 2. POST replaying the cookie and the token succeeds.
	if rec := post(issued); rec.Code != http.StatusOK {
		t.Errorf("POST with a valid token: status = %d, want 200 (body %q)", rec.Code, rec.Body)
	}
	// 3. POST with a tampered token fails.
	//
	// The mutation is on the *first* character deliberately. Changing the last
	// one used to look equivalent and was not: the final base64 character of a
	// token carries four significant bits and two unused ones, so replacing it
	// left the decoded token unchanged about a quarter of the time and this
	// assertion passed without anything having been tampered with. It made the
	// test flaky at roughly 20%, and it would have gone on "passing" against a
	// library that accepted tampered tokens outright.
	tampered := "A" + issued[1:]
	if issued[0] == 'A' {
		tampered = "B" + issued[1:]
	}
	if rec := post(tampered); rec.Code != http.StatusForbidden {
		t.Errorf("POST with a tampered token: status = %d, want 403", rec.Code)
	}
	// 4. POST with no token fails.
	if rec := post(""); rec.Code != http.StatusForbidden {
		t.Errorf("POST with no token: status = %d, want 403", rec.Code)
	}
}

func TestMaxBodyBytes(t *testing.T) {
	tests := []struct {
		name       string
		limit      int64
		bodyLen    int
		wantStatus int
	}{
		{"under the default limit", 0, 100, http.StatusForbidden}, // reaches CSRF, which rejects
		{"over an explicit limit", 16, 100, http.StatusRequestEntityTooLarge},
		{"under an explicit limit", 4096, 100, http.StatusForbidden},
		{"a negative limit rejects any body", -1, 1, http.StatusRequestEntityTooLarge},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			chain, err := preset.API(preset.Config{
				DirectlyExposed: true,
				CSRFSecret:      testSecret(t),
				RateLimitBurst:  10,
				RateLimitPerSec: 10,
				MaxBodyBytes:    tc.limit,
			})
			if err != nil {
				t.Fatal(err)
			}
			r := httptest.NewRequest(http.MethodPost, "https://"+host+"/", strings.NewReader(strings.Repeat("A", tc.bodyLen)))
			r.Host = host
			r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			r.Header.Set("Origin", "https://"+host)

			rec := httptest.NewRecorder()
			chain.Then(okHandler()).ServeHTTP(rec, r)
			if rec.Code != tc.wantStatus {
				t.Errorf("status = %d, want %d", rec.Code, tc.wantStatus)
			}
		})
	}
}

// TestOptionsArePassedThrough checks that per-component overrides reach the
// component, so that adopting the preset does not mean giving up tuning.
func TestOptionsArePassedThrough(t *testing.T) {
	chain, err := preset.API(preset.Config{
		DirectlyExposed: true,
		CSRFSecret:      testSecret(t),
		RateLimitBurst:  10,
		RateLimitPerSec: 10,
		HeaderOptions: []secureheaders.Option{
			secureheaders.WithCSP("default-src 'self' https://cdn.example.com"),
		},
		CSRFOptions: []csrf.Option{
			csrf.WithHeaderName("X-App-Token"),
		},
		RateLimitOptions: []ratelimit.Option{
			ratelimit.WithHeaders(ratelimit.HeaderStandard),
		},
	})
	if err != nil {
		t.Fatal(err)
	}

	var issued string
	handler := chain.Then(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		issued, _ = csrf.Token(r)
	}))

	rec := httptest.NewRecorder()
	get := httptest.NewRequest(http.MethodGet, "https://"+host+"/", nil)
	get.Host = host
	handler.ServeHTTP(rec, get)

	if got, want := rec.Header().Get("Content-Security-Policy"), "default-src 'self' https://cdn.example.com"; got != want {
		t.Errorf("CSP = %q, want %q", got, want)
	}
	if rec.Header().Get("X-RateLimit-Limit") != "" {
		t.Error("legacy rate-limit headers present despite HeaderStandard")
	}
	if rec.Header().Get("RateLimit-Limit") == "" {
		t.Error("standard rate-limit headers missing")
	}

	// The renamed CSRF header is the one that works.
	cookie := rec.Result().Cookies()[0]
	post := func(header string) int {
		r := httptest.NewRequest(http.MethodPost, "https://"+host+"/", nil)
		r.Host = host
		r.Header.Set("Origin", "https://"+host)
		r.Header.Set(header, issued)
		r.AddCookie(cookie)
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, r)
		return rec.Code
	}
	if got := post("X-App-Token"); got != http.StatusOK {
		t.Errorf("POST with the configured header: status = %d, want 200", got)
	}
	if got := post("X-CSRF-Token"); got != http.StatusForbidden {
		t.Errorf("POST with the default header after renaming: status = %d, want 403", got)
	}
}

// TestTrustedOrigins checks the Config field reaches the CSRF Origin check.
func TestTrustedOrigins(t *testing.T) {
	chain, err := preset.API(preset.Config{
		DirectlyExposed: true,
		CSRFSecret:      testSecret(t),
		RateLimitBurst:  10,
		RateLimitPerSec: 10,
		TrustedOrigins:  []string{"https://console.example.com"},
	})
	if err != nil {
		t.Fatal(err)
	}

	var issued string
	handler := chain.Then(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		issued, _ = csrf.Token(r)
	}))

	rec := httptest.NewRecorder()
	get := httptest.NewRequest(http.MethodGet, "https://"+host+"/", nil)
	get.Host = host
	handler.ServeHTTP(rec, get)
	cookie := rec.Result().Cookies()[0]

	post := func(origin string) int {
		r := httptest.NewRequest(http.MethodPost, "https://"+host+"/", nil)
		r.Host = host
		r.Header.Set("Origin", origin)
		r.Header.Set(csrf.DefaultHeaderName, issued)
		r.AddCookie(cookie)
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, r)
		return rec.Code
	}

	if got := post("https://console.example.com"); got != http.StatusOK {
		t.Errorf("listed origin: status = %d, want 200", got)
	}
	// With an allow-list configured, the request's own host is no longer
	// automatically trusted.
	if got := post("https://" + host); got != http.StatusForbidden {
		t.Errorf("unlisted origin: status = %d, want 403", got)
	}
}

// TestOnErrorReceivesStoreFailures: without this hook a store outage is
// invisible, because the library never logs.
func TestOnErrorReceivesStoreFailures(t *testing.T) {
	outage := errors.New("redis: connection refused")
	var reported error

	chain, err := preset.API(preset.Config{
		DirectlyExposed: true,
		CSRFSecret:      testSecret(t),
		RateLimitBurst:  10,
		RateLimitPerSec: 10,
		RateLimitStore:  failingStore{err: outage},
		OnError:         func(err error) { reported = err },
	})
	if err != nil {
		t.Fatal(err)
	}

	rec := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "https://"+host+"/", nil)
	r.Host = host
	chain.Then(okHandler()).ServeHTTP(rec, r)

	if rec.Code == http.StatusOK {
		t.Error("a store outage was served anyway; the preset must fail closed")
	}
	if !errors.Is(reported, outage) {
		t.Errorf("OnError got %v, want %v", reported, outage)
	}
}

type failingStore struct{ err error }

func (s failingStore) TakeN(context.Context, string, int, ratelimit.Config, time.Time) (ratelimit.Result, error) {
	return ratelimit.Result{}, s.err
}
func (s failingStore) Close() error { return nil }

// TestSharedStoreIsUsed confirms Config.RateLimitStore actually replaces the
// in-process one, which is what makes the limit shared across instances.
func TestSharedStoreIsUsed(t *testing.T) {
	shared := ratelimit.NewMemoryStore()
	t.Cleanup(func() { _ = shared.Close() })

	newChain := func() http.Handler {
		chain, err := preset.API(preset.Config{
			DirectlyExposed: true,
			DisableCSRF:     true,
			RateLimitBurst:  1,
			RateLimitPerSec: 0.001,
			RateLimitStore:  shared,
		})
		if err != nil {
			t.Fatal(err)
		}
		return chain.Then(okHandler())
	}

	// Two chains stand in for two instances of the application.
	instanceA, instanceB := newChain(), newChain()

	req := func() *http.Request {
		r := httptest.NewRequest(http.MethodGet, "https://"+host+"/", nil)
		r.Host = host
		r.RemoteAddr = "203.0.113.50:1234"
		return r
	}

	recA := httptest.NewRecorder()
	instanceA.ServeHTTP(recA, req())
	if recA.Code != http.StatusOK {
		t.Fatalf("instance A: status = %d, want 200", recA.Code)
	}

	recB := httptest.NewRecorder()
	instanceB.ServeHTTP(recB, req())
	if recB.Code != http.StatusTooManyRequests {
		t.Errorf("instance B: status = %d, want 429; the store is not shared, so each instance enforces its own limit", recB.Code)
	}
}

func ExampleAPI() {
	// In production, load this from your secret store.
	key := secret.New([]byte("a-32-byte-or-longer-secret-value"))

	chain, err := preset.API(preset.Config{
		DirectlyExposed: true,
		CSRFSecret:      key,
		RateLimitBurst:  20,
		RateLimitPerSec: 5,
	})
	if err != nil {
		fmt.Println("preset:", err)
		return
	}

	mux := http.NewServeMux()
	handler := chain.Then(mux)

	rec := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "https://app.example.com/", nil)
	r.Host = "app.example.com"
	handler.ServeHTTP(rec, r)

	fmt.Println(rec.Header().Get("X-Frame-Options"))
	fmt.Println(rec.Header().Get("X-Content-Type-Options"))
	// Output:
	// DENY
	// nosniff
}

// ExampleAPI_missingSecret shows the failure this package exists to cause: a
// preset that cannot build a complete chain says so instead of quietly
// shipping without CSRF protection.
func ExampleAPI_missingSecret() {
	_, err := preset.API(preset.Config{
		DirectlyExposed: true,
		RateLimitBurst:  20,
		RateLimitPerSec: 5,
	})
	fmt.Println(err)
	// Output: preset: CSRFSecret is required unless DisableCSRF is set
}

// ExampleAPI_bearerTokenAPI opts out of CSRF deliberately. A request forged by
// another origin cannot set an Authorization header, and the browser will not
// attach one, so an API authenticated only that way is not exposed to CSRF.
func ExampleAPI_bearerTokenAPI() {
	chain, err := preset.API(preset.Config{
		DirectlyExposed: true,
		DisableCSRF:     true, // deliberate, greppable, reviewable
		RateLimitBurst:  100,
		RateLimitPerSec: 50,
	})
	fmt.Println(chain.Len(), err)
	// Output: 3 <nil>
}

func ExampleHeaders() {
	// The parameter-free subset: response headers and nothing else.
	handler := preset.Headers().Then(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))

	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/", nil))

	fmt.Println(rec.Header().Get("Content-Security-Policy"))
	// Output: default-src 'self'; base-uri 'self'; form-action 'self'; frame-ancestors 'none'; object-src 'none'
}

// TestEveryRejectionHookIsReachableThroughThePreset is the coherence guard for
// the §3.4 invariant at the preset layer.
//
// The invariant says every middleware that can reject a request exposes a
// customizable handler. A preset that wires those middlewares but offers no way
// to reach their hooks satisfies the letter and defeats the purpose: the point
// of one-call adoption is that it does not cost you what selective adoption
// would have given you.
//
// Every rejection the chain can produce must therefore carry the caller's
// envelope. This test drives all four to a rejection and requires it.
func TestEveryRejectionHookIsReachableThroughThePreset(t *testing.T) {
	envelope := func(status int, msg string) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(status)
			fmt.Fprintf(w, `{"error":%q}`, msg)
		})
	}

	chain, err := preset.API(preset.Config{
		DirectlyExposed: true,
		CSRFSecret:      testSecret(t),
		RateLimitBurst:  2,     // spent by the body-limit and CSRF probes below
		RateLimitPerSec: 0.001, // effectively no refill for the life of the test
		MaxBodyBytes:    8,
		CSRFOptions: []csrf.Option{
			csrf.WithErrorHandler(envelope(http.StatusForbidden, "csrf")),
		},
		RateLimitOptions: []ratelimit.Option{
			ratelimit.WithDeniedHandler(envelope(http.StatusTooManyRequests, "rate")),
		},
		BodyLimitOptions: []validate.BodyLimitOption{
			validate.WithMaxBodyErrorHandler(envelope(http.StatusRequestEntityTooLarge, "body")),
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	h := chain.Then(okHandler())

	// 1. Body too large. Ordered before CSRF in the chain, so this is what a
	//    big unauthenticated POST hits first.
	big := httptest.NewRequest(http.MethodPost, "https://"+host+"/x", strings.NewReader(strings.Repeat("A", 100)))
	big.Host = host
	big.Header.Set("Origin", "https://"+host)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, big)
	if rec.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("body limit: status = %d, want 413", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), `"error":"body"`) {
		t.Errorf("body limit answered %q, not the caller's envelope; "+
			"BodyLimitOptions is not reaching validate.MaxBodyBytes", rec.Body)
	}

	// 2. CSRF rejection: a small POST with no token.
	small := httptest.NewRequest(http.MethodPost, "https://"+host+"/x", strings.NewReader("hi"))
	small.Host = host
	small.Header.Set("Origin", "https://"+host)
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, small)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("csrf: status = %d, want 403", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), `"error":"csrf"`) {
		t.Errorf("csrf answered %q, not the caller's envelope", rec.Body)
	}

	// 3. Rate limit: the burst of 2 was spent by the two requests above.
	get := httptest.NewRequest(http.MethodGet, "https://"+host+"/x", nil)
	get.Host = host
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, get)
	if rec.Code != http.StatusTooManyRequests {
		t.Fatalf("rate limit: status = %d, want 429", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), `"error":"rate"`) {
		t.Errorf("rate limit answered %q, not the caller's envelope", rec.Body)
	}
}

// TestStoreErrorHookIsReachableThroughThePreset covers the fourth rejection,
// which needs a failing store to provoke.
func TestStoreErrorHookIsReachableThroughThePreset(t *testing.T) {
	envelope := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusServiceUnavailable)
		_, _ = w.Write([]byte(`{"error":"store"}`))
	})

	chain, err := preset.API(preset.Config{
		DirectlyExposed: true,
		CSRFSecret:      testSecret(t),
		RateLimitBurst:  10,
		RateLimitPerSec: 5,
		RateLimitStore:  failingStore{err: errors.New("redis down")},
		RateLimitOptions: []ratelimit.Option{
			ratelimit.WithStoreErrorHandler(envelope),
		},
	})
	if err != nil {
		t.Fatal(err)
	}

	rec := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "https://"+host+"/x", nil)
	r.Host = host
	chain.Then(okHandler()).ServeHTTP(rec, r)

	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want 503", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), `"error":"store"`) {
		t.Errorf("store outage answered %q, not the caller's envelope", rec.Body)
	}
}

// TestTrustedProxiesKeepsClientsInSeparateBuckets is the R4 HIGH-1 regression.
//
// Behind a load balancer every request carries the balancer's address in
// RemoteAddr, so a limiter keyed on RemoteAddr counts every client on earth as
// one client. The consequence is not a bypass — it is denial of service against
// everyone else: one client spending its allowance holds the whole service at
// the limit, and from outside it is indistinguishable from ordinary throttling.
//
// NEGATIVE CONTROL: delete the WithKeyFunc wiring in API (the `if
// len(cfg.TrustedProxies) > 0` block), which is exactly the pre-fix behaviour,
// and the victim below is refused. Verified red.
func TestTrustedProxiesKeepsClientsInSeparateBuckets(t *testing.T) {
	const burst = 5
	chain, err := preset.API(preset.Config{
		CSRFSecret:      testSecret(t),
		RateLimitBurst:  burst,
		RateLimitPerSec: 0.01, // nothing refills during the test
		TrustedProxies:  []string{"10.0.0.0/8"},
	})
	if err != nil {
		t.Fatal(err)
	}
	h := chain.Then(okHandler())

	get := func(clientIP string) int {
		r := httptest.NewRequest(http.MethodGet, "https://"+host+"/", nil)
		r.Host = host
		r.RemoteAddr = "10.0.0.7:54321" // the balancer, identical for every client
		r.Header.Set("X-Forwarded-For", clientIP)
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, r)
		return rec.Code
	}

	// One client spends its whole allowance.
	for i := range burst {
		if code := get("203.0.113.9"); code != http.StatusOK {
			t.Fatalf("noisy client request %d: status = %d, want 200", i+1, code)
		}
	}
	if code := get("203.0.113.9"); code != http.StatusTooManyRequests {
		t.Errorf("noisy client past its burst: status = %d, want 429", code)
	}

	// A different client, arriving for the first time, must be unaffected.
	for i := range burst {
		if code := get("198.51.100.42"); code != http.StatusOK {
			t.Fatalf("second client request %d: status = %d, want 200 — clients are sharing a bucket", i+1, code)
		}
	}
}

// TestProxyTopologyMustBeStated pins the shape of the requirement: the ambiguous
// configuration is impossible, while both explicit answers work.
//
// An empty TrustedProxies is not rejected on its own, deliberately. Empty cannot
// be told apart from "I have no proxy", and erroring on it would break the
// legitimate direct deployment — which pushes an operator to type any CIDR at
// all just to boot, a worse outcome than the one being fixed. So the choice is
// forced instead: name the proxies, or state the exposure.
func TestProxyTopologyMustBeStated(t *testing.T) {
	base := func() preset.Config {
		return preset.Config{
			CSRFSecret:      testSecret(t),
			RateLimitBurst:  10,
			RateLimitPerSec: 5,
		}
	}

	t.Run("neither answer is refused", func(t *testing.T) {
		_, err := preset.API(base())
		if !errors.Is(err, preset.ErrProxyTopologyUnspecified) {
			t.Fatalf("error = %v, want ErrProxyTopologyUnspecified", err)
		}
	})

	t.Run("TrustedProxies is accepted", func(t *testing.T) {
		cfg := base()
		cfg.TrustedProxies = []string{"10.0.0.0/8"}
		if _, err := preset.API(cfg); err != nil {
			t.Fatalf("API = %v, want no error", err)
		}
	})

	t.Run("DirectlyExposed is accepted", func(t *testing.T) {
		cfg := base()
		cfg.DirectlyExposed = true
		if _, err := preset.API(cfg); err != nil {
			t.Fatalf("API = %v, want no error", err)
		}
	})

	t.Run("both together is contradictory", func(t *testing.T) {
		cfg := base()
		cfg.TrustedProxies = []string{"10.0.0.0/8"}
		cfg.DirectlyExposed = true
		if _, err := preset.API(cfg); err == nil {
			t.Fatal("API accepted TrustedProxies together with DirectlyExposed")
		}
	})

	t.Run("not asked when rate limiting is off", func(t *testing.T) {
		cfg := preset.Config{CSRFSecret: testSecret(t), DisableRateLimit: true}
		if _, err := preset.API(cfg); err != nil {
			t.Fatalf("API = %v, want no error", err)
		}
	})

	t.Run("a bad CIDR is reported, not ignored", func(t *testing.T) {
		cfg := base()
		cfg.TrustedProxies = []string{"not-a-cidr"}
		if _, err := preset.API(cfg); err == nil {
			t.Fatal("API accepted an unparsable CIDR")
		}
	})

	t.Run("the default route is refused through the preset too", func(t *testing.T) {
		cfg := base()
		cfg.TrustedProxies = []string{"0.0.0.0/0"}
		if _, err := preset.API(cfg); !errors.Is(err, realip.ErrDefaultRouteTrusted) {
			t.Fatalf("error = %v, want realip.ErrDefaultRouteTrusted", err)
		}
	})
}
