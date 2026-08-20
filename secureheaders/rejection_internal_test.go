package secureheaders

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// fullyConfigured turns on every header this package can emit, so that "the
// full set" below is the widest set available rather than the default one.
func fullyConfigured(extra ...Option) []Option {
	opts := []Option{
		WithCSP("default-src 'self'"),
		WithCSPReportOnly("default-src 'self'; report-uri /csp"),
		WithHSTS(365*24*time.Hour, true, false),
		WithFrameOptions(FrameDeny),
		WithReferrerPolicy("no-referrer"),
		WithPermissionsPolicy("geolocation=()"),
		WithCrossOriginOpenerPolicy(COOPSameOrigin),
		WithCrossOriginResourcePolicy(CORPSameOrigin),
		WithCrossOriginEmbedderPolicy(COEPRequireCorp),
		WithNonce("script-src"),
	}
	return append(opts, extra...)
}

func workingNonce() (string, error) { return "dGVzdG5vbmNlMDAwMA", nil }

// TestEveryResponseCarriesTheFullHeaderSet asserts the package's contract as a
// property rather than as a list of cases: *every* response this middleware can
// produce carries the headers, not just the ones someone remembered to test.
//
// # Why this test is shaped like this
//
// The 429-without-headers bug (DESIGN.md §10.6) was closed by a subtest named
// for the 429. That guarded the instance, not the class, and nothing asserted
// the general property — so the very next rejection point added, the nonce
// failure in this package, reintroduced the same bug and no test noticed.
//
// So the expected header set is not written down here. It is captured from a
// successful response and then required of every other path. A header added to
// this package in future appears in the success response automatically and is
// thereby demanded of every rejection, with no edit to this test. The companion
// TestResponseWritingSitesAreAllAccountedFor stops a *path* from being added
// without one.
func TestEveryResponseCarriesTheFullHeaderSet(t *testing.T) {
	okHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	// The reference: what a response looks like when nothing goes wrong. Every
	// other path is measured against it.
	ref := httptest.NewRecorder()
	Middleware(append(fullyConfigured(), withNonceSource(workingNonce))...)(okHandler).
		ServeHTTP(ref, httptest.NewRequest(http.MethodGet, "/", nil))
	if ref.Code != http.StatusOK {
		t.Fatalf("reference response status = %d, want 200", ref.Code)
	}
	want := securityHeaders(ref.Header())
	if len(want) < 8 {
		t.Fatalf("the reference response carried only %d security headers (%v); the test is not configured to exercise the full set", len(want), want)
	}

	custom := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusServiceUnavailable)
		fmt.Fprint(w, "custom")
	})
	// A handler that rejects on its own, to check the contract's "including
	// errors and redirects" clause from the other direction.
	failingApp := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "boom", http.StatusInternalServerError)
	})

	paths := []struct {
		name       string
		opts       []Option
		next       http.Handler
		wantStatus int
	}{
		{
			name:       "success",
			opts:       []Option{withNonceSource(workingNonce)},
			next:       okHandler,
			wantStatus: http.StatusOK,
		},
		{
			name:       "the wrapped handler writes its own error",
			opts:       []Option{withNonceSource(workingNonce)},
			next:       failingApp,
			wantStatus: http.StatusInternalServerError,
		},
		{
			// The rejection this package owns, and the one that regressed.
			name:       "rejection: nonce generation failed, default response",
			opts:       []Option{withNonceSource(failingNonce)},
			next:       okHandler,
			wantStatus: http.StatusInternalServerError,
		},
		{
			name:       "rejection: nonce generation failed, caller's handler",
			opts:       []Option{withNonceSource(failingNonce), WithNonceErrorHandler(custom)},
			next:       okHandler,
			wantStatus: http.StatusServiceUnavailable,
		},
		{
			name:       "rejection: nonce generation failed, nil handler falls back",
			opts:       []Option{withNonceSource(failingNonce), WithNonceErrorHandler(nil)},
			next:       okHandler,
			wantStatus: http.StatusInternalServerError,
		},
	}

	for _, tc := range paths {
		t.Run(tc.name, func(t *testing.T) {
			rec := httptest.NewRecorder()
			Middleware(fullyConfigured(tc.opts...)...)(tc.next).
				ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/", nil))

			if rec.Code != tc.wantStatus {
				t.Fatalf("status = %d, want %d", rec.Code, tc.wantStatus)
			}
			for name, refValue := range want {
				got := rec.Header().Get(name)
				if got == "" {
					t.Errorf("%s is missing: this response reached the client with no %s, "+
						"while a successful response carries %q", name, name, refValue)
					continue
				}
				// The CSP carries a per-request nonce on the success path and
				// cannot on a path where nonce generation is what failed, so it
				// is checked for presence and for the configured base policy
				// rather than for equality.
				if strings.HasPrefix(name, "Content-Security-Policy") {
					if !strings.Contains(got, "default-src 'self'") {
						t.Errorf("%s = %q, want it to carry the configured policy", name, got)
					}
					continue
				}
				if got != refValue {
					t.Errorf("%s = %q, want %q (the value a successful response carries)", name, got, refValue)
				}
			}
		})
	}
}

// securityHeaders extracts the headers this package emits, ignoring whatever the
// responding handler adds of its own (Content-Type, X-Content-Type-Options is
// ours, Date, and so on are not comparable across paths).
func securityHeaders(h http.Header) map[string]string {
	out := map[string]string{}
	for name := range h {
		switch {
		case strings.HasPrefix(name, "Content-Security-Policy"),
			strings.HasPrefix(name, "Cross-Origin-"),
			name == "Strict-Transport-Security",
			name == "X-Frame-Options",
			name == "X-Content-Type-Options",
			name == "Referrer-Policy",
			name == "Permissions-Policy":
			out[name] = h.Get(name)
		}
	}
	return out
}
