package secureheaders

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// errNoEntropy stands in for a CSPRNG failure, which cannot be provoked from
// outside the package.
var errNoEntropy = errors.New("no entropy")

func failingNonce() (string, error) { return "", errNoEntropy }

// TestNonceFailureRejectsTheRequest is the "fail high, do not emit a broken
// CSP" requirement. Serving the page with no nonce yields a policy that blocks
// the page's own scripts; serving it with an empty one is worse, because
// 'nonce-' matches nothing and nothing reports it.
//
// Note what "broken" means here, because this test originally asserted
// something stronger and wrong: it required that *no* CSP be sent at all, which
// put it in direct conflict with the package contract that every response
// carries the headers. A rejection is a response. What must not be sent is a
// policy carrying a dangling or empty nonce source; the configured policy
// without any nonce source is not broken, it is merely stricter — injectNonce
// only ever adds sources — and it is the correct thing to put on an error page.
// See TestEveryResponseCarriesTheFullHeaderSet.
func TestNonceFailureRejectsTheRequest(t *testing.T) {
	reached := false
	h := Middleware(WithNonce(), withNonceSource(failingNonce))(
		http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			reached = true
		}))

	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/", nil))

	if reached {
		t.Error("the handler ran without a nonce")
	}
	if rec.Code != http.StatusInternalServerError {
		t.Errorf("status = %d, want 500", rec.Code)
	}
	got := rec.Header().Get("Content-Security-Policy")
	if got == "" {
		t.Error("the rejection carried no CSP; every response this package produces must carry the header set")
	}
	if strings.Contains(got, "'nonce-") {
		t.Errorf("the rejection advertised a nonce source it could not fill: %q", got)
	}
}

func TestNonceFailureUsesTheCustomHandler(t *testing.T) {
	custom := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusServiceUnavailable)
		_, _ = w.Write([]byte(`{"error":"nonce unavailable"}`))
	})

	h := Middleware(WithNonce(), WithNonceErrorHandler(custom), withNonceSource(failingNonce))(
		http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			t.Error("the handler ran without a nonce")
		}))

	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/", nil))

	if rec.Code != http.StatusServiceUnavailable {
		t.Errorf("status = %d, want the custom 503", rec.Code)
	}
	if got := rec.Header().Get("Content-Type"); got != "application/json" {
		t.Errorf("Content-Type = %q, want the custom envelope", got)
	}
}

func TestNonceErrorHandlerNilIsIgnored(t *testing.T) {
	h := Middleware(WithNonce(), WithNonceErrorHandler(nil), withNonceSource(failingNonce))(
		http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))

	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/", nil))
	if rec.Code != http.StatusInternalServerError {
		t.Errorf("status = %d, want the default 500", rec.Code)
	}
}

// TestInjectNonce exercises the policy rewriting directly, including the shapes
// that only show up with unusual spacing.
func TestInjectNonce(t *testing.T) {
	tests := []struct {
		name       string
		policy     string
		directives []string
		want       string
	}{
		{
			name:       "absent directive is added",
			policy:     "default-src 'self'",
			directives: []string{"script-src"},
			want:       "default-src 'self'; script-src " + noncePlaceholder,
		},
		{
			name:       "present directive is extended",
			policy:     "default-src 'self'; script-src 'self'",
			directives: []string{"script-src"},
			want:       "default-src 'self'; script-src 'self' " + noncePlaceholder,
		},
		{
			name:       "matching is case-insensitive",
			policy:     "SCRIPT-SRC 'self'",
			directives: []string{"script-src"},
			want:       "SCRIPT-SRC 'self' " + noncePlaceholder,
		},
		{
			name:       "trailing spaces do not double up",
			policy:     "script-src 'self'   ",
			directives: []string{"script-src"},
			want:       "script-src 'self' " + noncePlaceholder,
		},
		{
			name:       "several directives",
			policy:     "script-src 'self'; style-src 'self'",
			directives: []string{"script-src", "style-src"},
			want:       "script-src 'self' " + noncePlaceholder + "; style-src 'self' " + noncePlaceholder,
		},
		{
			name:       "an empty policy stays empty",
			policy:     "",
			directives: []string{"script-src"},
			want:       "",
		},
		{
			// A directive whose name is a prefix of another must not match it.
			name:       "no prefix confusion",
			policy:     "default-src 'self'; script-src-elem 'self'",
			directives: []string{"script-src"},
			want:       "default-src 'self'; script-src-elem 'self'; script-src " + noncePlaceholder,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := injectNonce(tc.policy, tc.directives); got != tc.want {
				t.Errorf("injectNonce = %q, want %q", got, tc.want)
			}
		})
	}
}

// TestRenderCSPHasNoPlaceholderLeft guards against a placeholder reaching a
// browser, which would be a policy containing a NUL byte.
func TestRenderCSPHasNoPlaceholderLeft(t *testing.T) {
	parts := splitAroundNonce(injectNonce(DefaultCSP, []string{"script-src", "style-src"}))
	got := renderCSP(parts, "AAAAAAAAAAAAAAAAAAAAAA==")

	if got == "" {
		t.Fatal("empty policy")
	}
	for _, r := range got {
		if r == 0 {
			t.Fatalf("the placeholder survived into the policy: %q", got)
		}
	}
}
