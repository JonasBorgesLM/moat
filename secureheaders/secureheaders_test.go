package secureheaders_test

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/JonasBorgesLM/gosecure/secureheaders"
)

// serve runs one request through the middleware and reports the response
// recorder plus whether the wrapped handler was reached.
func serve(t *testing.T, opts ...secureheaders.Option) (*httptest.ResponseRecorder, bool) {
	t.Helper()
	reached := false
	h := secureheaders.Middleware(opts...)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		reached = true
		w.WriteHeader(http.StatusOK)
	}))
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/", nil))
	return rec, reached
}

// TestDefaults asserts the shipped defaults explicitly, value by value. This is
// the test that fails if someone quietly relaxes a default: for this package the
// default *is* the product.
func TestDefaults(t *testing.T) {
	rec, reached := serve(t)
	if !reached {
		t.Fatal("wrapped handler was not called")
	}

	want := map[string]string{
		"Content-Security-Policy":   "default-src 'self'; base-uri 'self'; form-action 'self'; frame-ancestors 'none'; object-src 'none'",
		"Strict-Transport-Security": "max-age=31536000; includeSubDomains",
		"X-Frame-Options":           "DENY",
		"X-Content-Type-Options":    "nosniff",
		"Referrer-Policy":           "strict-origin-when-cross-origin",
	}
	for k, v := range want {
		if got := rec.Header().Get(k); got != v {
			t.Errorf("%s = %q, want %q", k, got, v)
		}
	}

	pp := rec.Header().Get("Permissions-Policy")
	for _, feature := range []string{"camera=()", "microphone=()", "geolocation=()"} {
		if !contains(pp, feature) {
			t.Errorf("Permissions-Policy = %q, want it to contain %q", pp, feature)
		}
	}

	// preload is effectively irreversible and must never be on by default.
	if contains(rec.Header().Get("Strict-Transport-Security"), "preload") {
		t.Error("HSTS preload is enabled by default; it is effectively irreversible and must be opt-in")
	}
	// Report-only alone enforces nothing, so it must not appear unasked.
	if v := rec.Header().Get("Content-Security-Policy-Report-Only"); v != "" {
		t.Errorf("Content-Security-Policy-Report-Only = %q, want absent by default", v)
	}
}

// TestDefaultCSPCoversNonInheritingDirectives guards the subtle part of the
// default policy: frame-ancestors, base-uri and form-action do not fall back to
// default-src, so a policy that only sets default-src leaves clickjacking,
// <base> hijacking and form exfiltration unprotected.
func TestDefaultCSPCoversNonInheritingDirectives(t *testing.T) {
	rec, _ := serve(t)
	csp := rec.Header().Get("Content-Security-Policy")
	for _, directive := range []string{"default-src 'self'", "frame-ancestors 'none'", "base-uri 'self'", "form-action 'self'", "object-src 'none'"} {
		if !contains(csp, directive) {
			t.Errorf("default CSP %q is missing %q", csp, directive)
		}
	}
}

func TestOverrides(t *testing.T) {
	tests := []struct {
		name   string
		opts   []secureheaders.Option
		header string
		want   string
	}{
		{
			name:   "WithCSP replaces the policy",
			opts:   []secureheaders.Option{secureheaders.WithCSP("default-src 'self' https://cdn.example.com")},
			header: "Content-Security-Policy",
			want:   "default-src 'self' https://cdn.example.com",
		},
		{
			name:   "WithoutCSP removes the header",
			opts:   []secureheaders.Option{secureheaders.WithoutCSP()},
			header: "Content-Security-Policy",
			want:   "",
		},
		{
			name:   "an empty WithCSP also removes the header",
			opts:   []secureheaders.Option{secureheaders.WithCSP("")},
			header: "Content-Security-Policy",
			want:   "",
		},
		{
			name:   "WithCSPReportOnly is additive",
			opts:   []secureheaders.Option{secureheaders.WithCSPReportOnly("default-src 'none'")},
			header: "Content-Security-Policy-Report-Only",
			want:   "default-src 'none'",
		},
		{
			name:   "WithHSTS sets max-age and subdomains",
			opts:   []secureheaders.Option{secureheaders.WithHSTS(48*time.Hour, true, false)},
			header: "Strict-Transport-Security",
			want:   "max-age=172800; includeSubDomains",
		},
		{
			name:   "WithHSTS can drop includeSubDomains",
			opts:   []secureheaders.Option{secureheaders.WithHSTS(48*time.Hour, false, false)},
			header: "Strict-Transport-Security",
			want:   "max-age=172800",
		},
		{
			name:   "WithHSTS can opt into preload",
			opts:   []secureheaders.Option{secureheaders.WithHSTS(secureheaders.DefaultHSTSMaxAge, true, true)},
			header: "Strict-Transport-Security",
			want:   "max-age=31536000; includeSubDomains; preload",
		},
		{
			name:   "max-age of zero disables the header entirely",
			opts:   []secureheaders.Option{secureheaders.WithHSTS(0, true, true)},
			header: "Strict-Transport-Security",
			want:   "",
		},
		{
			name:   "a negative max-age also disables the header",
			opts:   []secureheaders.Option{secureheaders.WithHSTS(-time.Hour, true, false)},
			header: "Strict-Transport-Security",
			want:   "",
		},
		{
			name:   "WithoutHSTS removes the header",
			opts:   []secureheaders.Option{secureheaders.WithoutHSTS()},
			header: "Strict-Transport-Security",
			want:   "",
		},
		{
			name:   "WithFrameOptions accepts SAMEORIGIN",
			opts:   []secureheaders.Option{secureheaders.WithFrameOptions(secureheaders.FrameSameOrigin)},
			header: "X-Frame-Options",
			want:   "SAMEORIGIN",
		},
		{
			name:   "WithoutFrameOptions removes the header",
			opts:   []secureheaders.Option{secureheaders.WithoutFrameOptions()},
			header: "X-Frame-Options",
			want:   "",
		},
		{
			name:   "WithReferrerPolicy replaces the value",
			opts:   []secureheaders.Option{secureheaders.WithReferrerPolicy("no-referrer")},
			header: "Referrer-Policy",
			want:   "no-referrer",
		},
		{
			name:   "an empty referrer policy removes the header",
			opts:   []secureheaders.Option{secureheaders.WithReferrerPolicy("")},
			header: "Referrer-Policy",
			want:   "",
		},
		{
			name:   "WithPermissionsPolicy replaces the value",
			opts:   []secureheaders.Option{secureheaders.WithPermissionsPolicy("camera=(self)")},
			header: "Permissions-Policy",
			want:   "camera=(self)",
		},
		{
			name:   "an empty permissions policy removes the header",
			opts:   []secureheaders.Option{secureheaders.WithPermissionsPolicy("")},
			header: "Permissions-Policy",
			want:   "",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			rec, reached := serve(t, tc.opts...)
			if !reached {
				t.Fatal("wrapped handler was not called")
			}
			if got := rec.Header().Get(tc.header); got != tc.want {
				t.Errorf("%s = %q, want %q", tc.header, got, tc.want)
			}
		})
	}
}

// TestNosniffIsNotConfigurable pins a deliberate omission: there is no option to
// turn off X-Content-Type-Options, so it must survive every other relaxation.
func TestNosniffIsNotConfigurable(t *testing.T) {
	rec, _ := serve(t,
		secureheaders.WithoutCSP(),
		secureheaders.WithoutHSTS(),
		secureheaders.WithoutFrameOptions(),
		secureheaders.WithReferrerPolicy(""),
		secureheaders.WithPermissionsPolicy(""),
	)
	if got := rec.Header().Get("X-Content-Type-Options"); got != "nosniff" {
		t.Errorf("X-Content-Type-Options = %q, want nosniff even with everything else relaxed", got)
	}
}

// TestInvalidFrameOptionKeepsTheDefault covers the typo case: an unrecognized
// value must not silently disable framing protection.
func TestInvalidFrameOptionKeepsTheDefault(t *testing.T) {
	rec, _ := serve(t, secureheaders.WithFrameOptions("SAMEORIGN"))
	if got := rec.Header().Get("X-Frame-Options"); got != "DENY" {
		t.Errorf("X-Frame-Options = %q, want DENY: a typo must not disable the header", got)
	}
}

// TestHeadersOnEveryResponse checks the paths people forget: an error page and a
// redirect are still pages, and are just as framable and injectable.
func TestHeadersOnEveryResponse(t *testing.T) {
	tests := []struct {
		name    string
		handler http.HandlerFunc
		status  int
	}{
		{"success", func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusOK) }, http.StatusOK},
		{"error", func(w http.ResponseWriter, r *http.Request) { http.Error(w, "nope", http.StatusInternalServerError) }, http.StatusInternalServerError},
		{"redirect", func(w http.ResponseWriter, r *http.Request) { http.Redirect(w, r, "/elsewhere", http.StatusFound) }, http.StatusFound},
		{"not found", func(w http.ResponseWriter, r *http.Request) { http.NotFound(w, r) }, http.StatusNotFound},
		{"no explicit write", func(w http.ResponseWriter, r *http.Request) {}, http.StatusOK},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			rec := httptest.NewRecorder()
			secureheaders.Middleware()(tc.handler).
				ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/", nil))
			if rec.Code != tc.status {
				t.Errorf("status = %d, want %d", rec.Code, tc.status)
			}
			if rec.Header().Get("Content-Security-Policy") == "" {
				t.Error("CSP missing")
			}
			if rec.Header().Get("X-Content-Type-Options") != "nosniff" {
				t.Error("nosniff missing")
			}
		})
	}
}

// TestHandlerCanOverride confirms headers are written before the handler runs,
// so a handler that genuinely needs a different policy for one response can set
// one, rather than having to bypass the middleware.
func TestHandlerCanOverride(t *testing.T) {
	rec := httptest.NewRecorder()
	secureheaders.Middleware()(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Security-Policy", "default-src 'none'")
	})).ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/", nil))

	if got := rec.Header().Get("Content-Security-Policy"); got != "default-src 'none'" {
		t.Errorf("CSP = %q, want the handler's override", got)
	}
}

func TestNilOptionIsIgnored(t *testing.T) {
	rec, reached := serve(t, nil)
	if !reached {
		t.Fatal("wrapped handler was not called")
	}
	if rec.Header().Get("Content-Security-Policy") != secureheaders.DefaultCSP {
		t.Error("a nil option disturbed the defaults")
	}
}

// TestConfigIsResolvedOnce guards against per-request mutation of the resolved
// header set: two responses from the same middleware must be identical.
func TestConfigIsResolvedOnce(t *testing.T) {
	mw := secureheaders.Middleware()
	h := mw(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))

	first := httptest.NewRecorder()
	h.ServeHTTP(first, httptest.NewRequest(http.MethodGet, "/", nil))
	second := httptest.NewRecorder()
	h.ServeHTTP(second, httptest.NewRequest(http.MethodGet, "/", nil))

	if fmt.Sprint(first.Header()) != fmt.Sprint(second.Header()) {
		t.Errorf("headers differ between requests:\n%v\n%v", first.Header(), second.Header())
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

func ExampleMiddleware() {
	handler := secureheaders.Middleware()(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))

	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/", nil))

	fmt.Println(rec.Header().Get("Content-Security-Policy"))
	fmt.Println(rec.Header().Get("Strict-Transport-Security"))
	fmt.Println(rec.Header().Get("X-Frame-Options"))
	fmt.Println(rec.Header().Get("X-Content-Type-Options"))
	// Output:
	// default-src 'self'; base-uri 'self'; form-action 'self'; frame-ancestors 'none'; object-src 'none'
	// max-age=31536000; includeSubDomains
	// DENY
	// nosniff
}

// ExampleWithCSP relaxes exactly one directive to allow a CDN, keeping the
// directives that do not inherit from default-src. Rebuilding a policy from
// scratch is where those silently get dropped.
func ExampleWithCSP() {
	handler := secureheaders.Middleware(
		secureheaders.WithCSP("default-src 'self' https://cdn.example.com; base-uri 'self'; form-action 'self'; frame-ancestors 'none'; object-src 'none'"),
	)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))

	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/", nil))

	fmt.Println(rec.Header().Get("Content-Security-Policy"))
	// Output: default-src 'self' https://cdn.example.com; base-uri 'self'; form-action 'self'; frame-ancestors 'none'; object-src 'none'
}

// ExampleWithHSTS opts into the preload list. Do this only when every subdomain
// is reachable over HTTPS: removal from the preload list takes months to reach
// users and cannot be hurried.
func ExampleWithHSTS() {
	handler := secureheaders.Middleware(
		secureheaders.WithHSTS(secureheaders.DefaultHSTSMaxAge, true, true),
	)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))

	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/", nil))

	fmt.Println(rec.Header().Get("Strict-Transport-Security"))
	// Output: max-age=31536000; includeSubDomains; preload
}
