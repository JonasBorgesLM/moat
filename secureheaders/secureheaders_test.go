package secureheaders_test

import (
	"encoding/base64"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/JonasBorgesLM/moat/secureheaders"
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

// --- CSP nonce ---------------------------------------------------------------

// nonceFrom extracts the nonce source from a rendered policy, so tests can
// assert on it without hard-coding a random value.
func nonceFrom(t *testing.T, policy string) string {
	t.Helper()
	i := strings.Index(policy, "'nonce-")
	if i < 0 {
		t.Fatalf("no nonce in policy %q", policy)
	}
	rest := policy[i+len("'nonce-"):]
	j := strings.Index(rest, "'")
	if j < 0 {
		t.Fatalf("unterminated nonce in policy %q", policy)
	}
	return rest[:j]
}

// run drives one request through an already-built middleware, which the nonce
// tests need because they inspect what the handler saw as well as the response.
func run(t *testing.T, mw func(http.Handler) http.Handler, h http.Handler) *httptest.ResponseRecorder {
	t.Helper()
	rec := httptest.NewRecorder()
	mw(h).ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/", nil))
	return rec
}

func TestNonceIsInjectedAndReadable(t *testing.T) {
	var seen string
	var ok bool
	rec := run(t, secureheaders.Middleware(secureheaders.WithNonce()),
		http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			seen, ok = secureheaders.Nonce(r)
		}))

	if !ok {
		t.Fatal("Nonce reported no value inside a nonce-enabled middleware")
	}
	policy := rec.Header().Get("Content-Security-Policy")
	if got := nonceFrom(t, policy); got != seen {
		t.Errorf("policy nonce %q != handler nonce %q", got, seen)
	}
	if !strings.Contains(policy, "script-src 'nonce-"+seen+"'") {
		t.Errorf("policy = %q, want script-src carrying the nonce", policy)
	}
}

// TestNonceIsUniquePerRequest is the property the whole mechanism rests on: a
// reused nonce is a nonce an attacker can learn from one response and replay
// into an injection on the next.
func TestNonceIsUniquePerRequest(t *testing.T) {
	mw := secureheaders.Middleware(secureheaders.WithNonce())
	h := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {})

	seen := make(map[string]bool, 200)
	for i := range 200 {
		n := nonceFrom(t, run(t, mw, h).Header().Get("Content-Security-Policy"))
		if seen[n] {
			t.Fatalf("nonce %q repeated on request %d", n, i)
		}
		seen[n] = true

		// It must also be long enough to be unguessable.
		raw, err := base64.StdEncoding.DecodeString(n)
		if err != nil {
			t.Fatalf("nonce %q is not standard base64: %v", n, err)
		}
		if len(raw) < 16 {
			t.Errorf("nonce carries %d bytes, want at least 16", len(raw))
		}
	}
}

// TestNonceAddsAnAbsentDirective is the reason a missing script-src cannot
// produce a silently broken policy: DefaultCSP has no script-src at all.
func TestNonceAddsAnAbsentDirective(t *testing.T) {
	if strings.Contains(secureheaders.DefaultCSP, "script-src") {
		t.Skip("DefaultCSP now has a script-src; this test needs rewriting")
	}
	policy := run(t, secureheaders.Middleware(secureheaders.WithNonce()),
		http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {})).
		Header().Get("Content-Security-Policy")

	if !strings.Contains(policy, "script-src 'nonce-") {
		t.Errorf("policy = %q, want an added script-src", policy)
	}
	// The rest of the policy must survive intact.
	for _, want := range []string{"default-src 'self'", "frame-ancestors 'none'", "object-src 'none'"} {
		if !strings.Contains(policy, want) {
			t.Errorf("policy = %q, lost %q", policy, want)
		}
	}
}

func TestNonceJoinsAnExistingDirective(t *testing.T) {
	mw := secureheaders.Middleware(
		secureheaders.WithCSP("default-src 'self'; script-src 'self' https://cdn.example.com; style-src 'self'"),
		secureheaders.WithNonce("script-src", "style-src"),
	)
	policy := run(t, mw, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {})).
		Header().Get("Content-Security-Policy")
	n := nonceFrom(t, policy)

	if !strings.Contains(policy, "script-src 'self' https://cdn.example.com 'nonce-"+n+"'") {
		t.Errorf("policy = %q, want the nonce appended to the existing script-src sources", policy)
	}
	if !strings.Contains(policy, "style-src 'self' 'nonce-"+n+"'") {
		t.Errorf("policy = %q, want the nonce appended to style-src", policy)
	}
	if strings.Count(policy, "script-src") != 1 {
		t.Errorf("policy = %q, script-src was duplicated rather than extended", policy)
	}
}

// TestNonceMatchesAcrossBothPolicies: a report-only policy must carry the same
// nonce as the enforced one, or trialling a policy reports violations that the
// enforced policy would not have produced.
func TestNonceInReportOnlyPolicy(t *testing.T) {
	mw := secureheaders.Middleware(
		secureheaders.WithCSPReportOnly("default-src 'self'; script-src 'self'"),
		secureheaders.WithNonce(),
	)
	rec := run(t, mw, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))

	enforced := rec.Header().Get("Content-Security-Policy")
	report := rec.Header().Get("Content-Security-Policy-Report-Only")
	if report == "" {
		t.Fatal("report-only policy is missing")
	}
	if nonceFrom(t, enforced) != nonceFrom(t, report) {
		t.Errorf("the two policies carry different nonces:\n  %s\n  %s", enforced, report)
	}
}

// TestNonceIsAbsentWithoutTheOption pins that Nonce follows csrf.Token: no
// silent empty string when the feature is off.
func TestNonceIsAbsentWithoutTheOption(t *testing.T) {
	var ok bool
	var got string
	run(t, secureheaders.Middleware(), http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got, ok = secureheaders.Nonce(r)
	}))
	if ok || got != "" {
		t.Errorf("Nonce = %q, %v; want empty and false without WithNonce", got, ok)
	}

	// And with no middleware at all.
	if got, ok := secureheaders.Nonce(httptest.NewRequest(http.MethodGet, "/", nil)); ok || got != "" {
		t.Errorf("Nonce on a bare request = %q, %v; want empty and false", got, ok)
	}
	if got, ok := secureheaders.Nonce(nil); ok || got != "" {
		t.Errorf("Nonce(nil) = %q, %v; want empty and false", got, ok)
	}
}

func TestNonceModeStillWritesTheOtherHeaders(t *testing.T) {
	rec := run(t, secureheaders.Middleware(secureheaders.WithNonce()),
		http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))

	for _, h := range []string{
		"Strict-Transport-Security", "X-Frame-Options",
		"X-Content-Type-Options", "Referrer-Policy", "Permissions-Policy",
	} {
		if rec.Header().Get(h) == "" {
			t.Errorf("%s is missing in nonce mode", h)
		}
	}
	if n := len(rec.Header().Values("Content-Security-Policy")); n != 1 {
		t.Errorf("Content-Security-Policy appears %d times, want 1", n)
	}
}

func TestWithoutCSPAndNonce(t *testing.T) {
	// Nonces with no policy to inject into: the nonce is still issued (a
	// handler may render it), but no CSP header is invented.
	var ok bool
	rec := run(t, secureheaders.Middleware(secureheaders.WithoutCSP(), secureheaders.WithNonce()),
		http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			_, ok = secureheaders.Nonce(r)
		}))
	if !ok {
		t.Error("no nonce was issued")
	}
	if got := rec.Header().Get("Content-Security-Policy"); got != "" {
		t.Errorf("Content-Security-Policy = %q, want it absent after WithoutCSP", got)
	}
}

func TestWithNonceIgnoresEmptyAndDuplicateDirectives(t *testing.T) {
	mw := secureheaders.Middleware(
		secureheaders.WithCSP("default-src 'self'"),
		secureheaders.WithNonce("script-src", "", "  ", "SCRIPT-SRC"),
	)
	policy := run(t, mw, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {})).
		Header().Get("Content-Security-Policy")

	if strings.Count(policy, "script-src") != 1 {
		t.Errorf("policy = %q, want exactly one script-src", policy)
	}
}

// --- Cache-Control -----------------------------------------------------------

func TestNoStore(t *testing.T) {
	rec := httptest.NewRecorder()
	secureheaders.NoStore(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"access_token":"x"}`))
	})).ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/token", nil))

	if got := rec.Header().Get("Cache-Control"); got != "no-store" {
		t.Errorf("Cache-Control = %q, want no-store (RFC 6749 §5.1)", got)
	}
	if got := rec.Header().Get("Pragma"); got != "no-cache" {
		t.Errorf("Pragma = %q, want no-cache (RFC 6749 §5.1)", got)
	}
	if rec.Code != http.StatusOK {
		t.Errorf("status = %d, want the wrapped handler's 200", rec.Code)
	}
}

// TestNoStoreSetsHeadersBeforeTheHandler: a handler that writes its status
// immediately must not lose the headers.
func TestNoStoreSetsHeadersBeforeTheHandler(t *testing.T) {
	rec := httptest.NewRecorder()
	secureheaders.NoStore(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusCreated)
	})).ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/token", nil))

	if got := rec.Header().Get("Cache-Control"); got != "no-store" {
		t.Errorf("Cache-Control = %q; the headers were written too late", got)
	}
}

// TestNoStoreIsOverridable keeps the package's stated contract that a handler
// may replace any header this package sets.
func TestNoStoreIsOverridable(t *testing.T) {
	rec := httptest.NewRecorder()
	secureheaders.NoStore(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "public, max-age=60")
	})).ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/public", nil))

	if got := rec.Header().Get("Cache-Control"); got != "public, max-age=60" {
		t.Errorf("Cache-Control = %q, want the handler's value", got)
	}
}

// --- Clear-Site-Data ---------------------------------------------------------

func TestClearSiteData(t *testing.T) {
	tests := []struct {
		name  string
		types []secureheaders.SiteDataType
		want  string
	}{
		{
			name: "the default is cache, cookies and storage",
			want: `"cache", "cookies", "storage"`,
		},
		{
			name:  "an explicit selection is used as given",
			types: []secureheaders.SiteDataType{secureheaders.SiteDataCookies},
			want:  `"cookies"`,
		},
		{
			name: "executionContexts is available on request",
			types: []secureheaders.SiteDataType{
				secureheaders.SiteDataCookies, secureheaders.SiteDataExecutionContexts,
			},
			want: `"cookies", "executionContexts"`,
		},
		{
			name:  "the wildcard is passed through",
			types: []secureheaders.SiteDataType{secureheaders.SiteDataAll},
			want:  `"*"`,
		},
		{
			name: "duplicates and blanks are dropped",
			types: []secureheaders.SiteDataType{
				secureheaders.SiteDataCookies, "", "  ", secureheaders.SiteDataCookies,
			},
			want: `"cookies"`,
		},
		{
			name:  "an entirely empty selection falls back to the default",
			types: []secureheaders.SiteDataType{"", "   "},
			want:  `"cache", "cookies", "storage"`,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			rec := httptest.NewRecorder()
			secureheaders.ClearSiteData(tc.types...)(
				http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					w.WriteHeader(http.StatusNoContent)
				})).ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/logout", nil))

			if got := rec.Header().Get("Clear-Site-Data"); got != tc.want {
				t.Errorf("Clear-Site-Data = %q, want %q", got, tc.want)
			}
		})
	}
}

// TestClearSiteDataValuesAreQuoted pins the one detail that makes the header
// work at all: an unquoted value is ignored by browsers, so the middleware
// would silently do nothing.
func TestClearSiteDataValuesAreQuoted(t *testing.T) {
	rec := httptest.NewRecorder()
	secureheaders.ClearSiteData()(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {})).
		ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/logout", nil))

	value := rec.Header().Get("Clear-Site-Data")
	for _, part := range strings.Split(value, ",") {
		part = strings.TrimSpace(part)
		if !strings.HasPrefix(part, `"`) || !strings.HasSuffix(part, `"`) {
			t.Errorf("entry %q is not quoted; browsers ignore unquoted values (full header %q)", part, value)
		}
	}
}

// TestClearSiteDataSurvivesARedirect covers the shape a real logout has: the
// handler redirects, and the header must be on the redirect response itself
// because the browser will not carry it to the destination.
func TestClearSiteDataSurvivesARedirect(t *testing.T) {
	rec := httptest.NewRecorder()
	secureheaders.ClearSiteData()(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "/", http.StatusSeeOther)
	})).ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/logout", nil))

	if rec.Code != http.StatusSeeOther {
		t.Fatalf("status = %d, want 303", rec.Code)
	}
	if rec.Header().Get("Clear-Site-Data") == "" {
		t.Error("the header was lost on the redirect response")
	}
}

func ExampleClearSiteData() {
	logout := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Invalidate the session server-side first. Clear-Site-Data is defense
		// in depth: it is ignored on plaintext origins and support is uneven,
		// so a logout must never depend on it.
		http.Redirect(w, r, "/", http.StatusSeeOther)
	})

	mux := http.NewServeMux()
	mux.Handle("POST /logout", secureheaders.ClearSiteData()(logout))

	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/logout", nil))

	fmt.Println(rec.Header().Get("Clear-Site-Data"))
	// Output: "cache", "cookies", "storage"
}

// --- Cross-origin isolation headers ------------------------------------------

// TestCrossOriginHeadersAreNotDefaults is the load-bearing test for this group.
// The library is published; adding any of these three to the default set would
// change behaviour for every already-deployed consumer with no compile error to
// warn them, and each has a documented breakage mode. If a default is ever
// added deliberately, this test fails and forces the change to be a decision.
func TestCrossOriginHeadersAreNotDefaults(t *testing.T) {
	rec, _ := serve(t)
	for _, h := range []string{
		"Cross-Origin-Opener-Policy",
		"Cross-Origin-Resource-Policy",
		"Cross-Origin-Embedder-Policy",
	} {
		if got := rec.Header().Get(h); got != "" {
			t.Errorf("%s = %q by default; changing a default in a published security "+
				"library breaks consumers silently -- see DESIGN.md §4.4", h, got)
		}
	}
}

func TestCrossOriginOptions(t *testing.T) {
	tests := []struct {
		name   string
		opt    secureheaders.Option
		header string
		want   string
	}{
		{
			name:   "COOP same-origin-allow-popups",
			opt:    secureheaders.WithCrossOriginOpenerPolicy(secureheaders.COOPSameOriginAllowPopups),
			header: "Cross-Origin-Opener-Policy",
			want:   "same-origin-allow-popups",
		},
		{
			name:   "COOP same-origin",
			opt:    secureheaders.WithCrossOriginOpenerPolicy(secureheaders.COOPSameOrigin),
			header: "Cross-Origin-Opener-Policy",
			want:   "same-origin",
		},
		{
			name:   "CORP same-origin",
			opt:    secureheaders.WithCrossOriginResourcePolicy(secureheaders.CORPSameOrigin),
			header: "Cross-Origin-Resource-Policy",
			want:   "same-origin",
		},
		{
			name:   "CORP cross-origin for a public asset",
			opt:    secureheaders.WithCrossOriginResourcePolicy(secureheaders.CORPCrossOrigin),
			header: "Cross-Origin-Resource-Policy",
			want:   "cross-origin",
		},
		{
			name:   "COEP require-corp",
			opt:    secureheaders.WithCrossOriginEmbedderPolicy(secureheaders.COEPRequireCorp),
			header: "Cross-Origin-Embedder-Policy",
			want:   "require-corp",
		},
		{
			name:   "COEP credentialless",
			opt:    secureheaders.WithCrossOriginEmbedderPolicy(secureheaders.COEPCredentialless),
			header: "Cross-Origin-Embedder-Policy",
			want:   "credentialless",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			rec, _ := serve(t, tc.opt)
			if got := rec.Header().Get(tc.header); got != tc.want {
				t.Errorf("%s = %q, want %q", tc.header, got, tc.want)
			}
		})
	}
}

// TestCrossOriginEmptyValueOmitsTheHeader covers passing a zero value, which
// must mean "do not send" rather than sending an empty header a browser would
// treat as invalid.
func TestCrossOriginEmptyValueOmitsTheHeader(t *testing.T) {
	rec, _ := serve(t,
		secureheaders.WithCrossOriginOpenerPolicy(""),
		secureheaders.WithCrossOriginResourcePolicy(""),
		secureheaders.WithCrossOriginEmbedderPolicy(""),
	)
	for _, h := range []string{
		"Cross-Origin-Opener-Policy",
		"Cross-Origin-Resource-Policy",
		"Cross-Origin-Embedder-Policy",
	} {
		if _, ok := rec.Header()[h]; ok {
			t.Errorf("%s was sent for an empty value", h)
		}
	}
}

// TestCORPCanBeOverriddenPerRoute documents the escape hatch for the mixed
// case: a strict chain-wide CORP with public assets served through it.
func TestCORPCanBeOverriddenPerRoute(t *testing.T) {
	mw := secureheaders.Middleware(
		secureheaders.WithCrossOriginResourcePolicy(secureheaders.CORPSameOrigin))

	rec := httptest.NewRecorder()
	mw(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cross-Origin-Resource-Policy", string(secureheaders.CORPCrossOrigin))
	})).ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/avatar.png", nil))

	if got := rec.Header().Get("Cross-Origin-Resource-Policy"); got != "cross-origin" {
		t.Errorf("Cross-Origin-Resource-Policy = %q, want the handler's value", got)
	}
}
