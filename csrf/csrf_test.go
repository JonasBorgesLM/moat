package csrf_test

import (
	"bufio"
	"encoding/base64"
	"errors"
	"fmt"
	"html/template"
	"io"
	"mime/multipart"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"

	"github.com/JonasBorgesLM/moat/csrf"
	"github.com/JonasBorgesLM/moat/secret"
)

const testHost = "app.example.com"

func testSecret(t *testing.T) secret.Value {
	t.Helper()
	v, err := csrf.GenerateSecret()
	if err != nil {
		t.Fatal(err)
	}
	return v
}

// echoHandler reports the token it can see, so tests can check that a token is
// available to handlers on both accepted and rejected requests.
func echoHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		token, ok := csrf.Token(r)
		if !ok {
			http.Error(w, "no token", http.StatusInternalServerError)
			return
		}
		// #nosec G705 -- this writes the token as plain text into a test
		// recorder, not as HTML into a page. ExampleNew shows the html/template
		// form that real code should use.
		fmt.Fprint(w, token)
	})
}

// issue performs a GET through the protector and returns the cookie it set and
// the token the handler saw.
func issue(t *testing.T, p *csrf.Protector) (*http.Cookie, string) {
	t.Helper()
	rec := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "https://"+testHost+"/form", nil)
	r.Host = testHost
	p.Middleware(echoHandler()).ServeHTTP(rec, r)

	if rec.Code != http.StatusOK {
		t.Fatalf("GET returned %d, want 200", rec.Code)
	}
	cookies := rec.Result().Cookies()
	if len(cookies) != 1 {
		t.Fatalf("GET set %d cookies, want 1", len(cookies))
	}
	token := rec.Body.String()
	if token == "" {
		t.Fatal("GET produced no token")
	}
	return cookies[0], token
}

// post builds an unsafe request carrying the given cookie and token.
type postOpts struct {
	cookie      *http.Cookie
	headerToken string
	formToken   string
	origin      string
	referer     string
	noOrigin    bool
	method      string
	contentType string
	body        string
}

func post(t *testing.T, p *csrf.Protector, o postOpts) *httptest.ResponseRecorder {
	t.Helper()

	method := o.method
	if method == "" {
		method = http.MethodPost
	}

	body := o.body
	contentType := o.contentType
	if o.formToken != "" && body == "" {
		body = url.Values{"moat.csrf": {o.formToken}, "amount": {"100"}}.Encode()
		if contentType == "" {
			contentType = "application/x-www-form-urlencoded"
		}
	}

	r := httptest.NewRequest(method, "https://"+testHost+"/transfer", strings.NewReader(body))
	r.Host = testHost
	if contentType != "" {
		r.Header.Set("Content-Type", contentType)
	}
	if o.cookie != nil {
		r.AddCookie(o.cookie)
	}
	if o.headerToken != "" {
		r.Header.Set("X-CSRF-Token", o.headerToken)
	}
	switch {
	case o.noOrigin:
		// leave both headers unset
	case o.origin != "":
		r.Header.Set("Origin", o.origin)
	case o.referer != "":
		r.Header.Set("Referer", o.referer)
	default:
		r.Header.Set("Origin", "https://"+testHost)
	}

	rec := httptest.NewRecorder()
	p.Middleware(echoHandler()).ServeHTTP(rec, r)
	return rec
}

func TestNew(t *testing.T) {
	tests := []struct {
		name    string
		secret  secret.Value
		wantErr error
	}{
		{"a 32-byte secret is accepted", secret.New(make([]byte, 32)), nil},
		{"a longer secret is accepted", secret.New(make([]byte, 64)), nil},
		{"31 bytes is rejected", secret.New(make([]byte, 31)), csrf.ErrSecretTooShort},
		{"an empty secret is rejected", secret.Value{}, csrf.ErrSecretTooShort},
		{"a short human-chosen secret is rejected", secret.New([]byte("hunter2")), csrf.ErrSecretTooShort},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			p, err := csrf.New(tc.secret)
			if !errors.Is(err, tc.wantErr) {
				t.Fatalf("New error = %v, want %v", err, tc.wantErr)
			}
			if tc.wantErr == nil && p == nil {
				t.Fatal("New returned a nil Protector without an error")
			}
		})
	}
}

// TestNewCopiesTheSecret checks that mutating the caller's slice afterwards
// cannot change how tokens verify. secret.Value copies on the way in and on the
// way out, so a caller holding either slice cannot reach the Protector's key.
func TestNewCopiesTheSecret(t *testing.T) {
	key := testSecret(t)
	p, err := csrf.New(key)
	if err != nil {
		t.Fatal(err)
	}
	cookie, token := issue(t, p)

	// Mutate the bytes the caller can still see, both from the Value and from
	// the slice New was handed.
	raw := key.Bytes()
	for i := range raw {
		raw[i] = 0
	}

	if rec := post(t, p, postOpts{cookie: cookie, headerToken: token}); rec.Code != http.StatusOK {
		t.Errorf("status = %d after mutating the caller's secret slice, want 200", rec.Code)
	}
}

func TestGenerateSecret(t *testing.T) {
	a, err := csrf.GenerateSecret()
	if err != nil {
		t.Fatal(err)
	}
	if a.Len() != csrf.MinSecretLen {
		t.Errorf("len = %d, want %d", a.Len(), csrf.MinSecretLen)
	}
	b, err := csrf.GenerateSecret()
	if err != nil {
		t.Fatal(err)
	}
	if a.Equal(b) {
		t.Error("two generated secrets are identical")
	}
	// It must be usable directly, with no further processing.
	if _, err := csrf.New(a); err != nil {
		t.Errorf("New rejected a generated secret: %v", err)
	}
}

// TestGeneratedSecretDoesNotPrint is the reason GenerateSecret returns a
// secret.Value rather than a []byte: the value it hands back must survive
// contact with the formatting and logging paths an application will inevitably
// point at its config.
func TestGeneratedSecretDoesNotPrint(t *testing.T) {
	v, err := csrf.GenerateSecret()
	if err != nil {
		t.Fatal(err)
	}
	raw := string(v.Bytes())

	for _, out := range []string{
		fmt.Sprintf("%v", v),
		fmt.Sprintf("%+v", v),
		fmt.Sprintf("%#v", v),
		fmt.Sprintf("%s", v),
		fmt.Sprintf("%x", v),
		fmt.Sprintf("%d", v),
		fmt.Sprintf("%v", struct{ Secret secret.Value }{v}),
	} {
		if strings.Contains(out, raw) {
			t.Errorf("a generated secret leaked through formatting: %s", out)
		}
	}
}

// TestSafeMethodIssuesCookieAndToken covers the issuing half of the flow.
func TestSafeMethodIssuesCookieAndToken(t *testing.T) {
	p, err := csrf.New(testSecret(t))
	if err != nil {
		t.Fatal(err)
	}

	for _, method := range []string{http.MethodGet, http.MethodHead, http.MethodOptions} {
		t.Run(method, func(t *testing.T) {
			rec := httptest.NewRecorder()
			r := httptest.NewRequest(method, "https://"+testHost+"/", nil)
			r.Host = testHost
			p.Middleware(echoHandler()).ServeHTTP(rec, r)

			if rec.Code != http.StatusOK {
				t.Fatalf("status = %d, want 200", rec.Code)
			}
			cookies := rec.Result().Cookies()
			if len(cookies) != 1 {
				t.Fatalf("set %d cookies, want 1", len(cookies))
			}
			c := cookies[0]
			if !c.HttpOnly {
				t.Error("cookie is not HttpOnly")
			}
			if !c.Secure {
				t.Error("cookie is not Secure")
			}
			if c.SameSite != http.SameSiteLaxMode {
				t.Errorf("SameSite = %v, want Lax", c.SameSite)
			}
			if c.Path != "/" {
				t.Errorf("Path = %q, want /", c.Path)
			}
			if c.Domain != "" {
				t.Errorf("Domain = %q, want empty (a Domain lets subdomains overwrite the cookie)", c.Domain)
			}
			if !strings.HasPrefix(c.Name, "__Host-") {
				t.Errorf("cookie name = %q, want the __Host- prefix", c.Name)
			}
			if c.Value == token(t, rec) {
				t.Error("the cookie value equals the token; the token must be a signature over the cookie, not the cookie")
			}
		})
	}
}

func token(t *testing.T, rec *httptest.ResponseRecorder) string {
	t.Helper()
	return rec.Body.String()
}

// TestExistingCookieIsReused checks that a valid cookie is not replaced on
// every request, which would invalidate any form already rendered.
//
// It is the *cookie* that must be stable, not the token. Tokens carry a fresh
// one-time pad per response and are expected to differ every time; the property
// that matters is that both encodings still verify against the one cookie. An
// earlier version of this test asserted the token bytes were identical, which
// is exactly the BREACH precondition the masking removed.
func TestExistingCookieIsReused(t *testing.T) {
	p, err := csrf.New(testSecret(t))
	if err != nil {
		t.Fatal(err)
	}
	cookie, first := issue(t, p)

	rec := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "https://"+testHost+"/", nil)
	r.Host = testHost
	r.AddCookie(cookie)
	p.Middleware(echoHandler()).ServeHTTP(rec, r)

	second := rec.Body.String()
	if cookies := rec.Result().Cookies(); len(cookies) != 0 {
		t.Errorf("re-issued %d cookies for a request that already had one", len(cookies))
	}
	if second == first {
		t.Error("the token was byte-identical across two responses; the per-response mask is not being applied")
	}
	// Both must verify against the same cookie.
	for name, tok := range map[string]string{"first": first, "second": second} {
		if rec := post(t, p, postOpts{cookie: cookie, headerToken: tok}); rec.Code != http.StatusOK {
			t.Errorf("the %s token did not verify against the reused cookie: status %d", name, rec.Code)
		}
	}
}

func TestVerification(t *testing.T) {
	p, err := csrf.New(testSecret(t))
	if err != nil {
		t.Fatal(err)
	}
	cookie, tok := issue(t, p)

	// A second, independent cookie/token pair, for the cross-pair case.
	otherCookie, otherToken := issue(t, p)

	// A protector with a different secret, for the rotated-secret case.
	other, err := csrf.New(testSecret(t))
	if err != nil {
		t.Fatal(err)
	}
	_, foreignToken := issue(t, other)

	tests := []struct {
		name       string
		opts       postOpts
		wantStatus int
	}{
		{
			name:       "a valid token in the header is accepted",
			opts:       postOpts{cookie: cookie, headerToken: tok},
			wantStatus: http.StatusOK,
		},
		{
			name:       "a valid token in the form field is accepted",
			opts:       postOpts{cookie: cookie, formToken: tok},
			wantStatus: http.StatusOK,
		},
		{
			name:       "PUT is verified too",
			opts:       postOpts{cookie: cookie, headerToken: tok, method: http.MethodPut},
			wantStatus: http.StatusOK,
		},
		{
			name:       "DELETE is verified too",
			opts:       postOpts{cookie: cookie, headerToken: tok, method: http.MethodDelete},
			wantStatus: http.StatusOK,
		},

		// Missing pieces
		{
			name:       "no token at all is rejected",
			opts:       postOpts{cookie: cookie},
			wantStatus: http.StatusForbidden,
		},
		{
			name:       "no cookie is rejected",
			opts:       postOpts{headerToken: tok},
			wantStatus: http.StatusForbidden,
		},
		{
			name:       "an empty token is rejected",
			opts:       postOpts{cookie: cookie, headerToken: " "},
			wantStatus: http.StatusForbidden,
		},

		// Tampering
		{
			name:       "a tampered token is rejected",
			opts:       postOpts{cookie: cookie, headerToken: flip(tok)},
			wantStatus: http.StatusForbidden,
		},
		{
			name:       "a truncated token is rejected",
			opts:       postOpts{cookie: cookie, headerToken: tok[:len(tok)-1]},
			wantStatus: http.StatusForbidden,
		},
		{
			name:       "an extended token is rejected",
			opts:       postOpts{cookie: cookie, headerToken: tok + "A"},
			wantStatus: http.StatusForbidden,
		},
		{
			name:       "the cookie value submitted as the token is rejected",
			opts:       postOpts{cookie: cookie, headerToken: cookie.Value},
			wantStatus: http.StatusForbidden,
		},

		// Cross-pair: the attack a naive implementation misses.
		{
			name:       "a token belonging to a different cookie is rejected",
			opts:       postOpts{cookie: cookie, headerToken: otherToken},
			wantStatus: http.StatusForbidden,
		},
		{
			name:       "a cookie belonging to a different token is rejected",
			opts:       postOpts{cookie: otherCookie, headerToken: tok},
			wantStatus: http.StatusForbidden,
		},
		{
			name:       "a token signed with a different secret is rejected",
			opts:       postOpts{cookie: cookie, headerToken: foreignToken},
			wantStatus: http.StatusForbidden,
		},

		// Attacker-planted cookie: they can set a cookie, but cannot sign it.
		{
			name: "an attacker-chosen cookie with a matching plaintext token is rejected",
			opts: postOpts{
				// #nosec G124 -- deliberately a bare cookie with no security
				// attributes: it stands in for one an attacker planted, and the
				// point of the case is that planting it achieves nothing.
				cookie:      &http.Cookie{Name: "__Host-moat.csrf", Value: "attacker-chosen-value"},
				headerToken: "attacker-chosen-value",
			},
			wantStatus: http.StatusForbidden,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			rec := post(t, p, tc.opts)
			if rec.Code != tc.wantStatus {
				t.Errorf("status = %d, want %d (body %q)", rec.Code, tc.wantStatus, rec.Body)
			}
		})
	}
}

// flip changes one character of a token, keeping it the same length and still
// valid base64.
func flip(token string) string {
	b := []byte(token)
	if b[0] == 'A' {
		b[0] = 'B'
	} else {
		b[0] = 'A'
	}
	return string(b)
}

func TestOriginValidation(t *testing.T) {
	p, err := csrf.New(testSecret(t))
	if err != nil {
		t.Fatal(err)
	}
	cookie, tok := issue(t, p)

	tests := []struct {
		name       string
		opts       postOpts
		wantStatus int
	}{
		{
			name:       "a same-origin request is accepted",
			opts:       postOpts{cookie: cookie, headerToken: tok, origin: "https://" + testHost},
			wantStatus: http.StatusOK,
		},
		{
			name:       "a matching Referer is accepted when Origin is absent",
			opts:       postOpts{cookie: cookie, headerToken: tok, referer: "https://" + testHost + "/form"},
			wantStatus: http.StatusOK,
		},
		{
			name:       "the host comparison is case-insensitive",
			opts:       postOpts{cookie: cookie, headerToken: tok, origin: "https://APP.example.COM"},
			wantStatus: http.StatusOK,
		},

		// The attack: a valid token replayed from another origin.
		{
			name:       "a cross-origin request is rejected even with a valid token",
			opts:       postOpts{cookie: cookie, headerToken: tok, origin: "https://attacker.example"},
			wantStatus: http.StatusForbidden,
		},
		{
			name:       "a subdomain is not the same origin",
			opts:       postOpts{cookie: cookie, headerToken: tok, origin: "https://evil." + testHost},
			wantStatus: http.StatusForbidden,
		},
		{
			name:       "a suffix-matching host is rejected",
			opts:       postOpts{cookie: cookie, headerToken: tok, origin: "https://evil-" + testHost},
			wantStatus: http.StatusForbidden,
		},
		{
			name:       "a host that merely contains the expected one is rejected",
			opts:       postOpts{cookie: cookie, headerToken: tok, origin: "https://" + testHost + ".attacker.example"},
			wantStatus: http.StatusForbidden,
		},
		{
			name:       "a different port is a different origin",
			opts:       postOpts{cookie: cookie, headerToken: tok, origin: "https://" + testHost + ":8443"},
			wantStatus: http.StatusForbidden,
		},
		{
			name:       "a cross-origin Referer is rejected",
			opts:       postOpts{cookie: cookie, headerToken: tok, referer: "https://attacker.example/page"},
			wantStatus: http.StatusForbidden,
		},
		{
			name:       "an opaque null origin is rejected",
			opts:       postOpts{cookie: cookie, headerToken: tok, origin: "null"},
			wantStatus: http.StatusForbidden,
		},
		{
			name:       "a malformed Origin is rejected",
			opts:       postOpts{cookie: cookie, headerToken: tok, origin: "not a url"},
			wantStatus: http.StatusForbidden,
		},
		{
			name:       "no Origin and no Referer is rejected",
			opts:       postOpts{cookie: cookie, headerToken: tok, noOrigin: true},
			wantStatus: http.StatusForbidden,
		},
		{
			name:       "a Referer with no scheme is rejected",
			opts:       postOpts{cookie: cookie, headerToken: tok, referer: "/relative/path"},
			wantStatus: http.StatusForbidden,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			rec := post(t, p, tc.opts)
			if rec.Code != tc.wantStatus {
				t.Errorf("status = %d, want %d", rec.Code, tc.wantStatus)
			}
		})
	}
}

// TestOriginIsCheckedBeforeTheToken is the layering claim: a cross-origin
// request must be refused whether or not it also has a valid token.
func TestOriginIsCheckedIndependentlyOfTheToken(t *testing.T) {
	p, err := csrf.New(testSecret(t))
	if err != nil {
		t.Fatal(err)
	}
	cookie, tok := issue(t, p)

	// Valid token, wrong origin.
	if rec := post(t, p, postOpts{cookie: cookie, headerToken: tok, origin: "https://attacker.example"}); rec.Code != http.StatusForbidden {
		t.Errorf("valid token from a foreign origin: status = %d, want 403", rec.Code)
	}
	// Right origin, invalid token.
	if rec := post(t, p, postOpts{cookie: cookie, headerToken: flip(tok), origin: "https://" + testHost}); rec.Code != http.StatusForbidden {
		t.Errorf("invalid token from the right origin: status = %d, want 403", rec.Code)
	}
}

func TestTrustedOrigins(t *testing.T) {
	p, err := csrf.New(testSecret(t), csrf.WithTrustedOrigins("https://console.example.com", "https://"+testHost))
	if err != nil {
		t.Fatal(err)
	}
	cookie, tok := issue(t, p)

	tests := []struct {
		name       string
		origin     string
		wantStatus int
	}{
		{"a listed origin is accepted", "https://console.example.com", http.StatusOK},
		{"the request's own origin, also listed", "https://" + testHost, http.StatusOK},
		{"an unlisted origin is rejected", "https://other.example.com", http.StatusForbidden},
		// With an allow-list the scheme is pinned, unlike the default.
		{"the wrong scheme is rejected", "http://console.example.com", http.StatusForbidden},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			rec := post(t, p, postOpts{cookie: cookie, headerToken: tok, origin: tc.origin})
			if rec.Code != tc.wantStatus {
				t.Errorf("status = %d, want %d", rec.Code, tc.wantStatus)
			}
		})
	}
}

// TestBodyIsNotParsedForNonFormRequests is the audit fix: the middleware must
// not touch the body of a request it was not meant to parse.
func TestBodyIsNotParsedForNonFormRequests(t *testing.T) {
	p, err := csrf.New(testSecret(t))
	if err != nil {
		t.Fatal(err)
	}
	cookie, tok := issue(t, p)

	const payload = `{"amount": 100}`
	var seen string
	handler := p.Middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		seen = string(b)
	}))

	r := httptest.NewRequest(http.MethodPost, "https://"+testHost+"/transfer", strings.NewReader(payload))
	r.Host = testHost
	r.Header.Set("Content-Type", "application/json")
	r.Header.Set("Origin", "https://"+testHost)
	r.Header.Set("X-CSRF-Token", tok)
	r.AddCookie(cookie)

	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, r)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	if seen != payload {
		t.Errorf("handler read %q, want the untouched body %q", seen, payload)
	}
}

// TestJSONBodyCannotSupplyTheToken confirms the field lookup really is gated:
// a JSON body containing a field of the right name must not be consulted.
func TestJSONBodyCannotSupplyTheToken(t *testing.T) {
	p, err := csrf.New(testSecret(t))
	if err != nil {
		t.Fatal(err)
	}
	cookie, tok := issue(t, p)

	body := `{"moat.csrf": "` + tok + `"}`
	rec := post(t, p, postOpts{
		cookie:      cookie,
		contentType: "application/json",
		body:        body,
	})
	if rec.Code != http.StatusForbidden {
		t.Errorf("status = %d, want 403: a JSON body must not be consulted for the token", rec.Code)
	}
}

func TestMultipartFormToken(t *testing.T) {
	p, err := csrf.New(testSecret(t))
	if err != nil {
		t.Fatal(err)
	}
	cookie, tok := issue(t, p)

	tests := []struct {
		name       string
		token      string
		wantStatus int
	}{
		{"a valid token in a multipart field is accepted", tok, http.StatusOK},
		{"an invalid token in a multipart field is rejected", flip(tok), http.StatusForbidden},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			var body strings.Builder
			mw := multipart.NewWriter(&body)
			if err := mw.WriteField("moat.csrf", tc.token); err != nil {
				t.Fatal(err)
			}
			part, err := mw.CreateFormFile("upload", "photo.jpg")
			if err != nil {
				t.Fatal(err)
			}
			_, _ = part.Write([]byte("binary"))
			_ = mw.Close()

			rec := post(t, p, postOpts{
				cookie:      cookie,
				contentType: mw.FormDataContentType(),
				body:        body.String(),
			})
			if rec.Code != tc.wantStatus {
				t.Errorf("status = %d, want %d", rec.Code, tc.wantStatus)
			}
		})
	}
}

// TestTokenAvailableOnRejectedRequests: a handler re-rendering the form after a
// failure still needs a usable token.
func TestTokenAvailableOnRejectedRequests(t *testing.T) {
	var seen string
	errorHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		tok, ok := csrf.Token(r)
		if ok {
			seen = tok
		}
		w.WriteHeader(http.StatusForbidden)
	})

	p, err := csrf.New(testSecret(t), csrf.WithErrorHandler(errorHandler))
	if err != nil {
		t.Fatal(err)
	}
	cookie, tok := issue(t, p)

	rec := post(t, p, postOpts{cookie: cookie, headerToken: flip(tok)})
	if rec.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403", rec.Code)
	}
	// The token handed to the error handler is minted for *this* response, so
	// it is a different encoding from the one issued earlier. What the handler
	// needs is a token that works, not a particular string.
	if seen == "" {
		t.Fatal("the error handler saw no token; a form re-rendered after a failure would have none")
	}
	if again := post(t, p, postOpts{cookie: cookie, headerToken: seen}); again.Code != http.StatusOK {
		t.Errorf("the token given to the error handler does not verify: status %d", again.Code)
	}
}

// TestTokenWithoutMiddleware pins the reason Token returns a bool: the absence
// of the middleware must be detectable, not silently produce "".
func TestTokenWithoutMiddleware(t *testing.T) {
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	if tok, ok := csrf.Token(r); ok || tok != "" {
		t.Errorf("Token = (%q, %v), want (\"\", false)", tok, ok)
	}
	if tok, ok := csrf.Token(nil); ok || tok != "" {
		t.Errorf("Token(nil) = (%q, %v), want (\"\", false)", tok, ok)
	}
}

func TestMalformedCookieIsReplaced(t *testing.T) {
	p, err := csrf.New(testSecret(t))
	if err != nil {
		t.Fatal(err)
	}

	tests := []string{"", "not-base64!!", "c2hvcnQ"}
	for _, value := range tests {
		t.Run(fmt.Sprintf("value=%q", value), func(t *testing.T) {
			rec := httptest.NewRecorder()
			r := httptest.NewRequest(http.MethodGet, "https://"+testHost+"/", nil)
			r.Host = testHost
			// #nosec G124 -- a malformed cookie with no attributes is exactly
			// what this test needs; the assertion is that it gets replaced.
			r.AddCookie(&http.Cookie{Name: "__Host-moat.csrf", Value: value})
			p.Middleware(echoHandler()).ServeHTTP(rec, r)

			if rec.Code != http.StatusOK {
				t.Fatalf("status = %d, want 200", rec.Code)
			}
			if len(rec.Result().Cookies()) != 1 {
				t.Error("a malformed cookie was not replaced; the user would be stuck")
			}
		})
	}
}

func TestCookieOptions(t *testing.T) {
	tests := []struct {
		name       string
		opts       []csrf.Option
		wantName   string
		wantSecure bool
		wantPath   string
		wantDomain string
	}{
		{
			name:       "defaults use the __Host- prefix",
			wantName:   csrf.DefaultCookieName,
			wantSecure: true,
			wantPath:   "/",
		},
		{
			// __Host- requires Secure; keeping the name would make the browser
			// drop the cookie and break every request.
			name:       "an insecure cookie drops the __Host- prefix",
			opts:       []csrf.Option{csrf.WithInsecureCookie()},
			wantName:   "moat.csrf",
			wantSecure: false,
			wantPath:   "/",
		},
		{
			name:       "a Domain drops the __Host- prefix",
			opts:       []csrf.Option{csrf.WithCookieDomain("example.com")},
			wantName:   "moat.csrf",
			wantSecure: true,
			wantPath:   "/",
			wantDomain: "example.com",
		},
		{
			name:       "a narrowed Path drops the __Host- prefix",
			opts:       []csrf.Option{csrf.WithCookiePath("/app")},
			wantName:   "moat.csrf",
			wantSecure: true,
			wantPath:   "/app",
		},
		{
			name:       "an explicit name is kept",
			opts:       []csrf.Option{csrf.WithCookieName("my-csrf")},
			wantName:   "my-csrf",
			wantSecure: true,
			wantPath:   "/",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			p, err := csrf.New(testSecret(t), tc.opts...)
			if err != nil {
				t.Fatal(err)
			}
			rec := httptest.NewRecorder()
			r := httptest.NewRequest(http.MethodGet, "https://"+testHost+"/", nil)
			r.Host = testHost
			p.Middleware(echoHandler()).ServeHTTP(rec, r)

			c := lastCookie(t, rec)
			if c.Name != tc.wantName {
				t.Errorf("Name = %q, want %q", c.Name, tc.wantName)
			}
			if c.Secure != tc.wantSecure {
				t.Errorf("Secure = %v, want %v", c.Secure, tc.wantSecure)
			}
			if c.Path != tc.wantPath {
				t.Errorf("Path = %q, want %q", c.Path, tc.wantPath)
			}
			if c.Domain != tc.wantDomain {
				t.Errorf("Domain = %q, want %q", c.Domain, tc.wantDomain)
			}
		})
	}
}

func TestCustomNames(t *testing.T) {
	p, err := csrf.New(testSecret(t),
		csrf.WithHeaderName("X-My-Token"),
		csrf.WithFieldName("_token"),
	)
	if err != nil {
		t.Fatal(err)
	}
	cookie, tok := issue(t, p)

	// The custom header works.
	r := httptest.NewRequest(http.MethodPost, "https://"+testHost+"/", nil)
	r.Host = testHost
	r.Header.Set("Origin", "https://"+testHost)
	r.Header.Set("X-My-Token", tok)
	r.AddCookie(cookie)
	rec := httptest.NewRecorder()
	p.Middleware(echoHandler()).ServeHTTP(rec, r)
	if rec.Code != http.StatusOK {
		t.Errorf("custom header: status = %d, want 200", rec.Code)
	}

	// The default header no longer does.
	r = httptest.NewRequest(http.MethodPost, "https://"+testHost+"/", nil)
	r.Host = testHost
	r.Header.Set("Origin", "https://"+testHost)
	r.Header.Set("X-CSRF-Token", tok)
	r.AddCookie(cookie)
	rec = httptest.NewRecorder()
	p.Middleware(echoHandler()).ServeHTTP(rec, r)
	if rec.Code != http.StatusForbidden {
		t.Errorf("default header after renaming: status = %d, want 403", rec.Code)
	}

	// The custom form field works.
	body := url.Values{"_token": {tok}}.Encode()
	r = httptest.NewRequest(http.MethodPost, "https://"+testHost+"/", strings.NewReader(body))
	r.Host = testHost
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	r.Header.Set("Origin", "https://"+testHost)
	r.AddCookie(cookie)
	rec = httptest.NewRecorder()
	p.Middleware(echoHandler()).ServeHTTP(rec, r)
	if rec.Code != http.StatusOK {
		t.Errorf("custom field: status = %d, want 200", rec.Code)
	}
}

// TestRejectionDoesNotLeakTheReason: every failure mode must produce the same
// response, or the handler becomes a debugging aid for a forged request.
func TestRejectionDoesNotLeakTheReason(t *testing.T) {
	p, err := csrf.New(testSecret(t))
	if err != nil {
		t.Fatal(err)
	}
	cookie, tok := issue(t, p)

	cases := []postOpts{
		{cookie: cookie},                         // no token
		{headerToken: tok},                       // no cookie
		{cookie: cookie, headerToken: flip(tok)}, // bad token
		{cookie: cookie, headerToken: tok, origin: "https://evil.test"}, // bad origin
		{cookie: cookie, headerToken: tok, noOrigin: true},              // no origin
	}

	var first string
	for i, opts := range cases {
		rec := post(t, p, opts)
		got := fmt.Sprintf("%d|%s|%s", rec.Code, rec.Body.String(), rec.Header().Get("Content-Type"))
		if i == 0 {
			first = got
			continue
		}
		if got != first {
			t.Errorf("case %d response %q differs from %q; rejections must be indistinguishable", i, got, first)
		}
	}
}

func TestNilOptionsAreIgnored(t *testing.T) {
	p, err := csrf.New(testSecret(t), nil, csrf.WithCookieName(""), csrf.WithErrorHandler(nil))
	if err != nil {
		t.Fatal(err)
	}
	cookie, tok := issue(t, p)
	if rec := post(t, p, postOpts{cookie: cookie, headerToken: tok}); rec.Code != http.StatusOK {
		t.Errorf("status = %d, want 200", rec.Code)
	}
}

// formTemplate renders the hidden field. See ExampleNew.
var formTemplate = template.Must(template.New("form").Parse(
	`<input type="hidden" name="{{.FieldName}}" value="{{.Token}}">`))

func ExampleNew() {
	// In production, load this from your secret store. It must be identical on
	// every instance and stable across deploys.
	key := secret.New([]byte("a-32-byte-or-longer-secret-value"))

	protector, err := csrf.New(key)
	if err != nil {
		fmt.Println("csrf:", err)
		return
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/form", func(w http.ResponseWriter, r *http.Request) {
		token, ok := csrf.Token(r)
		if !ok {
			// The middleware is not in front of this handler. Returning a bare
			// string here would render an empty field and break every POST.
			http.Error(w, "csrf middleware not installed", http.StatusInternalServerError)
			return
		}
		// html/template encodes contextually. That -- not any sanitizer, and
		// certainly not hand-formatted HTML -- is what makes interpolation
		// safe, and it is worth modelling correctly even for a value this
		// package generated itself.
		_ = formTemplate.Execute(w, struct{ FieldName, Token string }{csrf.DefaultFieldName, token})
	})

	handler := protector.Middleware(mux)

	rec := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "https://app.example.com/form", nil)
	r.Host = "app.example.com"
	handler.ServeHTTP(rec, r)

	fmt.Println(rec.Code, strings.Contains(rec.Body.String(), "moat.csrf"))
	// Output: 200 true
}

// ExampleGenerateSecret returns a secret and never prints it. The secret.Value
// wrapper means that stays true even if you try: printing it yields the
// placeholder, and the bytes come out only through an explicit Bytes call.
func ExampleGenerateSecret() {
	key, err := csrf.GenerateSecret()
	if err != nil {
		return
	}

	fmt.Println(key.Len(), "bytes")
	fmt.Printf("printing it gives %v\n", key)

	// Hand it straight to New; there is no reason to unwrap it here.
	if _, err := csrf.New(key); err != nil {
		fmt.Println("csrf:", err)
	}

	// Output:
	// 32 bytes
	// printing it gives [REDACTED]
}

// ExampleToken shows the two-value form. The bool is what stops a missing
// middleware from silently rendering an empty token.
func ExampleToken() {
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		token, ok := csrf.Token(r)
		fmt.Println(token == "", ok)
	})

	// No middleware in front, so no token.
	handler.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "/", nil))
	// Output: true false
}

// --- Rotate ------------------------------------------------------------------

// lastCookie returns the cookie a browser would end up holding: when the
// middleware minted one and Rotate then replaced it, both are on the response
// and the last wins.
func lastCookie(t *testing.T, rec *httptest.ResponseRecorder) *http.Cookie {
	t.Helper()
	cookies := rec.Result().Cookies()
	if len(cookies) == 0 {
		t.Fatal("no cookies were set")
	}
	return cookies[len(cookies)-1]
}

// loginHandler simulates a privilege change: it rotates and reports the token
// Token(r) sees afterwards, which is what a real handler would render.
func loginHandler(t *testing.T, p *csrf.Protector, rotErr *error) http.Handler {
	t.Helper()
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, err := p.Rotate(w, r)
		if rotErr != nil {
			*rotErr = err
		}
		if err != nil {
			http.Error(w, "rotate failed", http.StatusInternalServerError)
			return
		}
		token, ok := csrf.Token(r)
		if !ok {
			http.Error(w, "no token", http.StatusInternalServerError)
			return
		}
		// #nosec G705 -- a library-generated CSRF token written as plain text so
		// the test client can submit it; not attacker-controlled and not HTML.
		_, _ = w.Write([]byte(token))
	})
}

// TestRotateInvalidatesTheOldToken is the fixation defence: a token computed
// from the pre-login cookie must stop verifying once the privilege level
// changes.
func TestRotateInvalidatesTheOldToken(t *testing.T) {
	p, err := csrf.New(testSecret(t))
	if err != nil {
		t.Fatal(err)
	}

	// What an attacker who planted the cookie would hold.
	oldCookie, oldToken := issue(t, p)

	// The victim logs in; the handler rotates.
	rec := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "https://"+testHost+"/login", nil)
	r.Host = testHost
	r.AddCookie(oldCookie)
	p.Middleware(loginHandler(t, p, nil)).ServeHTTP(rec, r)

	if rec.Code != http.StatusOK {
		t.Fatalf("login returned %d: %s", rec.Code, rec.Body)
	}
	newCookie := lastCookie(t, rec)
	newToken := rec.Body.String()

	if newCookie.Value == oldCookie.Value {
		t.Fatal("the cookie value was not rotated")
	}
	if newToken == oldToken {
		t.Fatal("the token was not rotated")
	}

	// The property that actually defeats fixation: the victim's browser now
	// sends newCookie, and the token the attacker precomputed does not match
	// it. (The old pair still verifies against itself -- this scheme is
	// stateless and has nothing to revoke -- but presenting it requires the
	// attacker's own browser and their own session, which is not the attack.)
	if got := post(t, p, postOpts{cookie: newCookie, headerToken: oldToken}); got.Code == http.StatusOK {
		t.Error("the old token verified against the new cookie")
	}
	if got := post(t, p, postOpts{cookie: oldCookie, headerToken: newToken}); got.Code == http.StatusOK {
		t.Error("the new token verified against the old cookie")
	}
	// And the new pair works.
	if got := post(t, p, postOpts{cookie: newCookie, headerToken: newToken}); got.Code != http.StatusOK {
		t.Errorf("the rotated pair was rejected: %d", got.Code)
	}
}

// TestRotateIsNotServerSideRevocation pins the documented limit of the
// stateless design, so the doc comment cannot drift into claiming more than the
// scheme can deliver.
func TestRotateIsNotServerSideRevocation(t *testing.T) {
	p, err := csrf.New(testSecret(t))
	if err != nil {
		t.Fatal(err)
	}
	oldCookie, oldToken := issue(t, p)

	rec := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "https://"+testHost+"/login", nil)
	r.Host = testHost
	r.AddCookie(oldCookie)
	p.Middleware(loginHandler(t, p, nil)).ServeHTTP(rec, r)

	if got := post(t, p, postOpts{cookie: oldCookie, headerToken: oldToken}); got.Code != http.StatusOK {
		t.Errorf("the old self-consistent pair was rejected (%d); the scheme has become "+
			"stateful, or Rotate now revokes -- either way §4.3 and the Rotate doc need updating", got.Code)
	}
}

// TestTokenAfterRotateIsTheNewOne is the trap the holder indirection exists to
// close: a stale Token(r) would render the old value into the page and break
// every subsequent POST.
func TestTokenAfterRotateIsTheNewOne(t *testing.T) {
	p, err := csrf.New(testSecret(t))
	if err != nil {
		t.Fatal(err)
	}

	var before, after string
	h := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		before, _ = csrf.Token(r)
		if _, err := p.Rotate(w, r); err != nil {
			t.Errorf("Rotate: %v", err)
			return
		}
		after, _ = csrf.Token(r)
	})

	rec := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "https://"+testHost+"/login", nil)
	r.Host = testHost
	p.Middleware(h).ServeHTTP(rec, r)

	if before == "" || after == "" {
		t.Fatalf("tokens missing: before=%q after=%q", before, after)
	}
	if before == after {
		t.Fatal("Token still reports the pre-rotation value; the page would render a dead token")
	}

	// And it must be the token that matches the cookie now on the response.
	if got := post(t, p, postOpts{cookie: lastCookie(t, rec), headerToken: after}); got.Code != http.StatusOK {
		t.Errorf("the post-rotation token does not match the new cookie: %d", got.Code)
	}
}

// TestRotateReturnsTheSameTokenTokenReports guards against the return value and
// the context drifting apart.
func TestRotateReturnsTheSameTokenTokenReports(t *testing.T) {
	p, err := csrf.New(testSecret(t))
	if err != nil {
		t.Fatal(err)
	}

	var returned, fromContext string
	h := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		returned, _ = p.Rotate(w, r)
		fromContext, _ = csrf.Token(r)
	})

	rec := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "https://"+testHost+"/login", nil)
	r.Host = testHost
	p.Middleware(h).ServeHTTP(rec, r)

	if returned != fromContext {
		t.Errorf("Rotate returned %q but Token reports %q", returned, fromContext)
	}
}

// TestRotateWithoutMiddleware covers a login route mounted outside the
// protected chain: there is no holder to update, so the return value is the
// only channel, and it must still be usable.
func TestRotateWithoutMiddleware(t *testing.T) {
	p, err := csrf.New(testSecret(t))
	if err != nil {
		t.Fatal(err)
	}

	rec := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPost, "https://"+testHost+"/login", nil)
	r.Host = testHost

	token, err := p.Rotate(rec, r)
	if err != nil {
		t.Fatalf("Rotate: %v", err)
	}
	if token == "" {
		t.Fatal("Rotate returned an empty token")
	}
	// Token reports nothing, because the middleware never ran -- and that is
	// the honest answer rather than a silent empty string.
	if got, ok := csrf.Token(r); ok || got != "" {
		t.Errorf("Token = %q, %v; want empty and false without the middleware", got, ok)
	}

	if got := post(t, p, postOpts{cookie: lastCookie(t, rec), headerToken: token}); got.Code != http.StatusOK {
		t.Errorf("the rotated pair from outside the chain was rejected: %d", got.Code)
	}
}

// TestRotateCookieKeepsItsAttributes: a rotated cookie that lost Secure,
// HttpOnly or SameSite would quietly downgrade the protection at exactly the
// moment the session becomes valuable.
func TestRotateCookieKeepsItsAttributes(t *testing.T) {
	p, err := csrf.New(testSecret(t))
	if err != nil {
		t.Fatal(err)
	}

	rec := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPost, "https://"+testHost+"/login", nil)
	r.Host = testHost
	if _, err := p.Rotate(rec, r); err != nil {
		t.Fatal(err)
	}

	c := lastCookie(t, rec)
	if !c.Secure {
		t.Error("the rotated cookie is not Secure")
	}
	if !c.HttpOnly {
		t.Error("the rotated cookie is not HttpOnly")
	}
	if c.SameSite != http.SameSiteLaxMode {
		t.Errorf("SameSite = %v, want Lax", c.SameSite)
	}
	if c.Path != "/" {
		t.Errorf("Path = %q, want /", c.Path)
	}
	if !strings.HasPrefix(c.Name, "__Host-") {
		t.Errorf("name = %q, want the __Host- prefix", c.Name)
	}
}

func TestRotateRejectsNilArguments(t *testing.T) {
	p, err := csrf.New(testSecret(t))
	if err != nil {
		t.Fatal(err)
	}
	r := httptest.NewRequest(http.MethodPost, "https://"+testHost+"/login", nil)

	if _, err := p.Rotate(nil, r); err == nil {
		t.Error("Rotate(nil, r) returned no error")
	}
	if _, err := p.Rotate(httptest.NewRecorder(), nil); err == nil {
		t.Error("Rotate(w, nil) returned no error")
	}
}

// TestRotateIsConcurrencySafe covers a handler that hands the request to
// goroutines, which is why the holder carries a mutex.
func TestRotateIsConcurrencySafe(t *testing.T) {
	p, err := csrf.New(testSecret(t))
	if err != nil {
		t.Fatal(err)
	}

	h := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var wg sync.WaitGroup
		for range 8 {
			wg.Add(1)
			go func() {
				defer wg.Done()
				_, _ = csrf.Token(r)
			}()
		}
		// Rotate concurrently with the readers. Under -race this is where a
		// plain string in the context would be caught.
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, _ = p.Rotate(httptest.NewRecorder(), r)
		}()
		wg.Wait()
	})

	rec := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "https://"+testHost+"/login", nil)
	r.Host = testHost
	p.Middleware(h).ServeHTTP(rec, r)
}

// TestRotateAfterWriteHeaderIsReported is the detection requirement: calling
// Rotate too late must fail loudly, because net/http drops a Set-Cookie added
// after the header block is serialized and the handler would otherwise believe
// it had rotated.
func TestRotateAfterWriteHeaderIsReported(t *testing.T) {
	p, err := csrf.New(testSecret(t))
	if err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		name  string
		begin func(w http.ResponseWriter)
	}{
		{"explicit WriteHeader", func(w http.ResponseWriter) { w.WriteHeader(http.StatusOK) }},
		{"implicit via Write", func(w http.ResponseWriter) { _, _ = w.Write([]byte("hello")) }},
		{"a redirect", func(w http.ResponseWriter) {
			http.Redirect(w, httptest.NewRequest(http.MethodGet, "/", nil), "/", http.StatusSeeOther)
		}},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			var rotErr error
			var token string
			h := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				tc.begin(w)
				token, rotErr = p.Rotate(w, r)
			})

			rec := httptest.NewRecorder()
			req := httptest.NewRequest(http.MethodGet, "https://"+testHost+"/login", nil)
			req.Host = testHost
			p.Middleware(h).ServeHTTP(rec, req)

			if !errors.Is(rotErr, csrf.ErrHeadersAlreadySent) {
				t.Fatalf("Rotate error = %v, want ErrHeadersAlreadySent", rotErr)
			}
			if token != "" {
				t.Errorf("Rotate returned token %q alongside an error", token)
			}
			// And it must genuinely have changed nothing: the only cookie on
			// the response is the one the middleware minted.
			if n := len(rec.Result().Cookies()); n != 1 {
				t.Errorf("response carries %d cookies, want 1; the late Rotate wrote one anyway", n)
			}
		})
	}
}

// TestRotateBeforeWriteHeaderStillWorks is the control for the test above: the
// detection must not fire on the correct ordering.
func TestRotateBeforeWriteHeaderStillWorks(t *testing.T) {
	p, err := csrf.New(testSecret(t))
	if err != nil {
		t.Fatal(err)
	}

	var rotErr error
	h := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, rotErr = p.Rotate(w, r)
		w.WriteHeader(http.StatusOK)
	})

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "https://"+testHost+"/login", nil)
	req.Host = testHost
	p.Middleware(h).ServeHTTP(rec, req)

	if rotErr != nil {
		t.Fatalf("Rotate on the correct ordering failed: %v", rotErr)
	}
}

// flushHijacker is a ResponseWriter with the optional capabilities a streaming
// or upgrading handler needs, so the test can prove they survive the wrapper.
type flushHijacker struct {
	http.ResponseWriter
	flushed  bool
	hijacked bool
}

func (f *flushHijacker) Flush() { f.flushed = true }

func (f *flushHijacker) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	f.hijacked = true
	return nil, nil, nil
}

// TestMiddlewareDoesNotHideFlusherOrHijacker pins that wrapping the
// ResponseWriter does not cost the rest of the chain its capabilities.
// http.ResponseController follows the Unwrap convention to reach them.
func TestMiddlewareDoesNotHideFlusherOrHijacker(t *testing.T) {
	p, err := csrf.New(testSecret(t))
	if err != nil {
		t.Fatal(err)
	}

	underlying := &flushHijacker{ResponseWriter: httptest.NewRecorder()}

	h := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		rc := http.NewResponseController(w)
		if err := rc.Flush(); err != nil {
			t.Errorf("ResponseController.Flush through the wrapper: %v", err)
		}
		if _, _, err := rc.Hijack(); err != nil {
			t.Errorf("ResponseController.Hijack through the wrapper: %v", err)
		}
	})

	req := httptest.NewRequest(http.MethodGet, "https://"+testHost+"/stream", nil)
	req.Host = testHost
	p.Middleware(h).ServeHTTP(underlying, req)

	if !underlying.flushed {
		t.Error("Flush did not reach the underlying ResponseWriter")
	}
	if !underlying.hijacked {
		t.Error("Hijack did not reach the underlying ResponseWriter")
	}
}

// TestRotateOutsideTheChainStillRotates pins that the late-call detection is a
// safety net and cannot disable the thing it guards: with no wrapper to consult,
// rotation must still happen.
func TestRotateOutsideTheChainStillRotates(t *testing.T) {
	p, err := csrf.New(testSecret(t))
	if err != nil {
		t.Fatal(err)
	}

	rec := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPost, "https://"+testHost+"/login", nil)
	r.Host = testHost

	token, err := p.Rotate(rec, r)
	if err != nil {
		t.Fatalf("Rotate outside the chain: %v", err)
	}
	if token == "" {
		t.Fatal("Rotate returned an empty token")
	}
	if got := post(t, p, postOpts{cookie: lastCookie(t, rec), headerToken: token}); got.Code != http.StatusOK {
		t.Errorf("the rotated pair was rejected: %d", got.Code)
	}
}

// TestTokenIsMaskedPerResponse is the R4 MEDIUM-1 regression.
//
// An unmasked token is a pure function of the cookie, so it is byte-identical in
// every response until the cookie rotates. That is the precondition for BREACH:
// an app serving compressed HTML that reflects any attacker-influenced string
// into the same response becomes an adaptive compression oracle, and a constant
// secret in that response is recoverable byte by byte. The mask removes the
// constant.
//
// NEGATIVE CONTROL: make maskToken return
// base64.RawURLEncoding.EncodeToString(raw) and unmaskToken decode it
// symmetrically — the pre-fix design — and the distinctness assertion fails on
// the second response. Verified red.
func TestTokenIsMaskedPerResponse(t *testing.T) {
	p, err := csrf.New(testSecret(t))
	if err != nil {
		t.Fatal(err)
	}
	cookie, _ := issue(t, p)

	const responses = 25
	seen := make(map[string]int, responses)
	for i := range responses {
		rec := httptest.NewRecorder()
		r := httptest.NewRequest(http.MethodGet, "https://"+testHost+"/", nil)
		r.Host = testHost
		r.AddCookie(cookie)
		p.Middleware(echoHandler()).ServeHTTP(rec, r)

		tok := rec.Body.String()
		if first, dup := seen[tok]; dup {
			t.Fatalf("response %d repeated the token from response %d: the token is a constant across responses, which is what BREACH extracts", i, first)
		}
		seen[tok] = i

		// Distinct is worthless if they stop working.
		if got := post(t, p, postOpts{cookie: cookie, headerToken: tok}); got.Code != http.StatusOK {
			t.Fatalf("token from response %d did not verify: status %d", i, got.Code)
		}
	}

	// The masking must not be a rename: no two encodings may share the pad half
	// either, or the oracle just moves to the other half.
	pads := make(map[string]bool, responses)
	for tok := range seen {
		raw, err := base64.RawURLEncoding.DecodeString(tok)
		if err != nil {
			t.Fatalf("token is not valid base64url: %v", err)
		}
		if len(raw) != 64 {
			t.Fatalf("token decoded to %d bytes, want 64 (32-byte pad + 32-byte masked MAC)", len(raw))
		}
		if pads[string(raw[:32])] {
			t.Error("two responses reused the same pad")
		}
		pads[string(raw[:32])] = true
	}
}

// TestRotateIssuesAUsableMaskedToken checks the half of the format change that
// is easy to miss: Rotate mints its own token and must produce the same shape
// the middleware does, against the cookie it just set.
func TestRotateIssuesAUsableMaskedToken(t *testing.T) {
	p, err := csrf.New(testSecret(t))
	if err != nil {
		t.Fatal(err)
	}

	var rotated string
	var rotErr error
	h := p.Middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		rotated, rotErr = p.Rotate(w, r)
	}))

	rec := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "https://"+testHost+"/", nil)
	r.Host = testHost
	h.ServeHTTP(rec, r)
	if rotErr != nil {
		t.Fatalf("Rotate: %v", rotErr)
	}

	cookies := rec.Result().Cookies()
	if len(cookies) == 0 {
		t.Fatal("Rotate set no cookie")
	}
	newCookie := cookies[len(cookies)-1]

	if got := post(t, p, postOpts{cookie: newCookie, headerToken: rotated}); got.Code != http.StatusOK {
		t.Errorf("the rotated token did not verify against the rotated cookie: status %d", got.Code)
	}
	// And Token(r) inside the same request must agree with what Rotate returned.
	if raw, err := base64.RawURLEncoding.DecodeString(rotated); err != nil || len(raw) != 64 {
		t.Errorf("Rotate returned a token of the wrong shape (%d bytes, err %v)", len(raw), err)
	}
}

// TestMalformedTokenIsRejected covers the parse the mask introduced. Every input
// here is attacker-supplied, so none of these paths may accept, and none of them
// consults the secret.
func TestMalformedTokenIsRejected(t *testing.T) {
	p, err := csrf.New(testSecret(t))
	if err != nil {
		t.Fatal(err)
	}
	cookie, tok := issue(t, p)

	raw, err := base64.RawURLEncoding.DecodeString(tok)
	if err != nil {
		t.Fatal(err)
	}

	cases := map[string]string{
		"empty":                  "",
		"not base64":             "!!!!not-base64!!!!",
		"too short":              base64.RawURLEncoding.EncodeToString(raw[:32]),
		"too long":               base64.RawURLEncoding.EncodeToString(append(append([]byte(nil), raw...), 0)),
		"pad only":               base64.RawURLEncoding.EncodeToString(raw[:32]),
		"the bare unmasked MAC":  base64.RawURLEncoding.EncodeToString(raw[32:]),
		"one bit flipped in pad": base64.RawURLEncoding.EncodeToString(append([]byte{raw[0] ^ 1}, raw[1:]...)),
	}
	for name, bad := range cases {
		t.Run(name, func(t *testing.T) {
			if rec := post(t, p, postOpts{cookie: cookie, headerToken: bad}); rec.Code != http.StatusForbidden {
				t.Errorf("status = %d, want 403", rec.Code)
			}
		})
	}
}

// TestManyEncodingsOfOneTokenAreAllValid records a property of the masking that
// looks like a flaw and is not, so that nobody "fixes" it later.
//
// Because the mask is an XOR, every pair (pad, mac^pad) encodes the same MAC —
// swapping the two halves is just another valid encoding, and there are 2^256 of
// them. That is the point: the token has no canonical form, which is what stops
// two responses from sharing bytes. It grants an attacker nothing, because
// producing another encoding requires already holding one, and holding one is
// the thing being protected.
//
// What must not be forgeable is an encoding of a MAC the attacker does not have,
// and TestMalformedTokenIsRejected covers that: flipping a bit anywhere changes
// the recovered MAC and is refused.
func TestManyEncodingsOfOneTokenAreAllValid(t *testing.T) {
	p, err := csrf.New(testSecret(t))
	if err != nil {
		t.Fatal(err)
	}
	cookie, tok := issue(t, p)
	raw, err := base64.RawURLEncoding.DecodeString(tok)
	if err != nil {
		t.Fatal(err)
	}

	swapped := base64.RawURLEncoding.EncodeToString(append(append([]byte(nil), raw[32:]...), raw[:32]...))
	if swapped == tok {
		t.Fatal("the two halves happened to be equal; pick another secret")
	}
	if rec := post(t, p, postOpts{cookie: cookie, headerToken: swapped}); rec.Code != http.StatusOK {
		t.Errorf("a re-encoding of the same MAC was refused: status %d", rec.Code)
	}
}
