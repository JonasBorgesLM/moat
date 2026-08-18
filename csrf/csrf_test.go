package csrf_test

import (
	"errors"
	"fmt"
	"html/template"
	"io"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/JonasBorgesLM/gosecure/csrf"
)

const testHost = "app.example.com"

func testSecret(t *testing.T) []byte {
	t.Helper()
	secret, err := csrf.GenerateSecret()
	if err != nil {
		t.Fatal(err)
	}
	return secret
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
		body = url.Values{"gosecure.csrf": {o.formToken}, "amount": {"100"}}.Encode()
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
		secret  []byte
		wantErr error
	}{
		{"a 32-byte secret is accepted", make([]byte, 32), nil},
		{"a longer secret is accepted", make([]byte, 64), nil},
		{"31 bytes is rejected", make([]byte, 31), csrf.ErrSecretTooShort},
		{"an empty secret is rejected", nil, csrf.ErrSecretTooShort},
		{"a short human-chosen secret is rejected", []byte("hunter2"), csrf.ErrSecretTooShort},
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
// cannot change how tokens verify.
func TestNewCopiesTheSecret(t *testing.T) {
	secret := testSecret(t)
	p, err := csrf.New(secret)
	if err != nil {
		t.Fatal(err)
	}
	cookie, token := issue(t, p)

	for i := range secret {
		secret[i] = 0
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
	if len(a) != csrf.MinSecretLen {
		t.Errorf("len = %d, want %d", len(a), csrf.MinSecretLen)
	}
	b, err := csrf.GenerateSecret()
	if err != nil {
		t.Fatal(err)
	}
	if string(a) == string(b) {
		t.Error("two generated secrets are identical")
	}
	// It must be usable directly, with no further processing.
	if _, err := csrf.New(a); err != nil {
		t.Errorf("New rejected a generated secret: %v", err)
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

	if got := rec.Body.String(); got != first {
		t.Errorf("token changed on a request that already had a cookie: %q then %q", first, got)
	}
	if cookies := rec.Result().Cookies(); len(cookies) != 0 {
		t.Errorf("re-issued %d cookies for a request that already had one", len(cookies))
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
				cookie:      &http.Cookie{Name: "__Host-gosecure.csrf", Value: "attacker-chosen-value"},
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

	body := `{"gosecure.csrf": "` + tok + `"}`
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
			if err := mw.WriteField("gosecure.csrf", tc.token); err != nil {
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
	if seen != tok {
		t.Errorf("error handler saw token %q, want %q", seen, tok)
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
			r.AddCookie(&http.Cookie{Name: "__Host-gosecure.csrf", Value: value})
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
			wantName:   "gosecure.csrf",
			wantSecure: false,
			wantPath:   "/",
		},
		{
			name:       "a Domain drops the __Host- prefix",
			opts:       []csrf.Option{csrf.WithCookieDomain("example.com")},
			wantName:   "gosecure.csrf",
			wantSecure: true,
			wantPath:   "/",
			wantDomain: "example.com",
		},
		{
			name:       "a narrowed Path drops the __Host- prefix",
			opts:       []csrf.Option{csrf.WithCookiePath("/app")},
			wantName:   "gosecure.csrf",
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

			c := rec.Result().Cookies()[0]
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
	secret := []byte("a-32-byte-or-longer-secret-value")

	protector, err := csrf.New(secret)
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

	fmt.Println(rec.Code, strings.Contains(rec.Body.String(), "gosecure.csrf"))
	// Output: 200 true
}

// ExampleGenerateSecret returns a secret and never prints it. Store the result
// the way you store other secrets.
func ExampleGenerateSecret() {
	secret, err := csrf.GenerateSecret()
	if err != nil {
		return
	}
	fmt.Println(len(secret))
	// Output: 32
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
