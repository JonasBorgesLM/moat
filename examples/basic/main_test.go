package main

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/JonasBorgesLM/moat/csrf"
)

const host = "app.example.com"

// newTestServer builds the example's handler over a temporary public directory.
func newTestServer(t *testing.T) http.Handler {
	t.Helper()

	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "style.css"), []byte("body{}"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(filepath.Dir(dir), "outside.txt"), []byte("secret"), 0o600); err != nil {
		t.Fatal(err)
	}

	secret, err := csrf.GenerateSecret()
	if err != nil {
		t.Fatal(err)
	}
	handler, cleanup, err := newServer(secret, dir)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(cleanup)
	return handler
}

// TestSmoke walks the example end to end. It is a smoke test rather than an
// exhaustive one -- the components have their own suites -- but it does have to
// prove the wiring is right, because wiring is what an example teaches.
func TestSmoke(t *testing.T) {
	handler := newTestServer(t)

	get := func(path string) *httptest.ResponseRecorder {
		r := httptest.NewRequest(http.MethodGet, "https://"+host+path, nil)
		r.Host = host
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, r)
		return rec
	}

	// The form renders, with headers and a token.
	rec := get("/")
	if rec.Code != http.StatusOK {
		t.Fatalf("GET /: status = %d, body %q", rec.Code, rec.Body)
	}
	if rec.Header().Get("Content-Security-Policy") == "" {
		t.Error("security headers missing")
	}
	if !strings.Contains(rec.Body.String(), csrf.DefaultFieldName) {
		t.Error("the form has no CSRF field")
	}
	cookies := rec.Result().Cookies()
	if len(cookies) != 1 {
		t.Fatalf("issued %d cookies, want 1", len(cookies))
	}

	// Pull the token back out of the rendered form.
	token := extractToken(t, rec.Body.String())

	post := func(values url.Values, withToken bool) *httptest.ResponseRecorder {
		if withToken {
			values.Set(csrf.DefaultFieldName, token)
		}
		r := httptest.NewRequest(http.MethodPost, "https://"+host+"/subscribe", strings.NewReader(values.Encode()))
		r.Host = host
		r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		r.Header.Set("Origin", "https://"+host)
		r.AddCookie(cookies[0])
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, r)
		return rec
	}

	tests := []struct {
		name       string
		values     url.Values
		withToken  bool
		wantStatus int
	}{
		{
			name:       "a valid submission",
			values:     url.Values{"email": {"ada@example.com"}, "name": {"Ada Lovelace"}},
			withToken:  true,
			wantStatus: http.StatusOK,
		},
		{
			name:       "without a CSRF token",
			values:     url.Values{"email": {"ada@example.com"}, "name": {"Ada Lovelace"}},
			wantStatus: http.StatusForbidden,
		},
		{
			name:       "an invalid email",
			values:     url.Values{"email": {"not-an-email"}, "name": {"Ada"}},
			withToken:  true,
			wantStatus: http.StatusBadRequest,
		},
		{
			name:       "markup in a name field",
			values:     url.Values{"email": {"ada@example.com"}, "name": {"<script>alert(1)</script>"}},
			withToken:  true,
			wantStatus: http.StatusBadRequest,
		},
		{
			name:       "an empty name",
			values:     url.Values{"email": {"ada@example.com"}, "name": {""}},
			withToken:  true,
			wantStatus: http.StatusBadRequest,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			rec := post(tc.values, tc.withToken)
			if rec.Code != tc.wantStatus {
				t.Errorf("status = %d, want %d (body %q)", rec.Code, tc.wantStatus, rec.Body)
			}
		})
	}

	// The file route serves what it should and refuses what it should not.
	if rec := get("/files/style.css"); rec.Code != http.StatusOK {
		t.Errorf("GET /files/style.css: status = %d, want 200", rec.Code)
	}
	for _, attempt := range []string{"/files/../outside.txt", "/files/../../etc/passwd"} {
		rec := get(attempt)
		if rec.Code == http.StatusOK {
			t.Errorf("GET %s: status = 200; traversal was served", attempt)
		}
	}
}

// TestRateLimit checks the limiter is actually in the chain, and first.
func TestRateLimit(t *testing.T) {
	handler := newTestServer(t)

	var last *httptest.ResponseRecorder
	saw429 := false
	for range 25 { // the example configures a burst of 20
		r := httptest.NewRequest(http.MethodGet, "https://"+host+"/", nil)
		r.Host = host
		r.RemoteAddr = "203.0.113.99:1234"
		last = httptest.NewRecorder()
		handler.ServeHTTP(last, r)
		if last.Code == http.StatusTooManyRequests {
			saw429 = true
			break
		}
	}
	if !saw429 {
		t.Fatalf("no request was rate limited in 25 attempts (last status %d)", last.Code)
	}
	if last.Header().Get("Retry-After") == "" {
		t.Error("the 429 has no Retry-After")
	}
}

// TestOversizedBodyIsRejectedBeforeCSRF pins the ordering the comments in
// main.go claim. If the two lines were swapped, this would be a 403 -- after
// CSRF had already parsed an unbounded form body.
func TestOversizedBodyIsRejectedBeforeCSRF(t *testing.T) {
	handler := newTestServer(t)

	body := "name=" + strings.Repeat("A", 2<<20)
	r := httptest.NewRequest(http.MethodPost, "https://"+host+"/subscribe", strings.NewReader(body))
	r.Host = host
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	r.Header.Set("Origin", "https://"+host)

	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, r)

	if rec.Code != http.StatusRequestEntityTooLarge {
		t.Errorf("status = %d, want 413: the body limit must run before CSRF parses the form", rec.Code)
	}
}

func TestLoadSecret(t *testing.T) {
	tests := []struct {
		name    string
		value   string
		wantErr bool
	}{
		{"unset", "", true},
		{"not base64", "!!!not base64!!!", true},
		{"valid", "YWJjZGVmZ2hpamtsbW5vcHFyc3R1dnd4eXoxMjM0NTY=", false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Setenv("CSRF_SECRET", tc.value)
			_, err := loadSecret()
			if (err != nil) != tc.wantErr {
				t.Errorf("loadSecret() error = %v, wantErr = %v", err, tc.wantErr)
			}
		})
	}
}

// extractToken pulls the hidden field's value out of the rendered form.
func extractToken(t *testing.T, html string) string {
	t.Helper()
	const marker = `name="` + csrf.DefaultFieldName + `" value="`
	i := strings.Index(html, marker)
	if i < 0 {
		t.Fatalf("no CSRF field in the rendered form:\n%s", html)
	}
	rest := html[i+len(marker):]
	j := strings.IndexByte(rest, '"')
	if j < 0 {
		t.Fatal("malformed CSRF field")
	}
	return rest[:j]
}
