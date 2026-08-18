//go:build integration

package integration

import (
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/JonasBorgesLM/gosecure/csrf"
	"github.com/JonasBorgesLM/gosecure/pathguard"
	"github.com/JonasBorgesLM/gosecure/preset"
)

// harness is a running server plus a client that behaves like a browser: it
// keeps cookies in a jar and sends an Origin header on state-changing requests.
type harness struct {
	t      *testing.T
	url    string
	client *http.Client
}

// newHarness starts a TLS test server behind a preset chain.
//
// TLS is not incidental. The CSRF cookie is Secure and carries the __Host-
// prefix, so over plain HTTP a real cookie jar would refuse to send it back and
// every POST would fail for a reason that has nothing to do with the code under
// test. Serving over TLS is what makes this suite exercise the configuration
// that actually ships.
func newHarness(t *testing.T, cfg preset.Config) *harness {
	t.Helper()

	if cfg.CSRFSecret == nil && !cfg.DisableCSRF {
		secret, err := csrf.GenerateSecret()
		if err != nil {
			t.Fatal(err)
		}
		cfg.CSRFSecret = secret
	}

	chain, err := preset.API(cfg)
	if err != nil {
		t.Fatalf("preset.API: %v", err)
	}

	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "public.txt"), []byte("public file"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(filepath.Dir(root), "outside.txt"), []byte("secret"), 0o644); err != nil {
		t.Fatal(err)
	}
	guard, err := pathguard.New(root)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = guard.Close() })

	mux := http.NewServeMux()
	mux.HandleFunc("/form", func(w http.ResponseWriter, r *http.Request) {
		token, ok := csrf.Token(r)
		switch {
		case ok:
			fmt.Fprint(w, token)
		case cfg.DisableCSRF:
			// CSRF was switched off deliberately, so no token is expected.
			fmt.Fprint(w, "no-csrf")
		default:
			// The middleware should be in front of this handler and is not.
			// This is exactly the situation csrf.Token's bool exists to make
			// visible instead of rendering an empty field.
			http.Error(w, "csrf middleware missing", http.StatusInternalServerError)
		}
	})
	mux.HandleFunc("/transfer", func(w http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(r.Body)
		if err != nil {
			var maxErr *http.MaxBytesError
			if errors.As(err, &maxErr) {
				http.Error(w, "too large", http.StatusRequestEntityTooLarge)
				return
			}
			http.Error(w, "bad body", http.StatusBadRequest)
			return
		}
		fmt.Fprintf(w, "accepted %d bytes", len(body))
	})
	mux.Handle("/files/", http.StripPrefix("/files/", guard.FileServer()))

	srv := newTLSServer(t, chain.Then(mux))

	jar, err := cookiejar.New(nil)
	if err != nil {
		t.Fatal(err)
	}
	client := srv.Client()
	client.Jar = jar
	client.Timeout = 10 * time.Second
	// Do not follow redirects: a redirect would hide a status this suite is
	// asserting on.
	client.CheckRedirect = func(*http.Request, []*http.Request) error {
		return http.ErrUseLastResponse
	}

	return &harness{t: t, url: srv.URL, client: client}
}

// get performs a GET, returning the response with its body already read.
func (h *harness) get(path string) (*http.Response, string) {
	h.t.Helper()
	req, err := http.NewRequest(http.MethodGet, h.url+path, nil)
	if err != nil {
		h.t.Fatal(err)
	}
	return h.do(req)
}

// postForm performs a form POST with a browser-like Origin header.
func (h *harness) postForm(path string, values url.Values) (*http.Response, string) {
	h.t.Helper()
	req, err := http.NewRequest(http.MethodPost, h.url+path, strings.NewReader(values.Encode()))
	if err != nil {
		h.t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Origin", h.url)
	return h.do(req)
}

func (h *harness) do(req *http.Request) (*http.Response, string) {
	h.t.Helper()
	resp, err := h.client.Do(req)
	if err != nil {
		h.t.Fatalf("%s %s: %v", req.Method, req.URL, err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		h.t.Fatalf("reading body: %v", err)
	}
	return resp, string(body)
}

// token fetches a fresh CSRF token, which also puts the cookie in the jar.
func (h *harness) token() string {
	h.t.Helper()
	resp, body := h.get("/form")
	if resp.StatusCode != http.StatusOK {
		h.t.Fatalf("GET /form: status = %d, body %q", resp.StatusCode, body)
	}
	if body == "" {
		h.t.Fatal("GET /form produced no token")
	}
	return body
}

// TestFullFlow walks the sequence a browser performs, over a real connection
// with a real cookie jar.
func TestFullFlow(t *testing.T) {
	h := newHarness(t, preset.Config{RateLimitBurst: 50, RateLimitPerSec: 50})

	// 1. GET issues the cookie and the token.
	resp, token := h.get("/form")
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("GET /form: status = %d", resp.StatusCode)
	}
	if token == "" {
		t.Fatal("no token issued")
	}

	// The jar must actually hold the cookie. If it does not, the cookie's
	// attributes are wrong for a real browser and everything after this passes
	// only because the test cheated.
	u, _ := url.Parse(h.url)
	cookies := h.client.Jar.Cookies(u)
	if len(cookies) != 1 {
		t.Fatalf("the cookie jar holds %d cookies, want 1: the cookie attributes are not usable by a real client", len(cookies))
	}
	if !strings.HasPrefix(cookies[0].Name, "__Host-") {
		t.Errorf("cookie name = %q, want the __Host- prefix", cookies[0].Name)
	}

	// 2. A POST replaying the cookie and the token succeeds.
	resp, body := h.postForm("/transfer", url.Values{
		csrf.DefaultFieldName: {token},
		"amount":              {"100"},
	})
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("POST with a valid token: status = %d, body %q", resp.StatusCode, body)
	}

	// 3. A stale token is rejected.
	resp, _ = h.postForm("/transfer", url.Values{
		csrf.DefaultFieldName: {token[:len(token)-1] + "Z"},
		"amount":              {"100"},
	})
	if resp.StatusCode != http.StatusForbidden {
		t.Errorf("POST with a tampered token: status = %d, want 403", resp.StatusCode)
	}

	// 4. A missing token is rejected.
	resp, _ = h.postForm("/transfer", url.Values{"amount": {"100"}})
	if resp.StatusCode != http.StatusForbidden {
		t.Errorf("POST with no token: status = %d, want 403", resp.StatusCode)
	}
}

// TestCrossOriginPostIsRejected is the attack the whole CSRF layer exists for:
// a valid token replayed from another origin.
func TestCrossOriginPostIsRejected(t *testing.T) {
	h := newHarness(t, preset.Config{RateLimitBurst: 50, RateLimitPerSec: 50})
	token := h.token()

	body := url.Values{csrf.DefaultFieldName: {token}, "amount": {"100"}}.Encode()
	req, err := http.NewRequest(http.MethodPost, h.url+"/transfer", strings.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Origin", "https://attacker.example")

	resp, _ := h.do(req)
	if resp.StatusCode != http.StatusForbidden {
		t.Errorf("cross-origin POST with a valid token: status = %d, want 403", resp.StatusCode)
	}
}

// TestSecurityHeadersOnEveryResponse checks the headers survive the round trip
// on success and on the failures the middleware itself writes.
func TestSecurityHeadersOnEveryResponse(t *testing.T) {
	h := newHarness(t, preset.Config{RateLimitBurst: 50, RateLimitPerSec: 50})
	token := h.token()

	required := []string{
		"Content-Security-Policy",
		"Strict-Transport-Security",
		"X-Frame-Options",
		"X-Content-Type-Options",
		"Referrer-Policy",
		"Permissions-Policy",
	}

	responses := map[string]*http.Response{}
	resp, _ := h.get("/form")
	responses["GET /form (200)"] = resp
	resp, _ = h.get("/nope")
	responses["GET /nope (404)"] = resp
	resp, _ = h.postForm("/transfer", url.Values{})
	responses["POST without a token (403)"] = resp
	resp, _ = h.postForm("/transfer", url.Values{csrf.DefaultFieldName: {token}})
	responses["POST with a token (200)"] = resp
	resp, _ = h.get("/files/../../outside.txt")
	responses["GET traversal (404)"] = resp

	for name, resp := range responses {
		for _, header := range required {
			if resp.Header.Get(header) == "" {
				t.Errorf("%s: missing %s", name, header)
			}
		}
	}
}

// TestRateLimitOverTheWire checks the 429 and its Retry-After survive a real
// round trip, and that the limiter counts requests rather than connections.
func TestRateLimitOverTheWire(t *testing.T) {
	const burst = 3
	h := newHarness(t, preset.Config{
		DisableCSRF:     true,
		RateLimitBurst:  burst,
		RateLimitPerSec: 0.01, // slow enough that nothing refills mid-test
	})

	var statuses []int
	var lastResp *http.Response
	for range burst + 2 {
		resp, _ := h.get("/form")
		statuses = append(statuses, resp.StatusCode)
		lastResp = resp
	}

	for i := range burst {
		if statuses[i] != http.StatusOK {
			t.Errorf("request %d: status = %d, want 200 (statuses %v)", i, statuses[i], statuses)
		}
	}
	for i := burst; i < len(statuses); i++ {
		if statuses[i] != http.StatusTooManyRequests {
			t.Errorf("request %d: status = %d, want 429 (statuses %v)", i, statuses[i], statuses)
		}
	}

	retryAfter := lastResp.Header.Get("Retry-After")
	if retryAfter == "" {
		t.Fatal("429 response has no Retry-After")
	}
	secs, err := strconv.Atoi(retryAfter)
	if err != nil || secs < 1 {
		t.Errorf("Retry-After = %q, want a positive whole number of seconds", retryAfter)
	}
	if lastResp.Header.Get("RateLimit-Limit") != strconv.Itoa(burst) {
		t.Errorf("RateLimit-Limit = %q, want %d", lastResp.Header.Get("RateLimit-Limit"), burst)
	}
}

// TestOversizedBodyIsRejected exercises the limit against a real body written
// to a real connection, including the case where the declared length lies.
func TestOversizedBodyIsRejected(t *testing.T) {
	const limit = 512
	h := newHarness(t, preset.Config{
		DisableCSRF:     true,
		RateLimitBurst:  50,
		RateLimitPerSec: 50,
		MaxBodyBytes:    limit,
	})

	t.Run("a declared oversized body", func(t *testing.T) {
		req, err := http.NewRequest(http.MethodPost, h.url+"/transfer", strings.NewReader(strings.Repeat("A", limit*4)))
		if err != nil {
			t.Fatal(err)
		}
		req.Header.Set("Content-Type", "text/plain")
		resp, _ := h.do(req)
		if resp.StatusCode != http.StatusRequestEntityTooLarge {
			t.Errorf("status = %d, want 413", resp.StatusCode)
		}
	})

	t.Run("a chunked body that declares no length", func(t *testing.T) {
		// A body of unknown length is sent chunked, so the header check has
		// nothing to compare and MaxBytesReader has to catch it mid-read.
		req, err := http.NewRequest(http.MethodPost, h.url+"/transfer", io.NopCloser(strings.NewReader(strings.Repeat("A", limit*4))))
		if err != nil {
			t.Fatal(err)
		}
		req.ContentLength = -1
		req.Header.Set("Content-Type", "text/plain")
		resp, _ := h.do(req)
		if resp.StatusCode != http.StatusRequestEntityTooLarge {
			t.Errorf("status = %d, want 413", resp.StatusCode)
		}
	})

	t.Run("a body under the limit is accepted", func(t *testing.T) {
		req, err := http.NewRequest(http.MethodPost, h.url+"/transfer", strings.NewReader(strings.Repeat("A", 100)))
		if err != nil {
			t.Fatal(err)
		}
		req.Header.Set("Content-Type", "text/plain")
		resp, body := h.do(req)
		if resp.StatusCode != http.StatusOK {
			t.Errorf("status = %d, want 200 (body %q)", resp.StatusCode, body)
		}
	})
}

// TestTraversalOverTheWire sends the traversal encodings a client can actually
// put on the wire, which is a different set from what a unit test can construct
// directly, since net/http normalizes some of them before the handler sees them.
func TestTraversalOverTheWire(t *testing.T) {
	h := newHarness(t, preset.Config{
		DisableCSRF:     true,
		RateLimitBurst:  100,
		RateLimitPerSec: 100,
	})

	t.Run("a legitimate file is served", func(t *testing.T) {
		resp, body := h.get("/files/public.txt")
		if resp.StatusCode != http.StatusOK || body != "public file" {
			t.Errorf("status = %d, body = %q", resp.StatusCode, body)
		}
	})

	attempts := []string{
		"/files/../outside.txt",
		"/files/../../outside.txt",
		"/files/%2e%2e/outside.txt",
		"/files/%2e%2e%2foutside.txt",
		"/files/..%2foutside.txt",
		"/files/%252e%252e/outside.txt",
		"/files/....//outside.txt",
		"/files/sub/../../outside.txt",
		"/files/",
		"/files/.hidden",
	}
	for _, attempt := range attempts {
		t.Run(attempt, func(t *testing.T) {
			// Build the request without letting url.Parse normalize the path
			// away, so the server sees what a raw client would send.
			req, err := http.NewRequest(http.MethodGet, h.url+attempt, nil)
			if err != nil {
				t.Skipf("client refuses to send %q: %v", attempt, err)
			}
			resp, body := h.do(req)

			// The only thing that must never happen.
			if strings.Contains(body, "secret") {
				t.Fatalf("%s served content from outside the root: %q", attempt, body)
			}
			if resp.StatusCode == http.StatusOK {
				t.Fatalf("%s returned 200; nothing under /files/ resolves to that path", attempt)
			}

			// A 3xx here is net/http's own doing: ServeMux cleans the request
			// path and redirects when the cleaned form differs, so the
			// traversal is answered before the file server ever sees it. Follow
			// it and confirm the destination does not serve the file either.
			if loc := resp.Header.Get("Location"); resp.StatusCode >= 300 && resp.StatusCode < 400 && loc != "" {
				followed, followedBody := h.get(loc)
				if followed.StatusCode == http.StatusOK && strings.Contains(followedBody, "secret") {
					t.Fatalf("%s redirected to %s, which served content from outside the root", attempt, loc)
				}
				return
			}
			if resp.StatusCode != http.StatusNotFound {
				t.Errorf("%s: status = %d, want 404", attempt, resp.StatusCode)
			}
		})
	}
}
