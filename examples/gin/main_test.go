package main

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"

	"github.com/JonasBorgesLM/gosecure/csrf"
)

const host = "app.example.com"

func newTestRouter(t *testing.T) *gin.Engine {
	t.Helper()
	secret, err := csrf.GenerateSecret()
	if err != nil {
		t.Fatal(err)
	}
	router, err := newRouter(secret)
	if err != nil {
		t.Fatal(err)
	}
	return router
}

// TestAdapterCarriesTheRequestContext is the adapter's most important
// property. Without c.Request = r, the CSRF token never reaches a handler and
// csrf.Token reports false on every request.
func TestAdapterCarriesTheRequestContext(t *testing.T) {
	router := newTestRouter(t)

	r := httptest.NewRequest(http.MethodGet, "https://"+host+"/token", nil)
	r.Host = host
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, r)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, body %q", rec.Code, rec.Body)
	}
	if rec.Body.Len() == 0 {
		t.Fatal("no token reached the handler; the adapter dropped the request context")
	}
}

// TestAdapterAbortsOnRejection covers the other half: when a middleware
// short-circuits, Gin must not carry on to the handler.
func TestAdapterAbortsOnRejection(t *testing.T) {
	reached := false

	gin.SetMode(gin.ReleaseMode)
	router := gin.New()
	deny := func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			http.Error(w, "denied", http.StatusForbidden)
		})
	}
	router.Use(Adapt(deny))
	router.GET("/", func(c *gin.Context) {
		reached = true
		c.String(http.StatusOK, "handler ran")
	})

	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/", nil))

	if reached {
		t.Error("the handler ran despite a short-circuiting middleware")
	}
	if rec.Code != http.StatusForbidden {
		t.Errorf("status = %d, want 403", rec.Code)
	}
}

func TestSmoke(t *testing.T) {
	router := newTestRouter(t)

	// GET issues the cookie and token, and the response carries the headers.
	r := httptest.NewRequest(http.MethodGet, "https://"+host+"/token", nil)
	r.Host = host
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, r)

	if rec.Code != http.StatusOK {
		t.Fatalf("GET /token: status = %d", rec.Code)
	}
	for _, h := range []string{"Content-Security-Policy", "X-Frame-Options", "X-Content-Type-Options"} {
		if rec.Header().Get(h) == "" {
			t.Errorf("missing %s", h)
		}
	}
	token := rec.Body.String()
	cookies := rec.Result().Cookies()
	if len(cookies) != 1 {
		t.Fatalf("issued %d cookies, want 1", len(cookies))
	}

	post := func(withToken bool) *httptest.ResponseRecorder {
		values := url.Values{"field": {"value"}}
		if withToken {
			values.Set(csrf.DefaultFieldName, token)
		}
		r := httptest.NewRequest(http.MethodPost, "https://"+host+"/submit", strings.NewReader(values.Encode()))
		r.Host = host
		r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		r.Header.Set("Origin", "https://"+host)
		r.AddCookie(cookies[0])
		rec := httptest.NewRecorder()
		router.ServeHTTP(rec, r)
		return rec
	}

	if rec := post(true); rec.Code != http.StatusOK {
		t.Errorf("POST with a token: status = %d, want 200 (body %q)", rec.Code, rec.Body)
	}
	if rec := post(false); rec.Code != http.StatusForbidden {
		t.Errorf("POST without a token: status = %d, want 403", rec.Code)
	}
}

func TestRateLimit(t *testing.T) {
	router := newTestRouter(t)

	saw429 := false
	for range 25 { // the preset here configures a burst of 20
		r := httptest.NewRequest(http.MethodGet, "https://"+host+"/token", nil)
		r.Host = host
		r.RemoteAddr = "203.0.113.77:1234"
		rec := httptest.NewRecorder()
		router.ServeHTTP(rec, r)
		if rec.Code == http.StatusTooManyRequests {
			saw429 = true
			break
		}
	}
	if !saw429 {
		t.Error("no request was rate limited in 25 attempts")
	}
}
