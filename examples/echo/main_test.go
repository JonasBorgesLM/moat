package main

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/labstack/echo/v4"

	"github.com/JonasBorgesLM/moat/csrf"
)

const host = "app.example.com"

func newTestRouter(t *testing.T) *echo.Echo {
	t.Helper()
	secret, err := csrf.GenerateSecret()
	if err != nil {
		t.Fatal(err)
	}
	e, err := newRouter(secret)
	if err != nil {
		t.Fatal(err)
	}
	return e
}

// TestAdapterCarriesTheRequestContext is the adapter's most important
// property. Without c.SetRequest(r), the CSRF token never reaches a handler.
func TestAdapterCarriesTheRequestContext(t *testing.T) {
	e := newTestRouter(t)

	r := httptest.NewRequest(http.MethodGet, "https://"+host+"/token", nil)
	r.Host = host
	rec := httptest.NewRecorder()
	e.ServeHTTP(rec, r)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, body %q", rec.Code, rec.Body)
	}
	if rec.Body.Len() == 0 {
		t.Fatal("no token reached the handler; the adapter dropped the request context")
	}
}

// TestAdapterPropagatesHandlerErrors: swallowing the handler's error would turn
// every failure into a silent success.
func TestAdapterPropagatesHandlerErrors(t *testing.T) {
	e := echo.New()
	e.HideBanner, e.HidePort = true, true

	passthrough := func(next http.Handler) http.Handler { return next }
	e.Use(Adapt(passthrough))
	e.GET("/boom", func(c echo.Context) error {
		return errors.New("handler failed")
	})

	rec := httptest.NewRecorder()
	e.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/boom", nil))

	if rec.Code != http.StatusInternalServerError {
		t.Errorf("status = %d, want 500: the handler's error was swallowed", rec.Code)
	}
}

// TestAdapterStopsAtRejection: when a middleware short-circuits, the handler
// must never run.
func TestAdapterStopsAtRejection(t *testing.T) {
	reached := false

	e := echo.New()
	e.HideBanner, e.HidePort = true, true
	deny := func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			http.Error(w, "denied", http.StatusForbidden)
		})
	}
	e.Use(Adapt(deny))
	e.GET("/", func(c echo.Context) error {
		reached = true
		return c.String(http.StatusOK, "handler ran")
	})

	rec := httptest.NewRecorder()
	e.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/", nil))

	if reached {
		t.Error("the handler ran despite a short-circuiting middleware")
	}
	if rec.Code != http.StatusForbidden {
		t.Errorf("status = %d, want 403", rec.Code)
	}
}

func TestSmoke(t *testing.T) {
	e := newTestRouter(t)

	r := httptest.NewRequest(http.MethodGet, "https://"+host+"/token", nil)
	r.Host = host
	rec := httptest.NewRecorder()
	e.ServeHTTP(rec, r)

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
		e.ServeHTTP(rec, r)
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
	e := newTestRouter(t)

	saw429 := false
	for range 25 { // the preset here configures a burst of 20
		r := httptest.NewRequest(http.MethodGet, "https://"+host+"/token", nil)
		r.Host = host
		r.RemoteAddr = "203.0.113.88:1234"
		rec := httptest.NewRecorder()
		e.ServeHTTP(rec, r)
		if rec.Code == http.StatusTooManyRequests {
			saw429 = true
			break
		}
	}
	if !saw429 {
		t.Error("no request was rate limited in 25 attempts")
	}
}
