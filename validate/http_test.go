package validate_test

import (
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/JonasBorgesLM/gosecure/validate"
)

// readAllHandler drains the body and reports what happened, mapping the
// oversize error the way the documentation tells handlers to.
func readAllHandler(read *int64, readErr *error) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, err := io.ReadAll(r.Body)
		*read = int64(len(b))
		*readErr = err
		if err != nil {
			var maxErr *http.MaxBytesError
			if errors.As(err, &maxErr) {
				http.Error(w, "Request Entity Too Large", http.StatusRequestEntityTooLarge)
				return
			}
			http.Error(w, "bad request", http.StatusBadRequest)
			return
		}
		w.WriteHeader(http.StatusOK)
	})
}

func TestMaxBodyBytes(t *testing.T) {
	tests := []struct {
		name string
		// limit is the byte bound.
		limit int64
		// body is what the client actually sends.
		body string
		// declared overrides Content-Length; -1 means "leave it accurate".
		declared   int64
		wantStatus int
		wantRead   int64
	}{
		{
			name:       "a body under the limit is passed through",
			limit:      100,
			body:       "hello",
			declared:   -1,
			wantStatus: http.StatusOK,
			wantRead:   5,
		},
		{
			name:       "a body exactly at the limit is allowed",
			limit:      5,
			body:       "hello",
			declared:   -1,
			wantStatus: http.StatusOK,
			wantRead:   5,
		},
		{
			name:       "one byte over is rejected",
			limit:      5,
			body:       "hello!",
			declared:   -1,
			wantStatus: http.StatusRequestEntityTooLarge,
			wantRead:   0,
		},
		{
			// The attack case: Content-Length is a claim, not a fact. The header
			// check is skipped, and MaxBytesReader has to catch it during the
			// read.
			name:       "a lying Content-Length does not get past the reader",
			limit:      5,
			body:       strings.Repeat("A", 5000),
			declared:   1,
			wantStatus: http.StatusRequestEntityTooLarge,
			wantRead:   5,
		},
		{
			// A chunked request declares no length at all.
			name:       "an unknown Content-Length is caught by the reader",
			limit:      5,
			body:       strings.Repeat("A", 5000),
			declared:   -2,
			wantStatus: http.StatusRequestEntityTooLarge,
			wantRead:   5,
		},
		{
			name:       "an empty body is fine",
			limit:      10,
			body:       "",
			declared:   -1,
			wantStatus: http.StatusOK,
			wantRead:   0,
		},
		{
			name:       "a zero limit rejects any body",
			limit:      0,
			body:       "x",
			declared:   -1,
			wantStatus: http.StatusRequestEntityTooLarge,
			wantRead:   0,
		},
		{
			name:       "a negative limit is treated as zero",
			limit:      -1,
			body:       "x",
			declared:   -1,
			wantStatus: http.StatusRequestEntityTooLarge,
			wantRead:   0,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			var read int64
			var readErr error
			h := validate.MaxBodyBytes(tc.limit)(readAllHandler(&read, &readErr))

			r := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(tc.body))
			switch tc.declared {
			case -1:
				// leave the accurate length httptest computed
			case -2:
				r.ContentLength = -1
			default:
				r.ContentLength = tc.declared
			}

			rec := httptest.NewRecorder()
			h.ServeHTTP(rec, r)

			if rec.Code != tc.wantStatus {
				t.Errorf("status = %d, want %d (read %d bytes, err %v)", rec.Code, tc.wantStatus, read, readErr)
			}
			if read != tc.wantRead {
				t.Errorf("handler read %d bytes, want %d", read, tc.wantRead)
			}
		})
	}
}

// TestMaxBodyBytesRejectsBeforeTheHandlerRuns proves the header check
// short-circuits: an oversized declared upload must not reach the handler at
// all, so no work is spent on it.
func TestMaxBodyBytesRejectsBeforeTheHandlerRuns(t *testing.T) {
	reached := false
	h := validate.MaxBodyBytes(10)(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		reached = true
	}))

	r := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(strings.Repeat("A", 1000)))
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, r)

	if reached {
		t.Error("handler ran for a body declared over the limit")
	}
	if rec.Code != http.StatusRequestEntityTooLarge {
		t.Errorf("status = %d, want 413", rec.Code)
	}
}

// TestMaxBodyBytesErrorIsIdentifiable checks the contract handlers depend on:
// the read failure must be a *http.MaxBytesError so it can be mapped to 413
// rather than mistaken for a client disconnect.
func TestMaxBodyBytesErrorIsIdentifiable(t *testing.T) {
	var read int64
	var readErr error
	h := validate.MaxBodyBytes(4)(readAllHandler(&read, &readErr))

	r := httptest.NewRequest(http.MethodPost, "/", strings.NewReader("aaaaaaaa"))
	r.ContentLength = -1
	h.ServeHTTP(httptest.NewRecorder(), r)

	var maxErr *http.MaxBytesError
	if !errors.As(readErr, &maxErr) {
		t.Fatalf("read error = %v (%T), want *http.MaxBytesError", readErr, readErr)
	}
	if maxErr.Limit != 4 {
		t.Errorf("MaxBytesError.Limit = %d, want 4", maxErr.Limit)
	}
}

func TestRequireContentType(t *testing.T) {
	tests := []struct {
		name        string
		allowed     []string
		method      string
		contentType string
		wantStatus  int
	}{
		{
			name:        "an exact match is allowed",
			allowed:     []string{"application/json"},
			method:      http.MethodPost,
			contentType: "application/json",
			wantStatus:  http.StatusOK,
		},
		{
			name:        "parameters such as charset are ignored",
			allowed:     []string{"application/json"},
			method:      http.MethodPost,
			contentType: "application/json; charset=utf-8",
			wantStatus:  http.StatusOK,
		},
		{
			name:        "matching is case-insensitive",
			allowed:     []string{"application/json"},
			method:      http.MethodPost,
			contentType: "Application/JSON",
			wantStatus:  http.StatusOK,
		},
		{
			name:        "a configured parameter is ignored too",
			allowed:     []string{"application/json; charset=utf-8"},
			method:      http.MethodPost,
			contentType: "application/json",
			wantStatus:  http.StatusOK,
		},
		{
			name:        "any of several allowed types matches",
			allowed:     []string{"application/json", "application/xml"},
			method:      http.MethodPost,
			contentType: "application/xml",
			wantStatus:  http.StatusOK,
		},
		{
			// The CSRF-adjacent case: an HTML form can only send these types, so
			// a JSON-only endpoint is out of reach of a forged form post.
			name:        "a form-encoded post to a JSON endpoint is rejected",
			allowed:     []string{"application/json"},
			method:      http.MethodPost,
			contentType: "application/x-www-form-urlencoded",
			wantStatus:  http.StatusUnsupportedMediaType,
		},
		{
			name:        "multipart to a JSON endpoint is rejected",
			allowed:     []string{"application/json"},
			method:      http.MethodPost,
			contentType: "multipart/form-data; boundary=xyz",
			wantStatus:  http.StatusUnsupportedMediaType,
		},
		{
			name:        "text/plain to a JSON endpoint is rejected",
			allowed:     []string{"application/json"},
			method:      http.MethodPost,
			contentType: "text/plain",
			wantStatus:  http.StatusUnsupportedMediaType,
		},
		{
			name:        "a missing Content-Type on a POST is rejected",
			allowed:     []string{"application/json"},
			method:      http.MethodPost,
			contentType: "",
			wantStatus:  http.StatusUnsupportedMediaType,
		},
		{
			name:        "a malformed Content-Type is rejected rather than guessed at",
			allowed:     []string{"application/json"},
			method:      http.MethodPost,
			contentType: "application/json; charset=",
			wantStatus:  http.StatusUnsupportedMediaType,
		},
		{
			name:        "a prefix is not a match",
			allowed:     []string{"application/json"},
			method:      http.MethodPost,
			contentType: "application/json-patch+json",
			wantStatus:  http.StatusUnsupportedMediaType,
		},
		{
			name:        "an empty allow-list rejects everything",
			allowed:     nil,
			method:      http.MethodPost,
			contentType: "application/json",
			wantStatus:  http.StatusUnsupportedMediaType,
		},
		// Methods without a body are never subject to the check.
		{"GET is not checked", []string{"application/json"}, http.MethodGet, "", http.StatusOK},
		{"HEAD is not checked", []string{"application/json"}, http.MethodHead, "", http.StatusOK},
		{"DELETE is not checked", []string{"application/json"}, http.MethodDelete, "", http.StatusOK},
		{"OPTIONS is not checked", []string{"application/json"}, http.MethodOptions, "", http.StatusOK},
		// Methods with a body all are.
		{"PUT is checked", []string{"application/json"}, http.MethodPut, "text/plain", http.StatusUnsupportedMediaType},
		{"PATCH is checked", []string{"application/json"}, http.MethodPatch, "text/plain", http.StatusUnsupportedMediaType},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			reached := false
			h := validate.RequireContentType(tc.allowed...)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				reached = true
				w.WriteHeader(http.StatusOK)
			}))

			r := httptest.NewRequest(tc.method, "/", strings.NewReader("{}"))
			if tc.contentType != "" {
				r.Header.Set("Content-Type", tc.contentType)
			}
			rec := httptest.NewRecorder()
			h.ServeHTTP(rec, r)

			if rec.Code != tc.wantStatus {
				t.Errorf("status = %d, want %d", rec.Code, tc.wantStatus)
			}
			if want := tc.wantStatus == http.StatusOK; reached != want {
				t.Errorf("handler reached = %v, want %v", reached, want)
			}
		})
	}
}

// TestRequireContentTypeChecksEmptyBodies pins the documented decision that a
// POST must declare its type even when it happens to carry nothing.
func TestRequireContentTypeChecksEmptyBodies(t *testing.T) {
	h := validate.RequireContentType("application/json")(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))

	r := httptest.NewRequest(http.MethodPost, "/", nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, r)

	if rec.Code != http.StatusUnsupportedMediaType {
		t.Errorf("status = %d, want 415 for an undeclared empty POST", rec.Code)
	}
}

// TestGuardOrdering demonstrates the ordering rule the preset package encodes:
// the size bound has to be in place before anything parses the body.
func TestGuardOrdering(t *testing.T) {
	const limit = 16

	var parsed url.Values
	parseForm := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// This is what a body-parsing middleware does. With the limit already
		// applied, it cannot be made to parse more than `limit` bytes.
		if err := r.ParseForm(); err != nil {
			http.Error(w, "too large", http.StatusRequestEntityTooLarge)
			return
		}
		parsed = r.PostForm
		w.WriteHeader(http.StatusOK)
	})

	h := validate.MaxBodyBytes(limit)(parseForm)

	body := "a=" + strings.Repeat("A", 10_000)
	r := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(body))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	r.ContentLength = -1 // force the reader, not the header check, to catch it

	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, r)

	if rec.Code != http.StatusRequestEntityTooLarge {
		t.Errorf("status = %d, want 413", rec.Code)
	}
	if len(parsed) != 0 {
		t.Errorf("an oversized form was parsed anyway: %v", parsed)
	}
}

func ExampleMaxBodyBytes() {
	// Handlers behind this must still check the error from reading the body:
	// the limit is enforced during the read, and ignoring the error is the bug
	// the middleware cannot prevent for you.
	handler := validate.MaxBodyBytes(1 << 20)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(r.Body)
		var maxErr *http.MaxBytesError
		if errors.As(err, &maxErr) {
			http.Error(w, "Request Entity Too Large", http.StatusRequestEntityTooLarge)
			return
		}
		fmt.Fprintf(w, "read %d bytes", len(body))
	}))

	r := httptest.NewRequest(http.MethodPost, "/", strings.NewReader("hello"))
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, r)

	fmt.Println(rec.Code, rec.Body)
	// Output: 200 read 5 bytes
}

func ExampleRequireContentType() {
	handler := validate.RequireContentType("application/json")(
		http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
		}))

	// A forged HTML form post cannot set this header to application/json, so a
	// JSON-only endpoint is out of reach of that technique.
	r := httptest.NewRequest(http.MethodPost, "/", strings.NewReader("a=1"))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, r)

	fmt.Println(rec.Code)
	// Output: 415
}
