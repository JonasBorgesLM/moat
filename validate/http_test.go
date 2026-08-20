package validate_test

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/JonasBorgesLM/moat/validate"
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
			h := validate.RequireContentType(tc.allowed)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
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
	h := validate.RequireContentType([]string{"application/json"})(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))

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

// ExampleMaxBodyBytes wires both rejection paths to one error envelope.
//
// An oversized request is refused in two different places — by the middleware
// when the declared Content-Length is too large, and by http.MaxBytesReader
// inside the handler when the client lied or declared nothing. Adopting the
// middleware means handling both, or the same condition produces two different
// response shapes depending only on how the client framed its request.
func ExampleMaxBodyBytes() {
	// The envelope the rest of the application already documents.
	writeError := func(w http.ResponseWriter, status int, msg string) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(status)
		_ = json.NewEncoder(w).Encode(map[string]string{"error": msg})
	}

	const tooLarge = "request body too large"

	// Path 1: the declared length is over the limit. The middleware answers,
	// so the envelope is installed as an Option.
	overLimit := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		writeError(w, http.StatusRequestEntityTooLarge, tooLarge)
	})

	// Path 2: the declaration was absent or a lie. Nothing is known until the
	// body is read, the middleware has already returned, and the failure
	// arrives as a *http.MaxBytesError from Read. Same envelope, by hand.
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(r.Body)
		var maxErr *http.MaxBytesError
		if errors.As(err, &maxErr) {
			writeError(w, http.StatusRequestEntityTooLarge, tooLarge)
			return
		}
		if err != nil {
			writeError(w, http.StatusBadRequest, "cannot read body")
			return
		}
		fmt.Fprintf(w, "read %d bytes", len(body))
	})

	limited := validate.MaxBodyBytes(8, validate.WithMaxBodyErrorHandler(overLimit))(handler)

	// An honest oversized request: caught by the header check.
	declared := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(strings.Repeat("A", 100)))
	honest := httptest.NewRecorder()
	limited.ServeHTTP(honest, declared)

	// The same body, declaring no length: caught by the reader instead.
	chunked := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(strings.Repeat("A", 100)))
	chunked.ContentLength = -1
	lying := httptest.NewRecorder()
	limited.ServeHTTP(lying, chunked)

	fmt.Printf("declared: %d %s", honest.Code, honest.Body)
	fmt.Printf("chunked:  %d %s", lying.Code, lying.Body)

	// Output:
	// declared: 413 {"error":"request body too large"}
	// chunked:  413 {"error":"request body too large"}
}

func ExampleRequireContentType() {
	handler := validate.RequireContentType([]string{"application/json"})(
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

// envelopeHandler writes the {"error": ...} shape an application with its own
// contract would use, so a test can tell it apart from net/http's text/plain.
func envelopeHandler(status int, msg string) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(status)
		_ = json.NewEncoder(w).Encode(map[string]string{"error": msg})
	})
}

func TestWithMaxBodyErrorHandler(t *testing.T) {
	custom := envelopeHandler(http.StatusRequestEntityTooLarge, "too big")
	h := validate.MaxBodyBytes(5, validate.WithMaxBodyErrorHandler(custom))(
		http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			t.Error("the handler ran for an oversized request")
		}))

	r := httptest.NewRequest(http.MethodPost, "/", strings.NewReader("hello world"))
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, r)

	if rec.Code != http.StatusRequestEntityTooLarge {
		t.Errorf("status = %d, want 413", rec.Code)
	}
	if got := rec.Header().Get("Content-Type"); got != "application/json" {
		t.Errorf("Content-Type = %q, want application/json", got)
	}
	if !strings.Contains(rec.Body.String(), `"error":"too big"`) {
		t.Errorf("body = %q, want the custom envelope", rec.Body)
	}
}

// TestWithMaxBodyErrorHandlerDoesNotCoverTheReaderPath pins the documented
// limit of the option: the second rejection path is not routed through it, and
// an adopter who sets only the option still gets text/plain from the reader.
// This is the asymmetry the doc comment tells them to close with errors.As.
func TestWithMaxBodyErrorHandlerDoesNotCoverTheReaderPath(t *testing.T) {
	custom := envelopeHandler(http.StatusRequestEntityTooLarge, "too big")
	h := validate.MaxBodyBytes(5, validate.WithMaxBodyErrorHandler(custom))(
		http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// A handler that ignores the read error, as the docs warn against.
			_, err := io.ReadAll(r.Body)
			var maxErr *http.MaxBytesError
			if !errors.As(err, &maxErr) {
				t.Errorf("read error = %v, want *http.MaxBytesError", err)
			}
		}))

	r := httptest.NewRequest(http.MethodPost, "/", strings.NewReader("hello world"))
	r.ContentLength = -1 // skip the header check, force the reader
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, r)

	if ct := rec.Header().Get("Content-Type"); ct == "application/json" {
		t.Error("the option unexpectedly covered the reader path; update the docs")
	}
}

// TestMaxBodyBytesWrapsTheReaderEvenWhenTheDeclaredLengthPasses is the
// regression guard for the bypass: a small declared length must not stop the
// reader from being installed, or a lying client gets through unbounded.
func TestMaxBodyBytesWrapsTheReaderEvenWhenTheDeclaredLengthPasses(t *testing.T) {
	var read int64
	var readErr error
	h := validate.MaxBodyBytes(5)(readAllHandler(&read, &readErr))

	r := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(strings.Repeat("A", 5000)))
	r.ContentLength = 1 // a claim, and a false one
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, r)

	var maxErr *http.MaxBytesError
	if !errors.As(readErr, &maxErr) {
		t.Fatalf("read error = %v, want *http.MaxBytesError", readErr)
	}
	if read != 5 {
		t.Errorf("handler read %d bytes, want 5", read)
	}
}

func TestWithContentTypeErrorHandler(t *testing.T) {
	custom := envelopeHandler(http.StatusUnsupportedMediaType, "unsupported")
	h := validate.RequireContentType([]string{"application/json"},
		validate.WithContentTypeErrorHandler(custom))(
		http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			t.Error("the handler ran for an unsupported media type")
		}))

	// All three rejection causes must produce the one custom response.
	for _, ct := range []string{"text/plain", "", "application/json; charset=\x00"} {
		rec := httptest.NewRecorder()
		r := httptest.NewRequest(http.MethodPost, "/", strings.NewReader("{}"))
		if ct != "" {
			r.Header.Set("Content-Type", ct)
		}
		h.ServeHTTP(rec, r)

		if rec.Code != http.StatusUnsupportedMediaType {
			t.Errorf("Content-Type %q: status = %d, want 415", ct, rec.Code)
		}
		if !strings.Contains(rec.Body.String(), `"error":"unsupported"`) {
			t.Errorf("Content-Type %q: body = %q, want the custom envelope", ct, rec.Body)
		}
	}
}

func TestNilOptionsAreIgnored(t *testing.T) {
	// A nil handler must not disable the default response, and a nil option
	// must not panic — a failed constructor upstream should not silently
	// remove a rejection.
	body := validate.MaxBodyBytes(5, nil, validate.WithMaxBodyErrorHandler(nil))(
		http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	rec := httptest.NewRecorder()
	body.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/", strings.NewReader("hello world")))
	if rec.Code != http.StatusRequestEntityTooLarge {
		t.Errorf("MaxBodyBytes status = %d, want 413", rec.Code)
	}

	ct := validate.RequireContentType([]string{"application/json"}, nil,
		validate.WithContentTypeErrorHandler(nil))(
		http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	rec = httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPost, "/", strings.NewReader("x"))
	r.Header.Set("Content-Type", "text/plain")
	ct.ServeHTTP(rec, r)
	if rec.Code != http.StatusUnsupportedMediaType {
		t.Errorf("RequireContentType status = %d, want 415", rec.Code)
	}
}
