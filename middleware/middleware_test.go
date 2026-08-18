package middleware_test

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/JonasBorgesLM/gosecure/middleware"
)

// tag returns a middleware that appends name to a shared trace on the way in
// and name+"-out" on the way out, so that both ordering and nesting are
// observable.
func tag(trace *[]string, name string) middleware.Middleware {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			*trace = append(*trace, name)
			next.ServeHTTP(w, r)
			*trace = append(*trace, name+"-out")
		})
	}
}

func TestChainOrder(t *testing.T) {
	tests := []struct {
		name  string
		build func(trace *[]string) middleware.Chain
		want  string
	}{
		{
			name:  "zero chain is identity",
			build: func(*[]string) middleware.Chain { return middleware.Chain{} },
			want:  "handler",
		},
		{
			name: "declaration order is execution order",
			build: func(tr *[]string) middleware.Chain {
				return middleware.New(tag(tr, "a"), tag(tr, "b"), tag(tr, "c"))
			},
			want: "a,b,c,handler,c-out,b-out,a-out",
		},
		{
			name: "append runs after the base",
			build: func(tr *[]string) middleware.Chain {
				return middleware.New(tag(tr, "a")).Append(tag(tr, "b"))
			},
			want: "a,b,handler,b-out,a-out",
		},
		{
			name: "extend concatenates in order",
			build: func(tr *[]string) middleware.Chain {
				return middleware.New(tag(tr, "a")).Extend(middleware.New(tag(tr, "b"), tag(tr, "c")))
			},
			want: "a,b,c,handler,c-out,b-out,a-out",
		},
		{
			name: "nil middleware is skipped, not panicked on",
			build: func(tr *[]string) middleware.Chain {
				return middleware.New(tag(tr, "a"), nil, tag(tr, "b"))
			},
			want: "a,b,handler,b-out,a-out",
		},
		{
			name: "a chain nests as a single middleware",
			build: func(tr *[]string) middleware.Chain {
				inner := middleware.New(tag(tr, "b"), tag(tr, "c"))
				return middleware.New(tag(tr, "a"), inner.Middleware())
			},
			want: "a,b,c,handler,c-out,b-out,a-out",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			var trace []string
			h := tc.build(&trace).Then(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
				trace = append(trace, "handler")
			}))
			h.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "/", nil))
			if got := strings.Join(trace, ","); got != tc.want {
				t.Errorf("trace = %q, want %q", got, tc.want)
			}
		})
	}
}

// TestChainDerivationIsIsolated guards the aliasing bug that copyAppend exists
// to prevent: two chains derived from the same base must not share a backing
// array, or one route's middleware silently replaces another's — which in this
// library means silently dropping a security control.
func TestChainDerivationIsIsolated(t *testing.T) {
	var trace []string
	base := middleware.New(tag(&trace, "base"))

	left := base.Append(tag(&trace, "left"))
	right := base.Append(tag(&trace, "right"))

	run := func(c middleware.Chain) string {
		trace = nil
		c.Then(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {})).
			ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "/", nil))
		return strings.Join(trace, ",")
	}

	if got, want := run(left), "base,left,left-out,base-out"; got != want {
		t.Errorf("left chain = %q, want %q", got, want)
	}
	if got, want := run(right), "base,right,right-out,base-out"; got != want {
		t.Errorf("right chain = %q, want %q", got, want)
	}
	if got, want := run(base), "base,base-out"; got != want {
		t.Errorf("base chain mutated: %q, want %q", got, want)
	}
	if base.Len() != 1 {
		t.Errorf("base.Len() = %d, want 1", base.Len())
	}
}

// TestChainShortCircuit verifies that a middleware which does not call next
// stops the pipeline — the mechanism every rejection in this library relies on.
func TestChainShortCircuit(t *testing.T) {
	reached := false
	deny := func(http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusForbidden)
		})
	}
	h := middleware.New(deny).Then(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		reached = true
	}))

	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/", nil))

	if reached {
		t.Error("inner handler ran despite a short-circuiting middleware")
	}
	if rec.Code != http.StatusForbidden {
		t.Errorf("status = %d, want %d", rec.Code, http.StatusForbidden)
	}
}

func TestThenNilUsesDefaultServeMux(t *testing.T) {
	if got := middleware.New().Then(nil); got != http.DefaultServeMux {
		t.Errorf("Then(nil) = %v, want http.DefaultServeMux", got)
	}
	if got := middleware.New().ThenFunc(nil); got != http.DefaultServeMux {
		t.Errorf("ThenFunc(nil) = %v, want http.DefaultServeMux", got)
	}
}

func TestThenIsReusable(t *testing.T) {
	var trace []string
	c := middleware.New(tag(&trace, "a"))
	inner := http.HandlerFunc(func(http.ResponseWriter, *http.Request) {})

	for i := range 3 {
		trace = nil
		c.Then(inner).ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "/", nil))
		if got, want := strings.Join(trace, ","), "a,a-out"; got != want {
			t.Fatalf("call %d: trace = %q, want %q", i, got, want)
		}
	}
}

func ExampleChain() {
	header := func(name, value string) middleware.Middleware {
		return func(next http.Handler) http.Handler {
			return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set(name, value)
				next.ServeHTTP(w, r)
			})
		}
	}

	// Read top to bottom: this is the order requests traverse the pipeline.
	chain := middleware.New(
		header("X-First", "1"),
		header("X-Second", "2"),
	)

	handler := chain.ThenFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, "hello")
	})

	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/", nil))

	fmt.Println(rec.Header().Get("X-First"), rec.Header().Get("X-Second"), rec.Body)
	// Output: 1 2 hello
}

func ExampleChain_Append() {
	// A shared base, extended per route. Append copies, so the two routes
	// cannot clobber each other's middleware.
	base := middleware.New()

	public := base
	admin := base.Append(func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.Header.Get("Authorization") == "" {
				http.Error(w, "unauthorized", http.StatusUnauthorized)
				return
			}
			next.ServeHTTP(w, r)
		})
	})

	fmt.Println(public.Len(), admin.Len())
	// Output: 0 1
}
