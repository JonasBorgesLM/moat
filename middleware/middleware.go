// Package middleware provides Chain, a flat and order-explicit way to compose
// net/http middleware.
//
// It imports no sibling package, so depending on the composition helper does
// not drag the rest of the library into your build.
//
// # Why this exists
//
// Middleware order is a security property, not a style preference. A CSRF
// check placed before a body-size limit will parse an unbounded form body; a
// rate limiter placed after expensive work does not limit the expense.
// Hand-nested wrapping reads inside-out, which is exactly where such ordering
// mistakes hide:
//
//	limiter.Middleware(headers(bodyLimit(csrf(mux))))
//
// Chain reads top-to-bottom in the order requests traverse it, so the pipeline
// can be audited at a glance.
//
// Chain deliberately does not validate order. Enforcing a safe order is the job
// of the preset package; Chain is the escape hatch for callers who know what
// they are doing.
package middleware

import "net/http"

// Middleware is the decorator shape every middleware in this library follows.
//
// A Middleware wraps a handler and returns a handler. Wrapping must not consume
// the request body or write to the ResponseWriter unless it is short-circuiting
// the request, since the next handler in the pipeline may need both.
type Middleware func(http.Handler) http.Handler

// Chain is an immutable, ordered list of middleware.
//
// The zero Chain is valid and behaves as the identity: Then returns its
// argument unchanged.
//
// Chain values are safe to share and to build upon concurrently: every method
// that produces a new Chain copies the underlying slice rather than appending
// in place, so two Chains derived from a common prefix can never overwrite each
// other's middleware.
type Chain struct {
	// mw is never mutated after construction; see copyAppend.
	mw []Middleware
}

// New returns a Chain that applies mw in the order given.
//
// The first middleware is the outermost: it sees every request first and every
// response last. Order the cheapest and most protective checks first, so that
// work is not spent on requests that will be rejected anyway.
func New(mw ...Middleware) Chain {
	return Chain{mw: copyAppend(nil, mw)}
}

// Append returns a new Chain with mw added after the existing middleware.
//
// The receiver is not modified, so a shared base chain can be extended
// differently per route without the extensions colliding.
func (c Chain) Append(mw ...Middleware) Chain {
	return Chain{mw: copyAppend(c.mw, mw)}
}

// Extend returns a new Chain with other's middleware added after the receiver's.
//
// The receiver is not modified.
func (c Chain) Extend(other Chain) Chain {
	return Chain{mw: copyAppend(c.mw, other.mw)}
}

// Len reports how many middleware the Chain applies.
func (c Chain) Len() int { return len(c.mw) }

// Then wraps h with the Chain's middleware and returns the resulting handler.
//
// If h is nil, http.DefaultServeMux is used, matching the convention of
// http.Handle. Then is safe to call more than once; each call builds an
// independent handler.
func (c Chain) Then(h http.Handler) http.Handler {
	if h == nil {
		h = http.DefaultServeMux
	}
	// Wrap in reverse so that c.mw[0] ends up outermost and therefore runs
	// first, matching declaration order.
	for i := len(c.mw) - 1; i >= 0; i-- {
		if c.mw[i] == nil {
			continue
		}
		h = c.mw[i](h)
	}
	return h
}

// ThenFunc is Then for an http.HandlerFunc.
//
// A nil fn is treated the same as a nil handler passed to Then.
func (c Chain) ThenFunc(fn http.HandlerFunc) http.Handler {
	if fn == nil {
		return c.Then(nil)
	}
	return c.Then(fn)
}

// Middleware adapts the whole Chain to a single Middleware, so that a chain can
// itself be nested inside another chain.
func (c Chain) Middleware() Middleware {
	return func(next http.Handler) http.Handler { return c.Then(next) }
}

// copyAppend returns a fresh slice holding base followed by extra.
//
// The explicit allocation is load-bearing rather than defensive style: reusing
// base's backing array via append would let two Chains derived from the same
// prefix silently overwrite each other's middleware, which for this library
// means silently dropping a security control.
func copyAppend(base, extra []Middleware) []Middleware {
	if len(base)+len(extra) == 0 {
		return nil
	}
	out := make([]Middleware, 0, len(base)+len(extra))
	out = append(out, base...)
	out = append(out, extra...)
	return out
}
