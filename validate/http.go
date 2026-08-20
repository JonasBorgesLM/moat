package validate

import (
	"mime"
	"net/http"
	"strings"
)

// MaxBodyBytes returns middleware that bounds how much of a request body any
// handler behind it can read.
//
// # Threat
//
// A handler that reads a request body without a bound lets one client decide
// how much of your memory to use. io.ReadAll on an unbounded body, or a JSON
// decoder fed a stream that never ends, turns a single request into an
// out-of-memory kill. It costs the attacker one connection.
//
// # How it works, and why both halves are needed
//
// Two checks, because either alone is bypassable:
//
//   - Content-Length is compared against n up front, so an oversized upload is
//     refused with 413 before its body is read at all.
//   - r.Body is then wrapped with http.MaxBytesReader, which enforces the limit
//     during reading. This is what catches the client that lies: a chunked
//     request declares no length, and a declared Content-Length is a claim, not
//     a fact. The header check is an optimization; the reader is the control.
//
// # The two rejection paths, and how to make them agree
//
// An oversized request is refused in one of two places, and they are answered
// differently on purpose. Adopting this middleware means handling **both**;
// handling one leaves your API returning two different shapes for the same
// condition, depending only on whether the client declared its length honestly.
//
//  1. **The declared length is too large.** This middleware answers 413 itself,
//     before the body is read. Replace that response with
//     [WithMaxBodyErrorHandler] so it carries your error envelope.
//
//  2. **The client lied, or declared nothing.** Nothing is known until the body
//     is read, so the limit is enforced by http.MaxBytesReader inside your
//     handler. The handler's Read returns a *http.MaxBytesError, and **this
//     middleware has already returned by then** — it cannot write a response
//     for you. Match the error with errors.As and emit the same envelope:
//
//     var maxErr *http.MaxBytesError
//     if errors.As(err, &maxErr) {
//     writeError(w, http.StatusRequestEntityTooLarge, "request body too large")
//     return
//     }
//
// The asymmetry is one of mechanism, not of result: one path is configured with
// an Option and the other is handled downstream with errors.As, but both are
// meant to produce the same status and the same body. See [ExampleMaxBodyBytes]
// for the two wired together.
//
// Delegating the second path is the correct design rather than a gap. The
// middleware is no longer on the stack when the read fails, and a middleware
// that tried to write then would be racing a handler that may already have sent
// headers. **Handlers must check the error from reading or decoding the body**;
// ignoring a decode error and proceeding with a zero value is the bug this
// middleware cannot prevent for you.
//
// MaxBytesReader also arranges for the connection to be closed rather than
// leaving an unread oversized body draining, so a rejected upload does not tie
// up the connection while the client keeps sending.
//
// # Ordering
//
// Place this before anything that reads or parses the body — CSRF form-field
// lookup, JSON decoding, multipart parsing. Middleware ordering is a security
// property: a body parser that runs before the limit has already done the work
// the limit exists to prevent. The preset package fixes this order for you.
//
// n is the maximum number of bytes readable from the body. A negative n is
// treated as zero, which rejects any request that carries a body at all.
func MaxBodyBytes(n int64, opts ...BodyLimitOption) func(http.Handler) http.Handler {
	if n < 0 {
		n = 0
	}
	var cfg bodyLimitConfig
	for _, opt := range opts {
		if opt != nil {
			opt(&cfg)
		}
	}
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// ContentLength is -1 when unknown (a chunked request), in which
			// case there is nothing to compare and MaxBytesReader does the work.
			if r.ContentLength > n {
				cfg.writeTooLarge(w, r)
				return
			}
			// Wrapped unconditionally, and never with the declared length: a
			// Content-Length small enough to pass the check above is still only
			// a claim, so the reader must enforce n regardless of what was
			// declared. Making this wrap conditional would be a bypass.
			if r.Body != nil {
				r.Body = http.MaxBytesReader(w, r.Body, n)
			}
			next.ServeHTTP(w, r)
		})
	}
}

// BodyLimitOption configures [MaxBodyBytes].
//
// It is a distinct type from [ContentTypeOption] so that an option cannot be
// passed to the constructor it does not belong to. A single shared option type
// would compile and then silently do nothing, which is the failure mode this
// package exists to avoid.
type BodyLimitOption func(*bodyLimitConfig)

type bodyLimitConfig struct {
	tooLarge http.Handler
}

// WithMaxBodyErrorHandler replaces the response written when a request declares
// a Content-Length larger than the limit. The default writes 413.
//
// This covers only the first of the two rejection paths described above. The
// second one surfaces as a *http.MaxBytesError inside your handler and cannot
// be routed here — setting this option without also handling that error leaves
// the inconsistency it was meant to fix.
//
// A nil handler is ignored.
func WithMaxBodyErrorHandler(h http.Handler) BodyLimitOption {
	return func(c *bodyLimitConfig) {
		if h != nil {
			c.tooLarge = h
		}
	}
}

func (c bodyLimitConfig) writeTooLarge(w http.ResponseWriter, r *http.Request) {
	if c.tooLarge != nil {
		c.tooLarge.ServeHTTP(w, r)
		return
	}
	http.Error(w, "Request Entity Too Large", http.StatusRequestEntityTooLarge)
}

// RequireContentType returns middleware that rejects a body-carrying request
// whose Content-Type is not one of the given media types, with 415.
//
// # Threat
//
// Content type is the contract for how a body will be parsed, and confusion
// about it is exploitable. A cross-site request forged with an HTML form can
// only send application/x-www-form-urlencoded, multipart/form-data or
// text/plain; an endpoint that accepts application/json and nothing else is out
// of reach of that technique. Conversely, an endpoint that will parse whatever
// it is handed can be steered into a parser the developer never considered —
// XML with external entities being the classic example.
//
// Requiring an explicit type is a cheap way to keep an endpoint's parsing
// surface to the one format it was written for.
//
// # Matching
//
// Types are compared as parsed media types with parameters ignored, so
// "application/json" matches a request sending
// "application/json; charset=utf-8". Comparison is case-insensitive, as the
// grammar requires. A malformed Content-Type is rejected rather than guessed
// at, because a value the standard library refuses to parse is exactly the sort
// of value that two parsers will disagree about.
//
// # Scope
//
// The check applies to methods that carry a body — POST, PUT and PATCH — and
// only to those, so a GET is never rejected for having no Content-Type. A POST
// with an empty body is still required to declare its type: whether an endpoint
// accepts an empty body is a decision for the handler, and letting a
// declaration-free request through on the grounds that it happened to be empty
// this time is the kind of special case that later turns out to be reachable
// with a body attached.
//
// Calling this with no media types rejects every body-carrying request, which
// is the fail-closed reading of an empty allow-list.
//
// The rejection response is replaceable with [WithContentTypeErrorHandler].
func RequireContentType(mediaTypes []string, opts ...ContentTypeOption) func(http.Handler) http.Handler {
	var cfg contentTypeConfig
	for _, opt := range opts {
		if opt != nil {
			opt(&cfg)
		}
	}
	// Normalize once, at construction: a typo or a stray parameter in the
	// caller's list should not silently make the allow-list unmatchable.
	allowed := make([]string, 0, len(mediaTypes))
	for _, t := range mediaTypes {
		if parsed, _, err := mime.ParseMediaType(t); err == nil {
			allowed = append(allowed, parsed)
		} else {
			// Keep an unparsable entry as a lowercased literal rather than
			// dropping it, so a configuration mistake shows up as requests being
			// rejected, not as an allow-list that quietly lost an entry.
			allowed = append(allowed, strings.ToLower(strings.TrimSpace(t)))
		}
	}

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if !methodHasBody(r.Method) {
				next.ServeHTTP(w, r)
				return
			}
			got, _, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
			if err != nil {
				cfg.writeUnsupported(w, r)
				return
			}
			for _, a := range allowed {
				if got == a {
					next.ServeHTTP(w, r)
					return
				}
			}
			cfg.writeUnsupported(w, r)
		})
	}
}

// ContentTypeOption configures [RequireContentType]. See [BodyLimitOption] for
// why the two constructors do not share one option type.
type ContentTypeOption func(*contentTypeConfig)

type contentTypeConfig struct {
	unsupported http.Handler
}

// WithContentTypeErrorHandler replaces the response written when a request's
// Content-Type is missing, malformed, or outside the allow-list. The default
// writes 415.
//
// All three causes share one response, and a replacement should keep it that
// way. Telling a client which of them applied describes the allow-list back to
// whoever is probing it, one request at a time.
//
// A nil handler is ignored.
func WithContentTypeErrorHandler(h http.Handler) ContentTypeOption {
	return func(c *contentTypeConfig) {
		if h != nil {
			c.unsupported = h
		}
	}
}

func (c contentTypeConfig) writeUnsupported(w http.ResponseWriter, r *http.Request) {
	if c.unsupported != nil {
		c.unsupported.ServeHTTP(w, r)
		return
	}
	http.Error(w, "Unsupported Media Type", http.StatusUnsupportedMediaType)
}

// methodHasBody reports whether a request method is one that carries a body and
// is therefore subject to the content-type requirement.
//
// GET, HEAD, DELETE and OPTIONS are excluded: a body on those is unusual, is
// ignored by most handlers, and rejecting them for a missing Content-Type would
// break ordinary clients for no security benefit.
func methodHasBody(method string) bool {
	switch method {
	case http.MethodPost, http.MethodPut, http.MethodPatch:
		return true
	}
	return false
}
