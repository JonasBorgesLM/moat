// Package preset provides batteries-included middleware bundles, in the spirit
// of helmet.js: a sensible starting point in one call, with per-component
// overrides, and with manual composition remaining the serious path.
//
// # What a preset is and is not
//
// A preset is a defensible default for a common shape of application. It is not
// a security strategy, it is not a compliance control, and installing one does
// not mean an application is secure. Read what it wires up, decide whether that
// matches your threat model, and move to an explicit middleware.Chain as soon
// as your needs stop matching the default.
//
// # Why API returns an error
//
// [API] returns an error rather than a chain built from whatever it was given.
// The failure mode it exists to prevent is specific and has been observed
// repeatedly: a preset needs a parameter it was not given — a CSRF secret, a
// rate limit — so it quietly omits that protection, the application starts and
// serves traffic, and nothing anywhere says a control is missing. The name on
// the constructor then does the rest of the damage, because a reasonable
// developer infers from "this is the recommended preset" that the recommended
// protections are present.
//
// So omitting a protection here must be said out loud. [Config.DisableCSRF] and
// [Config.DisableRateLimit] are deliberate, greppable, code-reviewable, and
// they show up in a diff. Leaving a field zero is not a decision, and this
// package refuses to treat it as one.
//
// # Why the preset owns the order
//
// Middleware order is a security property. A CSRF check that parses a form body
// before a size limit is in place has already done the work the limit exists to
// prevent; a rate limiter placed after expensive work has already paid for the
// request it was meant to reject. Ordering mistakes are hard to see in nested
// wrapping and easy to make.
//
// [API] therefore fixes the order and treats it as an implementation detail
// covered by tests. If you need a different one, use middleware.Chain directly:
// it does not validate order, and it is the documented escape hatch for people
// who know what they are doing.
package preset

import (
	"errors"
	"fmt"
	"net/http"

	"github.com/JonasBorgesLM/gosecure/csrf"
	"github.com/JonasBorgesLM/gosecure/middleware"
	"github.com/JonasBorgesLM/gosecure/ratelimit"
	"github.com/JonasBorgesLM/gosecure/secureheaders"
	"github.com/JonasBorgesLM/gosecure/validate"
)

// DefaultMaxBodyBytes is the request body limit [API] applies when
// [Config.MaxBodyBytes] is left zero.
//
// A body limit is defaulted rather than demanded because, unlike a CSRF secret,
// there is a value that is right for almost everyone and safe for everyone: one
// mebibyte comfortably fits a form or a JSON document, and endpoints that
// legitimately accept more — uploads — need a considered number anyway. The
// distinction that matters is that defaulting here still leaves the protection
// present, whereas defaulting a CSRF secret would remove one.
const DefaultMaxBodyBytes = 1 << 20

// Errors reported by [API]. Test for them with errors.Is.
var (
	// ErrMissingCSRFSecret reports that no CSRF secret was supplied and
	// DisableCSRF was not set.
	ErrMissingCSRFSecret = errors.New("preset: CSRFSecret is required unless DisableCSRF is set")

	// ErrMissingRateLimit reports that no rate limit was supplied and
	// DisableRateLimit was not set.
	ErrMissingRateLimit = errors.New("preset: RateLimitBurst and RateLimitPerSec are required unless DisableRateLimit is set")
)

// Config parameterizes [API].
//
// The zero Config is deliberately not usable: it would describe an application
// with no CSRF protection and no rate limiting, which is exactly the outcome
// this package refuses to produce by accident.
type Config struct {
	// CSRFSecret is the server secret used to sign CSRF tokens. It must be at
	// least csrf.MinSecretLen bytes, identical across every instance, and
	// stable across deploys. Generate one with csrf.GenerateSecret.
	//
	// Required unless DisableCSRF is set.
	CSRFSecret []byte

	// DisableCSRF omits CSRF protection.
	//
	// This is legitimate for an API authenticated purely by a bearer token in
	// an Authorization header, because a forged cross-site request cannot set
	// that header and the browser will not attach it automatically. It is not
	// legitimate for anything authenticated by a cookie. Setting it is a
	// decision that should be visible in review, which is why it exists as a
	// named field rather than as an empty secret.
	DisableCSRF bool

	// RateLimitBurst is how many requests a client may make back to back.
	// Required unless DisableRateLimit is set.
	RateLimitBurst int

	// RateLimitPerSec is the sustained rate at which a client's allowance is
	// replenished. Required unless DisableRateLimit is set.
	RateLimitPerSec float64

	// DisableRateLimit omits rate limiting.
	//
	// Reasonable when limiting happens upstream, at a load balancer or an API
	// gateway. Not reasonable because the numbers were inconvenient to pick.
	DisableRateLimit bool

	// RateLimitStore supplies a shared store, such as the redisstore module, so
	// that every instance enforces one limit rather than one each. When nil, a
	// bounded in-process store is used, and N instances behind a load balancer
	// allow N times the configured rate.
	//
	// A store passed here is owned by the caller and is not closed by the chain.
	RateLimitStore ratelimit.Store

	// MaxBodyBytes bounds the request body. Zero means [DefaultMaxBodyBytes].
	// A negative value rejects every request that carries a body.
	MaxBodyBytes int64

	// TrustedOrigins, when set, replaces the CSRF Origin check's default
	// behavior — comparing against the request's own Host — with an explicit
	// allow-list of full origins, scheme included.
	TrustedOrigins []string

	// OnError receives rate-limit store failures. Without it, a store outage is
	// invisible: the limiter fails closed and every request is rejected with no
	// signal to operators. This library never logs, so this hook is the only
	// way those errors reach you.
	//
	// It runs synchronously on the request path and must not block or panic.
	OnError func(error)

	// HeaderOptions are passed through to secureheaders.Middleware, for
	// relaxing a default such as the CSP.
	HeaderOptions []secureheaders.Option

	// CSRFOptions are passed through to csrf.New. Options set here are applied
	// after the ones this preset derives from Config, so they win.
	CSRFOptions []csrf.Option

	// RateLimitOptions are passed through to ratelimit.New. Options set here
	// are applied after the ones this preset derives from Config, so they win.
	RateLimitOptions []ratelimit.Option
}

// Headers returns a chain containing only the response-header middleware.
//
// This is the genuinely parameter-free subset — the honest analogue of calling
// helmet() bare — and it is honest about being only that. It sets a strict
// Content-Security-Policy, HSTS, framing and sniffing protection, a referrer
// policy and a permissions policy. It does not rate limit, it does not check
// CSRF, and it does not bound the request body, because none of those can be
// configured without knowing something about your application.
//
// It is a middleware.Chain rather than a bare middleware so that it composes
// with Append and Extend the same way [API]'s result does.
func Headers(opts ...secureheaders.Option) middleware.Chain {
	return middleware.New(secureheaders.Middleware(opts...))
}

// API returns a chain wiring rate limiting, security headers, a request body
// limit and CSRF protection, in that order.
//
// It fails rather than silently omitting a protection: a missing CSRF secret or
// a missing rate limit is an error unless the corresponding Disable field says
// the omission is intended. See the package documentation for why.
//
// # The order, and what it buys
//
//  1. Rate limiting, so that an abusive client is turned away before anything
//     else spends work on it.
//  2. Security headers, set on the way in so that every response carries them,
//     including the errors written by the middleware that follow.
//  3. The body size limit, before anything reads or parses a body.
//  4. CSRF, which may parse a form-encoded body — and can now only ever parse a
//     bounded one. This ordering is the whole reason the pair is fixed here:
//     reversed, an attacker's oversized form body would be parsed in full
//     before any limit applied.
//
// One consequence is worth stating plainly rather than leaving to be
// discovered: because the limiter runs first and short-circuits, a 429 response
// does **not** carry the security headers. If you need them on rate-limit
// rejections too, compose the chain yourself with secureheaders first — the
// header middleware is a handful of map writes, so putting it ahead of the
// limiter costs effectively nothing.
//
// # Lifetime
//
// When [Config.RateLimitStore] is nil the chain uses a bounded in-process store
// that runs no background goroutine, so nothing needs to be closed. A store you
// supply is yours to close.
func API(cfg Config) (middleware.Chain, error) {
	if err := cfg.validate(); err != nil {
		return middleware.Chain{}, err
	}

	var mw []middleware.Middleware

	if !cfg.DisableRateLimit {
		opts := []ratelimit.Option{}
		if cfg.RateLimitStore != nil {
			opts = append(opts, ratelimit.WithStore(cfg.RateLimitStore))
		}
		if cfg.OnError != nil {
			opts = append(opts, ratelimit.WithOnError(cfg.OnError))
		}
		opts = append(opts, cfg.RateLimitOptions...)

		limiter := ratelimit.New(cfg.RateLimitBurst, cfg.RateLimitPerSec, opts...)
		mw = append(mw, limiter.Middleware)
	}

	mw = append(mw, secureheaders.Middleware(cfg.HeaderOptions...))

	maxBody := cfg.MaxBodyBytes
	if maxBody == 0 {
		maxBody = DefaultMaxBodyBytes
	}
	mw = append(mw, validate.MaxBodyBytes(maxBody))

	if !cfg.DisableCSRF {
		opts := []csrf.Option{}
		if len(cfg.TrustedOrigins) > 0 {
			opts = append(opts, csrf.WithTrustedOrigins(cfg.TrustedOrigins...))
		}
		opts = append(opts, cfg.CSRFOptions...)

		protector, err := csrf.New(cfg.CSRFSecret, opts...)
		if err != nil {
			return middleware.Chain{}, fmt.Errorf("preset: %w", err)
		}
		mw = append(mw, protector.Middleware)
	}

	return middleware.New(mw...), nil
}

// validate reports the first configuration problem that would result in a
// silently missing protection.
func (cfg Config) validate() error {
	if !cfg.DisableCSRF && len(cfg.CSRFSecret) == 0 {
		return ErrMissingCSRFSecret
	}
	if cfg.DisableCSRF && len(cfg.CSRFSecret) > 0 {
		// Contradictory input. Guessing which half was meant would mean either
		// silently ignoring a secret that was deliberately supplied, or
		// silently enabling a protection that was deliberately disabled.
		return errors.New("preset: CSRFSecret is set but DisableCSRF is also set; pick one")
	}
	if !cfg.DisableRateLimit && (cfg.RateLimitBurst <= 0 || cfg.RateLimitPerSec <= 0) {
		return ErrMissingRateLimit
	}
	if cfg.DisableRateLimit && (cfg.RateLimitBurst > 0 || cfg.RateLimitPerSec > 0) {
		return errors.New("preset: rate limits are set but DisableRateLimit is also set; pick one")
	}
	return nil
}

// compile-time check that the values this package produces really are the
// middleware shape the rest of the library promises.
var (
	_ middleware.Middleware           = secureheaders.Middleware()
	_ middleware.Middleware           = validate.MaxBodyBytes(1)
	_ func(http.Handler) http.Handler = secureheaders.Middleware()
)
