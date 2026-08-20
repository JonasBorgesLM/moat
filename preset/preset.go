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

	"github.com/JonasBorgesLM/moat/csrf"
	"github.com/JonasBorgesLM/moat/middleware"
	"github.com/JonasBorgesLM/moat/ratelimit"
	"github.com/JonasBorgesLM/moat/realip"
	"github.com/JonasBorgesLM/moat/secret"
	"github.com/JonasBorgesLM/moat/secureheaders"
	"github.com/JonasBorgesLM/moat/validate"
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

	// ErrProxyTopologyUnspecified reports that rate limiting is enabled but the
	// chain was told neither which proxies to trust nor that the service is
	// directly exposed.
	//
	// # Why this cannot be defaulted
	//
	// A rate limiter is only as good as the identity it counts against. With no
	// answer here the limiter would fall back to r.RemoteAddr, which behind a
	// load balancer is the balancer's address for every client on earth — so
	// every client shares one bucket and any single one of them can hold the
	// whole service at its limit indefinitely. That is not a bypass, it is
	// denial of service against everyone else, and it looks exactly like
	// ordinary throttling from the outside, which is what makes it so bad a
	// default to ship silently.
	//
	// The opposite guess is no better: reading X-Forwarded-For without knowing
	// which peer is allowed to set it lets each request choose its own identity,
	// which removes the limit entirely. There is no safe default because the
	// answer is a fact about your deployment that only you have.
	//
	// Answer it with [Config.TrustedProxies] or, if nothing sits in front of
	// this server, with [Config.DirectlyExposed]. Refusing an empty
	// TrustedProxies outright would be the wrong shape: it would break the
	// legitimate direct deployment and push an operator to type something —
	// anything — to make startup succeed, which is worse than what it replaced.
	ErrProxyTopologyUnspecified = errors.New("preset: set TrustedProxies to your proxy CIDRs, or DirectlyExposed if nothing fronts this server; without one the rate limiter counts every client as the same client")
)

// Config parameterizes [API].
//
// The zero Config is deliberately not usable: it would describe an application
// with no CSRF protection and no rate limiting, which is exactly the outcome
// this package refuses to produce by accident.
type Config struct {
	// CSRFSecret is the server secret used to sign CSRF tokens. It must be at
	// least csrf.MinSecretLen bytes, identical across every instance, and
	// stable across deploys. Generate one with csrf.GenerateSecret, or wrap
	// bytes from your secret store with secret.New.
	//
	// It is a secret.Value so that a Config dumped with %+v, marshalled into a
	// startup log line, or passed to slog.Any does not carry the signing key
	// with it. A Config is exactly the kind of struct that gets logged.
	//
	// Required unless DisableCSRF is set.
	CSRFSecret secret.Value

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

	// TrustedProxies lists the CIDRs of the reverse proxies in front of this
	// server — the load balancer, ingress or CDN — in the form realip.New
	// accepts ("10.0.0.0/8", "2001:db8::/32", or a bare address for a single
	// host).
	//
	// When set, the rate limiter keys on the client address derived by realip
	// rather than on r.RemoteAddr, so clients arriving through one balancer are
	// counted separately instead of sharing a bucket. Set it to your *proxies*,
	// never to your clients: a client range here would let requests from it
	// choose their own identity.
	//
	// Required unless [Config.DirectlyExposed] is set, and only when rate
	// limiting is enabled. See [ErrProxyTopologyUnspecified].
	TrustedProxies []string

	// DirectlyExposed states that no proxy sits in front of this server, so
	// r.RemoteAddr already is the client.
	//
	// It is the alternative to [Config.TrustedProxies], not a way to skip the
	// question. It exists as a named field for the same reason
	// [Config.DisableCSRF] does: the claim is a real one about your deployment,
	// it is wrong for most production topologies, and it should be visible to
	// whoever reviews the diff. If it is set while the service is in fact behind
	// a balancer, every client shares one rate-limit bucket.
	//
	// Setting it together with TrustedProxies is contradictory and is an error.
	DirectlyExposed bool

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

	// BodyLimitOptions are passed through to validate.MaxBodyBytes, for
	// replacing the 413 written when a request declares a body larger than the
	// limit.
	//
	// It exists so that adopting the preset does not cost you a hook you would
	// have had by wiring the packages yourself. Without it, an application with
	// its own error envelope gets that envelope from the rate limiter, the CSRF
	// check and the store-outage path — every rejection in the chain — and
	// text/plain from this one, which is the inconsistency the preset is
	// supposed to save you from rather than introduce.
	//
	// Note that this covers only the declared-Content-Length rejection. The
	// other half of the body limit surfaces inside your handler as a
	// *http.MaxBytesError and is mapped there; see validate.MaxBodyBytes.
	BodyLimitOptions []validate.BodyLimitOption
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

// API returns a chain wiring security headers, rate limiting, a request body
// limit and CSRF protection, in that order.
//
// It fails rather than silently omitting a protection: a missing CSRF secret or
// a missing rate limit is an error unless the corresponding Disable field says
// the omission is intended. See the package documentation for why.
//
// # The order, and what it buys
//
//  1. Security headers, set on the way in so that every response carries them
//     — including a rate-limit rejection, a CSRF rejection, or any other error
//     written by the middleware that follow. An error response is still a
//     response: it is exactly as capable of being framed, sniffed as a
//     different content type, or rendered without a CSP as a 200 is, and it is
//     a well-known injection surface in its own right. Putting headers first
//     costs a handful of map writes on every request in exchange for never
//     shipping an unprotected error page.
//  2. Rate limiting, so that an abusive client is turned away before anything
//     further downstream spends work on it.
//  3. The body size limit, before anything reads or parses a body.
//  4. CSRF, which may parse a form-encoded body — and can now only ever parse a
//     bounded one. This ordering is the whole reason the pair is fixed here:
//     reversed, an attacker's oversized form body would be parsed in full
//     before any limit applied.
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

	mw = append(mw, secureheaders.Middleware(cfg.HeaderOptions...))

	if !cfg.DisableRateLimit {
		opts := []ratelimit.Option{}
		if len(cfg.TrustedProxies) > 0 {
			// The whole point of the field: the library already knows how to do
			// this correctly, and the preset should reach it rather than leave
			// every consumer to wire realip by hand through RateLimitOptions.
			extractor, err := realip.New(cfg.TrustedProxies)
			if err != nil {
				return middleware.Chain{}, fmt.Errorf("preset: TrustedProxies: %w", err)
			}
			opts = append(opts, ratelimit.WithKeyFunc(extractor.KeyFunc()))
		}
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

	maxBody := cfg.MaxBodyBytes
	if maxBody == 0 {
		maxBody = DefaultMaxBodyBytes
	}
	mw = append(mw, validate.MaxBodyBytes(maxBody, cfg.BodyLimitOptions...))

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
	if !cfg.DisableCSRF && cfg.CSRFSecret.IsZero() {
		return ErrMissingCSRFSecret
	}
	if cfg.DisableCSRF && !cfg.CSRFSecret.IsZero() {
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
	if len(cfg.TrustedProxies) > 0 && cfg.DirectlyExposed {
		// Contradictory input, same treatment as the pairs above: one says
		// requests arrive through a proxy, the other says they do not.
		return errors.New("preset: TrustedProxies is set but DirectlyExposed is also set; pick one")
	}
	if !cfg.DisableRateLimit && len(cfg.TrustedProxies) == 0 && !cfg.DirectlyExposed {
		// The ambiguous case, and the only one that must be impossible: an
		// empty TrustedProxies cannot be told apart from an unset one.
		return ErrProxyTopologyUnspecified
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
