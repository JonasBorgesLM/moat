// Package secureheaders sets the HTTP response headers that instruct a browser
// to enforce security policy on your behalf.
//
// # Threat model
//
// These headers do not protect the server; they protect the user's browser from
// the consequences of a compromise elsewhere. Each default addresses a specific
// attack:
//
//   - Content-Security-Policy limits where scripts, styles and other
//     subresources may come from. It is the last line of defense when an XSS
//     hole exists: an injected <script src=evil.com> is blocked even though the
//     injection succeeded. The default also sets frame-ancestors, base-uri and
//     form-action, none of which fall back to default-src, and which
//     respectively block clickjacking, <base> tag hijacking of every relative
//     URL on the page, and form-action redirection of submitted credentials.
//   - Strict-Transport-Security removes the plaintext first request that an
//     active network attacker uses to strip TLS (sslstrip) before the redirect
//     to HTTPS can happen.
//   - X-Frame-Options: DENY blocks clickjacking on browsers that predate
//     frame-ancestors. It is redundant with CSP on current browsers and cheap
//     enough to keep.
//   - X-Content-Type-Options: nosniff stops content-type sniffing, which turns
//     an innocuous upload endpoint into script execution when a browser decides
//     a text/plain response "looks like" HTML or JavaScript.
//   - Referrer-Policy stops URLs — which routinely carry session tokens, reset
//     links and internal hostnames — from leaking to third parties in the
//     Referer header.
//   - Permissions-Policy denies access to camera, microphone, geolocation and
//     similar capabilities, so that injected or embedded content cannot request
//     them in your origin's name.
//
// # Defaults
//
// Defaults are the strict choice; every relaxation is an explicit, greppable
// option. Headers are written before the wrapped handler runs, so a handler
// that needs a different value for one response can still overwrite it.
//
// The strict default CSP forbids inline scripts and styles, and will break
// pages that use them. That is the point: adopting 'unsafe-inline' should be a
// visible decision in a code review, not the state you inherit by installing a
// library.
package secureheaders

import (
	"net/http"
	"strconv"
	"time"
)

// Default header values. They are exported so that a caller relaxing one can
// build on the original rather than retyping it, and so that tests in your own
// project can assert against the values this package actually ships.
const (
	// DefaultCSP allows subresources only from the page's own origin, and
	// additionally locks down the three directives that do not inherit from
	// default-src: frame-ancestors (clickjacking), base-uri (<base> hijacking
	// of every relative URL) and form-action (exfiltration of form posts).
	// object-src 'none' removes the plugin surface entirely.
	DefaultCSP = "default-src 'self'; base-uri 'self'; form-action 'self'; frame-ancestors 'none'; object-src 'none'"

	// DefaultReferrerPolicy sends the origin — not the full URL — to other
	// origins, and nothing at all when downgrading to HTTP. Full URLs leak
	// session tokens and password-reset links; a bare origin is enough for the
	// analytics use that makes people relax this.
	DefaultReferrerPolicy = "strict-origin-when-cross-origin"

	// DefaultPermissionsPolicy denies the capabilities that most applications
	// never use and that are most damaging when obtained by injected content.
	DefaultPermissionsPolicy = "accelerometer=(), autoplay=(), camera=(), display-capture=(), encrypted-media=(), fullscreen=(), geolocation=(), gyroscope=(), magnetometer=(), microphone=(), midi=(), payment=(), picture-in-picture=(), publickey-credentials-get=(), screen-wake-lock=(), usb=(), xr-spatial-tracking=()"

	// DefaultHSTSMaxAge is one year, the minimum that browsers and the preload
	// list treat as a serious commitment.
	DefaultHSTSMaxAge = 365 * 24 * time.Hour
)

// FrameOption is the value written to X-Frame-Options.
type FrameOption string

// Recognized X-Frame-Options values. Anything else is refused by
// [WithFrameOptions], so a typo cannot silently disable the header.
const (
	// FrameDeny forbids framing by anyone. This is the default.
	FrameDeny FrameOption = "DENY"

	// FrameSameOrigin permits framing by pages on the same origin. Note that
	// "same origin" here is the browser's notion, so any page you host can frame
	// any other — including a page an attacker can inject content into.
	FrameSameOrigin FrameOption = "SAMEORIGIN"
)

// config holds the resolved header set. It is unexported so that the zero value
// can never be a usable, silently header-free middleware: the only way to build
// one is through [Middleware], which starts from the strict defaults.
type config struct {
	csp               string
	cspReportOnly     string
	hstsEnabled       bool
	hstsMaxAge        time.Duration
	hstsSubdomains    bool
	hstsPreload       bool
	frameOptions      FrameOption
	referrerPolicy    string
	permissionsPolicy string
}

// Option relaxes or replaces one of the strict defaults.
type Option func(*config)

// Middleware returns middleware that writes the security headers to every
// response.
//
// With no options it writes [DefaultCSP], one-year HSTS with includeSubDomains
// and without preload, X-Frame-Options: DENY, X-Content-Type-Options: nosniff,
// [DefaultReferrerPolicy] and [DefaultPermissionsPolicy].
//
// Headers are set before the wrapped handler runs, so the handler may override
// any of them for an individual response. They are set on every response,
// including errors and redirects — an error page is still a page, and is just
// as capable of being framed or of executing injected script.
//
// The returned value has type func(http.Handler) http.Handler and can be used
// directly or placed in a middleware.Chain.
func Middleware(opts ...Option) func(http.Handler) http.Handler {
	cfg := config{
		csp:               DefaultCSP,
		hstsEnabled:       true,
		hstsMaxAge:        DefaultHSTSMaxAge,
		hstsSubdomains:    true,
		frameOptions:      FrameDeny,
		referrerPolicy:    DefaultReferrerPolicy,
		permissionsPolicy: DefaultPermissionsPolicy,
	}
	for _, opt := range opts {
		if opt != nil {
			opt(&cfg)
		}
	}
	// Resolve the header set once at construction: the per-request path should
	// do nothing but copy strings.
	headers := cfg.headers()

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			h := w.Header()
			for _, kv := range headers {
				h.Set(kv[0], kv[1])
			}
			next.ServeHTTP(w, r)
		})
	}
}

// headers renders the config into the literal header pairs to be written.
func (c config) headers() [][2]string {
	out := make([][2]string, 0, 7)
	if c.csp != "" {
		out = append(out, [2]string{"Content-Security-Policy", c.csp})
	}
	if c.cspReportOnly != "" {
		out = append(out, [2]string{"Content-Security-Policy-Report-Only", c.cspReportOnly})
	}
	// A zero or negative max-age omits the header entirely rather than sending
	// max-age=0. The two are not equivalent: max-age=0 is an instruction to
	// forget an existing HSTS policy for the host, so emitting it on every
	// response actively tears down protection that earlier responses
	// established. Silence simply leaves any existing policy in place.
	if c.hstsEnabled && c.hstsMaxAge > 0 {
		out = append(out, [2]string{"Strict-Transport-Security", hstsValue(c)})
	}
	if c.frameOptions != "" {
		out = append(out, [2]string{"X-Frame-Options", string(c.frameOptions)})
	}
	// nosniff is not configurable. There is no application that benefits from
	// letting a browser guess the type of its responses, and every case where
	// someone wants it off is better fixed by sending the right Content-Type.
	out = append(out, [2]string{"X-Content-Type-Options", "nosniff"})
	if c.referrerPolicy != "" {
		out = append(out, [2]string{"Referrer-Policy", c.referrerPolicy})
	}
	if c.permissionsPolicy != "" {
		out = append(out, [2]string{"Permissions-Policy", c.permissionsPolicy})
	}
	return out
}

// hstsValue renders the header. It is only reached with a positive max-age;
// see headers for why a zero max-age is omitted instead.
func hstsValue(c config) string {
	secs := int64(c.hstsMaxAge / time.Second)
	if secs < 1 {
		// A sub-second max-age truncates to zero, which would mean "forget the
		// policy". Round up so that an absurdly small duration still asks for
		// protection rather than revoking it.
		secs = 1
	}
	v := "max-age=" + strconv.FormatInt(secs, 10)
	if c.hstsSubdomains {
		v += "; includeSubDomains"
	}
	if c.hstsPreload {
		v += "; preload"
	}
	return v
}

// WithCSP replaces the Content-Security-Policy value.
//
// The policy string is written verbatim; this package does not parse or
// validate it, because a parser that silently "corrects" a policy is worse than
// none. Two consequences worth stating: a typo in a directive name is ignored
// by browsers, silently removing that protection, and dropping frame-ancestors,
// base-uri or form-action from your policy removes those protections entirely,
// since none of them inherits from default-src.
//
// An empty policy is treated as [WithoutCSP].
func WithCSP(policy string) Option {
	return func(c *config) { c.csp = policy }
}

// WithoutCSP omits Content-Security-Policy.
//
// This removes the only header here that mitigates an XSS hole you have not
// found yet. Prefer narrowing the policy with [WithCSP] over removing it.
func WithoutCSP() Option {
	return func(c *config) { c.csp = "" }
}

// WithCSPReportOnly additionally sends Content-Security-Policy-Report-Only.
//
// It is for rolling out a stricter policy: violations are reported but not
// blocked, so you can measure the breakage before enforcing. It is additive and
// never replaces the enforced policy, because a report-only header alone
// enforces nothing — a rollout mechanism that silently disables protection
// would be exactly the wrong tool.
func WithCSPReportOnly(policy string) Option {
	return func(c *config) { c.cspReportOnly = policy }
}

// WithHSTS replaces the Strict-Transport-Security parameters.
//
// A maxAge of zero or less omits the header entirely, which is the documented
// way to switch HSTS off through this option and is equivalent to
// [WithoutHSTS]. Note that omitting the header is not the same as sending
// max-age=0: the latter instructs browsers to forget an existing HSTS policy
// for the host, actively undoing protection that earlier responses set up.
// This package never sends that value by accident.
//
// Otherwise maxAge is truncated to whole seconds. A max-age shorter than a few
// months substantially weakens the header, since the protection only applies to
// users who have visited within that window; browsers refresh it on every HTTPS
// response, so a long value costs nothing.
//
// includeSubdomains extends the policy to every subdomain. That is the secure
// choice, and it will break any subdomain still served over plain HTTP —
// including ones you have forgotten about.
//
// preload requests inclusion in the browser-vendor preload lists, which is
// effectively irreversible: removal takes months to propagate and cannot be
// hurried, and until it does, every subdomain must be reachable over HTTPS.
// Enable it only when you are certain, which is why it is off by default.
func WithHSTS(maxAge time.Duration, includeSubdomains, preload bool) Option {
	return func(c *config) {
		c.hstsEnabled = true
		c.hstsMaxAge = maxAge
		c.hstsSubdomains = includeSubdomains
		c.hstsPreload = preload
	}
}

// WithoutHSTS omits Strict-Transport-Security.
//
// The header is harmless over plain HTTP — browsers are required to ignore it
// on a non-secure transport — so it is sent unconditionally by default rather
// than being suppressed based on r.TLS. Suppressing it that way looks correct
// but silently disables HSTS behind any TLS-terminating proxy, where r.TLS is
// nil for genuinely secure requests. Use this option only for a service that is
// deliberately and permanently plaintext.
func WithoutHSTS() Option {
	return func(c *config) { c.hstsEnabled = false }
}

// WithFrameOptions replaces the X-Frame-Options value. Unrecognized values are
// ignored, so that a typo cannot silently disable framing protection; use
// [WithoutFrameOptions] to remove the header deliberately.
//
// This header only matters for browsers that do not support CSP
// frame-ancestors. Relaxing it without also relaxing frame-ancestors in your
// CSP changes nothing on a current browser.
func WithFrameOptions(v FrameOption) Option {
	return func(c *config) {
		if v == FrameDeny || v == FrameSameOrigin {
			c.frameOptions = v
		}
	}
}

// WithoutFrameOptions omits X-Frame-Options. The CSP frame-ancestors directive
// still applies unless you have also removed it.
func WithoutFrameOptions() Option {
	return func(c *config) { c.frameOptions = "" }
}

// WithReferrerPolicy replaces the Referrer-Policy value. An empty value omits
// the header, which falls back to the browser's default — today usually
// strict-origin-when-cross-origin, but that is a vendor decision, not a
// guarantee.
//
// Avoid unsafe-url: it sends the full URL, including path and query, to every
// third party a page contacts. Session tokens, reset links and internal
// hostnames routinely live there.
func WithReferrerPolicy(policy string) Option {
	return func(c *config) { c.referrerPolicy = policy }
}

// WithPermissionsPolicy replaces the Permissions-Policy value. An empty value
// omits the header, which permits every capability the browser offers.
//
// The value is written verbatim. Note the syntax trap: an empty allow-list is
// written name=(), while name=* grants the capability to every embedded
// context, so a stray asterisk turns a denial into a blanket grant.
func WithPermissionsPolicy(policy string) Option {
	return func(c *config) { c.permissionsPolicy = policy }
}
