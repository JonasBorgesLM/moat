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
	"context"
	"crypto/rand"
	"encoding/base64"
	"net/http"
	"strconv"
	"strings"
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

	// The three cross-origin isolation headers. All default to empty, meaning
	// the header is not sent. See the options for why none of them is on by
	// default.
	coop CrossOriginOpenerPolicy
	corp CrossOriginResourcePolicy
	coep CrossOriginEmbedderPolicy

	// nonceDirectives is nil when per-request nonces are off. When set, it
	// names the CSP directives the nonce is injected into.
	nonceDirectives []string
	nonceErrored    http.Handler
	// nonceSource generates the per-request nonce. It is only ever replaced by
	// tests; see withNonceSource.
	nonceSource func() (string, error)
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

	if len(cfg.nonceDirectives) == 0 {
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

	if cfg.nonceSource == nil {
		cfg.nonceSource = newNonce
	}

	// Nonce mode. The policy is split around the insertion points once, here,
	// so that the per-request work is a Builder walk rather than a parse.
	enforce := splitAroundNonce(injectNonce(cfg.csp, cfg.nonceDirectives))
	report := splitAroundNonce(injectNonce(cfg.cspReportOnly, cfg.nonceDirectives))
	static := withoutCSP(headers)

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			nonce, err := cfg.nonceSource()
			if err != nil {
				// Serving the page with an empty or absent nonce would produce
				// exactly the silently broken CSP this option exists to avoid:
				// the template emits nonce="" and the browser blocks every
				// script. Refuse the request instead.
				//
				// The rejection is still a response, and this package's
				// contract is that every response carries the headers — an
				// error page is as framable and as injectable as any other. So
				// the full set goes on before the error is written, including
				// the CSP in its un-nonced form: injectNonce only ever *adds*
				// nonce sources, so the configured policy without them is
				// strictly the stricter of the two, which is the right way to
				// be wrong on an error page.
				h := w.Header()
				for _, kv := range headers {
					h.Set(kv[0], kv[1])
				}
				cfg.writeNonceError(w, r)
				return
			}

			h := w.Header()
			for _, kv := range static {
				h.Set(kv[0], kv[1])
			}
			if len(enforce) > 0 {
				h.Set("Content-Security-Policy", renderCSP(enforce, nonce))
			}
			if len(report) > 0 {
				h.Set("Content-Security-Policy-Report-Only", renderCSP(report, nonce))
			}

			next.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), nonceKey{}, nonce)))
		})
	}
}

// nonceKey types the context entry, so nothing else can collide with it.
type nonceKey struct{}

// noncePlaceholder marks where the per-request nonce is spliced into the
// policy. It is a control character because it cannot appear in a CSP policy,
// so it cannot collide with anything an operator writes.
const noncePlaceholder = "\x00"

// nonceBytes is the entropy per nonce. The CSP specification requires at least
// 128 bits and that the value be unguessable, since guessing it is equivalent
// to defeating the policy.
const nonceBytes = 16

// newNonce returns a fresh base64 nonce.
//
// Standard base64, not the URL-safe alphabet: the CSP grammar defines a nonce
// source as base64-value, and some browsers reject the URL-safe variant.
func newNonce() (string, error) {
	raw := make([]byte, nonceBytes)
	if _, err := rand.Read(raw); err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(raw), nil
}

// renderCSP splices the nonce into the pre-split policy.
func renderCSP(parts []string, nonce string) string {
	if len(parts) == 1 {
		return parts[0]
	}
	var b strings.Builder
	for i, part := range parts {
		if i > 0 {
			b.WriteString("'nonce-")
			b.WriteString(nonce)
			b.WriteString("'")
		}
		b.WriteString(part)
	}
	return b.String()
}

// splitAroundNonce breaks a policy at its placeholders, ready for renderCSP.
func splitAroundNonce(policy string) []string {
	if policy == "" {
		return nil
	}
	return strings.Split(policy, noncePlaceholder)
}

// withoutCSP drops the CSP headers from the precomputed static set, since in
// nonce mode they are rendered per request instead.
func withoutCSP(headers [][2]string) [][2]string {
	out := make([][2]string, 0, len(headers))
	for _, kv := range headers {
		if kv[0] == "Content-Security-Policy" || kv[0] == "Content-Security-Policy-Report-Only" {
			continue
		}
		out = append(out, kv)
	}
	return out
}

// injectNonce places a nonce placeholder in each of the named directives.
//
// A directive already present in the policy gains the nonce alongside its
// existing sources. A directive that is absent is **added**, containing only
// the nonce.
//
// Adding rather than skipping is the whole reason this cannot silently produce
// a broken policy. Consider [DefaultCSP], which has no script-src at all and
// relies on default-src 'self' for scripts. Skipping would leave the nonce in
// the request context and absent from the policy: templates would emit
// nonce="..." and the browser would ignore it. Adding "script-src 'nonce-X'"
// instead *tightens* the policy — scripts now need the nonce rather than merely
// being same-origin — and erring toward the restrictive side is the right
// direction for a security default.
//
// The cost, documented on [WithNonce], is that same-origin <script src> tags
// then need the nonce attribute too.
func injectNonce(policy string, directives []string) string {
	if policy == "" {
		return ""
	}

	segments := strings.Split(policy, ";")
	found := make(map[string]bool, len(directives))

	for i, seg := range segments {
		name, _, _ := strings.Cut(strings.TrimSpace(seg), " ")
		for _, want := range directives {
			if strings.EqualFold(name, want) {
				found[want] = true
				segments[i] = strings.TrimRight(seg, " ") + " " + noncePlaceholder
			}
		}
	}

	out := strings.Join(segments, ";")
	for _, want := range directives {
		if !found[want] {
			out += "; " + want + " " + noncePlaceholder
		}
	}
	return out
}

// writeNonceError writes the response used when the CSPRNG fails.
//
// The caller has already set the full header set on w, so a replacement handler
// inherits it and may override it, exactly as the wrapped handler can on the
// success path. Do not write a response from here without that having happened:
// see TestEveryResponseCarriesTheFullHeaderSet.
func (c config) writeNonceError(w http.ResponseWriter, r *http.Request) {
	if c.nonceErrored != nil {
		c.nonceErrored.ServeHTTP(w, r)
		return
	}
	http.Error(w, "Internal Server Error", http.StatusInternalServerError)
}

// Nonce returns the Content-Security-Policy nonce for the request, and whether
// one is present.
//
// Pass it to html/template and put it on every inline script the page emits:
//
//	<script nonce="{{.Nonce}}"> ... </script>
//
// # Why this returns a bool
//
// The same reason csrf.Token does. A bare string with "" meaning "no nonce"
// flows silently into the template, the page renders nonce="", the browser
// blocks every script, and the fastest apparent fix is to add 'unsafe-inline'
// to the policy — which is equivalent to having no CSP at all. The bool forces
// the caller to notice that the middleware is not in front of this handler, or
// that [WithNonce] was never enabled.
//
// A nonce is present on every request that passed through a Middleware built
// with [WithNonce], and on no others.
func Nonce(r *http.Request) (string, bool) {
	if r == nil {
		return "", false
	}
	nonce, ok := r.Context().Value(nonceKey{}).(string)
	if !ok || nonce == "" {
		return "", false
	}
	return nonce, true
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
	// Absent unless explicitly configured. Adding any of these to the default
	// set would change behaviour for every already-deployed consumer without a
	// compile error to warn them; see the options for the analysis.
	if c.coop != "" {
		out = append(out, [2]string{"Cross-Origin-Opener-Policy", string(c.coop)})
	}
	if c.corp != "" {
		out = append(out, [2]string{"Cross-Origin-Resource-Policy", string(c.corp)})
	}
	if c.coep != "" {
		out = append(out, [2]string{"Cross-Origin-Embedder-Policy", string(c.coep)})
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

// DefaultNonceDirectives is what [WithNonce] injects into when called with no
// arguments: script-src only.
//
// style-src is deliberately not included. Nonced styles are a much rarer need,
// and adding the directive would silently tighten style loading for every
// caller who only wanted script nonces — a page whose same-origin stylesheet
// stopped loading would be a confusing way to find that out. Ask for it
// explicitly: WithNonce("script-src", "style-src").
var DefaultNonceDirectives = []string{"script-src"}

// WithNonce enables a fresh Content-Security-Policy nonce per request, injected
// into the named directives, and readable from the handler with [Nonce].
//
// With no arguments it injects into [DefaultNonceDirectives].
//
// # Why you want this
//
// The strict default CSP forbids inline scripts, and real pages have them —
// a bootstrap snippet, a JSON blob, an analytics tag. The usual response is to
// add 'unsafe-inline', which permits every inline script including the injected
// one, and is therefore equivalent to having no script policy at all. A nonce
// is the way to keep the policy strict and still run the inline scripts you
// wrote: the browser executes only the ones carrying this request's value, and
// an injected script cannot carry it because it is unguessable and changes
// every response.
//
// # What it costs
//
// A named directive that is absent from the policy is added containing only the
// nonce. For [DefaultCSP], which has no script-src and relies on
// default-src 'self', that means scripts stop being allowed merely for being
// same-origin: **every <script> tag, including <script src="/app.js">, needs
// the nonce attribute**. That is a real migration cost and it is the correct
// direction — a nonce whose policy still admitted every same-origin script
// would be decoration.
//
// If you would rather keep same-origin script loading and nonce only the inline
// ones, put 'strict-dynamic' or your own source list in the policy yourself with
// [WithCSP]; this option will inject alongside whatever is already there.
//
// # Interaction with caching
//
// A nonced response is unique per request and must not be cached and replayed,
// or every visitor after the first receives a policy whose nonce does not match
// the page. Do not put a shared cache in front of nonced HTML.
//
// The nonce is also injected into a report-only policy when one is configured,
// so [WithCSPReportOnly] can be used to trial a nonced policy before enforcing
// it.
//
// Unknown or duplicated directive names are used as given; the option does not
// validate them against the CSP grammar, because the set of valid directives
// grows and a library that rejected a new one would be an obstacle rather than
// a check.
func WithNonce(directives ...string) Option {
	return func(c *config) {
		if len(directives) == 0 {
			c.nonceDirectives = append([]string(nil), DefaultNonceDirectives...)
			return
		}
		seen := make(map[string]bool, len(directives))
		out := make([]string, 0, len(directives))
		for _, d := range directives {
			d = strings.TrimSpace(d)
			if d == "" || seen[strings.ToLower(d)] {
				continue
			}
			seen[strings.ToLower(d)] = true
			out = append(out, d)
		}
		if len(out) > 0 {
			c.nonceDirectives = out
		}
	}
}

// WithNonceErrorHandler replaces the response written when the system CSPRNG
// fails and no nonce can be generated. The default writes 500.
//
// This is a rejection point, so it is customizable for the same reason every
// other one in this library is: an application with its own error envelope
// should not have this single path answer in text/plain.
//
// It must not fall through to the handler. Serving the page without a nonce
// produces a policy that blocks the page's own scripts, which is a broken page
// that looks like a CSP misconfiguration; serving it with an empty nonce is
// worse, because 'nonce-' matches nothing and the failure is silent.
//
// A nil handler is ignored, and the option has no effect unless [WithNonce] is
// also set.
func WithNonceErrorHandler(h http.Handler) Option {
	return func(c *config) {
		if h != nil {
			c.nonceErrored = h
		}
	}
}

// NoStore returns middleware that marks responses as uncacheable.
//
// It writes Cache-Control: no-store and Pragma: no-cache. Use it on the routes
// whose responses carry a credential or personal data: a token endpoint, a
// session bootstrap, an account page.
//
// # Not a preference
//
// RFC 6749 §5.1 *requires* both headers on the OAuth 2.0 token endpoint
// response, and RFC 6750 repeats the requirement for bearer tokens. Pragma is
// legacy — it is an HTTP/1.0 request header that HTTP/1.1 does not define for
// responses — and is sent anyway because the specification names it and
// intermediaries in the wild still honour it.
//
// no-store rather than no-cache: no-cache permits a shared cache to *store* the
// response and merely requires revalidation before reuse, which still leaves
// one user's token sitting in a proxy. no-store forbids writing it down at all.
//
// # Why this is not an option on [Middleware]
//
// Middleware is built once and applied to a whole chain, and no-store across a
// whole chain disables caching of static assets and public responses — trading
// a requirement that applies to a handful of routes for a site-wide performance
// regression. The requirement is about the response that carries the credential,
// so the scope is per-route, and the way this library expresses per-route is a
// plain func(http.Handler) http.Handler.
//
// Headers are written before the wrapped handler runs, so a handler that has
// already called WriteHeader cannot lose them, and a handler that genuinely
// needs different caching for one response can still overwrite them.
func NoStore(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		h.Set("Cache-Control", "no-store")
		h.Set("Pragma", "no-cache")
		next.ServeHTTP(w, r)
	})
}

// withNonceSource overrides the nonce generator.
//
// It is unexported because production code has no reason to supply its own
// entropy, and an exported hook would be an invitation to supply a predictable
// nonce, which defeats the entire mechanism. Tests use it to reach the
// CSPRNG-failure path, which is otherwise unreachable.
func withNonceSource(fn func() (string, error)) Option {
	return func(c *config) {
		if fn != nil {
			c.nonceSource = fn
		}
	}
}

// SiteDataType names one category of stored data for [ClearSiteData].
type SiteDataType string

// The data categories defined by the Clear-Site-Data specification.
const (
	// SiteDataCache clears the origin's HTTP cache. Without it a logged-out
	// user pressing Back can be served a cached authenticated page from disk.
	SiteDataCache SiteDataType = "cache"

	// SiteDataCookies clears cookies. Read the registrable-domain warning on
	// [ClearSiteData] before using it: the blast radius is wider than the
	// origin.
	SiteDataCookies SiteDataType = "cookies"

	// SiteDataStorage clears localStorage, sessionStorage, IndexedDB and the
	// other origin-scoped storage APIs. This is where single-page applications
	// keep access tokens.
	SiteDataStorage SiteDataType = "storage"

	// SiteDataExecutionContexts reloads other browsing contexts for the origin,
	// so a second tab left open on an authenticated page does not keep showing
	// it. It is not part of [DefaultSiteDataTypes]; see [ClearSiteData].
	SiteDataExecutionContexts SiteDataType = "executionContexts"

	// SiteDataAll is the "*" wildcard, meaning every category including ones
	// added to the specification later.
	SiteDataAll SiteDataType = "*"
)

// DefaultSiteDataTypes is what [ClearSiteData] sends when called with no
// arguments: cache, cookies and storage.
//
// [SiteDataExecutionContexts] is excluded, and "*" is not used because it
// implies it. Reloading every other tab on the origin is a visible, surprising
// effect that belongs to a deliberate choice rather than to a default, and on a
// logout page it can interrupt work in a tab the user did not intend to log out
// of. Ask for it explicitly when you want it.
var DefaultSiteDataTypes = []SiteDataType{SiteDataCache, SiteDataCookies, SiteDataStorage}

// ClearSiteData returns middleware that asks the browser to discard stored data
// for the origin. Put it on the logout route.
//
// With no arguments it sends [DefaultSiteDataTypes].
//
// # Why a logout needs it
//
// Invalidating the session server-side ends the session; it does not remove what
// the browser already has. The access token in localStorage survives, the
// authenticated pages in the HTTP cache survive and are served when the user
// presses Back, and a second tab keeps rendering the logged-in view. On a shared
// or public machine that residue is the whole problem the user was trying to
// solve by logging out.
//
// # It is defense in depth, never the mechanism
//
// Browser support is uneven, and the header is **ignored entirely on
// non-secure origins** — over plaintext HTTP it does nothing at all. So it must
// sit on top of real server-side invalidation, never in place of it. A logout
// that relies on the client agreeing to forget is not a logout.
//
// # The cookie blast radius is wider than the origin
//
// [SiteDataCookies] clears cookies for the *registrable domain*, not just this
// origin. Logging out of app.example.com also clears cookies set by
// shop.example.com and by example.com itself. On a domain that hosts several
// independent applications that is a cross-application logout, which may be
// exactly what you want or may be a surprise; it is the one part of this header
// that is worth checking before deploying.
//
// # Ordering
//
// The header is written before the wrapped handler runs, so a handler that
// redirects after logout still carries it. The browser applies it to the
// response that carries it, so put this on the logout endpoint itself rather
// than on the page it redirects to — a redirect the browser follows will not
// carry the header unless that response has it too.
//
// Duplicate and empty entries are dropped. A call that leaves nothing valid
// falls back to [DefaultSiteDataTypes], so a misconfiguration cannot silently
// turn the middleware into a no-op.
func ClearSiteData(types ...SiteDataType) func(http.Handler) http.Handler {
	selected := types
	if len(selected) == 0 {
		selected = DefaultSiteDataTypes
	}

	seen := make(map[SiteDataType]bool, len(selected))
	quoted := make([]string, 0, len(selected))
	for _, t := range selected {
		t = SiteDataType(strings.TrimSpace(string(t)))
		if t == "" || seen[t] {
			continue
		}
		seen[t] = true
		// Each value is a quoted string in the grammar. Unquoted values are
		// ignored by browsers, which would make this middleware silently do
		// nothing.
		quoted = append(quoted, `"`+string(t)+`"`)
	}
	if len(quoted) == 0 {
		for _, t := range DefaultSiteDataTypes {
			quoted = append(quoted, `"`+string(t)+`"`)
		}
	}
	value := strings.Join(quoted, ", ")

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Clear-Site-Data", value)
			next.ServeHTTP(w, r)
		})
	}
}

// CrossOriginOpenerPolicy is a value for the Cross-Origin-Opener-Policy header.
type CrossOriginOpenerPolicy string

// COOP values.
const (
	// COOPUnsafeNone is the browser default: the document shares a browsing
	// context group with whatever opened it, and window.opener works both ways.
	COOPUnsafeNone CrossOriginOpenerPolicy = "unsafe-none"

	// COOPSameOriginAllowPopups severs the link to a cross-origin document that
	// opened *this* one, while keeping the reference to popups this document
	// opens. It is the value that protects against being framed into someone
	// else's window group without breaking an OAuth or payment popup that this
	// application opens and expects postMessage back from.
	COOPSameOriginAllowPopups CrossOriginOpenerPolicy = "same-origin-allow-popups"

	// COOPSameOrigin severs the link in both directions. It is required, with
	// [COEPRequireCorp], to reach cross-origin isolation. It **breaks the popup
	// OAuth pattern**: a popup this document opens can no longer postMessage
	// back to it, because the opener reference is gone.
	COOPSameOrigin CrossOriginOpenerPolicy = "same-origin"
)

// CrossOriginResourcePolicy is a value for the Cross-Origin-Resource-Policy
// header.
type CrossOriginResourcePolicy string

// CORP values.
const (
	// CORPSameOrigin allows only this origin to embed the response.
	CORPSameOrigin CrossOriginResourcePolicy = "same-origin"

	// CORPSameSite allows any origin on the same site.
	CORPSameSite CrossOriginResourcePolicy = "same-site"

	// CORPCrossOrigin allows anyone. Use it on responses that are meant to be
	// embedded cross-origin — a public CDN asset, a font, an avatar.
	CORPCrossOrigin CrossOriginResourcePolicy = "cross-origin"
)

// CrossOriginEmbedderPolicy is a value for the Cross-Origin-Embedder-Policy
// header.
type CrossOriginEmbedderPolicy string

// COEP values.
const (
	// COEPUnsafeNone is the browser default: no restriction on subresources.
	COEPUnsafeNone CrossOriginEmbedderPolicy = "unsafe-none"

	// COEPRequireCorp refuses to load any cross-origin subresource that does
	// not explicitly opt in with CORP or CORS. Read [WithCrossOriginEmbedderPolicy]
	// before using it; the breakage is extensive and not subtle.
	COEPRequireCorp CrossOriginEmbedderPolicy = "require-corp"

	// COEPCredentialless loads cross-origin subresources without credentials
	// instead of refusing them. Less breakage than require-corp, but any
	// subresource that needed cookies to render now silently renders logged
	// out, and browser support is narrower.
	COEPCredentialless CrossOriginEmbedderPolicy = "credentialless" // #nosec G101 -- a COEP header value defined by the spec, not a credential.
)

// WithCrossOriginOpenerPolicy sets Cross-Origin-Opener-Policy.
//
// # What it defends
//
// Without it, a document that opens yours keeps a live window.opener reference
// and can navigate your window elsewhere — reverse tabnabbing, where the tab a
// user left open is quietly replaced with a phishing page. It also closes
// cross-window side channels used by XS-Leaks.
//
// # Why it is not a default here
//
// [COOPSameOrigin] breaks the popup OAuth and payment pattern outright: the
// popup can no longer postMessage back to the opener, and the flow hangs with
// no error the application can catch. That is a production outage delivered by
// a library upgrade, with no compile error to warn anyone.
//
// [COOPSameOriginAllowPopups] is the value most applications want: it protects
// against being opened by a hostile document while leaving popups you open
// working. Even that is not free — an application that is *itself* opened as a
// popup and talks back to its opener (an identity provider, an embeddable
// widget) depends on the link this severs.
//
// It is a candidate to become a default in a later version. If that happens it
// will be announced in the changelog as a behaviour change; it will not arrive
// as a quiet tightening in a patch release.
//
// An empty value omits the header.
func WithCrossOriginOpenerPolicy(v CrossOriginOpenerPolicy) Option {
	return func(c *config) { c.coop = v }
}

// WithCrossOriginResourcePolicy sets Cross-Origin-Resource-Policy.
//
// # What it defends
//
// It tells the browser who may embed this response as a subresource. With
// [CORPSameOrigin], another origin cannot pull your endpoint in as an image or
// a script and use a speculative-execution side channel to read the bytes it is
// not allowed to see. It also blunts cross-site script inclusion of
// JSON-shaped responses.
//
// # Why it is not a default here
//
// It is a header about *responses*, and this library is often installed in
// front of things that are deliberately consumed cross-origin: a public API, a
// CDN-hosted asset, an avatar or a font served to other origins. Defaulting to
// [CORPSameOrigin] would break those silently — the server keeps returning 200
// and the browser discards the response — which is among the hardest failures
// to diagnose from a server-side log.
//
// If you serve both kinds of response, set [CORPSameOrigin] on the chain and
// override the header on the routes that are meant to be public; handlers may
// overwrite anything this package sets.
//
// Like COOP, [CORPSameOrigin] is a candidate default for a later version, and
// would be announced in the changelog rather than arriving quietly.
//
// An empty value omits the header.
func WithCrossOriginResourcePolicy(v CrossOriginResourcePolicy) Option {
	return func(c *config) { c.corp = v }
}

// WithCrossOriginEmbedderPolicy sets Cross-Origin-Embedder-Policy.
//
// # Read this before using it
//
// [COEPRequireCorp] refuses every cross-origin subresource that does not
// explicitly opt in. In practice that means third-party images, fonts,
// analytics scripts, and embedded iframes — maps, video players, payment
// frames — stop loading unless each of those third parties sends CORP or
// correct CORS headers, which most do not. The page does not fail loudly; the
// resources are simply absent.
//
// It exists as an option because it is the price of cross-origin isolation:
// COEP plus [COOPSameOrigin] is what unlocks SharedArrayBuffer and
// high-resolution timers. If you do not need those, you do not need this
// header, and turning it on buys nothing for the breakage it costs.
//
// [COEPCredentialless] is the softer variant — subresources load without
// credentials rather than being refused — but anything that needed cookies to
// render now renders logged out, and support is narrower.
//
// This will never become a default, in any version. That is a settled
// decision, not a deferred one. An empty value omits the
// header.
func WithCrossOriginEmbedderPolicy(v CrossOriginEmbedderPolicy) Option {
	return func(c *config) { c.coep = v }
}
