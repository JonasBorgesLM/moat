// Package csrf provides stateless CSRF protection using a signed double-submit
// cookie, with Origin/Referer validation as defense in depth.
//
// # The attack
//
// Cross-site request forgery exploits the fact that browsers attach a site's
// cookies to requests regardless of who caused the request. A page on
// attacker.example can submit a form to bank.example, and the victim's session
// cookie rides along. The server sees an authenticated request to transfer
// money and has no way, from the cookie alone, to tell that the victim did not
// ask for it.
//
// The defense is to require something on every state-changing request that the
// attacker's page cannot obtain: a token it can neither read nor guess.
//
// # The mechanism
//
// A random secret is stored in an HttpOnly cookie. The token handed to your
// templates is HMAC-SHA256(serverSecret, cookieValue). A request is accepted
// only when the token it submits matches the HMAC of the cookie it presents.
//
// Why this beats the naive double-submit cookie, where the cookie and the form
// field simply have to be equal: an attacker who can *set* a cookie on your
// domain — through a subdomain takeover, a compromised sibling application, or
// an active network attacker on any plaintext sibling origin — can set both
// halves to a value of their choosing and satisfy the equality check. Signing
// with a server-side secret closes that: the attacker can plant a cookie, but
// cannot produce the matching HMAC.
//
// It is stateless. There is no session store, no server-side token list, and
// nothing to replicate between instances. The only shared state is the secret.
//
// # Hardening beyond the token
//
// Three further measures, each addressing a specific gap:
//
//   - **Origin/Referer validation** on unsafe methods, per OWASP guidance. Even
//     signed double-submit is weakened by cookie injection; the browser-supplied
//     Origin header is not forgeable by a cross-site page, so checking it closes
//     most of what remains.
//   - **The __Host- cookie prefix** by default. A cookie so named is rejected by
//     the browser unless it is Secure, has Path=/, and carries no Domain
//     attribute — which means a subdomain, or an attacker who has taken one
//     over, cannot overwrite it. This directly attacks the cookie-injection
//     scenario above.
//   - **SameSite=Lax** by default, so the cookie is not sent on cross-site
//     subrequests at all. This is defense in depth, not the defense: SameSite
//     behavior varies across browsers and versions, and relying on it alone
//     leaves users of older browsers unprotected.
//
// # What this cannot do
//
// **Same-origin XSS defeats CSRF protection completely, and no CSRF design can
// change that.** Script running on your origin can read the token out of the
// page and issue a perfectly valid request. If you have an XSS hole, you do not
// have a CSRF problem to solve; you have an XSS problem. Fix it with contextual
// output encoding (html/template) and a strict Content-Security-Policy.
//
// Related limits worth stating:
//
//   - The secret must be identical across every instance and stable across
//     deploys. A per-process random secret invalidates every outstanding token
//     whenever a process restarts or a request lands on another instance, and
//     the fastest "fix" for the resulting flood of 403s is to turn CSRF off.
//   - Rotating the secret invalidates outstanding tokens, so users with an open
//     form get one rejection and must reload. Rotate deliberately.
//   - This protects against forged requests, not against a user who is
//     legitimately authenticated and hostile. It is not authorization.
package csrf

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"mime"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// MinSecretLen is the shortest server secret [New] accepts.
//
// Thirty-two bytes matches the output width of SHA-256, which is the point at
// which lengthening the key stops adding strength to the HMAC. Shorter secrets
// are rejected rather than accepted with a warning, because a warning in a
// library nobody reads is not a control.
const MinSecretLen = 32

// Default names. The cookie carries the __Host- prefix, which browsers enforce:
// a cookie so named is only accepted when it is Secure, has Path=/, and has no
// Domain attribute, so no subdomain can overwrite it.
const (
	DefaultCookieName = "__Host-gosecure.csrf"
	DefaultFieldName  = "gosecure.csrf"
	DefaultHeaderName = "X-CSRF-Token"

	// fallbackCookieName is used when the configuration makes the __Host-
	// prefix invalid, since a browser would otherwise silently drop the cookie.
	fallbackCookieName = "gosecure.csrf"
)

// DefaultMaxAge is how long an issued cookie remains valid.
//
// It is bounded rather than session-lifetime so that a token left behind in a
// shared or long-lived browser session eventually stops working.
const DefaultMaxAge = 12 * time.Hour

// Errors reported by this package. Test for them with errors.Is.
var (
	// ErrSecretTooShort reports a server secret below [MinSecretLen].
	ErrSecretTooShort = errors.New("csrf: secret must be at least 32 bytes")

	// ErrNoToken reports that no CSRF token was present in the request context.
	// It is what [Token] signals by returning false.
	ErrNoToken = errors.New("csrf: no token in request context")
)

// contextKey is unexported so that no other package can write to or read the
// context slot this package uses. A string key would let any package overwrite
// the token with one of its choosing.
type contextKey struct{}

// tokenKey is the sole context slot this package uses. It is a package-level
// value of an unexported type, so no other package can construct an equal key
// and overwrite the token with one of its own choosing.
var tokenKey contextKey

// Protector issues and verifies CSRF tokens.
//
// It is safe for concurrent use and is intended to be created once at startup
// and shared. The zero value is not usable; create one with [New].
type Protector struct {
	secret []byte

	cookieName   string
	fieldName    string
	headerName   string
	cookiePath   string
	cookieDomain string
	sameSite     http.SameSite
	secure       bool
	maxAge       time.Duration

	trustedOrigins []string
	errorHandler   http.Handler
}

// Option configures a [Protector].
type Option func(*Protector)

// New returns a Protector that signs tokens with secret.
//
// secret must be at least [MinSecretLen] bytes of cryptographically random
// data, and must be identical across every instance of your application and
// stable across deploys. Generate one with [GenerateSecret], store it wherever
// you keep other secrets, and load it at startup.
//
// Do not generate a fresh secret per process. Every token issued by one process
// is then rejected by every other, producing intermittent 403s that look like a
// bug in this library and get "fixed" by disabling CSRF protection.
//
// New copies the secret, so the caller may reuse or zero the slice afterwards.
func New(secret []byte, opts ...Option) (*Protector, error) {
	if len(secret) < MinSecretLen {
		return nil, fmt.Errorf("%w (got %d)", ErrSecretTooShort, len(secret))
	}

	p := &Protector{
		secret:     append([]byte(nil), secret...),
		cookieName: DefaultCookieName,
		fieldName:  DefaultFieldName,
		headerName: DefaultHeaderName,
		cookiePath: "/",
		sameSite:   http.SameSiteLaxMode,
		secure:     true,
		maxAge:     DefaultMaxAge,
	}
	for _, opt := range opts {
		if opt != nil {
			opt(p)
		}
	}

	// A browser rejects a __Host- cookie that is not Secure, not Path=/, or
	// carries a Domain. Silently keeping the name would mean the cookie is never
	// stored and every request fails; renaming keeps the configuration working
	// and costs only the prefix's extra protection, which that configuration
	// had already given up.
	if strings.HasPrefix(p.cookieName, "__Host-") && !p.hostPrefixValid() {
		p.cookieName = fallbackCookieName
	}
	return p, nil
}

// hostPrefixValid reports whether the current configuration satisfies the
// browser's requirements for the __Host- cookie name prefix.
func (p *Protector) hostPrefixValid() bool {
	return p.secure && p.cookiePath == "/" && p.cookieDomain == ""
}

// GenerateSecret returns [MinSecretLen] cryptographically random bytes suitable
// for [New].
//
// It returns the value and never prints it. A library that writes a secret to
// stdout is unusable in a real application: the value lands in CI logs, in
// container logs, and in whatever aggregates them. Store the result the way you
// store other secrets.
//
// The cmd/gosecure-secret helper wraps this for command-line use, where
// printing is the caller's explicit intent rather than a library's side effect.
func GenerateSecret() ([]byte, error) {
	secret := make([]byte, MinSecretLen)
	if _, err := rand.Read(secret); err != nil {
		return nil, fmt.Errorf("csrf: generating secret: %w", err)
	}
	return secret, nil
}

// WithCookieName sets the cookie name.
//
// The default carries the __Host- prefix, which browsers enforce as a
// requirement that the cookie be Secure, Path=/ and Domain-less — the property
// that stops a subdomain from overwriting it. Choosing a name without that
// prefix gives up that protection.
func WithCookieName(name string) Option {
	return func(p *Protector) {
		if name != "" {
			p.cookieName = name
		}
	}
}

// WithFieldName sets the form field consulted on form-encoded submissions.
// The default is [DefaultFieldName].
func WithFieldName(name string) Option {
	return func(p *Protector) {
		if name != "" {
			p.fieldName = name
		}
	}
}

// WithHeaderName sets the request header consulted for the token. The default
// is [DefaultHeaderName], which is what fetch and XHR clients normally send.
func WithHeaderName(name string) Option {
	return func(p *Protector) {
		if name != "" {
			p.headerName = name
		}
	}
}

// WithCookiePath sets the cookie Path attribute. The default is "/".
//
// Narrowing the path also disables the __Host- prefix, since that prefix
// requires Path=/; the cookie name falls back to one without it.
func WithCookiePath(path string) Option {
	return func(p *Protector) {
		if path != "" {
			p.cookiePath = path
		}
	}
}

// WithCookieDomain sets the cookie Domain attribute, which shares the cookie
// with subdomains.
//
// This is a meaningful weakening and is off by default. A cookie scoped to
// example.com is writable by anything running on any subdomain, which is
// exactly the cookie-injection scenario the signed token and the __Host- prefix
// exist to resist. Setting a Domain also disables the __Host- prefix.
func WithCookieDomain(domain string) Option {
	return func(p *Protector) { p.cookieDomain = domain }
}

// WithSameSite sets the cookie SameSite attribute. The default is
// http.SameSiteLaxMode.
//
// http.SameSiteNoneMode requires Secure and permits the cookie on cross-site
// requests, giving up this layer of defense; only use it when a genuine
// cross-site flow needs it. SameSite is defense in depth here — the signed
// token is the actual control — so a relaxation is survivable, but it should
// still be deliberate.
func WithSameSite(mode http.SameSite) Option {
	return func(p *Protector) { p.sameSite = mode }
}

// WithMaxAge sets how long an issued cookie remains valid. The default is
// [DefaultMaxAge]. A non-positive value makes it a session cookie, which lives
// until the browser is closed — a longer life than it appears, given how rarely
// browsers are closed.
func WithMaxAge(d time.Duration) Option {
	return func(p *Protector) { p.maxAge = d }
}

// WithInsecureCookie drops the Secure attribute, so the cookie is sent over
// plain HTTP.
//
// This exists for local development against http://localhost and nothing else.
// In production it lets an active network attacker read and, more importantly,
// *write* the cookie over any plaintext request to your domain, which is the
// cookie-injection case the design works to resist. It also disables the
// __Host- prefix, so the cookie name falls back.
//
// The name says "insecure" so that it is obvious in a diff.
func WithInsecureCookie() Option {
	return func(p *Protector) { p.secure = false }
}

// WithTrustedOrigins replaces the Origin check's default behavior — comparing
// against the request's own Host — with an explicit allow-list.
//
// Each entry is a full origin, scheme included: "https://app.example.com".
// Comparison is exact on scheme, host and port, with the host compared
// case-insensitively.
//
// Use this when requests legitimately arrive from another origin, and when you
// want the scheme pinned rather than ignored (see [Protector.Middleware] on why
// the default cannot check the scheme reliably). An entry that fails to parse
// is kept as given and will simply never match, so a typo shows up as
// rejections rather than as a silently widened allow-list.
func WithTrustedOrigins(origins ...string) Option {
	return func(p *Protector) {
		p.trustedOrigins = make([]string, 0, len(origins))
		for _, o := range origins {
			p.trustedOrigins = append(p.trustedOrigins, strings.ToLower(strings.TrimSuffix(o, "/")))
		}
	}
}

// WithErrorHandler replaces the response written when verification fails.
//
// The default writes 403 with a generic message. A replacement must not tell
// the client *why* verification failed: distinguishing "no cookie" from "bad
// token" from "wrong origin" hands an attacker a debugging aid for their forged
// request. It is also the wrong place to log the token, which is a credential.
//
// A nil handler is ignored.
func WithErrorHandler(h http.Handler) Option {
	return func(p *Protector) {
		if h != nil {
			p.errorHandler = h
		}
	}
}

// Token returns the CSRF token for the request, and whether one is present.
//
// Embed it in every form that performs a state-changing request, and hand it to
// JavaScript clients to send in the [DefaultHeaderName] header.
//
// # Why this returns a bool
//
// The obvious signature returns a bare string, with "" meaning "no token". That
// is a trap. The empty string flows silently into a template, the form renders
// with an empty hidden field, every POST starts failing with 403, and the
// fastest apparent fix is to disable CSRF protection — turning a wiring mistake
// into a security hole. Returning a bool forces the caller to notice that the
// middleware is not in front of this handler.
//
// A token is present on every request that passed through
// [Protector.Middleware], including requests that were rejected, so a handler
// re-rendering a form after a failure still has one.
func Token(r *http.Request) (string, bool) {
	if r == nil {
		return "", false
	}
	token, ok := r.Context().Value(tokenKey).(string)
	if !ok || token == "" {
		return "", false
	}
	return token, true
}

// Middleware enforces CSRF protection.
//
// Requests using a safe method (GET, HEAD, OPTIONS, TRACE) are passed through
// after ensuring a cookie is set and a token is available via [Token]. Safe
// methods are exempt because, by definition, they do not change state — if one
// of yours does, that is the bug to fix, since browsers will preload, prefetch
// and retry them freely.
//
// Every other method must satisfy both checks:
//
//  1. **Origin.** The Origin header is compared against the request's Host, or
//     against [WithTrustedOrigins] if configured. If Origin is absent, Referer
//     is used. If both are absent, the request is rejected: a browser sends one
//     of them on every cross-site state-changing request, so their absence
//     means the request did not come from a page, and a non-browser client that
//     has no cookies has nothing to forge with anyway.
//
//     By default only the host is compared, not the scheme. Behind a
//     TLS-terminating proxy the server sees a plaintext connection while the
//     browser reports an https origin, so a scheme comparison would reject
//     every request in the most common production topology. Pin the scheme with
//     [WithTrustedOrigins] where you can. Comparing against the client-supplied
//     Host header is sound here because an attacker cannot make the victim's
//     browser send a Host and an Origin of their choosing — the browser sets
//     both from the URL being requested.
//
//  2. **Token.** The token is taken from the [DefaultHeaderName] header, or,
//     when the request is form-encoded, from the [DefaultFieldName] form field.
//     It is compared with HMAC-SHA256 of the presented cookie using
//     crypto/hmac.Equal.
//
// # Why the form field is gated on Content-Type
//
// Calling r.FormValue unconditionally makes this middleware parse the body of
// every request it sees, including bodies it was never meant to touch — a JSON
// payload, a raw upload, a gRPC-web frame. That consumes the body before the
// handler gets it and spends memory on parsing that was never wanted. The field
// is consulted only for application/x-www-form-urlencoded and
// multipart/form-data; everything else must use the header.
//
// # Ordering
//
// Place a body-size limit before this middleware. Parsing a form-encoded body
// is exactly the kind of work that must happen only after a bound is in place;
// without one, an attacker sends a form body of arbitrary size and this
// middleware parses it. The preset package fixes this ordering for you.
func (p *Protector) Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		cookieValue, err := p.cookieValue(r)
		if err != nil {
			// No usable cookie: mint one. Doing this even on an unsafe request
			// means the handler that renders the retry page has a working token.
			cookieValue, err = newCookieValue()
			if err != nil {
				// The system CSPRNG failed. There is no safe way to continue.
				p.reject(w, r, "")
				return
			}
			p.setCookie(w, cookieValue)
		}

		token := p.sign(cookieValue)
		r = r.WithContext(context.WithValue(r.Context(), tokenKey, token))

		if isSafeMethod(r.Method) {
			next.ServeHTTP(w, r)
			return
		}
		if !p.originOK(r) {
			p.reject(w, r, token)
			return
		}
		if !p.tokenOK(r, token) {
			p.reject(w, r, token)
			return
		}
		next.ServeHTTP(w, r)
	})
}

// cookieValue returns the raw cookie value, or an error when it is absent or
// malformed. A malformed value is treated as absent so that a corrupted or
// attacker-planted cookie leads to a fresh one rather than a permanent failure.
func (p *Protector) cookieValue(r *http.Request) (string, error) {
	c, err := r.Cookie(p.cookieName)
	if err != nil {
		return "", err
	}
	raw, err := base64.RawURLEncoding.DecodeString(c.Value)
	if err != nil || len(raw) != cookieBytes {
		return "", http.ErrNoCookie
	}
	return c.Value, nil
}

// cookieBytes is the amount of entropy in the cookie. 32 bytes is well beyond
// any feasible guessing attack and matches the HMAC width.
const cookieBytes = 32

// newCookieValue returns a fresh random cookie value.
func newCookieValue() (string, error) {
	raw := make([]byte, cookieBytes)
	if _, err := rand.Read(raw); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(raw), nil
}

// setCookie writes the secret cookie.
//
// HttpOnly is essential: it keeps the cookie out of reach of JavaScript, so
// that the token in the page and the secret in the cookie are not both readable
// from the same place. It is not a defense against XSS — script can still make
// requests that carry the cookie — but it does mean a script cannot simply read
// the cookie and mint tokens offline.
func (p *Protector) setCookie(w http.ResponseWriter, value string) {
	// #nosec G124 -- Secure is true unless the caller explicitly asked for
	// WithInsecureCookie, and SameSite defaults to Lax. gosec sees variables
	// rather than literals here and cannot tell that the defaults are the safe
	// ones; TestCookieOptions asserts them instead.
	c := &http.Cookie{
		Name:     p.cookieName,
		Value:    value,
		Path:     p.cookiePath,
		Domain:   p.cookieDomain,
		HttpOnly: true,
		Secure:   p.secure,
		SameSite: p.sameSite,
	}
	if p.maxAge > 0 {
		c.MaxAge = int(p.maxAge / time.Second)
		c.Expires = time.Now().Add(p.maxAge)
	}
	http.SetCookie(w, c)
}

// sign derives the token for a cookie value.
func (p *Protector) sign(cookieValue string) string {
	mac := hmac.New(sha256.New, p.secret)
	mac.Write([]byte(cookieValue))
	return base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
}

// tokenOK reports whether the request presents the token matching its cookie.
//
// The comparison uses hmac.Equal, which takes the same time whatever the
// inputs. A plain == compares byte by byte and returns as soon as it finds a
// difference, so the time it takes reveals how many leading bytes were correct.
// An attacker who can measure that solves the token one byte at a time —
// hundreds of guesses instead of 2^256. Whether that timing is measurable
// across a real network is debatable; the constant-time comparison costs
// nothing, so there is no version of this trade-off worth taking.
func (p *Protector) tokenOK(r *http.Request, expected string) bool {
	submitted := p.submittedToken(r)
	if submitted == "" {
		return false
	}
	return hmac.Equal([]byte(submitted), []byte(expected))
}

// submittedToken extracts the token from the request, consulting the body only
// when the request is genuinely a form.
func (p *Protector) submittedToken(r *http.Request) string {
	if v := r.Header.Get(p.headerName); v != "" {
		return v
	}
	// Consult the form only for content types that actually are forms. See the
	// Middleware documentation on why parsing anything else is wrong.
	mediaType, _, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
	if err != nil {
		return ""
	}
	switch mediaType {
	case "application/x-www-form-urlencoded":
		if err := r.ParseForm(); err != nil {
			return ""
		}
		return r.PostForm.Get(p.fieldName)
	case "multipart/form-data":
		// The memory this can consume is bounded by whatever body limit
		// precedes this middleware, which is why that ordering is documented as
		// a requirement rather than a suggestion.
		//
		// #nosec G120 -- the bound comes from validate.MaxBodyBytes running
		// earlier in the chain, which gosec cannot see from here. preset.API
		// fixes that order, and TestMiddlewareOrder asserts it.
		if err := r.ParseMultipartForm(defaultMultipartMemory); err != nil {
			return ""
		}
		if r.MultipartForm == nil {
			return ""
		}
		if vs := r.MultipartForm.Value[p.fieldName]; len(vs) > 0 {
			return vs[0]
		}
	}
	return ""
}

// defaultMultipartMemory matches net/http's own default for ParseMultipartForm,
// so that adding this middleware does not change how much of a multipart
// request a handler finds in memory versus spilled to disk.
const defaultMultipartMemory = 32 << 20

// originOK reports whether the request's Origin, or failing that its Referer,
// identifies an acceptable source.
func (p *Protector) originOK(r *http.Request) bool {
	if origin := r.Header.Get("Origin"); origin != "" {
		// "null" is what a sandboxed iframe, a data: URL or a redirected
		// cross-origin request reports. It identifies nothing, so it can never
		// be matched against an expected origin.
		if origin == "null" {
			return false
		}
		return p.originMatches(origin, r.Host)
	}
	if referer := r.Header.Get("Referer"); referer != "" {
		u, err := url.Parse(referer)
		if err != nil || u.Scheme == "" || u.Host == "" {
			return false
		}
		return p.originMatches(u.Scheme+"://"+u.Host, r.Host)
	}
	// Neither header: a browser always sends at least one on a cross-site
	// state-changing request, so this is not a request worth accepting.
	return false
}

// originMatches compares an origin against the allow-list, or against the
// request's own Host header when no allow-list is configured.
//
// See Middleware on why comparing against a client-supplied Host is sound: the
// browser derives both the Host and the Origin from the URL being requested, so
// a cross-site page cannot choose a pair that matches.
func (p *Protector) originMatches(origin, requestHost string) bool {
	u, err := url.Parse(origin)
	if err != nil || u.Host == "" {
		return false
	}
	if len(p.trustedOrigins) > 0 {
		normalized := strings.ToLower(u.Scheme + "://" + u.Host)
		for _, trusted := range p.trustedOrigins {
			if normalized == trusted {
				return true
			}
		}
		return false
	}
	return requestHost != "" && strings.EqualFold(u.Host, requestHost)
}

// reject writes the failure response.
//
// The response is identical whatever went wrong. Telling the client that the
// cookie was missing rather than that the token was invalid gives an attacker
// a progress indicator for their forged request.
func (p *Protector) reject(w http.ResponseWriter, r *http.Request, token string) {
	if p.errorHandler != nil {
		if token != "" {
			r = r.WithContext(context.WithValue(r.Context(), tokenKey, token))
		}
		p.errorHandler.ServeHTTP(w, r)
		return
	}
	http.Error(w, "Forbidden", http.StatusForbidden)
}

// isSafeMethod reports whether a method is defined as not changing state, and
// is therefore exempt from verification.
func isSafeMethod(method string) bool {
	switch method {
	case http.MethodGet, http.MethodHead, http.MethodOptions, http.MethodTrace:
		return true
	}
	return false
}
