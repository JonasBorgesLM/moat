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
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"mime"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/JonasBorgesLM/moat/secret"
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
	DefaultCookieName = "__Host-moat.csrf"
	DefaultFieldName  = "moat.csrf"
	DefaultHeaderName = "X-CSRF-Token"

	// fallbackCookieName is used when the configuration makes the __Host-
	// prefix invalid, since a browser would otherwise silently drop the cookie.
	fallbackCookieName = "moat.csrf"
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

// tokenHolder is what actually goes in the context, rather than the token
// string itself.
//
// The indirection exists so that [Protector.Rotate] can replace the token for a
// request that is already in flight. If the context held a plain string, a
// handler that rotated on login and then called [Token] would receive the token
// from *before* the rotation, render it into the page, and every subsequent
// POST would be rejected — reintroducing by another route exactly the silent
// staleness that Token's (string, bool) signature exists to prevent.
//
// The mutex is not ceremony: a handler may hand the request to goroutines, and
// then Rotate and Token can genuinely run concurrently.
type tokenHolder struct {
	mu    sync.RWMutex
	token string
}

func (h *tokenHolder) get() string {
	h.mu.RLock()
	defer h.mu.RUnlock()
	return h.token
}

func (h *tokenHolder) set(token string) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.token = token
}

// Protector issues and verifies CSRF tokens.
//
// It is safe for concurrent use and is intended to be created once at startup
// and shared. The zero value is not usable; create one with [New].
type Protector struct {
	secret []byte

	// optErr carries a problem found while applying options, so that [New] can
	// report it. Options cannot return an error themselves.
	optErr error

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
// key must be at least [MinSecretLen] bytes of cryptographically random data,
// and must be identical across every instance of your application and stable
// across deploys. Generate one with [GenerateSecret], store it wherever you
// keep other secrets, and load it at startup.
//
// Do not generate a fresh secret per process. Every token issued by one process
// is then rejected by every other, producing intermittent 403s that look like a
// bug in this library and get "fixed" by disabling CSRF protection.
//
// The secret is a [secret.Value] rather than a []byte so that it cannot reach a
// log through an accidental Printf or a marshalled config struct. Load one from
// your secret store with [secret.New], or generate one with [GenerateSecret].
func New(key secret.Value, opts ...Option) (*Protector, error) {
	if key.Len() < MinSecretLen {
		return nil, fmt.Errorf("%w (got %d)", ErrSecretTooShort, key.Len())
	}

	p := &Protector{
		secret:     key.Bytes(),
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
	if p.optErr != nil {
		return nil, p.optErr
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
// for [New], wrapped in a [secret.Value].
//
// It returns the value and never prints it. A library that writes a secret to
// stdout is unusable in a real application: the value lands in CI logs, in
// container logs, and in whatever aggregates them. The [secret.Value] wrapper
// extends that guarantee past this function: the result cannot be printed,
// marshalled or logged by accident either, and the raw bytes come out only
// through an explicit Bytes call.
//
// The cmd/moat-secret helper wraps this for command-line use, where
// printing is the caller's explicit intent rather than a library's side effect.
func GenerateSecret() (secret.Value, error) {
	b := make([]byte, MinSecretLen)
	if _, err := rand.Read(b); err != nil {
		return secret.Value{}, fmt.Errorf("csrf: generating secret: %w", err)
	}
	return secret.New(b), nil
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
		trusted := make([]string, 0, len(origins))
		for _, o := range origins {
			if o = strings.TrimSpace(o); o == "" {
				continue
			}
			trusted = append(trusted, strings.ToLower(strings.TrimSuffix(o, "/")))
		}
		if len(trusted) == 0 {
			// Recorded rather than ignored: silently keeping the Host-matching
			// default is the failure this refuses. See [ErrNoTrustedOrigins].
			p.optErr = ErrNoTrustedOrigins
			return
		}
		p.trustedOrigins = trusted
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
	holder, ok := r.Context().Value(tokenKey).(*tokenHolder)
	if !ok || holder == nil {
		return "", false
	}
	token := holder.get()
	if token == "" {
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
//     It is unmasked (see [maskToken]) and the recovered value is compared with
//     HMAC-SHA256 of the presented cookie using crypto/hmac.Equal.
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
	return http.HandlerFunc(func(rw http.ResponseWriter, r *http.Request) {
		// Wrapped so that [Protector.Rotate] can detect being called after the
		// response has begun, instead of writing a Set-Cookie that net/http
		// silently drops. See responseRecorder.
		w := &responseRecorder{ResponseWriter: rw}

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

		expected := p.sign(cookieValue)
		token, err := maskToken(expected)
		if err != nil {
			// The system CSPRNG failed. There is no safe way to continue.
			p.reject(w, r, "")
			return
		}
		r = r.WithContext(context.WithValue(r.Context(), tokenKey, &tokenHolder{token: token}))

		if isSafeMethod(r.Method) {
			next.ServeHTTP(w, r)
			return
		}
		if !p.originOK(r) {
			p.reject(w, r, token)
			return
		}
		if !p.tokenOK(r, expected) {
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
	// Strict for the same reason as [unmaskToken]: one value, one encoding.
	raw, err := base64.RawURLEncoding.Strict().DecodeString(c.Value)
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

// sign derives the raw MAC for a cookie value. It is never handed out directly;
// see [maskToken] for why.
func (p *Protector) sign(cookieValue string) []byte {
	mac := hmac.New(sha256.New, p.secret)
	mac.Write([]byte(cookieValue))
	return mac.Sum(nil)
}

// maskedTokenBytes is the wire length of an issued token: a random pad followed
// by the MAC XOR that pad.
const maskedTokenBytes = 2 * sha256.Size

// maskToken wraps a raw MAC in a fresh one-time pad, so that the token a page
// carries is different on every response.
//
// # Why the token cannot be sent as-is
//
// The MAC is a pure function of the cookie, so an unmasked token is byte
// identical in every response for the lifetime of that cookie. That is the
// precondition for BREACH: an application that serves compressed HTML and
// reflects any attacker-influenced string into the same response — a search
// term, a username, an echoed error, a ?utm_ parameter — becomes an adaptive
// compression oracle. The attacker submits guesses, a correct prefix compresses
// shorter, and the token falls out byte by byte. With it, every request the
// victim's browser can be made to issue is forgeable until the cookie rotates,
// which it does only on an explicit [Protector.Rotate].
//
// Masking removes the precondition rather than the compression: two responses
// carrying the same underlying MAC share no bytes, so there is nothing for the
// oracle to converge on. This is the same construction gorilla/csrf uses, and
// the parity matters — a reviewer comparing the two should not find this one
// weaker at the point it claims to have handled carefully.
//
// Only the token needs this. The cookie is HttpOnly and never appears in a
// compressed response body.
func maskToken(raw []byte) (string, error) {
	out := make([]byte, maskedTokenBytes)
	pad := out[:sha256.Size]
	if _, err := rand.Read(pad); err != nil {
		return "", err
	}
	// XORBytes rather than an indexed loop: it writes exactly
	// min(len(raw), len(pad)) bytes into a destination it has checked, so the
	// bounds are provable here instead of resting on sign always returning
	// sha256.Size bytes.
	subtle.XORBytes(out[sha256.Size:], raw, pad)
	return base64.RawURLEncoding.EncodeToString(out), nil
}

// unmaskToken recovers the raw MAC from a submitted token.
//
// Everything it inspects — the encoding, the length, the pad — comes from the
// request, so no branch here depends on the secret and none of it is a timing
// side channel on anything the attacker does not already know. The
// constant-time comparison happens afterwards, on the recovered bytes.
func unmaskToken(token string) ([]byte, bool) {
	// Strict, so that a token has exactly one valid encoding. Go's default
	// base64 decoder ignores the unused trailing bits of the final character:
	// 64 bytes occupy 86 base64url characters, of which the last carries four
	// significant bits and two that are discarded. Without Strict, two distinct
	// strings decode to the same token and mutating that character is a no-op
	// about a quarter of the time — which is not a vulnerability, since the
	// attacker still has to know the MAC, but it does mean "the token I sent is
	// not the token that was issued" and "the request is refused" stop being the
	// same statement. Canonical encoding keeps them the same.
	decoded, err := base64.RawURLEncoding.Strict().DecodeString(token)
	if err != nil || len(decoded) != maskedTokenBytes {
		return nil, false
	}
	pad, masked := decoded[:sha256.Size], decoded[sha256.Size:]
	raw := make([]byte, sha256.Size)
	subtle.XORBytes(raw, masked, pad)
	return raw, true
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
func (p *Protector) tokenOK(r *http.Request, expected []byte) bool {
	submitted := p.submittedToken(r)
	if submitted == "" {
		return false
	}
	// Unmask first: the presented token carries a per-response pad, so two
	// encodings of the same MAC share no bytes and comparing them directly
	// would reject every valid request. See [maskToken].
	raw, ok := unmaskToken(submitted)
	if !ok {
		return false
	}
	return hmac.Equal(raw, expected)
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
			r = r.WithContext(context.WithValue(r.Context(), tokenKey, &tokenHolder{token: token}))
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

// Rotate replaces the CSRF cookie in the client's browser with a fresh random
// value and returns the token that matches it.
//
// # Call this at every privilege change
//
// Session fixation applied to CSRF: an attacker who can plant a cookie in the
// victim's browser — through a subdomain they control, a network position on a
// plaintext sibling origin, or any other cookie-injection route — knows the
// cookie value and can therefore compute the token that goes with it. If that
// cookie survives the victim logging in, the attacker holds a token that
// matches what the victim's browser will send, and a forged request from the
// victim's browser verifies.
//
// Rotating on login breaks that. The Set-Cookie overwrites the planted value,
// so from that point the victim's browser sends a cookie the attacker never
// saw, and the token they precomputed no longer matches it. Call it immediately
// after authenticating, and again on anything else that changes what the
// session may do — assuming another user, elevating to an admin mode,
// completing a second factor.
//
// # What rotation is not
//
// It is not server-side revocation, and it cannot be. This scheme is stateless
// by design (§4.3): a token is `HMAC(serverSecret, cookieValue)` and is verified
// by recomputation, so there is no list of issued tokens to strike anything
// from. An old cookie paired with its old token still verifies if something
// presents both.
//
// That is not the attack. A CSRF attack needs the *victim's browser* to send
// the credential-bearing cookie, and after rotation the victim's browser holds
// the new value. An attacker who kept the old pair can present it only from
// their own browser, carrying their own session, which achieves nothing.
//
// If you need to revoke tokens across the board — a compromised server secret,
// for instance — rotate the secret passed to [New] and redeploy. That
// invalidates every token everywhere, at the cost of one rejection for every
// user with a form already open.
//
// # It does not rotate your session identifier
//
// This is the limitation most likely to be misread, because calling Rotate at
// login looks like it handles session fixation. It does not. It rotates the
// **CSRF** secret and nothing else. Classic session fixation — an attacker
// fixing the victim's *session* cookie before login and then riding the
// authenticated session — is defeated by issuing a new session identifier at
// the privilege change, which is your session layer's job and which this
// package has no access to.
//
// Rotate closes the CSRF half. Rotating the session ID closes the other half.
// A login that does only one of the two is still vulnerable to the other, and
// doing only this one is the easier mistake to make.
//
// The __Host- cookie prefix (see [WithCookieName]) already blocks the most
// common injection route by stopping a subdomain from overwriting the cookie.
// Rotation is the defence for the cases the prefix does not cover, and the two
// are complementary rather than alternatives.
//
// # Ordering, and how a mistake is reported
//
// Rotate writes a Set-Cookie header, so it must be called before anything is
// written to w — before WriteHeader, before the first Write, and before any
// redirect. Afterwards, net/http has already serialized the header block and
// discards the cookie without complaint.
//
// That failure is detected rather than merely documented. The middleware wraps
// the ResponseWriter to note when the response begins, and a late Rotate
// returns [ErrHeadersAlreadySent] and changes nothing, instead of reporting
// success while leaving the old cookie in place. Check the error.
//
// Detection needs the middleware's wrapper to be reachable from the w you pass.
// It is found through the [http.ResponseWriter] Unwrap convention, so
// intervening middleware that follows that convention does not hide it. If no
// wrapper is found — Rotate called on a route outside the protected chain —
// rotation still happens; only the late-call check is unavailable, because a
// safety net must not be able to disable the thing it guards.
//
// A request that already carries a valid cookie receives exactly one
// Set-Cookie. A request that arrived without one and passed through
// [Protector.Middleware] receives two — the middleware minted one before the
// handler ran, and Rotate replaced it. Both name the same cookie and the last
// wins, so the result is correct; it is mentioned only because it is visible
// when reading the raw response.
//
// # It updates the token for this request too
//
// After Rotate returns, [Token] on the same request reports the new token, so a
// handler that logs the user in and then renders a page does not have to thread
// the return value through its template data to stay correct. The return value
// is there for convenience, not because ignoring it is a bug.
//
// # Errors
//
// A non-nil error means the system CSPRNG failed and no new secret could be
// generated. The old cookie is left in place and unchanged. Abort the privilege
// change rather than continuing: proceeding would complete a login while
// leaving a possibly attacker-known token valid, which is the exact state
// rotation exists to leave behind.
//
// Rotate does not require the request to have passed through
// [Protector.Middleware], so it can be used on a login route that is mounted
// outside the protected chain. When it has, the context is updated in place.
func (p *Protector) Rotate(w http.ResponseWriter, r *http.Request) (string, error) {
	if w == nil || r == nil {
		return "", ErrNoToken
	}
	// Checked before anything is generated or written: once the response has
	// begun, the Set-Cookie below would be discarded by net/http and the caller
	// would be told it had rotated when it had not.
	if rr := findRecorder(w); rr != nil && rr.wroteHeader.Load() {
		return "", ErrHeadersAlreadySent
	}

	cookieValue, err := newCookieValue()
	if err != nil {
		return "", fmt.Errorf("csrf: rotating token: %w", err)
	}
	p.setCookie(w, cookieValue)
	token, err := maskToken(p.sign(cookieValue))
	if err != nil {
		return "", fmt.Errorf("csrf: rotating token: %w", err)
	}

	// Update the in-flight request so a later Token call cannot hand back the
	// pre-rotation value. When the request never went through the middleware
	// there is no holder, and the caller uses the return value.
	if holder, ok := r.Context().Value(tokenKey).(*tokenHolder); ok && holder != nil {
		holder.set(token)
	}
	return token, nil
}

// ErrHeadersAlreadySent reports that [Protector.Rotate] was called after the
// response had already begun, so the new cookie could not be set.
//
// It exists because the alternative is silent. Once a handler has called
// WriteHeader — or written a single byte, which calls it implicitly — net/http
// has already serialized the header block, and any Set-Cookie added afterwards
// is discarded without complaint. The handler would go on believing it had
// rotated, the browser would keep the old cookie, and the fixation that
// rotation exists to close would still be open. Failing loudly turns that into
// a bug you find in testing.
//
// Recover by rotating earlier in the handler, before anything is written.
var ErrHeadersAlreadySent = errors.New("csrf: response headers already sent; Rotate must be called before writing the response")

// ErrNoTrustedOrigins reports that [WithTrustedOrigins] was given no usable
// origin.
//
// An empty list is refused rather than quietly meaning "keep the default",
// because the overwhelmingly likely cause is an unset environment variable
// feeding a slice — `WithTrustedOrigins(cfg.AllowedOrigins...)` where the config
// never loaded. Accepting it would leave the operator believing that scheme and
// host are pinned while verification had silently reverted to matching the
// request's own Host: the scheme is then unpinned and any sibling subdomain
// restriction is gone.
//
// This mirrors realip.ErrNoTrustedProxies, which refuses the same input shape
// for the same reason. If you want the Host-based default, do not pass the
// option at all — that is what it means.
var ErrNoTrustedOrigins = errors.New("csrf: WithTrustedOrigins was given no usable origin")

// responseRecorder notes whether the response has begun.
//
// It records rather than intercepts: every method delegates, and the only extra
// behaviour is a flag. WriteHeader sets it directly; Write sets it too, because
// the first Write triggers an implicit WriteHeader(200) and is just as final.
//
// The flag is atomic because a handler may write from one goroutine while
// another calls Rotate — the same concurrency the token holder is protected
// against, and the race detector finds it in exactly the same way.
type responseRecorder struct {
	http.ResponseWriter
	wroteHeader atomic.Bool
}

func (rr *responseRecorder) WriteHeader(statusCode int) {
	rr.wroteHeader.Store(true)
	rr.ResponseWriter.WriteHeader(statusCode)
}

func (rr *responseRecorder) Write(b []byte) (int, error) {
	rr.wroteHeader.Store(true)
	return rr.ResponseWriter.Write(b)
}

// Unwrap exposes the underlying ResponseWriter to [http.ResponseController].
//
// Wrapping a ResponseWriter otherwise hides whatever optional interfaces the
// real one implements, so a handler further down that needs to flush a stream
// or hijack the connection would find those capabilities gone. ResponseController
// follows Unwrap to reach them, so Flush, Hijack, SetReadDeadline and the rest
// keep working through this middleware:
//
//	rc := http.NewResponseController(w)
//	if err := rc.Flush(); err != nil { ... }
//
// Note the limitation this does not remove: a *direct* type assertion such as
// w.(http.Flusher) does not follow Unwrap and will not match this wrapper. That
// is the assertion http.ResponseController was introduced to replace, and code
// behind this middleware should use the controller instead.
func (rr *responseRecorder) Unwrap() http.ResponseWriter { return rr.ResponseWriter }

// findRecorder walks the Unwrap chain looking for this package's recorder.
//
// The handler does not necessarily hold the recorder directly: middleware
// mounted between this one and the handler may have wrapped it again. Walking
// the chain finds it through those wrappers, provided they follow the same
// Unwrap convention. If none is found, rotation proceeds without the check —
// the detection is a safety net, and its absence must not disable rotation.
//
// The walk is bounded so that a wrapper whose Unwrap returns a cycle cannot
// hang the request.
func findRecorder(w http.ResponseWriter) *responseRecorder {
	for range 16 {
		if rr, ok := w.(*responseRecorder); ok {
			return rr
		}
		u, ok := w.(interface{ Unwrap() http.ResponseWriter })
		if !ok {
			return nil
		}
		next := u.Unwrap()
		if next == nil || next == w {
			return nil
		}
		w = next
	}
	return nil
}
