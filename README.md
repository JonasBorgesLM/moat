# moat

Composable HTTP security middleware for Go: rate limiting, CSRF protection,
secure response headers, input validation, and path-traversal-safe file access.

**The core module has zero external dependencies** — standard library only.

```go
key, err := csrf.GenerateSecret() // 32 bytes; store it, do not regenerate per process
if err != nil {
    log.Fatal(err)
}

chain, err := preset.API(preset.Config{
    CSRFSecret:      key,
    RateLimitBurst:  20,
    RateLimitPerSec: 5,
})
if err != nil {
    log.Fatal(err)
}

http.ListenAndServe(":8080", chain.Then(mux))
```

> **Status: pre-1.0.** The API may change between minor versions. This library
> has not been independently audited — see [Security](#security).

---

## Why this exists

Most Go security middleware either pulls in a large third-party stack or is
copy-pasted from a forum answer without much thought for the edge cases:
symlink-based traversal, IP-spoofed rate-limit bypass, timing attacks on token
comparison, unbounded body reads, TOCTOU races.

This project does that plumbing carefully and **writes down the reasoning**, so
it can be inspected rather than trusted — which is what you should do with any
security library, including this one. The full design record, including the
audit that reshaped several of these APIs, is in
[`doc/DESIGN.md`](./doc/DESIGN.md).

## Design principles

- **Zero external dependencies in the core.** Minimizes supply-chain attack
  surface and keeps the implementation auditable in one sitting. The optional
  Redis backend lives in a *separate module*, so it never appears in your
  `go.sum` unless you ask for it.
- **Secure by default, opt out explicitly.** Strict CSP, `DENY` framing,
  `Secure` cookies, fail-closed rate limiting. Loosening a default is visible in
  code review; forgetting to configure something leaves you on the safe path.
- **Fail loudly rather than silently degrade.** A preset that cannot build a
  safe chain returns an error instead of quietly omitting a protection.
- **`func(http.Handler) http.Handler` everywhere.** Plain decorators — works
  with `net/http`, `chi`, `gorilla/mux` out of the box, and with Gin/Echo via
  small adapters (compiled and tested, in [`examples/`](./examples)).
- **Allow-list over block-list.** Reject input that doesn't match a known-good
  shape rather than trying to strip what looks dangerous.
- **The library never logs or prints.** Errors surface through hooks and return
  values; your application owns observability.

## Install

```sh
go get github.com/JonasBorgesLM/moat
```

Optional Redis-backed distributed rate limiting (separate module, pulls in
`go-redis`):

```sh
go get github.com/JonasBorgesLM/moat/redisstore
```

The core module requires **Go 1.24+** — the floor set by `os.Root`, which
`pathguard` is built on and which landed in 1.24. The core has no external
dependencies, so nothing pushes it higher.

The `redisstore` module declares **Go 1.26.6**, and that one is a security floor
rather than a dependency floor: it reaches `crypto/tls` and `encoding/asn1`,
which carry [GO-2026-6090](https://pkg.go.dev/vuln/GO-2026-6090) and
[GO-2026-5972](https://pkg.go.dev/vuln/GO-2026-5972), fixed in 1.25.13 and
1.26.6. It is declared in the `go` directive rather than `toolchain`, because a
`toolchain` line in a dependency is ignored by whoever imports it — see
[`redisstore/README.md`](./redisstore/README.md) for why 1.25.13 would not have
done the job. `examples/` declares 1.25, forced there by `gin`.

Neither floor affects you unless you import those modules. The core is unchanged
at 1.24.

## Packages

| Package | What it does |
|---|---|
| `middleware` | `Chain` — flat, order-explicit middleware composition |
| `preset` | helmet.js-style bundles for one-call adoption |
| `ratelimit` | Token bucket rate limiting, pluggable storage backend |
| `csrf` | Stateless CSRF protection (signed double-submit cookie + Origin check) |
| `secureheaders` | CSP, HSTS, `X-Frame-Options`, `nosniff`, Referrer-Policy, Permissions-Policy |
| `validate` | Composable field rules + body size / content-type guards |
| `sanitize` | Plain-text normalization (control chars, whitespace) |
| `pathguard` | Traversal- and TOCTOU-safe file resolution and serving |
| `realip` | Client IP behind trusted proxies, parsed right-to-left |
| `secret` | `Value` — bytes that cannot be printed, logged or marshalled by accident |
| [`redisstore`](./redisstore/README.md) *(separate module)* | Redis-backed `ratelimit.Store`, atomic via Lua |

Every package is independently importable — take only what you need.

---

## Usage

### Quick start with a preset

Presets are the fastest safe starting point, in the spirit of `helmet.js`:
opinionated defaults, per-component overrides, and no pretense of being a
complete security strategy.

```go
raw, err := base64.StdEncoding.DecodeString(os.Getenv("CSRF_SECRET"))
if err != nil {
    log.Fatal(err)
}
key := secret.New(raw) // wrap it so it cannot reach a log line

chain, err := preset.API(preset.Config{
    CSRFSecret:      key, // a secret.Value of 32 or more random bytes
    RateLimitBurst:  20,
    RateLimitPerSec: 5,
    TrustedProxies:  []string{"10.0.0.0/8"}, // your balancer, or DirectlyExposed: true
})
```

The order `preset.API` fixes is: security headers, rate limit, body size limit,
CSRF. Headers run outermost so that every response carries them, including a
`429` from the rate limiter or a `403` from CSRF — an error response is still a
response, and is exactly as capable of being framed or rendered without a CSP
as a `200` is. The body limit must precede CSRF because CSRF parses
form-encoded bodies, and doing that before a bound is in place is the ordering
bug that makes an oversized form a problem.

`preset.API` **returns an error** rather than build a chain whose protections
are missing or ambiguous — a missing CSRF secret, missing rate limits, or a rate
limiter that has not been told where the client address comes from. It is not a
general guarantee that nothing can be misconfigured; it is a list of the cases
that are checked, and it grew by one after `TrustedProxies` was found missing
from it.

`TrustedProxies` is required whenever rate limiting is on, because a limiter is
only as good as the identity it counts. Behind a load balancer `r.RemoteAddr` is
the balancer for every client, so without this the whole service shares one
bucket and any single client can hold everyone else at the limit — a denial of
service that looks exactly like ordinary throttling. If nothing fronts the
server, say so instead:

```go
chain, err := preset.API(preset.Config{
    CSRFSecret:      key,
    RateLimitBurst:  20,
    RateLimitPerSec: 5,
    DirectlyExposed: true, // no proxy in front; RemoteAddr is the client
})
```

Skipping CSRF is possible, but only by saying so:

```go
chain, err := preset.API(preset.Config{
    DisableCSRF:     true, // deliberate, greppable, reviewable
    RateLimitBurst:  20,
    RateLimitPerSec: 5,
})
```

Headers-only, the true parameter-free subset:

```go
handler := preset.Headers().Then(mux)
```

### Explicit composition

When you want to own the pipeline, compose it flat and in order. Nested wrapping
is where ordering bugs hide — and an ordering bug here is a security bug, not a
style issue:

```go
chain := middleware.New(
    secureheaders.Middleware(),       // 1. outermost, so every response gets these — even the rejections below
    limiter.Middleware,               // 2. turn away abusive clients before spending more work
    validate.MaxBodyBytes(1<<20),     // 3. BEFORE anything that reads the body
    protector.Middleware,             // 4. CSRF can now read a bounded body
)
handler := chain.Then(mux)
```

`Chain` does not enforce order — that is `preset`'s job. `Chain` is the escape
hatch for people who know what they're doing.

### Rate limiting

```go
limiter := ratelimit.New(20, 5) // burst of 20, refills at 5 tokens/sec
handler := limiter.Middleware(mux)
```

Token bucket, not a fixed window — a fixed window allows up to 2× the intended
rate across a boundary.

The default key function uses `r.RemoteAddr`, **not** `X-Forwarded-For`. That
header is client-controlled and trivially spoofable; trusting it blindly turns
rate limiting into a no-op.

`RemoteAddr` is not a safe default either, only a safe-*failing* one: behind a
proxy it is the proxy for every client, so all clients share one bucket. Both
directions are wrong, which is why `preset.API` refuses to guess. Constructing a
limiter directly, use `realip` to derive the key:

```go
extractor, err := realip.New([]string{"10.0.0.0/8"}) // your proxies, not your clients
if err != nil {
    log.Fatal(err)
}
limiter := ratelimit.New(20, 5, ratelimit.WithKeyFunc(extractor.KeyFunc()))
```

Distributed limiting across instances:

```go
store, err := redisstore.New(redisClient)
limiter := ratelimit.New(20, 5, ratelimit.WithStore(store))
```

The Redis store is atomic (Lua, single round trip) and **fails closed** by
default: if Redis is unreachable, requests are rejected rather than waved
through. Switch with `ratelimit.WithFailureMode(ratelimit.FailOpen)` if
availability matters more than enforcement for your use case.

The limiter is also callable directly, for the identity you only know *after*
authenticating — an account, an API key, a tenant — which the middleware cannot
derive from the request:

```go
if !limiter.Allow(r.Context(), account.ID) {
    writeError(w, http.StatusTooManyRequests, "rate limit exceeded")
    return
}
```

`AllowN` charges a weighted cost, so an expensive operation can pay more than a
cheap one. The deduction is all-or-nothing and atomic — including on Redis,
where the cost goes into the same Lua call rather than a loop:

```go
if !limiter.AllowN(r.Context(), account.ID, report.Cost()) { ... }
```

Both apply the configured failure mode and report store errors to `WithOnError`.
Use `Take`/`TakeN` instead when you want the `Result` and the error and intend to
decide yourself. The middleware is a thin consumer of the same code path, so an
in-handler call and a middleware call charge one bucket, not two.

### CSRF

```go
protector, err := csrf.New(key) // a secret.Value; 32+ random bytes, stable across deploys
handler := protector.Middleware(mux)

// in a handler rendering a form:
token, ok := csrf.Token(r)
```

Stateless signed double-submit cookie — no session store required — with
Origin/Referer validation as defense in depth. The cookie is `HttpOnly`,
`Secure`, `SameSite=Lax`, and carries the `__Host-` prefix, which browsers
enforce as "Secure, `Path=/`, no `Domain`" — so no subdomain can overwrite it. `Token` returns
`(string, bool)` rather than a silent empty string: an empty token silently
breaking every POST is exactly the situation that gets CSRF disabled "to fix it".

Rotate the token when the session's privilege level changes — on login above
all. An attacker who managed to plant a CSRF cookie in the victim's browser can
compute the matching token; rotating overwrites the planted value, so the
victim's browser starts sending one the attacker never saw:

```go
if _, err := protector.Rotate(w, r); err != nil {
    // The CSPRNG failed. Abort the login rather than completing it with a
    // possibly attacker-known token still valid.
    return
}
```

`csrf.Token(r)` reports the new token immediately afterwards, so a handler that
logs the user in and then renders a page stays correct.

Call it **before writing anything to the response** — it sets a cookie, and
net/http discards a `Set-Cookie` added after the headers are sent. That mistake
is detected rather than left to bite you: a late call returns
`csrf.ErrHeadersAlreadySent` and changes nothing, instead of reporting success
while the browser keeps the old cookie.

Note what it does *not* do: it rotates the CSRF secret, not your session
identifier. Defeating session fixation also requires issuing a new session ID at
login, which is your session layer's job.

Need a secret to get started?

```go
key, err := csrf.GenerateSecret() // a secret.Value; never prints it
```

It returns a `secret.Value`, not a `[]byte`, and `csrf.New` and
`preset.Config.CSRFSecret` take one too. The wrapper is there because a signing
key in a plain `[]byte` is one `%+v` away from a log aggregator — and a `Config`
struct is exactly the kind of thing that gets logged at startup. Printing,
marshalling or `slog`-ing a `Value` yields `[REDACTED]`; the bytes come out only
through an explicit `.Bytes()` call that a reviewer can see. Wrap bytes from your
own secret store with `secret.New`.

Or from a shell, where printing is your explicit intent rather than a library's
side effect:

```sh
go run github.com/JonasBorgesLM/moat/cmd/moat-secret
```

### Secure headers

```go
handler := secureheaders.Middleware(
    secureheaders.WithCSP("default-src 'self' https://cdn.example.com"),
)(mux)
```

Defaults: `X-Frame-Options: DENY`, `nosniff`, one-year HSTS with
`includeSubDomains`, `Referrer-Policy: strict-origin-when-cross-origin`, a
locked-down `Permissions-Policy`, and this CSP:

```
default-src 'self'; base-uri 'self'; form-action 'self'; frame-ancestors 'none'; object-src 'none'
```

The last three directives are there because none of them inherits from
`default-src`: dropping them silently removes clickjacking, `<base>`-hijacking
and form-exfiltration protection. Keep them when you relax the policy.

HSTS `preload` is off by default — it is effectively irreversible. Setting
`max-age` to 0 omits the header rather than sending `max-age=0`, which would
instruct browsers to *forget* an existing policy.

Real pages have inline scripts, and the strict default CSP forbids them. The
usual escape is `'unsafe-inline'`, which permits *every* inline script including
an injected one — that is not a weaker CSP, it is no script policy at all. Use a
per-request nonce instead:

```go
headers := secureheaders.Middleware(secureheaders.WithNonce())

// in the handler
nonce, ok := secureheaders.Nonce(r)   // (string, bool), like csrf.Token
```

```html
<script nonce="{{.Nonce}}"> ... </script>
```

`WithNonce` **adds** `script-src` if the policy lacks it, so the default CSP goes
from "scripts may be same-origin" to "scripts must carry this request's nonce".
That is stricter, and it means `<script src="/app.js">` needs the attribute too.
If the CSPRNG fails the request is rejected rather than served with a policy that
blocks its own scripts; customize that response with `WithNonceErrorHandler`.

For responses carrying a credential — an OAuth token endpoint, a session
bootstrap — mark them uncacheable. RFC 6749 §5.1 requires it:

```go
mux.Handle("POST /token", secureheaders.NoStore(tokenHandler))
```

It is a per-route function rather than a `Middleware` option on purpose:
`no-store` across a whole chain would also stop your static assets from being
cached.

On logout, ask the browser to discard what it already has — ending the session
server-side does not empty localStorage or the back-button cache:

```go
mux.Handle("POST /logout", secureheaders.ClearSiteData()(logoutHandler))
```

Defense in depth only: the header is ignored on plaintext origins and support is
uneven, so it never replaces server-side invalidation. Note that `"cookies"`
clears the whole registrable domain, so logging out of `app.example.com` also
clears `shop.example.com`.

**COOP, CORP and COEP are available but off by default:**

```go
secureheaders.Middleware(
    secureheaders.WithCrossOriginOpenerPolicy(secureheaders.COOPSameOriginAllowPopups),
    secureheaders.WithCrossOriginResourcePolicy(secureheaders.CORPSameOrigin),
)
```

They are opt-in because each breaks in a way your server cannot see — it keeps
returning 200 while the browser discards the response. COOP `same-origin` breaks
popup OAuth; CORP `same-origin` breaks any asset meant to be embedded
cross-origin; COEP `require-corp` breaks essentially every third-party
subresource and is only worth it if you need `SharedArrayBuffer`.

None of them becomes a default in v0.2.0. If `COOPSameOriginAllowPopups` or
`CORPSameOrigin` is ever promoted it will be announced in the changelog as a
behaviour change. COEP will never be a default.

### Validation and sanitization

```go
err := validate.Validate("email", input.Email,
    validate.Required(),
    validate.Email(),
    validate.MaxLen(254),
)

clean := sanitize.PlainText(input.DisplayName)
```

`sanitize` is **not** an HTML sanitizer and deliberately does not pretend to be
one. The correct XSS defense is contextual output encoding — `html/template`
does this for you. For fields that must never contain markup, reject rather than
mangle: `validate.NoHTMLTags()`.

A URL that a user supplies and you later render into an `href` needs its scheme
constrained, or it is a script-execution primitive:

```go
validate.URL()                    // http and https
validate.URL("https")             // https only
```

`html/template` will not save you here — inside an `href`, `javascript:alert(1)`
is a *valid* URL, not something to escape. The rule also rejects control
characters before parsing, because a browser strips `\t`, `\n` and `\r` from a
URL before reading its scheme: `java\tscript:` navigates as `javascript:` while
Go's `net/url` sees a different scheme entirely. That is the standard bypass for
scheme allow-lists. Scheme-relative `//evil.example.com` is rejected too.

It does **not** check the host, so it is not on its own an open-redirect or SSRF
defense — compare the parsed host against your own allow-list for those.

### Path traversal

```go
guard, err := pathguard.New("./public")
handler := http.StripPrefix("/files/", guard.FileServer())
```

Built on `os.Root`, which enforces containment at the syscall layer.
This closes the TOCTOU window that resolve-then-open approaches leave open: an
attacker who can write into the tree can swap a path component for a symlink
between validation and the actual open. Manual checks cannot win that race.

### Framework adapters

`net/http`, `chi`, and `gorilla/mux` work with no adapter. Gin and Echo need a
few lines of glue — provided as **compiled, tested code** in
[`examples/`](./examples), not as snippets that rot:

- [`examples/gin`](./examples/gin)
- [`examples/echo`](./examples/echo)
- [`examples/basic`](./examples/basic) — plain `net/http`, all middleware wired

---

## Testing

This is a multi-module repository, and `go test ./...` at the root **does not**
descend into `redisstore/` or `examples/`. Test each module:

```sh
go test -race ./...                 # core: unit tests + examples, no infra needed
(cd redisstore && go test -race ./...)
(cd examples   && go test -race ./...)
```

Integration suites sit behind a build tag so the default run stays fast and
needs no Docker:

```sh
go test -tags=integration -race ./integration/...   # full chain over a real TLS server
(cd redisstore && go test -tags=integration -race ./...)  # real Redis, via testcontainers
```

The Redis suite lives in the `redisstore` module rather than alongside the
others, because `testcontainers` is a dependency and a test-only dependency in
the core module would still land in every consumer's `go.sum`.

```sh
go test -fuzz=FuzzResolve -fuzztime=60s ./pathguard  # property: nothing escapes the root
```
 Fuzz targets are treated as a security control, not
decoration: "no input ever resolves outside root" is a stronger claim than any
handful of `../../` test cases.

## Security

**This library has not been independently audited.** It implements
well-understood patterns carefully and documents its reasoning; that is not a
guarantee.

Report vulnerabilities privately per [`SECURITY.md`](./SECURITY.md) — not in
public issues.

Known limitations, stated up front because they matter more than the feature
list:

- `ratelimit.MemoryStore` is per-process. Behind a load balancer, each instance
  enforces its own limit unless you use a shared store.
- CSRF protection is defeated by same-origin XSS. If an attacker can run JS on
  your origin, they can read the token.
- `pathguard` constrains filesystem paths; it does not sandbox process behavior.
- None of this replaces TLS, secrets management, dependency scanning, or
  least-privilege infrastructure.

## Contributing

See [`CONTRIBUTING.md`](./CONTRIBUTING.md). Changes affecting security
properties need a matching update to [`doc/DESIGN.md`](./doc/DESIGN.md) — the
reasoning is part of the deliverable.

## License

MIT — see [LICENSE](./LICENSE).
