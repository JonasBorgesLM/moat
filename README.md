# moat

Composable HTTP security middleware for Go: rate limiting, CSRF protection,
secure response headers, input validation, and path-traversal-safe file access.

**The core module has zero external dependencies** — standard library only.

```go
secret, err := csrf.GenerateSecret() // 32 bytes; store it, do not regenerate per process
if err != nil {
    log.Fatal(err)
}

chain, err := preset.API(preset.Config{
    CSRFSecret:      secret,
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

Requires **Go 1.25+**. (`pathguard` needs `os.Root`, which landed in 1.24; the
modules declare 1.25, the toolchain the project is developed and tested against.)

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
| `redisstore` *(separate module)* | Redis-backed `ratelimit.Store`, atomic via Lua |

Every package is independently importable — take only what you need.

---

## Usage

### Quick start with a preset

Presets are the fastest safe starting point, in the spirit of `helmet.js`:
opinionated defaults, per-component overrides, and no pretense of being a
complete security strategy.

```go
secret, err := base64.StdEncoding.DecodeString(os.Getenv("CSRF_SECRET"))
if err != nil {
    log.Fatal(err)
}

chain, err := preset.API(preset.Config{
    CSRFSecret:      secret, // []byte, 32 or more random bytes
    RateLimitBurst:  20,
    RateLimitPerSec: 5,
})
```

The order `preset.API` fixes is: security headers, rate limit, body size limit,
CSRF. Headers run outermost so that every response carries them, including a
`429` from the rate limiter or a `403` from CSRF — an error response is still a
response, and is exactly as capable of being framed or rendered without a CSP
as a `200` is. The body limit must precede CSRF because CSRF parses
form-encoded bodies, and doing that before a bound is in place is the ordering
bug that makes an oversized form a problem.

`preset.API` **returns an error** if a protection would be silently missing.
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
rate limiting into a no-op. Behind a trusted proxy, supply a key function *after*
verifying the peer really is that proxy:

```go
limiter := ratelimit.New(20, 5, ratelimit.WithKeyFunc(myTrustedProxyKeyFunc))
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

### CSRF

```go
protector, err := csrf.New(secret) // 32+ random bytes, stable across deploys
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

Need a secret to get started?

```go
secret, err := csrf.GenerateSecret() // returns the value; never prints it
```

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
