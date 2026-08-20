# Changelog

All notable changes to this project are documented here.

The reasoning behind each change lives in `doc/DESIGN.md`; this file is the
migration list. Sections marked **BREAKING** require a source or configuration
change to upgrade.

This project is pre-1.0. Breaking changes may occur in a minor release, which is
what v0 signals — see `doc/DESIGN.md` §8.

## Unreleased

- Example code no longer names a local variable after an imported package
  (`examples/basic`). Added to the review checklist in `CONTRIBUTING.md`.
- Private vulnerability reporting enabled on the repository, so the channel
  `SECURITY.md` documents is actually usable by a third-party reporter.

## redisstore/v0.2.1

**`redisstore/v0.2.0` is retracted. Upgrade to v0.2.1.**

`redisstore/v0.2.0` was published with `go.mod` still requiring the core module
at `v0.1.0`, whose `ratelimit.Store` interface declares `Take` rather than
`TakeN`. Resolved fresh from the module proxy, `*redisstore.Store` therefore did
not satisfy `ratelimit.Store` and the module did not compile:

```
cannot use (*Store)(nil) as ratelimit.Store value: missing method Take
```

Nothing local could see it: the development workspace lists all three modules
under `use`, so `redisstore` resolved the core against the working tree and the
stale `require` was never exercised. It was caught by fetching the published tag
into a clean directory outside the repository and running real code against it.

v0.2.1 requires the core at `v0.2.0` and carries a `retract v0.2.0` directive.
The core module's own `v0.2.0` tag is unaffected and needs no reissue.

## v0.2.0

Modules: `github.com/JonasBorgesLM/moat` and
`github.com/JonasBorgesLM/moat/redisstore`, tagged together.

### BREAKING — source changes required

**Secrets are `secret.Value`, not `[]byte`.** A new `secret` package holds byte
secrets so that a struct dumped with `%+v`, marshalled into a startup log line,
or passed to `slog.Any` cannot carry the signing key with it.

| Before (v0.1.0) | After (v0.2.0) |
|---|---|
| `csrf.New(secret []byte, ...)` | `csrf.New(key secret.Value, ...)` |
| `csrf.GenerateSecret() ([]byte, error)` | `csrf.GenerateSecret() (secret.Value, error)` |
| `preset.Config.CSRFSecret []byte` | `preset.Config.CSRFSecret secret.Value` |

```go
// before
key, _ := csrf.GenerateSecret()
protector, _ := csrf.New(key)

// after — GenerateSecret already returns a secret.Value
key, _ := csrf.GenerateSecret()
protector, _ := csrf.New(key)

// after — bytes from your own secret store
protector, _ := csrf.New(secret.New(rawBytes))
```

**`ratelimit.Store.Take` is now `Store.TakeN`.** The interface method carries a
token count so that an expensive operation can cost more than a cheap one.
Anyone who *implements* `ratelimit.Store` must rename the method and accept `n`;
anyone who only *calls* the limiter is unaffected — `Limiter.Take` and
`Limiter.Allow` still exist and are unchanged.

```go
// before
Take(ctx context.Context, key string, cfg Config, now time.Time) (Result, error)

// after
TakeN(ctx context.Context, key string, n int, cfg Config, now time.Time) (Result, error)
```

All `n` are taken or none are, `n` below 1 is treated as 1, and `n` above
`cfg.Burst` is a denial rather than an error. `redisstore.Store` implements the
new method; if you use it through `ratelimit.WithStore`, no change is needed.

**`validate.RequireContentType` takes a slice.** The media types moved into a
slice so the function could grow an options parameter, which is what carries the
new error handler.

```go
// before
validate.RequireContentType("application/json")

// after
validate.RequireContentType([]string{"application/json"})
validate.RequireContentType([]string{"application/json"},
    validate.WithContentTypeErrorHandler(myHandler))
```

**`validate.MaxBodyBytes` and `pathguard.Guard.FileServer` gained variadic
options.** Existing call sites compile unchanged; listed only because the
signatures differ.

### BREAKING — configuration changes required

**`preset.API` now requires you to state your proxy topology** when rate
limiting is enabled. A v0.1.0 config that compiles will return
`preset.ErrProxyTopologyUnspecified` at startup until it names one of:

```go
TrustedProxies:  []string{"10.0.0.0/8"}, // the balancer in front of you
// or
DirectlyExposed: true,                    // nothing is in front of you
```

This is not a new knob for its own sake. Without it the limiter fell back to
`r.RemoteAddr`, which behind a load balancer is the balancer's address for every
client — so the whole service shared one rate-limit bucket and any single client
could hold every other user at the limit indefinitely. Setting `TrustedProxies`
wires the new `realip` package in as the limiter's key function. Setting both
fields is contradictory and is an error.

**`redisstore.New` can now fail on an unsafe server configuration.** It performs
one `CONFIG GET maxmemory*` and returns `redisstore.ErrUnsafeEvictionPolicy` if
the server reports a memory ceiling together with any `maxmemory-policy` other
than `noeviction` — eviction discards rate-limit state and resets limits. The
check is best-effort and silently skipped when it cannot be established (managed
Redis usually disables `CONFIG`). Override with `redisstore.InsecureAllowKeyEviction()`.

**`csrf.WithTrustedOrigins` rejects an empty list** with
`csrf.ErrNoTrustedOrigins` instead of silently falling back to host-only
matching. `WithTrustedOrigins(cfg.AllowedOrigins...)` against an unset
environment variable used to lose scheme pinning without saying so. If you want
host matching, do not pass the option.

**`realip.New` rejects the default route.** `0.0.0.0/0` and `::/0` return
`realip.ErrDefaultRouteTrusted`, because trusting them makes every client a
trusted proxy. Override with `realip.InsecureTrustEveryPeer()`.

### BREAKING — wire format

**CSRF tokens changed shape.** A token is now
`base64(pad || hmac^pad)` with a fresh 32-byte pad per response — 86 characters
instead of 43 — so that the same token is never byte-identical across two
responses. An unmasked token was a constant for the life of the cookie, which is
the precondition for BREACH extraction from a compressed response.

No API changed: `csrf.Token(r)` and `Protector.Rotate` return the new form and
verification accepts it. **But a form rendered before the upgrade carries an old
token that the upgraded server will refuse.** During a rolling deploy those POSTs
get one 403 and succeed on retry; tokens are ephemeral, so it self-heals. Plan
for it in the release window rather than being surprised by it.

### Added

- **`secret`** — byte secrets that cannot escape through formatting,
  serialization, or logging. Every fmt verb, `encoding/json`, `encoding.TextMarshaler`
  and `log/slog` write `[REDACTED]`.
- **`realip`** — derives a client address from forwarding headers, right to left,
  only when the peer is a trusted proxy. `Extractor.KeyFunc` plugs straight into
  `ratelimit.WithKeyFunc`.
- `ratelimit`: `Limiter.TakeN`, `Limiter.AllowN`, `Limiter.Allow`.
- `secureheaders`: `NoStore`, `ClearSiteData`, CSP nonces (`WithNonce`,
  `Nonce(r)`, `WithNonceErrorHandler`), and the cross-origin isolation options
  (`WithCrossOriginOpenerPolicy`, `WithCrossOriginResourcePolicy`,
  `WithCrossOriginEmbedderPolicy`).
- `csrf`: `Protector.Rotate` for privilege changes, with `ErrHeadersAlreadySent`
  when called after the response has begun.
- Replaceable rejection responses across the library:
  `validate.WithMaxBodyErrorHandler`, `validate.WithContentTypeErrorHandler`,
  `pathguard.WithNotFoundHandler`, `pathguard.WithMethodNotAllowedHandler`,
  `secureheaders.WithNonceErrorHandler`.
- `validate.URL(schemes ...string)` to restrict accepted URL schemes.

### Fixed — security

- **`ratelimit.MemoryStore` eviction granted a limit reset.** Eviction dropped
  the least recently used bucket, which is the bucket of a client that has just
  been throttled — so pressure on the key cap handed a throttled client a fresh
  full burst. Buckets are now ordered by how refilled they are and the most
  refilled is dropped, which in the ordinary case grants nothing.
- **`secret`'s mask was one shared, repeating pad.** One known plaintext
  recovered the keystream for every other value in the process, and a secret
  longer than the pad repeated it. The keystream is now derived per value.
- **`secureheaders` wrote its own rejection with no security headers.** The
  nonce-failure 500 skipped the header set, contradicting the package's contract
  that every response carries them.
- **`secret`'s CSPRNG fallback was fail-open**, masking every value under a
  publicly derivable pad if it ever ran. It now panics.
- Standard-library vulnerabilities reachable from `redisstore` (GO-2026-6090,
  GO-2026-5972) closed by building on go1.26.6.

### Requirements

- The core module still requires **Go 1.24** and still depends on the standard
  library only — verified by building a consumer that imports all nine packages
  on a go1.24 toolchain and produces no `go.sum`.
- `redisstore` requires Go 1.25.

## v0.1.0

Initial release.
