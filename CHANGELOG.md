# Changelog

All notable changes to this project are documented here.

The reasoning behind each change lives in `doc/DESIGN.md`; this file is the
migration list. Sections marked **BREAKING** require a source or configuration
change to upgrade.

This project is pre-1.0. Breaking changes may occur in a minor release, which is
what v0 signals — see `doc/DESIGN.md` §8.

The two modules are tagged independently and their versions have already
diverged, so this file is split by module rather than kept as one timeline. A
`redisstore` entry and a core entry that sit next to each other are not
necessarily related, and reading them as one sequence is how a reader concludes
that `redisstore/v0.2.1` supersedes the core's `v0.2.0`. It does not; it requires
it. The mapping lives in `redisstore/README.md`.

---

# Core — `github.com/JonasBorgesLM/moat`

## Unreleased

### Requirements — action may be needed

- **The `go` directive is now `1.27.2`** (it was `1.24`, with a `toolchain
  go1.26.6` line that consumers ignore). Building this module now requires Go
  1.27.2 or newer: under the default `GOTOOLCHAIN=auto` an older toolchain
  upgrades itself, under `GOTOOLCHAIN=local` the build fails with a clear
  message.

  This is a security floor. govulncheck reports the core reaching
  GO-2026-6617, -6613, -6612, -6611 and -6603 in `net/http`, and GO-2026-6604
  in `os.Root`, which is `pathguard`'s containment mechanism. All are fixed in
  1.26.9 and 1.27.2. It is 1.27.2 because a 1.26.9 floor is satisfied by 1.27.0
  and 1.27.1, which carry none of the fixes. `os.Root`'s 1.24 is still the
  technical floor; `doc/DESIGN.md` §6.18 records why the declared one is now
  higher.

### Other

- `realip` gains three runnable examples (`ExampleNew`,
  `ExampleExtractor_KeyFunc`, `ExampleNew_viaPreset`). It was the package with no
  indexed example on pkg.go.dev, which is a poor place for that gap given it is
  the answer to the shared-bucket rate-limit finding.
- Example code no longer names a local variable after an imported package
  (`examples/basic`). Added to the review checklist in `CONTRIBUTING.md`.
- Private vulnerability reporting enabled on the repository, so the channel
  `SECURITY.md` documents is actually usable by a third-party reporter.
- CI gains `released-satellites`, which builds, vets and tests each satellite
  module with `GOWORK=off` against the core version its `go.mod` names. This is
  the mechanism that would have caught the `redisstore/v0.2.0` break before it
  was tagged; `CONTRIBUTING.md` now also fixes the release order that keeps it
  green. See `doc/DESIGN.md` §6.0 and §6.16.

## v0.2.0

`redisstore/v0.2.0` was tagged on the same commit, and broken — see the
`redisstore` section below. Tagging the two in lockstep is what this project
stopped doing as a result; `CONTRIBUTING.md` now specifies the order.

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
  on a go1.24 toolchain and produces no `go.sum`. This has not changed since, and
  the `redisstore` toolchain floor does not propagate to it.

## v0.1.0

Initial release.

---

# `redisstore` — `github.com/JonasBorgesLM/moat/redisstore`

Requires the core module. Which version of it, per release, is in
`redisstore/README.md`; the numbers on the two modules do not track each other.

## redisstore/Unreleased

### Requirements — action may be needed

- **The `go` directive is now `1.27.2`** (it was `1.26.6`). Same reason as
  `v0.2.2`'s raise, with new IDs: GO-2026-6607 in `crypto/tls`, and
  GO-2026-6617, -6613, -6612, -6611 and -6603 in `net/http`. All are fixed in
  1.26.9 and 1.27.2, and 1.27.2 because a 1.26.9 floor admits 1.27.0 and
  1.27.1.

## redisstore/v0.2.2

### Requirements — action may be needed

- **The `go` directive is now `1.26.6`** (it was `1.25.0`, with a `toolchain
  go1.26.6` line that consumers ignore). Building this module now requires Go
  1.26.6 or newer: under the default `GOTOOLCHAIN=auto` an older toolchain
  upgrades itself, under `GOTOOLCHAIN=local` the build fails with a clear
  message.

  This is a security floor, not a language-feature one. The module reaches
  `crypto/tls` via go-redis and `encoding/asn1` via certificate parsing, which
  carry [GO-2026-6090](https://pkg.go.dev/vuln/GO-2026-6090) and
  [GO-2026-5972](https://pkg.go.dev/vuln/GO-2026-5972). Up to `v0.2.1` the floor
  was declared only in `toolchain`, which protected this repository's CI and no
  consumer's build.

  It is 1.26.6 rather than 1.25.13, though both carry the fixes: Go orders
  versions across release lines, so a floor of 1.25.13 is satisfied by 1.26.5,
  which has neither fix.

  The core module is unaffected and still requires only Go 1.24.

### Added

- **`Store.EvictionCheck() EvictionCheck`** reports what the construction-time
  eviction check actually established. Previously a check that was *skipped* —
  `CONFIG` disabled or renamed, the server unreachable, a client that cannot
  issue `CONFIG`, an unparsable reply — was indistinguishable from one that
  passed: `New` returned a Store and no error either way.

  This matters because the skip cases are the normal case on ElastiCache,
  MemoryDB, Upstash and Azure Cache, which is where most production deployments
  run. The check tended to fire in local Docker and stay silent in production.

  Nothing about the check's behaviour changed and no call site needs updating.
  What is new is being able to ask:

  ```go
  if check := store.EvictionCheck(); !check.Verified() {
      log.Printf("redisstore: eviction policy unverified (%s)", check)
  }
  ```

  The doc comment also now records two gaps a *verified* result does not close:
  it is a snapshot of mutable server state taken once at construction, and in
  cluster mode only the masters reachable at that moment are asked — so a policy
  changed during a memory incident, or a replica promoted by failover, is not
  covered.

- `redisstore/README.md`, carrying the core-version compatibility table and the
  toolchain floor.

### Fixed — security

- **`github.com/moby/go-archive` bumped `v0.2.0` → `v0.3.0`** for
  [GHSA-hfg8-hc9c-6c3h](https://github.com/advisories/GHSA-hfg8-hc9c-6c3h)
  (CVE-2026-17106, **high**): a crafted tar archive can write outside the
  extraction directory. It reaches this module transitively through
  `testcontainers-go`, which is used only by the integration suite.

  **`redisstore/v0.2.1` and earlier carry the vulnerable version.** What that
  does and does not mean for you, measured against the published tag from a
  clean directory rather than reasoned about:

  | Question | v0.2.1 consumer |
  |---|---|
  | Is `go-archive` in your `go.sum`? | **Yes** — both the `h1:` and `/go.mod` hashes |
  | Is it in your module graph (`go list -m all`)? | **Yes** |
  | Is any of its code in your build (`go list -deps`)? | **No** |
  | Does `govulncheck` report it? | **No — "No vulnerabilities found"** |

  So this is **not** runtime exposure: the vulnerable code is never compiled into
  a consumer's binary, and there is no attack path through `redisstore` to a tar
  extraction. It is real anyway for a different reason. Dependency scanners —
  Dependabot, Snyk, `dependency-review-action` with `fail-on-severity` — read the
  module graph, not the reachability analysis. Every consumer of `v0.2.1`
  therefore inherits a **high** alert on their own repository that they cannot
  clear without upgrading, because the requirement lives in *our* `go.mod`.

  Handing downstream projects an unactionable high alert is a real cost even when
  no binary is affected, and a path-traversal advisory sitting unactioned in a
  library that ships `pathguard` is not a defensible look. **Upgrade to
  `redisstore/v0.2.2`.** No retract: `v0.2.1` compiles, runs, and is not
  exploitable — retracting it would be the wrong instrument.

  Found by Dependabot alerts within minutes of enabling them, on a repository
  that had been running without them since its first commit. That is the argument
  for having had them on, and it is recorded here rather than quietly fixed.

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

> **Superseded.** This version requires `github.com/moby/go-archive v0.2.0`,
> which carries CVE-2026-17106 (high). It is not exploitable through this module
> and `govulncheck` reports nothing, but it will raise a high alert in your own
> dependency scanner. See the `redisstore/v0.2.2` entry above; upgrading is the
> only way to clear it.

## redisstore/v0.1.0

Initial release, tagged alongside the core's `v0.1.0` and requiring it. Verified
after the fact from a clean directory against the module proxy: it compiles and
`*Store` satisfies `ratelimit.Store`. It was correct by coincidence rather than
by verification — nothing in the pipeline resolved the core outside the
workspace until `e7c8801` — which is why it was re-checked rather than assumed.
No retract is needed.
