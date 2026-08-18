# Design & Architecture

This document is the authoritative design record for the library: what it does,
why each decision was made, which alternatives were rejected, and what is
explicitly out of scope. It exists so that reviewers (and future maintainers)
can audit the reasoning, not just the code — which is the only responsible way
to ship anything security-related.

**Status:** implemented. The design below was written before the code and has
been kept accurate as it was built; §10 records the decisions that were only
forced once there was something to run, including two places where reality
disagreed with the plan.

---

## 1. Goals and non-goals

### Goals

1. **Correct-by-default security primitives** for common web application
   concerns: rate limiting, CSRF, response headers, input validation, and path
   traversal.
2. **Minimum external dependencies.** The core module depends on the Go standard
   library only. This is not purism: for a security library it minimizes
   supply-chain attack surface and keeps the whole implementation auditable in
   one sitting.
3. **Genuinely easy to adopt in someone else's project.** Composability,
   discoverable API, runnable examples, and framework interop are treated as
   first-class requirements, not documentation afterthoughts.

### Non-goals

- Being a WAF, an IDS, or a replacement for defense in depth.
- Session management, authentication, or authorization.
- HTML sanitization for untrusted rich text (see §6.4 — this is a trap, and the
  library deliberately refuses to pretend it solves it).

---

## 2. Module layout

Two Go modules, versioned independently:

```
github.com/JonasBorgesLM/gosecure/
├── go.mod                      module github.com/JonasBorgesLM/gosecure   (stdlib only)
│   ├── doc.go                  package docs only, no code
│   ├── middleware/             Chain — zero sibling imports
│   ├── ratelimit/              token bucket + Store interface
│   ├── csrf/                   signed double-submit cookie
│   ├── secureheaders/          CSP, HSTS, frame options, ...
│   ├── validate/               composable rules + body guards
│   ├── sanitize/               plain-text normalization
│   ├── pathguard/              traversal-safe file access
│   └── preset/                 helmet-style bundles (imports siblings)
│
├── redisstore/
│   └── go.mod                  module .../gosecure/redisstore  (+ go-redis, testcontainers)
│
├── examples/
│   └── go.mod                  module .../gosecure/examples    (+ gin, echo)
│
└── go.work                     local development only, not committed to tags
```

### Why multi-module

Go resolves dependencies **per module, not per package**. If the Redis store
lived in the core module, `github.com/redis/go-redis/v9` would appear in the
core `go.sum`, and supply-chain scanners (Dependabot, `govulncheck`, SBOM
tooling) that read `go.sum` would report the core as depending on Redis even for
consumers that only import `secureheaders`. A separate module makes the
zero-dependency claim literally true and machine-verifiable.

**Cost accepted:** independent version tags (`v1.2.0` for core,
`redisstore/v1.2.0` for the store), and CI must run tests per module —
`go test ./...` at the root does not descend into submodules.

### Why `examples/` is its own module

Framework adapters (Gin, Echo) must be **compiled and tested**, or they rot
silently and become wrong advice — which for a security library is worse than no
advice. Putting them in their own module means they are real, CI-verified code
without leaking `gin`/`echo` into the core `go.sum`.

---

## 3. Core abstractions

### 3.1 The middleware contract

Every middleware is a plain decorator:

```go
func(http.Handler) http.Handler
```

This is `net/http`'s own convention, so it composes with `chi`, `gorilla/mux`,
and anything else that follows it, with no adapters. Frameworks with their own
handler type (Gin, Echo) are supported via thin, documented, compiled adapters
in `examples/` — never by importing those frameworks into the core.

### 3.2 `middleware.Chain`

```go
chain := middleware.New(
    limiter.Middleware,
    secureheaders.Middleware(),
    validate.MaxBodyBytes(1 << 20),
    protector.Middleware,
)
handler := chain.Then(mux)
```

`Chain` exists because deeply nested wrapping is where ordering bugs hide — and
an ordering bug in this library is a security bug, not a style issue (§6.1).
Reading top-to-bottom in declaration order makes the pipeline auditable at a
glance.

`Chain` lives in its own package with **no imports of sibling packages**, so
taking the composition helper does not drag the entire library into the build.

`Chain` is intentionally unopinionated: it does not validate order. Enforcing a
safe order is the job of `preset` (§3.3). `Chain` is the escape hatch for people
who know what they are doing.

### 3.3 `preset` — helmet.js-style bundles

Modeled on `helmet.js`: a batteries-included default that is explicitly
documented as a starting point, with per-component overrides, and with manual
composition remaining the "serious" path.

```go
chain, err := preset.API(preset.Config{
    CSRFSecret:      secret,          // required unless DisableCSRF is set
    RateLimitBurst:  20,
    RateLimitPerSec: 5,
})
```

Two hard rules, both consequences of the audit (§6.2):

1. **`preset.API` returns an `error` and refuses to build a chain with a
   silently missing protection.** Omitting CSRF requires
   `DisableCSRF: true` — a deliberate, greppable, code-reviewable decision
   rather than an accident of leaving a field zero.
2. **`preset` owns middleware ordering.** The safe order is an implementation
   detail of the preset, tested in integration tests.

`preset.Headers()` is the no-parameters-needed subset (response headers only) —
the true analogue of calling `helmet()` bare — and is honest about being only
that.

---

## 4. Component design

### 4.1 `ratelimit`

**Algorithm:** token bucket. Chosen over a fixed-window counter because a fixed
window permits up to 2× the intended rate across a window boundary. Chosen over
a leaky bucket because short bursts are desirable for user-facing APIs.

**Store interface** (revised — see §6.3):

```go
type Result struct {
    Allowed    bool
    Remaining  int
    RetryAfter time.Duration
}

type Store interface {
    Take(ctx context.Context, key string, cfg Config, now time.Time) (Result, error)
    Close() error
}
```

`context.Context` is mandatory for any network-backed store (timeouts,
cancellation, tracing propagation). `error` is mandatory so a backend outage is
distinguishable from a legitimate denial.

**Failure policy:** on store error the middleware **fails closed** (rejects the
request) and invokes an `OnError func(error)` hook. The library never logs or
prints anything itself — hooks let the host application route errors into its
own logger, metrics, and alerting.

> Fail-closed is a deliberate, and debatable, choice. For pure abuse mitigation,
> fail-open is often preferred (availability over enforcement). It is
> configurable via `WithFailureMode`, defaulting to closed, so the safer
> behavior is what you get by forgetting to decide.

**Key function:** defaults to `r.RemoteAddr`, **not** `X-Forwarded-For`, which
is client-controlled and trivially spoofable. Behind a trusted proxy, supply a
`WithKeyFunc` that reads the forwarded header *after* verifying the peer is
actually that proxy. This is documented prominently because getting it wrong
turns rate limiting into a no-op.

**Memory bounds:** `MemoryStore` caps the number of tracked keys and evicts the
least recently used entry past the cap, in addition to TTL-based cleanup. An
unbounded map keyed by client IP is itself a memory-exhaustion vector — a single
host with an IPv6 /64 can mint effectively unlimited distinct addresses (§6.5).

**Response headers:** emits both the widely deployed `X-RateLimit-*` headers and
the standardized `RateLimit-*` form, configurable and disableable — exposing
limit state helps well-behaved clients and marginally helps attackers tune, so
it is a choice, not a default assumption.

### 4.2 `redisstore` (separate module)

Implements `ratelimit.Store` against Redis so that horizontally scaled instances
share one limit.

- **Atomicity via Lua.** Read state, compute refill, decide, write back — all in
  one `EVALSHA` round trip. A read-modify-write from Go would race between
  concurrent requests and let clients exceed the limit. The script lives in a
  standalone `.lua` file embedded with `go:embed`, so it can be linted, read with
  syntax highlighting, and debugged directly with `redis-cli --eval`.
- **TTL in Redis** replaces the in-process janitor.
- **Fail-closed** on connection error or timeout, per §4.1.
- Depends on `github.com/redis/go-redis/v9`, confined to this module.

### 4.3 `csrf`

**Pattern:** signed double-submit cookie. An `HttpOnly` random secret cookie plus
a token derived as `HMAC-SHA256(serverSecret, cookieValue)`, compared with
`hmac.Equal` (constant time). Stateless — no session store, which the library
deliberately does not provide.

Hardening added during the audit (§6.6):

- **Origin/Referer validation** on unsafe methods as defense in depth, per OWASP
  guidance. Double-submit alone is weakened by cookie-injection scenarios
  (subdomain takeover, MITM on a sibling HTTP origin); an origin check closes
  most of that gap.
- **The form-field lookup is gated on `Content-Type`** rather than calling
  `r.FormValue` unconditionally, so the middleware never touches the body of a
  request it was not meant to parse.
- **`Token(r)` returns `(string, bool)`**. A silent empty string flows into a
  template, every POST starts failing, and the fastest "fix" a developer reaches
  for is disabling CSRF. Making absence explicit prevents that failure mode.

Documented limitations: XSS on the same origin defeats CSRF protection entirely;
the HMAC secret must be stable across deploys and rotated deliberately.

### 4.4 `secureheaders`

Sets `Content-Security-Policy`, `Strict-Transport-Security`, `X-Frame-Options`,
`X-Content-Type-Options`, `Referrer-Policy`, and `Permissions-Policy`.

Secure by default: strict CSP, `DENY` framing, one-year HSTS with
`includeSubDomains`. Loosening any of these is an explicit, visible opt-in via
functional options. `preload` is off by default and documented as effectively
irreversible.

### 4.5 `validate` and `sanitize`

Validation and sanitization are kept separate on purpose: a rule answers "is
this acceptable?" and rejects with a reason; it never silently mutates input.
This follows OWASP's preference for allow-list validation over post-hoc
sanitization.

`validate` provides composable `Rule` values (`Required`, `MinLen`, `MaxLen`,
`Email`, `Matches`, `OneOf`, `NoHTMLTags`) plus HTTP guards (`MaxBodyBytes`,
`RequireContentType`).

`sanitize` is scoped to **normalizing text that is expected to be plain**:
stripping control characters (which have been used for log injection and
terminal escape injection), and collapsing whitespace. See §6.4 for what was
removed and why.

### 4.6 `pathguard`

Prevents path traversal when resolving user-supplied paths under a root.

**Primary implementation: `os.Root` (Go 1.24+; this module requires 1.25).** `os.OpenRoot` enforces
containment at the syscall layer, which closes the TOCTOU window that any
resolve-then-open approach leaves open: between `EvalSymlinks` returning a safe
path and the subsequent `os.Open`, an attacker with write access to the tree can
swap a component for a symlink. Manual validation cannot fix this race; the
kernel-level primitive can (§6.7).

The manual `filepath.Rel`-based containment check is retained as a defense-in-
depth pre-check and for path validation that does not open a file.

Also provided: `ResolveNew` for paths that do not exist yet (validating the
parent), since upload destinations are a common real-world need.

---

## 5. Usability requirements

These are treated as requirements, not nice-to-haves.

1. **`middleware.Chain`** for flat, auditable composition (§3.2).
2. **`preset`** for helmet-style adoption in one call, with unsafe omissions
   made impossible-by-accident (§3.3).
3. **Framework adapters** for Gin and Echo, living as compiled, tested code in
   the `examples/` module — not as prose snippets that silently rot.
4. **Testable examples (`ExampleXxx`)** in every public package, rendered on
   pkg.go.dev and compiled by `go test`, so documentation cannot drift from the
   API. Examples that would depend on wall-clock timing or network are written
   as compile-only examples (no `// Output:` line) rather than as flaky tests.
5. **`csrf.GenerateSecret() ([]byte, error)`** to remove first-run friction,
   returning a value — never printing. A library that writes to stdout/stderr is
   unusable in a serious application (§6.8). A `cmd/` helper wraps it for CLI use.
6. **Doc comments carry the threat model**, not just the API shape. For a
   security library, "why" is the load-bearing part of the documentation.

---

## 6. Audit findings and resulting changes

Recorded because the reasoning is the deliverable, and because several of these
were real defects in the first design pass.

### 6.1 Ordering bugs are security bugs (found in the first draft)

The original example wired CSRF **before** the body-size limit. `r.FormValue`
parses a form-encoded body; with no limit in place first, an attacker could have
an oversized body parsed before any bound applied. Fixed by reordering, and
structurally addressed by `Chain` (§3.2) and by `preset` owning the order (§3.3).

### 6.2 `Recommended()` was a naming trap

A preset named "Recommended" that silently omits CSRF and rate limiting —
because those need parameters — invites the reasonable inference that it is the
recommended security posture. Replaced with `preset.API(Config) (Chain, error)`,
which fails loudly rather than shipping a chain missing its most important
protections, and `preset.Headers()` for the genuinely parameter-free subset.

### 6.3 `Store` could not express "the backend is down"

`Take(key, cfg, now) (bool, int)` has no `error` and no `context`. With
fail-closed Redis, an outage would surface as ordinary `429`s, indistinguishable
from real rate limiting, with no signal to operators — and no way to set a
timeout on the Redis call. **This is a breaking interface change and must land
before v1.** Revised signature in §4.1.

### 6.4 Regex-based `StripTags` was security theater

Stripping `<[^>]*>` is trivially bypassable and, worse, its presence in a
*security* library implies it makes input safe to render as HTML. It does not;
the correct XSS defense is contextual output encoding (`html/template`).
Removed. Replaced by `validate.NoHTMLTags()` — reject, don't mangle — which is
honest about being an input-shape constraint rather than an XSS fix.

### 6.5 `MemoryStore` was an unbounded map

Keyed by client address with only TTL-based eviction, memory grows with distinct
sources. Added an LRU-bounded cap (§4.1).

### 6.6 CSRF gaps

Unconditional `r.FormValue`, no Origin/Referer check, and a `Token(r)` that
returns `""` silently. All three addressed in §4.3.

### 6.7 `pathguard` had a TOCTOU window

Resolve-then-open is racy against symlink swaps. Adopted `os.Root` (Go 1.24+) as
the primary mechanism (§4.6). This raises the minimum Go version to 1.24 — an
acceptable trade for closing a real race in the component whose entire job is
containment. The shipped `go.mod` declares **1.25**, one release above the
technical floor, because that is the toolchain the project is developed and
tested against; nothing in the code requires it.

### 6.8 Library-side logging and printing

Any design where the library writes to stdout/stderr or holds its own logger is
rejected. Errors surface through `OnError` hooks and returned values; the host
application owns observability.

### 6.9 Supply-chain hygiene in CI

`go install ...@latest` in CI is non-reproducible and is itself a supply-chain
risk — inappropriate for a security library. All tooling is version-pinned.

### 6.10 Module path naming

`gosecure` is a crowded name in the Go ecosystem, and the community style guide
discourages `go`-prefixed package names. **Verify availability on pkg.go.dev
before the first tag**, since the module path is baked into every consumer's
import and is painful to change afterwards.

---

## 7. Testing strategy

| Layer | Scope | Runs by default |
|---|---|---|
| Unit | Per package, table-driven, attack cases explicitly exercised | yes |
| Examples | `ExampleXxx` compiled and (where deterministic) output-verified | yes |
| Fuzz | `pathguard` containment, `validate` rules, `sanitize` normalization | short seed run in CI |
| Integration A | Full chain over `httptest.Server` with a real cookie-jar client | build tag `integration` |
| Integration B | `redisstore` against real Redis via testcontainers | build tag `integration` |

Integration suites sit behind `//go:build integration` so `go test ./...` stays
fast and infrastructure-free for contributors.

**Fuzzing is a first-class requirement, not decoration.** A property-based fuzz
target asserting "no input ever resolves outside root" is the strongest evidence
`pathguard` can offer, and is far more convincing than a handful of `../../`
test cases.

CI runs, per module: `go vet`, `staticcheck`, `gosec`, `go build`,
`go test -race -cover`, a short fuzz run, and a pinned `govulncheck`.

---

## 8. Versioning and stability

- Ships as **v0.x until the API has been used in anger.** v0 signals that
  breaking changes may occur; claiming v1 prematurely is a promise this project
  is not yet in a position to keep.
- Post-v1, the exported API follows the Go compatibility promise; breaking
  changes require a new major version and module path suffix.
- Each module is tagged independently (`v0.3.0`, `redisstore/v0.3.0`).

---

## 9. Security posture and disclosure

This library is **not independently audited**. It implements well-understood
patterns carefully and documents its reasoning, which is not the same as a
security guarantee. `SECURITY.md` defines private vulnerability reporting;
issues affecting the security properties described here are handled there, not
in public issues.

Threat-model limitations, restated because they matter more than the feature list:

- `ratelimit.MemoryStore` is per-process; without a shared store, each instance
  enforces its own limit.
- CSRF protection is defeated by same-origin XSS.
- `pathguard` constrains filesystem paths; it does not sandbox process behavior.
- None of this substitutes for TLS, secrets management, dependency scanning, or
  least-privilege infrastructure.

---

## 10. Decisions forced by the implementation

Recorded here rather than edited invisibly into the sections above, so that the
difference between what was planned and what shipped stays auditable. Each of
these is covered by a test named in the entry.

### 10.1 `MemoryStore` has no janitor goroutine

§4.2 implies the in-process store needs a background cleaner, contrasted with
Redis expiry. It does not, and shipping one would have been a mistake: a library
that starts a goroutine per store leaks one for every caller who forgets to
`Close`, and "forgets to Close" is the normal case for something created once at
startup.

Instead, entries are held in an LRU recency list, so expired entries accumulate
at the tail and are reclaimed during `Take` in time proportional to the number
actually expired. Memory stays bounded by the key cap either way, and `Close`
becomes optional rather than load-bearing.

### 10.2 An idle bucket is never dropped before it would have refilled

Discovered by a test written against the original design, which then failed:
with a TTL shorter than the refill window, a throttled client could wait out the
TTL, have its bucket discarded, and come back to a full allowance. That is a
rate-limit bypass reachable by doing nothing.

The effective TTL is therefore `max(idleTTL, burst/rate)` in both stores, and a
bucket that never refills is never expired by time at all. See
`TestMemoryStoreDoesNotForgetUnrefilledBuckets` and `TestTTLCoversTheRefillWindow`.

### 10.3 A store outage answers 503, not 429

§6.3 identified that an outage was indistinguishable from throttling. The
`error` on `Store.Take` fixes that for the *operator*, through `OnError`. It
does not fix it for the *client*, which still sees a rejection either way.

Genuine denials answer 429; store failures under `FailClosed` answer 503. The
two are then separable in ordinary request metrics without any custom
instrumentation. See `TestStoreOutageIsNotA429`.

### 10.4 The CSRF cookie uses the `__Host-` prefix by default

§4.3 names cookie injection — subdomain takeover, a plaintext sibling origin —
as the weakness that signing the token exists to mitigate. Browsers offer a
direct control for it: a cookie named `__Host-…` is rejected unless it is
`Secure`, has `Path=/`, and carries no `Domain`, which means no subdomain can
overwrite it.

Using it costs nothing and closes the injection vector at the source rather than
only surviving it. Where the configuration makes the prefix invalid — an
explicitly insecure cookie, a `Domain`, a narrowed `Path` — the name falls back
automatically, because a cookie the browser silently drops would break every
request. See `TestCookieOptions`.

### 10.5 `os.Root` refuses absolute symlinks, including ones pointing inside

Not anticipated in §4.6 and surprising enough to be worth stating: `os.Root`
resolves every component relative to its directory handle, so an absolute
symlink target cannot be interpreted at all — even when it points inside the
root. `/srv/www/current -> /srv/www/v3` fails; `current -> v3` works.

This is a real behavioral constraint for deployments that use absolute symlinks
for release switching, and it is documented in the package rather than left to
be discovered in production. See the `inside-abs` case in `TestOpenAndResolve`.

### 10.6 `preset.API` leaves a 429 without security headers

The order fixed in §3.3 puts the rate limiter outermost, so a rejected request
short-circuits before the header middleware runs. A 429 therefore carries no
CSP, no `nosniff`, and no framing protection.

The ordering is kept, because the reasoning for it — do not spend work on a
request you are going to reject — still holds. But the consequence is a small
real gap, the header middleware is only a handful of map writes, and callers who
care can put `secureheaders` first with a hand-composed `middleware.Chain`. It is
documented on `preset.API` and pinned by a test named for the fact that it is a
documented consequence rather than a desirable one, so that the documentation
cannot quietly drift away from the behavior.

### 10.7 The Redis integration suite cannot live in `integration/`

§7 places both integration suites in one package. It cannot: the Redis suite
needs `testcontainers`, and a test-only dependency is still a dependency — it
lands in the core module's `go.sum` and therefore in every consumer's SBOM,
which is precisely the property §2 exists to protect.

Suite A (full chain over a real TLS server with a real cookie jar) is in
`integration/` and needs only the standard library. Suite B (Redis) is in the
`redisstore` module, behind the same build tag. Both are wired into CI.

### 10.8 `secureheaders` omits HSTS rather than sending `max-age=0`

The two are not equivalent. `max-age=0` instructs a browser to *forget* an
existing HSTS policy for the host, so emitting it on every response actively
tears down protection that earlier responses established. Disabling HSTS
therefore omits the header entirely, and a sub-second `max-age` rounds up to 1
rather than truncating to 0.

### 10.9 The pre-tag workspace needs a versioned replace

`redisstore` and `examples` require the core at `v0.1.0`, which does not resolve
until that tag is pushed. `go.work` therefore carries
`replace github.com/JonasBorgesLM/gosecure v0.1.0 => ./`, which can be dropped
once the tag exists. It lives in the workspace rather than in a module's
`go.mod` because a `replace` in a published `go.mod` is ignored by consumers and
only misleads them. CI recreates the workspace, since `go.work` is not
committed.

### 10.10 The name is as crowded as §6.10 feared

A pkg.go.dev search for `gosecure` returns at least fourteen distinct modules
using that name, none of them related to this one. The module *path*
`github.com/JonasBorgesLM/gosecure` is unclaimed and works, since the path is
namespaced by account. What is crowded is the package name people will type and
search for.

§6.10 asked for this to be verified before the first tag. It has been, and the
answer is unfavorable. Renaming is cheap now and expensive after v0.1.0, since
the module path is baked into every consumer's import.
