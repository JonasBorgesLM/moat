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
github.com/JonasBorgesLM/moat/
├── go.mod                      module github.com/JonasBorgesLM/moat   (stdlib only)
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
│   └── go.mod                  module .../moat/redisstore  (+ go-redis, testcontainers)
│
├── examples/
│   └── go.mod                  module .../moat/examples    (+ gin, echo)
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

### Why there is no `moat/jwtauth` — a decision, not an omission

**Decided: not extracting. Deferred until the criterion below is met.** This is
recorded so that the question is not reopened from scratch every time someone
notices JWT validation is missing from a library that otherwise covers the
request edge.

The criterion for extracting anything into this repository is that **the
signature has stabilized under real use**, measured two ways: how many times it
changed over the consumer's last few iterations, and whether a second consumer
besides the originating one has informed the design. A shape that is still moving
is a shape nobody has finished learning, and publishing it converts every
remaining lesson into a breaking change.

`jwtauth` fails that criterion by a wide margin, and not marginally on one leg of
it — it has no measurements at all. The authentication gateway that would be its
first consumer is still in requirements and has no code. The local
`pkg/tokenvalidator` that was supposed to accumulate the usage experience does
not exist either, so there is no signature to have stabilized and no change count
to take. Extracting now would mean designing a library against an imagined
consumer, which is precisely what the original plan refused to do — and doing it
for token validation, where getting the shape wrong is not merely awkward.

**Re-evaluate when, and only when:** the gateway has a validator in real use;
its signature has gone some meaningful stretch of that consumer's iterations
without changing; and there is either a second consumer or a concrete reason to
believe the first one's needs generalize. Until all three hold, the answer here
stays no, and the absence of a `moat/jwtauth` is the plan working rather than
something left undone.

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
    secureheaders.Middleware(),
    limiter.Middleware,
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
2. **`preset` owns middleware ordering.** The order is fixed inside `API`
   rather than left to the caller, and is covered by tests:

   1. `secureheaders`, outermost, so that every response carries the security
      headers — including a rejection written by any middleware that follows.
      An error response is still a response, and is a well-known injection
      surface in its own right; losing `nosniff` or the CSP on it specifically
      is not a place to save a handful of map writes (§10.6).
   2. `ratelimit`, so that an abusive client is turned away before anything
      further downstream spends work on it.
   3. `validate.MaxBodyBytes`, before anything reads or parses a body.
   4. `csrf`, which may parse a form-encoded body — and can now only ever
      parse a bounded one, because the size limit runs first (§6.1).

`preset.Headers()` is the no-parameters-needed subset (response headers only) —
the true analogue of calling `helmet()` bare — and is honest about being only
that.

### 3.4 Invariant: every middleware that can reject a request exposes a customizable handler

**Any middleware in this library that can refuse a request must let the
application replace the response it writes.**

The reason is not aesthetic. An application publishes one error contract — say
the `{"error": ...}` envelope in its `openapi.yaml` — and clients are written
against it. A middleware that answers with `net/http`'s `text/plain` breaks that
contract on exactly the routes where a protection fired, which is to say on the
routes where the client most needs a parseable answer. Worse, it breaks it
*inconsistently*: the same client gets the documented shape from every handler
and an undocumented one from the rate limiter, so the failure looks like a bug
in the client's own error handling.

Three rules follow, and each has cost a real inconsistency here:

1. **Every rejection point, not every middleware.** A component with two ways to
   say no needs two handlers. `pathguard.FileServer` had a 404 and a 405;
   exposing only the 404 would have swapped one inconsistency for another inside
   a single handler.
2. **Distinct causes get distinct handlers when the status differs.**
   `ratelimit` separates `WithDeniedHandler` (429) from `WithStoreErrorHandler`
   (503) because answering an outage with 429 makes it indistinguishable from
   real throttling. Merging them would be a monitoring failure, not just a
   formatting one.
3. **Customizable does not mean informative.** A replacement inherits the
   original's discretion. `pathguard`'s 404 stays identical across every cause
   or it becomes a filesystem-mapping oracle again (§4.6); `csrf`'s 403 must not
   say *why* verification failed. The doc comment on each option states what the
   replacement must not reveal.

#### The audit against this invariant — closed

Every response-writing site in the library was swept (`http.Error`,
`http.NotFound`, `WriteHeader`, `Redirect`, `w.Write`), and re-swept after the
hooks landed and after `secureheaders` gained a rejection point of its own.

**Status: closed for all known cases.** Every rejection point in the eleven core
packages routes through an unexported `write*` helper that dispatches to a
configurable handler and falls back to the built-in response, and every option
follows the same convention: `func(h http.Handler) Option`, nil ignored.

| Package | Rejection points | Hook | Origin |
|---|---|---|---|
| `ratelimit` | 429 denial | `WithDeniedHandler` | pre-existing |
| `ratelimit` | 503 store outage | `WithStoreErrorHandler` | pre-existing |
| `csrf` | 403 verification failure | `WithErrorHandler` | pre-existing |
| `pathguard` | 404, all causes | `WithNotFoundHandler` | **found by the audit** |
| `pathguard` | 405 wrong method | `WithMethodNotAllowedHandler` | **found by the audit** |
| `validate` | 415 content type | `WithContentTypeErrorHandler` | **found by the audit** |
| `validate` | 413 declared length | `WithMaxBodyErrorHandler` | **found by the audit** |
| `secureheaders` | 500 CSPRNG failure | `WithNonceErrorHandler` | added with the feature (§4.4) |
| `sanitize`, `middleware`, `realip`, `secret` | none | — | never refuse a request |
| `preset` | none of its own | passes `HeaderOptions`, `CSRFOptions`, `RateLimitOptions` and `BodyLimitOptions` through | **`BodyLimitOptions` found by the coherence sweep** |
| `redisstore` | none | — | not an HTTP component |

The two the audit found are the ones worth remembering, because both were
*second* rejection points in a component that already had one and therefore
looked covered from a distance: `pathguard`'s 405 sat behind its 404, and
`validate`'s 413 header pre-check sat behind its `MaxBytesReader` path. The
lesson encoded in rule 1 above — every rejection *point*, not every middleware —
came from these two.

`secureheaders` is the invariant working prospectively rather than
retroactively: CSP nonces introduced the package's first-ever rejection point,
and it shipped with its hook rather than acquiring one in a later audit.

#### The invariant has a second layer: `preset`

A hook that exists on a package but cannot be reached through `preset` satisfies
the letter of the invariant and defeats its purpose. `preset` exists for
one-call adoption, and one-call adoption must not cost the caller something that
wiring the packages by hand would have given them.

A sweep of what `preset.API` actually wires found exactly one gap. It composes
four middlewares:

| Wired | Hook | Reachable via |
|---|---|---|
| `secureheaders.Middleware` | `WithNonceErrorHandler` | `HeaderOptions` |
| `ratelimit.New` | `WithDeniedHandler`, `WithStoreErrorHandler` | `RateLimitOptions` |
| `validate.MaxBodyBytes` | `WithMaxBodyErrorHandler` | **was unreachable** — `BodyLimitOptions` added |
| `csrf.New` | `WithErrorHandler` | `CSRFOptions` |

The consequence of the gap was precise and exactly the thing §3.4 exists to
prevent: an application with a JSON error envelope got that envelope from the
rate limiter, the store-outage path and the CSRF check, and `text/plain` from
the 413 — one inconsistent route out of four, introduced by the very component
whose job is coherent adoption.

`pathguard.FileServer` and `validate.RequireContentType` are not wired by any
preset, so their hooks have nothing to be reachable *through*; that is absence,
not a gap.

`TestEveryRejectionHookIsReachableThroughThePreset` drives all four rejections
through a preset-built chain and requires the caller's envelope on each, so this
layer cannot silently regress. Verified by removal: dropping the passthrough
fails it on the 413.

#### The one place the invariant is satisfied by two mechanisms

`validate.MaxBodyBytes` refuses an oversized request in two places, and only one
of them can be an Option:

- The **declared** `Content-Length` is over the limit. The middleware answers
  itself, so `WithMaxBodyErrorHandler` covers it.
- The client **lied or declared nothing**. Nothing is known until the body is
  read, and by then the middleware has returned. The failure surfaces as a
  `*http.MaxBytesError` from the handler's `Read`, and is mapped downstream with
  `errors.As`.

Making the second path write its own response was rejected: a middleware that is
no longer on the stack would be racing a handler that may already have sent
headers. Deleting the first path's response instead — letting the header check
merely shorten the body so the reader always fires — was also rejected, because
it gives up refusing an oversized upload *before* reading it, which is the whole
point of checking the header.

So the invariant is met by two mechanisms with one *observable result*, and the
distinction matters enough to state precisely: the two paths do **not** pass
through the same configured handler, and cannot. The reader path surfaces after
the middleware has returned from the stack, so there is nothing left to dispatch
to. What is identical is what the client sees, and only if the adopter wires
both — which is why the doc comment presents them as one two-part task rather
than as an option plus a footnote, and why `ExampleMaxBodyBytes` shows both
producing byte-identical output.

`TestWithMaxBodyErrorHandlerDoesNotCoverTheReaderPath` pins the boundary so the
documentation cannot drift into claiming the stronger, false version.

A note on what the header check is *not*: it only ever rejects. The
`MaxBytesReader` wrap is unconditional and always uses the configured limit,
never the declared length, so a small declared `Content-Length` cannot skip it.
Making that wrap conditional would turn the optimization into a bypass —
`TestMaxBodyBytesWrapsTheReaderEvenWhenTheDeclaredLengthPasses` guards it.

#### Cost accepted

`validate.RequireContentType` changed from `(mediaTypes ...string)` to
`(mediaTypes []string, opts ...ContentTypeOption)`. The variadic was already
spent on the media types, so options could not be appended without it. Source
break, taken deliberately under the pre-1.0 policy (§8); the call sites were
tests and examples only.

`validate` uses two option types, `BodyLimitOption` and `ContentTypeOption`,
rather than one package-wide `Option`. With a single type, passing a
content-type option to `MaxBodyBytes` would compile and silently do nothing —
precisely the class of quiet misconfiguration this library refuses elsewhere.
`pathguard` has one option type because it has one constructor that takes them.

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
    TakeN(ctx context.Context, key string, n int, cfg Config, now time.Time) (Result, error)
    Close() error
}
```

`context.Context` is mandatory for any network-backed store (timeouts,
cancellation, tracing propagation). `error` is mandatory so a backend outage is
distinguishable from a legitimate denial.

**Why the interface method is `TakeN` and not `Take`.** Weighted cost cannot be
built on top of a single-token primitive. Calling `Take` n times is exactly the
read-modify-write interleaving the Lua script exists to prevent, and it also
admits a *partial* deduction: a caller charged for three of five tokens and then
denied has paid for work it was not allowed to do. So the count has to reach the
atomic step, which means it has to be in the interface.

The alternative considered was keeping `Take` and adding `TakeN` as an optional
interface discovered by type assertion, with `AllowN(n>1)` returning an
"unsupported" error for stores that lack it. Rejected: it buys source
compatibility for third-party stores at the price of two code paths, a
permanently two-method contract, and a runtime failure mode that exists only to
paper over the split. Under the pre-1.0 policy (§8) the clean break is the
cheaper answer, and both in-tree stores are ours.

`Take(ctx, key)` survives on the `Limiter` as a wrapper for `TakeN(ctx, key, 1)`
— one implementation, no drift.

**The callable API.** The limiter was previously reachable only as middleware
plus a raw `Take`. That is insufficient for the case it is most often wanted in:
limiting by an identity that is only known *after* authentication — an account,
an API key, a tenant — which a `KeyFunc` cannot derive from the request. So:

```go
func (l *Limiter) Allow(ctx, key) bool                 // TakeN(1), failure policy applied
func (l *Limiter) AllowN(ctx, key string, n int) bool  // weighted, failure policy applied
func (l *Limiter) Take(ctx, key) (Result, error)       // raw
func (l *Limiter) TakeN(ctx, key string, n int) (Result, error)
```

`Allow`/`AllowN` apply the configured `FailureMode` and report to `OnError`;
`Take`/`TakeN` hand back the error so the caller can decide. That is the entire
difference, and it is the reason both pairs exist rather than one.

`AllowN` returns a bare `bool` rather than a `Result`. A caller that wants the
remaining allowance or a retry hint is asking a different question and should
call `TakeN`, whose answer already carries both; folding them into the common
case would make every call site carry values it does not use.

**One copy of the failure policy.** The middleware and `AllowN` both route
through an unexported `evaluate`, which returns a four-state `outcome`
(allowed / denied / store-error / failed-open) rather than a `(Result, error)`
pair each caller re-interprets. `failed-open` is deliberately distinct from
`allowed`: there is no `Result` behind it, so the middleware knows not to
publish rate-limit headers derived from a zero value — advertising a zeroed
allowance would tell clients they are throttled when the truth is that no
decision was made. `TestFailOpenWritesNoRateLimitHeaders` pins it.

**Cost normalization.** `n < 1` is clamped to 1, in the `Limiter` and again in
every store. A weight that arrives miscomputed — an empty list, a truncating
integer division — must not produce a request that passes through the limiter
without paying for itself. `n > Burst` can never be satisfied and is reported as
a *denial*, not an error: it is a decision about a request that costs more than
the bucket can ever hold. It must also not drain the bucket on its way to
refusing, which `TestCostAboveBurstIsDeniedNotErrored` checks against real
Redis.

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

**Memory bounds:** `MemoryStore` caps the number of tracked keys and discards
the **most refilled** bucket past the cap, in addition to TTL-based cleanup. An
unbounded map keyed by client IP is itself a memory-exhaustion vector — a single
host with an IPv6 /64 can mint effectively unlimited distinct addresses (§6.5).
The eviction policy is not a detail: discarding a bucket grants its client a
fresh burst, so the only bucket that is free to discard is one that had already
refilled. Least-recently-used ordering picks the opposite of that, which is why
it is gone (§6.12).

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
- **Weighted cost inside the same script.** The cost is `ARGV[5]`, so a
  `TakeN(n)` is still one `EVALSHA`. Deducting `n` by invoking the script `n`
  times would reintroduce precisely the interleaving the script exists to
  prevent, and would allow a partial deduction. The script takes all of the cost
  or none of it.
- **TTL in Redis** replaces the in-process janitor.
- **Fail-closed** on connection error or timeout, per §4.1.
- Depends on `github.com/redis/go-redis/v9`, confined to this module.

The retry hint distinguishes the two cases a weighted call produces: after a
*successful* take it reports the wait for the next single token, and after a
*denial* the wait for the remainder of this call's cost — so a client that comes
back at the advertised time succeeds instead of being rejected a second time.

The unit tests drive a fake scripter and can only assert that the cost reaches
the script. The arithmetic itself is only executed by a real server, so the
weighted behaviour is pinned by the Docker-backed integration suite:
`TestWeightedCost`, `TestCostAboveBurstIsDeniedNotErrored`,
`TestCostBelowOneIsClamped`, and `TestWeightedConcurrencyIsAtomic` — the last
firing twenty concurrent cost-5 calls at a burst of 50 and requiring exactly ten
to be granted.

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

#### Rotation on privilege change

`Protector.Rotate(w, r)` replaces the cookie and returns the matching token.
Session fixation applies to CSRF: an attacker who plants a cookie the victim's
browser keeps can compute the token that goes with it, and a forged request from
the victim's browser then verifies. Rotating on login overwrites the planted
value, so from that moment the victim's browser sends something the attacker
never saw.

**It is not server-side revocation, and the doc comment says so.** The scheme is
stateless — a token is `HMAC(secret, cookieValue)`, verified by recomputation —
so there is no issued-token list to strike from, and an old cookie paired with
its old token still verifies. That is not the attack: presenting the old pair
requires the attacker's own browser and their own session. The first draft of
this feature claimed "invalidating every token issued before it"; the test
disproved it, and `TestRotateIsNotServerSideRevocation` now pins the real limit
so the claim cannot creep back.

**The context holds a `*tokenHolder`, not a string.** If it held the string,
`Token(r)` after `Rotate(w, r)` would return the *pre*-rotation value, the
handler would render a dead token, and every subsequent POST would 403 — which
is precisely the silent staleness `Token`'s `(string, bool)` signature exists to
prevent, reintroduced by another route. The holder carries a mutex because a
handler may hand the request to goroutines. `Rotate` also returns the new token
directly, so the common call site does not have to ask for it again; the holder
is for code deeper in the stack that only has `r`.

**Calling `Rotate` too late is detected, not just documented.** Once the header
block is serialized, net/http discards any further `Set-Cookie` silently. A
handler that rotated after `WriteHeader` — or after its first `Write`, or after
a redirect — would be told it had succeeded while the browser kept the old
cookie, leaving open exactly the fixation the call was meant to close. The
middleware therefore wraps the `ResponseWriter` in a recorder that notes when
the response begins, and `Rotate` returns `ErrHeadersAlreadySent` and changes
nothing. The flag is atomic for the same reason the holder has a mutex.

The wrapper implements `Unwrap() http.ResponseWriter`, so `http.ResponseController`
reaches `Flush`, `Hijack` and the rest through it — wrapping a ResponseWriter
otherwise costs the rest of the chain those capabilities. The residual
limitation is stated in the doc comment: a *direct* `w.(http.Flusher)` does not
follow `Unwrap`, which is the assertion `ResponseController` exists to replace.
`findRecorder` walks the Unwrap chain, so intervening middleware following the
same convention does not hide the recorder; when none is found rotation still
proceeds, because a safety net must not be able to disable what it guards.

Both guarantees are verified by removal: deleting the check fails all three
subtests of `TestRotateAfterWriteHeaderIsReported`, and deleting `Unwrap` fails
`TestMiddlewareDoesNotHideFlusherOrHijacker`.

**What `Rotate` does not do: it does not rotate the session identifier.** This
is the limitation most likely to be misread, because calling it at login looks
like it handles session fixation. It handles the CSRF half. Classic session
fixation — an attacker fixing the victim's *session* cookie and then riding the
authenticated session — is defeated by issuing a new session ID at the privilege
change, which belongs to the consumer's session layer and which this package
cannot reach. A login that does only one of the two remains vulnerable to the
other, and doing only this one is the easier mistake.

### 4.4 `secureheaders`

Sets `Content-Security-Policy`, `Strict-Transport-Security`, `X-Frame-Options`,
`X-Content-Type-Options`, `Referrer-Policy`, and `Permissions-Policy`.

Secure by default: strict CSP, `DENY` framing, one-year HSTS with
`includeSubDomains`. Loosening any of these is an explicit, visible opt-in via
functional options. `preload` is off by default and documented as effectively
irreversible.

In `preset.API` this middleware runs outermost, before rate limiting or CSRF
(§3.3). The headers are the cheapest check in the chain and apply to every
response the chain produces, including the ones the other middleware reject —
so there is no ordering reason to delay them, and a real reason not to: an
error page is exactly as capable of being framed, sniffed as a different
content type, or rendered without a CSP as a success response is.

#### CSP nonces

The strict default CSP forbids inline scripts, and real pages have them. The
usual response is `'unsafe-inline'`, which permits every inline script including
the injected one — equivalent to having no script policy. A per-request nonce
keeps the policy strict and still runs the scripts you wrote.

**A named directive that is absent is added, not skipped.** `DefaultCSP` has no
`script-src` at all; it relies on `default-src 'self'`. Skipping would leave the
nonce in the context and absent from the policy — templates emit `nonce="..."`,
the browser ignores it, and the operator has a silently broken CSP, which is
what the requirement said must not happen. Adding `script-src 'nonce-X'`
*tightens* instead: scripts now need the nonce rather than merely being
same-origin. The cost is that same-origin `<script src>` tags need the attribute
too, which is documented prominently on the option — a nonce whose policy still
admitted every same-origin script would be decoration.

**A CSPRNG failure rejects the request.** This is a new rejection point in a
package that previously had none, so under §3.4 it needs a customizable handler:
`WithNonceErrorHandler`. Falling through would serve a page whose own scripts
its policy blocks; serving an empty nonce is worse, because `'nonce-'` matches
nothing and nothing reports it. The failure path is otherwise unreachable from
outside the package, so an unexported `withNonceSource` test hook exists —
unexported specifically because an exported one would invite supplying a
predictable nonce, which defeats the mechanism.

`Nonce(r)` returns `(string, bool)`, mirroring `csrf.Token` for the same reason:
a bare `""` renders `nonce=""`, every script is blocked, and the fastest apparent
fix is `'unsafe-inline'`.

The policy is split around the insertion points once at construction, so the
per-request cost is a `strings.Builder` walk rather than a parse.

#### `NoStore` is a function, not an option

RFC 6749 §5.1 requires `Cache-Control: no-store` and `Pragma: no-cache` on the
OAuth token response. It is a per-*route* requirement: applied to a whole chain
it would disable caching of static assets and public responses, trading a
requirement that covers a handful of routes for a site-wide regression. So it is
a plain `func(http.Handler) http.Handler`, which is how this library expresses
per-route.

`no-store` rather than `no-cache`: `no-cache` lets a shared cache *store* the
response and merely revalidate, which still leaves a token sitting in a proxy.

#### `ClearSiteData` for logout

Server-side invalidation ends the session; it does not remove what the browser
already holds. The access token in localStorage survives, the authenticated
pages in the HTTP cache are served when the user presses Back, and a second tab
keeps rendering the logged-in view. On a shared machine that residue is the
whole problem the user was trying to solve.

`ClearSiteData(types...)` is per-route, for the same reason `NoStore` is: it
belongs on the logout response and nowhere else.

Two things are documented prominently because they are the ways this gets
misused:

- **It is ignored on non-secure origins and support is uneven**, so it is
  defense in depth on top of real invalidation, never the mechanism. A logout
  that relies on the client agreeing to forget is not a logout.
- **`cookies` clears the registrable domain, not the origin.** Logging out of
  app.example.com also clears cookies for shop.example.com. That may be the
  intent or may be a surprise, and it is the one part worth checking before
  deploying.

`executionContexts` is excluded from the default (and `"*"` is not used, since
it implies it). Reloading every other tab on the origin is a visible, surprising
effect that belongs to a deliberate choice.

The values are quoted, because browsers ignore unquoted ones — which would make
the middleware silently do nothing. `TestClearSiteDataValuesAreQuoted` pins it.

#### COOP, CORP and COEP: opt-in, and this is a closed decision

**Decision, settled:** all three ship as options. **None becomes a default in
v0.2.0.** `COOPSameOriginAllowPopups` and `CORPSameOrigin` remain candidates for
some later version, and if either is ever promoted it must be announced in the
changelog as a behaviour change. **COEP never becomes a default, in any
version.** Nothing here is awaiting further input.

All three are available through `WithCrossOriginOpenerPolicy`,
`WithCrossOriginResourcePolicy` and `WithCrossOriginEmbedderPolicy`. **None is
in the default set**, and `TestCrossOriginHeadersAreNotDefaults` fails if one
ever becomes one without the change being deliberate.

The reasoning is about the shape of the risk, not about the headers' value. A
default in a *published* security library changes behaviour for every deployed
consumer on upgrade, with no compile error to warn anyone, and each of these
three fails in a way the server cannot see: the server keeps returning 200 and
the browser discards or refuses to load something. That is the worst diagnostic
profile a regression can have.

Per header:

- **COOP.** `same-origin` breaks the popup OAuth and payment pattern outright —
  the popup can no longer `postMessage` back to its opener, and the flow hangs
  with no catchable error, so it is permanently unsuitable as a default.
  `same-origin-allow-popups` is the value most applications want and is a
  candidate for a later version; even it breaks an application that is *itself*
  opened as a popup and talks to its opener, which is exactly what an identity
  provider or an embeddable widget is — so promoting it is a changelog event,
  not a quiet tightening.
- **CORP.** Real value against speculative-execution cross-origin reads and
  XSSI. But it is a statement about responses, and this library sits in front of
  things that are deliberately cross-origin: public APIs, CDN assets, fonts,
  avatars. `same-origin` by default would break those silently. Also a candidate
  for a later version, under the same changelog condition.
- **COEP.** Never a default, in any version — this is settled, not deferred.
  `require-corp` refuses every
  cross-origin subresource that does not opt in, so third-party images, fonts,
  analytics and embedded iframes stop loading unless each third party cooperates
  — which most do not. It exists only because it is the price of cross-origin
  isolation (with COOP `same-origin`) for SharedArrayBuffer and high-resolution
  timers. An application that does not need those gains nothing from it.

The mixed CORP case — a strict chain with some public assets — is served by the
package's existing contract that headers are written before the handler runs, so
a route may overwrite any of them. `TestCORPCanBeOverriddenPerRoute` documents
that shape.

`TestCrossOriginHeadersAreNotDefaults` enforces the decision in code: it fails
if any of the three appears in the default set, so promoting one cannot happen
as a side effect of an unrelated edit.

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

#### `URL` and the control-character bypass

`validate.URL(schemes...)` allows `http` and `https` by default. The threat is a
user-supplied URL later rendered into an `href`: `javascript:` runs in your
origin with the victim's session, and `html/template` does not help — inside an
`href` a `javascript:` URL is a *valid* URL, not a syntax error to escape.

The substance is not the allow-list, which is obvious, but two things around it:

- **Control characters are rejected before parsing — but measure who is
  actually rejecting them.** A browser strips tab, newline and carriage return
  before reading a URL's scheme, so `"java\tscript:alert(1)"` navigates as
  `javascript:`. An allow-list comparing the *parsed* scheme is where that gets
  through.

  The first version of this section claimed the pre-check was what closed that
  bypass. Checking rather than asserting showed otherwise: **`net/url` refuses
  to parse a control character in the scheme, host or path**, so on current Go
  the disagreement never arises and the rule rejects on the parse error. The
  original table test passed identically with the pre-check deleted — it was
  testing `net/url`, not this package.

  The pre-check stays, for two non-hypothetical reasons: a guarantee that is a
  side effect of another package's current strictness is one upgrade away from
  not holding, and it rejects cases `net/url` *does* accept — control characters
  in a fragment, spaces in a path, query or trailing position, all of which
  parse cleanly with an allowed scheme.

  The testing was restructured to match. `hasControlOrSpace` is a named function
  so it can be tested on its own; `TestPreCheckRejectsWhatNetURLAccepts` uses
  only inputs `net/url` accepts, so the pre-check is the sole thing that can
  reject them (verified: it fails on all seven when the check is removed); and
  `TestNetURLRejectsControlCharactersInScheme` is a canary that fails if a
  future Go loosens the scheme check, at which point the pre-check stops being
  defense in depth and becomes load-bearing.

  The fuzz target still asserts the end-to-end property: for any input the rule
  accepts, the browser-stripped form must not begin with a script-bearing
  scheme.
- **A scheme is required**, which rejects `//evil.example.com` — scheme-relative,
  parsed with an empty scheme, treated by a browser as "same scheme as the
  current page", and the classic open-redirect payload.

Deliberately out of scope: host allow-listing and DNS resolution. An allowed
scheme still permits any host, so this is not sufficient for a redirect target
and is not an SSRF defence; both need application knowledge this package does
not have. Also out of scope is anything OAuth-shaped — exact `redirect_uri`
matching, registered-origin comparison — which would make this a rule about one
protocol rather than about input.

### 4.6 `pathguard`

Prevents path traversal when resolving user-supplied paths under a root.

**Primary implementation: `os.Root` (Go 1.24+, which is this module's floor).** `os.OpenRoot` enforces
containment at the syscall layer, which closes the TOCTOU window that any
resolve-then-open approach leaves open: between `EvalSymlinks` returning a safe
path and the subsequent `os.Open`, an attacker with write access to the tree can
swap a component for a symlink. Manual validation cannot fix this race; the
kernel-level primitive can (§6.7).

The manual `filepath.Rel`-based containment check is retained as a defense-in-
depth pre-check and for path validation that does not open a file.

Also provided: `ResolveNew` for paths that do not exist yet (validating the
parent), since upload destinations are a common real-world need.

### 4.7 `realip`

Derives a client address from a request that arrived through reverse proxies.

**Why it exists at all.** `ratelimit` correctly refuses to read `X-Forwarded-For`
and tells the operator to supply a `KeyFunc` that reads the forwarded header
"only after confirming the peer really is that proxy" (§4.1). That advice was
sound and unserviced: the library named the sensitive code and then left every
consumer to write it by hand. A security library that documents a trap without
shipping the tool to avoid it has moved the risk, not reduced it.

**Configuration is a set of trusted proxy CIDRs, and nothing else.** There is no
per-request permissive mode and no "trust the header anyway" flag. When the peer
is outside the set, every forwarding header is ignored in full and `RemoteAddr`
is returned. A flag to relax that is a flag that lets clients choose their own
identity, which would make the rest of the package decorative.

An empty trusted set is an error rather than "trust nothing", because the
overwhelmingly likely cause is an unset environment variable. Failing loudly at
startup beats an operator believing a proxy configuration is in effect when it
is not. Wanting `RemoteAddr` alone is already spelled `ratelimit.RemoteAddrKey`.

The same reasoning refuses the *other* end of the range. A trusted set of
`0.0.0.0/0` or `::/0` reaches the permissive mode this package will not ship, by
configuration rather than by flag: every client becomes a trusted proxy, so
`X-Forwarded-For` is honoured from anyone and the rate-limit key becomes whatever
the client types. `New` therefore returns `ErrDefaultRouteTrusted` unless
`InsecureTrustEveryPeer()` says otherwise (§6.12).

#### The chain is walked right to left. Here is the bypass if it is not.

A proxy **appends** the address it received from to the right-hand end of the
chain; it does not replace what is already there. That single fact decides the
direction of the walk.

Take a service behind one trusted load balancer at `10.0.0.1`, rate limiting by
client IP. An attacker sends:

```http
GET /login HTTP/1.1
X-Forwarded-For: 1.2.3.4
```

The load balancer appends the address it actually saw, and the application
receives:

```http
X-Forwarded-For: 1.2.3.4, 198.51.100.23
RemoteAddr: 10.0.0.1:54321
```

Read **left to right**, the answer is `1.2.3.4` — a value the attacker typed.
Nothing stops them typing a different one on the next request:

```
X-Forwarded-For: 1.2.3.5   ->  key 1.2.3.5   -> fresh bucket
X-Forwarded-For: 1.2.3.6   ->  key 1.2.3.6   -> fresh bucket
X-Forwarded-For: 1.2.3.7   ->  key 1.2.3.7   -> fresh bucket
```

Every request mints a new bucket, so the limiter admits every request. The
limit is not weakened, it is *absent*, and it is absent in exactly the scenario
it was deployed for — credential stuffing against `/login` from behind a
CDN. Worse, the attacker can pick a victim's address and exhaust *their*
allowance, turning the limiter into a denial-of-service tool aimed at whoever
they choose.

Read **right to left**, the walk starts at `198.51.100.23`, which the load
balancer wrote and the client could not touch. It is not in the trusted set, so
it is the answer. The attacker's `1.2.3.4` sits to its left and is never
reached. Entries that *are* in the trusted set are skipped, so multiple proxy
hops work: the walk stops at the first entry that a trusted machine did not
write.

The general rule: **everything to the left of the first untrusted entry is
attacker-controlled**, because a client can prepend arbitrary content and no
proxy removes it. Only the suffix appended by trusted infrastructure carries any
guarantee, so only the suffix may be used.

An entry that does not parse as an address ends the walk and yields the peer.
Skipping over it would reconnect the trusted suffix to a client-written prefix
across a gap that nothing accounts for, which is the same bug with extra steps.

#### Multiple sources are opt-in, and precedence does not fall back

`Forwarded` (RFC 7239) and `X-Real-IP` are supported, but the default reads
`X-Forwarded-For` alone. Enabling a source is a claim that *your proxy owns that
header* — writes it, or strips it. That claim is what right-to-left parsing
depends on, and it does not transfer between headers.

Concretely: a proxy that appends to `X-Forwarded-For` and ignores `Forwarded`
delivers a client's `Forwarded: for=1.2.3.4` untouched. That chain has exactly
one element, written by the client, with no trusted suffix. Walking it right to
left stops immediately on the forged entry. The direction of the walk cannot
rescue a header the proxy never touched — so the defense is to not enable it.

Precedence is "first source present wins", with no fallback when the winning
source turns out to be unusable. Falling through would let an attacker who
cannot forge the header the proxy writes send a deliberately broken
higher-precedence header and steer the lookup onto one the proxy does not
sanitize.

#### Testing

The fuzz target carries two properties, and the split is deliberate:

1. An untrusted peer never steers the result. **This property does not test the
   walk direction** — when the peer is untrusted the headers are never read, so
   a left-to-right implementation satisfies it too. Verified: with the walk
   reversed, `TestKeyFuncCannotBeSteeredByAnUntrustedPeer` still passes.
2. With a trusted peer, a chain of `<fuzzed junk>, <address the proxy observed>`
   must resolve to the observed address (or to the peer, when the junk is
   unparsable and legitimately breaks the chain). This is the property that
   pins the direction: reversing the walk fails it on seed #6 immediately, and
   fails 19 of the table-driven cases.

Property 1 alone would have been a test that passes against the bug it exists
to catch.

### 4.8 `secret`

Holds byte secrets so they cannot escape through formatting.

**The threat is accidental output, not an attacker in the process.** A signing
key in a `[]byte` is one `%+v` away from a log aggregator, and it is rarely a
deliberate print that does it: a struct dumped while debugging, a config
marshalled into a startup line, `slog.Any("config", cfg)`. `secret.Value` makes
every standard output path write `[REDACTED]`, and the bytes leave only through
an explicit `Bytes()` call that a reviewer can see.

This is not encryption and not memory protection. Anything that can read process
memory recovers the value trivially. The claim is about printing, and nothing
else.

#### `fmt.Formatter`, not just `fmt.Stringer`

`Stringer` is consulted only for `%v`, `%s`, `%q`, `%x` and `%X`. A `%d` against
a struct holding a `Value` descends into the fields and prints the bytes as
numbers. `Formatter` is consulted for every verb, so implementing it leaves no
verb that reveals anything. `%#v` routes to `GoString`; everything else,
including width and precision, writes the placeholder — honouring a precision
would let a caller extract the value one character at a time.

`String` and `GoString` are kept even though `fmt` no longer reaches them, because
code outside `fmt` calls them directly: a hand-written error message doing string
concatenation, a logging façade type-switching on `fmt.Stringer`. They are tested
by direct call for exactly that reason.

Receivers are by value. A `String` method on a pointer receiver is skipped for a
non-pointer argument, which is the most common way this kind of type is written
wrong.

#### Two paths no method can cover, and why the bytes are masked

Redaction by method has a floor. Two `fmt` paths never consult the method table:

1. **The bad-verb path.** `fmt` handles `%p` before looking for a `Formatter`,
   and a struct is not a pointer, so it routes there; `%w` outside `fmt.Errorf`
   lands in the same place. The path sets an internal `erroring` flag that
   suppresses `Formatter` *and* `Stringer` at every nesting depth, then dumps the
   value structurally. Measured, not assumed: `%T`, `%p` and `%w` are the
   complete set that escapes `Formatter` — ordinary unknown verbs (`%h`, `%z`)
   do reach it and hit its default branch.
2. **An unexported struct field.** `fmt` walks fields by reflection and cannot
   call methods on a value it cannot convert back to an interface.

Both were found by the test rather than by reasoning — the first draft
implemented every method the design called for and still leaked, which is the
argument for writing the "no verb may leak" test before believing the design.

Neither is overridable; they are properties of `fmt` and `reflect`. So the
defence is not another method: the bytes are stored XOR-masked under a keystream
derived **per `Value`**, and plaintext exists only inside `Bytes()`. Both paths
then print keystream output and a nonce, which carry no information.

The derivation is `HMAC-SHA-256(processKey, nonce || counter)`, with `processKey`
held as package state and never as a field of a `Value`. That placement is
load-bearing rather than tidy: the paths this defends against dump a `Value`
*structurally*, so a pad stored beside the bytes it masks would be printed
alongside them and XOR straight back to the plaintext. A per-`Value` pad held in
the struct would be worse than no mask at all. §6.12 covers what the previous
single shared pad leaked and why it had to go.

`Equal` can no longer compare stored bytes — equal secrets under different
keystreams mask differently. It folds four bytes per position instead,
`masked_a ^ ks_a ^ masked_b ^ ks_b`, which is `plaintext_a ^ plaintext_b`
without either plaintext ever being assembled. Constant time is preserved
because every position is visited, differences are accumulated with `OR` rather
than branched on, and the one decision is taken at the end. Keeping the
plaintext off the heap is what ruled out the obvious
`bytes.Equal(v.Bytes(), other.Bytes())`, and a test asserts the allocation cost
does not grow with the secret so that version cannot come back.

`Value` holds a slice, so it is not comparable with `==` and cannot be a map key.
That is load-bearing rather than incidental: it forces every comparison through
`Equal`, which is constant time. `TestValueIsNotComparable` asserts it, so a
future change to a fixed-size array would fail rather than silently reopen the
timing side channel.

#### Unmarshalling is not the inverse of marshalling

`Value` marshals to `[REDACTED]`, so a round trip would install the literal
placeholder as the secret. Every instance would then agree on a well-known value
and CSRF tokens signed with it would verify against forgeries. `UnmarshalText`
and `UnmarshalJSON` therefore return `ErrRedacted` for that input: a silent
compromise becomes a startup error.

The text is taken as-is rather than base64-decoded. Guessing at an encoding would
make a secret that happens to be valid base64 mean two different things.

### 4.9 `csrf.GenerateSecret` returns a `secret.Value` — the break, and why

`GenerateSecret`, `csrf.New` and `preset.Config.CSRFSecret` all changed from
`[]byte` to `secret.Value`. This is a source break, taken deliberately under §8.

**Why all three and not just the generator.** Changing only `GenerateSecret`
would put the protective type on the function that *produces* a secret and not
on the ones that *consume* it. Every call site would become
`csrf.New(v.Bytes(), ...)`, the raw `[]byte` would travel through application
code exactly as before, and the type would be pure ceremony — worse than
useless, because it would look like the problem had been addressed. The whole
value of the wrapper is that it is unavoidable.

**The alternative was `GenerateSecretValue`.** Zero breakage, but two functions
doing the same job forever, with the unprotected one appearing first in godoc
and in the README and therefore in everything copied from them. The `secret`
package would become opt-in decoration.

`preset.Config` is the most important of the three. A `Config` struct is exactly
the kind of thing an application logs at startup.

`cmd/moat-secret` is the one place that calls `Bytes()` to unwrap deliberately —
printing is the command's entire purpose, so the unwrap is intent, not accident.
Everywhere else the `Value` is passed along unopened.

Migration cost was 8 call sites, all tests and examples. Callers loading from an
environment variable or a secret store wrap at the boundary with `secret.New`,
which `examples/basic` demonstrates.

---

## 5. Usability requirements

These are treated as requirements, not nice-to-haves.

1. **`middleware.Chain`** for flat, auditable composition (§3.2).
2. **`preset`** for helmet-style adoption in one call, with unsafe omissions
   made impossible-by-accident (§3.3).
3. **Framework adapters** for Gin and Echo, living as compiled, tested code in
   the `examples/` module — not as prose snippets that silently rot.

   One correction to that claim, since it was stated more broadly than it held.
   Up to and including v0.2.0 the adapters were compiled and tested — against
   the **working tree**, through `go.work`, while `examples/go.mod` declared a
   `require` on the core that nothing ever resolved. So the guarantee was real,
   but it was a guarantee about the code in this repository, not about the
   version the file claimed to build against. §6.16 is the same defect reaching
   a published tag. The `released-satellites` CI job now builds `examples/` with
   `GOWORK=off`, which is what makes the sentence above true as written.
4. **Testable examples (`ExampleXxx`)** in every public package, rendered on
   pkg.go.dev and compiled by `go test`, so documentation cannot drift from the
   API. Examples that would depend on wall-clock timing or network are written
   as compile-only examples (no `// Output:` line) rather than as flaky tests.
5. **`csrf.GenerateSecret() (secret.Value, error)`** to remove first-run
   friction, returning a value — never printing. (It returned `[]byte` up to
   v0.1.0; §4.9 records the migration to `secret.Value` and why the whole
   cascade had to move together.) A library that writes to stdout/stderr is
   unusable in a serious application (§6.8). A `cmd/` helper wraps it for CLI use.
6. **Doc comments carry the threat model**, not just the API shape. For a
   security library, "why" is the load-bearing part of the documentation.

---

## 6. Audit findings and resulting changes

Recorded because the reasoning is the deliverable, and because several of these
were real defects in the first design pass.

### 6.0 Policy: a finding whose fix is "remember to X" is not closed

This is policy, not a log entry, and it was earned three times over.

- §6.13 closed a class of bug with a guard named after the single instance that
  had been found, which left the class open.
- §6.15 (MEDIUM-2) found that the remedy against instance-level guards had
  itself been applied at the instance.
- §6.16 closed a released-broken satellite module with a **standing item** — a
  sentence in this document asking a future release to remember something. The
  mechanism that would have caught it was known at the time, was written into
  the commit message ("Running the satellite test suites with `GOWORK=off`
  before tagging would have caught this locally"), and was not built. The
  commit touched six files and none of them was in `.github/`.

The third one is the informative one, because the failure was not ignorance. The
mechanism was identified, articulated, and skipped — and it was skipped at the
moment of tagging a release, which is exactly when a checklist gets the least
attention.

**The rule:** a finding whose remedy is "remember to do X" is not closed while
the only thing standing between the project and a repeat is somebody
remembering. It is closed when there is a mechanism that fails, loudly and by
default, when X is skipped. A checklist item cannot fail. Nobody is paged when
it is forgotten, and no record exists that it was.

Two consequences worth stating, because both are ways this rule gets quietly
broken:

- **The mechanism has to be shown red.** A guard that has never failed on the
  bug it exists to catch is a guess. §6.16's job was verified by putting the
  original stale `require` back and watching the build fail with
  `*Store does not implement ratelimit.Store (missing method Take)` — the exact
  error a consumer got from the published tag.
- **The bypass, where one is genuinely needed, is explicit and visible.** Not a
  disabled job, not a warning: a named opt-out somebody has to type, on the
  record. `redisstore.InsecureAllowKeyEviction` is the shape; the
  `cross-module-window` PR label is the same shape applied to CI.

Checklists still have a place — the review checklist in `CONTRIBUTING.md` covers
properties no tool can currently assert, and says so in each entry. The rule is
that a checklist is not where a finding *ends* when a mechanism was available.

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
containment.

The core `go.mod` declares exactly **1.24**, the technical floor. A library
declares the lowest version it can actually be built with, not the newest
toolchain its authors happen to run: every release above the floor is a
consumer excluded for no reason. The core has zero external dependencies, so
nothing pushes it past `os.Root`.

The two satellite modules do declare **1.25**, and not by choice —
`redisstore` because `testcontainers-go` requires 1.25, `examples/` because
`gin` does. `go mod tidy -go=1.24.0` refuses in both. Since neither module is
on the import path of a core consumer, their floors do not propagate.

### 6.8 Library-side logging and printing

Any design where the library writes to stdout/stderr or holds its own logger is
rejected. Errors surface through `OnError` hooks and returned values; the host
application owns observability.

### 6.9 Supply-chain hygiene in CI

`go install ...@latest` in CI is non-reproducible and is itself a supply-chain
risk — inappropriate for a security library. All tooling is version-pinned.

### 6.10 Module path naming

The working name during design and initial implementation was `gosecure`. The
Go community style guide discourages `go`-prefixed package names for good
reason — the prefix says nothing about what the package does — and a
pre-implementation review flagged it as a name to verify before the first tag,
since the module path is baked into every consumer's import and is painful to
change afterwards.

That verification happened, found the name was in fact crowded, and the module
was renamed to `moat` as a result. §10.10 has the search results and the
reasoning for the replacement name; this section is left in place, rather than
edited to read as if `moat` had been the plan all along, because a design
record that quietly rewrites its own history is worth less than one that shows
its work.

### 6.11 Pre-release hardening: rename verified, ordering gap closed, self-found bugs audited

Four passes ran between initial implementation and the first tag, each closing
something an earlier pass had only asserted, deferred, or accepted as a
trade-off:

- The module was renamed from `gosecure` to `moat` once the pkg.go.dev
  crowding §6.10 flagged as a risk was actually confirmed (§10.10). Every
  import path, protocol-level default (the CSRF cookie and field names, the
  Redis key prefix), and reference in this document was updated to match;
  nothing under the old name was ever pushed to the remote.
- `preset.API`'s middleware order was changed so `secureheaders` runs
  outermost, ahead of rate limiting, closing the gap where a `429` shipped
  with no CSP or `nosniff` (§10.6). That gap was originally documented and
  accepted as a trade-off; it was reconsidered and reversed rather than
  shipped that way.
- The Redis integration suite (`redisstore`, build tag `integration`) was run
  for real against a live container, not merely compiled. Its atomicity claim
  was verified two ways: the concurrency test now asserts an exact admitted
  count against a single-digit-capacity bucket under heavy contention, and —
  as a check on the test itself — the atomic Lua path was temporarily
  replaced with a naive two-round-trip read-then-write, which the test caught
  immediately (200 of 200 requests admitted against a capacity of 8, in a
  test that asserts exactly 8). The naive path was never committed.
- The two bugs self-found during initial implementation (§10.2's idle-eviction
  floor, and a timeout-less `http.ListenAndServe` in a `redisstore` doc
  example) were each verified round-trip: the pre-fix code was temporarily
  reintroduced, the regression test — or, for the timeout case, the `gosec`
  CI gate, since a compile-only doc example has no runtime assertion to make
  about timeouts — was confirmed to fail, and the fix was restored. The
  codebase was then swept for the same shape of each bug elsewhere: no other
  TTL-evicting store exists in the tree, and every other `http.Server` in
  `examples/` was checked and brought to a consistent timeout configuration.
  Both bug classes are now standing items in `CONTRIBUTING.md`'s review
  checklist, since neither has a fuzz target and both are easy to
  reintroduce by copy-paste without a reviewer having seen the original
  finding.

`v0.1.0` was tagged on the commit that closes this section, not on any earlier
one — see §8.

### 6.12 Post-v0.1.0: three security fixes, all blocking v0.2.0

A review after the first tag found three places where a documented protection was
weaker than its documentation claimed. All three share a shape worth naming: the
code was not wrong by accident, it was wrong in a way the surrounding prose had
already argued against. Each fix ships with a **negative control** — the previous
behaviour restored, the new test confirmed to fail, then the fix put back — on the
principle §6.11 established. A test that passes against both implementations is
testing nothing.

#### M-1: eviction granted a limit reset (`ratelimit.MemoryStore`)

`reclaim` refused to discard a bucket that had not refilled, and its comment gave
the reason: discarding an empty bucket resets the client's allowance, which is a
rate-limit bypass. `evictOverCap`, in the same file, did exactly that with no
condition — `order.Back()`, the least recently used entry, deleted.

The contradiction was reachable without an attacker minting keys. A client
exhausts its burst on `/login`; the empty bucket stops being touched, so it drifts
to the tail of the recency list; once `DefaultMaxKeys` distinct keys arrive behind
it, it is deleted and the next request builds a full bucket. Any service with more
than 100k distinct clients per window does this to its own users continuously. The
effective limit stops being `PerSecond` and becomes the store's turnover rate.

The root cause is that **recency is anti-correlated with safety here**. A
throttled client cannot make requests, so its bucket is the *least* recently used
by construction — LRU selects the bucket whose loss grants the most. The fix
inverts the ordering: discard the **most refilled** bucket, whose loss grants the
least, and which in the ordinary case is at capacity and grants nothing at all.

The sort key is `fullAt`, the instant a bucket reaches capacity, not the token
count. Token counts move with the clock and would mean re-sorting the store on
every call; `fullAt` is static between `Take`s and orders identically, since a
bucket holds `burst - (fullAt - now) * rate` tokens at any instant. `container/list`
became a min-heap on `fullAt`. One structure now serves both paths (§10.1).

The heap is hand-written rather than driven through `container/heap`, for a
measured reason: this is the hot path, and reaching `Less`/`Swap` through an
interface cost about 115ns of the 240ns per `Take` at 100k keys. The concrete
version runs at about 125ns against the recency list's 67ns. That remaining ~58ns
is the O(log n) sift, and it is the price of the property. It is written down here
because "no regression on the hot path" was a stated constraint and this is a
regression, just a bounded and justified one. A randomized invariant test checks
the heap directly, since an ordering that is subtly wrong would silently return
eviction to picking arbitrary buckets while every behavioural test still passed.

The residual case was decided rather than left implicit: when *every* tracked
bucket is still in debt there is no cost-free eviction available, and the cap wins
anyway — growing the map without limit would reinstate the memory-exhaustion
vector the cap exists to close (§6.5), which is the worse of the two. The bucket
closest to full is dropped, the smallest grant on offer. Reaching that state costs
an attacker `maxKeys × PerSecond` requests per second sustained, every one already
counted against a bucket. `WithMaxKeys` now says all of this, and in particular
names the failure as a **bypass** rather than as the fairness problem it used to
describe ("a flood of unique keys resets a legitimate client's bucket") — the two
readings call for different sizing decisions.

One thing the fix had to avoid: a newly created bucket is at capacity, so under
the new ordering it is the most attractive eviction candidate and would evict
itself, leaving the key untracked and its next request starting from a full burst
again. Room is therefore made *before* the insertion, not after.

#### M-2: `realip.New` accepted `0.0.0.0/0` in silence

The package documentation stated "There is no permissive mode". `New` accepted the
default route without comment, which is the permissive mode reached by
configuration instead of by flag: every peer becomes a trusted proxy, so
`X-Forwarded-For` is honoured from anyone and the rate-limit key becomes whatever
the client types — a new identity per request.

What decided the fix was the asymmetry, not the severity. `New` already rejected
the *empty* list with `ErrNoTrustedProxies`, reasoning that the likely cause is an
unset environment variable. Failing loudly on the harmless misconfiguration while
silently accepting the maximally dangerous one is not a defensible pair.

Only the default route is refused, not wide prefixes generally. A bit-count floor
was considered and rejected: it is a guess about topology the library does not
have. `10.0.0.0/8` and `fc00::/7` are legitimate proxy ranges already sitting at
the wide end, so a floor tight enough to add anything over `/0` would reject real
configurations, and a looser one would add nothing. `0.0.0.0/0` has no legitimate
reading. Normalization already folds `::ffff:0:0/96` to `0.0.0.0/0`, so both
spellings land on the same check.

The escape hatch is `InsecureTrustEveryPeer()` — deliberately not spelled
`With...`, deliberately not a bool field, in the same spirit as
`preset.Config.DisableCSRF`: it should be impossible to read a call site
containing it and not notice. The sentinel is `ErrDefaultRouteTrusted`, its own
error rather than a generic one, so a caller can distinguish it from a malformed
CIDR. Options are now applied before the CIDRs are parsed, because one of them
decides what counts as valid.

**Known and accepted limitation.** The check does not catch a trusted set that
covers the whole address space in pieces — `0.0.0.0/1` plus `128.0.0.0/1` is
equivalent to `0.0.0.0/0` in every way that matters, and passes. This is
documented on `ErrDefaultRouteTrusted` rather than fixed, for two reasons. The
failure being targeted is an *accident*: an operator who does not know the
balancer's range writing the default route to make things work. Splitting it
across two lines is not an accident, and whoever writes it has already chosen to
trust everyone — the named opt-out exists for exactly that person. And closing it
would mean deciding how much aggregate address space is too much, which is the
bit-count floor rejected in the paragraph above, now summed over the set: the
same guess about topology with more arithmetic behind it. A passing `New` means
"this set is not the default route", not "this set has been checked for breadth",
and the documentation now says so in those words so the check is not mistaken for
complete coverage.

#### M-3: the secret mask was one shared, repeating pad (`secret`)

64 random bytes, XOR applied by position, shared by every `Value` in the process.
Two consequences, neither documented, both *inside* the scenario the mask exists
for — an adversary holding leaked masked bytes:

1. **Keystream recovery.** Anyone with the masked bytes of a secret whose
   plaintext they know or supplied recovered up to 64 bytes of keystream by XOR.
   Every other masked value leaked from that process then decrypted for free.
2. **Pad reuse.** For a secret longer than 64 bytes the pad repeated, so XORing
   two blocks cancelled the keystream and left the XOR of two plaintext blocks —
   structure, with no known plaintext needed at all.

The mask's guarantee had quietly degraded from "reveals nothing" to "reveals
nothing unless you have one known plaintext from the same process", and that
clause was written down nowhere.

**The obvious fix would have made it worse.** A random pad per `Value`, of the
same length as the secret, kills both consequences and is the simplest thing to
audit — but the pad has to live somewhere, and a field on `Value` is exactly the
wrong place. The two paths the mask defends against dump a `Value`
*structurally*; a pad stored beside the bytes it masks would be printed alongside
them, and the two XOR back to the plaintext. The current design works precisely
because the keystream is *not* in the struct.

So the keystream is derived, not stored: each `Value` carries a nonce, and its
stream is `HMAC-SHA-256(processKey, nonce || counter)` with `processKey` as
package state. Recovering one `Value`'s keystream yields the input to a one-way
function rather than the process key, so it says nothing about any other `Value`;
counter mode extends the stream to any length without a block recurring. The
nonce is an atomic counter, not a random draw — uniqueness is the only property
required, since unpredictability comes from `processKey`, and a counter delivers
it outright where a random draw only makes collisions unlikely and can fail at the
CSPRNG. Its start is randomized so a structural dump does not advertise how many
secrets the process has created.

`Equal` was the delicate part, as expected. It compared masked bytes directly,
which was correct *only* while the keystream was shared and positional — the same
property that caused failure (1). Under per-`Value` streams, equal plaintexts mask
to unrelated bytes. The replacement folds four bytes per position,
`masked_a ^ ks_a ^ masked_b ^ ks_b`, which equals `plaintext_a ^ plaintext_b`
while neither plaintext is ever assembled: they exist only as intermediate values
of that expression, so there is no unmasked buffer to allocate, leak into a heap
dump, or forget to wipe. That constraint is what ruled out the one-line
`bytes.Equal(v.Bytes(), other.Bytes())`. Constant time survives because every
position is visited, differences accumulate with `OR` instead of being branched
on, and the single decision is taken at the end over the accumulator; the
keystreams are generated in the same order and quantity for any two inputs of a
given length. The length check still short-circuits, as it always did, and leaks
only the length — which `subtle.ConstantTimeCompare` cannot hide either and which
is not usefully secret.

Timing cannot be unit-tested without flakiness, so the tests pin what can be
checked deterministically: correctness at every block seam, and — as the guard
against the `Bytes()`-based rewrite — that the per-call allocation cost does not
grow with the secret's length. The `Bytes()` version fails that by two orders of
magnitude.

The package documentation now carries the revised threat model explicitly,
including the statement that anything able to read process memory holds
`processKey` and can unmask everything. That line is not a defect being confessed;
it is the boundary no in-process masking scheme can cross, and saying so is what
keeps the mask from being mistaken for encryption.

#### The recurrence sweep, and the one thing it found

Each of the three shapes was swept for elsewhere in the tree, per the practice
§6.11 established. M-2 and M-3 came back clean: no other constructor accepts a
maximally-permissive value in silence, and no other code masks or compares secret
material outside `csrf`, which uses `hmac.Equal`.

M-1 did not. `redisstore` computes its own TTL correctly — `max(idleTTL, refill
window)`, refreshed on every call, with the Lua script commenting the reason — but
that reasoning is enforceable only as far as Redis lets it be. A server running
under `maxmemory` with `allkeys-lru` discards keys under pressure without knowing
they are rate-limit state, and it will drop a bucket that has not refilled. It is
the same bug one layer down, reintroduced by deployment configuration rather than
by code, and with the same anti-correlation: a throttled client cannot make
requests, so its bucket is the best LRU candidate.

`redisstore.New` therefore checks it: one `CONFIG GET maxmemory*` at
construction, returning `ErrUnsafeEvictionPolicy` when the server reports a
memory ceiling together with any policy other than `noeviction`. The escape
hatch is `InsecureAllowKeyEviction()`, named in the same spirit as
`realip.InsecureTrustEveryPeer()`.

**The check is best-effort by design, and the asymmetry is the point.** It is
skipped in silence whenever the answer cannot be established: the client exposes
no `CONFIG` (matched by type assertion off `redis.Scripter`, so a custom client
or a test double is skipped rather than rejected), `CONFIG` is disabled or
renamed — the normal case on ElastiCache, MemoryDB, Upstash and Azure Cache — the
server is not yet reachable, or the reply is not understood. Only a definite
"this server evicts" produces an error. A library that guessed would either
reject deployments it cannot inspect or claim an assurance it does not have;
refusing only what it can see keeps the error trustworthy. `New` therefore still
never fails because Redis is down, and the cost is one round trip bounded by the
store's timeout, skipped entirely under the opt-out.

**Two ways this is weaker than the §6.12 M-2 check, both documented on the
error.** M-2 validates its own argument, which is immutable for the process
lifetime. This validates another system's *mutable runtime state*:
`CONFIG SET maxmemory-policy allkeys-lru` is one command away, and the moment it
is most likely to be run is a memory incident — precisely when the bypass
matters. A cluster node joining later is not covered either (every reachable
master or shard is asked at construction, but only then). So a passing check
means "this server reported a safe configuration at startup", never "this
deployment is safe", and the documentation says so in those words.

**A correction to the first draft of this section.** It originally offered
`volatile-ttl` as an acceptable alternative to `noeviction`. That is wrong, and
the check refuses it. Every bucket carries a TTL, so the `volatile-*` family
excludes nothing here — in a Redis shared with a cache whose entries do not all
expire, it makes the rate-limit buckets the *preferred* victims. And
`volatile-ttl` specifically evicts the key nearest expiry; because every bucket's
TTL is refreshed to the same value on every call, remaining TTL is a strictly
decreasing function of time since last touch, so "nearest expiry" is "longest
idle" restated. It is the recency ordering with a different name, carrying the
same anti-correlation. `noeviction` is the only safe setting, and under it Redis
rejects writes at the ceiling instead of discarding limits — a visible outage
through `WithFailureMode` rather than an invisible bypass.

### 6.13 Post-R1: a class that had only been closed at the instance

#### B-1: the 429 bug was still open, and the next rejection point walked into it

`secureheaders`' contract is that the headers go on *every* response, "including
errors and redirects — an error page is still a page". The nonce-failure path
broke it: `writeNonceError` ran before the loop that writes the headers, so the
500 went out bare. Nothing could reach it in production (§10.11), so the
exploitability was nil. What mattered was what it proved.

§10.6 closed the `preset.API` 429-without-headers bug, and the guard added with
it was a subtest named for the 429. That is a test for the *instance*. Nothing
asserted the property, and the very next rejection point added anywhere in the
tree violated it — inside the headers package itself. A class of bug is not
closed by fixing every instance you currently have; it is closed when adding a
new instance is caught.

So the guard is now two tests that together state the class:

- `TestEveryResponseCarriesTheFullHeaderSet` does not hard-code the expected
  headers. It issues one successful request, captures whatever security headers
  came back, and then requires that set of every other path the middleware can
  produce. A header added to this package appears in the reference response
  automatically and is thereby demanded of every rejection, with no edit to the
  test.
- `TestResponseWritingSitesAreAllAccountedFor` parses the package's own syntax
  tree, finds every call that receives an `http.ResponseWriter` — as an argument
  or as a receiver — and requires each to be listed with what it is. A new
  rejection point fails this test until someone classifies it, at which point its
  absence from the behavioural table is in front of whoever added it. This is the
  part that makes the guard a statement about the class rather than a longer list
  of instances. Verified by adding a throwaway rejection handler and watching it
  fail with the site named.

One existing test had to change. `TestNonceFailureRejectsTheRequest` asserted
that *no* CSP was sent on the rejection, which put it in direct conflict with the
package contract. Its stated requirement was "do not emit a **broken** CSP", and
the assertion was stronger than the requirement: a policy with a dangling
`'nonce-'` source is broken, while the configured policy *without* nonce sources
is merely stricter — `injectNonce` only ever adds them — and is the right thing
to put on an error page that cannot have a nonce. The assertion now says that.

A note on how the fix was verified, since it is the point of the exercise: the
first attempt at the fix silently did not apply. The tests that existed at the
time all passed anyway. The new property test failed immediately and named the
nine missing headers.

#### B-3: toolchain, and where the bump had to live

`govulncheck` reported two standard-library vulnerabilities in `redisstore`
(GO-2026-6090 in `crypto/tls`, GO-2026-5972 in `encoding/asn1`) and four in
`examples`, all present in go1.26.5 and fixed in go1.26.6. The core was clean —
not by luck, but because it reaches neither package.

The bump is a `toolchain go1.26.6` directive, and it needed two homes rather than
one. Adding it to `redisstore/go.mod` and `examples/go.mod` is correct and is what
a standalone checkout of those modules honours (confirmed: `GOWORK=off` selects
go1.26.6). But a Go **workspace** overrides member modules' toolchain directives,
and CI creates one — so inside the workspace those directives were inert and the
build stayed on go1.26.5. The directive therefore also goes in the root `go.mod`,
which is the file `actions/setup-go` reads via `go-version-file`, so every CI job
installs go1.26.6 and the workspace it then creates inherits it.

**This does not move the consumer floor.** The `go` directive is what a consumer
sees, and it is untouched: 1.24 for the core (§6.7), 1.25.0 for the other two. A
dependency's `toolchain` line is ignored by the module that imports it. The
directive says how *this repository* is built, not what it demands of anyone else.

**It does cost one thing, stated rather than buried.** With `toolchain` in the
root `go.mod`, CI now builds the core with go1.26.6 instead of a 1.24.x
toolchain, so the declared 1.24 floor is no longer exercised by any job. That
floor was already only weakly exercised — the workspace includes members
declaring `go 1.25.0`, which forces the whole workspace up regardless — but it is
now definitively unverified. Closing that properly means a CI job that builds the
core alone at 1.24 with `GOWORK=off`, which is worth adding and is not in this
change.

### 6.14 The round in one place: six findings, and what each cost

The detailed reasoning for these lives in §6.12, §6.13 and §10.11. This entry is
the log view — what was found, why it mattered, what happened — so the round can
be read without reading the analysis.

Two of the six are worth naming as a pattern: **M-1 and B-1 are both cases where
the library contradicted its own documentation.** Not cases where the docs were
vague and the code guessed — cases where a comment or a package doc stated the
rule, correctly, and the code a few lines away broke it. Prose that argues for an
invariant is evidence that someone understood it once; it is not evidence that
anything enforces it. Both were found by reading the two against each other, and
that is the cheapest audit technique in this document.

**M-1 — `ratelimit.MemoryStore` eviction granted a limit reset.** `reclaim`
refused to discard an unrefilled bucket and its comment named the reason, a
rate-limit bypass; `evictOverCap`, in the same file, did exactly that with no
condition. Reachable without an attacker: any service with more than
`DefaultMaxKeys` distinct clients per window does it to its own users. The root
cause was that recency is anti-correlated with safety — a throttled client stops
making requests, so LRU selects it by construction. Eviction now orders on refill
level. Cost: the hot path went from ~67ns to ~125ns per `Take`. §6.12.

**M-2 — `realip.New` accepted `0.0.0.0/0` in silence.** The package doc claimed
"There is no permissive mode" while the default route reached exactly that by
configuration. What decided the fix was the asymmetry, not the severity: the
empty list was *already* a loud error on the reasoning that it is probably an
unset env var. Failing loudly on the harmless misconfiguration and silently
accepting the maximally dangerous one is not a defensible pair. Now
`ErrDefaultRouteTrusted`, with `InsecureTrustEveryPeer()` as the named opt-out.
Known gap, documented rather than closed: split prefixes. §6.12.

**M-3 — `secret`'s mask was one shared, repeating pad.** Two consequences, both
*inside* the scenario the mask exists for: one known plaintext recovered the
keystream for every other `Value` in the process, and a secret longer than the
pad repeated it, leaking structure with no known plaintext at all. The obvious
fix — a random pad per `Value` — would have been worse, because the fmt paths the
mask defends against dump the struct *structurally*, and a pad stored beside the
bytes it masks gets printed next to them. Keystream is now derived, not stored.
`Equal` was rewritten to fold both keystreams into the comparison. §6.12.

**B-1 — a rejection went out with no security headers, in the headers package.**
`writeNonceError` ran before the header loop, contradicting the package's own
"set on every response, including errors". Unreachable in production (§10.11), so
the exploitability was nil — the finding was that §10.6's 429 bug had been closed
at the *instance* and not the class. The guard added then was a subtest named for
the 429; the next rejection point added anywhere violated the same property. Now
guarded by a test that captures the header set from a real success response, plus
an AST check that fails when the package grows a response-writing site nobody
classified. §6.13.

**B-2 — the CSPRNG fallback in `secret` was fail-open.** On `rand.Read` failure
the process key fell back to `byte(i*31+7)`. Had it run, every `Value` would have
been masked under a publicly derivable keystream and the two accepted leak paths
would have gone from revealing nothing to revealing everything, silently. Dead
code at the Go 1.24 floor, but fail-open dead code in a fail-closed library, and
"defence in depth" was the wrong label for it. Now panics — the one documented
exception to no-panic-in-a-library. The other CSPRNG error paths are kept and
recorded as unreachable so nobody chases coverage over them. §10.11.

**B-3 — `govulncheck` was red on two modules.** Two standard-library
vulnerabilities reachable from `redisstore`, four from `examples`, all fixed in
go1.26.6. Bumped via a `toolchain` directive, which needed a second home in the
root `go.mod` because a Go workspace overrides member modules' toolchain lines and
CI builds one. Consumer floors untouched. One stated cost: CI no longer exercises
the declared 1.24 floor. §6.13.

**Also closed in the same round, without being findings:** `gosec` was red with
eleven results across the tree, all verified false positives — six fixed properly
with explicit blank assignment rather than pragmas, five annotated with a reason.
A red gate that everyone learns to ignore is worse than no gate, and on a
published security library it is the first thing a visitor sees.

### 6.15 R4: an adversarial pass over the whole library

Four findings, three of them tag-blocking. The round's theme is that the two
previous rounds fixed instances of patterns whose general form was still open.

#### HIGH-1: `preset.API` gave every client one rate-limit bucket

`preset.API` built the limiter with no key function, so `RemoteAddrKey` applied.
Behind a load balancer — the topology almost every consumer has — `RemoteAddr` is
the balancer for every client on earth, so the whole service shared one bucket
and any single client spending its allowance held everyone else at the limit
indefinitely. Not a bypass: denial of service against the other users, and from
outside indistinguishable from ordinary throttling.

An API failure rather than operator error, on the package's own terms. `preset`
is the safe-by-default entry point and its `validate()` already asserts that a
silently missing protection is a startup error — it refuses a missing CSRF secret
and missing rate limits. It said nothing here, while the library shipped the
correct answer in `realip` and the preset could only reach it through the
undocumented `RateLimitOptions` escape hatch.

The fix is `Config.TrustedProxies`, wired to `realip` automatically. **The shape
of the refusal mattered more than the refusal.** Erroring on an empty
`TrustedProxies` would have been wrong: empty cannot be distinguished from "I
have no proxy", so it would break the legitimate direct deployment and push an
operator to type any CIDR at all just to boot — a worse state than the one being
fixed, because it manufactures a false trusted set. So the ambiguity is what
becomes impossible, in the shape `DisableCSRF` established: name the proxies, or
state the exposure with `DirectlyExposed`. Setting both is contradictory and is
an error, like the other pairs. The question is not asked when rate limiting is
off, and a bad CIDR — including `0.0.0.0/0`, which §6.12 already refuses — is
reported rather than swallowed.

README's claim that `preset.API` "returns an error if a protection would be
silently missing" was false in exactly this case, and a divergence between
security documentation and behaviour is a finding in its own right. It now says
what is actually checked, and notes that the list grew by one when this was
found.

#### MEDIUM-1: the CSRF token was a constant, and therefore BREACH-extractable

`token = base64(HMAC(secret, cookieValue))` is a pure function of the cookie, so
it was byte-identical in every response until an explicit `Rotate`. An
application serving compressed HTML that reflects any attacker-influenced string
into the same response is then an adaptive compression oracle: a correct guessed
prefix compresses shorter, and the token comes out byte by byte. With it every
request the victim's browser can be induced to make is forgeable.

The decisive argument was not BREACH in the abstract but **ecosystem parity**.
`gorilla/csrf` masks with a fresh per-request pad for precisely this reason, so
the mitigated form is the norm and anyone comparing the two will assume parity. A
library whose pitch is that the plumbing was done carefully cannot be behind the
popular alternative at the point it claims care.

Tokens are now `base64(pad || mac^pad)` with a fresh 32-byte pad per response,
unmasked before a `hmac.Equal` on the recovered MAC. Three things the change
turned up:

- Only the token needs it; the cookie is HttpOnly and never appears in a
  compressed body.
- The format change touches `Rotate` and `Token(r)` together, and two existing
  tests asserted the token was *stable* across responses — the pre-fix property.
  They now assert what actually matters: that the encodings differ and that both
  verify against the one cookie.
- Many encodings of one token are all valid, since XOR is commutative and any
  `(pad, mac^pad)` works. That looks like a flaw and is not — it is what stops
  two responses sharing bytes, and producing another encoding requires already
  holding one. `TestManyEncodingsOfOneTokenAreAllValid` records it so nobody
  "fixes" it later.

Decoding is now `Strict()`, for both the token and the cookie. Go's default
base64 decoder ignores the unused trailing bits of the final character, so a
token had multiple valid encodings and mutating that character was a no-op about
a quarter of the time. Not a vulnerability — the attacker still has to know the
MAC — but it meant "this is not the token that was issued" and "this request is
refused" were not the same statement, and canonical encoding makes them the same.

That non-canonicality had also made `TestEndToEnd` **flaky at about 20%**,
measured over 40 runs. It tampered with a token by replacing its last character,
which a quarter of the time changed nothing. The flake predates the masking — the
43-character unmasked token had the same two unused bits — and the assertion
would have gone on "passing" against a library that accepted tampered tokens
outright. It now mutates the first character, which always carries six
significant bits, and 40 further runs are clean.

#### MEDIUM-2: the guard against instance-level guards was itself instance-level

The most instructive finding of the round. §6.13 closed the 429/nonce class with
an AST walk that required every response-writing site to be classified — but it
called `parser.ParseDir` on one directory, so it proved the property for
`secureheaders` alone. The remedy for "the class was closed at the instance" had
been applied at the instance. Adding an unhooked `http.Error` to `csrf`,
`ratelimit`, `validate` or `pathguard` failed nothing, and §3.4's "closed" table
would have gone quietly false.

The walk now lives at the module root and covers every package in the core
module. Verified by adding an unhooked rejection to `ratelimit` **and**
`pathguard` simultaneously and confirming both were named — the control §6.13's
version could not have produced.

Hoisting it exposed a blind spot in the original: it followed only the
`http.ResponseWriter` *parameter*, and `csrf.Middleware` immediately aliases its
writer (`w := &responseRecorder{ResponseWriter: rw}`) before using it. The
package with the most rejection points in the library reported none. The
module-wide version tracks assignment aliases to a fixpoint, which is what makes
`csrf.Middleware -> p.reject` visible at all.

The invariant itself held throughout: every rejection point already routed
through a `write*` helper with a configurable handler. What was missing was
anything that would keep it holding.

#### LOW-1: `csrf.WithTrustedOrigins()` with an empty slice degraded in silence

The option assigned its slice unconditionally and `originMatches` tested
`len(...) > 0`, so an operator writing `WithTrustedOrigins(cfg.AllowedOrigins...)`
against an unset environment variable silently got host-only matching: no scheme
pinning, no restriction between sibling subdomains. Bounded damage — host
matching is still a real defence, and the `Secure` cookie means a genuine
plaintext origin usually has no cookie to send — but it is the same input shape
`realip.New` already refuses with `ErrNoTrustedProxies`, for the same stated
reason, and that `preset` already guards with `if len(...) > 0`. Direct `csrf`
users had neither. Now `ErrNoTrustedOrigins`, reported through `New`.

### 6.16 The workspace hid a stale cross-module version pin

`redisstore/v0.2.0` was tagged and pushed with `go.mod` still requiring the core
at `v0.1.0`. Since v0.2.0 renamed `ratelimit.Store.Take` to `TakeN`, the
published module did not satisfy the interface it exists to implement and did
not compile for anyone resolving it from the proxy.

Every local signal was green, and necessarily so. `go.work` lists all three
modules under `use`, which makes `redisstore` resolve the core against the
working tree and the `require` line inert. Building, vetting, testing and
fuzzing from inside the repository cannot detect a stale cross-module pin,
because inside the repository the pin is not used. This is the same shape as the
findings in §6.13 and §6.15 — a check that passes for a reason unrelated to the
property it is believed to prove.

What caught it was the release step that fetches the published tag into a clean
directory outside the repository and runs real code against it. That step is
therefore not a formality at the end of a release; it is the only check in the
process that exercises inter-module version resolution at all. `redisstore`'s
tag was reissued as v0.2.1 with `retract v0.2.0`, since a published tag is
immutable once the proxy has cached it.

#### How far back it goes: the `go.sum` evidence

The stale pin was not a slip in one release. Both satellites' `go.sum` files
gained their first line for `github.com/JonasBorgesLM/moat` in `e7c8801` — the
commit that fixed this finding. Before that, `redisstore/go.sum` and
`examples/go.sum` had entries for go-redis, testcontainers, gin, echo and their
transitive trees, and no entry for the one module both of them exist to extend:

```
$ git log --oneline -p -- redisstore/go.sum | grep -E '^[0-9a-f]{7} |JonasBorgesLM/moat '
e7c8801 redisstore: require the core at v0.2.0 and retract redisstore/v0.2.0
+github.com/JonasBorgesLM/moat v0.2.0 h1:4GWDJInGeIgLmdeUxzK2ckUT1WBBhffWyoZP5hSW0v0=
+github.com/JonasBorgesLM/moat v0.2.0/go.mod h1:65xs3itYF+S7xsAZ32o0N7FvZj1564SDquOvmE2nD0o=
e2d961e Implement the library described in doc/DESIGN.md
```

A `go.sum` with no hash for a declared dependency means that dependency was
never resolved outside the workspace — not "not since the last release", but
never, since `e2d961e`. `go mod tidy` would not have added it either: `tidy`
honours the workspace like everything else. So `redisstore/v0.1.0` and every
`examples/` build up to that point were published or verified under the same
unchecked condition; `v0.2.0` is only where the condition finally produced a
visible break, because it is where the interface changed.

`redisstore/v0.1.0` was therefore re-checked from a clean directory outside the
repository, resolved through the proxy with `GOWORK=off`. It builds, and
`*Store` satisfies `ratelimit.Store` — it names the core at `v0.1.0`, which was
consistent at the time. It was correct by coincidence rather than by
verification, which is why it was checked rather than assumed. No retract is
needed for it.

#### Closed with a mechanism, not a standing item

The original close for this finding was a standing item in this document asking
future releases to remember two things. That is precisely the shape §6.0 now
rules out, and this finding is the reason §6.0 exists.

What closes it instead:

- **`released-satellites`**, a CI job that builds, vets, tests and
  `go mod verify`s each satellite with `GOWORK=off`, resolving the core from the
  proxy at the version its `go.mod` actually names. It asserts no workspace is
  active before doing anything, so it cannot pass for the wrong reason.
- **Verified red.** Restoring the original `require github.com/JonasBorgesLM/moat
  v0.1.0` and building with `GOWORK=off` fails with
  `cannot use (*Store)(nil) ... *Store does not implement ratelimit.Store
  (missing method Take)`, the same error the published tag gave consumers.
  Restoring `v0.2.0` makes it pass.
- **A written release order** in `CONTRIBUTING.md` — tag core, bump the
  satellite require, green `released-satellites`, tag satellite, clean-room
  fetch — which removes the chicken-and-egg window rather than papering over it,
  since the core version the satellite names is already published when the bump
  is committed.
- **A visible bypass** for the one legitimate red case (a PR changing a core API
  and its consumers together): the `cross-module-window` label, chosen by a
  human and on the record.

The clean-room fetch keeps its place as the last step, but it is no longer the
*only* check that exercises inter-module resolution, which is what made it
load-bearing in a way a release step should not be.

### 6.17 R6: a review whose central finding was not reproducible

This round started from an external review that reported, with a table of
evidence, that the published `main` branch was missing much of the v0.2.0 work:
no `realip/`, no `secret/`, no `CHANGELOG.md`, a README declaring "Requires Go
1.25+" against a `go.mod` saying 1.24, no mention of `preset.Config.TrustedProxies`,
and a quick-start snippet in its pre-`secret.Value` form. The proposed conclusion
was that the `v0.2.0` tag was not an ancestor of `main` — that the published
module existed only on the tag, and the branch a visitor reads first described an
API the release no longer had. Everything else was to be blocked behind fixing it.

None of it reproduced. Recorded here in full, because a finding that was chased
and refuted is worth as much in this log as one that was fixed:

```
$ for t in $(git tag -l); do
    git merge-base --is-ancestor "$t" main && echo "$t -> ancestor" || echo "$t -> NOT ancestor"
  done
redisstore/v0.1.0 -> ancestor
redisstore/v0.2.0 -> ancestor
redisstore/v0.2.1 -> ancestor
v0.1.0 -> ancestor
v0.2.0 -> ancestor

$ git ls-tree -r --name-only main -- realip secret CHANGELOG.md
CHANGELOG.md
realip/realip.go
realip/realip_test.go
secret/mask_internal_test.go
secret/secret.go
secret/secret_test.go
```

Byte-identical to the same listing against `v0.2.0`. `main` is `dea0800`, two
commits *ahead* of the `v0.2.0` tag and one ahead of `redisstore/v0.2.1`; the
README says "The core module requires **Go 1.24+**", lists both `realip` and
`secret` in the package table, documents `TrustedProxies` in three places, and
its quick start decodes into `raw` before wrapping it with `secret.New`. The only
branches that are not merged are four Dependabot bumps, each a single commit
against `.github/workflows/ci.yml`.

The mechanism is mundane and worth naming so the next reader recognises it: the
review was working from a cached or stale view of the repository, one that
predates the release. Every individual observation in it was true of some earlier
state, which is exactly what makes that kind of report persuasive — it is
internally consistent, and it is consistent with a snapshot that really existed.

The generalisable lesson is not about that reviewer. It is that **a claim about
repository state is verifiable in one command, and a report that asserts one
without showing the command has not made a finding — it has made a hypothesis.**
The correct response was to run the commands before acting on the conclusion, and
the cost of not doing so would have been high: the proposed remediation was to
"bring the v0.2.0 work back to main", which against a `main` that already has it
means rewriting a correct branch on the strength of a stale reading.

Two smaller claims from the same review were also refuted by measurement rather
than argument, and both had been offered as near-certainties:

- **`redisstore/v0.1.0` "was probably published under the same unverified
  condition and may need retracting."** The premise is right — the `go.sum`
  evidence in §6.16 shows the core was never resolved outside the workspace, so
  the tag was never verified. The conclusion is wrong. Fetched from the proxy
  into a clean directory with `GOWORK=off`, it builds and `*Store` satisfies
  `ratelimit.Store`: it names the core at `v0.1.0`, which was consistent at the
  time. Correct by coincidence, but correct. No retract.

- **"Raise the `redisstore` `go` directive to 1.26.6."** The right action, for a
  reason the review did not give and that changes what the alternative would have
  been. Both GO-2026-6090 and GO-2026-5972 are fixed in **1.25.13 as well as
  1.26.6**, so a floor of `go 1.25.13` looks like the more conservative choice.
  It is not, and it would have been silently useless: Go orders versions across
  release lines, so `1.26.5` satisfies a `1.25.13` floor — and 1.26.5 has neither
  fix. Only 1.26.6 covers both lines. A "more conservative" floor here would have
  left the exact consumers most likely to be affected unprotected.

What the review got right, and what this round therefore acted on, is that
§6.16's close was a checklist item where a mechanism was available and known.
That is §6.0, and it is the substantive outcome of the round. The rest of the
work — the eviction check's skipped state becoming reportable, the toolchain
floor moving to the `go` directive, the compatibility table, the `realip`
examples, the split changelog — all stands on its own and is recorded in the
sections it belongs to.

#### Round summary

| # | Claim | Verdict |
|---|---|---|
| 1 | `main` is missing the v0.2.0 work; `v0.2.0` is not an ancestor | **Refuted.** All five tags are ancestors; `main` is two commits ahead |
| 2 | README contradicts `go.mod` on the Go floor | **Refuted.** README says 1.24+, matching `go.mod` |
| 3 | README lacks `secret`, `realip`, `TrustedProxies`; snippet is pre-M1 | **Refuted.** All present |
| 4 | §6.16 was closed with a checklist item where a mechanism was known | **Confirmed.** Closed with `released-satellites`, verified red (§6.0) |
| 5 | Satellites' `go.sum` never carried the core until `e7c8801` | **Confirmed.** Evidence in §6.16 |
| 6 | `redisstore/v0.1.0` may need retracting | **Refuted by clean-room build.** No retract |
| 7 | `redisstore` `go` directive should be 1.26.6 | **Confirmed**, for a sharper reason: 1.25.13 would not have worked |
| 8 | The eviction check is silent exactly where it matters | **Confirmed.** `Store.EvictionCheck` added |
| 9 | Versions have drifted, so a compatibility table is needed | **Confirmed.** Added; §8 corrected |
| 10 | `realip` has no examples | **Confirmed.** Three added |

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
- Each module is tagged independently (`v0.3.0`, `redisstore/v0.3.0`). That
  sentence was written when the numbers happened to match, and the example above
  reads as a convention of tagging in lockstep. **It is not one, and it no longer
  describes reality**: `redisstore/v0.2.1` was issued on its own to fix §6.16
  while the core stayed at `v0.2.0`, and the two have not been in step since.

  The consequence is worth stating rather than leaving to be inferred. Once the
  numbers diverge, a satellite's version carries no information about which core
  it works with — and the contract between them is an interface that has already
  broken once. So the mapping is written down explicitly, in the compatibility
  table in `redisstore/README.md`, and updating it is part of the release rather
  than documentation to catch up on afterwards. `CHANGELOG.md` is split by module
  for the same reason: a single timeline invites reading `redisstore/v0.2.1` as
  superseding the core's `v0.2.0`, when in fact it requires it.

- **Release order is specified** in `CONTRIBUTING.md`, and is a mechanism rather
  than a preference: tag the core, bump the satellite's `require`, wait for the
  `released-satellites` job, then tag the satellite. Doing it in another order is
  what produced §6.16.
- **`v0.1.0` (core) and `redisstore/v0.1.0` were tagged on the commit that
  closes §6.11** — after the rename to `moat`, after the `preset.API`
  ordering fix, and after both self-found bugs were verified and swept for
  recurrence — not on the commit that first implemented the library, and not
  on the commit that introduced the rename or the reorder in isolation. The
  tag marks the state that was actually verified end-to-end: renamed,
  reordered, and audited, with the full verification table re-run under the
  final module name rather than carried forward from an earlier pass.

---

## 9. Security posture and disclosure

This library is **not independently audited**. It implements well-understood
patterns carefully and documents its reasoning, which is not the same as a
security guarantee. `SECURITY.md` defines private vulnerability reporting;
issues affecting the security properties described here are handled there, not
in public issues.

### Pre-tag checklist item "audit in a clean session": NOT MET

Recorded as unmet rather than closed, because it was not met and the difference
matters.

Two adversarial passes were run over this library (§6.14, §6.15) and both found
real defects, including in code the reviewer had written — the shared rate-limit
bucket in `preset.API` and the package-scoped invariant guard were both caught
that way. So the passes were not worthless. But **both were performed by the same
agent that wrote the code**, which is precisely what the checklist item exists to
exclude.

The mitigation stated at the time — weight the packages the author had not
touched, re-read the code instead of recalling it — is honest and it addresses
*recall* bias: the risk of reviewing a remembered version rather than the real
one. It does not address the bias that actually matters here, which is in **where
one chooses to look**. An author's sense of which parts are worth attacking is
shaped by the same assumptions that produced the code, and the areas that feel
settled are exactly the ones that get a shorter look. No amount of discipline
inside the session corrects for that, because the omission is invisible from
inside it: you cannot notice the question you did not think to ask.

Concretely, both passes examined every package but produced findings concentrated
in composition and in documented-invariant coverage — the shapes the author had
been primed on by the preceding rounds. Whether the parsing and validation code
would survive a reviewer with different instincts is untested.

**What would close it:** a pass by a reviewer with no part in writing the code
and no access to this document's reasoning, working from the public API and the
README as a consumer would. Until then, §6.14 and §6.15 should be read as what
they are — structured self-review that found things — and not as an audit.

**Still not met as of R6.** R6 (§6.17) came from outside this session, which is
closer to the bar than §6.14 or §6.15 were, and it found one real thing: that
§6.16 had been closed with a checklist item where a mechanism was available. That
is worth something.

It does not close this item, for two reasons that should be stated rather than
glossed. The first is that it was the same model reviewing its own work from a
different session — a clean session is a weaker condition than an independent
reviewer, and with the same model on both sides it is close to the minimum that
could be called independent at all. The second is that its central finding, the
one everything else was staged behind, was not reproducible: it asserted a
repository state that a single `git merge-base` refutes, and it asserted it
without running one. A pass that opens with an unverified claim about
verifiable state has not demonstrated the property this item is asking for.

So the item stays open, and `v0.2.2` will ship with it open. Marking it met on
the strength of R6 would be exactly the kind of accounting the item exists to
prevent.

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

Instead, entries are held in a min-heap ordered by the instant each bucket
refills, so the buckets that are safe to forget accumulate at the root and are
reclaimed during `Take` in time proportional to the number actually expired.
Memory stays bounded by the key cap either way, and `Close` becomes optional
rather than load-bearing.

The ordering was a recency list until §6.12; reclaiming and evicting now read the
same structure, because a bucket that has been idle past the cutoff has also been
*full* past it. The proxy is conservative in the safe direction — a bucket in
debt when last touched carries a refill instant later than its last touch, so it
can outlive the TTL by up to one refill window. That is a memory question the key
cap already bounds, not a correctness one.

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

### 10.6 `preset.API` left a 429 without security headers — since fixed

**Superseded.** The order originally shipped put the rate limiter outermost, so
a rejected request short-circuited before the header middleware ran. A 429
therefore carried no CSP, no `nosniff`, and no framing protection. That was
recorded here as an accepted, deliberate trade-off — do not spend work on a
request you are about to reject — with the header middleware left available to
move first by hand for anyone who cared.

That trade-off was reconsidered and reversed rather than shipped. An error
response is still a response: it is exactly as capable of being framed, sniffed
as a different content type, or rendered without a CSP as a 200 is, and a
rejection is a well-known place for an attacker to look for exactly this kind
of gap — losing `nosniff` and the CSP there specifically is not the six map
writes are worth saving. `secureheaders` now runs outermost in `preset.API`
(§3.3), ahead of rate limiting, so every response the chain produces carries
the headers, including every rejection the middleware behind it write. The test
that pinned the old behavior — deliberately named for the fact that it
documented a bug rather than a feature — has been rewritten to assert the
opposite: that a 429 does carry the security headers.

This entry is kept rather than deleted for the same reason §6.10 was kept
after the rename in §10.10: a design record that quietly rewrites its own
history is worth less than one that shows the trade-off actually being made,
and then being unmade once it turned out not to be worth it.

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
`replace github.com/JonasBorgesLM/moat v0.1.0 => ./`, which can be dropped
once the tag exists. It lives in the workspace rather than in a module's
`go.mod` because a `replace` in a published `go.mod` is ignored by consumers and
only misleads them. CI recreates the workspace, since `go.work` is not
committed.

### 10.10 The name was `gosecure`, verified crowded, and replaced with `moat`

§6.10 asked for pkg.go.dev availability to be checked before the first tag.
That check happened against the original working name, `gosecure`, and the
result was unfavorable: at least fourteen distinct modules on pkg.go.dev
already use that name, unrelated to this project and to each other, and the
Go style guide separately discourages a `go`-prefixed package name regardless.
The module *path* was never at risk — `github.com/JonasBorgesLM/gosecure`
was unclaimed and namespaced by account like any other — but the package name
people type, import, and search for was not distinctive, and renaming after a
tagged release is expensive in a way that renaming before one is not.

Eight replacement candidates were checked the same way, against both
pkg.go.dev and a GitHub repository-name search, before picking one:

| Candidate | Verdict |
|---|---|
| `httpguard` | Rejected — `Laisky/go-httpguard`, an existing Go HTTP-protection/rate-limiting library. Same problem space. |
| `gatekeeper` | Rejected — dominated by OPA/Kubernetes Gatekeeper, extremely well known in Go cloud-native tooling. |
| `bastion` | Rejected — `ifreddyrondon/bastion` is an existing Go HTTP web framework with its own middleware. |
| `aegis` | Rejected — collides with a real AEAD cipher (`ericlagergren/aegis`, `philhofer/aegis`); misleading for a library with no encryption primitive of its own. |
| `parapet` | Rejected — `moonrhythm/parapet` is an actively maintained Go HTTP middleware/WAF library. Direct collision. |
| `rampart` | Rejected — `manimovassagh/rampart` provides JWT verification middleware for Go HTTP servers. Direct collision. |
| `warden` | Rejected — heavily used already for authorization frameworks and container engines; a Ruby-Warden middleware clone exists too. Crowded, generic. |
| `bulwark`, `redoubt`, `palisade`, `moat` | Clean or near-clean: no Go/HTTP-middleware collision on pkg.go.dev for any of the four. `bulwark` and `palisade` each carry a moderately known unrelated project in the broader security space (a cryptocurrency project and a vulnerability-management tool for the former; GCHQ's data-access-policy tool for the latter). `redoubt` and `moat` had the cleanest results of all eight candidates. |

`moat` was chosen from that final group: shortest, reads as a natural Go
identifier (`moat.New`, `moat.Chain`, `moat.API`), and is an apt metaphor for
what the library does — a moat is a protective barrier around what it
defends, the same role this library's middleware plays around an
`http.Handler`. Its one soft collision, `laravel/moat` (a GitHub-organization
security-posture scanner), is a different language and a different kind of
tool, unlikely to be confused with a Go HTTP-middleware import.

The rename touched every module path, the package declaration, the protocol-
level CSRF cookie and field name defaults (`gosecure.csrf` →
`moat.csrf`, `__Host-gosecure.csrf` → `__Host-moat.csrf`), the Redis key
prefix, and the `cmd/gosecure-secret` binary (renamed to `cmd/moat-secret`).
It was done before the first tag specifically so that none of those were ever
part of a released, importable API.

### 10.11 Every CSPRNG error path in the core is unreachable at the Go 1.24 floor

As of Go 1.24 `crypto/rand.Read` is defined never to fail. The signature still
returns an error for compatibility, but a system entropy source that cannot be
read now crashes the program irrecoverably instead of returning one. At the
module's declared floor of 1.24 (§6.7), therefore, every error branch hanging off
a CSPRNG call in the core module is dead code:

| Site | Dead branch |
|---|---|
| `csrf.GenerateSecret` (`csrf.go:255`) | the returned error |
| `csrf.newCookieValue` (`csrf.go:528`) | the rejection, and `Rotate` returning an error |
| `secureheaders.newNonce` (`secureheaders.go:244`) | the whole `WithNonceErrorHandler` apparatus |

**They are staying.** They cost nothing, they are correct, and they are the
difference between a clean upgrade and a silent regression if the standard
library's contract ever moves again. This entry exists so that nobody spends an
afternoon trying to raise coverage over them from the outside: they cannot be
provoked through the public API, only by injecting a failing source — which is
what `secureheaders`'s unexported `withNonceSource` hook exists for, and how
`TestEveryResponseCarriesTheFullHeaderSet` reaches the nonce rejection.

**One of them was not harmless and has been removed.** `secret`'s process key
fell back to a fixed byte pattern, `byte(i*31+7)`, on CSPRNG failure. Had it ever
run, every `Value` in the process would have been masked under a publicly
derivable keystream, and the two accepted leak paths — the `%p`/`%w` bad-verb
dump and the unexported-field dump (§4.8) — would have gone from revealing
nothing to revealing everything, with no signal that anything had changed. That
is a fail-open default inside a library whose stated posture is fail-closed, and
"defence in depth" was the wrong label for it: a mask an observer can derive is
not a weaker mask, it is the appearance of one.

It now panics. That is a deliberate exception to the rule that a library must not
abort its host, and it is narrow: a process that cannot obtain entropy cannot
generate CSRF secrets or nonces either and has no business serving requests, and
the standard library already reached the same conclusion for the same reason.
The neighbouring fallback in `secret`'s nonce counter is *kept*, because it fails
open on nothing — a failed seed costs a cosmetic property while uniqueness, the
property the security argument rests on, comes from the counter regardless.
