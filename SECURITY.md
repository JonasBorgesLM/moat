# Security Policy

## This library has not been independently audited

Stated plainly, up front, because it is the single most important thing to know
before depending on this code:

**`moat` has not been reviewed by an independent security auditor.** It
implements well-understood patterns — token-bucket rate limiting, signed
double-submit CSRF tokens, `os.Root`-based path containment — carefully, and it
writes down its reasoning in [`doc/DESIGN.md`](./doc/DESIGN.md) so that the
reasoning can be checked rather than trusted. That is not the same as a security
guarantee, and it should not be read as one.

Treat this the way you should treat any security dependency: read the code, read
the design record, and satisfy yourself that it does what you need. If you find
that it does not, the process below is how to tell us.

## Supported versions

The project is pre-1.0. Only the latest tagged minor version of each module
receives security fixes.

| Module | Supported |
|---|---|
| `github.com/JonasBorgesLM/moat` (core) | latest `v0.x` tag |
| `github.com/JonasBorgesLM/moat/redisstore` | latest `redisstore/v0.x` tag |
| `examples/` | not supported; illustrative code, not a released artifact |

Older `v0.x` tags are not patched. Because the API may still change between
minor versions, upgrading is the fix.

`redisstore/v0.2.0` is **retracted** and does not compile; see
`doc/DESIGN.md` §6.16. `go get` will not select it, but a `go.mod` that pins it
explicitly still needs changing.

### Required Go toolchain

The toolchain a consumer builds with is part of this library's security posture,
because the standard library is where most of the reachable vulnerability surface
lives — the core module has no external dependencies at all.

| Module | `go` directive | Why |
|---|---|---|
| `github.com/JonasBorgesLM/moat` (core) | **1.24** | The floor set by `os.Root`, which `pathguard` is built on. No dependencies, and neither `crypto/tls` nor `encoding/asn1` is reachable from it. |
| `github.com/JonasBorgesLM/moat/redisstore` | **1.26.6** | Reaches `crypto/tls` via `go-redis` and `encoding/asn1` via certificate parsing. [GO-2026-6090](https://pkg.go.dev/vuln/GO-2026-6090) and [GO-2026-5972](https://pkg.go.dev/vuln/GO-2026-5972) are fixed in 1.25.13 and 1.26.6. |

Two things about the `redisstore` floor are worth stating explicitly, because
both were wrong in `redisstore/v0.2.1` and earlier:

- It is declared in the **`go` directive**, not `toolchain`. A `toolchain` line
  in a dependency is ignored by whoever imports it, so a floor declared there
  protects this repository's CI and nobody else's build. That was the state up to
  `redisstore/v0.2.1`: the two vulnerabilities above were fixed for the
  maintainer and for no consumer. The `go` directive is honoured — under the
  default `GOTOOLCHAIN=auto` an older toolchain is upgraded automatically, and
  under `GOTOOLCHAIN=local` the build fails with a clear message.
- It is **1.26.6, not 1.25.13**, though both carry the fixes. Go orders versions
  across release lines, so a floor of `1.25.13` is satisfied by `1.26.5`, which
  has neither fix.

If you build `redisstore` with an older toolchain by overriding this, both
vulnerable paths are reachable in your binary regardless of what this library
does.

## Reporting a vulnerability — privately

**Do not open a public issue, pull request, or discussion for a security
problem.** A public report is a disclosure: it tells everyone running the
affected version, including people looking for something to exploit, before
there is a fix to upgrade to.

Report privately through **GitHub's private vulnerability reporting**:

1. Go to <https://github.com/JonasBorgesLM/moat/security/advisories/new>
   (or the repository's **Security** tab → **Report a vulnerability**).
2. Fill in the advisory form. The report is visible only to the maintainers
   until it is published.

This channel requires a GitHub account and needs no key exchange or mailing
list, which is why it is the primary one. If you cannot use it, open a public
issue containing **only** a request for a private contact channel and no
technical detail whatsoever, and a maintainer will follow up.

### What to include

The more of this you can provide, the faster the fix:

- Affected module, package, and version or commit.
- The security property you believe is violated — for example "the rate limiter
  can be bypassed", "CSRF tokens validate across origins", "a path escapes the
  root".
- A minimal reproduction: ideally a failing Go test, otherwise concrete steps.
- Impact as you see it, and any conditions required (a specific `GOOS`, a
  particular configuration, a non-default option).
- Whether you intend to disclose publicly on your own schedule, and when.

You do not need a working exploit. A precise description of an unsound argument
in `doc/DESIGN.md` is a legitimate report; for a security library the reasoning
is part of the product.

### What to expect

| Stage | Target |
|---|---|
| Acknowledgement that the report was received | 3 business days |
| Initial assessment: confirmed, needs info, or not a vulnerability | 10 business days |
| Fix released, or a written plan with a date if the fix is complex | 90 days from confirmation |

These are targets from a small volunteer project, not a contractual SLA. If a
deadline passes without a response, the report was probably lost — please ping
the advisory thread.

We will keep you updated as the assessment progresses, credit you in the
advisory unless you ask us not to, and let you review the advisory text before
it is published.

## Coordinated disclosure

We ask for the industry-standard **90 days** from confirmation before public
disclosure, and will usually publish sooner. If a fix is going to take longer
than that, we will say so and explain why rather than let the clock run out
silently. If a vulnerability is being actively exploited, we will move as fast
as we can and disclose immediately after the fix ships.

When a fix ships we publish a GitHub Security Advisory with a CVE where one is
warranted, so that `govulncheck` and dependency scanners can see it. A security
fix that nobody's tooling can detect is only half a fix.

## Scope

**In scope** — a failure of any security property this library claims:

- Rate limits that can be bypassed, including via key derivation, store
  eviction, or a race in `Take`.
- CSRF tokens that validate when they should not: cross-origin, cross-user,
  forged, replayed after secret rotation, or accepted with a mismatched cookie.
- Timing side channels in token or secret comparison.
- Any input that causes `pathguard` to read, write, or reveal the existence of a
  file outside its root, including via symlinks, `..`, absolute paths, Windows
  device names, or a TOCTOU race.
- Response headers that are omitted, malformed, or weaker than documented.
- `validate` guards that can be evaded — an unbounded body read past
  `MaxBodyBytes`, a content-type check that a real parser disagrees with.
- Panics reachable from untrusted input. The library must not panic in normal
  operation; a remotely triggerable panic is a denial of service.
- Unbounded memory growth driven by attacker-controlled input.
- Anything in `doc/DESIGN.md` that is factually wrong about a threat.

**Out of scope** — real concerns, but not defects in this library:

- The absence of features it explicitly does not provide: it is not a WAF, an
  IDS, a session manager, an authenticator, or an HTML sanitizer
  (see `doc/DESIGN.md` §1 and §6.4).
- Limitations that are documented as such, unless you can show the
  documentation is wrong. Notably: `MemoryStore` is per-process; same-origin XSS
  defeats CSRF protection entirely; `pathguard` constrains paths and does not
  sandbox the process.
- Vulnerabilities in `go-redis`, or in any dependency of the `examples/` module.
  Report those to their maintainers; if the flaw is in how we *use* them, that
  is in scope.
- Insecure configuration chosen deliberately by an application — for example
  `WithFailureMode(FailOpen)`, `WithoutCSP()`, or a `KeyFunc` that trusts
  `X-Forwarded-For` unconditionally. If a *default* is unsafe, that is in scope
  and we want to hear it.
- Findings from a scanner with no accompanying analysis of exploitability.

## Safe harbor

We will not pursue or support legal action against anyone who reports in good
faith through the channel above, tests only against their own deployment, avoids
privacy violations and service degradation, and gives us reasonable time to fix
the issue before disclosing.

There is no bug bounty. This is an unfunded project; we can offer credit,
a public thank-you, and a fast fix.
