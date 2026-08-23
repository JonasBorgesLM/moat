# Contributing

Thanks for considering it. This is a security library, so a few of the rules
below are stricter than you may be used to. They exist because the cost of a
quiet mistake here is paid by someone else's users.

**Found a vulnerability? Stop and read [`SECURITY.md`](./SECURITY.md) instead.**
Do not open a public issue or pull request for it.

## The short version

1. The core module imports the standard library and nothing else.
2. Every exported symbol has a doc comment. For anything security-relevant, the
   comment explains the threat, not just the signature.
3. Tests cover the attacks a component defends against, not only the happy path.
4. A change to a security property comes with a matching change to
   [`doc/DESIGN.md`](./doc/DESIGN.md). The reasoning is part of the deliverable.
5. The library never logs, prints, or panics in normal operation.

## Getting set up

```sh
git clone https://github.com/JonasBorgesLM/moat
cd moat
go work init . ./redisstore ./examples   # if go.work is not already present
go test ./...
```

`go.work` is deliberately **not committed**: it is a local development
convenience, and a committed workspace file changes how the modules resolve for
everyone who clones the repo. Create your own.

Because this is a multi-module repository, `go test ./...` at the root **does
not descend into `redisstore/` or `examples/`**. Test each module:

```sh
go test -race ./...
(cd redisstore && go test -race ./...)
(cd examples   && go test -race ./...)
```

Integration suites sit behind a build tag so that the default run needs no
Docker and no network:

```sh
go test -tags=integration ./integration/...
(cd redisstore && go test -tags=integration ./...)
```

You need **Go 1.26.6 or newer** to work in this repository, because `redisstore`
declares that floor (see `redisstore/README.md` for why). The core module itself
still requires only 1.24, and that is checked separately in CI. If `go work init`
complains that a module requires a newer Go than the workspace lists, the fix is
`go work edit -go=1.26.6`.

### Working the way a consumer resolves

Every command above runs inside the workspace, where the satellites resolve the
core from the **working tree** and their `require` lines on it are inert. That is
the convenience; it is also a blind spot, and it is the one that shipped
`redisstore/v0.2.0` broken (DESIGN.md §6.16). To resolve the way a consumer does:

```sh
(cd redisstore && GOWORK=off go build ./... && GOWORK=off go test ./...)
(cd examples   && GOWORK=off go build ./... && GOWORK=off go test ./...)
```

That is what the `released-satellites` CI job runs, so a failure there reproduces
here. Note that a cross-module change will fail this until the core carrying it
is tagged — see "Release order" below; that is the job working, not a broken
setup.

## The dependency rule

**The core module depends on the Go standard library only.** This is not
minimalism for its own sake. Go resolves dependencies per module, so anything in
the core `go.mod` appears in the `go.sum` of every consumer — and in their SBOM,
their Dependabot alerts, and their `govulncheck` output — even if they only
import `secureheaders`. Keeping the core at zero dependencies makes that claim
literally true and machine-verifiable, and keeps the whole implementation
auditable in one sitting.

Practically:

- A pull request that adds a `require` line to the root `go.mod` will be
  declined. If you need a third-party library, the feature belongs in its own
  module, the way `redisstore/` does.
- `redisstore/` may depend on `go-redis`. `examples/` may depend on the
  frameworks it demonstrates. Neither may be imported by the core.
- Test-only dependencies count. Use the standard library's `testing`,
  `net/http/httptest`, and hand-written helpers.

## Code standards

### Doc comments carry the threat model

Every exported identifier needs a doc comment, and `go vet` is not the standard
here — the standard is that a reader can tell **what breaks if they get this
wrong**. Compare:

```go
// WithKeyFunc sets the key function.                     // useless
```

```go
// WithKeyFunc replaces the function that derives a bucket key from a request.
//
// The default deliberately ignores X-Forwarded-For because it is supplied by
// the client: keying on it lets an attacker present a new identity with every
// request and bypass the limit entirely. Only read a forwarded header after
// verifying that r.RemoteAddr belongs to a proxy you control.
```

The second one prevents a real, common, catastrophic misconfiguration. That is
the bar.

### Middleware shape

Every middleware is `func(http.Handler) http.Handler`. No custom handler types,
no framework interfaces in the core. Framework glue lives in `examples/` as
compiled, tested code — never as prose in a README, which rots into confidently
wrong advice.

Middleware must not consume the request body unless it is rejecting the request:
the handler behind it usually needs the body too.

### No logging, no printing, no panicking

The library never writes to stdout or stderr and never holds a logger. Errors
are returned, or surfaced through hooks such as `ratelimit.WithOnError`, so the
host application owns observability. A library that prints is unusable in a
serious application, and a library that panics on untrusted input is a denial of
service.

Panicking on a programmer error at construction time is also out: constructors
return errors, or clamp obviously-invalid values to their **safe** extreme and
document that they do.

### Secure by default

A default is the behavior someone gets when they have not thought about the
question. It must be the safe one. Every relaxation is an explicit, named,
greppable opt-in, so that it is visible in code review — `WithoutCSP()`,
`DisableCSRF: true`, `FailOpen`. If you find yourself adding a default that is
convenient rather than safe, that is a design discussion for an issue first.

### Errors

Return errors; wrap with `%w` so `errors.Is` works across package boundaries.
Do not put attacker-controlled input into an error string that might be returned
to the client — an error message that echoes the request is a reflection
primitive.

## Tests

`go test -race ./...` must pass before you open a pull request, in every module
you touched.

### Table-driven where it fits

Most tests here are a slice of cases with a name, an input, and an expectation.
Use `t.Run` so a failure names itself.

### Attack cases are mandatory

A test that only proves the feature works when used correctly does not tell us
whether the security property holds. Every component needs tests for what it
defends against. For example:

- `ratelimit`: spoofed `X-Forwarded-For` does not mint a fresh bucket;
  concurrent `Take` calls never exceed the burst; an unbounded stream of distinct
  keys does not grow the store without bound; an idle bucket is not discarded
  before it would have refilled.
- `csrf`: a token from another user, another origin, or a rotated secret is
  rejected; a missing cookie is rejected; comparison is constant-time.
- `pathguard`: `../`, absolute paths, symlinks pointing outside the root, and
  encoded traversal all fail to escape.
- `validate`: a body one byte over the limit is rejected, and a lying
  `Content-Length` does not get past the reader.

If you fix a bug, the regression test should demonstrate the attack, not just
the symptom.

### Examples are tests

Every public package has at least one `ExampleXxx` in a `_test.go` file. They are
compiled by `go test` and rendered on pkg.go.dev, which is what keeps the
documentation from drifting away from the API.

Examples that depend on wall-clock timing or on the network are written
**compile-only** — no `// Output:` line — rather than as flaky tests. A flaky
example teaches contributors to ignore red CI, which is a security problem
eventually.

### Fuzzing

`pathguard`, `validate` and `sanitize` carry fuzz targets, and they are treated
as a security control rather than decoration. "No input ever resolves outside
the root" is a far stronger claim than a handful of `../../` cases. If you touch
those packages, run the corpus:

```sh
go test -fuzz=FuzzResolve -fuzztime=60s ./pathguard
```

Add any input that finds a bug to `testdata/fuzz/` as a seed.

## Review checklist

Two bugs were found and fixed during initial implementation, in places no fuzz
target covers. Both are the kind of thing that is obvious once flagged and
easy to reintroduce by copy-paste without a reviewer having seen the original
finding. Check for both, on every PR that touches the relevant code:

- **TTL-based eviction must never fire before a bucket's next scheduled
  refill.** The bug: `ratelimit.MemoryStore` originally expired an idle bucket
  after a flat `idleTTL`, with no floor at how long the bucket actually takes
  to refill. A throttled client could wait out the TTL and get a fresh
  allowance before it had genuinely earned one — a rate-limit bypass reachable
  by doing nothing but waiting. Fixed by taking the cutoff as
  `max(idleTTL, refillWindow)` in both `ratelimit.MemoryStore.reclaim` and
  `redisstore.Store.ttlMillis`; regression-tested by
  `TestMemoryStoreDoesNotForgetUnrefilledBuckets` and
  `TestTTLCoversTheRefillWindow` respectively.

  **If a PR adds or touches any Store implementation, cache, or other
  structure with TTL-based expiry:** confirm by inspection that eviction
  cannot fire before whatever state it holds would naturally have reset or
  refilled on its own — and if there is no such natural reset (a plain cache,
  not a rate limiter), confirm that expiring early is actually harmless for
  that data before waving it through. There is no fuzz target for this and
  none is planned — it is a property about scheduling relative to
  configuration, not about input shape — so this is a human read of the
  eviction logic, every time, not a one-time fix.

- **Every `http.Server` needs `ReadHeaderTimeout`, `ReadTimeout`,
  `WriteTimeout`, and `IdleTimeout`.** The bug: a `redisstore` doc example used
  bare `http.ListenAndServe` with no timeouts at all — the exact anti-pattern
  `examples/basic` has a comment warning against, in the same repository.
  net/http sets none of these by default; without them a slow client holds a
  connection open indefinitely, which is a denial of service no middleware in
  this library can see or prevent.

  CI's `gosec` step already catches the two most common shapes of the missing
  half of this — `G114` for a bare `http.ListenAndServe`/`ListenAndServeTLS`
  call, `G112` for an `&http.Server{}` literal with no `ReadHeaderTimeout` — so
  a PR that omits `ReadHeaderTimeout` entirely will fail CI on its own.
  **`ReadTimeout`, `WriteTimeout`, and `IdleTimeout` are not checked by
  anything.** When reviewing a PR that adds or edits an `http.Server` or a call
  to `http.ListenAndServe`/`ListenAndServeTLS` anywhere in the repo — most
  likely in `examples/`, but check `redisstore`'s doc examples too — confirm
  all four are set, not just the one gosec would have caught for you.

- **Example and documentation code must never name a variable after an imported
  package.** The bug: `secret, err := loadSecret()` in a file that imports
  `moat/secret`. It compiles, because the shadow only bites if the package is
  referenced later in the same scope — so the compiler, `go vet`, `staticcheck`
  and `gosec` all stay silent, and the snippet ships. It surfaced four separate
  times in one release cycle (`examples/echo`, `examples/gin`, `examples/basic`,
  and a README snippet), each time found by hand rather than by tooling, and the
  README one did not compile at all when it was finally extracted and built.

  This matters more in example code than in library code because examples are
  copied. A reader who pastes `secret, err := ...` into a file that goes on to
  call `secret.New` gets a confusing compile error in *their* code, not ours.

  **On any PR touching `examples/`, a doc comment, or the README:** check that
  no local variable, parameter, or short-variable declaration shares a name with
  an imported package. `key` for a `secret.Value`, `rl` for a limiter, `v` for a
  `validate` result. Struct fields are fine — `p.secret` is reachable only
  through its receiver and shadows nothing — so do not "fix" those.

## Design changes

[`doc/DESIGN.md`](./doc/DESIGN.md) is the authoritative record of what the
library does and **why**, including the alternatives that were rejected and the
audit findings that reshaped several APIs. It is not generated from the code and
it is not optional reading.

If your change affects a security property, an API shape, or a default, update
`doc/DESIGN.md` in the same pull request. State the reasoning and, if you are
overturning an earlier decision, say which one and why it was wrong. A reviewer
should be able to audit the argument, not just the diff.

For anything larger than a bug fix, open an issue first. It is much cheaper to
disagree about a design in an issue than in a finished pull request.

## Pull requests

- One logical change per pull request.
- Explain the threat or bug in the description, not only the mechanism.
- `gofmt` (not just `go fmt` on your editor's whim), `go vet`, and the linters
  in CI must be clean.
- CI runs, per module: `go vet`, `staticcheck`, `gosec`, `go build`,
  `go test -race -cover`, a short fuzz run, and `govulncheck`.
- **All CI tooling is version-pinned.** Do not add a step that runs
  `go install some/tool@latest`: it is non-reproducible, and it means a
  compromise of that tool's repository executes in our CI. That is precisely the
  supply-chain risk this project exists to take seriously.

## Commit messages

Short imperative subject, prefixed with the package: `ratelimit: fail closed
when the store errors`. Explain *why* in the body if it is not obvious. Link the
issue.

## Versioning

Modules are tagged independently: `v0.3.0` for the core, `redisstore/v0.3.0` for
the store. The project stays on `v0.x` until the API has been used in anger;
claiming `v1` early is a compatibility promise we are not yet in a position to
keep. Post-v1, a breaking change needs a new major version and module path
suffix.

Independent tagging means the version numbers of the core and a satellite carry
no compatibility information about each other — `redisstore/v0.2.1` requires the
core at `v0.2.0`, and they will keep drifting. The compatibility table in
`redisstore/README.md` is where that information lives, and it is part of the
release, not documentation to be caught up on later.

## Release order

The order below is not a preference. Doing it in a different order is what
shipped `redisstore/v0.2.0` broken (DESIGN.md §6.16), and it is the reason the
`released-satellites` CI job exists.

Releasing the core and a satellite together:

1. **Tag and push the core** (`v0.3.0`), annotated and signed, with a real
   message — see "Tags are signed" below.
2. **Bump the satellite's `require`** on the core to that version, in its own
   commit, and run `go mod tidy` in the satellite directory with `GOWORK=off` —
   `tidy` ignores `go.work`, but `GOWORK=off` also makes `go list`/`go build`
   in the same shell resolve the way a consumer does.
3. **Wait for `released-satellites` to go green** on that commit. It resolves
   the satellite against the proxy at the version its `go.mod` names, which is
   the only check in the pipeline that exercises cross-module resolution at all.
4. **Tag and push the satellite** (`redisstore/v0.3.0`), same conditions as
   step 1.
5. **Clean-room fetch** both from the proxy, into a directory outside the repo,
   and run real code against them.
6. **Publish a GitHub Release** for each new tag, with the module's section of
   `CHANGELOG.md` in the body. The release body is GitHub metadata and stays
   editable after the fact; the tag message does not.

### Tags are signed

Release tags are **annotated and signed**, using SSH signing with the
maintainer's ed25519 key registered on GitHub as a signing key:

```sh
git config gpg.format ssh
git config user.signingkey ~/.ssh/id_ed25519.pub
git config tag.gpgsign true
```

With `tag.gpgsign` on, `git tag -a` signs without being asked. Verify before
pushing — a signature nobody checks is decoration:

```sh
git tag -v redisstore/v0.3.0     # wants: Good "git" signature ...
```

`git tag -v` needs `gpg.ssh.allowedSignersFile` pointing at a file mapping the
signing identity to its public key, or it will report the signature as being
from an unknown key. GitHub shows a **Verified** badge on the tag independently
of that local setting.

**Write a real tag message.** It is the one part of a release that cannot be
corrected afterwards: once the module proxy has fetched a version, the tag is
immutable in practice, and deleting or moving it makes the proxy serve something
the repository no longer shows — strictly worse than the original mistake. A
placeholder in a tag message is permanent. `redisstore/v0.2.2` shipped with a
literal `...` as its message and unsigned, and both are now uncorrectable for
that version; the notes live in its GitHub Release instead.

Tags already published are never re-signed or moved, for the same reason. The
policy applies from the next tag forward.

Done in that order there is no window where CI is legitimately red: the core
version the satellite names is already published at the moment the bump is
committed. If you find yourself wanting to bump the require *before* tagging the
core, stop — that is the failure mode itself.

### When red is expected

One case is legitimate: a PR that changes a core API and its satellite consumers
together, before the core carrying that change is tagged. The satellite's
require still names the previous core, so `released-satellites` fails, correctly.

Label that PR `cross-module-window` and the job skips. Do not disable the job,
do not weaken it to a warning, and do not merge with the label still on a branch
that no longer needs it — the label is visible on the PR precisely so that the
skip is a thing somebody chose, in the same spirit as
`redisstore.InsecureAllowKeyEviction`. After merging, follow the release order
above; the label is not a substitute for step 3.

## License

By contributing you agree that your contributions are licensed under the MIT
License, the same as the rest of the project.
