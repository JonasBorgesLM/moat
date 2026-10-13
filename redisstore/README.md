# `moat/redisstore`

A Redis-backed [`ratelimit.Store`](https://pkg.go.dev/github.com/JonasBorgesLM/moat/ratelimit#Store)
for [`moat`](https://github.com/JonasBorgesLM/moat), atomic via a Lua script, so
that a rate limit is shared across every instance of an application instead of
enforced separately by each one.

It is a **separate module** so that `go-redis` never appears in the `go.sum` of
consumers who only import the core packages. See `doc/DESIGN.md` §2.

```sh
go get github.com/JonasBorgesLM/moat/redisstore
```

---

## Compatibility

The two modules are tagged independently, and their version numbers have already
diverged — `redisstore/v0.2.1` requires the core at `v0.2.0`. That is not a
mistake to be tidied up later; it is what independent tagging means. It does mean
the version number on its own tells you nothing about which core it works with,
and the contract between them is an interface that has broken once already
(`ratelimit.Store.Take` became `TakeN` in the core's v0.2.0), so the mapping is
written down rather than inferred.

| `redisstore` | requires core | Go toolchain floor | Notes |
|---|---|---|---|
| `v0.2.2` | `v0.2.0` | **1.26.6** | Adds `Store.EvictionCheck`. Raises the `go` directive to enforce the stdlib floor below. |
| `v0.2.1` | `v0.2.0` | 1.25.0 (not enforced) | First version that actually compiles against the core it names. |
| `v0.2.0` | `v0.1.0` | 1.25.0 (not enforced) | **Retracted, does not compile.** It names a core whose `ratelimit.Store` still declares `Take`, so `*Store` does not satisfy the interface. See `doc/DESIGN.md` §6.16. |
| `v0.1.0` | `v0.1.0` | 1.25.0 (not enforced) | Compiles; verified from a clean directory against the proxy. |

Go's minimal version selection takes the highest requirement in the build, so a
consumer who imports `redisstore` gets at least the core version in the table
even if they also require an older one directly.

## Go toolchain floor

**This module requires Go 1.27.2 or newer**, declared in its `go` directive.
The core declares the same floor, for its own reasons (`SECURITY.md`).

The reason is a security one rather than a language-feature one. This module
reaches `crypto/tls` through `go-redis`, `encoding/asn1` through certificate
parsing on a TLS connection to Redis, and `net/http`. Each carries known
vulnerabilities:

| ID | Package | Fixed in |
|---|---|---|
| [GO-2026-6090](https://pkg.go.dev/vuln/GO-2026-6090) | `crypto/tls` — unbounded post-handshake messages | 1.25.13, 1.26.6 |
| [GO-2026-5972](https://pkg.go.dev/vuln/GO-2026-5972) | `encoding/asn1` — unbounded recursion depth | 1.25.13, 1.26.6 |
| [GO-2026-6607](https://pkg.go.dev/vuln/GO-2026-6607) | `crypto/tls` — malformed ECH outer extension references | 1.26.9, 1.27.2 |
| [GO-2026-6617](https://pkg.go.dev/vuln/GO-2026-6617), [-6613](https://pkg.go.dev/vuln/GO-2026-6613), [-6612](https://pkg.go.dev/vuln/GO-2026-6612), [-6611](https://pkg.go.dev/vuln/GO-2026-6611), [-6603](https://pkg.go.dev/vuln/GO-2026-6603) | `net/http` — HTTP/1 and HTTP/2 server | 1.26.9, 1.27.2 |

Two details in how that floor is declared, both deliberate:

- **It is the `go` directive, not `toolchain`.** A `toolchain` line in a
  dependency is ignored by whoever imports it, so declaring the floor there
  protected this repository's CI and nobody else's build. The `go` directive is
  honoured: under the default `GOTOOLCHAIN=auto` a consumer on an older toolchain
  downloads and switches to a conforming one, and under `GOTOOLCHAIN=local` they
  get an explicit refusal rather than a silently vulnerable binary.

- **It is 1.27.2, not 1.26.9**, even though 1.26.9 also carries every fix. Go
  orders versions across release lines, so a floor of `1.26.9` is satisfied by
  `1.27.0` and `1.27.1`, which have none. Only 1.27.2 covers both lines. (1.26.6
  was chosen over 1.25.13 before for the same reason.)

If a 1.27.2 floor is not workable for you, pin an older tag and enforce
the toolchain version in your own build. What you must not do is assume the
older tag is safe because it declares a lower number; it is the same code with
an unenforced floor.

## Eviction policy

Redis running under `maxmemory` with any eviction policy other than `noeviction`
will discard rate-limit buckets to reclaim memory, and a discarded bucket hands
its client a fresh full burst. Worse, the eviction lands on whichever bucket is
least recently used or nearest to expiry — which, since every bucket's TTL is
refreshed on every call, is whichever client was most recently throttled. The
limit becomes advisory at exactly the moment it is doing the most work.

`New` refuses to build a `Store` against a server it can see is configured this
way, returning `ErrUnsafeEvictionPolicy`. `InsecureAllowKeyEviction()` is the
only way past, and is named to be noticed at the call site.

**The check is best-effort, and it is quietest where it matters most.** It is
skipped whenever the answer cannot be established: `CONFIG` disabled or renamed
(the normal case on ElastiCache, MemoryDB, Upstash and Azure Cache), a server
unreachable at construction, a client that cannot issue `CONFIG` at all, or a
reply that is not understood. Those are the managed platforms most production
deployments run on, so the check tends to fire in local Docker and stay silent in
production.

Since v0.2.2 a skipped check is reportable rather than implicit:

```go
store, err := redisstore.New(client)
if err != nil {
    return err // includes ErrUnsafeEvictionPolicy
}
if check := store.EvictionCheck(); !check.Verified() {
    log.Printf("redisstore: eviction policy unverified (%s); "+
        "confirm maxmemory-policy is noeviction on every node", check)
}
```

Two gaps a *verified* result does not close, and neither is closable from inside
a library:

- **It is a snapshot, not an invariant.** It describes the server's mutable
  runtime state at construction. `CONFIG SET maxmemory-policy allkeys-lru` is one
  command away, and a memory incident is when it is most likely to be run —
  exactly when the bypass matters. Nothing re-checks afterwards. A process
  restarting during that incident also constructs its store against an
  unreachable Redis, skips the check, and comes up unverified.
- **Cluster membership is checked once.** Every master reachable at construction
  is asked, and only then. A node that joins later, or a replica promoted by
  failover with a different configuration, is not covered — and failover is also
  a thing that happens during memory incidents.

If you need the stronger property, assert `maxmemory-policy noeviction` from
configuration management, where it is an invariant rather than an observation.

## Security

Vulnerability reporting for this module follows the root
[`SECURITY.md`](../SECURITY.md), which also records the toolchain floor above as
a supported-versions statement.
