// Package moat is the documentation root for a collection of composable
// HTTP security middleware for Go. It contains no code; every feature lives in
// a subpackage that can be imported on its own.
//
// The core module depends on the Go standard library only. This is a
// supply-chain decision: a security library that pulls in transitive
// dependencies asks you to trust code neither you nor its author has read.
// The optional Redis-backed rate-limit store lives in a separate module
// (github.com/JonasBorgesLM/moat/redisstore) so that go-redis never appears
// in your go.sum unless you ask for it.
//
// # Packages
//
//   - [github.com/JonasBorgesLM/moat/middleware]: Chain, a flat and
//     order-explicit composition helper.
//   - [github.com/JonasBorgesLM/moat/preset]: helmet.js-style bundles that
//     refuse to build a chain with a silently missing protection.
//   - [github.com/JonasBorgesLM/moat/ratelimit]: token-bucket rate limiting
//     with a pluggable, context-aware store.
//   - [github.com/JonasBorgesLM/moat/csrf]: stateless CSRF protection via a
//     signed double-submit cookie plus Origin/Referer validation.
//   - [github.com/JonasBorgesLM/moat/secureheaders]: CSP, HSTS, framing,
//     nosniff, Referrer-Policy and Permissions-Policy.
//   - [github.com/JonasBorgesLM/moat/validate]: composable field rules and
//     HTTP body guards.
//   - [github.com/JonasBorgesLM/moat/sanitize]: normalization of text that
//     is expected to be plain. Not an HTML sanitizer.
//   - [github.com/JonasBorgesLM/moat/pathguard]: traversal- and TOCTOU-safe
//     resolution of user-supplied paths under a root.
//
// # Conventions
//
// Every middleware is a plain decorator, func(http.Handler) http.Handler, so it
// composes with net/http, chi, gorilla/mux and anything else following that
// convention without adapters.
//
// The library never logs, prints, or panics in normal operation. Errors are
// returned or surfaced through hooks such as ratelimit.WithOnError, leaving
// observability entirely to the host application.
//
// Defaults are the secure choice. Loosening one is always an explicit,
// greppable opt-in, so that forgetting to configure something leaves you on the
// safe path and relaxing a control is visible in code review.
//
// # Threat model
//
// This library implements well-understood patterns carefully; it is not a WAF,
// not an IDS, and not a substitute for defense in depth. It has not been
// independently audited. The design record, including the audit that reshaped
// several of these APIs, is in doc/DESIGN.md. Per-package documentation states
// the specific attacks each component does and does not defend against.
package moat
