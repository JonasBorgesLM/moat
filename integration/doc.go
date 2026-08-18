// Package integration holds end-to-end tests that exercise the whole library
// through a real HTTP server and a real client.
//
// Everything here is behind the `integration` build tag, so the default
// `go test ./...` stays fast and needs no infrastructure. Run this suite with:
//
//	go test -tags=integration -race ./integration/...
//
// The unit suites prove each component in isolation. This one exists because
// the failures that matter most in a security library are the ones that only
// appear when the pieces are wired together: a middleware ordering mistake, a
// cookie attribute that stops a real browser from sending anything back, a
// token that verifies in a handler test but never survives a round trip.
//
// The Redis-backed suite is not here. It needs testcontainers, and the core
// module depends on the standard library only — a test-only dependency is still
// a dependency, and it would appear in the go.sum of every consumer. That suite
// lives in the redisstore module, which already depends on go-redis:
//
//	cd redisstore && go test -tags=integration -race ./...
package integration
