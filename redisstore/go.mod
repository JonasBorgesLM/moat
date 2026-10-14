// Module redisstore implements ratelimit.Store against Redis.
//
// It is a separate module so that go-redis never appears in the go.sum of
// consumers who only import the core packages. See doc/DESIGN.md §2.
module github.com/JonasBorgesLM/moat/redisstore

// 1.26.6, not 1.25.x, and stated as a full patch version on purpose.
//
// This module reaches crypto/tls (through go-redis) and encoding/asn1 (through
// certificate parsing on a TLS connection to Redis), which are the two packages
// carrying GO-2026-6090 and GO-2026-5972. Both are fixed in 1.25.13 and in
// 1.26.6.
//
// `toolchain go1.26.6` used to be the only floor here, and a toolchain line is
// ignored by anyone importing the module (DESIGN.md §6.13) — so it protected
// this repository's CI and nobody else. The `go` directive is not ignored: with
// GOTOOLCHAIN=auto, the default, a consumer on an older toolchain downloads and
// switches to this one, and with GOTOOLCHAIN=local they get a clear refusal
// instead of a silent vulnerable build.
//
// `go 1.25.13` would NOT do the job, and the reason is worth spelling out
// because it looks like the more conservative choice. Go orders versions across
// lines, so 1.26.5 satisfies a floor of 1.25.13 — and 1.26.5 is vulnerable to
// both. Only 1.26.6 covers the 1.26 line as well as the 1.25 one.
//
// The core module stays at go 1.24 and is unaffected: it has no dependencies and
// reaches neither package. See README.md in this directory.
go 1.26.6

// v0.2.0 was published requiring the core module at v0.1.0, whose
// ratelimit.Store interface still declares Take rather than TakeN. *Store
// therefore does not satisfy ratelimit.Store for anyone resolving it fresh from
// the proxy, and the module does not compile. The local development workspace
// resolved the core against the working tree, so nothing caught it before the
// tag. Use v0.2.1.
retract v0.2.0

require (
	github.com/JonasBorgesLM/moat v0.2.0
	github.com/redis/go-redis/v9 v9.23.0
	github.com/testcontainers/testcontainers-go v0.44.0
)

require (
	dario.cat/mergo v1.0.2 // indirect
	github.com/Azure/go-ansiterm v0.0.0-20250102033503-faa5f7b0171c // indirect
	github.com/Microsoft/go-winio v0.6.2 // indirect
	github.com/cenkalti/backoff/v4 v4.3.0 // indirect
	github.com/cespare/xxhash/v2 v2.3.0 // indirect
	github.com/containerd/errdefs v1.0.0 // indirect
	github.com/containerd/errdefs/pkg v0.3.0 // indirect
	github.com/containerd/log v0.1.0 // indirect
	github.com/containerd/platforms v0.2.1 // indirect
	github.com/cpuguy83/dockercfg v0.3.2 // indirect
	github.com/distribution/reference v0.6.0 // indirect
	github.com/docker/go-connections v0.7.0 // indirect
	github.com/docker/go-units v0.5.0 // indirect
	github.com/ebitengine/purego v0.10.1 // indirect
	github.com/felixge/httpsnoop v1.1.0 // indirect
	github.com/go-logr/logr v1.4.3 // indirect
	github.com/go-logr/stdr v1.2.2 // indirect
	github.com/go-ole/go-ole v1.3.0 // indirect
	github.com/google/uuid v1.6.0 // indirect
	github.com/klauspost/compress v1.18.7 // indirect
	github.com/lufia/plan9stats v0.0.0-20260330125221-c963978e514e // indirect
	github.com/magiconair/properties v1.8.10 // indirect
	github.com/moby/docker-image-spec v1.3.1 // indirect
	github.com/moby/go-archive v0.3.0 // indirect
	github.com/moby/moby/api v1.55.0 // indirect
	github.com/moby/moby/client v0.5.0 // indirect
	github.com/moby/patternmatcher v0.6.1 // indirect
	github.com/moby/sys/sequential v0.7.0 // indirect
	github.com/moby/sys/user v0.4.1 // indirect
	github.com/moby/sys/userns v0.1.0 // indirect
	github.com/moby/term v0.5.2 // indirect
	github.com/opencontainers/go-digest v1.0.0 // indirect
	github.com/opencontainers/image-spec v1.1.1 // indirect
	github.com/power-devops/perfstat v0.0.0-20240221224432-82ca36839d55 // indirect
	github.com/shirou/gopsutil/v4 v4.26.6 // indirect
	github.com/sirupsen/logrus v1.9.4 // indirect
	github.com/stretchr/testify v1.12.1 // indirect
	github.com/tklauser/go-sysconf v0.4.0 // indirect
	github.com/tklauser/numcpus v0.12.0 // indirect
	github.com/yusufpapurcu/wmi v1.2.4 // indirect
	go.opentelemetry.io/auto/sdk v1.2.1 // indirect
	go.opentelemetry.io/contrib/instrumentation/net/http/otelhttp v0.69.0 // indirect
	go.opentelemetry.io/otel v1.44.0 // indirect
	go.opentelemetry.io/otel/metric v1.44.0 // indirect
	go.opentelemetry.io/otel/trace v1.44.0 // indirect
	go.uber.org/atomic v1.12.0 // indirect
	go.yaml.in/yaml/v3 v3.0.5 // indirect
	golang.org/x/crypto v0.54.0 // indirect
	golang.org/x/sys v0.48.0 // indirect
)
