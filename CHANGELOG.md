# Changelog

All notable changes to `go-ssf` are documented here. The format
follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and
the project adheres to [Semantic Versioning](https://semver.org/).

The library SemVer is independent of the Shared Signals Framework
spec version it implements — `ssf.SpecVersion` tracks the latter; this
file tracks the former.

## [Unreleased]

## [0.1.0] - 2026-05-26

First tagged release. Implements OpenID Shared Signals Framework 1.0
(Final, 2026) — the vendor-neutral wire protocol for transporting
Security Event Tokens (SETs) between an event Transmitter and an
event Receiver, over both push (RFC 8935) and poll (RFC 8936)
delivery.

### Added

- **Wire types** for every spec-defined message: `TransmitterConfig`
  (well-known metadata), `StreamConfig`, `Delivery` (push/poll
  discriminated union), `StreamStatus` + `StatusResponse` +
  `StatusUpdateRequest`, `AddSubjectRequest` / `RemoveSubjectRequest`
  (typed against `github.com/hstern/go-subjectid` for RFC 9493 Subject
  Identifiers), `VerificationRequest` + `VerificationEvent`,
  `PollRequest` / `PollResponse` (RFC 8936). Open-extension fields are
  `json.RawMessage` so they round-trip byte-stably; discriminators
  emit first for interop-fixture stability.
- **Delivery-method registry** (`RegisterDeliveryMethod`,
  `LookupDeliveryMethod`) backed by `sync.RWMutex` with built-ins for
  RFC 8935 push and RFC 8936 poll. Unknown methods parse into
  `UnknownDelivery{Method, Raw}` for forward compatibility per the
  IANA-registry-as-source-of-truth rule.
- **SET signing and verification** (`SETSigner` / `SETVerifier`
  interfaces) over `github.com/go-jose/go-jose/v4`. `JOSESetSigner`
  enforces `typ: secevent+jwt` and rejects `alg: none` at
  construction; `JOSESetVerifier` enforces both at verify time per
  RFC 8417 §2.2.
- **`transmitter/` package**: nine-method `Transmitter` interface
  (one per spec endpoint), `NotImplementedTransmitter` embed-and-
  override zero value, per-endpoint `http.Handler` constructors,
  composed `MuxHandler`, `WellKnownHandler` for
  `/.well-known/ssf-configuration` with Cache-Control honoring,
  `AuthFunc` + `StreamScope` + `AlwaysReject`/`AlwaysAllow` (testing
  only) + `Default401Handler`, and a `PushDriver` with exponential
  backoff, jitter, dead-letter callback, and `Retry-After` honoring.
- **`receiver/` package**: one-method `Sink` interface + `SinkFunc`
  adapter, `PushHandler` for RFC 8935 push with `ErrPermanent`
  permanent-vs-transient signaling, `Poller` for RFC 8936 poll with
  spec-conformant ack/setErrs semantics, configurable backoff via
  `WithNoEventsBackoff` / `WithErrorBackoff` / `WithMaxEvents`, and
  serial delivery by default with opt-in `WithParallelDelivery`
  (documented ordering loss). `VerificationChallenger` orchestrates
  the spec §7.1.4 verification handshake via a `WrapSink` interception
  pattern.
- **`client/` package**: `Client` over an `HTTPDoer` interface,
  one method per Transmitter endpoint, `ParseHTTPError` mapping
  non-2xx responses to `*ssf.HTTPError` with RFC 7807 problem-details
  parsing and sentinel attachment via `errors.Join`,
  `FetchTransmitterConfig` for well-known discovery with `ConfigCache`
  + Cache-Control honoring.
- **`memstore/` package**: `InMemoryStore` implementation of the
  `ssf.StreamStore` interface for tests and demos.
  `sync.Mutex`-guarded; production deployments back `StreamStore`
  with their own storage.
- **Conformance**: `internal/specfixtures/` with 16 embedded JSON
  fixtures covering every spec-defined message; `internal/interop/`
  with library-vs-library loopback under the `interop` build tag
  exercising all four cells (Transmitter+push, Transmitter+poll,
  Receiver+push, Receiver+poll); `forward_compat_test.go` pinning
  `UnknownDelivery` round-trip and unknown-event-type passthrough.
- **CI fan-out** on GitHub Actions: `static`, `test`, `lint`,
  `interop` jobs, plus a separate daily `vuln` workflow running
  `govulncheck` against `main`. Branch protection on `main` requires
  all four checks green and the branch up-to-date with `main` before
  merge.
- **Documentation**: `README.md` with a ~30-line quickstart for each
  of the four matrix cells, package architecture, stability posture,
  and cross-references to `go-subjectid` and `go-jose`. `AGENTS.md`
  for contributor conventions. Godoc on every exported symbol naming
  the spec section it implements; `Example` functions in `_test.go`
  files for the load-bearing surfaces (`MuxHandler`,
  `WellKnownHandler`, `PushDriver.Deliver`, `PushHandler`,
  `Poller.Run`, `VerificationChallenger.Challenge`, `NewClient`,
  `FetchTransmitterConfig`, `NewInMemoryStore`,
  `RegisterDeliveryMethod`).

### Compatibility

- Go 1.26+.
- Runtime dependencies: `github.com/hstern/go-subjectid` (RFC 9493
  Subject Identifier types) and `github.com/go-jose/go-jose/v4`
  (JWS / SET signing and verification). No others.

### Deferred to a future release

- CAEP and RISC event-payload schemas (future sibling libraries
  `go-caep`, `go-risc`).
- Full SET envelope encoder / decoder beyond signing helpers (may
  move to a `go-set` sibling if demand surfaces).
- Persistent `StreamStore` adapters (SQL, Redis, etc.) — out of
  scope for the library; the in-memory store ships, persistent
  backends live in consumer code.
- HTTP/3, Server-Sent Events transport — spec is HTTP/1.1+.
- A reference `Transmitter` implementation backed by the in-memory
  store as a public type — the test-only adapter under
  `internal/interop` is sufficient for v0.1; a public surface here
  would be premature.

Tracks OpenID Shared Signals Framework 1.0 (Final, 2026).
