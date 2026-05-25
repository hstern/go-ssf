# go-ssf

A Go implementation of the
[OpenID Shared Signals Framework 1.0](https://openid.net/specs/openid-sharedsignals-framework-1_0.html)
— the vendor-neutral wire protocol for transporting Security Event
Tokens (SETs) between an event Transmitter and an event Receiver, over
both push (RFC 8935) and poll (RFC 8936) delivery.

`go-ssf` is intended to provide:

- `http.Handler` constructors over a `Transmitter` interface for the
  server side of the framework — stream configuration, status, subjects,
  verification, and the poll endpoint.
- A push-mode delivery driver that signs each event as a SET and
  POSTs it to the configured Receiver endpoint.
- A `Sink` interface plus push `http.Handler` and a poll-mode
  `Poller` for the Receiver side.
- A typed HTTP client wrapping the Transmitter endpoints, used by
  Receivers to manage stream configuration.
- The full type surface for every spec-defined message, with
  byte-stable JSON round-trip on open extension fields.
- `/.well-known/ssf-configuration` metadata document support.

The library is **library-vendor-neutral**: it implements the spec,
nothing more. It does not include a CAEP or RISC event-payload schema,
an opinion about how Transmitter and Receiver authenticate to each
other beyond what the framework specifies, or a vendor-specific
adapter. Those belong in downstream consumers.

## Status

Pre-publication. The first tagged release will be `v0.1.0`. The wire
surface, the codec layer, and the conformance harness against the
OpenID Shared Signals Framework interop suite are being built out in
phased work; the public API is unstable until that tag lands. See
[`CHANGELOG.md`](CHANGELOG.md) for what has shipped.

Spec version tracked: **OpenID Shared Signals Framework 1.0**
(Final, 2026), exposed as `ssf.SpecVersion`.

## Install

```
go get github.com/hstern/go-ssf
```

```go
import "github.com/hstern/go-ssf"
```

## Compatibility

- **Go**: 1.26+
- **Runtime dependencies**: `github.com/hstern/go-subjectid`
  (RFC 9493 Subject Identifier types) and
  `github.com/go-jose/go-jose/v4` (JWS / SET signing and
  verification). No others.
- **Spec**: OpenID Shared Signals Framework 1.0 (Final, 2026).

## Contributing

See [`AGENTS.md`](AGENTS.md) for the contributor conventions — they
are written as guidance for AI coding assistants, but humans will
find the same conventions useful. The short version: standard Go
style (`gofmt`, `go vet`, `staticcheck`, `golangci-lint` all run in
CI), table-driven tests, and a strong preference for wire fidelity
over ergonomic shortcuts. New exported API surface and new
dependencies go through review.

## License

Apache License 2.0. See [`LICENSE`](LICENSE).
