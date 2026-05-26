# go-ssf

A Go implementation of the
[OpenID Shared Signals Framework 1.0](https://openid.net/specs/openid-sharedsignals-framework-1_0.html)
— the vendor-neutral wire protocol for transporting Security Event
Tokens (SETs) between an event Transmitter and an event Receiver, over
both push (RFC 8935) and poll (RFC 8936) delivery.

`go-ssf` provides:

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
OpenID Shared Signals Framework interop suite are settled; the public
API is unstable until that tag lands. See
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
- **Runtime dependencies**: [`github.com/hstern/go-subjectid`](https://github.com/hstern/go-subjectid)
  (RFC 9493 Subject Identifier types) and
  [`github.com/go-jose/go-jose/v4`](https://github.com/go-jose/go-jose)
  (JWS / SET signing and verification). No others.
- **Spec**: OpenID Shared Signals Framework 1.0 (Final, 2026).

## Architecture

The library is split into five packages, each owning one concern.

- **`ssf`** (root) — wire types for every spec-defined message
  (`StreamConfig`, `StatusResponse`, `AddSubjectRequest`,
  `VerificationRequest`, `PollRequest`/`PollResponse`, etc.), the
  `SETSigner` / `SETVerifier` interfaces and their go-jose-backed
  implementations, the `StreamStore` interface, the delivery-method
  registry, sentinel errors, and `SpecVersion`.
- **`transmitter`** — the Transmitter-side HTTP surface. Defines the
  `Transmitter` business-logic interface (one Go method per spec
  endpoint), the per-endpoint `http.Handler` constructors, the
  composed `MuxHandler`, the `/.well-known/ssf-configuration`
  handler, and the `PushDriver` that signs SETs and POSTs them to a
  Receiver per RFC 8935.
- **`receiver`** — the Receiver-side surface. Defines the `Sink`
  interface, the `PushHandler` that verifies POSTed SETs and hands
  them to a Sink per RFC 8935, the `Poller` that drives a Sink
  against a Transmitter's poll endpoint per RFC 8936, and the
  `VerificationChallenger` that orchestrates the SSF §10
  verification flow.
- **`client`** — a typed HTTP client over the Transmitter endpoint
  set. Receivers use it to create/update streams, manage subjects,
  trigger verification, and (in poll-mode deployments) drain events.
- **`memstore`** — an in-memory `StreamStore` for tests, demos, and
  the loopback interop harness. Production deployments back the
  `StreamStore` interface with their own storage.

## Quickstart

The four blocks below cover every cell of the
Transmitter+push, Transmitter+poll, Receiver+push, Receiver+poll
matrix. Each block stands alone.

### Transmitter — push delivery

Sign a Security Event Token and POST it to a Receiver's push
endpoint. The `PushDriver` is stateless: a Transmitter persists
undelivered events in its `StreamStore` and feeds them to `Deliver`
one at a time.

```go
package main

import (
	"context"

	"github.com/go-jose/go-jose/v4"
	ssf "github.com/hstern/go-ssf"
	"github.com/hstern/go-ssf/transmitter"
)

func push(ctx context.Context, key []byte, payload []byte) error {
	opts := (&jose.SignerOptions{}).WithType(ssf.SETMediaType)
	js, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.HS256, Key: key}, opts)
	if err != nil {
		return err
	}
	signer, err := ssf.NewJOSESetSigner(js)
	if err != nil {
		return err
	}

	driver := transmitter.NewPushDriver(signer)
	target := transmitter.Target{
		EndpointURL:         "https://receiver.example/events",
		AuthorizationHeader: "Bearer s3cret",
	}
	return driver.Deliver(ctx, target, payload)
}
```

### Transmitter — poll delivery

Mount the spec's Transmitter endpoints on an `http.ServeMux`. The
poll endpoint drains queued SETs to a Receiver that POSTs to it.
Consumers implement `transmitter.Transmitter` over their own
storage; the snippet below delegates the methods it needs to
`memstore.InMemoryStore` and embeds `NotImplementedTransmitter`
for everything else.

```go
package main

import (
	"context"
	"net/http"

	ssf "github.com/hstern/go-ssf"
	"github.com/hstern/go-ssf/memstore"
	"github.com/hstern/go-ssf/transmitter"
)

type myTx struct {
	transmitter.NotImplementedTransmitter
	store *memstore.InMemoryStore
}

func (t *myTx) CreateConfig(ctx context.Context, c *ssf.StreamConfig) (*ssf.StreamConfig, error) {
	return t.store.CreateStream(ctx, c)
}

func serveTransmitter() {
	store := memstore.NewInMemoryStore()
	// Enqueue a SET the Receiver will later drain via PollEvents.
	_ = store.EnqueueSET(context.Background(), "stream-1", "eyJ.compact.jws")

	mux := transmitter.MuxHandler(&myTx{store: store}, transmitter.AlwaysAllow)
	_ = http.ListenAndServe(":8080", mux)
}
```

### Receiver — push delivery

Accept POSTs from a Transmitter on `application/secevent+jwt`,
verify the JWS against the Transmitter's published JWKS, and hand
the payload bytes to a `Sink`. A nil return ack-202s the delivery;
a non-nil return 503s for retry (or 400s when wrapping
`receiver.ErrPermanent`).

```go
package main

import (
	"context"
	"net/http"

	"github.com/go-jose/go-jose/v4"
	ssf "github.com/hstern/go-ssf"
	"github.com/hstern/go-ssf/receiver"
)

func servePush(jwks jose.JSONWebKeySet) {
	verifier := ssf.NewJOSESetVerifier(jwks)
	sink := receiver.SinkFunc(func(ctx context.Context, payload []byte) error {
		// Decode the SET claims set, route on the event type, persist.
		return nil
	})
	http.Handle("/events", receiver.PushHandler(verifier, sink))
	_ = http.ListenAndServe(":9090", nil)
}
```

### Receiver — poll delivery

Drive a `Sink` against a Transmitter's poll endpoint. `Poller.Run`
loops: POST a `PollRequest`, verify each returned SET, deliver to
the Sink, ack consumed JTIs on the next poll. Cancel the context to
stop.

```go
package main

import (
	"context"

	"github.com/go-jose/go-jose/v4"
	ssf "github.com/hstern/go-ssf"
	"github.com/hstern/go-ssf/receiver"
)

func poll(ctx context.Context, jwks jose.JSONWebKeySet) error {
	verifier := ssf.NewJOSESetVerifier(jwks)
	sink := receiver.SinkFunc(func(ctx context.Context, payload []byte) error {
		return nil
	})
	p := receiver.NewPoller(
		"https://transmitter.example/streams/poll",
		verifier, sink,
		receiver.WithAuthorizationHeader("Bearer s3cret"),
		receiver.WithMaxEvents(50),
	)
	return p.Run(ctx)
}
```

## Stability

Pre-1.0. The wire types (`StreamConfig`, `StatusResponse`, every
spec-defined message) are pinned to the OpenID Shared Signals
Framework 1.0 spec and round-trip byte-stable on open extension
fields; those will not churn. The Go-surface around them
(constructor signatures, option names, package boundaries) may
still change before `v0.1.0`. Breaking changes between pre-1.0
tags are called out in [`CHANGELOG.md`](CHANGELOG.md).

After `v0.1.0`:

- The library SemVer is independent of the spec version; spec
  revisions arrive as minor bumps when they are wire-additive and as
  major bumps when they are not.
- Post-1.0 major bumps live on a `vN` branch, no versioned
  subdirectory in the module path — the go-jose precedent. The
  `main` branch carries the latest major.
- The merge style on this repo is merge commits (not squash); each
  PR's full review history is preserved in `git log --first-parent`.

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
