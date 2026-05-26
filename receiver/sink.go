// Copyright 2026 The go-ssf Authors
// SPDX-License-Identifier: Apache-2.0

// Package receiver implements the Receiver half of the OpenID Shared
// Signals Framework 1.0 wire protocol — the side that consumes
// Security Event Tokens emitted by a Transmitter.
//
// A Receiver consumes events through one of two delivery modes:
//
//   - Push (RFC 8935): the Transmitter POSTs each SET to a
//     Receiver-controlled endpoint. The Receiver responds 2xx on
//     accept, 4xx on permanent failure, 5xx on transient failure.
//     This package provides [PushHandler] — an [net/http.Handler]
//     that validates the request, verifies the SET via the
//     caller-supplied [github.com/hstern/go-ssf.SETVerifier], and
//     hands the verified payload bytes to a [Sink].
//   - Poll (RFC 8936): the Receiver POSTs to the Transmitter's poll
//     endpoint, drains the returned SETs, and acks the consumed jti
//     set on the next poll. Polling is implemented separately and
//     also drives the consumer through the [Sink] interface.
//
// The [Sink] interface is the consumer's one-method hook for what to
// do with a delivered event. The same [Sink] is reusable across both
// delivery modes; a consumer that swaps push for poll only needs to
// replace the surrounding handler/poller, not the event handler.
//
// This package does not parse the SET claims set. The verifier
// returns the JSON payload bytes from the JWS as-is and the Sink
// receives those bytes verbatim. Event-payload schemas (CAEP, RISC)
// are deliberately out of scope for the transport library; a
// consumer that needs typed events decodes the payload in its Sink.
package receiver

import (
	"context"
	"errors"
)

// Sink is the consumer-supplied hook the [PushHandler] (and the
// Poller, in a later phase) call once a Security Event Token has been
// successfully verified at the JWS layer. The payload is the raw JSON
// bytes of the SET claims set as published by the Transmitter; the
// library has already enforced the RFC 8417 §2.2 invariants ("typ"
// header, "alg" not "none", signature against the Transmitter's
// JWKS) by the time DeliverSET is called.
//
// Implementations decide what counts as a successful delivery for
// their pipeline — typically: parse the payload, route on the event
// type, persist or enqueue, and return nil. A non-nil error from
// DeliverSET tells the transport layer the delivery failed and
// shapes the wire response back to the Transmitter:
//
//   - By default, an error from DeliverSET is treated as a
//     transient/server-side failure and the push handler responds
//     503 Service Unavailable so RFC 8935 §3.2 directs the
//     Transmitter to retry. This is the safe default — most real
//     errors (database down, downstream timeout, deserialization
//     glitch from a transient cause) benefit from a retry.
//
//   - When the consumer has determined the event will never succeed
//     (the SET is semantically malformed, the event type is one this
//     deployment refuses to process, the subject is on a denylist),
//     the consumer should return an error that wraps [ErrPermanent].
//     The push handler then responds 400 Bad Request, which RFC 8935
//     §3.2 directs the Transmitter to record as a permanent failure
//     and NOT retry. Wrapping is done with [%w]:
//
//     return fmt.Errorf("malformed event payload: %w", receiver.ErrPermanent)
//
// Consumers MUST NOT panic from DeliverSET. The push handler does
// not recover panics; a panicking Sink crashes the request goroutine
// and the Transmitter sees no response (a connection reset).
//
// DeliverSET is invoked synchronously on the request goroutine. If
// the consumer needs to dispatch the event to background processing,
// it does so itself — enqueue, return nil, and own the durability
// guarantees from there. The library will not buffer events behind
// the Sink.
//
// The context carries the request's deadline and cancellation; the
// Sink SHOULD honor it for any long-running work.
type Sink interface {
	DeliverSET(ctx context.Context, payload []byte) error
}

// SinkFunc adapts a plain function to the [Sink] interface. It
// mirrors the [net/http.HandlerFunc] pattern so consumers with a
// small Sink can avoid declaring a named type.
type SinkFunc func(ctx context.Context, payload []byte) error

// DeliverSET calls f(ctx, payload). It implements [Sink].
func (f SinkFunc) DeliverSET(ctx context.Context, payload []byte) error {
	return f(ctx, payload)
}

// ErrPermanent marks a [Sink] failure as permanent so the push
// handler responds 400 Bad Request instead of the default 503
// Service Unavailable. A 400 tells the Transmitter, per RFC 8935
// §3.2, to record the delivery as failed and NOT retry. Use this
// when the consumer is certain a retry of the same SET will never
// succeed — malformed payload, unsupported event type, policy
// rejection. Errors not wrapping ErrPermanent are treated as
// transient and the Transmitter is asked to retry.
//
// Wrap with [%w] so [errors.Is] still matches through additional
// context:
//
//	return fmt.Errorf("event type %q not handled: %w",
//	    eventType, receiver.ErrPermanent)
var ErrPermanent = errors.New("permanent sink failure")
