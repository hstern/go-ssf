// Copyright 2026 The go-ssf Authors
// SPDX-License-Identifier: Apache-2.0

// Package transmitter is the server-side half of OpenID Shared
// Signals Framework 1.0.
//
// A Transmitter, in spec terms, is the party that owns the streams,
// signs Security Event Tokens, and exposes the HTTP endpoints
// described in §7 of the OpenID Shared Signals Framework 1.0 spec.
// This package defines the [Transmitter] interface — one method per
// spec endpoint — and the [NotImplementedTransmitter] helper that
// makes partial implementations practical.
//
// Consumers integrate by implementing [Transmitter] over whatever
// storage and signing they already have, then mounting the HTTP
// handlers exposed by this package onto an [net/http.ServeMux] or
// any compatible router. The interface deliberately exposes one
// Go method per spec endpoint rather than HTTP-shaped surfaces
// (no [net/http.ResponseWriter], no path parameters) so the same
// implementation can drive HTTP, in-process tests, and alternative
// transports interchangeably.
//
// The HTTP-handler constructors that translate [Transmitter] method
// calls into spec-conformant HTTP responses ship in a follow-up
// commit; this file establishes the contract.
package transmitter

import (
	"context"
	"encoding/json"

	ssf "github.com/hstern/go-ssf"
)

// Transmitter is the server-side contract of OpenID Shared Signals
// Framework 1.0. Each method maps 1:1 to one of the HTTP endpoints
// described in spec §7 — Stream Configuration, Stream Status,
// Subjects, Verification, and the RFC 8936 Poll-delivery endpoint.
//
// Implementations carry the operator's storage, signing keys, and
// authorization decisions. The HTTP-handler layer in this package
// is a thin adapter: it decodes a request, calls the corresponding
// Transmitter method, and renders the result (or error) onto the
// wire per the spec's JSON shapes and RFC 7807 problem-details for
// error responses.
//
// Errors returned by Transmitter methods drive the HTTP status
// mapping. Sentinels from the root [github.com/hstern/go-ssf]
// package — for example [ssf.ErrStreamNotFound],
// [ssf.ErrUnauthorized], [ssf.ErrNotImplemented] — are recognized
// by the handler layer and translated to the spec-mandated status
// codes. Returning a wrapped sentinel (via fmt.Errorf with %w) is
// idiomatic; the handler unwraps with [errors.Is].
//
// Concurrency is the implementation's responsibility. Handlers may
// dispatch method calls from many goroutines for the same Transmitter
// value; method implementations MUST be safe for concurrent use.
//
// Partial implementations are expected. A Transmitter that only
// supports poll delivery, for instance, has no business implementing
// the push-only verification flow. Embed
// [NotImplementedTransmitter] in such cases and override only the
// methods the implementation supports — the unimplemented methods
// then return [ssf.ErrNotImplemented], which the handler layer maps
// to HTTP 501 Not Implemented.
type Transmitter interface {
	// GetConfig returns the stream configuration identified by
	// streamID per spec §7.1.1 (GET with stream_id query parameter).
	// Implementations return [ssf.ErrStreamNotFound] if streamID
	// does not name an existing stream owned by the caller.
	GetConfig(ctx context.Context, streamID string) (*ssf.StreamConfig, error)

	// ListConfig returns a page of stream configurations the caller
	// is authorized to see per spec §7.1.1 (GET without stream_id).
	// pageToken is the opaque continuation token returned in the
	// previous call's nextToken; the empty string requests the first
	// page. nextToken is empty when the listing is exhausted. The
	// page size is implementation-defined.
	ListConfig(ctx context.Context, pageToken string) (configs []*ssf.StreamConfig, nextToken string, err error)

	// CreateConfig persists a new stream described by cfg and
	// returns the canonical server-assigned representation per spec
	// §7.1.1 (POST). The returned StreamConfig MAY differ from the
	// input — at minimum the Transmitter typically assigns
	// [ssf.StreamConfig.StreamID], [ssf.StreamConfig.IssuerJWKSURI],
	// and any defaulted fields the request omitted. Implementations
	// return [ssf.ErrInvalidConfig] for structurally invalid input
	// (unknown event types, malformed delivery, etc.).
	CreateConfig(ctx context.Context, cfg *ssf.StreamConfig) (*ssf.StreamConfig, error)

	// UpdateConfig replaces the stream configuration identified by
	// cfg.StreamID with cfg and returns the canonical post-update
	// representation per spec §7.1.1 (PATCH with stream_id query
	// parameter). The operation is a full replacement, not a merge:
	// fields absent from cfg are cleared. Implementations return
	// [ssf.ErrStreamNotFound] when cfg.StreamID does not identify an
	// existing stream, and [ssf.ErrInvalidConfig] for structurally
	// invalid input.
	UpdateConfig(ctx context.Context, cfg *ssf.StreamConfig) (*ssf.StreamConfig, error)

	// DeleteConfig removes the stream identified by streamID per
	// spec §7.1.1 (DELETE with stream_id query parameter). Deleting
	// a non-existent stream returns [ssf.ErrStreamNotFound].
	DeleteConfig(ctx context.Context, streamID string) error

	// GetStatus returns the lifecycle state of the stream identified
	// by streamID per spec §7.1.2 (GET with stream_id query
	// parameter). When subject is non-nil the response is scoped to
	// that single subject; when nil the response describes the
	// stream as a whole.
	//
	// subject is the wire-form Subject Identifier as
	// [encoding/json.RawMessage] — the spec leaves the type open
	// (RFC 9493 subject identifier of any format) and downstream
	// codec helpers in the root [github.com/hstern/go-ssf] package
	// promote it to a typed Subject Identifier without altering
	// this signature.
	GetStatus(ctx context.Context, streamID string, subject json.RawMessage) (*ssf.StatusResponse, error)

	// UpdateStatus requests a lifecycle transition on the stream
	// identified by streamID per spec §7.1.2 (POST). The
	// Transmitter MAY honor, delay, or refuse the request; the
	// returned [ssf.StatusResponse] reflects the resulting state,
	// which may converge asynchronously.
	UpdateStatus(ctx context.Context, streamID string, req *ssf.StatusUpdateRequest) (*ssf.StatusResponse, error)

	// AddSubject registers a subject as in-scope for the stream
	// identified by streamID per spec §7.1.3 (POST to add endpoint).
	// Implementations return [ssf.ErrStreamNotFound] when streamID
	// is unknown.
	AddSubject(ctx context.Context, streamID string, req *ssf.AddSubjectRequest) error

	// RemoveSubject removes a subject from the stream identified by
	// streamID per spec §7.1.3 (POST to remove endpoint).
	// Implementations return [ssf.ErrStreamNotFound] when streamID
	// is unknown.
	RemoveSubject(ctx context.Context, streamID string, req *ssf.RemoveSubjectRequest) error

	// Verify initiates the verification flow on the stream
	// identified by streamID per spec §7.1.4. The Transmitter
	// generates and delivers a verification event carrying the
	// caller-supplied state value, and the caller waits for the
	// matching event to appear on the configured delivery channel.
	// This method completes once the verification event has been
	// queued for delivery; matching the response is the Receiver's
	// responsibility.
	Verify(ctx context.Context, streamID string, req *ssf.VerificationRequest) error

	// PollEvents serves an RFC 8936 poll request for the stream
	// identified by streamID. The response carries any pending SETs
	// in the body's sets map keyed by jti, and applies the
	// acknowledgements named in req.Ack / req.SetErrs against the
	// caller's outstanding events.
	PollEvents(ctx context.Context, streamID string, req *ssf.PollRequest) (*ssf.PollResponse, error)
}

// NotImplementedTransmitter is a zero-value [Transmitter] whose
// every method returns [ssf.ErrNotImplemented]. It is meant to be
// embedded in a partial implementation so the consumer only writes
// the methods that matter to them; the embedded zero value supplies
// the rest.
//
// Embed and override:
//
//	type pollOnly struct {
//	    transmitter.NotImplementedTransmitter
//	    store *myStore
//	}
//
//	func (p *pollOnly) PollEvents(ctx context.Context, streamID string, req *ssf.PollRequest) (*ssf.PollResponse, error) {
//	    // real implementation
//	}
//
// Calls to PollEvents on a *pollOnly hit the override; calls to any
// other Transmitter method fall through to the embedded
// NotImplementedTransmitter and return [ssf.ErrNotImplemented],
// which the HTTP-handler layer maps to 501 Not Implemented.
//
// NotImplementedTransmitter has no fields and no internal state; its
// zero value is ready to use.
type NotImplementedTransmitter struct{}

// GetConfig implements [Transmitter] by returning
// [ssf.ErrNotImplemented].
func (NotImplementedTransmitter) GetConfig(context.Context, string) (*ssf.StreamConfig, error) {
	return nil, ssf.ErrNotImplemented
}

// ListConfig implements [Transmitter] by returning
// [ssf.ErrNotImplemented].
func (NotImplementedTransmitter) ListConfig(context.Context, string) ([]*ssf.StreamConfig, string, error) {
	return nil, "", ssf.ErrNotImplemented
}

// CreateConfig implements [Transmitter] by returning
// [ssf.ErrNotImplemented].
func (NotImplementedTransmitter) CreateConfig(context.Context, *ssf.StreamConfig) (*ssf.StreamConfig, error) {
	return nil, ssf.ErrNotImplemented
}

// UpdateConfig implements [Transmitter] by returning
// [ssf.ErrNotImplemented].
func (NotImplementedTransmitter) UpdateConfig(context.Context, *ssf.StreamConfig) (*ssf.StreamConfig, error) {
	return nil, ssf.ErrNotImplemented
}

// DeleteConfig implements [Transmitter] by returning
// [ssf.ErrNotImplemented].
func (NotImplementedTransmitter) DeleteConfig(context.Context, string) error {
	return ssf.ErrNotImplemented
}

// GetStatus implements [Transmitter] by returning
// [ssf.ErrNotImplemented].
func (NotImplementedTransmitter) GetStatus(context.Context, string, json.RawMessage) (*ssf.StatusResponse, error) {
	return nil, ssf.ErrNotImplemented
}

// UpdateStatus implements [Transmitter] by returning
// [ssf.ErrNotImplemented].
func (NotImplementedTransmitter) UpdateStatus(context.Context, string, *ssf.StatusUpdateRequest) (*ssf.StatusResponse, error) {
	return nil, ssf.ErrNotImplemented
}

// AddSubject implements [Transmitter] by returning
// [ssf.ErrNotImplemented].
func (NotImplementedTransmitter) AddSubject(context.Context, string, *ssf.AddSubjectRequest) error {
	return ssf.ErrNotImplemented
}

// RemoveSubject implements [Transmitter] by returning
// [ssf.ErrNotImplemented].
func (NotImplementedTransmitter) RemoveSubject(context.Context, string, *ssf.RemoveSubjectRequest) error {
	return ssf.ErrNotImplemented
}

// Verify implements [Transmitter] by returning
// [ssf.ErrNotImplemented].
func (NotImplementedTransmitter) Verify(context.Context, string, *ssf.VerificationRequest) error {
	return ssf.ErrNotImplemented
}

// PollEvents implements [Transmitter] by returning
// [ssf.ErrNotImplemented].
func (NotImplementedTransmitter) PollEvents(context.Context, string, *ssf.PollRequest) (*ssf.PollResponse, error) {
	return nil, ssf.ErrNotImplemented
}

// Compile-time assertion: NotImplementedTransmitter satisfies
// Transmitter. This catches signature drift the moment Transmitter
// changes shape — far cheaper than a runtime surprise from an
// embedded type that silently no longer implements the interface.
var _ Transmitter = (*NotImplementedTransmitter)(nil)
