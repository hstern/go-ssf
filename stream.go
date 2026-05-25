// Copyright 2026 The go-ssf Authors
// SPDX-License-Identifier: Apache-2.0

package ssf

import "encoding/json"

// Delivery method discriminator URIs registered with IANA for the
// Shared Signals Framework's two built-in delivery modes. They are
// the values that appear in the [Delivery.Method] field on the wire,
// and the keys under which the built-in push and poll handlers will
// register themselves in the phase-3 delivery-method registry.
const (
	// DeliveryMethodPush is the discriminator URI for SET push
	// delivery per RFC 8935 — the Transmitter HTTP-POSTs each SET to
	// the Receiver's endpoint. See spec §7.1.1 ("delivery") and
	// RFC 8935 §2.
	DeliveryMethodPush = "urn:ietf:rfc:8935"

	// DeliveryMethodPoll is the discriminator URI for SET poll
	// delivery per RFC 8936 — the Receiver HTTP-POSTs to the
	// Transmitter's poll endpoint to drain queued SETs. See
	// spec §7.1.1 ("delivery") and RFC 8936 §2.
	DeliveryMethodPoll = "urn:ietf:rfc:8936"
)

// StreamConfig is the Shared Signals Framework Stream Configuration
// object per spec §7.1.1 — the canonical description of an event
// stream agreed between a Transmitter and a Receiver. The same shape
// is returned by the configuration endpoint on GET, accepted (minus
// [StreamConfig.StreamID]) on POST to create a stream, and accepted
// as a partial document on PATCH to update a stream.
//
// Field semantics follow the spec literally:
//
//   - StreamID is server-assigned; clients omit it on create and
//     receive it back in the response.
//   - Iss is the Transmitter's issuer URI and matches the
//     [TransmitterConfig.Issuer] of the well-known metadata
//     document.
//   - Aud is the audience identifier(s) for SETs delivered on this
//     stream. The spec permits either a single string or a JSON array
//     of strings; this library represents the field as
//     [json.RawMessage] so the exact bytes round-trip unchanged. The
//     marshal direction does not normalize the two forms — callers
//     who construct a [StreamConfig] in code are responsible for the
//     JSON shape they want on the wire. Consumers who need a typed
//     view can JSON-unmarshal Aud into either a string or a []string
//     themselves.
//   - EventsSupported, EventsRequested, and EventsDelivered are
//     slices of event-type URI strings. EventsRequested is spec-
//     required on the Receiver→Transmitter direction and MUST be
//     non-empty per spec §7.1.1; that constraint is enforced in a
//     later opt-in Validate function, not here at the type boundary,
//     per the library's lenient-unmarshal / strict-marshal posture.
//   - Delivery carries the push/poll discriminated union — see the
//     [Delivery] godoc.
//   - MinVerificationInterval, if non-zero, is the minimum number of
//     seconds between verification challenges the Transmitter will
//     honor. Zero means "unset" on the wire.
//   - Format, if non-empty, is the Receiver's preferred Subject
//     Identifier format (an RFC 9493 format name).
//
// JSON encoding follows the default [encoding/json] rules with the
// tags below. A custom MarshalJSON / UnmarshalJSON pair will land in
// a later codec pass to pin field-emission order for byte-stable
// interop fixtures and to dispatch [Delivery] through the
// delivery-method registry; for now the default codec is sufficient
// for round-trips of the two built-in delivery methods.
type StreamConfig struct {
	// StreamID is the server-assigned opaque identifier for the
	// stream. Clients omit it when creating a stream and receive it
	// in the response; subsequent operations on the stream use it as
	// a query parameter rather than a body field.
	StreamID string `json:"stream_id,omitempty"`

	// Iss is the Transmitter's issuer URI per spec §7.1.1. Required
	// at the marshal boundary.
	Iss string `json:"iss,omitempty"`

	// Aud is the audience identifier(s) for SETs on this stream. The
	// spec permits a single string or a JSON array of strings; the
	// field is [json.RawMessage] to preserve the exact wire shape
	// across a round-trip. Required at the marshal boundary.
	Aud json.RawMessage `json:"aud,omitempty"`

	// EventsSupported is the set of event-type URIs the Transmitter
	// can deliver on this stream. Optional in the request from the
	// Receiver; returned by the Transmitter in the response.
	EventsSupported []string `json:"events_supported,omitempty"`

	// EventsRequested is the set of event-type URIs the Receiver
	// wants delivered. Spec-required and MUSTed to be non-empty;
	// non-emptiness is checked by Validate, not by the type or codec.
	EventsRequested []string `json:"events_requested,omitempty"`

	// EventsDelivered is the intersection of EventsSupported and
	// EventsRequested — the set the Transmitter has actually agreed
	// to deliver. Server-set; clients should not populate it on
	// create.
	EventsDelivered []string `json:"events_delivered,omitempty"`

	// Delivery carries the per-stream delivery configuration — push
	// or poll, plus the endpoint URL and optional authorization
	// header. See [Delivery]. Required at the marshal boundary.
	Delivery Delivery `json:"delivery"`

	// MinVerificationInterval is the minimum number of seconds the
	// Transmitter will allow between verification challenges. Zero
	// means "unset" on the wire.
	MinVerificationInterval int `json:"min_verification_interval,omitempty"`

	// Format is the Receiver's preferred RFC 9493 Subject Identifier
	// format name. Optional.
	Format string `json:"format,omitempty"`
}

// Delivery is the per-stream delivery configuration on a
// [StreamConfig] per spec §7.1.1 — a discriminated union on
// [Delivery.Method] that selects between push (RFC 8935) and poll
// (RFC 8936) transport. Both built-in methods carry the same two
// fields, [Delivery.EndpointURL] and [Delivery.AuthorizationHeader],
// so this phase-2 type definition keeps them as exported struct
// fields rather than method-specific variant types.
//
// Forward compatibility: the spec permits additional delivery
// methods registered with IANA. A later codec pass will introduce a
// delivery-method registry plus custom marshal/unmarshal that
// dispatches by Method and round-trips unknown methods through a
// dedicated fallback type. Until that lands, this type covers the
// two built-in methods only and uses the default [encoding/json]
// codec; consumers that need to handle unregistered methods should
// not rely on this surface yet.
type Delivery struct {
	// Method is the delivery-method discriminator URI — one of
	// [DeliveryMethodPush] or [DeliveryMethodPoll] for the built-in
	// methods, or an IANA-registered URI for an extension method.
	Method string `json:"method,omitempty"`

	// EndpointURL is the absolute URL the delivery method dispatches
	// to. For push (RFC 8935) it is the Receiver endpoint the
	// Transmitter POSTs each SET to; for poll (RFC 8936) it is the
	// Transmitter endpoint the Receiver POSTs to drain queued SETs.
	EndpointURL string `json:"endpoint_url,omitempty"`

	// AuthorizationHeader, if non-empty, is the literal value of the
	// HTTP Authorization header to present on requests to
	// EndpointURL. Both built-in methods accept it; the spec leaves
	// the credential scheme to deployment.
	AuthorizationHeader string `json:"authorization_header,omitempty"`
}
