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
// tags below. The nested [Delivery] value carries its own
// [Delivery.UnmarshalJSON] and [Delivery.MarshalJSON] that dispatch
// the discriminator through the delivery-method registry, so a
// [StreamConfig] containing an unrecognized delivery method still
// round-trips through encoding/json without loss. A later codec
// pass will pin field-emission order on [StreamConfig] itself for
// byte-stable interop fixtures; the current encoding is the default
// struct field order.
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
// so the type keeps them as exported struct fields rather than
// method-specific variant types.
//
// Forward compatibility: the spec permits additional delivery
// methods registered with IANA. [Delivery.UnmarshalJSON] dispatches
// the JSON "method" discriminator through the package's
// delivery-method registry (see [RegisterDeliveryMethod] and
// [LookupDeliveryMethod]). A method URI that is neither built-in
// nor registered decodes into a [Delivery] whose [Delivery.Unknown]
// accessor returns a populated [UnknownDelivery] carrier holding
// the raw JSON bytes; re-encoding such a value reproduces the
// original payload byte-for-byte modulo JSON whitespace
// canonicalization. Built-in methods (push and poll) decode into a
// [Delivery] for which [Delivery.Known] reports true and the typed
// fields below are populated as usual.
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

	// unknown carries the original wire bytes for a [Delivery] whose
	// method URI was not in the delivery-method registry at decode
	// time. It is set only by [Delivery.UnmarshalJSON] on the
	// fallback path; the field is unexported so callers route
	// through [Delivery.Known] and [Delivery.Unknown] rather than
	// pattern-matching on a public sentinel value, keeping happy-
	// path access on Method / EndpointURL / AuthorizationHeader
	// unchanged for code that constructs a Delivery in memory.
	unknown *UnknownDelivery
}

// deliveryAlias is used by [Delivery.UnmarshalJSON] and
// [Delivery.MarshalJSON] to invoke the default struct codec for
// known delivery methods without recursing into the custom
// marshal/unmarshal methods on [Delivery] itself. It carries the
// same exported field set as [Delivery] but inherits none of its
// methods.
type deliveryAlias struct {
	Method              string `json:"method,omitempty"`
	EndpointURL         string `json:"endpoint_url,omitempty"`
	AuthorizationHeader string `json:"authorization_header,omitempty"`
}

// Known reports whether the [Delivery] was decoded from a method
// URI in the delivery-method registry at the time of decode. A
// freshly-constructed zero-value [Delivery] returns true (it has no
// unknown-method history); a [Delivery] produced by
// [Delivery.UnmarshalJSON] from an unregistered method URI returns
// false.
//
// Callers that need to branch on known versus unknown delivery
// methods typically check Known first and only consult
// [Delivery.Unknown] when Known returns false.
func (d Delivery) Known() bool { return d.unknown == nil }

// Unknown returns the [UnknownDelivery] carrier and true when the
// [Delivery] was decoded from a method URI the delivery-method
// registry did not recognize; otherwise it returns the zero value
// of [UnknownDelivery] and false. The returned carrier holds the
// original JSON bytes verbatim for byte-stable round-tripping.
//
// Unknown is the companion to [Delivery.Known]; the typical
// pattern is:
//
//	if u, ok := delivery.Unknown(); ok {
//		// handle unrecognized method u.Method, with u.Raw available.
//	}
func (d Delivery) Unknown() (UnknownDelivery, bool) {
	if d.unknown == nil {
		return UnknownDelivery{}, false
	}
	return *d.unknown, true
}

// UnmarshalJSON implements [json.Unmarshaler] for [Delivery] by
// peeking the "method" discriminator and dispatching through the
// delivery-method registry:
//
//   - When the registry has a factory for the method URI, the
//     factory is invoked to obtain a seed [Delivery] and the
//     standard struct decoder fills in the remaining fields. The
//     result is the canonical typed representation of the built-in
//     (or registered-extension) delivery method.
//   - When the registry has no factory for the method URI, the
//     [Delivery] decodes into an unknown-method carrier:
//     [Delivery.Method] is set to the discriminator, the typed
//     EndpointURL and AuthorizationHeader fields are left zero,
//     and the original input bytes are preserved verbatim for
//     retrieval via [Delivery.Unknown]. The library never errors
//     on an unrecognized method — that is the forward-
//     compatibility contract recorded in CLAUDE.md.
//
// Errors are reserved for malformed JSON (input that is not a JSON
// object, or whose "method" member is not a string). Extra members
// on a known method are silently dropped at decode per the
// library's lenient-unmarshal / strict-marshal posture.
func (d *Delivery) UnmarshalJSON(data []byte) error {
	var env struct {
		Method string `json:"method"`
	}
	if err := json.Unmarshal(data, &env); err != nil {
		return err
	}
	if factory, ok := LookupDeliveryMethod(env.Method); ok {
		seed := factory()
		alias := deliveryAlias{
			Method:              seed.Method,
			EndpointURL:         seed.EndpointURL,
			AuthorizationHeader: seed.AuthorizationHeader,
		}
		if err := json.Unmarshal(data, &alias); err != nil {
			return err
		}
		*d = Delivery{
			Method:              alias.Method,
			EndpointURL:         alias.EndpointURL,
			AuthorizationHeader: alias.AuthorizationHeader,
		}
		return nil
	}
	// Unknown method — copy the bytes so the caller cannot mutate
	// the carrier's state by holding a reference to data.
	raw := make(json.RawMessage, len(data))
	copy(raw, data)
	*d = Delivery{
		Method: env.Method,
		unknown: &UnknownDelivery{
			Method: env.Method,
			Raw:    raw,
		},
	}
	return nil
}

// MarshalJSON implements [json.Marshaler] for [Delivery]. For a
// known method — the registry recognized the discriminator at
// decode time, or the value was constructed in code — the output
// is the standard struct encoding of the typed fields. For an
// unknown method — the [Delivery] was decoded from an unregistered
// method URI — the preserved raw bytes are emitted verbatim so the
// round-trip is byte-stable modulo [encoding/json.Marshal]'s
// whitespace canonicalization of any [json.Marshaler]'s output.
//
// MarshalJSON exists here so the unknown-method carrier round-trips
// through [encoding/json.Marshal]; the full spec-order field-
// emission pass for the typed branch is the scope of a later codec
// commit, and the current typed-branch emission is the default
// struct encoding (struct field order).
func (d Delivery) MarshalJSON() ([]byte, error) {
	if d.unknown != nil {
		return d.unknown.Raw, nil
	}
	return json.Marshal(deliveryAlias{
		Method:              d.Method,
		EndpointURL:         d.EndpointURL,
		AuthorizationHeader: d.AuthorizationHeader,
	})
}
