// Copyright 2026 The go-ssf Authors
// SPDX-License-Identifier: Apache-2.0

package ssf

// PollRequest is the request body a Receiver POSTs to the
// Transmitter's poll endpoint per RFC 8936 §2.4. A poll serves two
// purposes simultaneously: it acknowledges SETs the Receiver has
// already processed from the previous poll, and it asks for more.
// An empty PollRequest (all fields zero) is a valid heartbeat —
// it acknowledges nothing and requests the Transmitter's default
// batch.
//
// Field naming follows RFC 8936 verbatim. The pointer types on
// MaxEvents and ReturnImmediately distinguish "field absent" from
// "field present with zero value", which matters for round-trip
// fidelity: per RFC 8936 §2.4.1, maxEvents=0 is a defined value
// (the Receiver wants no SETs at all, only to acknowledge), and a
// nil pointer means "the Receiver did not pin a cap, let the
// Transmitter pick".
type PollRequest struct {
	// Ack lists the JTIs of SETs the Receiver successfully consumed
	// since the previous poll. The Transmitter MUST stop redelivering
	// each acknowledged SET. The spec is silent on the ordering of
	// this array; implementations MUST NOT depend on order.
	Ack []string `json:"ack,omitempty"`

	// SetErrs lists JTIs the Receiver could not process, mapped to a
	// structured error describing why. The Transmitter's response to
	// reported errors is implementation-defined; see RFC 8936 §2.4.1.
	// JSON field name "setErrs" matches RFC 8936 verbatim.
	SetErrs map[string]SetErr `json:"setErrs,omitempty"`

	// MaxEvents caps the number of SETs the Transmitter returns in
	// this poll. A nil pointer means "no cap requested"; a non-nil
	// pointer to zero means "deliver no SETs, only honor the ack".
	// Per RFC 8936 §2.4.1.
	MaxEvents *int `json:"maxEvents,omitempty"`

	// ReturnImmediately, when non-nil and true, asks the Transmitter
	// to return the response without waiting (no long poll). A nil
	// pointer leaves the choice to the Transmitter. Per RFC 8936
	// §2.4.1.
	ReturnImmediately *bool `json:"returnImmediately,omitempty"`
}

// SetErr describes a failure the Receiver encountered while
// processing a single SET, reported back to the Transmitter through
// the [PollRequest.SetErrs] map per RFC 8936 §2.3. Err is a short
// machine-readable token (the SET delivery error code registry); the
// optional Description is a human-readable string for operator
// diagnostics.
type SetErr struct {
	// Err is the short error code identifying the failure class, drawn
	// from the SET Error Codes registry (RFC 8936 §6).
	Err string `json:"err"`

	// Description is an optional human-readable explanation. Operator
	// diagnostics, not machine-actionable.
	Description string `json:"description,omitempty"`
}

// PollResponse is the body the Transmitter returns from its poll
// endpoint per RFC 8936 §2.4. Sets carries the queued SETs as a map
// from JTI to JWS compact serialization — the same opaque token the
// Receiver will quote in its next [PollRequest.Ack] once consumed.
//
// The Sets field is intentionally tagged without omitempty: an empty
// poll response carries an explicit {"sets": {}} on the wire, not an
// absent sets key. MoreAvailable is a pointer so a nil value
// round-trips as field-absent, distinct from explicit "false".
type PollResponse struct {
	// Sets maps each SET's JTI to its JWS compact serialization (the
	// signed token string). An empty map is the wire-level "nothing
	// to deliver right now" response.
	Sets map[string]string `json:"sets"`

	// MoreAvailable, when non-nil and true, signals that the
	// Transmitter has additional queued SETs the Receiver should
	// poll for promptly rather than waiting out the normal cadence.
	// Per RFC 8936 §2.4.
	MoreAvailable *bool `json:"moreAvailable,omitempty"`
}
