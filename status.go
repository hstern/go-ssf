// Copyright 2026 The go-ssf Authors
// SPDX-License-Identifier: Apache-2.0

package ssf

import "encoding/json"

// StreamStatus is the lifecycle state of a single SSF stream per
// OpenID Shared Signals Framework 1.0 §7.1.2. A Receiver reads the
// current status from the Transmitter's status endpoint and may
// request a transition via [StatusUpdateRequest]; the Transmitter
// returns the resulting state — possibly delayed or refused — in a
// [StatusResponse].
//
// The wire form is a JSON string drawn from a closed three-value
// enum. Library code treats the type as an opaque string for
// round-trip purposes — unknown values decode and re-encode as-is —
// and an opt-in Validate helper that lands in a later phase rejects
// values outside the spec set on the send side.
type StreamStatus string

// The three StreamStatus values defined by OpenID Shared Signals
// Framework 1.0 §7.1.2.
//
// The spec does not define additional values; any future extension
// would arrive as a spec revision rather than a registry, so the
// list is closed by construction.
const (
	// StreamStatusEnabled marks a stream as actively delivering
	// events. Subjects added to the stream produce SETs that the
	// Transmitter pushes or makes available for polling.
	StreamStatusEnabled StreamStatus = "enabled"

	// StreamStatusPaused marks a stream as temporarily halted. The
	// Transmitter retains queued events and resumes delivery on a
	// transition back to [StreamStatusEnabled]; the spec leaves the
	// retention window implementation-defined.
	StreamStatusPaused StreamStatus = "paused"

	// StreamStatusDisabled marks a stream as administratively
	// stopped. The Transmitter MAY drop queued events; a Receiver
	// that wants delivery resumed transitions the stream back to
	// [StreamStatusEnabled] and accepts that events generated while
	// disabled may be lost.
	StreamStatusDisabled StreamStatus = "disabled"
)

// StatusResponse is the body a Transmitter returns from the stream
// status endpoint per OpenID Shared Signals Framework 1.0 §7.1.2.
// The Receiver issues GET with a stream_id query parameter and
// receives this object describing the stream's current state.
//
// [StatusResponse.Subject] is present only when the response scopes
// the status to a single subject within the stream rather than the
// stream as a whole. The field is kept as [json.RawMessage] so this
// file does not pull in the Subject Identifier dependency that
// lands in a later phase — codec wiring promotes it to a typed
// Subject Identifier without changing this struct's exported name.
type StatusResponse struct {
	// Status is the current lifecycle state of the stream (or of
	// the [StatusResponse.Subject] within the stream, if set).
	// Required by spec §7.1.2.
	Status StreamStatus `json:"status"`

	// Reason is a free-form human-readable explanation the
	// Transmitter MAY include alongside a [StreamStatusPaused] or
	// [StreamStatusDisabled] state per spec §7.1.2. Absent for the
	// enabled state in practice; the omitempty tag preserves
	// absence on round-trip.
	Reason string `json:"reason,omitempty"`

	// Subject, when present, scopes the response to a single
	// subject within the stream rather than the stream as a whole
	// per spec §7.1.2. Carried as [json.RawMessage] for wire-byte
	// fidelity; a later codec phase wires Subject Identifier
	// typing without changing this field's JSON name.
	Subject json.RawMessage `json:"subject,omitempty"`
}

// StatusUpdateRequest is the body a Receiver POSTs to the stream
// status endpoint to request a lifecycle transition per OpenID
// Shared Signals Framework 1.0 §7.1.2. The Transmitter MAY honor,
// delay, or refuse the request; the resulting state is returned in
// a [StatusResponse] (potentially asynchronously, with subsequent
// GETs reflecting the converged state).
//
// The shape mirrors [StatusResponse]: [StatusUpdateRequest.Status]
// names the requested state, [StatusUpdateRequest.Reason] carries
// an optional human-readable rationale, and
// [StatusUpdateRequest.Subject] scopes the request to a single
// subject when set. Subject is [json.RawMessage] for the same
// reason as on [StatusResponse].
type StatusUpdateRequest struct {
	// Status is the requested lifecycle state. Required by spec
	// §7.1.2.
	Status StreamStatus `json:"status"`

	// Reason is an optional human-readable rationale the Receiver
	// supplies alongside the request — for example, the operator
	// note motivating a pause. Preserved verbatim on round-trip.
	Reason string `json:"reason,omitempty"`

	// Subject, when present, scopes the requested transition to a
	// single subject within the stream rather than the stream as
	// a whole. Carried as [json.RawMessage] for wire-byte fidelity
	// pending the Subject Identifier wiring in a later phase.
	Subject json.RawMessage `json:"subject,omitempty"`
}
