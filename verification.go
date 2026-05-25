// Copyright 2026 The go-ssf Authors
// SPDX-License-Identifier: Apache-2.0

package ssf

// EventTypeVerification is the event-type URI for the Shared Signals
// Framework verification event, per spec §7.1.4. A Receiver POSTs a
// [VerificationRequest] to the Transmitter's verification endpoint;
// the Transmitter responds 200 and separately delivers a Security
// Event Token whose events claim is keyed by this URI and carries a
// [VerificationEvent] payload echoing the Receiver-supplied state.
//
// Receivers match the echoed state to the request to confirm that
// the configured delivery channel is functioning end-to-end.
const EventTypeVerification = "https://schemas.openid.net/secevent/ssf/event-type/verification"

// VerificationRequest is the body a Receiver POSTs to the
// Transmitter's verification endpoint per spec §7.1.4. The request
// itself carries no subject — it is a control-plane probe that
// asks the Transmitter to deliver a verification event over the
// stream's configured delivery method.
//
// The optional State is an opaque echo string chosen by the
// Receiver. The Transmitter copies it verbatim into the
// [VerificationEvent] carried by the resulting Security Event
// Token, letting the Receiver correlate the inbound event to the
// outbound request — for example when several verification probes
// are in flight concurrently.
type VerificationRequest struct {
	// State is the optional opaque echo string. Omitted from the
	// wire form when empty.
	State string `json:"state,omitempty"`
}

// VerificationEvent is the payload carried under the events claim
// of a verification Security Event Token, keyed by
// [EventTypeVerification], per spec §7.1.4. It mirrors the State
// supplied on the originating [VerificationRequest], or is empty
// when the Receiver omitted state.
type VerificationEvent struct {
	// State mirrors the Receiver-supplied state from the originating
	// [VerificationRequest]. Omitted from the wire form when empty.
	State string `json:"state,omitempty"`
}
