// Copyright 2026 The go-ssf Authors
// SPDX-License-Identifier: Apache-2.0

package ssf

import (
	"encoding/json"

	"github.com/hstern/go-subjectid"
)

// AddSubjectRequest is the body of a POST to the Transmitter's
// add-subject endpoint, per OpenID Shared Signals Framework 1.0
// §7.1.3.
//
// The Subject is an RFC 9493 Subject Identifier. Because Subject
// Identifiers are a discriminated union keyed on the "format"
// member, the concrete Go type is the [subjectid.SubjectIdentifier]
// interface; [AddSubjectRequest.UnmarshalJSON] dispatches through
// go-subjectid's format registry to pick the matching per-format
// type (AccountID, EmailID, IssSubID, OpaqueID, PhoneNumberID,
// DIDID, URIID, AliasesID, or an UnknownFormat carrier for
// extensions the registry has not seen).
//
// Verified is optional and carries the Transmitter's hint about
// whether the supplied subject identifier has already been
// verified through some out-of-band channel. The pointer-bool
// shape preserves the wire distinction between "absent" (nil) and
// "present and false" (&false): an explicit false is meaningful
// per the spec, and a plain bool with omitempty would lose it.
type AddSubjectRequest struct {
	// Subject is the RFC 9493 Subject Identifier the Receiver is
	// asking the Transmitter to begin emitting events for on the
	// referenced stream. Required.
	Subject subjectid.SubjectIdentifier `json:"subject"`

	// Verified, when non-nil, indicates whether the Transmitter
	// should treat the subject identifier as already verified.
	// Omitted from the wire when nil.
	Verified *bool `json:"verified,omitempty"`
}

// addSubjectRequestWire is the on-the-wire shape used by
// [AddSubjectRequest.UnmarshalJSON] to split the discriminator-
// bearing subject from the rest of the body. Subject is captured
// as raw bytes so [subjectid.Parse] can dispatch on the "format"
// member without re-parsing the outer envelope.
type addSubjectRequestWire struct {
	Subject  json.RawMessage `json:"subject"`
	Verified *bool           `json:"verified,omitempty"`
}

// UnmarshalJSON implements [json.Unmarshaler] for AddSubjectRequest.
// It captures the "subject" member as raw JSON, then delegates to
// [subjectid.Parse] so the format-dispatch logic — and the forward-
// compatible UnknownFormat fallback — lives in exactly one place,
// owned by go-subjectid.
//
// Per the lenient-unmarshal convention, extra members in the
// envelope are silently ignored; validation of the decoded subject
// is the caller's job via [subjectid.SubjectIdentifier.Validate].
func (r *AddSubjectRequest) UnmarshalJSON(data []byte) error {
	var w addSubjectRequestWire
	if err := json.Unmarshal(data, &w); err != nil {
		return err
	}
	subj, err := subjectid.Parse(w.Subject)
	if err != nil {
		return err
	}
	r.Subject = subj
	r.Verified = w.Verified
	return nil
}

// RemoveSubjectRequest is the body of a POST to the Transmitter's
// remove-subject endpoint, per OpenID Shared Signals Framework 1.0
// §7.1.3.
//
// Unlike [AddSubjectRequest] there is no "verified" member — the
// remove flow asks the Transmitter to stop emitting events for
// the named subject and has no notion of verification state.
type RemoveSubjectRequest struct {
	// Subject is the RFC 9493 Subject Identifier the Receiver is
	// asking the Transmitter to stop emitting events for on the
	// referenced stream. Required.
	Subject subjectid.SubjectIdentifier `json:"subject"`
}

// removeSubjectRequestWire mirrors [addSubjectRequestWire] but
// omits Verified — see [RemoveSubjectRequest] for why.
type removeSubjectRequestWire struct {
	Subject json.RawMessage `json:"subject"`
}

// UnmarshalJSON implements [json.Unmarshaler] for
// RemoveSubjectRequest. The dispatch contract matches
// [AddSubjectRequest.UnmarshalJSON]; only the envelope shape
// differs.
func (r *RemoveSubjectRequest) UnmarshalJSON(data []byte) error {
	var w removeSubjectRequestWire
	if err := json.Unmarshal(data, &w); err != nil {
		return err
	}
	subj, err := subjectid.Parse(w.Subject)
	if err != nil {
		return err
	}
	r.Subject = subj
	return nil
}
