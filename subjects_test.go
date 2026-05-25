// Copyright 2026 The go-ssf Authors
// SPDX-License-Identifier: Apache-2.0

package ssf

import (
	"encoding/json"
	"testing"

	"github.com/hstern/go-subjectid"
)

// TestAddSubjectRequestRoundTripAccount round-trips an
// AddSubjectRequest carrying an Account-format subject and the
// optional Verified=true flag. It pins both halves of the contract
// the spec §7.1.3 cares about:
//
//   - The "subject" discriminator ("format":"account") survives the
//     decode/encode cycle byte-for-byte.
//   - The pointer-bool Verified field round-trips its presence
//     (non-nil → emitted) and its value (true).
func TestAddSubjectRequestRoundTripAccount(t *testing.T) {
	t.Parallel()

	input := []byte(`{"subject":{"format":"account","uri":"acct:user@example.com"},"verified":true}`)

	var req AddSubjectRequest
	if err := json.Unmarshal(input, &req); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}

	acct, ok := req.Subject.(*subjectid.AccountID)
	if !ok {
		t.Fatalf("subject dispatched to %T, want *subjectid.AccountID", req.Subject)
	}
	if got, want := acct.URI, "acct:user@example.com"; got != want {
		t.Errorf("AccountID.URI = %q, want %q", got, want)
	}
	if req.Verified == nil || !*req.Verified {
		t.Errorf("Verified = %v, want non-nil pointer to true", req.Verified)
	}

	out, err := json.Marshal(req)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if string(out) != string(input) {
		t.Errorf("round-trip\n got: %s\nwant: %s", out, input)
	}
}

// TestAddSubjectRequestVerifiedFalseRoundTrips confirms that an
// explicit "verified":false survives the round trip. A plain
// bool with omitempty would have lost it; the pointer-bool shape
// is specifically there to keep the false/absent distinction the
// spec treats as meaningful.
func TestAddSubjectRequestVerifiedFalseRoundTrips(t *testing.T) {
	t.Parallel()

	input := []byte(`{"subject":{"format":"account","uri":"acct:user@example.com"},"verified":false}`)

	var req AddSubjectRequest
	if err := json.Unmarshal(input, &req); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if req.Verified == nil {
		t.Fatalf("Verified = nil, want non-nil pointer to false")
	}
	if *req.Verified {
		t.Errorf("*Verified = true, want false")
	}

	out, err := json.Marshal(req)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if string(out) != string(input) {
		t.Errorf("round-trip\n got: %s\nwant: %s", out, input)
	}
}

// TestAddSubjectRequestVerifiedAbsentOmitted confirms that an
// input with no "verified" member decodes to Verified=nil and
// re-marshals without emitting a "verified" key.
func TestAddSubjectRequestVerifiedAbsentOmitted(t *testing.T) {
	t.Parallel()

	input := []byte(`{"subject":{"format":"account","uri":"acct:user@example.com"}}`)

	var req AddSubjectRequest
	if err := json.Unmarshal(input, &req); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if req.Verified != nil {
		t.Errorf("Verified = %v, want nil", *req.Verified)
	}

	out, err := json.Marshal(req)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if string(out) != string(input) {
		t.Errorf("round-trip\n got: %s\nwant: %s", out, input)
	}
}

// TestRemoveSubjectRequestRoundTripEmail round-trips a
// RemoveSubjectRequest carrying an Email-format subject. The
// remove flow has no Verified member; absence of that field on
// the wire is the test.
func TestRemoveSubjectRequestRoundTripEmail(t *testing.T) {
	t.Parallel()

	input := []byte(`{"subject":{"format":"email","email":"user@example.com"}}`)

	var req RemoveSubjectRequest
	if err := json.Unmarshal(input, &req); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}

	em, ok := req.Subject.(*subjectid.EmailID)
	if !ok {
		t.Fatalf("subject dispatched to %T, want *subjectid.EmailID", req.Subject)
	}
	if got, want := em.Email, "user@example.com"; got != want {
		t.Errorf("EmailID.Email = %q, want %q", got, want)
	}

	out, err := json.Marshal(req)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if string(out) != string(input) {
		t.Errorf("round-trip\n got: %s\nwant: %s", out, input)
	}
}

// TestAddSubjectRequestUnknownFormatFallback confirms the forward-
// compatibility contract: an unrecognized "format" parses into an
// UnknownFormat carrier rather than failing, so a Receiver running
// an older copy of the library can still ingest an Add request for
// a subject identifier format introduced after the library's
// release.
func TestAddSubjectRequestUnknownFormatFallback(t *testing.T) {
	t.Parallel()

	input := []byte(`{"subject":{"format":"future-fmt","x":"y"}}`)

	var req AddSubjectRequest
	if err := json.Unmarshal(input, &req); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if _, ok := req.Subject.(*subjectid.UnknownFormat); !ok {
		t.Fatalf("subject dispatched to %T, want *subjectid.UnknownFormat", req.Subject)
	}
}

// TestAddSubjectRequestRejectsMissingFormat confirms that a
// subject envelope with no "format" member surfaces an error
// rather than silently producing a zero-valued identifier. The
// error origin is go-subjectid's Parse — the receive path here
// is just a delegate.
func TestAddSubjectRequestRejectsMissingFormat(t *testing.T) {
	t.Parallel()

	input := []byte(`{"subject":{"uri":"acct:x@example.com"}}`)

	var req AddSubjectRequest
	if err := json.Unmarshal(input, &req); err == nil {
		t.Fatalf("unmarshal succeeded, want error")
	}
}

// TestRemoveSubjectRequestRejectsMissingFormat is the same
// negative case for the remove flow.
func TestRemoveSubjectRequestRejectsMissingFormat(t *testing.T) {
	t.Parallel()

	input := []byte(`{"subject":{"email":"user@example.com"}}`)

	var req RemoveSubjectRequest
	if err := json.Unmarshal(input, &req); err == nil {
		t.Fatalf("unmarshal succeeded, want error")
	}
}
