// Copyright 2026 The go-ssf Authors
// SPDX-License-Identifier: Apache-2.0

package ssf

import (
	"encoding/json"
	"testing"
)

func TestVerificationRequestRoundTrip(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		req     VerificationRequest
		wantOut string
	}{
		{
			name:    "with state",
			req:     VerificationRequest{State: "VGhpcyBpcyBhbiBleGFtcGxlIHN0YXRl"},
			wantOut: `{"state":"VGhpcyBpcyBhbiBleGFtcGxlIHN0YXRl"}`,
		},
		{
			name:    "empty state omitted",
			req:     VerificationRequest{},
			wantOut: `{}`,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			out, err := json.Marshal(tc.req)
			if err != nil {
				t.Fatalf("Marshal: %v", err)
			}
			if got := string(out); got != tc.wantOut {
				t.Fatalf("Marshal: got %q, want %q", got, tc.wantOut)
			}

			var got VerificationRequest
			if err := json.Unmarshal(out, &got); err != nil {
				t.Fatalf("Unmarshal: %v", err)
			}
			if got != tc.req {
				t.Fatalf("round-trip: got %+v, want %+v", got, tc.req)
			}
		})
	}
}

// TestVerificationRequestUnmarshalLenient confirms that an explicit
// JSON null for the optional state field decodes to the zero value
// without error, per the library's lenient-unmarshal convention.
func TestVerificationRequestUnmarshalLenient(t *testing.T) {
	t.Parallel()

	var got VerificationRequest
	if err := json.Unmarshal([]byte(`{"state":null}`), &got); err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}
	if got.State != "" {
		t.Fatalf("State: got %q, want empty", got.State)
	}
}

// TestVerificationEventInSET round-trips a VerificationEvent inside
// the events claim of a synthetic SET-shaped JSON object, keyed by
// EventTypeVerification per spec §7.1.4.
func TestVerificationEventInSET(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name  string
		event VerificationEvent
	}{
		{
			name:  "with state",
			event: VerificationEvent{State: "VGhpcyBpcyBhbiBleGFtcGxlIHN0YXRl"},
		},
		{
			name:  "empty state",
			event: VerificationEvent{},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			envelope := map[string]map[string]VerificationEvent{
				"events": {
					EventTypeVerification: tc.event,
				},
			}
			out, err := json.Marshal(envelope)
			if err != nil {
				t.Fatalf("Marshal: %v", err)
			}

			var got map[string]map[string]VerificationEvent
			if err := json.Unmarshal(out, &got); err != nil {
				t.Fatalf("Unmarshal: %v", err)
			}
			roundTripped, ok := got["events"][EventTypeVerification]
			if !ok {
				t.Fatalf("event keyed by %q not present after round trip; payload was %s",
					EventTypeVerification, out)
			}
			if roundTripped != tc.event {
				t.Fatalf("round-trip: got %+v, want %+v", roundTripped, tc.event)
			}
		})
	}
}

// TestVerificationEventInRawSET confirms the on-wire shape against
// the literal payload from spec §7.1.4 — events claim mapping the
// verification URI to a single-field object carrying the echoed
// state.
func TestVerificationEventInRawSET(t *testing.T) {
	t.Parallel()

	raw := `{"events":{"` + EventTypeVerification + `":{"state":"VGhpcyBpcyBhbiBleGFtcGxlIHN0YXRl"}}}`

	var decoded struct {
		Events map[string]VerificationEvent `json:"events"`
	}
	if err := json.Unmarshal([]byte(raw), &decoded); err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}
	got, ok := decoded.Events[EventTypeVerification]
	if !ok {
		t.Fatalf("event keyed by %q not present in %q", EventTypeVerification, raw)
	}
	want := VerificationEvent{State: "VGhpcyBpcyBhbiBleGFtcGxlIHN0YXRl"}
	if got != want {
		t.Fatalf("decode: got %+v, want %+v", got, want)
	}

	out, err := json.Marshal(decoded)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	if string(out) != raw {
		t.Fatalf("round-trip mismatch:\n  got  %s\n  want %s", out, raw)
	}
}
