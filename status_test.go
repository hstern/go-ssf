// Copyright 2026 The go-ssf Authors
// SPDX-License-Identifier: Apache-2.0

package ssf_test

import (
	"bytes"
	"encoding/json"
	"testing"

	ssf "github.com/hstern/go-ssf"
)

func TestStreamStatusConstants(t *testing.T) {
	t.Parallel()
	cases := []struct {
		got  ssf.StreamStatus
		want string
	}{
		{ssf.StreamStatusEnabled, "enabled"},
		{ssf.StreamStatusPaused, "paused"},
		{ssf.StreamStatusDisabled, "disabled"},
	}
	for _, tc := range cases {
		if string(tc.got) != tc.want {
			t.Errorf("StreamStatus(%q) wire value = %q, want %q", tc.want, string(tc.got), tc.want)
		}
	}
}

func TestStatusResponseRoundTrip(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name string
		in   string
		want ssf.StatusResponse
	}{
		{
			name: "enabled stream-wide, no reason",
			in:   `{"status":"enabled"}`,
			want: ssf.StatusResponse{Status: ssf.StreamStatusEnabled},
		},
		{
			name: "paused with reason",
			in:   `{"status":"paused","reason":"maintenance window"}`,
			want: ssf.StatusResponse{Status: ssf.StreamStatusPaused, Reason: "maintenance window"},
		},
		{
			name: "disabled with reason",
			in:   `{"status":"disabled","reason":"administratively closed"}`,
			want: ssf.StatusResponse{Status: ssf.StreamStatusDisabled, Reason: "administratively closed"},
		},
		{
			name: "subject-scoped paused",
			in:   `{"status":"paused","reason":"per-subject quiet","subject":{"format":"email","email":"alice@example.com"}}`,
			want: ssf.StatusResponse{
				Status:  ssf.StreamStatusPaused,
				Reason:  "per-subject quiet",
				Subject: json.RawMessage(`{"format":"email","email":"alice@example.com"}`),
			},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			var got ssf.StatusResponse
			if err := json.Unmarshal([]byte(tc.in), &got); err != nil {
				t.Fatalf("unmarshal: %v", err)
			}
			if got.Status != tc.want.Status || got.Reason != tc.want.Reason {
				t.Errorf("decoded scalars = %+v, want %+v", got, tc.want)
			}
			if !bytes.Equal(got.Subject, tc.want.Subject) {
				t.Errorf("decoded subject = %s, want %s", got.Subject, tc.want.Subject)
			}

			out, err := json.Marshal(got)
			if err != nil {
				t.Fatalf("marshal: %v", err)
			}
			if !bytes.Equal(out, []byte(tc.in)) {
				t.Errorf("round-trip mismatch:\n  got  %s\n  want %s", out, tc.in)
			}
		})
	}
}

func TestStatusUpdateRequestRoundTrip(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name string
		in   string
		want ssf.StatusUpdateRequest
	}{
		{
			name: "request enabled, no reason",
			in:   `{"status":"enabled"}`,
			want: ssf.StatusUpdateRequest{Status: ssf.StreamStatusEnabled},
		},
		{
			name: "request paused with reason",
			in:   `{"status":"paused","reason":"caller-side pause"}`,
			want: ssf.StatusUpdateRequest{Status: ssf.StreamStatusPaused, Reason: "caller-side pause"},
		},
		{
			name: "request disabled with reason",
			in:   `{"status":"disabled","reason":"decommissioning receiver"}`,
			want: ssf.StatusUpdateRequest{Status: ssf.StreamStatusDisabled, Reason: "decommissioning receiver"},
		},
		{
			name: "subject-scoped disable",
			in:   `{"status":"disabled","reason":"subject opt-out","subject":{"format":"opaque","id":"abc123"}}`,
			want: ssf.StatusUpdateRequest{
				Status:  ssf.StreamStatusDisabled,
				Reason:  "subject opt-out",
				Subject: json.RawMessage(`{"format":"opaque","id":"abc123"}`),
			},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			var got ssf.StatusUpdateRequest
			if err := json.Unmarshal([]byte(tc.in), &got); err != nil {
				t.Fatalf("unmarshal: %v", err)
			}
			if got.Status != tc.want.Status || got.Reason != tc.want.Reason {
				t.Errorf("decoded scalars = %+v, want %+v", got, tc.want)
			}
			if !bytes.Equal(got.Subject, tc.want.Subject) {
				t.Errorf("decoded subject = %s, want %s", got.Subject, tc.want.Subject)
			}

			out, err := json.Marshal(got)
			if err != nil {
				t.Fatalf("marshal: %v", err)
			}
			if !bytes.Equal(out, []byte(tc.in)) {
				t.Errorf("round-trip mismatch:\n  got  %s\n  want %s", out, tc.in)
			}
		})
	}
}

func TestStatusResponseReasonOmitted(t *testing.T) {
	t.Parallel()
	resp := ssf.StatusResponse{Status: ssf.StreamStatusEnabled}
	out, err := json.Marshal(resp)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	const want = `{"status":"enabled"}`
	if string(out) != want {
		t.Errorf("marshal with empty reason = %s, want %s", out, want)
	}
}

func TestStatusResponseSubjectAbsentVsPresent(t *testing.T) {
	t.Parallel()
	// Absent subject must omit the key entirely; a nil RawMessage
	// is the absence form.
	absent := ssf.StatusResponse{Status: ssf.StreamStatusEnabled}
	out, err := json.Marshal(absent)
	if err != nil {
		t.Fatalf("marshal absent: %v", err)
	}
	if bytes.Contains(out, []byte(`"subject"`)) {
		t.Errorf("absent subject leaked into wire form: %s", out)
	}

	present := ssf.StatusResponse{
		Status:  ssf.StreamStatusEnabled,
		Subject: json.RawMessage(`{"format":"email","email":"bob@example.com"}`),
	}
	out, err = json.Marshal(present)
	if err != nil {
		t.Fatalf("marshal present: %v", err)
	}
	const want = `{"status":"enabled","subject":{"format":"email","email":"bob@example.com"}}`
	if string(out) != want {
		t.Errorf("subject-present marshal = %s, want %s", out, want)
	}
}
