// Copyright 2026 The go-ssf Authors
// SPDX-License-Identifier: Apache-2.0

package ssf

import (
	"bytes"
	"encoding/json"
	"reflect"
	"testing"
)

// roundTripJSON marshals v, unmarshals the result into a fresh
// instance of the same dynamic type, and returns the marshaled
// bytes plus the decoded value. The helper drives the round-trip
// tests below without each call site re-typing the boilerplate.
func roundTripJSON[T any](t *testing.T, v T) ([]byte, T) {
	t.Helper()

	encoded, err := json.Marshal(v)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}

	var decoded T
	if err := json.Unmarshal(encoded, &decoded); err != nil {
		t.Fatalf("unmarshal %s: %v", encoded, err)
	}

	return encoded, decoded
}

func TestPollRequest_RoundTrip(t *testing.T) {
	t.Parallel()

	maxEvents := 50
	returnImmediately := true

	tests := []struct {
		name string
		req  PollRequest
		// wantJSON is the exact JSON the marshaler must produce. The
		// fields are listed in struct-definition order, which is the
		// order encoding/json emits them.
		wantJSON string
	}{
		{
			name: "all fields populated",
			req: PollRequest{
				Ack: []string{"jti-1", "jti-2"},
				SetErrs: map[string]SetErr{
					"jti-3": {Err: "invalid_key", Description: "key not in JWKS"},
				},
				MaxEvents:         &maxEvents,
				ReturnImmediately: &returnImmediately,
			},
			wantJSON: `{"ack":["jti-1","jti-2"],"setErrs":{"jti-3":{"err":"invalid_key","description":"key not in JWKS"}},"maxEvents":50,"returnImmediately":true}`,
		},
		{
			name: "ack only",
			req: PollRequest{
				Ack: []string{"jti-1"},
			},
			wantJSON: `{"ack":["jti-1"]}`,
		},
		{
			name:     "empty heartbeat",
			req:      PollRequest{},
			wantJSON: `{}`,
		},
		{
			name: "explicit maxEvents zero round-trips",
			req: PollRequest{
				MaxEvents: ptr(0),
			},
			wantJSON: `{"maxEvents":0}`,
		},
		{
			name: "setErr with no description",
			req: PollRequest{
				SetErrs: map[string]SetErr{
					"jti-9": {Err: "decode_error"},
				},
			},
			wantJSON: `{"setErrs":{"jti-9":{"err":"decode_error"}}}`,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			encoded, decoded := roundTripJSON(t, tc.req)

			if string(encoded) != tc.wantJSON {
				t.Errorf("marshal:\n got: %s\nwant: %s", encoded, tc.wantJSON)
			}

			if !reflect.DeepEqual(decoded, tc.req) {
				t.Errorf("round-trip:\n got: %#v\nwant: %#v", decoded, tc.req)
			}
		})
	}
}

func TestPollResponse_RoundTrip(t *testing.T) {
	t.Parallel()

	moreAvailable := true

	tests := []struct {
		name     string
		resp     PollResponse
		wantJSON string
	}{
		{
			name: "one SET",
			resp: PollResponse{
				Sets: map[string]string{
					"jti-1": "eyJhbGciOiJSUzI1NiJ9.payload.signature",
				},
			},
			wantJSON: `{"sets":{"jti-1":"eyJhbGciOiJSUzI1NiJ9.payload.signature"}}`,
		},
		{
			name: "empty sets emits {}",
			resp: PollResponse{
				Sets: map[string]string{},
			},
			wantJSON: `{"sets":{}}`,
		},
		{
			name: "moreAvailable true",
			resp: PollResponse{
				Sets:          map[string]string{"jti-1": "set-bytes"},
				MoreAvailable: &moreAvailable,
			},
			wantJSON: `{"sets":{"jti-1":"set-bytes"},"moreAvailable":true}`,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			encoded, decoded := roundTripJSON(t, tc.resp)

			if !bytes.Equal(encoded, []byte(tc.wantJSON)) {
				t.Errorf("marshal:\n got: %s\nwant: %s", encoded, tc.wantJSON)
			}

			if !reflect.DeepEqual(decoded, tc.resp) {
				t.Errorf("round-trip:\n got: %#v\nwant: %#v", decoded, tc.resp)
			}
		})
	}
}

// TestPollResponse_NilSetsRoundTrip pins the asymmetry between nil
// and empty Sets maps: encoding/json emits "null" for a nil map, and
// decodes "null" back to nil. Both are legal on the wire under
// Postel's law; only the explicit empty map encodes as {}.
func TestPollResponse_NilSetsRoundTrip(t *testing.T) {
	t.Parallel()

	encoded, decoded := roundTripJSON(t, PollResponse{})
	const want = `{"sets":null}`

	if string(encoded) != want {
		t.Errorf("marshal:\n got: %s\nwant: %s", encoded, want)
	}

	if decoded.Sets != nil {
		t.Errorf("decoded Sets: got %#v, want nil", decoded.Sets)
	}
}

// ptr returns a pointer to v. Used in table-driven tests where the
// pointer fields on PollRequest / PollResponse need inline literal
// values.
func ptr[T any](v T) *T { return &v }
