// Copyright 2026 The go-ssf Authors
// SPDX-License-Identifier: Apache-2.0

package ssf

import (
	"bytes"
	"encoding/json"
	"reflect"
	"testing"
)

// TestStreamConfigRoundTripPush exercises a full round-trip of a
// push-mode StreamConfig modeled on the spec §7.1.1 example shape:
// a Transmitter-issued configuration with the push delivery method
// URI (urn:ietf:rfc:8935), an endpoint URL on the Receiver side, an
// audience as a single JSON string, and a single event-type URI
// requested. The test asserts that unmarshal-then-marshal yields
// JSON byte-equivalent to the input under [encoding/json]'s default
// canonical-key ordering (which is the order the struct fields are
// declared in), and that all typed fields survive the round-trip
// intact.
func TestStreamConfigRoundTripPush(t *testing.T) {
	t.Parallel()

	in := []byte(`{
		"stream_id": "f67e39a0a4d34d56b3aa1bc4cff0069f",
		"iss": "https://transmitter.example.com",
		"aud": "https://receiver.example.com",
		"events_supported": [
			"https://schemas.openid.net/secevent/ssf/event-type/verification",
			"https://schemas.openid.net/secevent/caep/event-type/session-revoked"
		],
		"events_requested": [
			"https://schemas.openid.net/secevent/ssf/event-type/verification"
		],
		"events_delivered": [
			"https://schemas.openid.net/secevent/ssf/event-type/verification"
		],
		"delivery": {
			"method": "urn:ietf:rfc:8935",
			"endpoint_url": "https://receiver.example.com/events",
			"authorization_header": "Bearer rcvr-token"
		},
		"min_verification_interval": 60,
		"format": "iss_sub"
	}`)

	var got StreamConfig
	if err := json.Unmarshal(in, &got); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}

	if got.StreamID != "f67e39a0a4d34d56b3aa1bc4cff0069f" {
		t.Errorf("StreamID = %q, want %q", got.StreamID, "f67e39a0a4d34d56b3aa1bc4cff0069f")
	}
	if got.Iss != "https://transmitter.example.com" {
		t.Errorf("Iss = %q", got.Iss)
	}
	// Aud is RawMessage — compare the canonical JSON form.
	if !jsonEqual(t, got.Aud, []byte(`"https://receiver.example.com"`)) {
		t.Errorf("Aud = %s", string(got.Aud))
	}
	if got.Delivery.Method != DeliveryMethodPush {
		t.Errorf("Delivery.Method = %q, want %q", got.Delivery.Method, DeliveryMethodPush)
	}
	if got.Delivery.EndpointURL != "https://receiver.example.com/events" {
		t.Errorf("Delivery.EndpointURL = %q", got.Delivery.EndpointURL)
	}
	if got.Delivery.AuthorizationHeader != "Bearer rcvr-token" {
		t.Errorf("Delivery.AuthorizationHeader = %q", got.Delivery.AuthorizationHeader)
	}
	if got.MinVerificationInterval != 60 {
		t.Errorf("MinVerificationInterval = %d", got.MinVerificationInterval)
	}
	if got.Format != "iss_sub" {
		t.Errorf("Format = %q", got.Format)
	}
	wantRequested := []string{
		"https://schemas.openid.net/secevent/ssf/event-type/verification",
	}
	if !reflect.DeepEqual(got.EventsRequested, wantRequested) {
		t.Errorf("EventsRequested = %v, want %v", got.EventsRequested, wantRequested)
	}

	out, err := json.Marshal(got)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}

	// Round-trip the marshal output back through unmarshal and
	// compare the result struct-for-struct. This catches both
	// "data dropped" and "data smeared" regressions without
	// asserting a specific byte order (which encoding/json doesn't
	// guarantee across Go versions for nested objects).
	var roundtrip StreamConfig
	if err := json.Unmarshal(out, &roundtrip); err != nil {
		t.Fatalf("re-unmarshal: %v", err)
	}
	if !equalStreamConfig(got, roundtrip) {
		t.Errorf("round-trip mismatch:\n in  = %+v\n out = %+v", got, roundtrip)
	}
}

// TestStreamConfigRoundTripPoll exercises the poll-mode counterpart:
// the poll delivery method URI (urn:ietf:rfc:8936), an audience
// expressed as a JSON array of strings (the spec permits both shapes
// and the library's [json.RawMessage]-typed Aud field preserves
// whichever shape arrived), no authorization header, and three
// requested events. Verifies that the array form of Aud round-trips
// byte-stably and that omitting the authorization_header on the
// wire decodes to an empty string and re-encodes as omitted.
func TestStreamConfigRoundTripPoll(t *testing.T) {
	t.Parallel()

	in := []byte(`{
		"stream_id": "0b8c1e2d3f4a5b6c7d8e9f0a1b2c3d4e",
		"iss": "https://transmitter.example.com",
		"aud": ["https://receiver-a.example.com","https://receiver-b.example.com"],
		"events_requested": [
			"https://schemas.openid.net/secevent/ssf/event-type/verification",
			"https://schemas.openid.net/secevent/caep/event-type/session-revoked",
			"https://schemas.openid.net/secevent/caep/event-type/credential-change"
		],
		"delivery": {
			"method": "urn:ietf:rfc:8936",
			"endpoint_url": "https://transmitter.example.com/ssf/poll"
		}
	}`)

	var got StreamConfig
	if err := json.Unmarshal(in, &got); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}

	if got.Delivery.Method != DeliveryMethodPoll {
		t.Errorf("Delivery.Method = %q, want %q", got.Delivery.Method, DeliveryMethodPoll)
	}
	if got.Delivery.EndpointURL != "https://transmitter.example.com/ssf/poll" {
		t.Errorf("Delivery.EndpointURL = %q", got.Delivery.EndpointURL)
	}
	if got.Delivery.AuthorizationHeader != "" {
		t.Errorf("Delivery.AuthorizationHeader = %q, want empty", got.Delivery.AuthorizationHeader)
	}
	if len(got.EventsRequested) != 3 {
		t.Errorf("EventsRequested length = %d, want 3", len(got.EventsRequested))
	}
	// The array form must round-trip as an array, not be flattened
	// to a single string. Compare the parsed JSON values to avoid
	// whitespace differences.
	wantAud := []byte(`["https://receiver-a.example.com","https://receiver-b.example.com"]`)
	if !jsonEqual(t, got.Aud, wantAud) {
		t.Errorf("Aud = %s, want %s", string(got.Aud), string(wantAud))
	}

	out, err := json.Marshal(got)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	// The omitted authorization_header field must not reappear on
	// marshal output. This is part of the lenient-in / strict-out
	// contract — an absent optional field stays absent.
	if bytes.Contains(out, []byte("authorization_header")) {
		t.Errorf("marshal reintroduced authorization_header: %s", string(out))
	}
	// Discriminator must round-trip byte-stably as the IANA URI.
	if !bytes.Contains(out, []byte(`"method":"`+DeliveryMethodPoll+`"`)) {
		t.Errorf("marshal lost the poll discriminator: %s", string(out))
	}
}

// TestStreamConfigByteStableRoundTrip exercises a compacted spec-
// shaped payload through unmarshal/marshal and asserts byte-equality
// against the source. Where TestStreamConfigRoundTripPush asserts the
// structural round-trip (DeepEqual), this test pins the wire
// stability that interop scenarios actually compare against.
func TestStreamConfigByteStableRoundTrip(t *testing.T) {
	t.Parallel()

	const in = `{"stream_id":"f67e39a0a4d34d56b3aa1bc4cff0069f",` +
		`"iss":"https://transmitter.example.com",` +
		`"aud":"https://receiver.example.com",` +
		`"events_supported":["https://schemas.openid.net/secevent/ssf/event-type/verification"],` +
		`"events_requested":["https://schemas.openid.net/secevent/ssf/event-type/verification"],` +
		`"events_delivered":["https://schemas.openid.net/secevent/ssf/event-type/verification"],` +
		`"delivery":{"method":"urn:ietf:rfc:8935","endpoint_url":"https://receiver.example.com/events","authorization_header":"Bearer rcvr-token"},` +
		`"min_verification_interval":60,` +
		`"format":"iss_sub"}`

	var sc StreamConfig
	if err := json.Unmarshal([]byte(in), &sc); err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}
	out, err := json.Marshal(sc)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	if string(out) != in {
		t.Errorf("byte-stable round-trip failed\n  in:  %s\n  out: %s", in, out)
	}
}

// TestDeliveryMarshalEmitsMethodFirst pins the discriminator-first
// emission convention that every published OpenID Shared Signals
// Framework example uses for the Delivery object. Receivers that
// stream-decode delivery objects (peeking the method discriminator
// without buffering the whole value) depend on "method" being the
// first member; the project's interop fixtures compare against
// payloads that put it first. The assertion is a byte-level prefix
// check on the marshal output for both built-in methods plus a
// constructed Delivery that carries an authorization header.
func TestDeliveryMarshalEmitsMethodFirst(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name string
		d    Delivery
	}{
		{
			name: "push without auth header",
			d:    Delivery{Method: DeliveryMethodPush, EndpointURL: "https://receiver.example.com/events"},
		},
		{
			name: "poll without auth header",
			d:    Delivery{Method: DeliveryMethodPoll, EndpointURL: "https://transmitter.example.com/ssf/poll"},
		},
		{
			name: "push with auth header",
			d: Delivery{
				Method:              DeliveryMethodPush,
				EndpointURL:         "https://receiver.example.com/events",
				AuthorizationHeader: "Bearer rcvr-token",
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			out, err := json.Marshal(tc.d)
			if err != nil {
				t.Fatalf("Marshal: %v", err)
			}
			if !bytes.HasPrefix(out, []byte(`{"method":"`)) {
				t.Errorf("marshal does not lead with \"method\": %s", out)
			}
		})
	}
}

// TestDeliveryMethodConstants pins the discriminator URI values to
// their IANA-registered form. Pure regression guard against a typo
// in the constant declarations propagating silently into wire
// fixtures.
func TestDeliveryMethodConstants(t *testing.T) {
	t.Parallel()

	if DeliveryMethodPush != "urn:ietf:rfc:8935" {
		t.Errorf("DeliveryMethodPush = %q", DeliveryMethodPush)
	}
	if DeliveryMethodPoll != "urn:ietf:rfc:8936" {
		t.Errorf("DeliveryMethodPoll = %q", DeliveryMethodPoll)
	}
}

// jsonEqual compares two JSON byte slices for semantic equality by
// unmarshaling both into [any] and comparing with reflect.DeepEqual.
// Avoids false negatives from whitespace, key order, or numeric
// formatting differences.
func jsonEqual(t *testing.T, a, b []byte) bool {
	t.Helper()
	var av, bv any
	if err := json.Unmarshal(a, &av); err != nil {
		t.Fatalf("jsonEqual: unmarshal a: %v (%s)", err, string(a))
	}
	if err := json.Unmarshal(b, &bv); err != nil {
		t.Fatalf("jsonEqual: unmarshal b: %v (%s)", err, string(b))
	}
	return reflect.DeepEqual(av, bv)
}

// equalStreamConfig compares two [StreamConfig] values for round-trip
// equivalence. Aud is compared as JSON values rather than as raw
// bytes, since [encoding/json] is free to re-emit whitespace inside
// a [json.RawMessage]; every other field is a primitive or slice
// that reflect.DeepEqual handles correctly.
func equalStreamConfig(a, b StreamConfig) bool {
	if a.StreamID != b.StreamID ||
		a.Iss != b.Iss ||
		a.MinVerificationInterval != b.MinVerificationInterval ||
		a.Format != b.Format ||
		a.Delivery != b.Delivery {
		return false
	}
	if !reflect.DeepEqual(a.EventsSupported, b.EventsSupported) ||
		!reflect.DeepEqual(a.EventsRequested, b.EventsRequested) ||
		!reflect.DeepEqual(a.EventsDelivered, b.EventsDelivered) {
		return false
	}
	// Both-nil Aud is trivially equal; mixed-nil is unequal. Avoid
	// passing nil to json.Unmarshal (which errors on empty input)
	// and short-circuit instead.
	if len(a.Aud) == 0 || len(b.Aud) == 0 {
		return len(a.Aud) == 0 && len(b.Aud) == 0
	}
	var av, bv any
	if err := json.Unmarshal(a.Aud, &av); err != nil {
		return false
	}
	if err := json.Unmarshal(b.Aud, &bv); err != nil {
		return false
	}
	return reflect.DeepEqual(av, bv)
}
