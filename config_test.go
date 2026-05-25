// Copyright 2026 The go-ssf Authors
// SPDX-License-Identifier: Apache-2.0

package ssf

import (
	"bytes"
	"encoding/json"
	"reflect"
	"strings"
	"testing"
)

// TestTransmitterConfig_RoundTrip exercises decode → encode → decode on
// representative well-known metadata payloads from OpenID Shared Signals
// Framework 1.0 §3. Per AGENTS.md the wire bytes are the source of
// truth: a payload that survives decode must marshal back to a form
// that re-decodes into a DeepEqual value, regardless of optional-field
// presence.
func TestTransmitterConfig_RoundTrip(t *testing.T) {
	tests := []struct {
		name string
		json string
	}{
		{
			name: "minimal_required_only",
			// Only the two spec-required fields populated.
			json: `{
				"issuer": "https://transmitter.example.com",
				"delivery_methods_supported": ["urn:ietf:rfc:8935"]
			}`,
		},
		{
			name: "spec_section_3_example",
			// Representative §3 payload: issuer, JWKS pointer, both
			// delivery methods, every stream-management endpoint, the
			// spec_version pointer, and an opaque authorization_schemes
			// surface. Mirrors the shape published in the §3 example.
			json: `{
				"spec_version": "1.0",
				"issuer": "https://transmitter.example.com",
				"jwks_uri": "https://transmitter.example.com/jwks.json",
				"delivery_methods_supported": [
					"urn:ietf:rfc:8935",
					"urn:ietf:rfc:8936"
				],
				"configuration_endpoint": "https://transmitter.example.com/ssf/stream",
				"status_endpoint": "https://transmitter.example.com/ssf/stream/status",
				"add_subject_endpoint": "https://transmitter.example.com/ssf/stream/subjects:add",
				"remove_subject_endpoint": "https://transmitter.example.com/ssf/stream/subjects:remove",
				"verification_endpoint": "https://transmitter.example.com/ssf/stream/verify",
				"critical_subject_members": ["user"],
				"authorization_schemes": [{"spec_urn": "urn:ietf:rfc:6749"}]
			}`,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			// Compact the input so any json.RawMessage fields decode
			// without surrounding whitespace. Marshal of RawMessage
			// passes the bytes through encoding/json's compactor, so a
			// non-compact source would not survive a Marshal →
			// Unmarshal round-trip byte-identically. Real-world wire
			// payloads from transport layers are compact; this mirrors
			// that.
			var compact bytes.Buffer
			if err := json.Compact(&compact, []byte(tc.json)); err != nil {
				t.Fatalf("compact source payload: %v", err)
			}

			var first TransmitterConfig
			if err := json.Unmarshal(compact.Bytes(), &first); err != nil {
				t.Fatalf("unmarshal initial payload: %v", err)
			}

			encoded, err := json.Marshal(&first)
			if err != nil {
				t.Fatalf("marshal decoded value: %v", err)
			}

			var second TransmitterConfig
			if err := json.Unmarshal(encoded, &second); err != nil {
				t.Fatalf("unmarshal re-encoded payload: %v", err)
			}

			if !reflect.DeepEqual(first, second) {
				t.Fatalf("round-trip mismatch:\n first  = %#v\n second = %#v", first, second)
			}
		})
	}
}

// TestTransmitterConfig_LenientUnmarshal verifies the Postel's-law
// contract from AGENTS.md: extra fields the spec does not name are
// silently dropped on the receive path. A Transmitter that publishes
// a forward-compatible extension MUST not break a Receiver built on
// this library.
func TestTransmitterConfig_LenientUnmarshal(t *testing.T) {
	withExtras := `{
		"issuer": "https://transmitter.example.com",
		"delivery_methods_supported": ["urn:ietf:rfc:8935"],
		"unknown_top_level": "ignored",
		"another_unknown": {"nested": ["value"]},
		"future_capability_uri": "https://example.org/cap"
	}`

	var cfg TransmitterConfig
	if err := json.Unmarshal([]byte(withExtras), &cfg); err != nil {
		t.Fatalf("unmarshal with unknown fields: %v", err)
	}

	if cfg.Issuer != "https://transmitter.example.com" {
		t.Errorf("issuer not decoded: got %q", cfg.Issuer)
	}
	if len(cfg.DeliveryMethodsSupported) != 1 || cfg.DeliveryMethodsSupported[0] != "urn:ietf:rfc:8935" {
		t.Errorf("delivery_methods_supported not decoded: got %#v", cfg.DeliveryMethodsSupported)
	}

	// The re-encoded form must not carry the unknown keys — lenient
	// receive does not imply lenient retransmit; unknown fields are
	// dropped, not preserved.
	encoded, err := json.Marshal(&cfg)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	for _, unknown := range []string{"unknown_top_level", "another_unknown", "future_capability_uri"} {
		if bytes.Contains(encoded, []byte(unknown)) {
			t.Errorf("re-encoded payload leaked unknown field %q: %s", unknown, encoded)
		}
	}
}

// TestTransmitterConfig_OmitemptyOnOptional pins the wire-shape
// distinction between absent and explicitly empty optional fields. The
// spec treats absence as "not implemented"; emitting "endpoint": "" on
// a Transmitter that has no such endpoint would be wrong.
func TestTransmitterConfig_OmitemptyOnOptional(t *testing.T) {
	cfg := TransmitterConfig{
		Issuer:                   "https://transmitter.example.com",
		DeliveryMethodsSupported: []string{"urn:ietf:rfc:8935"},
	}

	encoded, err := json.Marshal(&cfg)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}

	body := string(encoded)
	for _, optional := range []string{
		"jwks_uri",
		"configuration_endpoint",
		"status_endpoint",
		"add_subject_endpoint",
		"remove_subject_endpoint",
		"verification_endpoint",
		"critical_subject_members",
		"spec_version",
		"authorization_schemes",
	} {
		if strings.Contains(body, optional) {
			t.Errorf("optional field %q present in encoded zero-value payload: %s", optional, body)
		}
	}
}

// TestTransmitterConfig_RawMessageByteStable confirms that nested JSON
// inside the open-extension fields round-trips through the decode →
// encode cycle without reordering. This is the reason those fields
// are typed as [json.RawMessage] rather than map[string]any.
func TestTransmitterConfig_RawMessageByteStable(t *testing.T) {
	// Authorization schemes whose key order would shuffle through a
	// map: spec_urn must remain first, then the deployment-specific
	// keys in their original order.
	const schemes = `[{"spec_urn":"urn:ietf:rfc:6749","token_endpoint":"https://as.example.com/token","scopes_supported":["read","write"]}]`

	cfg := TransmitterConfig{
		Issuer:                   "https://transmitter.example.com",
		DeliveryMethodsSupported: []string{"urn:ietf:rfc:8935"},
		AuthorizationSchemes:     json.RawMessage(schemes),
	}

	encoded, err := json.Marshal(&cfg)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if !bytes.Contains(encoded, []byte(schemes)) {
		t.Errorf("authorization_schemes raw bytes not preserved verbatim:\n want substring: %s\n got:            %s", schemes, encoded)
	}
}
