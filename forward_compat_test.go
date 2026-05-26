// Copyright 2026 The go-ssf Authors
// SPDX-License-Identifier: Apache-2.0

package ssf_test

import (
	"bytes"
	"crypto/rand"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	jose "github.com/go-jose/go-jose/v4"
	"github.com/hstern/go-subjectid"

	"github.com/hstern/go-ssf"
)

// The tests in this file pin the library's forward-compatibility
// guarantees as a single auditable surface. Interop with future
// Transmitters depends on the library handling discriminators it
// has never seen — new delivery methods (IANA Security Event Token
// Delivery Methods registry, RFC 8935 §6), new event-type URIs,
// new Subject Identifier formats, and new top-level capability
// fields on the well-known metadata — without erroring and, where
// the wire shape calls for it, without losing data.
//
// Each test below pins one slice of that contract. A failure here
// is a behavior change that may affect every Receiver in the wild
// running this library against a Transmitter that has adopted a
// new wire element. The companion forward-compat suite in
// go-subjectid (forward_compat_test.go) covers the Subject
// Identifier registry; this file covers the SSF-layer surface
// plus the cross-library interop point (test 8).
//
// "Byte-stable round-trip" below means: json.Compact of the input
// equals the bytes emitted by [encoding/json.Marshal] of the
// decoded value. Whitespace in the input source is stripped before
// comparison because [encoding/json.Marshal] emits canonical JSON.

// compactJSON returns the canonical form of in. Tests use this on
// the source-side input before comparing to marshal output so
// whitespace in the test literals does not cause spurious diffs.
func compactJSON(t *testing.T, in []byte) []byte {
	t.Helper()
	var buf bytes.Buffer
	if err := json.Compact(&buf, in); err != nil {
		t.Fatalf("json.Compact: %v\ninput: %s", err, in)
	}
	return buf.Bytes()
}

// TestUnknownDeliveryRoundTrip pins the basic forward-compat path
// on [ssf.StreamConfig.Delivery]: a delivery method URI outside
// the IANA built-in set decodes into a [ssf.UnknownDelivery]
// carrier and re-encodes byte-stably. This is the contract a
// Receiver depends on when a Transmitter has adopted a newer IANA
// delivery method the locally-installed library does not yet know.
func TestUnknownDeliveryRoundTrip(t *testing.T) {
	t.Parallel()

	in := compactJSON(t, []byte(`{
		"iss": "https://transmitter.example.com",
		"aud": "https://receiver.example.com",
		"events_requested": ["https://schemas.openid.net/secevent/ssf/event-type/verification"],
		"delivery": {
			"method": "urn:example:future-delivery",
			"endpoint_url": "https://receiver.example.com/future"
		}
	}`))

	var cfg ssf.StreamConfig
	if err := json.Unmarshal(in, &cfg); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}

	if cfg.Delivery.Known() {
		t.Errorf("Delivery.Known() = true, want false for novel method URI")
	}
	u, ok := cfg.Delivery.Unknown()
	if !ok {
		t.Fatalf("Delivery.Unknown(): ok = false, want true")
	}
	if got, want := u.Method, "urn:example:future-delivery"; got != want {
		t.Errorf("UnknownDelivery.Method = %q, want %q", got, want)
	}

	out, err := json.Marshal(cfg)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if !bytes.Equal(out, in) {
		t.Errorf("round-trip mismatch:\n in  = %s\n out = %s", in, out)
	}
}

// TestUnknownDeliveryWithExtraFields pins the second leg of the
// unknown-delivery contract: the [ssf.UnknownDelivery.Raw] field
// captures the entire sub-object verbatim, so additional members
// the library has no schema for (likely future fields a new
// delivery method introduces) survive a marshal/unmarshal cycle
// unchanged.
func TestUnknownDeliveryWithExtraFields(t *testing.T) {
	t.Parallel()

	// Note: the raw delivery object is what UnmarshalJSON sees;
	// any whitespace inside it is preserved by the copy into Raw
	// and reproduced on marshal. Use compact JSON so the assertion
	// below is on the canonical bytes.
	in := compactJSON(t, []byte(`{
		"iss": "https://transmitter.example.com",
		"aud": "https://receiver.example.com",
		"events_requested": ["https://schemas.openid.net/secevent/ssf/event-type/verification"],
		"delivery": {
			"method": "urn:example:future-delivery",
			"endpoint_url": "https://receiver.example.com/future",
			"quux": ["a", "b"],
			"nested": {"k": 1}
		}
	}`))

	var cfg ssf.StreamConfig
	if err := json.Unmarshal(in, &cfg); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}

	u, ok := cfg.Delivery.Unknown()
	if !ok {
		t.Fatalf("Delivery.Unknown(): ok = false, want true")
	}
	// Spot-check that the raw bytes captured all the extras.
	for _, want := range []string{"endpoint_url", "quux", "nested", `"k":1`} {
		if !bytes.Contains(u.Raw, []byte(want)) {
			t.Errorf("UnknownDelivery.Raw missing %q:\n got: %s", want, u.Raw)
		}
	}

	out, err := json.Marshal(cfg)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if !bytes.Equal(out, in) {
		t.Errorf("round-trip mismatch:\n in  = %s\n out = %s", in, out)
	}
}

// TestRegisterDeliveryMethodForward validates the registry's
// forward-extensibility hook: once a consumer registers a
// previously-unknown method URI with [ssf.RegisterDeliveryMethod],
// subsequent decodes of payloads using that URI take the typed
// branch (Known() reports true), not the [ssf.UnknownDelivery]
// fallback. This is how a consumer plugs in support for a method
// the library does not yet ship.
func TestRegisterDeliveryMethodForward(t *testing.T) {
	const method = "urn:example:test:delivery-method:forward-compat"

	if err := ssf.RegisterDeliveryMethod(method, func() ssf.Delivery {
		return ssf.Delivery{Method: method}
	}); err != nil {
		t.Fatalf("RegisterDeliveryMethod(%q): %v", method, err)
	}

	in := compactJSON(t, []byte(`{
		"iss": "https://transmitter.example.com",
		"aud": "https://receiver.example.com",
		"events_requested": ["https://schemas.openid.net/secevent/ssf/event-type/verification"],
		"delivery": {
			"method": "`+method+`",
			"endpoint_url": "https://receiver.example.com/registered"
		}
	}`))

	var cfg ssf.StreamConfig
	if err := json.Unmarshal(in, &cfg); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}

	if !cfg.Delivery.Known() {
		t.Errorf("Delivery.Known() = false after RegisterDeliveryMethod; want true")
	}
	if _, ok := cfg.Delivery.Unknown(); ok {
		t.Errorf("Delivery.Unknown(): ok = true; want false after RegisterDeliveryMethod")
	}
	if got, want := cfg.Delivery.Method, method; got != want {
		t.Errorf("Delivery.Method = %q, want %q", got, want)
	}
	if got, want := cfg.Delivery.EndpointURL, "https://receiver.example.com/registered"; got != want {
		t.Errorf("Delivery.EndpointURL = %q, want %q", got, want)
	}
}

// TestRegisterDeliveryMethodReserved pins the inverse contract:
// the two IANA built-in URIs ([ssf.DeliveryMethodPush] and
// [ssf.DeliveryMethodPoll]) cannot be overridden through
// [ssf.RegisterDeliveryMethod]. Attempts to do so return an error
// wrapping [ssf.ErrMethodReserved]. Consumers needing different
// per-built-in behavior wrap the concrete typed branch instead
// of redefining the discriminator.
func TestRegisterDeliveryMethodReserved(t *testing.T) {
	t.Parallel()

	for _, method := range []string{ssf.DeliveryMethodPush, ssf.DeliveryMethodPoll} {
		err := ssf.RegisterDeliveryMethod(method, func() ssf.Delivery {
			return ssf.Delivery{Method: method}
		})
		if err == nil {
			t.Errorf("RegisterDeliveryMethod(%q): err = nil, want one wrapping ErrMethodReserved", method)
			continue
		}
		if !errors.Is(err, ssf.ErrMethodReserved) {
			t.Errorf("RegisterDeliveryMethod(%q): err = %v, want errors.Is(err, ErrMethodReserved)", method, err)
		}
	}
}

// TestUnknownEventTypeInSET pins the contract that the library's
// SET transport layer is opaque to event-type URIs. A SET whose
// "events" claim is keyed by a URI the library has no schema for
// is signed and verified without interpretation: the payload
// bytes round-trip through sign → verify → re-sign → verify
// unchanged. Downstream consumers — go-caep, go-risc, future
// event-set libraries — own the per-event-type decoding.
//
// The test also exercises a tiny key-inspection helper to confirm
// the verification event-type URI ([ssf.EventTypeVerification])
// is distinguishable from unknown URIs by string comparison
// alone, which is all the SSF layer ever needs.
func TestUnknownEventTypeInSET(t *testing.T) {
	t.Parallel()

	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		t.Fatalf("rand.Read: %v", err)
	}

	opts := (&jose.SignerOptions{}).WithType(ssf.SETMediaType)
	joseSigner, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.HS256, Key: key}, opts)
	if err != nil {
		t.Fatalf("jose.NewSigner: %v", err)
	}
	signer, err := ssf.NewJOSESetSigner(joseSigner)
	if err != nil {
		t.Fatalf("NewJOSESetSigner: %v", err)
	}
	verifier := ssf.NewJOSESetVerifier(jose.JSONWebKeySet{
		Keys: []jose.JSONWebKey{{Key: key, Algorithm: string(jose.HS256), Use: "sig"}},
	})

	const unknownEventType = "https://example.org/secevent/novel-event-type"
	// A SET payload whose events claim carries an event-type URI
	// the library has never heard of, plus arbitrary event data.
	// The library MUST NOT inspect, validate, or reject this payload
	// on the basis of the event-type key — that is downstream
	// territory.
	payload := []byte(`{"iss":"https://transmitter.example.com","aud":"receiver.example.com","jti":"forward-compat","iat":1716422400,"events":{"` +
		unknownEventType + `":{"novel_field":"novel_value","subject":{"format":"opaque","id":"x"}}}}`)

	jws, err := signer.Sign(payload)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	got, err := verifier.Verify(jws)
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if !bytes.Equal(got, payload) {
		t.Errorf("first round-trip payload mismatch:\n want %s\n  got %s", payload, got)
	}

	// Second pass: re-sign the verified payload and verify again.
	// Bytes must still match — there is no hidden normalization in
	// the SET path.
	jws2, err := signer.Sign(got)
	if err != nil {
		t.Fatalf("Sign (second pass): %v", err)
	}
	got2, err := verifier.Verify(jws2)
	if err != nil {
		t.Fatalf("Verify (second pass): %v", err)
	}
	if !bytes.Equal(got2, payload) {
		t.Errorf("second round-trip payload mismatch:\n want %s\n  got %s", payload, got2)
	}

	// Confirm the event-type key inspection: a minimal helper
	// distinguishes the spec's verification URI from an unknown.
	// The library does not provide this helper — the SSF layer
	// never needs to dispatch on event-type — but a Receiver may
	// want to special-case verification events before handing
	// everything else to a generic ingester.
	var claims struct {
		Events map[string]json.RawMessage `json:"events"`
	}
	if err := json.Unmarshal(got, &claims); err != nil {
		t.Fatalf("unmarshal events claim: %v", err)
	}
	if _, ok := claims.Events[ssf.EventTypeVerification]; ok {
		t.Errorf("verification event-type URI present in payload built without it")
	}
	if _, ok := claims.Events[unknownEventType]; !ok {
		t.Errorf("unknown event-type URI missing from decoded events claim")
	}
}

// TestUnknownFieldsOnTransmitterConfig pins the current
// [ssf.TransmitterConfig] behavior on unknown top-level keys:
// unmarshal succeeds (lenient), but the unknown keys are dropped
// on re-marshal (strict). The type holds no open-extension
// storage, so the default [encoding/json] behavior applies.
//
// The spec says implementations MUST ignore unknown fields. Drop-
// on-retransmit is consistent with that posture. If a future spec
// revision requires preservation, this test is the change marker:
// flipping it requires adding open-extension storage to
// [ssf.TransmitterConfig], a breaking change that should be
// surfaced explicitly.
func TestUnknownFieldsOnTransmitterConfig(t *testing.T) {
	t.Parallel()

	in := []byte(`{
		"issuer": "https://transmitter.example.com",
		"delivery_methods_supported": ["urn:ietf:rfc:8935"],
		"novel_capability": "https://example.org/capability/x",
		"another_unknown": {"nested": ["value"]}
	}`)

	var cfg ssf.TransmitterConfig
	if err := json.Unmarshal(in, &cfg); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if cfg.Issuer != "https://transmitter.example.com" {
		t.Errorf("Issuer = %q", cfg.Issuer)
	}

	out, err := json.Marshal(&cfg)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	// The unknown keys are dropped on re-marshal. This is the
	// pinned behavior; flipping it is a deliberate breaking
	// change.
	for _, dropped := range []string{"novel_capability", "another_unknown"} {
		if bytes.Contains(out, []byte(dropped)) {
			t.Errorf("unknown key %q leaked into marshaled output: %s", dropped, out)
		}
	}
}

// TestUnknownFieldsOnStreamConfig is the [ssf.StreamConfig]
// counterpart to the TransmitterConfig test above. Same
// drop-on-retransmit behavior: unknown top-level keys decode
// without error and re-marshal without trace. The nested
// [ssf.Delivery] retains its own forward-compat behavior (the
// preceding tests cover that); this test pins only the outer
// envelope's drop semantics.
func TestUnknownFieldsOnStreamConfig(t *testing.T) {
	t.Parallel()

	in := []byte(`{
		"iss": "https://transmitter.example.com",
		"aud": "https://receiver.example.com",
		"events_requested": ["https://schemas.openid.net/secevent/ssf/event-type/verification"],
		"delivery": {
			"method": "urn:ietf:rfc:8935",
			"endpoint_url": "https://receiver.example.com/events"
		},
		"novel_top_level": "https://example.org/future",
		"another_unknown": 42
	}`)

	var cfg ssf.StreamConfig
	if err := json.Unmarshal(in, &cfg); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if cfg.Iss != "https://transmitter.example.com" {
		t.Errorf("Iss = %q", cfg.Iss)
	}
	if !cfg.Delivery.Known() {
		t.Errorf("Delivery.Known() = false on built-in push, want true")
	}

	out, err := json.Marshal(&cfg)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	for _, dropped := range []string{"novel_top_level", "another_unknown"} {
		if bytes.Contains(out, []byte(dropped)) {
			t.Errorf("unknown key %q leaked into marshaled output: %s", dropped, out)
		}
	}
}

// TestSubjectIdentifierUnknownFormat is the cross-library
// interop check: an [ssf.AddSubjectRequest] whose subject carries
// a "format" the go-subjectid registry does not know decodes into
// go-subjectid's [subjectid.UnknownFormat] carrier and round-trips
// byte-stably. The dispatch lives in go-subjectid; this test pins
// the path through [ssf.AddSubjectRequest.UnmarshalJSON] so a
// future refactor of either side cannot regress the contract
// without surfacing here.
func TestSubjectIdentifierUnknownFormat(t *testing.T) {
	t.Parallel()

	in := compactJSON(t, []byte(`{
		"subject": {
			"format": "org.example.future",
			"novel_key": "novel_value",
			"widget_id": 42
		}
	}`))

	var req ssf.AddSubjectRequest
	if err := json.Unmarshal(in, &req); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}

	unk, ok := req.Subject.(*subjectid.UnknownFormat)
	if !ok {
		t.Fatalf("Subject dispatched to %T, want *subjectid.UnknownFormat", req.Subject)
	}
	if got, want := unk.FormatName, "org.example.future"; got != want {
		t.Errorf("UnknownFormat.FormatName = %q, want %q", got, want)
	}

	out, err := json.Marshal(&req)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	// The envelope's only field is "subject"; the AddSubjectRequest
	// re-marshal must not introduce other top-level keys, and the
	// inner subject must round-trip through the go-subjectid
	// UnknownFormat carrier byte-stably.
	if !bytes.Equal(out, in) {
		t.Errorf("round-trip mismatch:\n in  = %s\n out = %s", in, out)
	}
	// Defensive: confirm the novel inner members survived the trip.
	for _, want := range []string{"org.example.future", "novel_key", "widget_id"} {
		if !strings.Contains(string(out), want) {
			t.Errorf("re-marshaled output missing %q: %s", want, out)
		}
	}
}
