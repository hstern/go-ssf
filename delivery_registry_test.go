// Copyright 2026 The go-ssf Authors
// SPDX-License-Identifier: Apache-2.0

package ssf_test

import (
	"bytes"
	"encoding/json"
	"errors"
	"sync"
	"testing"

	"github.com/hstern/go-ssf"
)

// TestBuiltinDeliveryMethodsResolveOutOfTheBox guards the contract
// that the two IANA-registered built-in delivery methods are in
// the registry from package init, so a fresh process can decode
// any spec-conformant [ssf.StreamConfig] without any consumer-side
// registration step.
func TestBuiltinDeliveryMethodsResolveOutOfTheBox(t *testing.T) {
	t.Parallel()

	for _, name := range []string{ssf.DeliveryMethodPush, ssf.DeliveryMethodPoll} {
		factory, ok := ssf.LookupDeliveryMethod(name)
		if !ok {
			t.Errorf("LookupDeliveryMethod(%q): not registered, want built-in", name)
			continue
		}
		if factory == nil {
			t.Errorf("LookupDeliveryMethod(%q): factory is nil", name)
			continue
		}
		d := factory()
		if d.Method != name {
			t.Errorf("LookupDeliveryMethod(%q): factory produced Delivery.Method = %q, want %q",
				name, d.Method, name)
		}
	}
}

// TestRegisterDeliveryMethodBuiltinCollisionReturnsErrMethodReserved
// asserts the built-in URIs cannot be overridden. The contract
// matches the [errors.Is] convention used elsewhere in the
// library — the returned error wraps [ssf.ErrMethodReserved] so
// callers can match without string-matching the error message.
func TestRegisterDeliveryMethodBuiltinCollisionReturnsErrMethodReserved(t *testing.T) {
	t.Parallel()

	for _, name := range []string{ssf.DeliveryMethodPush, ssf.DeliveryMethodPoll} {
		err := ssf.RegisterDeliveryMethod(name, func() ssf.Delivery {
			return ssf.Delivery{Method: name}
		})
		if err == nil {
			t.Errorf("RegisterDeliveryMethod(%q): got nil error, want one wrapping ErrMethodReserved",
				name)
			continue
		}
		if !errors.Is(err, ssf.ErrMethodReserved) {
			t.Errorf("RegisterDeliveryMethod(%q): err = %v, want errors.Is(err, ErrMethodReserved)",
				name, err)
		}
	}
}

// TestRegisterDeliveryMethodExtensionSucceeds covers the happy
// path: a fresh URI registers without error, becomes visible to
// [ssf.LookupDeliveryMethod] immediately, and re-registering the
// same URI silently replaces the prior factory (matching the
// behavior documented on the function godoc).
func TestRegisterDeliveryMethodExtensionSucceeds(t *testing.T) {
	const name = "urn:example:test:delivery-method:fresh"

	called := 0
	factory := func() ssf.Delivery {
		called++
		return ssf.Delivery{Method: name}
	}
	if err := ssf.RegisterDeliveryMethod(name, factory); err != nil {
		t.Fatalf("RegisterDeliveryMethod(%q): err = %v, want nil", name, err)
	}
	if _, ok := ssf.LookupDeliveryMethod(name); !ok {
		t.Errorf("LookupDeliveryMethod(%q) after Register: not visible", name)
	}
	if err := ssf.RegisterDeliveryMethod(name, factory); err != nil {
		t.Fatalf("re-RegisterDeliveryMethod(%q): err = %v, want nil (silent replace)", name, err)
	}
	if called != 0 {
		t.Errorf("factory invoked %d times during registration, want 0 "+
			"(the codec, not Register, calls it)", called)
	}
}

// TestConcurrentLookupDeliveryMethod exercises the registry under
// parallel reads. The -race build flag in CI is the load-bearing
// check; this test only needs to issue enough concurrent lookups
// that the race detector has a chance to fire on any unsynchronized
// access. Two goroutines, a few thousand reads each, is plenty.
func TestConcurrentLookupDeliveryMethod(t *testing.T) {
	t.Parallel()

	const iterations = 4096

	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		for i := range iterations {
			if _, ok := ssf.LookupDeliveryMethod(ssf.DeliveryMethodPush); !ok {
				t.Errorf("push lookup missed on iteration %d", i)
				return
			}
		}
	}()
	go func() {
		defer wg.Done()
		for i := range iterations {
			if _, ok := ssf.LookupDeliveryMethod(ssf.DeliveryMethodPoll); !ok {
				t.Errorf("poll lookup missed on iteration %d", i)
				return
			}
		}
	}()
	wg.Wait()
}

// TestDeliveryUnmarshalUnknownMethod covers the forward-
// compatibility contract: a method URI the registry does not
// recognize decodes into a [ssf.Delivery] that reports
// [ssf.Delivery.Known] false, with the original JSON bytes
// preserved verbatim on the [ssf.UnknownDelivery] carrier.
//
// Round-tripping the value through [encoding/json.Marshal] then
// [encoding/json.Unmarshal] re-emits the bytes unchanged (modulo
// [encoding/json.Marshal]'s whitespace canonicalization, which
// is irrelevant here because the input is already canonical).
func TestDeliveryUnmarshalUnknownMethod(t *testing.T) {
	t.Parallel()

	in := []byte(`{"method":"urn:example:future:delivery-method:webhook+sse",` +
		`"endpoint_url":"https://receiver.example.com/sse",` +
		`"extension_field":["a","b"]}`)

	var d ssf.Delivery
	if err := json.Unmarshal(in, &d); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}

	if d.Known() {
		t.Errorf("Delivery.Known() = true, want false for unregistered method")
	}
	u, ok := d.Unknown()
	if !ok {
		t.Fatalf("Delivery.Unknown(): ok = false, want true")
	}
	if u.Method != "urn:example:future:delivery-method:webhook+sse" {
		t.Errorf("UnknownDelivery.Method = %q, want %q",
			u.Method, "urn:example:future:delivery-method:webhook+sse")
	}
	if !bytes.Equal(u.Raw, in) {
		t.Errorf("UnknownDelivery.Raw = %s, want %s", string(u.Raw), string(in))
	}
	// The typed convenience accessors stay populated for Method
	// only — EndpointURL is left zero on the unknown path because
	// the library has no schema for the unrecognized method and
	// must not invent typed fields.
	if d.Method != "urn:example:future:delivery-method:webhook+sse" {
		t.Errorf("Delivery.Method = %q", d.Method)
	}
	if d.EndpointURL != "" {
		t.Errorf("Delivery.EndpointURL = %q, want empty (unknown path leaves typed fields zero)",
			d.EndpointURL)
	}

	out, err := json.Marshal(d)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if !bytes.Equal(out, in) {
		t.Errorf("round-trip mismatch:\n in  = %s\n out = %s", string(in), string(out))
	}

	// Decode the marshaled output one more time and check the
	// second-generation Unknown carrier carries the same bytes —
	// catches a subtle bug where MarshalJSON emits the bytes but
	// UnmarshalJSON copies them through a different path that
	// alters them.
	var d2 ssf.Delivery
	if err := json.Unmarshal(out, &d2); err != nil {
		t.Fatalf("re-unmarshal: %v", err)
	}
	u2, ok := d2.Unknown()
	if !ok {
		t.Fatalf("re-decoded Delivery.Unknown(): ok = false, want true")
	}
	if !bytes.Equal(u2.Raw, in) {
		t.Errorf("second-generation UnknownDelivery.Raw = %s, want %s",
			string(u2.Raw), string(in))
	}
}

// TestDeliveryUnmarshalRegisteredExtension is the registered-
// extension counterpart to the unknown-method test: a consumer
// registers a factory for a previously-unknown URI, and from that
// point on a payload using that URI decodes through the typed
// branch (Known() reports true, EndpointURL is populated) rather
// than the unknown carrier branch.
func TestDeliveryUnmarshalRegisteredExtension(t *testing.T) {
	const name = "urn:example:test:delivery-method:registered"

	if err := ssf.RegisterDeliveryMethod(name, func() ssf.Delivery {
		return ssf.Delivery{Method: name}
	}); err != nil {
		t.Fatalf("RegisterDeliveryMethod(%q): %v", name, err)
	}

	in := []byte(`{"method":"` + name + `","endpoint_url":"https://x.example.com/e"}`)

	var d ssf.Delivery
	if err := json.Unmarshal(in, &d); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if !d.Known() {
		t.Errorf("Delivery.Known() = false, want true for registered extension")
	}
	if d.Method != name {
		t.Errorf("Delivery.Method = %q, want %q", d.Method, name)
	}
	if d.EndpointURL != "https://x.example.com/e" {
		t.Errorf("Delivery.EndpointURL = %q", d.EndpointURL)
	}
}

// TestDeliveryUnmarshalKnownPushSurvivesRegistryPath asserts that
// a payload with the built-in push discriminator URI still decodes
// through the new registry-aware code path into the typed fields
// the caller already relies on. This is a regression guard for
// the SSF-30 round-trip behavior — the new [Delivery.UnmarshalJSON]
// must not change observed semantics for any consumer of the
// built-in methods.
func TestDeliveryUnmarshalKnownPushSurvivesRegistryPath(t *testing.T) {
	t.Parallel()

	in := []byte(`{"method":"` + ssf.DeliveryMethodPush + `",` +
		`"endpoint_url":"https://receiver.example.com/events",` +
		`"authorization_header":"Bearer rcvr-token"}`)

	var d ssf.Delivery
	if err := json.Unmarshal(in, &d); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if !d.Known() {
		t.Errorf("Delivery.Known() = false, want true for built-in push")
	}
	if _, ok := d.Unknown(); ok {
		t.Errorf("Delivery.Unknown(): ok = true, want false for built-in push")
	}
	if d.Method != ssf.DeliveryMethodPush {
		t.Errorf("Delivery.Method = %q, want %q", d.Method, ssf.DeliveryMethodPush)
	}
	if d.EndpointURL != "https://receiver.example.com/events" {
		t.Errorf("Delivery.EndpointURL = %q", d.EndpointURL)
	}
	if d.AuthorizationHeader != "Bearer rcvr-token" {
		t.Errorf("Delivery.AuthorizationHeader = %q", d.AuthorizationHeader)
	}
}

// TestDeliveryUnmarshalMalformedJSONErrors confirms the codec
// errors on input that is not a valid JSON object — the only
// failure mode [Delivery.UnmarshalJSON] reserves an error for.
// Unknown method URIs are NOT errors (forward-compat); this test
// is the inverse guard.
func TestDeliveryUnmarshalMalformedJSONErrors(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name string
		in   string
	}{
		{"not json", `not json at all`},
		{"truncated", `{"method":`},
		{"method wrong type", `{"method": 42}`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			var d ssf.Delivery
			if err := json.Unmarshal([]byte(tc.in), &d); err == nil {
				t.Errorf("Unmarshal(%q): err = nil, want non-nil", tc.in)
			}
		})
	}
}
