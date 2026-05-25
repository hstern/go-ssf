// Copyright 2026 The go-ssf Authors
// SPDX-License-Identifier: Apache-2.0

package ssf_test

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/hstern/go-ssf"
)

// TestSentinelErrorsWrappable asserts every sentinel error in the
// inventory survives [fmt.Errorf] wrapping with the %w verb and is
// recovered by [errors.Is]. This is the contract callers rely on
// when adding context to a returned error.
func TestSentinelErrorsWrappable(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name     string
		sentinel error
	}{
		{"ErrStreamNotFound", ssf.ErrStreamNotFound},
		{"ErrUnauthorized", ssf.ErrUnauthorized},
		{"ErrInvalidConfig", ssf.ErrInvalidConfig},
		{"ErrMethodReserved", ssf.ErrMethodReserved},
		{"ErrUnsupportedDelivery", ssf.ErrUnsupportedDelivery},
		{"ErrUnsupportedEvent", ssf.ErrUnsupportedEvent},
		{"ErrVerificationTimeout", ssf.ErrVerificationTimeout},
		{"ErrNotImplemented", ssf.ErrNotImplemented},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			wrapped := fmt.Errorf("context: %w", tc.sentinel)
			if !errors.Is(wrapped, tc.sentinel) {
				t.Fatalf("errors.Is did not recover %s through wrap", tc.name)
			}

			// Sentinel messages are lowercase and unpunctuated per
			// AGENTS.md; check the convention does not regress.
			msg := tc.sentinel.Error()
			if msg == "" {
				t.Fatalf("%s has empty message", tc.name)
			}
			if msg != strings.ToLower(msg) {
				t.Errorf("%s message %q contains uppercase letters",
					tc.name, msg)
			}
			if strings.HasSuffix(msg, ".") {
				t.Errorf("%s message %q has trailing period", tc.name, msg)
			}
		})
	}
}

// TestSentinelErrorsDistinct asserts no two sentinels share an
// identity. Two sentinels with the same message but distinct
// [errors.New] values are still distinct under [errors.Is]; this
// test pins the property so a future refactor cannot collapse them.
func TestSentinelErrorsDistinct(t *testing.T) {
	t.Parallel()

	sentinels := []error{
		ssf.ErrStreamNotFound,
		ssf.ErrUnauthorized,
		ssf.ErrInvalidConfig,
		ssf.ErrMethodReserved,
		ssf.ErrUnsupportedDelivery,
		ssf.ErrUnsupportedEvent,
		ssf.ErrVerificationTimeout,
		ssf.ErrNotImplemented,
	}

	for i, a := range sentinels {
		for j, b := range sentinels {
			if i == j {
				continue
			}
			if errors.Is(a, b) {
				t.Errorf("sentinel %d (%q) reported as %d (%q)",
					i, a, j, b)
			}
		}
	}
}

// TestValidationErrorFormat asserts the *ValidationError Error()
// format includes all three fields. The format is part of the
// library's stable surface — log scrapers and tests rely on it.
func TestValidationErrorFormat(t *testing.T) {
	t.Parallel()

	err := &ssf.ValidationError{
		Rule:   "events_requested non-empty",
		Field:  "events_requested",
		Reason: "stream config must request at least one event type",
	}

	got := err.Error()

	for _, want := range []string{
		"events_requested non-empty",
		"events_requested",
		"stream config must request at least one event type",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("ValidationError.Error() = %q, missing %q",
				got, want)
		}
	}
}

// TestValidationErrorAs asserts a wrapped *ValidationError is
// recovered by [errors.As]. Callers commonly wrap the structural
// error with higher-level context; the pointer must still surface.
func TestValidationErrorAs(t *testing.T) {
	t.Parallel()

	original := &ssf.ValidationError{
		Rule:   "method required",
		Field:  "delivery.method",
		Reason: "delivery method URI is required",
	}
	wrapped := fmt.Errorf("decode stream config: %w", original)

	var recovered *ssf.ValidationError
	if !errors.As(wrapped, &recovered) {
		t.Fatalf("errors.As did not recover *ValidationError")
	}
	if recovered != original {
		t.Errorf("recovered pointer = %p, want %p", recovered, original)
	}
}

// TestHTTPErrorFormatRFC7807 covers the path where the response is
// RFC 7807 problem-details JSON: Error() reports the StatusCode and
// the parsed Title.
func TestHTTPErrorFormatRFC7807(t *testing.T) {
	t.Parallel()

	err := &ssf.HTTPError{
		StatusCode: 400,
		Body:       []byte(`{"type":"about:blank","title":"Invalid stream configuration","status":400}`),
		RFC7807: &ssf.ProblemDetails{
			Type:   "about:blank",
			Title:  "Invalid stream configuration",
			Status: 400,
		},
	}

	got := err.Error()
	if !strings.Contains(got, "400") {
		t.Errorf("HTTPError.Error() = %q, missing status 400", got)
	}
	if !strings.Contains(got, "Invalid stream configuration") {
		t.Errorf("HTTPError.Error() = %q, missing RFC7807 Title", got)
	}
}

// TestHTTPErrorFormatNonJSONBody covers the fallback path where the
// response body is not RFC 7807 problem-details — for example an
// HTML error page from a misconfigured reverse proxy. Error()
// includes the StatusCode and the raw body.
func TestHTTPErrorFormatNonJSONBody(t *testing.T) {
	t.Parallel()

	err := &ssf.HTTPError{
		StatusCode: 502,
		Body:       []byte("<html><body>Bad gateway</body></html>"),
		RFC7807:    nil,
	}

	got := err.Error()
	if !strings.Contains(got, "502") {
		t.Errorf("HTTPError.Error() = %q, missing status 502", got)
	}
	if !strings.Contains(got, "Bad gateway") {
		t.Errorf("HTTPError.Error() = %q, missing body fragment",
			got)
	}
}

// TestHTTPErrorFormatEmptyBody confirms Error() degrades gracefully
// when neither RFC 7807 details nor a body are present.
func TestHTTPErrorFormatEmptyBody(t *testing.T) {
	t.Parallel()

	err := &ssf.HTTPError{StatusCode: 401}

	got := err.Error()
	if !strings.Contains(got, "401") {
		t.Errorf("HTTPError.Error() = %q, missing status 401", got)
	}
}

// TestProblemDetailsRoundTripMinimal asserts a minimal RFC 7807
// document — type + title + status — round-trips byte-stably. The
// project's wire-fidelity posture treats this as a regression gate.
func TestProblemDetailsRoundTripMinimal(t *testing.T) {
	t.Parallel()

	in := []byte(`{"type":"https://example.com/probs/stream-not-found","title":"Stream not found","status":404}`)

	var pd ssf.ProblemDetails
	if err := json.Unmarshal(in, &pd); err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}

	out, err := json.Marshal(&pd)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}

	if !bytes.Equal(in, out) {
		t.Errorf("round trip not byte-stable\n  in:  %s\n  out: %s",
			in, out)
	}
}

// TestProblemDetailsRoundTripWithExtensions asserts that a document
// carrying RFC 7807 extension members round-trips byte-stably. Per
// RFC 7807 §3.2 extension members live at the top level of the
// problem-details object alongside the five registered fields, not
// under a nested "extensions" key. The Extensions field on
// [ssf.ProblemDetails] is [json.RawMessage] so the exact JSON bytes
// the responder emitted survive a decode/encode cycle — required for
// interop scenarios that pin payloads byte-for-byte.
func TestProblemDetailsRoundTripWithExtensions(t *testing.T) {
	t.Parallel()

	in := []byte(`{"type":"about:blank","title":"Invalid stream configuration","status":400,"detail":"events_requested must be non-empty","field":"events_requested","rule":"non-empty"}`)

	var pd ssf.ProblemDetails
	if err := json.Unmarshal(in, &pd); err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}

	if pd.Status != 400 {
		t.Errorf("Status = %d, want 400", pd.Status)
	}
	if len(pd.Extensions) == 0 {
		t.Errorf("Extensions was not captured")
	}

	out, err := json.Marshal(&pd)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}

	if !bytes.Equal(in, out) {
		t.Errorf("round trip not byte-stable\n  in:  %s\n  out: %s",
			in, out)
	}
}

// TestProblemDetailsExtensionsFlatNotNested confirms the load-bearing
// RFC 7807 §3.2 contract: extension members are emitted flat at the
// top level of the problem-details object, never under a nested
// "extensions" key. This is the asymmetry between Go struct shape
// (Extensions is a single Go field) and wire shape (multiple
// top-level JSON members) that the custom MarshalJSON enforces.
func TestProblemDetailsExtensionsFlatNotNested(t *testing.T) {
	t.Parallel()

	in := []byte(`{"type":"https://example.com/probs/quota","title":"Quota exceeded","status":429,"balance":42,"retry_after":60}`)

	var pd ssf.ProblemDetails
	if err := json.Unmarshal(in, &pd); err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}

	out, err := json.Marshal(&pd)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}

	if bytes.Contains(out, []byte(`"extensions":`)) {
		t.Errorf("Marshal emitted nested \"extensions\" key: %s", out)
	}
	if !bytes.Contains(out, []byte(`"balance":42`)) {
		t.Errorf("Marshal dropped extension member balance: %s", out)
	}
	if !bytes.Contains(out, []byte(`"retry_after":60`)) {
		t.Errorf("Marshal dropped extension member retry_after: %s", out)
	}
	if !bytes.Equal(in, out) {
		t.Errorf("round trip not byte-stable\n  in:  %s\n  out: %s", in, out)
	}
}

// TestProblemDetailsRegisteredMembersInSpecOrder confirms that when
// MarshalJSON emits the five RFC 7807 registered members it emits
// them in spec-figure order — type, title, status, detail, instance —
// regardless of the order they appeared in the source document. This
// is the ordering interop fixtures compare against.
func TestProblemDetailsRegisteredMembersInSpecOrder(t *testing.T) {
	t.Parallel()

	// Source document with the registered members in reverse order
	// to make sure the encoder is not just echoing input order.
	in := []byte(`{"instance":"/streams/abc","detail":"d","status":400,"title":"t","type":"about:blank"}`)

	var pd ssf.ProblemDetails
	if err := json.Unmarshal(in, &pd); err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}

	out, err := json.Marshal(&pd)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}

	const want = `{"type":"about:blank","title":"t","status":400,"detail":"d","instance":"/streams/abc"}`
	if string(out) != want {
		t.Errorf("Marshal:\n  got  %s\n  want %s", out, want)
	}
}

// TestProblemDetailsExtensionOrderPreserved confirms that extension
// members keep their source ordering across a decode/encode cycle.
// The custom UnmarshalJSON captures them into Extensions in wire
// order, and MarshalJSON re-emits them in that order — a
// map[string]any here would shuffle on every round trip.
func TestProblemDetailsExtensionOrderPreserved(t *testing.T) {
	t.Parallel()

	// Three extension members in a deliberate non-alphabetical order
	// (z, a, m) — a map iteration would reorder them.
	in := []byte(`{"type":"about:blank","status":400,"z_key":"first","a_key":"second","m_key":"third"}`)

	var pd ssf.ProblemDetails
	if err := json.Unmarshal(in, &pd); err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}
	out, err := json.Marshal(&pd)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	if !bytes.Equal(in, out) {
		t.Errorf("extension ordering not preserved\n  in:  %s\n  out: %s", in, out)
	}
}

// TestProblemDetailsNoExtensions confirms a document with no extension
// members emits no Extensions bytes and round-trips through a
// re-decode without populating the Extensions field.
func TestProblemDetailsNoExtensions(t *testing.T) {
	t.Parallel()

	in := []byte(`{"type":"about:blank","title":"x","status":500}`)
	var pd ssf.ProblemDetails
	if err := json.Unmarshal(in, &pd); err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}
	if pd.Extensions != nil {
		t.Errorf("Extensions = %s, want nil", pd.Extensions)
	}
	out, err := json.Marshal(&pd)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	if !bytes.Equal(in, out) {
		t.Errorf("round trip:\n  in:  %s\n  out: %s", in, out)
	}
}

// TestProblemDetailsOmitEmpty asserts that an empty ProblemDetails
// marshals to "{}" — every field is omitempty so a zero value
// produces no spurious keys.
func TestProblemDetailsOmitEmpty(t *testing.T) {
	t.Parallel()

	out, err := json.Marshal(&ssf.ProblemDetails{})
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	if string(out) != "{}" {
		t.Errorf("zero ProblemDetails marshalled to %s, want {}", out)
	}
}
