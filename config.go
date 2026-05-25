// Copyright 2026 The go-ssf Authors
// SPDX-License-Identifier: Apache-2.0

package ssf

import "encoding/json"

// TransmitterConfig is the well-known metadata document a Transmitter
// publishes at /.well-known/ssf-configuration per OpenID Shared Signals
// Framework 1.0 §3. A Receiver fetches the document to discover the
// Transmitter's identity, signing keys, supported delivery methods, and
// the absolute URLs of the stream-management endpoints it implements.
//
// Two fields are required by the spec: [TransmitterConfig.Issuer] and
// [TransmitterConfig.DeliveryMethodsSupported]. Every other field is
// optional — endpoint URLs are absent when the Transmitter does not
// implement the corresponding endpoint, and the capability / authorization
// metadata carries whatever the deployment chooses to advertise.
//
// JSON tags match the wire names from §3 verbatim. The open-extension
// fields use [json.RawMessage] rather than map[string]any so the wire
// bytes round-trip unchanged — interop fixtures pin exact JSON, and
// Go's map iteration order would reshuffle nested objects on re-marshal.
//
// Validation lives at the marshal boundary and in an opt-in Validate
// helper that lands in a later phase; this type's [json.Marshal] and
// [json.Unmarshal] paths are deliberately lenient. Per AGENTS.md the
// library decodes whatever the wire produced and rejects only on send.
type TransmitterConfig struct {
	// Issuer is the Transmitter's identifier URI. Required by spec §3.
	Issuer string `json:"issuer"`

	// JWKSURI is the JWKS endpoint serving the Transmitter's SET
	// signing keys. Spec-recommended; omitted when the Transmitter
	// distributes keys through a non-JWKS channel.
	JWKSURI string `json:"jwks_uri,omitempty"`

	// DeliveryMethodsSupported is the list of delivery-method URIs
	// the Transmitter implements — urn:ietf:rfc:8935 for push,
	// urn:ietf:rfc:8936 for poll, plus any registered extensions.
	// Required by spec §3.
	DeliveryMethodsSupported []string `json:"delivery_methods_supported"`

	// ConfigurationEndpoint is the absolute URL of the stream
	// configuration endpoint (spec §7.1.1). Absent when the
	// Transmitter does not expose stream configuration over HTTP.
	ConfigurationEndpoint string `json:"configuration_endpoint,omitempty"`

	// StatusEndpoint is the absolute URL of the stream status
	// endpoint (spec §7.1.2). Absent when not implemented.
	StatusEndpoint string `json:"status_endpoint,omitempty"`

	// AddSubjectEndpoint is the absolute URL of the add-subject
	// endpoint (spec §7.1.3.1). Absent when not implemented.
	AddSubjectEndpoint string `json:"add_subject_endpoint,omitempty"`

	// RemoveSubjectEndpoint is the absolute URL of the remove-subject
	// endpoint (spec §7.1.3.2). Absent when not implemented.
	RemoveSubjectEndpoint string `json:"remove_subject_endpoint,omitempty"`

	// VerificationEndpoint is the absolute URL of the verification
	// endpoint (spec §7.1.4). Absent when not implemented.
	VerificationEndpoint string `json:"verification_endpoint,omitempty"`

	// CriticalSubjectMembers lists subject-member names the
	// Transmitter requires Receivers to support per spec §3. An
	// empty list and absence carry different wire shapes; the
	// omitempty tag preserves the absence form on round-trip.
	CriticalSubjectMembers []string `json:"critical_subject_members,omitempty"`

	// SpecVersion is the Shared Signals Framework spec version this
	// Transmitter implements per spec §3. For a Transmitter built on
	// this library the natural value is [SpecVersion].
	SpecVersion string `json:"spec_version,omitempty"`

	// AuthorizationSchemes describes the authorization mechanisms
	// the Transmitter accepts on its stream-management endpoints
	// per spec §3. Left opaque as [json.RawMessage] so the wire
	// shape — an array of objects whose contents the spec leaves
	// to registries — round-trips byte-for-byte regardless of which
	// scheme-specific keys a deployment publishes.
	AuthorizationSchemes json.RawMessage `json:"authorization_schemes,omitempty"`
}
