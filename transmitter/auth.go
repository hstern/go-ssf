// Copyright 2026 The go-ssf Authors
// SPDX-License-Identifier: Apache-2.0

// Package transmitter provides HTTP handlers and supporting types for
// the Shared Signals Framework Transmitter role. The package wraps a
// [Transmitter] business-logic interface (declared in a sibling file)
// in stdlib [net/http] handlers that translate between SSF wire JSON
// and Go types.
//
// This file declares the authorization abstraction shared by every
// handler in the package: an [AuthFunc] callback the consumer plugs
// into the handler set, the [StreamScope] value such a callback
// returns when a request is permitted, and a [Default401Handler]
// utility for rendering the canonical 401 response.
//
// The package intentionally does not implement OAuth, mTLS, or any
// other concrete auth scheme. The Shared Signals Framework is
// authentication-agnostic — consumers wire their existing identity
// stack into [AuthFunc] and the handler set calls it before touching
// any [Transmitter] method.
package transmitter

import (
	"encoding/json"
	"net/http"

	"github.com/hstern/go-ssf"
)

// StreamScope is the result of a successful authorization decision.
// An [AuthFunc] returns a populated StreamScope to signal that the
// request may proceed, optionally pinning the decision to a specific
// stream or subject.
//
// Both fields are optional. A zero StreamScope means "authorized for
// whatever the request itself names" — appropriate for endpoints
// (like CreateConfig) that do not target a pre-existing stream, or
// for credentials that grant access to every stream visible to the
// caller. Populating [StreamScope.StreamID] narrows the authorization
// to one stream; populating [StreamScope.Subject] narrows it to
// requests scoped to that single Subject Identifier.
//
// The struct is deliberately small at this stage. Additional fields
// (issuer hints, scope sets, expiry) may join later as concrete
// authorization schemes accumulate; consumers and the handler set
// MUST treat unknown future fields as additive. Construct values with
// field-name keys (StreamScope{StreamID: "abc"}, not StreamScope{"abc"})
// so future additions do not break compilation.
type StreamScope struct {
	// StreamID, when non-empty, restricts the decision to the named
	// stream. Handlers that operate on a specific stream resource
	// reject the request when [StreamScope.StreamID] is set and does
	// not match the stream the request targets. The empty string
	// means the scope is not stream-restricted.
	StreamID string

	// Subject, when non-empty, restricts the decision to requests
	// whose payload references this Subject Identifier. The bytes are
	// the RFC 9493 Subject Identifier JSON object verbatim — held as
	// [json.RawMessage] rather than a decoded subject value so the
	// scope round-trips byte-for-byte with whatever credential carried
	// it. The empty value means the scope is not subject-restricted.
	Subject json.RawMessage
}

// AuthFunc is the per-request authorization callback the
// [Transmitter] handler set invokes before delegating to business
// logic. Implementations inspect the request — typically the
// Authorization header, a client certificate, or session state — and
// return either a populated [StreamScope] to allow the request or a
// non-nil error to reject it.
//
// On rejection the handler set renders the error via the configured
// 401 renderer (see [Default401Handler]); on success the handler set
// consults [StreamScope] to enforce any stream- or subject-level
// restriction before calling the [Transmitter] method. Returning
// [ssf.ErrUnauthorized] is the canonical "no credentials / wrong
// credentials" rejection; other error types are passed through to the
// 401 renderer unchanged.
type AuthFunc func(r *http.Request) (StreamScope, error)

// AlwaysReject is the default [AuthFunc] value used when a handler
// set is constructed without an explicit authorization callback. It
// returns [ssf.ErrUnauthorized] for every request, which the default
// 401 renderer turns into a well-formed RFC 7807 problem-details
// response.
//
// Defaulting to AlwaysReject is the fail-closed posture: a
// misconfigured deployment that forgets to wire up an [AuthFunc]
// still refuses every request rather than silently accepting them.
// Consumers replace this default by passing their own [AuthFunc] to
// the handler set constructor.
func AlwaysReject(_ *http.Request) (StreamScope, error) {
	return StreamScope{}, ssf.ErrUnauthorized
}

// AlwaysAllow authorizes every incoming request unconditionally,
// returning an empty [StreamScope] and a nil error.
//
// NEVER use this in production; the entire purpose of this function
// is to bypass authorization. AlwaysAllow exists so package tests,
// example servers, and local interop harnesses can exercise the
// handler set without standing up a real identity stack. Wiring it
// into a deployment that accepts traffic from anywhere on the
// internet is a security incident.
//
// The function signature matches [AuthFunc] so it plugs directly
// into the handler set constructor in test code.
func AlwaysAllow(_ *http.Request) (StreamScope, error) {
	return StreamScope{}, nil
}

// unauthorizedProblemType is the RFC 7807 "type" URI emitted by
// [Default401Handler]. RFC 7807 §3.1 says the default "about:blank"
// is appropriate when no problem-type-specific document is published;
// SSF deployments that do publish their own problem-type pages can
// override the rendering wholesale.
//
// "about:blank" is chosen over a synthetic schemas.openid.net URL on
// purpose. The library does not control the openid.net domain and
// MUST NOT mint URIs there that imply a published problem-type page
// when none exists. Consumers who want a richer type URI render
// their own response instead of using [Default401Handler].
const unauthorizedProblemType = "about:blank"

// Default401Handler returns an [http.Handler] that writes a
// 401 Unauthorized response carrying an RFC 7807 problem-details
// body derived from err. The body has Content-Type
// "application/problem+json" and the shape:
//
//	{
//	  "type":   "about:blank",
//	  "title":  "Unauthorized",
//	  "status": 401,
//	  "detail": "<err.Error()>"
//	}
//
// When err is nil the Detail field is omitted; the response is still
// a 401 with an otherwise-complete problem-details body.
//
// Default401Handler is the canonical rendering the [Transmitter]
// handler set falls back to when its [AuthFunc] rejects a request.
// Consumers who want a different 401 body — a custom Type URI, an
// extra Instance member, structured extension fields — supply their
// own [http.Handler] to the handler set instead.
func Default401Handler(err error) http.Handler {
	detail := ""
	if err != nil {
		detail = err.Error()
	}

	problem := &ssf.ProblemDetails{
		Type:   unauthorizedProblemType,
		Title:  "Unauthorized",
		Status: http.StatusUnauthorized,
		Detail: detail,
	}

	// Marshal once at construction so every invocation serves the same
	// bytes without re-encoding. The returned handler is safe for
	// concurrent use because it only reads the pre-encoded body.
	body, marshalErr := json.Marshal(problem)

	return http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/problem+json")
		w.WriteHeader(http.StatusUnauthorized)
		if marshalErr != nil {
			// Should be unreachable: ProblemDetails of well-formed
			// fields always marshals. Fall back to an empty body so
			// the status code is still useful.
			return
		}
		_, _ = w.Write(body)
	})
}
