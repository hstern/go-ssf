// Copyright 2026 The go-ssf Authors
// SPDX-License-Identifier: Apache-2.0

// Package ssf implements the OpenID Shared Signals Framework 1.0
// wire protocol — the transport between an event Transmitter and an
// event Receiver for Security Event Tokens (SETs), over both push
// (RFC 8935) and poll (RFC 8936) delivery modes.
//
// This package and its subpackages (transmitter, receiver, client,
// memstore) together form a library-vendor-neutral Go implementation
// of the spec at
// https://openid.net/specs/openid-sharedsignals-framework-1_0.html.
//
// Pre-v0.1.0: the surface is being built out in phased work. See
// CHANGELOG.md for what has landed, AGENTS.md for the contributor
// conventions, and the per-symbol godoc for the spec section each
// symbol implements.
package ssf

import "errors"

// SpecVersion is the OpenID Shared Signals Framework version this
// build implements. The spec reached Final in 2026; the library
// tracks 1.0 until the Shared Signals Framework itself ships a
// major.
const SpecVersion = "1.0"

// Sentinel errors for the Transmitter and client surfaces. The
// phase 2 work that lands the full type surface fixes the final
// inventory and the error-wrapping conventions; the three below
// are the recurring cases that every Transmitter implementation
// will need to return.
//
// Per AGENTS.md, error sentences are lowercase, unpunctuated, and
// callers wrap with %w when adding context. Use [errors.Is] to
// match a sentinel through wrapping.
var (
	// ErrStreamNotFound is returned by Transmitter methods when the
	// referenced stream ID does not exist. Per spec §7.1 the HTTP
	// layer maps this to 404 Not Found with an RFC 7807 problem-
	// details body.
	ErrStreamNotFound = errors.New("stream not found")

	// ErrUnauthorized is returned when the caller is not permitted
	// to perform the requested operation on the referenced stream —
	// either no credentials were presented or the scope they carry
	// does not cover the stream. Per spec §7 the HTTP layer maps
	// this to 401 Unauthorized.
	ErrUnauthorized = errors.New("unauthorized")

	// ErrInvalidConfig is returned by [Transmitter.CreateConfig] and
	// [Transmitter.UpdateConfig] when the proposed stream configuration
	// is rejected — unknown delivery method, missing required field,
	// or a value that violates the spec's validation rules. Per spec
	// §7.1.1 the HTTP layer maps this to 400 Bad Request with an
	// RFC 7807 problem-details body.
	ErrInvalidConfig = errors.New("invalid stream configuration")
)
