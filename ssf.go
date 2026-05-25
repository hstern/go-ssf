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

// SpecVersion is the OpenID Shared Signals Framework version this
// build implements. The spec reached Final in 2026; the library
// tracks 1.0 until the Shared Signals Framework itself ships a
// major.
const SpecVersion = "1.0"
