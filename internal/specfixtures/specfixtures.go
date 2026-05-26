// Copyright 2026 The go-ssf Authors
// SPDX-License-Identifier: Apache-2.0

// Package specfixtures embeds canonical JSON payloads for every
// message type defined by OpenID Shared Signals Framework 1.0 and
// exposes them as a [embed.FS] so conformance tests — both the
// in-package round-trip suite and any out-of-package interop driver
// that wants to reuse the same wire bytes — operate on a single
// shared set of payloads.
//
// The fixture files live under the testdata/ subdirectory in the
// canonical Go convention and are embedded into the binary at build
// time so consumers neither read from disk at test time nor need to
// reproduce the on-disk layout in their own packages.
//
// Each fixture is one JSON document, canonicalized through
// [encoding/json.Compact], and corresponds 1:1 to a spec type from
// the root ssf package. The conformance_test.go file in this package
// walks every fixture, decodes it into its mapped Go type, re-encodes
// it, and asserts byte-identical output modulo whitespace — the
// strongest possible guarantee that the library's encode/decode path
// preserves the wire shape the spec pins.
//
// The package is internal/ so the fixture set is a library-private
// implementation detail; downstream consumers that want to drive
// interop scenarios from these payloads should request a stable
// exported surface in a separate issue.
package specfixtures

import "embed"

// Fixtures embeds every JSON fixture under testdata/ as an
// [embed.FS]. The keys are testdata/<name>.json paths; callers
// either iterate with [embed.FS.ReadDir] or read one file directly
// with [embed.FS.ReadFile]. The byte slices returned are the verbatim
// on-disk bytes, untouched by the build system.
//
//go:embed testdata/*.json
var Fixtures embed.FS
