// Copyright 2026 The go-ssf Authors
// SPDX-License-Identifier: Apache-2.0

package specfixtures

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"

	"github.com/hstern/go-ssf"
)

// roundTripFunc decodes the fixture bytes into a fresh value of the
// fixture's mapped Go type and returns the re-marshaled bytes. The
// fixture name is wired through the closure so the table row reads
// as a plain (name, function) pair; the closure body picks the type
// and owns the decode/encode cycle without leaking the type name
// into the table-driver signature.
type roundTripFunc func(data []byte) ([]byte, error)

// fixtureCases enumerates every embedded fixture together with the
// Go type that owns its wire shape. Each row drives one subtest:
// the harness reads testdata/<name>.json, hands the bytes to fn,
// and asserts that the re-marshaled output is byte-identical to the
// input modulo [encoding/json.Compact] whitespace canonicalization.
//
// New fixtures land here as a new row; the row's fn is the shortest
// possible decode-then-re-encode through the mapped type. Keep the
// rows in lockstep with the testdata/ directory listing — the
// TestFixturesCoverAllFiles test below fails if a file appears in
// testdata/ that no row references.
func fixtureCases() []struct {
	name string
	fn   roundTripFunc
} {
	return []struct {
		name string
		fn   roundTripFunc
	}{
		{"transmitter_config_minimal", roundTrip[ssf.TransmitterConfig]},
		{"transmitter_config_full", roundTrip[ssf.TransmitterConfig]},
		{"stream_config_push", roundTrip[ssf.StreamConfig]},
		{"stream_config_poll", roundTrip[ssf.StreamConfig]},
		{"stream_config_unknown_delivery", roundTrip[ssf.StreamConfig]},
		{"status_response", roundTrip[ssf.StatusResponse]},
		{"status_response_per_subject", roundTrip[ssf.StatusResponse]},
		{"status_update_request", roundTrip[ssf.StatusUpdateRequest]},
		{"add_subject_request_account", roundTrip[ssf.AddSubjectRequest]},
		{"add_subject_request_email", roundTrip[ssf.AddSubjectRequest]},
		{"remove_subject_request", roundTrip[ssf.RemoveSubjectRequest]},
		{"verification_request", roundTrip[ssf.VerificationRequest]},
		{"verification_event", roundTrip[ssf.VerificationEvent]},
		{"poll_request", roundTrip[ssf.PollRequest]},
		{"poll_response", roundTrip[ssf.PollResponse]},
		{"problem_details", roundTrip[ssf.ProblemDetails]},
	}
}

// roundTrip is the generic decode-then-re-encode helper shared by
// every fixture row. It unmarshals into a fresh zero value of T,
// re-marshals through [encoding/json.Marshal], and returns the
// resulting bytes. Errors propagate to the caller for fixture-level
// reporting.
//
// Using a generic helper keeps the table rows to a (name, type)
// pair without per-row boilerplate. The address-of T is what
// [encoding/json.Unmarshal] requires; the typed value (not pointer)
// is what [encoding/json.Marshal] consumes so any [json.Marshaler]
// receiver defined on T itself — for example ssf.ProblemDetails —
// gets invoked.
func roundTrip[T any](data []byte) ([]byte, error) {
	var v T
	if err := json.Unmarshal(data, &v); err != nil {
		return nil, err
	}
	return json.Marshal(&v)
}

// TestFixturesRoundTrip is the core conformance suite. For every
// fixture row it asserts that decode-then-encode through the mapped
// Go type produces output byte-identical to the input modulo
// [encoding/json.Compact] whitespace canonicalization.
//
// The whitespace allowance covers two cases the JSON wire format
// permits but the library's marshal path does not preserve: indented
// or pretty-printed fixtures (the on-disk files are compact but the
// rule applies regardless), and the trailing newline on-disk fixtures
// carry for git-tooling reasons. The comparison normalizes both sides
// through json.Compact before checking for byte equality.
func TestFixturesRoundTrip(t *testing.T) {
	t.Parallel()

	for _, tc := range fixtureCases() {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			path := "testdata/" + tc.name + ".json"
			data, err := Fixtures.ReadFile(path)
			if err != nil {
				t.Fatalf("read %s: %v", path, err)
			}

			out, err := tc.fn(data)
			if err != nil {
				t.Fatalf("round-trip %s: %v", path, err)
			}

			wantCanonical, err := compact(data)
			if err != nil {
				t.Fatalf("compact fixture %s: %v", path, err)
			}
			gotCanonical, err := compact(out)
			if err != nil {
				t.Fatalf("compact output %s: %v", path, err)
			}
			if !bytes.Equal(wantCanonical, gotCanonical) {
				t.Fatalf("round-trip %s:\n  want %s\n  got  %s",
					path, wantCanonical, gotCanonical)
			}
		})
	}
}

// TestFixturesCoverAllFiles guards against drift between the on-disk
// fixture directory and the in-code fixtureCases table. If a new
// testdata/*.json lands without a matching row — or a row references
// a missing file — the test fails loudly with the offending name.
//
// Without this check it would be easy to add a fixture file and
// forget to wire it into the type table; the round-trip suite would
// then silently skip the new payload.
func TestFixturesCoverAllFiles(t *testing.T) {
	t.Parallel()

	entries, err := Fixtures.ReadDir("testdata")
	if err != nil {
		t.Fatalf("read testdata: %v", err)
	}

	onDisk := make(map[string]struct{}, len(entries))
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		name := e.Name()
		if !strings.HasSuffix(name, ".json") {
			continue
		}
		onDisk[strings.TrimSuffix(name, ".json")] = struct{}{}
	}

	inTable := make(map[string]struct{}, len(fixtureCases()))
	for _, tc := range fixtureCases() {
		inTable[tc.name] = struct{}{}
	}

	for name := range onDisk {
		if _, ok := inTable[name]; !ok {
			t.Errorf("fixture %s.json on disk has no row in fixtureCases()", name)
		}
	}
	for name := range inTable {
		if _, ok := onDisk[name]; !ok {
			t.Errorf("fixtureCases() row %q has no testdata/%s.json", name, name)
		}
	}
}

// compact returns the json.Compact form of data — the same JSON
// document with insignificant whitespace removed. It is the
// canonicalization used by the round-trip equality check so trailing
// newlines and any pretty-printing on either side wash out before the
// byte-level comparison.
func compact(data []byte) ([]byte, error) {
	var buf bytes.Buffer
	if err := json.Compact(&buf, data); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}
