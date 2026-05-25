// Copyright 2026 The go-ssf Authors
// SPDX-License-Identifier: Apache-2.0

package transmitter_test

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/hstern/go-ssf"
	"github.com/hstern/go-ssf/transmitter"
)

// sampleConfig returns a populated TransmitterConfig that exercises
// the full §3 surface — required fields, every optional endpoint, the
// spec_version pointer, the critical_subject_members list, and an
// authorization_schemes RawMessage. The handler tests use a config
// rather than a stub so the byte-stability check actually depends on
// the JSON encoder's behavior over the real wire types.
func sampleConfig() *ssf.TransmitterConfig {
	return &ssf.TransmitterConfig{
		Issuer:                   "https://transmitter.example/",
		JWKSURI:                  "https://transmitter.example/jwks.json",
		DeliveryMethodsSupported: []string{"urn:ietf:rfc:8935", "urn:ietf:rfc:8936"},
		ConfigurationEndpoint:    "https://transmitter.example/ssf/streams",
		StatusEndpoint:           "https://transmitter.example/ssf/streams/status",
		AddSubjectEndpoint:       "https://transmitter.example/ssf/streams/subjects:add",
		RemoveSubjectEndpoint:    "https://transmitter.example/ssf/streams/subjects:remove",
		VerificationEndpoint:     "https://transmitter.example/ssf/streams/verify",
		CriticalSubjectMembers:   []string{"user", "device"},
		SpecVersion:              ssf.SpecVersion,
		AuthorizationSchemes:     json.RawMessage(`[{"spec_urn":"urn:ietf:rfc:6749"}]`),
	}
}

func TestWellKnownHandler_GetReturnsConfig(t *testing.T) {
	cfg := sampleConfig()
	h := transmitter.WellKnownHandler(cfg)

	req := httptest.NewRequest(http.MethodGet, transmitter.WellKnownPath, nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	resp := rec.Result()
	t.Cleanup(func() { _ = resp.Body.Close() })

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status: got %d, want %d", resp.StatusCode, http.StatusOK)
	}
	if got, want := resp.Header.Get("Content-Type"), "application/json; charset=utf-8"; got != want {
		t.Errorf("Content-Type: got %q, want %q", got, want)
	}
	if got, want := resp.Header.Get("Cache-Control"), "max-age=3600"; got != want {
		t.Errorf("Cache-Control: got %q, want %q", got, want)
	}

	want, err := json.Marshal(cfg)
	if err != nil {
		t.Fatalf("marshal expected config: %v", err)
	}
	if !bytes.Equal(rec.Body.Bytes(), want) {
		t.Errorf("body bytes differ:\n got: %s\nwant: %s", rec.Body.Bytes(), want)
	}
}

func TestWellKnownHandler_HeadIsAllowed(t *testing.T) {
	// HEAD is the natural sibling of GET for a resource fetch — it
	// must reach the metadata path (status, Content-Type, Cache-Control)
	// rather than 405. net/http on a real server strips the response
	// body for HEAD; httptest.NewRecorder does not, so this test pins
	// status and headers, not body length.
	h := transmitter.WellKnownHandler(sampleConfig())

	req := httptest.NewRequest(http.MethodHead, transmitter.WellKnownPath, nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	resp := rec.Result()
	t.Cleanup(func() { _ = resp.Body.Close() })

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status: got %d, want %d", resp.StatusCode, http.StatusOK)
	}
	if got, want := resp.Header.Get("Content-Type"), "application/json; charset=utf-8"; got != want {
		t.Errorf("Content-Type: got %q, want %q", got, want)
	}
	if got, want := resp.Header.Get("Cache-Control"), "max-age=3600"; got != want {
		t.Errorf("Cache-Control: got %q, want %q", got, want)
	}
}

func TestWellKnownHandler_PostReturns405(t *testing.T) {
	h := transmitter.WellKnownHandler(sampleConfig())

	req := httptest.NewRequest(http.MethodPost, transmitter.WellKnownPath, nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	resp := rec.Result()
	t.Cleanup(func() { _ = resp.Body.Close() })

	if resp.StatusCode != http.StatusMethodNotAllowed {
		t.Fatalf("status: got %d, want %d", resp.StatusCode, http.StatusMethodNotAllowed)
	}
	if got, want := resp.Header.Get("Allow"), http.MethodGet; got != want {
		t.Errorf("Allow: got %q, want %q", got, want)
	}
}

func TestWellKnownHandler_WithCacheMaxAgeZeroOmitsHeader(t *testing.T) {
	h := transmitter.WellKnownHandler(sampleConfig(), transmitter.WithCacheMaxAge(0))

	req := httptest.NewRequest(http.MethodGet, transmitter.WellKnownPath, nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	resp := rec.Result()
	t.Cleanup(func() { _ = resp.Body.Close() })

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status: got %d, want %d", resp.StatusCode, http.StatusOK)
	}
	if got := resp.Header.Get("Cache-Control"); got != "" {
		t.Errorf("Cache-Control: got %q, want unset", got)
	}
}

func TestWellKnownHandler_WithCacheMaxAgeNegativeOmitsHeader(t *testing.T) {
	h := transmitter.WellKnownHandler(sampleConfig(), transmitter.WithCacheMaxAge(-5*time.Minute))

	req := httptest.NewRequest(http.MethodGet, transmitter.WellKnownPath, nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	resp := rec.Result()
	t.Cleanup(func() { _ = resp.Body.Close() })

	if got := resp.Header.Get("Cache-Control"); got != "" {
		t.Errorf("Cache-Control: got %q, want unset", got)
	}
}

func TestWellKnownHandler_WithCacheMaxAgeCustomDuration(t *testing.T) {
	h := transmitter.WellKnownHandler(sampleConfig(), transmitter.WithCacheMaxAge(30*time.Minute))

	req := httptest.NewRequest(http.MethodGet, transmitter.WellKnownPath, nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	resp := rec.Result()
	t.Cleanup(func() { _ = resp.Body.Close() })

	if got, want := resp.Header.Get("Cache-Control"), "max-age=1800"; got != want {
		t.Errorf("Cache-Control: got %q, want %q", got, want)
	}
}

func TestWellKnownHandler_NilConfigPanics(t *testing.T) {
	defer func() {
		if r := recover(); r == nil {
			t.Fatal("expected panic on nil config, got none")
		}
	}()
	_ = transmitter.WellKnownHandler(nil)
}

func TestWellKnownPath_Value(t *testing.T) {
	// The path is fixed by spec §3 via RFC 8615; a regression here
	// would silently break every Receiver in the wild. Pin it.
	if got, want := transmitter.WellKnownPath, "/.well-known/ssf-configuration"; got != want {
		t.Errorf("WellKnownPath: got %q, want %q", got, want)
	}
}
