// Copyright 2026 The go-ssf Authors
// SPDX-License-Identifier: Apache-2.0

package client_test

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/hstern/go-ssf"
	"github.com/hstern/go-ssf/client"
	"github.com/hstern/go-ssf/transmitter"
)

// fixtureConfig returns a minimal [*ssf.TransmitterConfig] sufficient
// for round-trip discovery tests. The two spec-required fields are
// set; everything else stays at the zero value to keep the JSON small
// and the diff-on-failure readable.
func fixtureConfig() *ssf.TransmitterConfig {
	return &ssf.TransmitterConfig{
		Issuer: "https://example.com",
		DeliveryMethodsSupported: []string{
			"urn:ietf:rfc:8935",
			"urn:ietf:rfc:8936",
		},
	}
}

// newDiscoveryServer stands up an [httptest.Server] that serves the
// well-known metadata document for path [transmitter.WellKnownPath]
// and records every hit on the supplied counter. The handler honors
// per-test overrides for status, body, and Cache-Control via the
// returned [*serverOptions] pointer so individual tests can simulate
// failure responses or cache directives without spinning up bespoke
// servers.
func newDiscoveryServer(t *testing.T, hits *atomic.Int64) (*httptest.Server, *serverOptions) {
	t.Helper()
	opts := &serverOptions{
		status: http.StatusOK,
		body:   mustMarshal(t, fixtureConfig()),
	}
	mux := http.NewServeMux()
	mux.HandleFunc(transmitter.WellKnownPath, func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		if opts.cacheControl != "" {
			w.Header().Set("Cache-Control", opts.cacheControl)
		}
		if opts.contentType != "" {
			w.Header().Set("Content-Type", opts.contentType)
		}
		if opts.delay > 0 {
			select {
			case <-time.After(opts.delay):
			case <-r.Context().Done():
				return
			}
		}
		w.WriteHeader(opts.status)
		_, _ = w.Write(opts.body)
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return srv, opts
}

// serverOptions is the per-test knob bag mutated through the pointer
// returned by [newDiscoveryServer]. Field zero values produce the
// happy-path response.
type serverOptions struct {
	status       int
	body         []byte
	cacheControl string
	contentType  string
	delay        time.Duration
}

func mustMarshal(t *testing.T, v any) []byte {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatalf("marshal fixture: %v", err)
	}
	return b
}

func TestFetchTransmitterConfig_HappyPath(t *testing.T) {
	t.Parallel()
	var hits atomic.Int64
	srv, _ := newDiscoveryServer(t, &hits)

	got, err := client.FetchTransmitterConfig(t.Context(), srv.URL)
	if err != nil {
		t.Fatalf("FetchTransmitterConfig: %v", err)
	}
	if got.Issuer != "https://example.com" {
		t.Errorf("Issuer = %q, want %q", got.Issuer, "https://example.com")
	}
	if len(got.DeliveryMethodsSupported) != 2 {
		t.Errorf("DeliveryMethodsSupported = %d entries, want 2", len(got.DeliveryMethodsSupported))
	}
	if h := hits.Load(); h != 1 {
		t.Errorf("server hit count = %d, want 1", h)
	}
}

func TestFetchTransmitterConfig_TrailingSlashOnBaseURL(t *testing.T) {
	t.Parallel()
	// A baseURL the operator constructs by string-concatenating with a
	// directory separator should still resolve to the canonical
	// well-known path with exactly one slash between origin and path.
	var hits atomic.Int64
	srv, _ := newDiscoveryServer(t, &hits)

	if _, err := client.FetchTransmitterConfig(t.Context(), srv.URL+"/"); err != nil {
		t.Fatalf("FetchTransmitterConfig with trailing slash: %v", err)
	}
	if h := hits.Load(); h != 1 {
		t.Errorf("server hit count = %d, want 1", h)
	}
}

func TestFetchTransmitterConfig_404MapsToErrStreamNotFound(t *testing.T) {
	t.Parallel()
	// Per [ParseHTTPError]'s sentinel table 404 maps to
	// [ssf.ErrStreamNotFound] unconditionally. For a well-known
	// fetch the spec does not pin a meaning for 404, but the test
	// documents the library's current behavior so a future change to
	// remap the well-known 404 surfaces as a deliberate test update.
	var hits atomic.Int64
	srv, opts := newDiscoveryServer(t, &hits)
	opts.status = http.StatusNotFound
	opts.body = []byte("not found")

	_, err := client.FetchTransmitterConfig(t.Context(), srv.URL)
	if err == nil {
		t.Fatal("FetchTransmitterConfig returned nil error for 404")
	}
	if !errors.Is(err, ssf.ErrStreamNotFound) {
		t.Errorf("errors.Is(err, ssf.ErrStreamNotFound) = false, want true; err=%v", err)
	}
	var httpErr *ssf.HTTPError
	if !errors.As(err, &httpErr) {
		t.Fatal("errors.As(err, &*ssf.HTTPError) = false")
	}
	if httpErr.StatusCode != http.StatusNotFound {
		t.Errorf("HTTPError.StatusCode = %d, want %d", httpErr.StatusCode, http.StatusNotFound)
	}
}

func TestFetchTransmitterConfig_500ReturnsHTTPError(t *testing.T) {
	t.Parallel()
	var hits atomic.Int64
	srv, opts := newDiscoveryServer(t, &hits)
	opts.status = http.StatusInternalServerError
	opts.body = []byte("boom")

	_, err := client.FetchTransmitterConfig(t.Context(), srv.URL)
	if err == nil {
		t.Fatal("FetchTransmitterConfig returned nil error for 500")
	}
	var httpErr *ssf.HTTPError
	if !errors.As(err, &httpErr) {
		t.Fatalf("errors.As(err, &*ssf.HTTPError) = false; err=%v", err)
	}
	if httpErr.StatusCode != http.StatusInternalServerError {
		t.Errorf("HTTPError.StatusCode = %d, want %d", httpErr.StatusCode, http.StatusInternalServerError)
	}
}

func TestFetchTransmitterConfig_DecodeErrorOnMalformedBody(t *testing.T) {
	t.Parallel()
	var hits atomic.Int64
	srv, opts := newDiscoveryServer(t, &hits)
	opts.body = []byte(`{not valid json`)

	if _, err := client.FetchTransmitterConfig(t.Context(), srv.URL); err == nil {
		t.Fatal("FetchTransmitterConfig returned nil error for malformed body")
	}
}

// fakeDoer is a minimal [client.HTTPDoer] used to confirm
// [client.WithHTTPDoer] routes the request through the supplied
// transport. The fake records the request URL and returns a canned
// 200 response with the fixture body.
type fakeDoer struct {
	calls atomic.Int64
	url   string
	body  []byte
}

func (d *fakeDoer) Do(req *http.Request) (*http.Response, error) {
	d.calls.Add(1)
	d.url = req.URL.String()
	rec := httptest.NewRecorder()
	rec.Header().Set("Content-Type", "application/json")
	rec.WriteHeader(http.StatusOK)
	_, _ = rec.Write(d.body)
	return rec.Result(), nil
}

func TestFetchTransmitterConfig_WithHTTPDoer(t *testing.T) {
	t.Parallel()
	doer := &fakeDoer{body: mustMarshal(t, fixtureConfig())}

	got, err := client.FetchTransmitterConfig(
		t.Context(),
		"https://transmitter.example",
		client.WithHTTPDoer(doer),
	)
	if err != nil {
		t.Fatalf("FetchTransmitterConfig: %v", err)
	}
	if got.Issuer != "https://example.com" {
		t.Errorf("Issuer = %q, want %q", got.Issuer, "https://example.com")
	}
	if c := doer.calls.Load(); c != 1 {
		t.Errorf("doer.calls = %d, want 1", c)
	}
	wantURL := "https://transmitter.example" + transmitter.WellKnownPath
	if doer.url != wantURL {
		t.Errorf("requested URL = %q, want %q", doer.url, wantURL)
	}
}

func TestFetchTransmitterConfig_WithHTTPDoer_NilIgnored(t *testing.T) {
	t.Parallel()
	// Passing a nil doer must not panic and must not replace the
	// default with nil; the default [http.DefaultClient] still drives
	// the actual fetch.
	var hits atomic.Int64
	srv, _ := newDiscoveryServer(t, &hits)

	if _, err := client.FetchTransmitterConfig(t.Context(), srv.URL, client.WithHTTPDoer(nil)); err != nil {
		t.Fatalf("FetchTransmitterConfig(WithHTTPDoer(nil)): %v", err)
	}
}

func TestFetchTransmitterConfig_ContextCancellation(t *testing.T) {
	t.Parallel()
	var hits atomic.Int64
	srv, opts := newDiscoveryServer(t, &hits)
	opts.delay = 200 * time.Millisecond

	ctx, cancel := context.WithCancel(t.Context())
	cancel()

	_, err := client.FetchTransmitterConfig(ctx, srv.URL)
	if err == nil {
		t.Fatal("FetchTransmitterConfig returned nil error on cancelled context")
	}
	if !errors.Is(err, context.Canceled) {
		t.Errorf("errors.Is(err, context.Canceled) = false; err=%v", err)
	}
}

func TestConfigCache_HitWithinTTL(t *testing.T) {
	t.Parallel()
	var hits atomic.Int64
	srv, _ := newDiscoveryServer(t, &hits)

	cache := client.NewConfigCache(10 * time.Second)
	for i := range 3 {
		if _, err := cache.FetchTransmitterConfig(t.Context(), srv.URL); err != nil {
			t.Fatalf("call %d: %v", i, err)
		}
	}
	if h := hits.Load(); h != 1 {
		t.Errorf("server hit count = %d, want 1 (three calls within TTL)", h)
	}
}

func TestConfigCache_MissAfterTTL(t *testing.T) {
	t.Parallel()
	// Drive the cache's clock manually so the test does not sleep
	// real wall-clock time. [ConfigCache] exposes a clock-swap hook
	// only through the unexported now field; the test reaches it via
	// the package-internal helper [setClock] declared in
	// discovery_export_test.go.
	var hits atomic.Int64
	srv, _ := newDiscoveryServer(t, &hits)

	cache := client.NewConfigCache(time.Second)
	current := time.Unix(0, 0)
	client.SetCacheClock(cache, func() time.Time { return current })

	if _, err := cache.FetchTransmitterConfig(t.Context(), srv.URL); err != nil {
		t.Fatalf("first fetch: %v", err)
	}
	current = current.Add(2 * time.Second) // past TTL
	if _, err := cache.FetchTransmitterConfig(t.Context(), srv.URL); err != nil {
		t.Fatalf("post-expiry fetch: %v", err)
	}
	if h := hits.Load(); h != 2 {
		t.Errorf("server hit count = %d, want 2 (one fresh + one post-expiry)", h)
	}
}

func TestConfigCache_MaxAgeZeroNotCached(t *testing.T) {
	t.Parallel()
	var hits atomic.Int64
	srv, opts := newDiscoveryServer(t, &hits)
	opts.cacheControl = "max-age=0"

	cache := client.NewConfigCache(10 * time.Second)
	for i := range 3 {
		if _, err := cache.FetchTransmitterConfig(t.Context(), srv.URL); err != nil {
			t.Fatalf("call %d: %v", i, err)
		}
	}
	if h := hits.Load(); h != 3 {
		t.Errorf("server hit count = %d, want 3 (max-age=0 disables caching)", h)
	}
}

func TestConfigCache_NoStoreNotCached(t *testing.T) {
	t.Parallel()
	// Both [Cache-Control] no-store and no-cache disable retention; the
	// cache treats them equivalently because it has no concept of a
	// conditional revalidation request (RFC 9111 §5.2). The table
	// pins both directives to keep the parser branches honest.
	tests := []struct {
		name      string
		directive string
	}{
		{"no-store", "no-store"},
		{"no-cache", "no-cache"},
		{"mixed with max-age", "no-store, max-age=60"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			var hits atomic.Int64
			srv, opts := newDiscoveryServer(t, &hits)
			opts.cacheControl = tt.directive

			cache := client.NewConfigCache(10 * time.Second)
			for i := range 2 {
				if _, err := cache.FetchTransmitterConfig(t.Context(), srv.URL); err != nil {
					t.Fatalf("call %d: %v", i, err)
				}
			}
			if h := hits.Load(); h != 2 {
				t.Errorf("server hit count = %d, want 2 (%s disables caching)", h, tt.directive)
			}
		})
	}
}

func TestConfigCache_ResponseMaxAgeShortensTTL(t *testing.T) {
	t.Parallel()
	// Configured TTL is 1 hour but the response advertises max-age=2;
	// after 5 simulated seconds the entry is stale and a refetch is
	// required.
	var hits atomic.Int64
	srv, opts := newDiscoveryServer(t, &hits)
	opts.cacheControl = "max-age=2"

	cache := client.NewConfigCache(time.Hour)
	current := time.Unix(0, 0)
	client.SetCacheClock(cache, func() time.Time { return current })

	if _, err := cache.FetchTransmitterConfig(t.Context(), srv.URL); err != nil {
		t.Fatalf("first fetch: %v", err)
	}
	current = current.Add(5 * time.Second)
	if _, err := cache.FetchTransmitterConfig(t.Context(), srv.URL); err != nil {
		t.Fatalf("post-max-age fetch: %v", err)
	}
	if h := hits.Load(); h != 2 {
		t.Errorf("server hit count = %d, want 2", h)
	}
}

func TestConfigCache_PerBaseURLKeying(t *testing.T) {
	t.Parallel()
	// Two distinct Transmitters must not share a cache entry; the
	// second baseURL drives its own fetch even when the first is
	// fresh.
	var hits1, hits2 atomic.Int64
	srv1, _ := newDiscoveryServer(t, &hits1)
	srv2, _ := newDiscoveryServer(t, &hits2)

	cache := client.NewConfigCache(time.Hour)
	if _, err := cache.FetchTransmitterConfig(t.Context(), srv1.URL); err != nil {
		t.Fatalf("srv1: %v", err)
	}
	if _, err := cache.FetchTransmitterConfig(t.Context(), srv2.URL); err != nil {
		t.Fatalf("srv2: %v", err)
	}
	if h := hits1.Load(); h != 1 {
		t.Errorf("srv1 hits = %d, want 1", h)
	}
	if h := hits2.Load(); h != 1 {
		t.Errorf("srv2 hits = %d, want 1", h)
	}
}

func TestConfigCache_NonPositiveTTLDisablesCaching(t *testing.T) {
	t.Parallel()
	// A zero or negative TTL is a deployment signal to skip the cache
	// layer entirely; every call performs an HTTP round-trip.
	var hits atomic.Int64
	srv, _ := newDiscoveryServer(t, &hits)

	cache := client.NewConfigCache(0)
	for i := range 3 {
		if _, err := cache.FetchTransmitterConfig(t.Context(), srv.URL); err != nil {
			t.Fatalf("call %d: %v", i, err)
		}
	}
	if h := hits.Load(); h != 3 {
		t.Errorf("server hit count = %d, want 3", h)
	}
}

func TestConfigCache_ErrorNotCached(t *testing.T) {
	t.Parallel()
	// A failed fetch leaves the cache empty so the next call retries.
	var hits atomic.Int64
	srv, opts := newDiscoveryServer(t, &hits)
	opts.status = http.StatusInternalServerError

	cache := client.NewConfigCache(time.Hour)
	if _, err := cache.FetchTransmitterConfig(t.Context(), srv.URL); err == nil {
		t.Fatal("expected error on first 500")
	}
	if _, err := cache.FetchTransmitterConfig(t.Context(), srv.URL); err == nil {
		t.Fatal("expected error on second 500")
	}
	if h := hits.Load(); h != 2 {
		t.Errorf("server hit count = %d, want 2 (errors are not cached)", h)
	}
}

// TestConfigCache_HonorsCustomDoerOnMiss exercises a cache miss
// routed through [client.WithHTTPDoer]. The doer's call counter
// confirms the cache used the supplied transport rather than
// [http.DefaultClient].
func TestConfigCache_HonorsCustomDoerOnMiss(t *testing.T) {
	t.Parallel()
	doer := &fakeDoer{body: mustMarshal(t, fixtureConfig())}
	cache := client.NewConfigCache(time.Hour)

	if _, err := cache.FetchTransmitterConfig(
		t.Context(),
		"https://transmitter.example",
		client.WithHTTPDoer(doer),
	); err != nil {
		t.Fatalf("first fetch: %v", err)
	}
	// Second call should hit the cache without invoking the doer.
	if _, err := cache.FetchTransmitterConfig(
		t.Context(),
		"https://transmitter.example",
		client.WithHTTPDoer(doer),
	); err != nil {
		t.Fatalf("second fetch: %v", err)
	}
	if c := doer.calls.Load(); c != 1 {
		t.Errorf("doer.calls = %d, want 1 (second call should hit cache)", c)
	}
}

// TestParseCacheControl_IgnoresUnparseable confirms the cache treats
// garbage Cache-Control values as "no directive present" rather than
// rejecting the response. The behavior is observed indirectly: a
// response with an unparseable max-age still caches under the
// configured TTL.
func TestConfigCache_IgnoresUnparseableMaxAge(t *testing.T) {
	t.Parallel()
	var hits atomic.Int64
	srv, opts := newDiscoveryServer(t, &hits)
	opts.cacheControl = "max-age=notanumber"

	cache := client.NewConfigCache(time.Hour)
	for i := range 2 {
		if _, err := cache.FetchTransmitterConfig(t.Context(), srv.URL); err != nil {
			t.Fatalf("call %d: %v", i, err)
		}
	}
	if h := hits.Load(); h != 1 {
		t.Errorf("server hit count = %d, want 1 (unparseable max-age ignored, default TTL applies)", h)
	}
}

// Static check that the package-level discovery function and the
// cache method share a signature shape — both take ctx, baseURL,
// variadic opts and return (*ssf.TransmitterConfig, error). The
// declaration is compile-only; if either signature drifts the build
// fails before any test runs.
var (
	_ func(context.Context, string, ...client.DiscoveryOption) (*ssf.TransmitterConfig, error) = client.FetchTransmitterConfig
	_ func(context.Context, string, ...client.DiscoveryOption) (*ssf.TransmitterConfig, error) = (*client.ConfigCache)(nil).FetchTransmitterConfig
)
