// Copyright 2026 The go-ssf Authors
// SPDX-License-Identifier: Apache-2.0

package client

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/hstern/go-ssf"
	"github.com/hstern/go-ssf/transmitter"
)

// HTTPDoer is the minimum surface the client needs from an HTTP
// transport: a single [http.Client.Do]-shaped method. Both
// [*http.Client] and [http.DefaultClient] satisfy it, so the common
// case is zero ceremony; tests inject a fake, and deployments that
// front their outbound traffic through an instrumented round-tripper
// pass a configured [*http.Client] without the library having to know
// what middleware it carries.
//
// The interface is intentionally narrower than [http.RoundTripper]:
// the discovery and per-endpoint helpers operate on whole requests
// (Do mutates [http.Request.Body], applies redirects, honors cookies),
// not on bare round-trips. A caller that needs round-tripper-level
// control wraps the round-tripper inside an [*http.Client] and passes
// the client.
type HTTPDoer interface {
	Do(req *http.Request) (*http.Response, error)
}

// DiscoveryOption configures a [FetchTransmitterConfig] call or a
// [ConfigCache.FetchTransmitterConfig] call. Options are applied in
// the order they are passed; later options override earlier ones for
// the same setting.
type DiscoveryOption func(*discoveryConfig)

// discoveryConfig is the resolved configuration assembled from the
// supplied [DiscoveryOption] values.
type discoveryConfig struct {
	// doer is the HTTP transport used to fetch the metadata document.
	// A nil value means use [http.DefaultClient].
	doer HTTPDoer
}

// WithHTTPDoer overrides the [HTTPDoer] used to fetch the metadata
// document. The default is [http.DefaultClient], which is the right
// choice for most consumers; pass a configured [*http.Client] when
// the deployment requires a custom transport (instrumented
// round-tripper, proxy, mTLS, request-scoped timeouts beyond what
// [context.Context] supplies).
//
// A nil doer is ignored and the default is retained, so passing
// WithHTTPDoer(nil) is a no-op rather than a runtime panic.
func WithHTTPDoer(doer HTTPDoer) DiscoveryOption {
	return func(c *discoveryConfig) {
		if doer != nil {
			c.doer = doer
		}
	}
}

// FetchTransmitterConfig fetches the well-known metadata document
// from a Transmitter and decodes it into a [*ssf.TransmitterConfig].
//
// The URL is assembled by appending [transmitter.WellKnownPath] to
// baseURL; baseURL is the Transmitter's origin (scheme + host, no
// trailing slash). A trailing slash on baseURL is tolerated and
// collapsed so the resulting URL has exactly one slash between origin
// and well-known path.
//
// On a 2xx response the body is decoded and the resulting config
// returned; on any non-2xx the response is handed to [ParseHTTPError]
// and the returned error preserves the spec-level cause via the
// sentinel-joining behavior documented on that function. On a
// transport error (DNS, connection refused, TLS handshake) the
// [HTTPDoer]'s error is wrapped with a fixed prefix and returned.
//
// The function is uncached: every call performs an HTTP round-trip.
// Consumers that want in-process caching keyed by baseURL should hold
// a [*ConfigCache] and call [ConfigCache.FetchTransmitterConfig]
// instead — cache lifetime is a deployment concern and the library
// declines to make that decision globally.
//
// The supplied [context.Context] flows through to the HTTP request,
// so cancellation and deadlines apply to the discovery fetch the same
// way they apply to any other [HTTPDoer]-backed call.
func FetchTransmitterConfig(ctx context.Context, baseURL string, opts ...DiscoveryOption) (*ssf.TransmitterConfig, error) {
	cfg := discoveryConfig{doer: http.DefaultClient}
	for _, opt := range opts {
		opt(&cfg)
	}
	result, err := fetchOnce(ctx, cfg.doer, baseURL)
	if err != nil {
		return nil, err
	}
	return result.config, nil
}

// fetchResult bundles the parsed config with the cache directives the
// response carried, so a [*ConfigCache] can apply [Cache-Control]
// without re-parsing headers from the live response.
type fetchResult struct {
	config *ssf.TransmitterConfig
	// maxAge is the value of [Cache-Control] max-age=N on the
	// response in seconds, or -1 when no max-age was present. A value
	// of 0 is preserved (and treated by the cache as
	// "do not cache" per RFC 9111).
	maxAge int64
	// noStore is true when the response carries [Cache-Control]
	// no-store or no-cache, in which case the cache must not retain
	// the entry per RFC 9111 §5.2.
	noStore bool
}

// fetchOnce performs a single discovery round-trip. It is shared
// between the package-level [FetchTransmitterConfig] (which discards
// cache directives) and [ConfigCache.FetchTransmitterConfig] (which
// uses them).
func fetchOnce(ctx context.Context, doer HTTPDoer, baseURL string) (*fetchResult, error) {
	url := strings.TrimRight(baseURL, "/") + transmitter.WellKnownPath
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, http.NoBody)
	if err != nil {
		return nil, fmt.Errorf("ssf: build discovery request: %w", err)
	}
	resp, err := doer.Do(req)
	if err != nil {
		return nil, fmt.Errorf("ssf: fetch transmitter config: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if err := ParseHTTPError(resp); err != nil {
		return nil, err
	}

	var cfg ssf.TransmitterConfig
	if err := json.NewDecoder(resp.Body).Decode(&cfg); err != nil {
		return nil, fmt.Errorf("ssf: decode transmitter config: %w", err)
	}

	maxAge, noStore := parseCacheControl(resp.Header.Get("Cache-Control"))
	return &fetchResult{config: &cfg, maxAge: maxAge, noStore: noStore}, nil
}

// parseCacheControl extracts the directives [ConfigCache] honors from
// a [Cache-Control] header. The parser is intentionally narrow: it
// recognises max-age=N (with N a non-negative integer), no-store, and
// no-cache, and ignores everything else. Per RFC 9111 §5.2 either
// no-store or no-cache directs an intermediate cache to revalidate;
// the cache layer here treats both as "do not store" because it has
// no concept of a conditional revalidation request.
//
// A missing header returns maxAge=-1 (caller chooses a default) and
// noStore=false. An unparseable max-age value is ignored — the same
// lenient posture used elsewhere in the library on inbound wire data.
func parseCacheControl(header string) (maxAge int64, noStore bool) {
	maxAge = -1
	if header == "" {
		return maxAge, false
	}
	for _, raw := range strings.Split(header, ",") {
		directive := strings.TrimSpace(raw)
		if directive == "" {
			continue
		}
		name, value, hasValue := strings.Cut(directive, "=")
		name = strings.ToLower(strings.TrimSpace(name))
		switch name {
		case "no-store", "no-cache":
			noStore = true
		case "max-age":
			if !hasValue {
				continue
			}
			v, err := strconv.ParseInt(strings.TrimSpace(value), 10, 64)
			if err != nil || v < 0 {
				continue
			}
			maxAge = v
		}
	}
	return maxAge, noStore
}

// ConfigCache is an in-process cache of [*ssf.TransmitterConfig]
// documents keyed by Transmitter base URL. A Receiver pointing at one
// or more Transmitters holds a single [*ConfigCache] and calls
// [ConfigCache.FetchTransmitterConfig] from every site that needs the
// metadata; the cache short-circuits the HTTP round-trip while the
// stored entry is still fresh.
//
// Freshness is the minimum of:
//
//   - the [Cache-Control] max-age on the response, when present;
//   - the TTL passed to [NewConfigCache].
//
// A response carrying [Cache-Control] no-store or no-cache is not
// retained, matching RFC 9111 §5.2 for intermediate caches that
// cannot perform conditional revalidation. A response carrying
// max-age=0 is fetched but not retained.
//
// ConfigCache is safe for concurrent use. The zero value is not
// usable; construct one with [NewConfigCache].
type ConfigCache struct {
	ttl     time.Duration
	now     func() time.Time
	entries sync.Map // map[string]*cacheEntry
}

// cacheEntry is the per-baseURL value stored in [ConfigCache.entries].
// expiresAt is the wall-clock time after which the entry is stale and
// must be re-fetched.
type cacheEntry struct {
	config    *ssf.TransmitterConfig
	expiresAt time.Time
}

// NewConfigCache returns a [*ConfigCache] with the supplied default
// TTL. The TTL is an upper bound: an individual entry's freshness is
// the minimum of the TTL and the response's [Cache-Control] max-age.
// A non-positive TTL disables caching entirely — every fetch performs
// an HTTP round-trip and the cache table stays empty, which matches
// what a caller asking for "zero or less freshness" plausibly means.
func NewConfigCache(ttl time.Duration) *ConfigCache {
	return &ConfigCache{ttl: ttl, now: time.Now}
}

// FetchTransmitterConfig returns a cached [*ssf.TransmitterConfig]
// for baseURL when one is still fresh, otherwise performs an HTTP
// round-trip via the package-level [FetchTransmitterConfig] logic and
// stores the result for future calls. The returned config is the same
// pointer stored in the cache; consumers that intend to mutate the
// returned value should copy it first.
//
// Options are the same set [FetchTransmitterConfig] accepts. The
// cache is keyed by baseURL only; passing a different [HTTPDoer]
// across calls for the same baseURL still returns the cached entry
// while it is fresh. Callers that need per-doer caching should hold
// one [*ConfigCache] per doer.
func (c *ConfigCache) FetchTransmitterConfig(ctx context.Context, baseURL string, opts ...DiscoveryOption) (*ssf.TransmitterConfig, error) {
	if c.ttl <= 0 {
		return FetchTransmitterConfig(ctx, baseURL, opts...)
	}
	if cached, ok := c.lookup(baseURL); ok {
		return cached, nil
	}

	cfg := discoveryConfig{doer: http.DefaultClient}
	for _, opt := range opts {
		opt(&cfg)
	}
	result, err := fetchOnce(ctx, cfg.doer, baseURL)
	if err != nil {
		return nil, err
	}

	c.store(baseURL, result)
	return result.config, nil
}

// lookup returns the cached config for baseURL when one is present
// and not yet expired, otherwise (nil, false). Expired entries are
// left in place; the next [ConfigCache.store] for the same baseURL
// overwrites them, and the table stays bounded by the set of
// Transmitters the consumer actually talks to.
func (c *ConfigCache) lookup(baseURL string) (*ssf.TransmitterConfig, bool) {
	raw, ok := c.entries.Load(baseURL)
	if !ok {
		return nil, false
	}
	entry, ok := raw.(*cacheEntry)
	if !ok {
		return nil, false
	}
	if !c.now().Before(entry.expiresAt) {
		return nil, false
	}
	return entry.config, true
}

// store records a successfully fetched config in the cache, honoring
// the response's [Cache-Control] directives. A no-store / no-cache
// response is not retained; a max-age of zero is treated the same way
// because storing an entry that is immediately stale wastes a map
// slot. Otherwise the entry's freshness is min(maxAge, configured
// TTL), where maxAge=-1 (no header) collapses to the configured TTL.
func (c *ConfigCache) store(baseURL string, result *fetchResult) {
	if result.noStore {
		return
	}
	freshness := c.ttl
	if result.maxAge == 0 {
		// Response explicitly opts out of caching.
		return
	}
	if result.maxAge > 0 {
		responseTTL := time.Duration(result.maxAge) * time.Second
		if responseTTL < freshness {
			freshness = responseTTL
		}
	}
	c.entries.Store(baseURL, &cacheEntry{
		config:    result.config,
		expiresAt: c.now().Add(freshness),
	})
}
