// Copyright 2026 The go-ssf Authors
// SPDX-License-Identifier: Apache-2.0

// Package transmitter implements the Transmitter half of the OpenID
// Shared Signals Framework 1.0 — the HTTP-handler constructors a
// service uses to publish its well-known metadata, accept stream
// configuration calls, and serve subject and verification operations
// to Receivers.
//
// The package is organized as constructors over interfaces: the caller
// provides the persistence and authorization behavior, and the package
// returns [net/http.Handler] values wired to the spec's request and
// response shapes. The handlers depend only on the standard library
// and the parent [ssf] package's wire types.
package transmitter

import (
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/hstern/go-ssf"
)

// WellKnownPath is the absolute path at which a Transmitter publishes
// its metadata document per OpenID Shared Signals Framework 1.0 §3.
// The spec fixes the path under the [/.well-known/] tree from RFC 8615;
// Receivers fetch it by appending the path to the Transmitter's origin.
const WellKnownPath = "/.well-known/ssf-configuration"

// defaultWellKnownMaxAge is the Cache-Control max-age applied to the
// metadata response when the caller does not override it. One hour is
// the conventional default for endpoint-discovery documents — short
// enough that a Transmitter rolling out a new endpoint sees Receiver
// uptake within a workday, long enough that the metadata fetch is not
// on every request's hot path.
const defaultWellKnownMaxAge = time.Hour

// WellKnownOption configures [WellKnownHandler]. Options are applied
// in the order they are passed; later options override earlier ones
// for the same setting.
type WellKnownOption func(*wellKnownConfig)

// wellKnownConfig is the resolved configuration assembled from the
// supplied [WellKnownOption] values.
type wellKnownConfig struct {
	// maxAge is the Cache-Control max-age advertised on the response.
	// A zero or negative value suppresses the Cache-Control header
	// entirely, leaving cache lifetime to the consumer's HTTP stack.
	maxAge time.Duration
}

// WithCacheMaxAge sets the Cache-Control max-age advertised on the
// metadata response. The default is one hour. Pass a zero or negative
// duration to omit the Cache-Control header entirely, which is the
// right choice when an upstream proxy or CDN already injects caching
// directives the Transmitter must not double-stamp.
func WithCacheMaxAge(d time.Duration) WellKnownOption {
	return func(c *wellKnownConfig) {
		c.maxAge = d
	}
}

// WellKnownHandler returns an [net/http.Handler] that serves the
// Transmitter metadata document at [WellKnownPath] per OpenID Shared
// Signals Framework 1.0 §3. The handler marshals cfg to JSON on every
// request — callers that want to amortize the marshal across requests
// should place a caching reverse proxy in front of the handler rather
// than caching inside the library, which keeps the handler trivially
// observable and lets operators tune cache policy independently of
// the binary.
//
// The handler responds 200 with Content-Type application/json and
// Cache-Control max-age=3600 by default. The response shape is the
// JSON encoding of cfg; per AGENTS.md the [encoding/json] default is
// strict on marshal and lenient on unmarshal, so the bytes a Receiver
// sees are byte-identical to [encoding/json.Marshal] of cfg.
//
// Only GET (and HEAD, which [net/http] handles by discarding the body
// of a GET response) reach the JSON path. Other methods receive 405
// with an Allow header advertising GET, per RFC 9110 §15.5.6.
//
// cfg is captured by pointer; mutating it after construction changes
// the served document on the next request, and concurrent mutation
// while a request is in flight is a data race. Callers wanting a
// frozen snapshot should copy before passing.
//
// Panics if cfg is nil — a nil metadata document is a setup error,
// not a runtime condition the handler can serve sensibly.
func WellKnownHandler(cfg *ssf.TransmitterConfig, opts ...WellKnownOption) http.Handler {
	if cfg == nil {
		panic("transmitter: WellKnownHandler requires a non-nil *ssf.TransmitterConfig")
	}
	resolved := wellKnownConfig{maxAge: defaultWellKnownMaxAge}
	for _, opt := range opts {
		opt(&resolved)
	}

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet && r.Method != http.MethodHead {
			w.Header().Set("Allow", http.MethodGet)
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}

		body, err := json.Marshal(cfg)
		if err != nil {
			http.Error(w, "marshal transmitter config", http.StatusInternalServerError)
			return
		}

		h := w.Header()
		h.Set("Content-Type", "application/json; charset=utf-8")
		if resolved.maxAge > 0 {
			h.Set("Cache-Control", fmt.Sprintf("max-age=%d", int64(resolved.maxAge.Seconds())))
		}
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(body)
	})
}
