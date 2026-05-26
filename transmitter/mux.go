// Copyright 2026 The go-ssf Authors
// SPDX-License-Identifier: Apache-2.0

package transmitter

// This file wires the per-endpoint handlers from handlers.go into a
// single [http.Handler] that exposes the OpenID Shared Signals
// Framework 1.0 §7 endpoints at standard relative paths. Consumers
// who want a different URL layout — for example, to mount the
// endpoints under a versioned prefix — either pass [MuxPath] options
// to override individual paths or construct their own [http.ServeMux]
// from the per-endpoint constructors directly.
//
// The well-known metadata document is *not* mounted by [MuxHandler].
// The metadata document's contents (issuer, endpoint URLs, signing
// JWKS URI, supported delivery methods) live with the consumer, not
// the library, so the [WellKnownHandler] constructor takes a
// [ssf.TransmitterConfig] that this package cannot construct for the
// caller. Consumers mount [WellKnownHandler] at [WellKnownPath] on
// the same [http.ServeMux] they pass [MuxHandler] into, alongside.

import (
	"net/http"
)

// Default URL paths for the Transmitter endpoint set. These match
// the example URLs in the OpenID Shared Signals Framework 1.0 spec
// figures and the values used in the well-known metadata document
// fixtures throughout the repo's tests.
//
// The paths follow Google's API design guidance for custom verbs
// (RFC 9110 §9.3 reserves the request method; resource-relative
// verbs use the `:verb` suffix): subjects/verify uses POST + body
// rather than a separate verb namespace, so paths are noun-shaped
// where they can be. The :add and :remove suffixes mirror the
// example URLs in spec §7.1.3.
const (
	// DefaultStreamsPath is mounted at [ConfigHandler]. The handler
	// multiplexes GET / POST / PATCH / DELETE on this single path
	// per spec §7.1.1.
	DefaultStreamsPath = "/streams"

	// DefaultStatusPath is mounted at [StatusHandler] per spec
	// §7.1.2.
	DefaultStatusPath = "/streams/status"

	// DefaultAddSubjectPath is mounted at [AddSubjectHandler] per
	// spec §7.1.3.
	DefaultAddSubjectPath = "/streams/subjects:add"

	// DefaultRemoveSubjectPath is mounted at [RemoveSubjectHandler]
	// per spec §7.1.3.
	DefaultRemoveSubjectPath = "/streams/subjects:remove"

	// DefaultVerificationPath is mounted at [VerificationHandler]
	// per spec §7.1.4.
	DefaultVerificationPath = "/streams/verify"

	// DefaultPollPath is mounted at [PollHandler] per RFC 8936.
	DefaultPollPath = "/streams/poll"
)

// MuxOption configures the [http.ServeMux] returned by
// [MuxHandler]. Options compose; later options override earlier
// ones for the same setting.
type MuxOption func(*muxConfig)

// muxConfig is the resolved configuration assembled from the
// [MuxOption] values supplied to [MuxHandler].
type muxConfig struct {
	streamsPath       string
	statusPath        string
	addSubjectPath    string
	removeSubjectPath string
	verificationPath  string
	pollPath          string
}

// WithStreamsPath overrides the URL path at which [ConfigHandler] is
// mounted. The default is [DefaultStreamsPath].
func WithStreamsPath(p string) MuxOption {
	return func(c *muxConfig) { c.streamsPath = p }
}

// WithStatusPath overrides the URL path at which [StatusHandler] is
// mounted. The default is [DefaultStatusPath].
func WithStatusPath(p string) MuxOption {
	return func(c *muxConfig) { c.statusPath = p }
}

// WithAddSubjectPath overrides the URL path at which
// [AddSubjectHandler] is mounted. The default is
// [DefaultAddSubjectPath].
func WithAddSubjectPath(p string) MuxOption {
	return func(c *muxConfig) { c.addSubjectPath = p }
}

// WithRemoveSubjectPath overrides the URL path at which
// [RemoveSubjectHandler] is mounted. The default is
// [DefaultRemoveSubjectPath].
func WithRemoveSubjectPath(p string) MuxOption {
	return func(c *muxConfig) { c.removeSubjectPath = p }
}

// WithVerificationPath overrides the URL path at which
// [VerificationHandler] is mounted. The default is
// [DefaultVerificationPath].
func WithVerificationPath(p string) MuxOption {
	return func(c *muxConfig) { c.verificationPath = p }
}

// WithPollPath overrides the URL path at which [PollHandler] is
// mounted. The default is [DefaultPollPath].
func WithPollPath(p string) MuxOption {
	return func(c *muxConfig) { c.pollPath = p }
}

// MuxHandler returns an [*http.ServeMux] that mounts every
// Transmitter endpoint defined by OpenID Shared Signals Framework
// 1.0 §7 at the paths defined by the supplied [MuxOption] values, or
// at the defaults named [DefaultStreamsPath], [DefaultStatusPath],
// [DefaultAddSubjectPath], [DefaultRemoveSubjectPath],
// [DefaultVerificationPath], and [DefaultPollPath]. Every endpoint
// runs the same auth callback; per-endpoint auth differentiation
// (e.g. a separate scope for the poll endpoint) is the consumer's
// job, performed by inspecting the URL inside [AuthFunc].
//
// The returned mux does not include the well-known configuration
// document. Consumers compose the two by mounting [WellKnownHandler]
// on the same parent mux at [WellKnownPath]:
//
//	mux := http.NewServeMux()
//	mux.Handle(transmitter.WellKnownPath, transmitter.WellKnownHandler(cfg))
//	mux.Handle("/", transmitter.MuxHandler(t, auth))
//
// The MuxHandler design keeps the metadata-document construction
// (issuer, JWKS URI, supported event types) with the consumer who
// owns those values; the library does not synthesize a metadata
// document from a [Transmitter] interface.
//
// t and auth are required. A nil [Transmitter] or nil [AuthFunc]
// causes a panic at construction time — both are setup errors that
// no runtime fallback can rescue (a nil Transmitter would NPE on
// the first request; a nil AuthFunc would silently accept every
// request, which is a security incident).
func MuxHandler(t Transmitter, auth AuthFunc, opts ...MuxOption) http.Handler {
	if t == nil {
		panic("transmitter: MuxHandler requires a non-nil Transmitter")
	}
	if auth == nil {
		panic("transmitter: MuxHandler requires a non-nil AuthFunc; use AlwaysReject for fail-closed defaults or AlwaysAllow for tests")
	}

	cfg := muxConfig{
		streamsPath:       DefaultStreamsPath,
		statusPath:        DefaultStatusPath,
		addSubjectPath:    DefaultAddSubjectPath,
		removeSubjectPath: DefaultRemoveSubjectPath,
		verificationPath:  DefaultVerificationPath,
		pollPath:          DefaultPollPath,
	}
	for _, opt := range opts {
		opt(&cfg)
	}

	mux := http.NewServeMux()
	mux.Handle(cfg.streamsPath, ConfigHandler(t, auth))
	mux.Handle(cfg.statusPath, StatusHandler(t, auth))
	mux.Handle(cfg.addSubjectPath, AddSubjectHandler(t, auth))
	mux.Handle(cfg.removeSubjectPath, RemoveSubjectHandler(t, auth))
	mux.Handle(cfg.verificationPath, VerificationHandler(t, auth))
	mux.Handle(cfg.pollPath, PollHandler(t, auth))
	return mux
}
