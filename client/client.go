// Copyright 2026 The go-ssf Authors
// SPDX-License-Identifier: Apache-2.0

package client

// This file declares the Receiver-side HTTP client for the
// Transmitter endpoints defined by OpenID Shared Signals Framework
// 1.0 §7 and RFC 8936 §2.4. The client is one Go method per spec
// endpoint, mirroring the [transmitter.Transmitter] interface from
// the sibling [github.com/hstern/go-ssf/transmitter] package so a
// Receiver can switch between an in-process Transmitter and a remote
// HTTP Transmitter without reshaping its call sites.
//
// Transport is pluggable through the [HTTPDoer] interface (the
// minimal one-method shape [golang.org/x/oauth2] settled on years
// ago). Consumers compose their own retry, auth, tracing, mTLS, and
// metrics layers around [net/http.Client] and inject the wrapped
// value with [WithHTTPDoer]; the client itself adds no policy on top
// of the spec's wire shapes.
//
// Error handling delegates to [ParseHTTPError] (in errors.go), so the
// status-code → sentinel mapping is the same on every method —
// [errors.Is](err, ssf.ErrUnauthorized) recovers 401 outcomes
// regardless of which endpoint produced them, and [errors.As] into
// [*ssf.HTTPError] always yields the raw body and any RFC 7807
// problem-details document.

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"

	"github.com/hstern/go-ssf"
	"github.com/hstern/go-ssf/transmitter"
)

// HTTPDoer is the minimal interface this package needs from an HTTP
// transport: one method that takes an [*http.Request] and returns an
// [*http.Response]. The shape matches [net/http.Client.Do] verbatim,
// and the [oauth2] package uses the same shape, so [*http.Client]
// already satisfies HTTPDoer out of the box.
//
// Consumers plug their own implementation to layer retries,
// authentication header injection, distributed-tracing propagation,
// mutual-TLS dialers, or any policy that wraps an outbound HTTP
// request. The client invokes Do exactly once per method call; back-
// off, retry, and circuit-breaking belong inside HTTPDoer, not in the
// client itself.
type HTTPDoer interface {
	Do(*http.Request) (*http.Response, error)
}

// EndpointPaths overrides the per-endpoint URL paths the client
// appends to its base URL. The zero value of each field means
// "keep the default" — the client falls back to the default path
// constants documented on [Client] when the corresponding field is
// empty.
//
// EndpointPaths is shaped to match the [transmitter.MuxHandler] path
// option group on the Transmitter side, so a deployment that mounts
// the Transmitter on a custom path layout can pass the symmetrical
// values to its clients without translating between two different
// option vocabularies.
//
// Paths are URL paths, not full URLs — they are appended to the
// configured base URL with [net/url.URL.ResolveReference]. Each path
// SHOULD begin with a leading slash for clarity; the client tolerates
// the leading slash being absent but the behaviour with relative
// paths follows [net/url]'s reference-resolution rules.
type EndpointPaths struct {
	// Config is the path for the stream-configuration endpoint
	// (spec §7.1.1). Default [DefaultConfigPath].
	Config string

	// Status is the path for the stream-status endpoint
	// (spec §7.1.2). Default [DefaultStatusPath].
	Status string

	// AddSubject is the path for the add-subject endpoint
	// (spec §7.1.3). Default [DefaultAddSubjectPath].
	AddSubject string

	// RemoveSubject is the path for the remove-subject endpoint
	// (spec §7.1.3). Default [DefaultRemoveSubjectPath].
	RemoveSubject string

	// Verify is the path for the verification endpoint
	// (spec §7.1.4). Default [DefaultVerifyPath].
	Verify string

	// Poll is the path for the poll-delivery endpoint
	// (RFC 8936 §2.4). Default [DefaultPollPath].
	Poll string
}

// Default URL paths the [Client] appends to its base URL for each
// Transmitter endpoint. The values mirror the default paths the
// [github.com/hstern/go-ssf/transmitter] package mounts via
// [transmitter.MuxHandler]; a Transmitter deployed with the
// out-of-the-box mux is reachable from a Client constructed with no
// [WithEndpoints] override.
const (
	DefaultConfigPath        = "/streams"
	DefaultStatusPath        = "/streams/status"
	DefaultAddSubjectPath    = "/streams/subjects:add"
	DefaultRemoveSubjectPath = "/streams/subjects:remove"
	DefaultVerifyPath        = "/streams/verify"
	DefaultPollPath          = "/streams/poll"
)

// acceptHeader is the value the [Client] sets on Accept for every
// request. RFC 7807 problem-details is included alongside
// application/json so a Transmitter signalling success with one and
// failure with the other does not have to guess which the caller is
// willing to receive.
const acceptHeader = "application/json, application/problem+json"

// jsonContentType is the Content-Type the [Client] sets on every
// request body. Charset is pinned because Go's [encoding/json]
// always emits UTF-8 and pinning it spares strict Transmitters from
// having to guess.
const jsonContentType = "application/json; charset=utf-8"

// Client is the Receiver-side contract for the HTTP endpoints defined
// by OpenID Shared Signals Framework 1.0 §7 and RFC 8936 §2.4. The
// 11 methods are 1:1 with the spec endpoints and have signatures
// identical to [transmitter.Transmitter] — so a Receiver that holds
// its Transmitter behind that interface can switch between an
// in-process implementation and a remote HTTP Transmitter by
// swapping the value, without reshaping its call sites.
//
// The default implementation is HTTP-backed and is constructed with
// [NewClient]. Transport is pluggable through [HTTPDoer];
// authentication is pluggable either through [WithAuthorizationHeader]
// (a static header value applied to every request) or by wrapping the
// doer to mint a fresh credential per request. The HTTP-backed Client
// is safe for concurrent use by multiple goroutines as long as the
// supplied [HTTPDoer] is.
//
// Errors returned by Client methods follow [ParseHTTPError]'s
// contract: on a non-2xx response the returned error is an
// [*ssf.HTTPError] joined with the matching root-package sentinel
// (when one applies), so callers can branch with [errors.Is] for
// the spec-level cause and with [errors.As] for the raw status,
// body, and RFC 7807 problem-details.
//
// Test doubles and alternative transports satisfy Client by
// implementing the same 11 methods; the interface deliberately
// exposes no HTTP-shaped surface (no [net/http.ResponseWriter], no
// path parameters) so a fake driving an in-process Transmitter is as
// usable as the HTTP-backed default.
type Client interface {
	// GetConfig fetches the stream configuration identified by
	// streamID per spec §7.1.1.
	GetConfig(ctx context.Context, streamID string) (*ssf.StreamConfig, error)

	// ListConfig fetches a page of stream configurations the caller
	// is authorized to see per spec §7.1.1. pageToken is the opaque
	// continuation token returned by the previous call (empty for
	// the first page); nextToken is empty when the listing is
	// exhausted.
	ListConfig(ctx context.Context, pageToken string) (configs []*ssf.StreamConfig, nextToken string, err error)

	// CreateConfig POSTs cfg to the stream-configuration endpoint
	// per spec §7.1.1 and returns the server-assigned canonical
	// representation.
	CreateConfig(ctx context.Context, cfg *ssf.StreamConfig) (*ssf.StreamConfig, error)

	// UpdateConfig PATCHes the stream identified by cfg.StreamID
	// with cfg and returns the post-update canonical representation
	// per spec §7.1.1.
	UpdateConfig(ctx context.Context, cfg *ssf.StreamConfig) (*ssf.StreamConfig, error)

	// DeleteConfig removes the stream identified by streamID per
	// spec §7.1.1.
	DeleteConfig(ctx context.Context, streamID string) error

	// GetStatus fetches the lifecycle state of the stream identified
	// by streamID per spec §7.1.2. When subject is non-empty the
	// response is scoped to that single subject; nil/empty returns
	// the stream-wide status.
	GetStatus(ctx context.Context, streamID string, subject json.RawMessage) (*ssf.StatusResponse, error)

	// UpdateStatus requests a lifecycle transition on the stream
	// identified by streamID per spec §7.1.2.
	UpdateStatus(ctx context.Context, streamID string, req *ssf.StatusUpdateRequest) (*ssf.StatusResponse, error)

	// AddSubject registers a subject as in-scope for the stream
	// identified by streamID per spec §7.1.3.
	AddSubject(ctx context.Context, streamID string, req *ssf.AddSubjectRequest) error

	// RemoveSubject removes a subject from the stream identified by
	// streamID per spec §7.1.3.
	RemoveSubject(ctx context.Context, streamID string, req *ssf.RemoveSubjectRequest) error

	// Verify initiates the verification flow on the stream
	// identified by streamID per spec §7.1.4.
	Verify(ctx context.Context, streamID string, req *ssf.VerificationRequest) error

	// PollEvents POSTs an RFC 8936 §2.4 poll request for the stream
	// identified by streamID and returns the response carrying any
	// pending SETs.
	PollEvents(ctx context.Context, streamID string, req *ssf.PollRequest) (*ssf.PollResponse, error)
}

// httpClient is the HTTP-backed implementation of [Client] that
// [NewClient] returns. It is unexported because consumers interact
// with the interface; access to its fields is reserved for tests in
// this package via export_test.go.
type httpClient struct {
	// baseURL is the parsed base URL the client appends endpoint
	// paths to. Stored pre-parsed so each request avoids re-parsing.
	baseURL *url.URL

	// doer is the HTTP transport. Defaults to [http.DefaultClient].
	doer HTTPDoer

	// authzHeader is the verbatim value to set on the Authorization
	// request header. Empty means no Authorization header is sent.
	authzHeader string

	// paths is the resolved endpoint path map after defaults and
	// any [WithEndpoints] override are applied.
	paths EndpointPaths
}

// Compile-time assertion: the HTTP-backed implementation satisfies
// both the package's own [Client] interface and the sibling
// [transmitter.Transmitter] interface, since the two share the same
// 11-method shape by design. Either side of the symmetry breaking
// (a method renamed, a signature drifted) trips this assertion at
// compile time rather than at first use.
var (
	_ Client                  = (*httpClient)(nil)
	_ transmitter.Transmitter = (*httpClient)(nil)
)

// Option configures the HTTP-backed [Client] at construction time.
// Options compose; later options override earlier ones for the same
// setting.
type Option func(*httpClient)

// WithHTTPDoer overrides the HTTP transport the client uses. The
// default is [http.DefaultClient]. Pass any value satisfying
// [HTTPDoer] — typically an [*http.Client] preconfigured with a
// custom [http.Transport], or a wrapper that layers retry, auth,
// metrics, or tracing.
//
// A nil doer is rejected at construction time so callers do not
// learn about the misconfiguration the first time a method panics on
// a nil-pointer dereference.
func WithHTTPDoer(doer HTTPDoer) Option {
	return func(c *httpClient) { c.doer = doer }
}

// WithAuthorizationHeader sets a verbatim Authorization header
// value the client adds to every request. Typical values are
// "Bearer <access-token>" for OAuth 2.0 bearer credentials or
// "Basic <base64>" for HTTP Basic authentication; the client does
// not interpret the value — it is copied onto each outbound request
// header as-is.
//
// Pass the empty string to clear a previously configured header.
// Callers needing per-request credentials (e.g. a token refreshed
// shortly before expiry) typically wrap [HTTPDoer] instead so the
// credential is minted at request time rather than fixed at client
// construction.
func WithAuthorizationHeader(header string) Option {
	return func(c *httpClient) { c.authzHeader = header }
}

// WithEndpoints overrides the per-endpoint URL paths the client
// appends to its base URL. Empty fields in paths fall through to the
// default value (see [DefaultConfigPath] and friends), so a caller
// who only needs to retarget one endpoint can leave the others zero.
//
// Use this option when the Transmitter is deployed with non-default
// path mounts (for example behind a reverse proxy that prefixes all
// SSF paths with `/api/v1`). The path values are joined to the base
// URL with [net/url] reference-resolution rules; supplying a
// fully-qualified URL in a path field is not supported.
func WithEndpoints(paths EndpointPaths) Option {
	return func(c *httpClient) {
		if paths.Config != "" {
			c.paths.Config = paths.Config
		}
		if paths.Status != "" {
			c.paths.Status = paths.Status
		}
		if paths.AddSubject != "" {
			c.paths.AddSubject = paths.AddSubject
		}
		if paths.RemoveSubject != "" {
			c.paths.RemoveSubject = paths.RemoveSubject
		}
		if paths.Verify != "" {
			c.paths.Verify = paths.Verify
		}
		if paths.Poll != "" {
			c.paths.Poll = paths.Poll
		}
	}
}

// NewClient constructs an HTTP-backed [Client] targeting the
// Transmitter at baseURL. The base URL is parsed and validated at
// construction time — an empty string or a string that does not
// parse as an absolute URL with an http(s) scheme is rejected with a
// wrapped [*ssf.ValidationError], so misconfiguration surfaces
// synchronously rather than as a confusing error from the first
// method call.
//
// Options apply after defaults: by default the client uses
// [http.DefaultClient] as its transport, sets no Authorization
// header, and uses the [DefaultConfigPath] / [DefaultStatusPath] /
// [DefaultAddSubjectPath] / [DefaultRemoveSubjectPath] /
// [DefaultVerifyPath] / [DefaultPollPath] endpoint paths.
//
// The returned Client is safe for concurrent use by multiple
// goroutines provided its [HTTPDoer] is — [http.DefaultClient] and
// any [*http.Client] are.
func NewClient(baseURL string, opts ...Option) (Client, error) {
	if baseURL == "" {
		return nil, &ssf.ValidationError{
			Rule:   "baseURL non-empty",
			Field:  "baseURL",
			Reason: "baseURL is required",
		}
	}
	parsed, err := url.Parse(baseURL)
	if err != nil {
		return nil, &ssf.ValidationError{
			Rule:   "baseURL parses",
			Field:  "baseURL",
			Reason: err.Error(),
		}
	}
	if !parsed.IsAbs() || parsed.Host == "" {
		return nil, &ssf.ValidationError{
			Rule:   "baseURL absolute",
			Field:  "baseURL",
			Reason: "baseURL must be an absolute URL with a host",
		}
	}
	if parsed.Scheme != "http" && parsed.Scheme != "https" {
		return nil, &ssf.ValidationError{
			Rule:   "baseURL scheme",
			Field:  "baseURL",
			Reason: fmt.Sprintf("baseURL scheme must be http or https, got %q", parsed.Scheme),
		}
	}

	c := &httpClient{
		baseURL: parsed,
		doer:    http.DefaultClient,
		paths: EndpointPaths{
			Config:        DefaultConfigPath,
			Status:        DefaultStatusPath,
			AddSubject:    DefaultAddSubjectPath,
			RemoveSubject: DefaultRemoveSubjectPath,
			Verify:        DefaultVerifyPath,
			Poll:          DefaultPollPath,
		},
	}
	for _, opt := range opts {
		opt(c)
	}
	if c.doer == nil {
		return nil, &ssf.ValidationError{
			Rule:   "doer non-nil",
			Field:  "doer",
			Reason: "WithHTTPDoer was passed nil; use http.DefaultClient or omit the option",
		}
	}
	return c, nil
}

// listConfigResponse mirrors the JSON envelope the Transmitter mux
// emits from its list-configuration endpoint:
//
//	{"streams": [ ...StreamConfig... ], "next_page_token": "..."}
//
// The shape is not pinned by OpenID Shared Signals Framework 1.0
// §7.1.1 — the spec is silent on a pagination envelope — but both
// halves of this library use the same shape so a client paired with
// the library's own [transmitter.MuxHandler] round-trips cleanly.
type listConfigResponse struct {
	Streams       []*ssf.StreamConfig `json:"streams"`
	NextPageToken string              `json:"next_page_token,omitempty"`
}

// GetConfig fetches the stream configuration identified by streamID
// per OpenID Shared Signals Framework 1.0 §7.1.1. The HTTP request
// is GET against the configured Config path with stream_id as a
// query parameter.
//
// A 404 response surfaces as an error matching
// [ssf.ErrStreamNotFound] (via [errors.Is]); other non-2xx responses
// follow [ParseHTTPError]'s usual mapping.
func (c *httpClient) GetConfig(ctx context.Context, streamID string) (*ssf.StreamConfig, error) {
	q := url.Values{"stream_id": []string{streamID}}
	req, err := c.newRequest(ctx, http.MethodGet, c.paths.Config, q, nil)
	if err != nil {
		return nil, err
	}
	var out ssf.StreamConfig
	if err := c.do(req, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// ListConfig fetches a page of stream configurations the caller is
// authorized to see per OpenID Shared Signals Framework 1.0 §7.1.1.
// pageToken is the opaque continuation token returned by the
// previous call (empty for the first page); nextToken is empty when
// the listing is exhausted.
//
// The wire envelope is the JSON object {"streams": [...],
// "next_page_token": "..."} that the library's own
// [transmitter.MuxHandler] emits. Transmitters that omit the
// envelope and return a bare JSON array of [ssf.StreamConfig] are
// not supported by this method — switch to a custom path layout and
// decode the array yourself if you have to integrate with one.
func (c *httpClient) ListConfig(ctx context.Context, pageToken string) (configs []*ssf.StreamConfig, nextToken string, err error) {
	q := url.Values{}
	if pageToken != "" {
		q.Set("page_token", pageToken)
	}
	req, err := c.newRequest(ctx, http.MethodGet, c.paths.Config, q, nil)
	if err != nil {
		return nil, "", err
	}
	var out listConfigResponse
	if err := c.do(req, &out); err != nil {
		return nil, "", err
	}
	return out.Streams, out.NextPageToken, nil
}

// CreateConfig POSTs cfg to the stream-configuration endpoint per
// OpenID Shared Signals Framework 1.0 §7.1.1 and returns the
// server-assigned canonical representation. The body is the
// JSON-encoded [ssf.StreamConfig]; the Transmitter typically assigns
// fields the caller omitted (StreamID, IssuerJWKSURI, …) and the
// returned value reflects those assignments.
func (c *httpClient) CreateConfig(ctx context.Context, cfg *ssf.StreamConfig) (*ssf.StreamConfig, error) {
	if cfg == nil {
		return nil, &ssf.ValidationError{
			Rule:   "cfg non-nil",
			Field:  "cfg",
			Reason: "cfg is required",
		}
	}
	req, err := c.newRequest(ctx, http.MethodPost, c.paths.Config, nil, cfg)
	if err != nil {
		return nil, err
	}
	var out ssf.StreamConfig
	if err := c.do(req, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// UpdateConfig PATCHes the stream identified by cfg.StreamID with
// cfg and returns the post-update canonical representation per
// OpenID Shared Signals Framework 1.0 §7.1.1. The stream_id is sent
// as a query parameter (the library's mux makes it authoritative)
// and the full configuration is the JSON body — the operation is a
// full replacement, not a merge.
func (c *httpClient) UpdateConfig(ctx context.Context, cfg *ssf.StreamConfig) (*ssf.StreamConfig, error) {
	if cfg == nil {
		return nil, &ssf.ValidationError{
			Rule:   "cfg non-nil",
			Field:  "cfg",
			Reason: "cfg is required",
		}
	}
	if cfg.StreamID == "" {
		return nil, &ssf.ValidationError{
			Rule:   "cfg.StreamID non-empty",
			Field:  "stream_id",
			Reason: "cfg.StreamID is required to identify the target stream",
		}
	}
	q := url.Values{"stream_id": []string{cfg.StreamID}}
	req, err := c.newRequest(ctx, http.MethodPatch, c.paths.Config, q, cfg)
	if err != nil {
		return nil, err
	}
	var out ssf.StreamConfig
	if err := c.do(req, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// DeleteConfig removes the stream identified by streamID per OpenID
// Shared Signals Framework 1.0 §7.1.1. The Transmitter returns 204
// No Content on success; the method drains and discards any body
// the Transmitter chose to include.
func (c *httpClient) DeleteConfig(ctx context.Context, streamID string) error {
	q := url.Values{"stream_id": []string{streamID}}
	req, err := c.newRequest(ctx, http.MethodDelete, c.paths.Config, q, nil)
	if err != nil {
		return err
	}
	return c.do(req, nil)
}

// GetStatus fetches the lifecycle state of the stream identified by
// streamID per OpenID Shared Signals Framework 1.0 §7.1.2. When
// subject is non-empty it is forwarded as the subject query parameter
// verbatim — the spec treats it as JSON bytes — and the response is
// scoped to that single subject; nil/empty returns the stream-wide
// status.
//
// subject is [encoding/json.RawMessage] rather than a typed Subject
// Identifier because the spec leaves the type open (any RFC 9493
// format). Callers that hold a typed value marshal it first.
func (c *httpClient) GetStatus(ctx context.Context, streamID string, subject json.RawMessage) (*ssf.StatusResponse, error) {
	q := url.Values{"stream_id": []string{streamID}}
	if len(subject) > 0 {
		q.Set("subject", string(subject))
	}
	req, err := c.newRequest(ctx, http.MethodGet, c.paths.Status, q, nil)
	if err != nil {
		return nil, err
	}
	var out ssf.StatusResponse
	if err := c.do(req, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// UpdateStatus requests a lifecycle transition on the stream
// identified by streamID per OpenID Shared Signals Framework 1.0
// §7.1.2. The Transmitter MAY honor, delay, or refuse the request;
// the returned [ssf.StatusResponse] reflects the resulting state,
// which may converge asynchronously.
func (c *httpClient) UpdateStatus(ctx context.Context, streamID string, body *ssf.StatusUpdateRequest) (*ssf.StatusResponse, error) {
	if body == nil {
		return nil, &ssf.ValidationError{
			Rule:   "body non-nil",
			Field:  "body",
			Reason: "body is required",
		}
	}
	q := url.Values{"stream_id": []string{streamID}}
	req, err := c.newRequest(ctx, http.MethodPost, c.paths.Status, q, body)
	if err != nil {
		return nil, err
	}
	var out ssf.StatusResponse
	if err := c.do(req, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// AddSubject registers a subject as in-scope for the stream
// identified by streamID per OpenID Shared Signals Framework 1.0
// §7.1.3. The Transmitter's response body (an empty JSON object) is
// drained and discarded; success is signalled by the absence of an
// error.
func (c *httpClient) AddSubject(ctx context.Context, streamID string, body *ssf.AddSubjectRequest) error {
	if body == nil {
		return &ssf.ValidationError{
			Rule:   "body non-nil",
			Field:  "body",
			Reason: "body is required",
		}
	}
	q := url.Values{"stream_id": []string{streamID}}
	req, err := c.newRequest(ctx, http.MethodPost, c.paths.AddSubject, q, body)
	if err != nil {
		return err
	}
	return c.do(req, nil)
}

// RemoveSubject removes a subject from the stream identified by
// streamID per OpenID Shared Signals Framework 1.0 §7.1.3. The
// response body (an empty JSON object) is drained and discarded.
func (c *httpClient) RemoveSubject(ctx context.Context, streamID string, body *ssf.RemoveSubjectRequest) error {
	if body == nil {
		return &ssf.ValidationError{
			Rule:   "body non-nil",
			Field:  "body",
			Reason: "body is required",
		}
	}
	q := url.Values{"stream_id": []string{streamID}}
	req, err := c.newRequest(ctx, http.MethodPost, c.paths.RemoveSubject, q, body)
	if err != nil {
		return err
	}
	return c.do(req, nil)
}

// Verify initiates the verification flow on the stream identified by
// streamID per OpenID Shared Signals Framework 1.0 §7.1.4. The
// Transmitter queues a verification SET for delivery and returns
// 200; the SET itself appears on the configured delivery channel
// (push endpoint or next poll), where the Receiver matches it
// against the state value supplied in body.
func (c *httpClient) Verify(ctx context.Context, streamID string, body *ssf.VerificationRequest) error {
	if body == nil {
		return &ssf.ValidationError{
			Rule:   "body non-nil",
			Field:  "body",
			Reason: "body is required",
		}
	}
	q := url.Values{"stream_id": []string{streamID}}
	req, err := c.newRequest(ctx, http.MethodPost, c.paths.Verify, q, body)
	if err != nil {
		return err
	}
	return c.do(req, nil)
}

// PollEvents POSTs a poll request to the Transmitter's poll endpoint
// per RFC 8936 §2.4 and returns the response carrying any pending
// SETs. The stream_id is supplied as a query parameter — the
// library's [transmitter.PollHandler] mounts the poll endpoint that
// way so a single handler can serve multiple streams behind a
// shared auth scope. (RFC 8936 itself leaves stream identification
// to the auth credential; the library's wire shape is the more
// explicit choice that the [transmitter.Transmitter] interface
// requires.)
func (c *httpClient) PollEvents(ctx context.Context, streamID string, body *ssf.PollRequest) (*ssf.PollResponse, error) {
	if body == nil {
		return nil, &ssf.ValidationError{
			Rule:   "body non-nil",
			Field:  "body",
			Reason: "body is required",
		}
	}
	q := url.Values{"stream_id": []string{streamID}}
	req, err := c.newRequest(ctx, http.MethodPost, c.paths.Poll, q, body)
	if err != nil {
		return nil, err
	}
	var out ssf.PollResponse
	if err := c.do(req, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// newRequest assembles an [*http.Request] for the given method,
// endpoint path, query, and optional JSON body. The path is resolved
// against the client's base URL with [net/url] reference-resolution
// rules; the query is appended as the URL's RawQuery; the body, when
// non-nil, is JSON-marshaled and the Content-Type header is set.
//
// The Authorization and Accept headers are applied here so every
// method shares the same outbound header policy.
func (c *httpClient) newRequest(ctx context.Context, method, path string, query url.Values, body any) (*http.Request, error) {
	endpoint, err := c.resolvePath(path)
	if err != nil {
		return nil, err
	}
	if len(query) > 0 {
		endpoint.RawQuery = query.Encode()
	}

	var bodyReader io.Reader
	if body != nil {
		buf, err := json.Marshal(body)
		if err != nil {
			return nil, fmt.Errorf("ssf/client: marshal request body: %w", err)
		}
		bodyReader = bytes.NewReader(buf)
	}

	req, err := http.NewRequestWithContext(ctx, method, endpoint.String(), bodyReader)
	if err != nil {
		return nil, fmt.Errorf("ssf/client: build request: %w", err)
	}
	req.Header.Set("Accept", acceptHeader)
	if body != nil {
		req.Header.Set("Content-Type", jsonContentType)
	}
	if c.authzHeader != "" {
		req.Header.Set("Authorization", c.authzHeader)
	}
	return req, nil
}

// resolvePath joins the supplied endpoint path to the client's base
// URL. The base URL's path is treated as a directory prefix — even
// when it has no trailing slash — so a base URL of
// "https://t.example.com/api" and a path of "/streams" produce
// "https://t.example.com/api/streams" rather than the
// [net/url.URL.ResolveReference] default of stripping "/api". This
// matches the way Transmitter deployments behind a reverse-proxy
// path prefix typically configure their clients.
func (c *httpClient) resolvePath(path string) (*url.URL, error) {
	if path == "" {
		return nil, &ssf.ValidationError{
			Rule:   "endpoint path non-empty",
			Field:  "path",
			Reason: "endpoint path is empty; ensure WithEndpoints leaves no required field blank",
		}
	}

	// Treat the base URL's path as a directory so suffix-joining the
	// endpoint path does not strip the last base-path segment.
	base := *c.baseURL
	if base.Path != "" && !strings.HasSuffix(base.Path, "/") {
		base.Path += "/"
	}
	rel := strings.TrimPrefix(path, "/")
	ref, err := url.Parse(rel)
	if err != nil {
		return nil, fmt.Errorf("ssf/client: parse endpoint path %q: %w", path, err)
	}
	return base.ResolveReference(ref), nil
}

// do executes req through the configured [HTTPDoer], parses the
// response, and — on a 2xx response with a non-nil out — JSON-decodes
// the body into out. On non-2xx the response is passed to
// [ParseHTTPError] and the resulting error is returned (joined with
// the matching root-package sentinel where applicable).
//
// On 2xx with out == nil the body is drained and discarded so the
// underlying TCP connection can be reused.
func (c *httpClient) do(req *http.Request, out any) error {
	resp, err := c.doer.Do(req)
	if err != nil {
		return fmt.Errorf("ssf/client: http %s %s: %w", req.Method, req.URL.Path, err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return ParseHTTPError(resp)
	}

	if out == nil {
		// Drain the body so the connection can be reused.
		_, _ = io.Copy(io.Discard, resp.Body)
		return nil
	}

	if resp.StatusCode == http.StatusNoContent || resp.ContentLength == 0 {
		// 204 by spec has no body; some Transmitters return 200 with
		// an empty body too. Either is fine — out keeps its zero
		// value.
		_, _ = io.Copy(io.Discard, resp.Body)
		return nil
	}

	if err := json.NewDecoder(resp.Body).Decode(out); err != nil {
		return fmt.Errorf("ssf/client: decode %s %s response: %w",
			req.Method, req.URL.Path, err)
	}
	return nil
}
