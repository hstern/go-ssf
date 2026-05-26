// Copyright 2026 The go-ssf Authors
// SPDX-License-Identifier: Apache-2.0

package receiver

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"sync"
	"time"

	"github.com/hstern/go-ssf"
)

// defaultChallengeTimeout is the wait used by [VerificationChallenger.Challenge]
// when the caller passes neither [WithTimeout] nor a context deadline.
// Spec §7.1.4 ties the verification round-trip to the stream's
// min_verification_interval; thirty seconds is a conservative default
// that fits the smallest reasonable interval while leaving slack for
// real-world delivery latency.
const defaultChallengeTimeout = 30 * time.Second

// challengeStateBytes is the entropy budget for a server-side
// generated state string — 32 bytes of crypto/rand, base64url-encoded
// without padding. That width matches the spec's "opaque" framing in
// §7.1.4 and is wider than any value an attacker could realistically
// guess between the POST and the SET delivery.
const challengeStateBytes = 32

// VerificationChallenger drives the Receiver side of the spec §7.1.4
// verification handshake. It POSTs a verification request to the
// Transmitter and waits for the matching verification Security Event
// Token to arrive over the stream's normal delivery channel.
//
// A VerificationChallenger is a small piece of cross-cutting state:
// it tracks the in-flight challenges by their state value and signals
// the waiter when the matching SET payload reaches the Receiver. The
// SET arrival side is exposed through [VerificationChallenger.WrapSink],
// which returns a [Sink] decorator the consumer wires into their
// [PushHandler] (or the Poller delivery path). Wrapped delivery
// inspects each SET's events claim for a verification event and, if
// the carried state matches an in-flight challenge, hands the payload
// to that challenge's waiter and stops the SET — verification SETs are
// a control-plane echo, not application data, and forwarding them to
// the downstream Sink confuses event routing.
//
// Multiple challenges may be in flight concurrently — for example one
// per stream, or one per scheduled re-verification. Each challenge's
// state value is unique among in-flight challenges; the second
// concurrent call to [VerificationChallenger.Challenge] reusing the
// same state via [WithState] is rejected. The library generates a
// fresh state when the caller does not supply one.
//
// The zero value of VerificationChallenger is not usable; construct
// one with [NewVerificationChallenger].
type VerificationChallenger struct {
	mu      sync.Mutex
	pending map[string]chan []byte
}

// NewVerificationChallenger returns a [VerificationChallenger] ready
// to serve concurrent challenges. The returned value is safe for use
// from multiple goroutines.
func NewVerificationChallenger() *VerificationChallenger {
	return &VerificationChallenger{
		pending: make(map[string]chan []byte),
	}
}

// challengeOptions holds the resolved configuration for one call to
// [VerificationChallenger.Challenge]. Fields are unexported so the
// option functions remain the only construction path.
type challengeOptions struct {
	endpoint   string
	streamID   string
	authHeader string
	state      string
	httpClient *http.Client
	timeout    time.Duration
}

// ChallengeOption configures a single call to
// [VerificationChallenger.Challenge]. Option functions are evaluated
// in order; later options override earlier ones for the same field.
type ChallengeOption func(*challengeOptions)

// WithEndpoint sets the absolute URL of the Transmitter's
// verification endpoint, per spec §7.1.4. The endpoint MUST be
// provided; Challenge returns an error if none is supplied.
func WithEndpoint(endpoint string) ChallengeOption {
	return func(o *challengeOptions) {
		o.endpoint = endpoint
	}
}

// WithStreamID adds the spec §7.1.4 stream_id query parameter to the
// verification POST. Omit when the deployment selects the stream by
// other means (e.g. URL path or authentication scope).
func WithStreamID(streamID string) ChallengeOption {
	return func(o *challengeOptions) {
		o.streamID = streamID
	}
}

// WithAuthorizationHeader sets the Authorization header on the
// verification POST verbatim. The spec is auth-scheme agnostic — the
// header value passes through unmodified, including any "Bearer "
// prefix the caller wishes to include.
func WithAuthorizationHeader(header string) ChallengeOption {
	return func(o *challengeOptions) {
		o.authHeader = header
	}
}

// WithState pins the state value used for this challenge. The state
// is echoed verbatim by the Transmitter into the verification SET so
// the Receiver correlates the inbound SET to this in-flight challenge.
// When the caller omits this option Challenge generates a fresh value
// from crypto/rand.
func WithState(state string) ChallengeOption {
	return func(o *challengeOptions) {
		o.state = state
	}
}

// WithHTTPClient overrides the [http.Client] used for the verification
// POST. The default is [http.DefaultClient]. Callers wanting custom
// transport, timeouts, or TLS settings supply their own client here.
func WithHTTPClient(client *http.Client) ChallengeOption {
	return func(o *challengeOptions) {
		o.httpClient = client
	}
}

// WithTimeout caps how long Challenge waits for the matching
// verification SET. The shorter of this timeout and the parent
// context's deadline wins. When neither is set the default
// (thirty seconds) applies.
func WithTimeout(timeout time.Duration) ChallengeOption {
	return func(o *challengeOptions) {
		o.timeout = timeout
	}
}

// Challenge initiates a spec §7.1.4 verification handshake against
// the Transmitter and returns the JSON payload of the matching
// verification Security Event Token once it arrives through the
// wrapped [Sink].
//
// The workflow is:
//
//  1. Resolve options and pick a state value (caller-supplied via
//     [WithState] or freshly generated).
//  2. Register the state in the in-flight challenge table.
//  3. POST {"state": ...} to the verification endpoint, with optional
//     stream_id query parameter and Authorization header.
//  4. Wait for the wrapped Sink to receive a verification SET carrying
//     the same state, or for the timeout / context cancellation to
//     fire.
//  5. Clean up the registration regardless of outcome and return.
//
// Timeout selection: when [WithTimeout] is supplied, that value sets
// an internal deadline; the effective wait is the shorter of that
// internal deadline and the parent context's own deadline. Cancelling
// the parent context unblocks the wait promptly. When neither is set
// the default (thirty seconds) applies.
//
// On timeout the returned error wraps [github.com/hstern/go-ssf.ErrVerificationTimeout]
// so [errors.Is] matches. On context cancellation the returned error
// is [context.Context.Err] from the caller's context. On POST failure
// (non-2xx or transport error) the registration is rolled back and
// the error from the HTTP layer is returned unwrapped — the caller
// distinguishes "could not reach Transmitter" from "Transmitter never
// delivered the SET" by error type.
//
// Challenge is safe to call concurrently. Each in-flight call holds
// its own channel and table slot; the only contention is the brief
// critical section around the table itself.
func (c *VerificationChallenger) Challenge(ctx context.Context, opts ...ChallengeOption) ([]byte, error) {
	cfg := challengeOptions{
		httpClient: http.DefaultClient,
	}
	for _, opt := range opts {
		opt(&cfg)
	}

	if cfg.endpoint == "" {
		return nil, fmt.Errorf("ssf/receiver: verification endpoint required (use receiver.WithEndpoint)")
	}

	state := cfg.state
	if state == "" {
		generated, err := generateState()
		if err != nil {
			return nil, fmt.Errorf("ssf/receiver: generate verification state: %w", err)
		}
		state = generated
	}

	waiter, err := c.register(state)
	if err != nil {
		return nil, err
	}
	defer c.unregister(state)

	if err := c.postChallenge(ctx, &cfg, state); err != nil {
		return nil, err
	}

	return c.wait(ctx, waiter, cfg.timeout)
}

// register installs a fresh channel for state in the in-flight table.
// Re-registering the same state returns an error rather than
// overwriting, so a caller that supplies a duplicate state via
// [WithState] gets a clear failure instead of one challenge stealing
// another's SET.
func (c *VerificationChallenger) register(state string) (chan []byte, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if _, exists := c.pending[state]; exists {
		return nil, fmt.Errorf("ssf/receiver: verification state already in flight")
	}
	ch := make(chan []byte, 1)
	c.pending[state] = ch
	return ch, nil
}

// unregister drops the state's slot from the in-flight table. Called
// from Challenge's deferred cleanup so both success and failure paths
// release the slot.
func (c *VerificationChallenger) unregister(state string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	delete(c.pending, state)
}

// postChallenge issues the spec §7.1.4 verification POST. The body is
// a single-field JSON object carrying the state value; the optional
// stream_id query parameter and Authorization header are added when
// configured. Any non-2xx response, transport error, or URL parse
// error is returned with enough context for the caller to act on.
func (c *VerificationChallenger) postChallenge(ctx context.Context, cfg *challengeOptions, state string) error {
	target, err := buildVerificationURL(cfg.endpoint, cfg.streamID)
	if err != nil {
		return err
	}

	body, err := json.Marshal(ssf.VerificationRequest{State: state})
	if err != nil {
		return fmt.Errorf("ssf/receiver: encode verification request: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, target, bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("ssf/receiver: build verification request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	if cfg.authHeader != "" {
		req.Header.Set("Authorization", cfg.authHeader)
	}

	resp, err := cfg.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("ssf/receiver: post verification request: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()
	// Drain any response body so the underlying connection can be
	// reused by the transport. The spec defines the response as
	// 200 with no required body shape; reading is a courtesy to the
	// HTTP client.
	_, _ = io.Copy(io.Discard, resp.Body)

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("ssf/receiver: verification endpoint returned %s", resp.Status)
	}
	return nil
}

// wait blocks until either the wrapped Sink signals a matching SET,
// the parent context fires, or the timeout elapses. Timeout selection
// honors the smaller of the option-supplied timeout and the parent
// context's deadline; the default applies when neither is set.
func (c *VerificationChallenger) wait(ctx context.Context, waiter <-chan []byte, optTimeout time.Duration) ([]byte, error) {
	timeout := resolveTimeout(ctx, optTimeout)

	timer := time.NewTimer(timeout)
	defer timer.Stop()

	select {
	case payload := <-waiter:
		return payload, nil
	case <-ctx.Done():
		return nil, ctx.Err()
	case <-timer.C:
		return nil, fmt.Errorf("ssf/receiver: waiting for verification SET: %w", ssf.ErrVerificationTimeout)
	}
}

// resolveTimeout collapses the option-supplied timeout, the parent
// context's deadline, and the default into a single duration. The
// smaller positive value wins; the default applies when both inputs
// are absent. A non-positive option timeout is treated as absent
// (i.e. defer to the context or the default), matching the convention
// elsewhere in the library.
func resolveTimeout(ctx context.Context, optTimeout time.Duration) time.Duration {
	var fromCtx time.Duration
	if deadline, ok := ctx.Deadline(); ok {
		fromCtx = time.Until(deadline)
		if fromCtx <= 0 {
			// The context is already past its deadline; the wait
			// will exit immediately via ctx.Done(). A near-zero
			// timer keeps the select from blocking on the timer
			// channel before the ctx.Done path fires.
			return time.Nanosecond
		}
	}

	switch {
	case optTimeout > 0 && fromCtx > 0:
		if optTimeout < fromCtx {
			return optTimeout
		}
		return fromCtx
	case optTimeout > 0:
		return optTimeout
	case fromCtx > 0:
		return fromCtx
	default:
		return defaultChallengeTimeout
	}
}

// buildVerificationURL composes the endpoint URL with the optional
// stream_id query parameter. The base endpoint MAY already carry
// query parameters; the function preserves them and appends stream_id
// when supplied.
func buildVerificationURL(endpoint, streamID string) (string, error) {
	if streamID == "" {
		return endpoint, nil
	}
	parsed, err := url.Parse(endpoint)
	if err != nil {
		return "", fmt.Errorf("ssf/receiver: parse verification endpoint: %w", err)
	}
	q := parsed.Query()
	q.Set("stream_id", streamID)
	parsed.RawQuery = q.Encode()
	return parsed.String(), nil
}

// generateState produces a fresh 32-byte random state value encoded
// as base64url without padding. crypto/rand.Read does not return
// short reads on success and reports any underlying failure as an
// error, so the returned string is always the full width on the
// happy path.
func generateState() (string, error) {
	buf := make([]byte, challengeStateBytes)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(buf), nil
}

// WrapSink decorates downstream so that verification SETs whose state
// matches an in-flight challenge are intercepted and forwarded to the
// waiter rather than the downstream Sink. Every other SET passes
// through to downstream unchanged.
//
// Match logic: the wrapped Sink decodes just enough of the payload to
// inspect its events claim. If the events claim carries a
// [github.com/hstern/go-ssf.EventTypeVerification] entry whose state
// matches a currently in-flight challenge, the payload is delivered
// to that challenge's waiter and the Sink returns nil — the SET does
// NOT reach downstream. Otherwise the payload is forwarded to
// downstream.DeliverSET as-is, including verification events whose
// state does not match (which can happen when a stale or unsolicited
// verification SET is delivered; the consumer's Sink decides what to
// do with it).
//
// WrapSink does not parse SET payloads it does not need to. A
// payload that is not valid JSON, or whose events claim is absent
// or non-object, is treated as "not a verification event match"
// and forwarded to downstream unchanged. This keeps the wrapper
// transparent for non-JSON payloads or future extensions.
func (c *VerificationChallenger) WrapSink(downstream Sink) Sink {
	return SinkFunc(func(ctx context.Context, payload []byte) error {
		if c.intercept(payload) {
			return nil
		}
		if downstream == nil {
			return nil
		}
		return downstream.DeliverSET(ctx, payload)
	})
}

// intercept inspects payload for a verification event whose state
// matches an in-flight challenge. On match it hands the payload to
// the waiter and returns true; otherwise returns false. Match
// failures are silent — the caller is expected to forward the
// payload to the downstream Sink.
func (c *VerificationChallenger) intercept(payload []byte) bool {
	state, ok := extractVerificationState(payload)
	if !ok {
		return false
	}

	c.mu.Lock()
	waiter, exists := c.pending[state]
	if exists {
		// Remove the entry under the lock so the same state cannot
		// be matched twice if a duplicate verification SET arrives.
		delete(c.pending, state)
	}
	c.mu.Unlock()

	if !exists {
		return false
	}

	// The waiter channel is buffered with capacity one and only the
	// sender writes to it, so this send never blocks.
	waiter <- payload
	return true
}

// extractVerificationState reads payload as a SET claims set, looks
// for a verification event in the events claim, and returns its
// state value. It is deliberately tolerant: any decode failure or
// missing field yields ("", false), and the caller treats that as
// "not a match" and forwards the SET unchanged. The shape probed is
// the minimum the spec §7.1.4 SET carries:
//
//	{ "events": { "<verification URI>": { "state": "..." } } }
func extractVerificationState(payload []byte) (string, bool) {
	var envelope struct {
		Events map[string]json.RawMessage `json:"events"`
	}
	if err := json.Unmarshal(payload, &envelope); err != nil {
		return "", false
	}
	raw, ok := envelope.Events[ssf.EventTypeVerification]
	if !ok {
		return "", false
	}
	var event ssf.VerificationEvent
	if err := json.Unmarshal(raw, &event); err != nil {
		return "", false
	}
	if event.State == "" {
		return "", false
	}
	return event.State, true
}
