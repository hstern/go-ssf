// Copyright 2026 The go-ssf Authors
// SPDX-License-Identifier: Apache-2.0

// This file implements the push-mode delivery driver — the
// retry-and-classify loop around a single HTTP POST of a signed
// Security Event Token to a Receiver endpoint per RFC 8935.

package transmitter

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"math/rand/v2"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/hstern/go-ssf"
)

// pushContentType is the HTTP Content-Type header value Receivers
// expect on POSTed Security Event Tokens per RFC 8935 §3.1.
// The token shipped in the body is the JWS-compact serialization
// of the SET; the JWS itself carries typ="secevent+jwt" per
// RFC 8417 §2.2 (see [ssf.SETMediaType]).
const pushContentType = "application/secevent+jwt"

// Default knobs for [PushDriver]. Chosen for the SSF push-mode
// shape: short individual retries (Receivers either respond fast
// or are unreachable), a small retry budget (the queue belongs to
// the [ssf.StreamStore], not the driver), and a one-minute ceiling
// so a long outage doesn't park goroutines on multi-minute sleeps.
const (
	defaultMaxRetries     = 5
	defaultInitialBackoff = 1 * time.Second
	defaultMaxBackoff     = 1 * time.Minute
	jitterFraction        = 0.20
)

// Target describes a single push-mode delivery endpoint. One
// [PushDriver] serves many Targets; the driver is stateless and
// carries no per-Target queue (see package doc).
type Target struct {
	// EndpointURL is the absolute URL the SET is POSTed to. The
	// value is taken from the Receiver's StreamConfig (RFC 8935
	// §2.1.1 "endpoint_url"). The driver does not validate the URL
	// scheme; callers wanting to forbid http:// targets should do
	// so at registration time.
	EndpointURL string

	// AuthorizationHeader is the verbatim value of the
	// Authorization request header sent on every POST to this
	// Target, or empty to send none. The driver does not interpret
	// the value — "Bearer …", "Basic …", or any other RFC 7235
	// scheme is accepted as-is. The Receiver-side authentication
	// scheme is negotiated out of band (RFC 8935 §3 leaves it
	// unspecified).
	AuthorizationHeader string
}

// PushDriver delivers signed Security Event Tokens to a [Target]
// via HTTP POST per RFC 8935 (push-based SET delivery). Each
// [PushDriver.Deliver] call signs the payload with the configured
// [ssf.SETSigner], POSTs the compact-serialized JWS, and retries
// transient failures with exponential backoff and jitter.
//
// The driver is stateless and carries no internal queue: the
// payload is signed and shipped within a single call. A
// Transmitter that wants at-least-once delivery semantics
// persists undelivered events in its [ssf.StreamStore] and feeds
// them to [PushDriver.Deliver] one at a time; the driver's role is
// the retry-and-classify loop around a single POST.
//
// A zero PushDriver is not useful — construct one with
// [NewPushDriver], which applies the defaults.
type PushDriver struct {
	signer         ssf.SETSigner
	httpClient     *http.Client
	maxRetries     int
	initialBackoff time.Duration
	maxBackoff     time.Duration
	onDeadLetter   func(ctx context.Context, target Target, payload []byte, lastErr error)

	// sleep is the cancellation-aware sleep primitive. It is a
	// field so tests can swap in a deterministic implementation
	// without monkey-patching time. The default is [contextSleep].
	sleep func(ctx context.Context, d time.Duration) error

	// now returns the current time. A field for the same reason as
	// sleep — Retry-After HTTP-date parsing needs an injectable
	// clock for deterministic tests.
	now func() time.Time
}

// PushDriverOption configures a [PushDriver] at construction
// time. See [NewPushDriver] for the canonical application order
// (defaults first, then options in the order supplied).
type PushDriverOption func(*PushDriver)

// WithHTTPClient overrides the [http.Client] the driver uses for
// the POST. The default is [http.DefaultClient]. Consumers needing
// per-Target TLS material, custom transports, or response-size
// limits supply their own client here.
func WithHTTPClient(client *http.Client) PushDriverOption {
	return func(d *PushDriver) {
		if client != nil {
			d.httpClient = client
		}
	}
}

// WithMaxRetries overrides the retry budget for transient
// failures. The value is the number of retries — a value of 5
// means the driver makes up to six total POST attempts before
// giving up. Values < 0 are clamped to 0 (no retries; one
// attempt total).
func WithMaxRetries(n int) PushDriverOption {
	return func(d *PushDriver) {
		if n < 0 {
			n = 0
		}
		d.maxRetries = n
	}
}

// WithBackoff overrides the exponential-backoff bounds. initial
// is the first sleep after the first failure; the sleep doubles
// on each subsequent retry, capped at maximum. ±20% jitter is
// applied at each step. A non-positive initial defaults to the
// package default; a maximum less than initial is raised to
// initial.
func WithBackoff(initial, maximum time.Duration) PushDriverOption {
	return func(d *PushDriver) {
		if initial > 0 {
			d.initialBackoff = initial
		}
		if maximum < d.initialBackoff {
			maximum = d.initialBackoff
		}
		d.maxBackoff = maximum
	}
}

// WithOnDeadLetter installs a callback invoked once per Deliver
// call that ultimately fails — either because the Receiver
// returned a permanent (non-retryable) status, or because the
// retry budget was exhausted on transient failures. The callback
// is the only signal the caller gets that a SET has been dropped;
// without one, Deliver still returns the last error but the
// payload is not surfaced anywhere else.
//
// The callback is invoked synchronously on the goroutine calling
// Deliver. It MUST NOT block — a slow dead-letter sink should
// hand off to its own goroutine. The callback is not invoked on
// context cancellation; the caller already has the [context.Context]
// in scope and can dead-letter at the call site if it cares.
func WithOnDeadLetter(fn func(ctx context.Context, target Target, payload []byte, lastErr error)) PushDriverOption {
	return func(d *PushDriver) {
		d.onDeadLetter = fn
	}
}

// NewPushDriver returns a [PushDriver] configured with the given
// signer and any number of options applied in order. The signer
// is required; passing nil panics, on the principle that a
// misconfigured signer is a programmer error rather than a
// runtime condition. Defaults applied before options:
//
//   - HTTPClient: [http.DefaultClient]
//   - MaxRetries: 5
//   - InitialBackoff: 1s
//   - MaxBackoff: 1m
//   - OnDeadLetter: no-op
func NewPushDriver(signer ssf.SETSigner, opts ...PushDriverOption) *PushDriver {
	if signer == nil {
		panic("transmitter: NewPushDriver requires a non-nil ssf.SETSigner")
	}
	d := &PushDriver{
		signer:         signer,
		httpClient:     http.DefaultClient,
		maxRetries:     defaultMaxRetries,
		initialBackoff: defaultInitialBackoff,
		maxBackoff:     defaultMaxBackoff,
		sleep:          contextSleep,
		now:            time.Now,
	}
	for _, opt := range opts {
		opt(d)
	}
	return d
}

// Deliver signs payload as a Security Event Token and POSTs it to
// target.EndpointURL. The payload is the raw JSON bytes of the
// SET claims set; signing produces the compact-serialized JWS
// transmitted in the request body.
//
// Status interpretation per RFC 8935 §3.2:
//
//   - 2xx: success, return nil.
//   - 408 Request Timeout, 429 Too Many Requests, 5xx: transient;
//     retry with exponential backoff (honoring Retry-After when
//     present on 429/503).
//   - other 4xx: permanent; do not retry, invoke the dead-letter
//     callback if configured, and return.
//   - network / transport error (connection refused, EOF mid-body,
//     etc.): transient; retry.
//
// On context cancellation Deliver returns [context.Context.Err]
// promptly — it does not wait for the current backoff sleep to
// elapse. The dead-letter callback is NOT invoked on cancellation;
// the caller already has the context in scope.
//
// On retry exhaustion the dead-letter callback is invoked with
// the last error and the original payload (the unsigned bytes —
// the JWS would be re-signed on retry by a fresh caller).
func (d *PushDriver) Deliver(ctx context.Context, target Target, payload []byte) error {
	if target.EndpointURL == "" {
		return errors.New("transmitter: PushDriver.Deliver requires a non-empty Target.EndpointURL")
	}

	jws, err := d.signer.Sign(payload)
	if err != nil {
		return fmt.Errorf("sign security event token: %w", err)
	}

	var (
		lastErr error
		backoff = d.initialBackoff
	)

	// Total attempts = 1 + maxRetries. The loop body runs once
	// per attempt; the trailing sleep gates the next attempt.
	for attempt := 0; attempt <= d.maxRetries; attempt++ {
		if err := ctx.Err(); err != nil {
			return err
		}

		retryAfter, attemptErr := d.attempt(ctx, target, jws)
		if attemptErr == nil {
			return nil
		}
		var perm *permanentError
		if errors.As(attemptErr, &perm) {
			// Surface the underlying status error — the internal
			// "permanent" marker is an implementation detail of
			// the retry loop and not part of the public surface.
			underlying := perm.underlying
			if d.onDeadLetter != nil {
				d.onDeadLetter(ctx, target, payload, underlying)
			}
			return underlying
		}
		lastErr = attemptErr

		// All remaining errors are transient. Sleep and try again,
		// unless this was the final attempt.
		if attempt == d.maxRetries {
			break
		}

		sleepFor := backoff
		if retryAfter > 0 {
			sleepFor = retryAfter
		}
		sleepFor = capDuration(applyJitter(sleepFor), d.maxBackoff)

		if err := d.sleep(ctx, sleepFor); err != nil {
			return err
		}

		// Double for the next attempt, but cap at maxBackoff so a
		// long string of transient failures doesn't drift the
		// per-attempt sleep past the configured ceiling.
		backoff *= 2
		if backoff > d.maxBackoff {
			backoff = d.maxBackoff
		}
	}

	if d.onDeadLetter != nil {
		d.onDeadLetter(ctx, target, payload, lastErr)
	}
	return lastErr
}

// permanentError marks an error as non-retryable. The marker is
// unexported because callers should not branch on the retry
// decision — they get the underlying status error via [Deliver]
// and the dead-letter callback fires once.
type permanentError struct{ underlying error }

func (e *permanentError) Error() string { return e.underlying.Error() }
func (e *permanentError) Unwrap() error { return e.underlying }

// attempt makes a single POST attempt and returns either nil
// (success), an [errPermanent]-wrapped error (do not retry), or a
// plain error (retry). The first return value is the parsed
// Retry-After hint in seconds; 0 means no hint.
func (d *PushDriver) attempt(ctx context.Context, target Target, jws string) (time.Duration, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, target.EndpointURL, strings.NewReader(jws))
	if err != nil {
		// A request-construction error (bad URL, bad method) is
		// not going to fix itself on retry.
		return 0, &permanentError{underlying: fmt.Errorf("build push request: %w", err)}
	}
	req.Header.Set("Content-Type", pushContentType)
	if target.AuthorizationHeader != "" {
		req.Header.Set("Authorization", target.AuthorizationHeader)
	}

	resp, err := d.httpClient.Do(req)
	if err != nil {
		// Network/transport errors are transient by default. Honor
		// context cancellation explicitly — the http client surfaces
		// it as a wrapped *url.Error, but the caller wants the bare
		// context.Canceled / DeadlineExceeded.
		if ctxErr := ctx.Err(); ctxErr != nil {
			return 0, ctxErr
		}
		return 0, fmt.Errorf("post security event token: %w", err)
	}

	// Drain and close so the connection can be returned to the
	// keep-alive pool. Reading the body also gives us something to
	// include in the error message on non-2xx responses for
	// operators triaging dead-lettered events.
	bodyBytes, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
	_ = resp.Body.Close()

	switch {
	case resp.StatusCode >= 200 && resp.StatusCode < 300:
		return 0, nil
	case resp.StatusCode == http.StatusRequestTimeout, // 408
		resp.StatusCode == http.StatusTooManyRequests, // 429
		resp.StatusCode >= 500:
		retryAfter := d.parseRetryAfter(resp.Header.Get("Retry-After"))
		return retryAfter, &pushHTTPError{StatusCode: resp.StatusCode, Body: bodyBytes}
	case resp.StatusCode >= 400 && resp.StatusCode < 500:
		return 0, &permanentError{underlying: &pushHTTPError{StatusCode: resp.StatusCode, Body: bodyBytes}}
	default:
		// 1xx / 3xx shouldn't happen on a POST with a body and the
		// Go client's default redirect-follower; treat as permanent
		// to avoid looping on a misbehaving Receiver.
		return 0, &permanentError{underlying: &pushHTTPError{StatusCode: resp.StatusCode, Body: bodyBytes}}
	}
}

// pushHTTPError reports a non-2xx response from the push
// endpoint. The error is surfaced verbatim to callers; the
// [PushDriver] does not parse the body as RFC 7807 because the
// push response shape is not specified by RFC 8935.
type pushHTTPError struct {
	StatusCode int
	Body       []byte
}

func (e *pushHTTPError) Error() string {
	if len(e.Body) == 0 {
		return fmt.Sprintf("push endpoint returned status %d", e.StatusCode)
	}
	return fmt.Sprintf("push endpoint returned status %d: %s", e.StatusCode, bytes.TrimSpace(e.Body))
}

// parseRetryAfter interprets an RFC 7231 §7.1.3 Retry-After
// header. The header is either delta-seconds (a non-negative
// integer) or an HTTP-date. Unparseable or non-positive values
// return 0, which signals "use the regular backoff".
func (d *PushDriver) parseRetryAfter(value string) time.Duration {
	value = strings.TrimSpace(value)
	if value == "" {
		return 0
	}
	if secs, err := strconv.Atoi(value); err == nil {
		if secs <= 0 {
			return 0
		}
		return time.Duration(secs) * time.Second
	}
	// HTTP-date forms: IMF-fixdate, RFC 850, ANSI C asctime.
	// net/http exposes the parser via [http.ParseTime].
	when, err := http.ParseTime(value)
	if err != nil {
		return 0
	}
	delta := when.Sub(d.now())
	if delta <= 0 {
		return 0
	}
	return delta
}

// applyJitter perturbs d by ±[jitterFraction]. Jitter is symmetric
// around d so the expected wait is unchanged; the variance prevents
// retry stampedes when many drivers hit the same Receiver at the
// same time.
func applyJitter(d time.Duration) time.Duration {
	if d <= 0 {
		return d
	}
	// rand.Float64() returns [0, 1); shift to [-jitterFraction, +jitterFraction).
	delta := (rand.Float64()*2 - 1) * jitterFraction
	jittered := float64(d) * (1 + delta)
	return time.Duration(jittered)
}

// capDuration returns d clamped to [0, max].
func capDuration(d, maximum time.Duration) time.Duration {
	if d < 0 {
		return 0
	}
	if d > maximum {
		return maximum
	}
	return d
}

// contextSleep is the default cancellation-aware sleep. It returns
// nil on completion and [context.Context.Err] on cancellation.
func contextSleep(ctx context.Context, d time.Duration) error {
	if d <= 0 {
		return nil
	}
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-t.C:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}
