// Copyright 2026 The go-ssf Authors
// SPDX-License-Identifier: Apache-2.0

package receiver

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/rand/v2"
	"net/http"
	"strconv"
	"sync"
	"time"

	"github.com/hstern/go-ssf"
)

// pollMediaType is the content type the Receiver sets on every
// poll request body. RFC 8936 §2.4 defines the poll endpoint as a
// JSON-bodied POST.
const pollMediaType = "application/json"

// SET-delivery error codes (RFC 8936 §6). The two codes the [Poller]
// reports are the standard tokens for "the JWS did not validate" and
// "the Sink could not process this SET"; consumers reading
// [ssf.PollRequest.SetErrs] on the Transmitter side see these strings
// verbatim.
const (
	setErrInvalidSET      = "invalid_set"
	setErrDeliveryFailure = "delivery_failed"
)

// Default cadence knobs. These are conservative starting points;
// callers tune via the With* options.
const (
	defaultMaxEvents             = 100
	defaultNoEventsBackoffMin    = 1 * time.Second
	defaultNoEventsBackoffMax    = 5 * time.Minute
	defaultErrorBackoffMin       = 1 * time.Second
	defaultErrorBackoffMax       = 1 * time.Hour
	defaultErrorBackoffJitterPct = 0.2
	defaultParallelism           = 1
)

// pollerClock abstracts the two time primitives the [Poller] needs so
// tests can drive cadence without real wall-clock waits. The default
// implementation is [realClock] and is unconditionally swapped in for
// production use.
type pollerClock interface {
	Now() time.Time
	NewTimer(d time.Duration) pollerTimer
}

// pollerTimer mirrors the slice of [*time.Timer] the [Poller] uses:
// a fire channel and a stop. The interface keeps the production path
// using [time.NewTimer] verbatim while tests can substitute an
// instant-fire timer that records the requested duration.
type pollerTimer interface {
	C() <-chan time.Time
	Stop() bool
}

// realClock is the production [pollerClock] implementation backed by
// the standard library.
type realClock struct{}

func (realClock) Now() time.Time { return time.Now() }
func (realClock) NewTimer(d time.Duration) pollerTimer {
	return &stdTimer{t: time.NewTimer(d)}
}

// stdTimer wraps a [*time.Timer] so it satisfies [pollerTimer].
type stdTimer struct{ t *time.Timer }

func (s *stdTimer) C() <-chan time.Time { return s.t.C }
func (s *stdTimer) Stop() bool          { return s.t.Stop() }

// Poller implements the Receiver side of the RFC 8936 poll-delivery
// profile. A configured Poller POSTs to a Transmitter's poll endpoint
// in a loop, verifies each returned Security Event Token via the
// caller-supplied [ssf.SETVerifier], hands the verified payload to
// the [Sink], and acknowledges successfully-consumed JTIs on the next
// poll. Failures are reported back through the same request's
// setErrs map per RFC 8936 §2.3.
//
// Poller is constructed by [NewPoller] and driven by [Poller.Run].
// The zero value is not usable; callers MUST go through the
// constructor so the cadence and parallelism defaults are populated.
//
// A Poller is safe to use from one goroutine — Run is intended to be
// the only caller. Concurrent calls to Run on the same Poller are not
// supported.
type Poller struct {
	pollEndpoint string
	authzHeader  string
	httpClient   *http.Client
	verifier     ssf.SETVerifier
	sink         Sink

	maxEvents       int
	noEventsBackoff backoff
	errorBackoff    backoff
	parallelism     int

	clock pollerClock
}

// PollerOption configures a [Poller]. The functional-options pattern
// keeps the [NewPoller] signature stable while leaving room for new
// tunables.
type PollerOption func(*Poller)

// WithHTTPClient overrides the [*http.Client] used for poll requests.
// The default is [http.DefaultClient]; callers replace it to inject
// custom transports (mTLS, OAuth bearer-token refresh, instrumented
// round-trippers).
func WithHTTPClient(c *http.Client) PollerOption {
	return func(p *Poller) {
		if c != nil {
			p.httpClient = c
		}
	}
}

// WithAuthorizationHeader sets the verbatim Authorization header on
// every poll request. The value is sent as-is; the library does not
// prepend "Bearer " or otherwise interpret the string. Pass the
// empty string to leave Authorization unset (the default).
func WithAuthorizationHeader(h string) PollerOption {
	return func(p *Poller) {
		p.authzHeader = h
	}
}

// WithMaxEvents caps the maxEvents field of each [ssf.PollRequest].
// The Transmitter is free to return fewer SETs than requested and
// MAY ignore the cap entirely per RFC 8936 §2.4.1; the field is a
// request, not a contract. Values ≤ 0 fall back to the default of
// 100.
func WithMaxEvents(n int) PollerOption {
	return func(p *Poller) {
		if n > 0 {
			p.maxEvents = n
		}
	}
}

// WithNoEventsBackoff overrides the exponential backoff applied when
// a poll returns no SETs (and moreAvailable is not set). The initial
// duration is used on the first empty poll; each subsequent empty
// poll doubles up to max. The backoff resets to initial on the first
// non-empty response.
//
// Both arguments MUST be > 0; non-positive values are silently
// ignored, leaving the field at its default.
func WithNoEventsBackoff(initial, maximum time.Duration) PollerOption {
	return func(p *Poller) {
		if initial > 0 && maximum >= initial {
			p.noEventsBackoff = backoff{initial: initial, max: maximum, current: initial}
		}
	}
}

// WithErrorBackoff overrides the exponential backoff applied when a
// poll round fails (network error, 5xx, malformed response). The
// backoff doubles on each consecutive failure up to max, with ±20%
// jitter applied to the computed sleep, and resets to initial on the
// first successful round.
//
// Both arguments MUST be > 0; non-positive values are silently
// ignored, leaving the field at its default.
func WithErrorBackoff(initial, maximum time.Duration) PollerOption {
	return func(p *Poller) {
		if initial > 0 && maximum >= initial {
			p.errorBackoff = backoff{initial: initial, max: maximum, current: initial, jitterPct: defaultErrorBackoffJitterPct}
		}
	}
}

// WithParallelDelivery configures the [Poller] to dispatch each
// poll's SETs to N goroutines in parallel rather than serially.
//
// Parallel delivery drops the only ordering guarantee RFC 8936
// makes about poll-mode: with the default serial dispatch
// (parallelism = 1), the Sink sees SETs in the order the
// Transmitter returned them, and the acks the next poll sends back
// preserve that order. With parallelism > 1, multiple workers
// consume the batch concurrently and Acks land in completion order,
// not poll order. THIS IS AN OPT-IN ORDERING LOSS; callers should
// use this only when their Sink is order-independent (typically
// idempotent on jti, with downstream deduplication) and the
// throughput win justifies the loss.
//
// Values ≤ 1 fall back to serial delivery.
func WithParallelDelivery(n int) PollerOption {
	return func(p *Poller) {
		if n > 1 {
			p.parallelism = n
		}
	}
}

// NewPoller returns a [Poller] configured for the given Transmitter
// poll endpoint, SET verifier, and Sink. The pollEndpoint MUST be the
// full absolute URL the Transmitter advertises for poll-mode
// delivery (RFC 8936 §2.4); this phase of the library does not
// perform well-known configuration discovery, so the caller resolves
// the URL out-of-band.
//
// Defaults: HTTP via [http.DefaultClient], maxEvents = 100, no
// authorization header, no-events backoff 1s → 5m doubling, error
// backoff 1s → 1h doubling with ±20% jitter, serial delivery
// (parallelism = 1, the RFC 8936 ordering preserve).
//
// The verifier and sink MUST be non-nil. NewPoller does not validate
// pollEndpoint as a URL — a malformed URL surfaces on the first
// [Poller.Run] iteration.
func NewPoller(pollEndpoint string, verifier ssf.SETVerifier, sink Sink, opts ...PollerOption) *Poller {
	p := &Poller{
		pollEndpoint: pollEndpoint,
		httpClient:   http.DefaultClient,
		verifier:     verifier,
		sink:         sink,
		maxEvents:    defaultMaxEvents,
		noEventsBackoff: backoff{
			initial: defaultNoEventsBackoffMin,
			max:     defaultNoEventsBackoffMax,
			current: defaultNoEventsBackoffMin,
		},
		errorBackoff: backoff{
			initial:   defaultErrorBackoffMin,
			max:       defaultErrorBackoffMax,
			current:   defaultErrorBackoffMin,
			jitterPct: defaultErrorBackoffJitterPct,
		},
		parallelism: defaultParallelism,
		clock:       realClock{},
	}
	for _, opt := range opts {
		opt(p)
	}
	return p
}

// pollOutcome captures the result of a single poll iteration so the
// Run loop can compute cadence without scattering the state across
// the function body.
type pollOutcome struct {
	// ack is the JTIs to acknowledge in the next poll request.
	ack []string
	// setErrs is the per-JTI failures to report in the next poll.
	setErrs map[string]ssf.SetErr
	// deliveredCount is how many SETs reached the Sink successfully;
	// used only for diagnostics, the cadence decision is driven by
	// whether the response was empty.
	deliveredCount int
	// empty reports whether the poll returned zero SETs.
	empty bool
	// moreAvailable mirrors the Transmitter's hint that more SETs
	// are queued; when true the loop polls immediately.
	moreAvailable bool
	// retryAfter, when non-zero, overrides the error backoff for the
	// next sleep. Set on 429/503 with a Retry-After header.
	retryAfter time.Duration
}

// Run drives the poll loop until ctx is cancelled or a non-recoverable
// error occurs. Each iteration:
//
//  1. Builds an [ssf.PollRequest] carrying the previous iteration's
//     ack and setErrs (empty on the first iteration) and posts it
//     to the configured pollEndpoint.
//  2. On a 2xx response, decodes the body as an [ssf.PollResponse]
//     and processes each returned SET: verifier.Verify → on
//     verifier failure record setErrs[invalid_set] and skip the
//     Sink; on Verify success call sink.DeliverSET; on a Sink
//     error wrapping [ErrPermanent] record setErrs[delivery_failed]
//     AND ack the JTI (the transport considers this terminal); on
//     a transient Sink error record setErrs[delivery_failed]
//     WITHOUT acking (the Transmitter will replay).
//  3. Sleeps according to the cadence rule that applies:
//     moreAvailable=true → poll immediately, no sleep; response
//     empty → noEventsBackoff doubling per consecutive empty;
//     network/5xx → errorBackoff doubling with jitter per
//     consecutive failure; Retry-After header on 429/503 → honor
//     that delta over the computed backoff.
//
// Run returns ctx.Err() on cancellation (including cancellation
// mid-sleep or mid-request) and a wrapped error on other terminal
// failures. Transient errors (network blips, 5xx) DO NOT terminate
// Run; the loop continues with the error backoff applied.
//
// ORDERING NOTE: with the default [WithParallelDelivery] setting of
// 1, the Sink sees SETs in the order the Transmitter returned them
// and the Ack array for the next poll reflects that order. When the
// caller has opted into parallel delivery via [WithParallelDelivery]
// with n > 1, neither guarantee holds; the Sink is invoked from N
// goroutines concurrently and the Ack/SetErrs entries land in
// completion order. RFC 8936 §2.4 makes no ordering claim across
// polls; the in-poll ordering preservation is a library convention
// that callers can trade for throughput at their discretion.
func (p *Poller) Run(ctx context.Context) error {
	var nextAck []string
	var nextSetErrs map[string]ssf.SetErr

	for {
		if err := ctx.Err(); err != nil {
			return err
		}

		outcome, err := p.pollOnce(ctx, nextAck, nextSetErrs)
		if err != nil {
			if ctx.Err() != nil {
				return ctx.Err()
			}
			// Transient: log via slept backoff and keep going. The
			// public surface (Run's return value) is reserved for
			// ctx cancellation and permanent terminal failures —
			// the latter category currently has no members; every
			// failure short of ctx cancellation is treated as a
			// retry candidate.
			//
			// A 429/503 response that carried a Retry-After header
			// surfaces here with err != nil and outcome.retryAfter
			// populated; honor that hint when present, since the
			// Transmitter has told us exactly how long to wait.
			sleep := outcome.retryAfter
			if sleep <= 0 {
				sleep = p.errorBackoff.Next()
			}
			if err := p.sleep(ctx, sleep); err != nil {
				return err
			}
			// Carry the previous ack/setErrs forward; we did not
			// successfully POST them, so the Transmitter still
			// owes us those SETs.
			continue
		}

		p.errorBackoff.Reset()

		nextAck = outcome.ack
		nextSetErrs = outcome.setErrs

		switch {
		case outcome.retryAfter > 0:
			if err := p.sleep(ctx, outcome.retryAfter); err != nil {
				return err
			}
		case outcome.moreAvailable:
			// Poll immediately. Reset the empty-backoff state since
			// the Transmitter is signalling work is queued.
			p.noEventsBackoff.Reset()
		case outcome.empty:
			sleep := p.noEventsBackoff.Next()
			if err := p.sleep(ctx, sleep); err != nil {
				return err
			}
		default:
			// Non-empty, no moreAvailable hint: poll again
			// immediately; the Transmitter implicitly tells us
			// there is more work by not setting moreAvailable but
			// returning a full batch. RFC 8936 §2.4 leaves this
			// case implementation-defined; polling immediately
			// matches the spirit of moreAvailable for
			// Transmitters that don't set it.
			p.noEventsBackoff.Reset()
		}
	}
}

// pollOnce performs one round-trip against the poll endpoint and
// drives the resulting SETs through the verifier and Sink. It
// returns the ack/setErrs the next iteration should send, along
// with the cadence-relevant flags.
func (p *Poller) pollOnce(ctx context.Context, ack []string, setErrs map[string]ssf.SetErr) (pollOutcome, error) {
	req, err := p.buildRequest(ctx, ack, setErrs)
	if err != nil {
		return pollOutcome{}, fmt.Errorf("build poll request: %w", err)
	}

	resp, err := p.httpClient.Do(req)
	if err != nil {
		return pollOutcome{}, fmt.Errorf("poll request: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode == http.StatusTooManyRequests || resp.StatusCode == http.StatusServiceUnavailable {
		// Drain so the connection can be reused.
		_, _ = io.Copy(io.Discard, resp.Body)
		retryAfter := parseRetryAfter(resp.Header.Get("Retry-After"), p.clock.Now())
		return pollOutcome{
			ack:        ack,
			setErrs:    setErrs,
			empty:      true,
			retryAfter: retryAfter,
		}, fmt.Errorf("poll endpoint returned %d", resp.StatusCode)
	}

	if resp.StatusCode/100 != 2 {
		_, _ = io.Copy(io.Discard, resp.Body)
		return pollOutcome{}, fmt.Errorf("poll endpoint returned %d", resp.StatusCode)
	}

	var pr ssf.PollResponse
	if err := json.NewDecoder(resp.Body).Decode(&pr); err != nil {
		return pollOutcome{}, fmt.Errorf("decode poll response: %w", err)
	}

	return p.process(ctx, pr), nil
}

// buildRequest assembles the [*http.Request] for one poll. The body
// is the JSON of an [ssf.PollRequest] carrying the previous round's
// ack and setErrs. The Authorization header is set only when a
// non-empty value was configured.
func (p *Poller) buildRequest(ctx context.Context, ack []string, setErrs map[string]ssf.SetErr) (*http.Request, error) {
	maxEvents := p.maxEvents
	body := ssf.PollRequest{
		Ack:       ack,
		SetErrs:   setErrs,
		MaxEvents: &maxEvents,
	}
	payload, err := json.Marshal(body)
	if err != nil {
		return nil, fmt.Errorf("marshal poll request: %w", err)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, p.pollEndpoint, bytes.NewReader(payload))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", pollMediaType)
	req.Header.Set("Accept", pollMediaType)
	if p.authzHeader != "" {
		req.Header.Set("Authorization", p.authzHeader)
	}
	return req, nil
}

// process runs each SET in the poll response through the verifier
// and Sink, collecting the ack and setErrs for the next round. The
// dispatch shape is serial when parallelism == 1 (the default,
// preserving RFC 8936 §2.4 poll-order = ack-order) and a bounded
// worker pool otherwise.
func (p *Poller) process(ctx context.Context, pr ssf.PollResponse) pollOutcome {
	moreAvailable := pr.MoreAvailable != nil && *pr.MoreAvailable
	outcome := pollOutcome{
		empty:         len(pr.Sets) == 0,
		moreAvailable: moreAvailable,
	}
	if len(pr.Sets) == 0 {
		return outcome
	}

	// Stable order materialization: the spec returns sets as a JSON
	// object so the on-the-wire order is not preserved by
	// json.Unmarshal into a map. We build a slice once and dispatch
	// from it; serial mode preserves this slice order in the ack,
	// which matches the property RFC 8936 §2.4 calls out (poll order
	// = ack order) for any Transmitter that emits a deterministic
	// JSON order. Parallel mode drops this guarantee — see Run's
	// godoc.
	type setEntry struct {
		jti string
		jws string
	}
	entries := make([]setEntry, 0, len(pr.Sets))
	for jti, jws := range pr.Sets {
		entries = append(entries, setEntry{jti: jti, jws: jws})
	}

	if p.parallelism <= 1 {
		ack := make([]string, 0, len(entries))
		var setErrs map[string]ssf.SetErr
		for _, e := range entries {
			ackJTI, errCode, errDesc := p.deliverOne(ctx, e.jws)
			if ackJTI {
				ack = append(ack, e.jti)
			}
			if errCode != "" {
				if setErrs == nil {
					setErrs = make(map[string]ssf.SetErr)
				}
				setErrs[e.jti] = ssf.SetErr{Err: errCode, Description: errDesc}
			}
		}
		outcome.ack = ack
		outcome.setErrs = setErrs
		outcome.deliveredCount = len(ack)
		return outcome
	}

	// Parallel dispatch. Each worker reads from the entries channel
	// and writes results back through a shared mutex-protected
	// accumulator. The pool is bounded by p.parallelism; for small
	// batches the worker count is capped by len(entries) to avoid
	// spawning idle goroutines.
	workers := p.parallelism
	if workers > len(entries) {
		workers = len(entries)
	}
	jobs := make(chan setEntry)
	var mu sync.Mutex
	var ack []string
	var setErrs map[string]ssf.SetErr

	var wg sync.WaitGroup
	for range workers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for e := range jobs {
				ackJTI, errCode, errDesc := p.deliverOne(ctx, e.jws)
				mu.Lock()
				if ackJTI {
					ack = append(ack, e.jti)
				}
				if errCode != "" {
					if setErrs == nil {
						setErrs = make(map[string]ssf.SetErr)
					}
					setErrs[e.jti] = ssf.SetErr{Err: errCode, Description: errDesc}
				}
				mu.Unlock()
			}
		}()
	}
	for _, e := range entries {
		jobs <- e
	}
	close(jobs)
	wg.Wait()

	outcome.ack = ack
	outcome.setErrs = setErrs
	outcome.deliveredCount = len(ack)
	return outcome
}

// deliverOne verifies a single JWS and, on success, hands the
// payload to the Sink. It returns:
//
//   - ackJTI: whether the next poll should ack this JTI (true on
//     Sink success or permanent failure; false on verifier failure
//     or transient Sink failure).
//   - errCode: the SET-delivery error code to record for this JTI
//     in the next poll's setErrs (empty when the SET was delivered
//     cleanly).
//   - errDesc: the human-readable description paired with errCode.
func (p *Poller) deliverOne(ctx context.Context, jwsCompact string) (ackJTI bool, errCode, errDesc string) {
	payload, err := p.verifier.Verify(jwsCompact)
	if err != nil {
		// Verifier rejected the JWS. The spec lets us either ack the
		// JTI (we've "consumed" it in that we will never accept it)
		// or skip the ack and rely on setErrs to inform the
		// Transmitter. The library chooses NOT to ack so the
		// Transmitter retains the SET for operator inspection; the
		// setErrs entry tells it not to expect delivery success.
		return false, setErrInvalidSET, err.Error()
	}
	if err := p.sink.DeliverSET(ctx, payload); err != nil {
		if errors.Is(err, ErrPermanent) {
			// Permanent: ack so the Transmitter stops retrying, AND
			// surface the failure via setErrs for diagnostics.
			return true, setErrDeliveryFailure, err.Error()
		}
		// Transient: don't ack; the Transmitter will replay.
		return false, setErrDeliveryFailure, err.Error()
	}
	return true, "", ""
}

// sleep blocks for d or until ctx is cancelled, whichever is first.
// A non-positive d returns immediately without consulting the timer.
func (p *Poller) sleep(ctx context.Context, d time.Duration) error {
	if d <= 0 {
		return ctx.Err()
	}
	timer := p.clock.NewTimer(d)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C():
		return nil
	}
}

// backoff is the exponentially-increasing sleep helper shared by the
// no-events and error cadence paths. jitterPct, when non-zero,
// applies a uniform ±jitterPct multiplicative jitter to each Next()
// result so concurrent Pollers do not synchronize on the same retry
// instants.
type backoff struct {
	initial   time.Duration
	max       time.Duration
	current   time.Duration
	jitterPct float64
}

// Next returns the next sleep duration, doubling the current backoff
// (capped at max) and applying jitter if configured. Successive
// calls grow the backoff; [backoff.Reset] returns it to initial.
func (b *backoff) Next() time.Duration {
	d := b.current
	// Compute the next stored value (doubled, capped) for the call
	// after this one. We return the pre-doubling value so the
	// first Next() returns initial, the second returns 2×initial,
	// and so on.
	next := b.current * 2
	if next > b.max || next < b.current { // overflow guard
		next = b.max
	}
	b.current = next

	if b.jitterPct > 0 {
		// Uniform jitter in [1-pct, 1+pct]. rand/v2 is unseeded by
		// design — every process picks an independent stream so
		// concurrent Pollers desynchronize.
		factor := 1 + (rand.Float64()*2-1)*b.jitterPct
		d = time.Duration(float64(d) * factor)
		if d < 0 {
			d = 0
		}
	}
	return d
}

// Reset returns the backoff to its initial duration. Called after a
// successful poll round so a single recovery normalizes the cadence.
func (b *backoff) Reset() {
	b.current = b.initial
}

// parseRetryAfter parses an HTTP Retry-After header value per
// RFC 9110 §10.2.3 — either a delta-seconds integer ("5") or an
// HTTP-date ("Wed, 21 Oct 2026 07:28:00 GMT"). Returns 0 on parse
// failure; the caller treats 0 as "no Retry-After override" and
// falls back to its normal backoff. now is the reference timestamp
// for the HTTP-date branch.
func parseRetryAfter(header string, now time.Time) time.Duration {
	if header == "" {
		return 0
	}
	if secs, err := strconv.Atoi(header); err == nil {
		if secs < 0 {
			return 0
		}
		return time.Duration(secs) * time.Second
	}
	if t, err := http.ParseTime(header); err == nil {
		d := t.Sub(now)
		if d < 0 {
			return 0
		}
		return d
	}
	return 0
}
