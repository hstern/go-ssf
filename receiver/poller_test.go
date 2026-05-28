// Copyright 2026 The go-ssf Authors
// SPDX-License-Identifier: Apache-2.0

package receiver_test

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/hstern/go-ssf"
	"github.com/hstern/go-ssf/receiver"
)

// pollHelper packages a test server that scripts a sequence of
// PollResponse bodies and records every PollRequest the Poller
// sends. Each call to ServeHTTP advances the script by one step;
// when the script is exhausted the server replies with an empty
// response so the Poller can be allowed to idle until ctx is
// cancelled.
type pollHelper struct {
	mu        sync.Mutex
	requests  []ssf.PollRequest
	responses []pollScripted
	pollTimes []time.Time
	t         *testing.T
}

// pollScripted is one entry of the response script. body is the
// JSON returned for that step; statusCode defaults to 200 when 0;
// retryAfter, when non-empty, is set as a Retry-After header.
type pollScripted struct {
	body       ssf.PollResponse
	statusCode int
	retryAfter string
}

func newPollHelper(t *testing.T) *pollHelper {
	return &pollHelper{t: t}
}

// queue appends a 200-OK response to the script.
func (h *pollHelper) queue(resp ssf.PollResponse) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.responses = append(h.responses, pollScripted{body: resp})
}

// queueStatus appends a response with a non-200 status. The body is
// the JSON of resp; for status codes where the body is ignored by
// the Poller the resp argument can be zero.
func (h *pollHelper) queueStatus(status int, resp ssf.PollResponse, retryAfter string) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.responses = append(h.responses, pollScripted{body: resp, statusCode: status, retryAfter: retryAfter})
}

// recordedRequest returns the i-th poll request the helper saw, or
// nil if the index is out of range.
func (h *pollHelper) recordedRequest(i int) *ssf.PollRequest {
	h.mu.Lock()
	defer h.mu.Unlock()
	if i < 0 || i >= len(h.requests) {
		return nil
	}
	r := h.requests[i]
	return &r
}

// requestCount returns the number of polls observed.
func (h *pollHelper) requestCount() int {
	h.mu.Lock()
	defer h.mu.Unlock()
	return len(h.requests)
}

func (h *pollHelper) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	body, err := io.ReadAll(r.Body)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	var req ssf.PollRequest
	if err := json.Unmarshal(body, &req); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	h.mu.Lock()
	h.requests = append(h.requests, req)
	h.pollTimes = append(h.pollTimes, time.Now())
	var step pollScripted
	if len(h.responses) > 0 {
		step = h.responses[0]
		h.responses = h.responses[1:]
	} else {
		step = pollScripted{body: ssf.PollResponse{Sets: map[string]string{}}}
	}
	h.mu.Unlock()

	if step.retryAfter != "" {
		w.Header().Set("Retry-After", step.retryAfter)
	}
	if step.statusCode != 0 && step.statusCode/100 != 2 {
		w.WriteHeader(step.statusCode)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	if step.statusCode != 0 {
		w.WriteHeader(step.statusCode)
	}
	out, _ := json.Marshal(step.body)
	_, _ = w.Write(out)
}

// mintSET signs samplePayload (or a per-test variant) and returns
// the compact JWS plus the matching verifier.
func mintSET(t *testing.T, payload []byte) (jws string, verifier *ssf.JOSESetVerifier) {
	t.Helper()
	jws, key := signSET(t, payload)
	return jws, verifierForKey(key)
}

// TestPollerHappyPath verifies that a normal poll round verifies
// each returned SET, hands the payload to the Sink, and reports the
// jtis in the next poll's ack array in the same order.
func TestPollerHappyPath(t *testing.T) {
	t.Parallel()

	// All three SETs share one key so a single verifier accepts the
	// whole batch.
	sharedKey := hs256Key(t)
	jws1 := mintWithKey(t, []byte(samplePayload), sharedKey)
	jws2 := mintWithKey(t, []byte(samplePayload), sharedKey)
	jws3 := mintWithKey(t, []byte(samplePayload), sharedKey)
	verifier := verifierForKey(sharedKey)

	helper := newPollHelper(t)
	helper.queue(ssf.PollResponse{Sets: map[string]string{
		"jti-1": jws1,
		"jti-2": jws2,
		"jti-3": jws3,
	}})
	helper.queue(ssf.PollResponse{Sets: map[string]string{}})

	srv := httptest.NewServer(helper)
	t.Cleanup(srv.Close)

	var delivered atomic.Int32
	sink := receiver.SinkFunc(func(_ context.Context, payload []byte) error {
		if string(payload) != samplePayload {
			t.Errorf("sink received %q, want %q", payload, samplePayload)
		}
		delivered.Add(1)
		return nil
	})

	p := receiver.NewPoller(srv.URL, verifier, sink,
		receiver.WithNoEventsBackoff(50*time.Millisecond, 50*time.Millisecond),
	)
	runPollerUntil(t, p, func() bool {
		return helper.requestCount() >= 2 && delivered.Load() >= 3
	})

	if got := delivered.Load(); got != 3 {
		t.Fatalf("delivered = %d, want 3", got)
	}
	// The second request should carry an ack of all three jtis.
	req := helper.recordedRequest(1)
	if req == nil {
		t.Fatalf("expected a second poll request")
	}
	if len(req.Ack) != 3 {
		t.Fatalf("second poll ack = %v, want 3 entries", req.Ack)
	}
	want := map[string]bool{"jti-1": true, "jti-2": true, "jti-3": true}
	for _, jti := range req.Ack {
		if !want[jti] {
			t.Errorf("unexpected ack jti %q", jti)
		}
		delete(want, jti)
	}
	if len(want) != 0 {
		t.Errorf("missing ack jtis: %v", want)
	}
}

// TestPollerEmptyResponseApplesBackoff verifies that an empty poll
// response triggers a noEventsBackoff sleep. We set a short backoff
// and ensure the second poll arrives no sooner than that delay.
func TestPollerEmptyResponseAppliesBackoff(t *testing.T) {
	t.Parallel()

	_, verifier := mintSET(t, []byte(samplePayload))

	helper := newPollHelper(t)
	helper.queue(ssf.PollResponse{Sets: map[string]string{}})
	helper.queue(ssf.PollResponse{Sets: map[string]string{}})

	srv := httptest.NewServer(helper)
	t.Cleanup(srv.Close)

	sink := receiver.SinkFunc(func(_ context.Context, _ []byte) error { return nil })

	const backoffDur = 100 * time.Millisecond
	p := receiver.NewPoller(srv.URL, verifier, sink,
		receiver.WithNoEventsBackoff(backoffDur, backoffDur),
	)
	runPollerUntil(t, p, func() bool { return helper.requestCount() >= 2 })

	if helper.requestCount() < 2 {
		t.Fatalf("requestCount = %d, want >= 2", helper.requestCount())
	}
	helper.mu.Lock()
	elapsed := helper.pollTimes[1].Sub(helper.pollTimes[0])
	helper.mu.Unlock()
	// Allow a small fudge below the configured backoff so timing
	// jitter doesn't flake the test, but assert the bulk of the
	// sleep happened.
	if elapsed < backoffDur/2 {
		t.Errorf("elapsed between empty polls = %v, want ≥ %v", elapsed, backoffDur/2)
	}
}

// TestPollerMoreAvailablePollsImmediately verifies that when the
// response sets moreAvailable=true the Poller does NOT apply the
// no-events backoff between polls.
func TestPollerMoreAvailablePollsImmediately(t *testing.T) {
	t.Parallel()

	jws, verifier := mintSET(t, []byte(samplePayload))
	more := true

	helper := newPollHelper(t)
	helper.queue(ssf.PollResponse{
		Sets:          map[string]string{"jti-1": jws},
		MoreAvailable: &more,
	})
	helper.queue(ssf.PollResponse{Sets: map[string]string{}})

	srv := httptest.NewServer(helper)
	t.Cleanup(srv.Close)

	sink := receiver.SinkFunc(func(_ context.Context, _ []byte) error { return nil })

	// Long no-events backoff so an immediate second poll is
	// unambiguously the moreAvailable path, not the cadence
	// firing.
	p := receiver.NewPoller(srv.URL, verifier, sink,
		receiver.WithNoEventsBackoff(10*time.Second, 10*time.Second),
	)
	runPollerUntil(t, p, func() bool { return helper.requestCount() >= 2 })

	helper.mu.Lock()
	elapsed := helper.pollTimes[1].Sub(helper.pollTimes[0])
	helper.mu.Unlock()
	if elapsed > 500*time.Millisecond {
		t.Errorf("elapsed between moreAvailable polls = %v, want < 500ms", elapsed)
	}
}

// TestPollerVerifierFailureReportedAsSetErr verifies that a SET
// whose JWS does not verify is NOT delivered to the Sink and is
// surfaced in the next poll's setErrs as "invalid_set". The jti is
// not acked.
func TestPollerVerifierFailureReportedAsSetErr(t *testing.T) {
	t.Parallel()

	// Sign with one key, verify with a different key — guaranteed
	// signature mismatch.
	signedKey := hs256Key(t)
	jws := mintWithKey(t, []byte(samplePayload), signedKey)
	otherKey := hs256Key(t)
	verifier := verifierForKey(otherKey)

	helper := newPollHelper(t)
	helper.queue(ssf.PollResponse{Sets: map[string]string{"jti-bad": jws}})
	helper.queue(ssf.PollResponse{Sets: map[string]string{}})

	srv := httptest.NewServer(helper)
	t.Cleanup(srv.Close)

	sinkCalled := atomic.Bool{}
	sink := receiver.SinkFunc(func(_ context.Context, _ []byte) error {
		sinkCalled.Store(true)
		return nil
	})

	p := receiver.NewPoller(srv.URL, verifier, sink,
		receiver.WithNoEventsBackoff(50*time.Millisecond, 50*time.Millisecond),
	)
	runPollerUntil(t, p, func() bool { return helper.requestCount() >= 2 })

	if sinkCalled.Load() {
		t.Errorf("sink should not be called for a verifier failure")
	}
	req := helper.recordedRequest(1)
	if req == nil {
		t.Fatalf("expected second poll request")
	}
	if len(req.Ack) != 0 {
		t.Errorf("ack on verifier failure = %v, want none", req.Ack)
	}
	se, ok := req.SetErrs["jti-bad"]
	if !ok {
		t.Fatalf("setErrs missing jti-bad: %#v", req.SetErrs)
	}
	if se.Err != "invalid_set" {
		t.Errorf("setErrs[jti-bad].err = %q, want %q", se.Err, "invalid_set")
	}
	if se.Description == "" {
		t.Errorf("setErrs[jti-bad].description should be non-empty")
	}
}

// TestPollerSinkTransientFailureDoesNotAck verifies that when the
// Sink returns a plain error (no ErrPermanent wrap), the jti is NOT
// included in the next poll's ack and IS surfaced via setErrs.
func TestPollerSinkTransientFailureDoesNotAck(t *testing.T) {
	t.Parallel()

	jws, verifier := mintSET(t, []byte(samplePayload))

	helper := newPollHelper(t)
	helper.queue(ssf.PollResponse{Sets: map[string]string{"jti-x": jws}})
	helper.queue(ssf.PollResponse{Sets: map[string]string{}})

	srv := httptest.NewServer(helper)
	t.Cleanup(srv.Close)

	sink := receiver.SinkFunc(func(_ context.Context, _ []byte) error {
		return errors.New("downstream offline")
	})

	p := receiver.NewPoller(srv.URL, verifier, sink,
		receiver.WithNoEventsBackoff(50*time.Millisecond, 50*time.Millisecond),
	)
	runPollerUntil(t, p, func() bool { return helper.requestCount() >= 2 })

	req := helper.recordedRequest(1)
	if req == nil {
		t.Fatalf("expected second poll request")
	}
	if len(req.Ack) != 0 {
		t.Errorf("ack on transient sink failure = %v, want none", req.Ack)
	}
	se, ok := req.SetErrs["jti-x"]
	if !ok {
		t.Fatalf("setErrs missing jti-x: %#v", req.SetErrs)
	}
	if se.Err != "delivery_failed" {
		t.Errorf("setErrs[jti-x].err = %q, want %q", se.Err, "delivery_failed")
	}
}

// TestPollerSinkPermanentFailureAcksWithSetErr verifies that when
// the Sink returns an error wrapping ErrPermanent the jti IS acked
// (the Transmitter must stop retrying) AND surfaced via setErrs.
func TestPollerSinkPermanentFailureAcksWithSetErr(t *testing.T) {
	t.Parallel()

	jws, verifier := mintSET(t, []byte(samplePayload))

	helper := newPollHelper(t)
	helper.queue(ssf.PollResponse{Sets: map[string]string{"jti-perm": jws}})
	helper.queue(ssf.PollResponse{Sets: map[string]string{}})

	srv := httptest.NewServer(helper)
	t.Cleanup(srv.Close)

	sink := receiver.SinkFunc(func(_ context.Context, _ []byte) error {
		return fmt.Errorf("unsupported event type: %w", receiver.ErrPermanent)
	})

	p := receiver.NewPoller(srv.URL, verifier, sink,
		receiver.WithNoEventsBackoff(50*time.Millisecond, 50*time.Millisecond),
	)
	runPollerUntil(t, p, func() bool { return helper.requestCount() >= 2 })

	req := helper.recordedRequest(1)
	if req == nil {
		t.Fatalf("expected second poll request")
	}
	if len(req.Ack) != 1 || req.Ack[0] != "jti-perm" {
		t.Errorf("ack on permanent sink failure = %v, want [jti-perm]", req.Ack)
	}
	se, ok := req.SetErrs["jti-perm"]
	if !ok {
		t.Fatalf("setErrs missing jti-perm: %#v", req.SetErrs)
	}
	if se.Err != "delivery_failed" {
		t.Errorf("setErrs[jti-perm].err = %q, want %q", se.Err, "delivery_failed")
	}
}

// TestPollerParallelDelivery verifies that WithParallelDelivery
// dispatches Sink calls from multiple goroutines. We block each
// Sink call on a barrier the test releases once all workers are in;
// this would deadlock under serial dispatch but completes under
// N≥4 parallel workers.
func TestPollerParallelDelivery(t *testing.T) {
	t.Parallel()

	sharedKey := hs256Key(t)
	verifier := verifierForKey(sharedKey)
	sets := map[string]string{}
	const n = 4
	for i := 0; i < n; i++ {
		sets[fmt.Sprintf("jti-%d", i)] = mintWithKey(t, []byte(samplePayload), sharedKey)
	}

	helper := newPollHelper(t)
	helper.queue(ssf.PollResponse{Sets: sets})
	helper.queue(ssf.PollResponse{Sets: map[string]string{}})

	srv := httptest.NewServer(helper)
	t.Cleanup(srv.Close)

	var wg sync.WaitGroup
	wg.Add(n)
	release := make(chan struct{})
	var concurrent atomic.Int32
	var maxConcurrent atomic.Int32

	sink := receiver.SinkFunc(func(ctx context.Context, _ []byte) error {
		c := concurrent.Add(1)
		for {
			m := maxConcurrent.Load()
			if c <= m {
				break
			}
			if maxConcurrent.CompareAndSwap(m, c) {
				break
			}
		}
		wg.Done()
		select {
		case <-release:
		case <-ctx.Done():
			return ctx.Err()
		}
		concurrent.Add(-1)
		return nil
	})

	p := receiver.NewPoller(srv.URL, verifier, sink,
		receiver.WithParallelDelivery(n),
		receiver.WithNoEventsBackoff(50*time.Millisecond, 50*time.Millisecond),
	)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- p.Run(ctx) }()

	wg.Wait()
	close(release)

	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if helper.requestCount() >= 2 {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	cancel()
	<-done

	if got := maxConcurrent.Load(); got < 2 {
		t.Errorf("max concurrent sink invocations = %d, want ≥ 2", got)
	}
}

// TestPollerContextCancellationReturnsQuickly verifies that
// cancelling the context mid-sleep returns from Run with
// context.Canceled in a timely fashion.
func TestPollerContextCancellationReturnsQuickly(t *testing.T) {
	t.Parallel()

	_, verifier := mintSET(t, []byte(samplePayload))

	helper := newPollHelper(t)
	helper.queue(ssf.PollResponse{Sets: map[string]string{}})

	srv := httptest.NewServer(helper)
	t.Cleanup(srv.Close)

	sink := receiver.SinkFunc(func(_ context.Context, _ []byte) error { return nil })

	// Long backoff so the Poller will be mid-sleep when ctx is
	// cancelled.
	p := receiver.NewPoller(srv.URL, verifier, sink,
		receiver.WithNoEventsBackoff(1*time.Hour, 1*time.Hour),
	)

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- p.Run(ctx) }()

	// Wait until the first poll has fired (so we know Run is in the
	// sleep arm).
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if helper.requestCount() >= 1 {
			break
		}
		time.Sleep(5 * time.Millisecond)
	}
	cancel()
	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) {
			t.Errorf("Run returned %v, want context.Canceled", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatalf("Run did not return within 2s of cancellation")
	}
}

// TestPollerServerErrorTriggersErrorBackoff verifies that a 503
// response triggers the error-backoff path rather than the
// no-events backoff.
func TestPollerServerErrorTriggersErrorBackoff(t *testing.T) {
	t.Parallel()

	_, verifier := mintSET(t, []byte(samplePayload))

	helper := newPollHelper(t)
	helper.queueStatus(http.StatusServiceUnavailable, ssf.PollResponse{}, "")
	helper.queue(ssf.PollResponse{Sets: map[string]string{}})

	srv := httptest.NewServer(helper)
	t.Cleanup(srv.Close)

	sink := receiver.SinkFunc(func(_ context.Context, _ []byte) error { return nil })

	// no-events backoff is short; error backoff is the longer of
	// the two. If the Poller mistakenly chose the no-events path
	// the second poll would arrive in ~10ms; under error-backoff
	// it should take noticeably longer.
	p := receiver.NewPoller(srv.URL, verifier, sink,
		receiver.WithNoEventsBackoff(10*time.Millisecond, 10*time.Millisecond),
		receiver.WithErrorBackoff(150*time.Millisecond, 150*time.Millisecond),
	)
	runPollerUntil(t, p, func() bool { return helper.requestCount() >= 2 })

	helper.mu.Lock()
	elapsed := helper.pollTimes[1].Sub(helper.pollTimes[0])
	helper.mu.Unlock()
	// Allow generous slack on the lower bound: jitter is ±20%, so
	// the minimum sleep is ~120ms. We assert that it isn't sub-50ms,
	// which would prove the no-events path was taken.
	if elapsed < 60*time.Millisecond {
		t.Errorf("elapsed after 503 = %v, want error-backoff (≥ ~120ms with jitter, asserting ≥ 60ms)", elapsed)
	}
}

// TestPollerRetryAfterHonored verifies that a 429 with
// Retry-After: 1 causes the Poller to sleep at least one second
// before the next poll.
func TestPollerRetryAfterHonored(t *testing.T) {
	t.Parallel()

	_, verifier := mintSET(t, []byte(samplePayload))

	helper := newPollHelper(t)
	helper.queueStatus(http.StatusTooManyRequests, ssf.PollResponse{}, "1")
	helper.queue(ssf.PollResponse{Sets: map[string]string{}})

	srv := httptest.NewServer(helper)
	t.Cleanup(srv.Close)

	sink := receiver.SinkFunc(func(_ context.Context, _ []byte) error { return nil })

	p := receiver.NewPoller(srv.URL, verifier, sink,
		// Tiny backoffs so the Retry-After dominates if honored.
		receiver.WithNoEventsBackoff(10*time.Millisecond, 10*time.Millisecond),
		receiver.WithErrorBackoff(10*time.Millisecond, 10*time.Millisecond),
	)
	runPollerUntil(t, p, func() bool { return helper.requestCount() >= 2 })

	helper.mu.Lock()
	elapsed := helper.pollTimes[1].Sub(helper.pollTimes[0])
	helper.mu.Unlock()
	if elapsed < 800*time.Millisecond {
		t.Errorf("elapsed after Retry-After: 1 = %v, want ≥ 800ms", elapsed)
	}
}

// TestPollerNoEventsBackoffDoubles verifies that repeated empty
// polls double the cadence up to the configured cap.
func TestPollerNoEventsBackoffDoubles(t *testing.T) {
	t.Parallel()

	_, verifier := mintSET(t, []byte(samplePayload))

	helper := newPollHelper(t)
	helper.queue(ssf.PollResponse{Sets: map[string]string{}})
	helper.queue(ssf.PollResponse{Sets: map[string]string{}})
	helper.queue(ssf.PollResponse{Sets: map[string]string{}})
	helper.queue(ssf.PollResponse{Sets: map[string]string{}})

	srv := httptest.NewServer(helper)
	t.Cleanup(srv.Close)

	sink := receiver.SinkFunc(func(_ context.Context, _ []byte) error { return nil })

	const initial = 30 * time.Millisecond
	p := receiver.NewPoller(srv.URL, verifier, sink,
		receiver.WithNoEventsBackoff(initial, 200*time.Millisecond),
	)
	runPollerUntil(t, p, func() bool { return helper.requestCount() >= 4 })

	helper.mu.Lock()
	defer helper.mu.Unlock()
	// gap(i) = pollTimes[i] - pollTimes[i-1]
	// gap(1) ~ initial, gap(2) ~ 2*initial, gap(3) ~ 4*initial
	gap1 := helper.pollTimes[1].Sub(helper.pollTimes[0])
	gap2 := helper.pollTimes[2].Sub(helper.pollTimes[1])
	gap3 := helper.pollTimes[3].Sub(helper.pollTimes[2])

	// The backoff is configured to double each empty poll. Compare each
	// successive gap as a ratio rather than absolute duration so OS
	// scheduler jitter on a loaded test runner does not flip a strict <
	// comparison while the doubling is qualitatively correct. The band
	// [1.5, 3.0] still rejects a regression to constant growth (ratio
	// ~1.0) or linear growth (ratio approaches 1 as gaps grow).
	const minRatio, maxRatio = 1.5, 3.0
	r1 := float64(gap2) / float64(gap1)
	r2 := float64(gap3) / float64(gap2)
	if r1 < minRatio || r1 > maxRatio || r2 < minRatio || r2 > maxRatio {
		t.Errorf("expected doubling backoff (ratios in [%.1f, %.1f]), got gaps %v -> %v -> %v (ratios %.2f, %.2f)",
			minRatio, maxRatio, gap1, gap2, gap3, r1, r2)
	}
}

// --- helpers ----------------------------------------------------------

// mintWithKey signs payload with a caller-supplied key so multiple
// SETs in one test share a verifier.
func mintWithKey(t *testing.T, payload, key []byte) string {
	t.Helper()
	signer, err := ssf.NewJOSESetSigner(newJOSESignerForSET(t, key))
	if err != nil {
		t.Fatalf("NewJOSESetSigner: %v", err)
	}
	jws, err := signer.Sign(payload)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	return jws
}

// runPollerUntil starts the Poller in a goroutine, waits for cond to
// hold (or 5s timeout), cancels the context, and waits for Run to
// return. Test failure happens via t.Fatalf if the condition is not
// met before the deadline.
func runPollerUntil(t *testing.T, p *receiver.Poller, cond func() bool) {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	done := make(chan error, 1)
	go func() { done <- p.Run(ctx) }()

	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if cond() {
			break
		}
		time.Sleep(5 * time.Millisecond)
	}
	if !cond() {
		cancel()
		<-done
		t.Fatalf("condition not satisfied within deadline")
	}
	cancel()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatalf("Poller.Run did not exit after cancel")
	}
}
