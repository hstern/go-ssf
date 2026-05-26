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
	"strconv"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/hstern/go-ssf"
	"github.com/hstern/go-ssf/receiver"
)

// makeVerificationSET builds a minimal verification SET claims-set
// payload — just enough of the spec §7.1.4 SET shape that
// VerificationChallenger.WrapSink's parser can locate the state value.
func makeVerificationSET(t *testing.T, state string) []byte {
	t.Helper()
	payload, err := json.Marshal(map[string]any{
		"iss": "https://transmitter.example.com",
		"aud": "receiver.example.com",
		"jti": "test-jti",
		"iat": 1716422400,
		"events": map[string]any{
			ssf.EventTypeVerification: map[string]any{
				"state": state,
			},
		},
	})
	if err != nil {
		t.Fatalf("marshal verification SET: %v", err)
	}
	return payload
}

// newVerificationServer spins up an httptest server that responds 200
// to POST and records the latest request shape for assertions.
type verificationServer struct {
	*httptest.Server
	mu        sync.Mutex
	lastQuery string
	lastAuth  string
	lastBody  []byte
	hits      atomic.Int32
}

func newVerificationServer(t *testing.T) *verificationServer {
	t.Helper()
	vs := &verificationServer{}
	vs.Server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "POST only", http.StatusMethodNotAllowed)
			return
		}
		body, err := io.ReadAll(r.Body)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		vs.mu.Lock()
		vs.lastQuery = r.URL.RawQuery
		vs.lastAuth = r.Header.Get("Authorization")
		vs.lastBody = body
		vs.mu.Unlock()
		vs.hits.Add(1)
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(vs.Close)
	return vs
}

// TestVerificationChallengerHappyPath exercises the full flow: POST
// reaches the test server, the server emits a matching SET shortly
// after via the wrapped Sink, and Challenge returns the SET payload.
func TestVerificationChallengerHappyPath(t *testing.T) {
	t.Parallel()

	vs := newVerificationServer(t)
	challenger := receiver.NewVerificationChallenger()

	// The wrapped Sink is the path that hands the SET back to the
	// waiter. The test server feeds the wrapped Sink directly via a
	// goroutine to simulate the Transmitter's separate SET delivery.
	wrapped := challenger.WrapSink(receiver.SinkFunc(func(context.Context, []byte) error {
		t.Error("non-verification SET should not have been forwarded")
		return nil
	}))

	const state = "fixed-test-state"
	go func() {
		// Small delay so Challenge has started waiting before the
		// SET arrives — mirrors the spec's "200 then SET" ordering.
		time.Sleep(10 * time.Millisecond)
		if err := wrapped.DeliverSET(context.Background(), makeVerificationSET(t, state)); err != nil {
			t.Errorf("wrapped Sink returned error: %v", err)
		}
	}()

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	payload, err := challenger.Challenge(ctx,
		receiver.WithEndpoint(vs.URL),
		receiver.WithState(state),
	)
	if err != nil {
		t.Fatalf("Challenge: %v", err)
	}
	if len(payload) == 0 {
		t.Fatal("Challenge returned empty payload")
	}

	gotState, ok := readEventState(t, payload)
	if !ok {
		t.Fatal("Challenge payload missing verification event state")
	}
	if gotState != state {
		t.Errorf("payload state = %q, want %q", gotState, state)
	}
	if vs.hits.Load() != 1 {
		t.Errorf("verification endpoint hit %d times, want 1", vs.hits.Load())
	}
}

// TestVerificationChallengerStateMismatchTimesOut feeds a SET with
// a non-matching state value. The Challenge waits out its timeout
// and returns ErrVerificationTimeout.
func TestVerificationChallengerStateMismatchTimesOut(t *testing.T) {
	t.Parallel()

	vs := newVerificationServer(t)
	challenger := receiver.NewVerificationChallenger()

	var forwarded atomic.Int32
	wrapped := challenger.WrapSink(receiver.SinkFunc(func(context.Context, []byte) error {
		forwarded.Add(1)
		return nil
	}))

	go func() {
		time.Sleep(10 * time.Millisecond)
		if err := wrapped.DeliverSET(context.Background(), makeVerificationSET(t, "other-state")); err != nil {
			t.Errorf("wrapped Sink returned error: %v", err)
		}
	}()

	ctx := context.Background()
	_, err := challenger.Challenge(ctx,
		receiver.WithEndpoint(vs.URL),
		receiver.WithState("expected-state"),
		receiver.WithTimeout(75*time.Millisecond),
	)
	if !errors.Is(err, ssf.ErrVerificationTimeout) {
		t.Fatalf("Challenge err = %v, want ErrVerificationTimeout", err)
	}

	// A non-matching verification SET is still a verification SET;
	// the wrapped Sink may forward it. The contract is "not
	// intercepted", not "dropped" — the consumer's Sink decides.
	if got := forwarded.Load(); got != 1 {
		t.Errorf("downstream Sink called %d times, want 1 (forwarded non-matching SET)", got)
	}
}

// TestVerificationChallengerForwardsNonVerificationEvents shows that
// a SET whose events claim does not carry the verification URI is
// forwarded to the downstream Sink unchanged.
func TestVerificationChallengerForwardsNonVerificationEvents(t *testing.T) {
	t.Parallel()

	challenger := receiver.NewVerificationChallenger()

	var got []byte
	wrapped := challenger.WrapSink(receiver.SinkFunc(func(_ context.Context, payload []byte) error {
		got = payload
		return nil
	}))

	nonVerification, err := json.Marshal(map[string]any{
		"iss": "https://transmitter.example.com",
		"events": map[string]any{
			"https://schemas.openid.net/secevent/caep/event-type/session-revoked": map[string]any{
				"reason": "policy",
			},
		},
	})
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}

	if err := wrapped.DeliverSET(context.Background(), nonVerification); err != nil {
		t.Fatalf("wrapped Sink: %v", err)
	}
	if len(got) == 0 {
		t.Fatal("downstream Sink did not see forwarded payload")
	}
	if string(got) != string(nonVerification) {
		t.Errorf("downstream payload not byte-identical to input")
	}
}

// TestVerificationChallengerContextCancelled cancels the parent
// context while Challenge is waiting; Challenge returns ctx.Err
// promptly.
func TestVerificationChallengerContextCancelled(t *testing.T) {
	t.Parallel()

	vs := newVerificationServer(t)
	challenger := receiver.NewVerificationChallenger()

	ctx, cancel := context.WithCancel(context.Background())
	time.AfterFunc(20*time.Millisecond, cancel)

	start := time.Now()
	_, err := challenger.Challenge(ctx,
		receiver.WithEndpoint(vs.URL),
		receiver.WithTimeout(5*time.Second),
	)
	elapsed := time.Since(start)
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("Challenge err = %v, want context.Canceled", err)
	}
	if elapsed > 500*time.Millisecond {
		t.Errorf("Challenge took %v, expected prompt cancel", elapsed)
	}
}

// TestVerificationChallengerWithStreamID asserts the stream_id query
// parameter is added to the POST URL.
func TestVerificationChallengerWithStreamID(t *testing.T) {
	t.Parallel()

	vs := newVerificationServer(t)
	challenger := receiver.NewVerificationChallenger()
	wrapped := challenger.WrapSink(nil)

	const state = "with-stream"
	const streamID = "stream-42"
	go func() {
		time.Sleep(10 * time.Millisecond)
		_ = wrapped.DeliverSET(context.Background(), makeVerificationSET(t, state))
	}()

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	if _, err := challenger.Challenge(ctx,
		receiver.WithEndpoint(vs.URL),
		receiver.WithState(state),
		receiver.WithStreamID(streamID),
	); err != nil {
		t.Fatalf("Challenge: %v", err)
	}

	vs.mu.Lock()
	gotQuery := vs.lastQuery
	vs.mu.Unlock()
	wantQuery := "stream_id=" + streamID
	if gotQuery != wantQuery {
		t.Errorf("query = %q, want %q", gotQuery, wantQuery)
	}
}

// TestVerificationChallengerWithStreamIDPreservesExistingQuery
// confirms an endpoint URL that already carries query parameters
// keeps them and adds stream_id alongside.
func TestVerificationChallengerWithStreamIDPreservesExistingQuery(t *testing.T) {
	t.Parallel()

	vs := newVerificationServer(t)
	challenger := receiver.NewVerificationChallenger()
	wrapped := challenger.WrapSink(nil)

	const state = "preserve-query"
	go func() {
		time.Sleep(10 * time.Millisecond)
		_ = wrapped.DeliverSET(context.Background(), makeVerificationSET(t, state))
	}()

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	if _, err := challenger.Challenge(ctx,
		receiver.WithEndpoint(vs.URL+"?foo=bar"),
		receiver.WithState(state),
		receiver.WithStreamID("s1"),
	); err != nil {
		t.Fatalf("Challenge: %v", err)
	}

	vs.mu.Lock()
	gotQuery := vs.lastQuery
	vs.mu.Unlock()
	// url.Values.Encode sorts keys alphabetically: foo, stream_id.
	want := "foo=bar&stream_id=s1"
	if gotQuery != want {
		t.Errorf("query = %q, want %q", gotQuery, want)
	}
}

// TestVerificationChallengerWithAuthorizationHeader asserts the
// Authorization header passes through verbatim.
func TestVerificationChallengerWithAuthorizationHeader(t *testing.T) {
	t.Parallel()

	vs := newVerificationServer(t)
	challenger := receiver.NewVerificationChallenger()
	wrapped := challenger.WrapSink(nil)

	const state = "with-auth"
	const auth = "Bearer test-token-123"
	go func() {
		time.Sleep(10 * time.Millisecond)
		_ = wrapped.DeliverSET(context.Background(), makeVerificationSET(t, state))
	}()

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	if _, err := challenger.Challenge(ctx,
		receiver.WithEndpoint(vs.URL),
		receiver.WithState(state),
		receiver.WithAuthorizationHeader(auth),
	); err != nil {
		t.Fatalf("Challenge: %v", err)
	}

	vs.mu.Lock()
	gotAuth := vs.lastAuth
	vs.mu.Unlock()
	if gotAuth != auth {
		t.Errorf("Authorization = %q, want %q", gotAuth, auth)
	}
}

// TestVerificationChallengerConcurrent launches several Challenges in
// parallel, each with its own state. Each one receives its matched
// SET. The race detector catches lock-ordering bugs.
func TestVerificationChallengerConcurrent(t *testing.T) {
	t.Parallel()

	vs := newVerificationServer(t)
	challenger := receiver.NewVerificationChallenger()
	wrapped := challenger.WrapSink(receiver.SinkFunc(func(context.Context, []byte) error {
		t.Error("downstream Sink should not be called for matched verification SETs")
		return nil
	}))

	const n = 10
	states := make([]string, n)
	for i := range states {
		states[i] = "state-" + strconv.Itoa(i)
	}

	// Feed all SETs from background goroutines; ordering is
	// deliberately non-deterministic to exercise the map lookup.
	for _, s := range states {
		go func() {
			time.Sleep(time.Duration(20+len(s)) * time.Millisecond)
			_ = wrapped.DeliverSET(context.Background(), makeVerificationSET(t, s))
		}()
	}

	var wg sync.WaitGroup
	wg.Add(n)
	errCh := make(chan error, n)
	for _, s := range states {
		go func() {
			defer wg.Done()
			ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
			defer cancel()
			payload, err := challenger.Challenge(ctx,
				receiver.WithEndpoint(vs.URL),
				receiver.WithState(s),
			)
			if err != nil {
				errCh <- fmt.Errorf("state %s: %w", s, err)
				return
			}
			got, ok := readEventState(t, payload)
			if !ok {
				errCh <- fmt.Errorf("state %s: payload missing state", s)
				return
			}
			if got != s {
				errCh <- fmt.Errorf("state %s: got payload state %s", s, got)
			}
		}()
	}
	wg.Wait()
	close(errCh)
	for err := range errCh {
		t.Error(err)
	}
}

// TestVerificationChallengerTimeoutBeatsContextDeadline confirms the
// option-supplied timeout wins when it is shorter than the context's
// deadline.
func TestVerificationChallengerTimeoutBeatsContextDeadline(t *testing.T) {
	t.Parallel()

	vs := newVerificationServer(t)
	challenger := receiver.NewVerificationChallenger()

	// Context deadline far in the future; option timeout small.
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	start := time.Now()
	_, err := challenger.Challenge(ctx,
		receiver.WithEndpoint(vs.URL),
		receiver.WithTimeout(60*time.Millisecond),
	)
	elapsed := time.Since(start)
	if !errors.Is(err, ssf.ErrVerificationTimeout) {
		t.Fatalf("Challenge err = %v, want ErrVerificationTimeout", err)
	}
	if elapsed > 500*time.Millisecond {
		t.Errorf("Challenge took %v, expected ~60ms", elapsed)
	}
}

// TestVerificationChallengerRequiresEndpoint asserts the error
// message when WithEndpoint is omitted.
func TestVerificationChallengerRequiresEndpoint(t *testing.T) {
	t.Parallel()

	challenger := receiver.NewVerificationChallenger()
	_, err := challenger.Challenge(context.Background())
	if err == nil {
		t.Fatal("Challenge without endpoint must error")
	}
}

// TestVerificationChallengerHTTPErrorPropagates checks that a non-2xx
// response from the verification endpoint surfaces back to the caller
// and the in-flight slot is released.
func TestVerificationChallengerHTTPErrorPropagates(t *testing.T) {
	t.Parallel()

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "no thanks", http.StatusForbidden)
	}))
	defer srv.Close()

	challenger := receiver.NewVerificationChallenger()
	_, err := challenger.Challenge(context.Background(),
		receiver.WithEndpoint(srv.URL),
		receiver.WithState("any"),
		receiver.WithTimeout(50*time.Millisecond),
	)
	if err == nil {
		t.Fatal("expected error from non-2xx response")
	}
	// Subsequent call reusing the same state must succeed in
	// registering — i.e. the failed call released the slot.
	_, err = challenger.Challenge(context.Background(),
		receiver.WithEndpoint(srv.URL),
		receiver.WithState("any"),
		receiver.WithTimeout(50*time.Millisecond),
	)
	if err == nil {
		t.Fatal("expected second call to also error")
	}
}

// TestVerificationChallengerDuplicateStateRejected confirms two
// in-flight challenges cannot share the same caller-supplied state.
// The first call gets its POST in flight against a server that hangs
// until the test releases it; while it is parked, a second call with
// the same state immediately fails registration without issuing its
// own POST.
func TestVerificationChallengerDuplicateStateRejected(t *testing.T) {
	t.Parallel()

	// Gate-held server: any request blocks until release closes.
	release := make(chan struct{})
	hit := make(chan struct{}, 1)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		select {
		case hit <- struct{}{}:
		default:
		}
		<-release
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()
	defer close(release)

	challenger := receiver.NewVerificationChallenger()

	firstDone := make(chan struct{})
	go func() {
		defer close(firstDone)
		_, _ = challenger.Challenge(context.Background(),
			receiver.WithEndpoint(srv.URL),
			receiver.WithState("shared"),
			receiver.WithTimeout(50*time.Millisecond),
		)
	}()

	// Wait for the first call's POST to actually reach the server,
	// guaranteeing its state slot is now registered.
	select {
	case <-hit:
	case <-time.After(2 * time.Second):
		t.Fatal("first Challenge POST never reached server")
	}

	// Second call with the same state must fail registration
	// immediately — before issuing any HTTP request.
	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()
	_, err := challenger.Challenge(ctx,
		receiver.WithEndpoint(srv.URL),
		receiver.WithState("shared"),
	)
	if err == nil {
		t.Fatal("second Challenge with duplicate state must error")
	}

	// Release the first call so the goroutine exits cleanly.
	release <- struct{}{}
	select {
	case <-firstDone:
	case <-time.After(2 * time.Second):
		t.Fatal("first Challenge goroutine did not exit")
	}
}

// readEventState mirrors the package-internal extractor. Tests live
// in the _test package so they cannot call the unexported helper; a
// small reimplementation keeps the boundary clean.
func readEventState(t *testing.T, payload []byte) (string, bool) {
	t.Helper()
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
	return event.State, event.State != ""
}
