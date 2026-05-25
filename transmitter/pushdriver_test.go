// Copyright 2026 The go-ssf Authors
// SPDX-License-Identifier: Apache-2.0

package transmitter

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// stubSigner implements [ssf.SETSigner] for tests. It echoes a
// constant compact JWS so handler-side assertions can pin the
// body bytes without a real go-jose round-trip.
type stubSigner struct {
	jws string
	err error
}

func (s stubSigner) Sign(payload []byte) (string, error) {
	if s.err != nil {
		return "", s.err
	}
	if s.jws != "" {
		return s.jws, nil
	}
	// Default: a recognizable non-empty token so the wire
	// assertions are meaningful.
	return "header." + string(payload) + ".sig", nil
}

// newTestDriver returns a driver with deterministic timing —
// zero backoffs so the loop iterates immediately, and an
// instant-return sleep so cancellation tests don't race a real
// timer.
func newTestDriver(t *testing.T, opts ...PushDriverOption) *PushDriver {
	t.Helper()
	base := []PushDriverOption{
		WithBackoff(1*time.Millisecond, 5*time.Millisecond),
	}
	base = append(base, opts...)
	d := NewPushDriver(stubSigner{}, base...)
	return d
}

func TestPushDriver_Success(t *testing.T) {
	t.Parallel()

	var (
		hits      atomic.Int32
		gotBody   string
		gotCT     string
		gotAuth   string
		captureMu sync.Mutex
	)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		captureMu.Lock()
		defer captureMu.Unlock()
		gotCT = r.Header.Get("Content-Type")
		gotAuth = r.Header.Get("Authorization")
		b, _ := io.ReadAll(r.Body)
		gotBody = string(b)
		w.WriteHeader(http.StatusAccepted)
	}))
	defer srv.Close()

	d := NewPushDriver(stubSigner{jws: "header.payload.sig"})
	err := d.Deliver(context.Background(), Target{EndpointURL: srv.URL}, []byte(`{"jti":"1"}`))
	if err != nil {
		t.Fatalf("Deliver: %v", err)
	}
	if got := hits.Load(); got != 1 {
		t.Fatalf("handler hits: got %d want 1", got)
	}
	if gotBody != "header.payload.sig" {
		t.Fatalf("body: got %q want signed JWS", gotBody)
	}
	if gotCT != pushContentType {
		t.Fatalf("Content-Type: got %q want %q", gotCT, pushContentType)
	}
	if gotAuth != "" {
		t.Fatalf("Authorization: got %q want empty (Target carries none)", gotAuth)
	}
}

func TestPushDriver_AuthorizationHeader(t *testing.T) {
	t.Parallel()

	var gotAuth string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAuth = r.Header.Get("Authorization")
		w.WriteHeader(http.StatusAccepted)
	}))
	defer srv.Close()

	d := newTestDriver(t)
	err := d.Deliver(context.Background(), Target{
		EndpointURL:         srv.URL,
		AuthorizationHeader: "Bearer xyz",
	}, []byte(`{}`))
	if err != nil {
		t.Fatalf("Deliver: %v", err)
	}
	if gotAuth != "Bearer xyz" {
		t.Fatalf("Authorization: got %q want %q", gotAuth, "Bearer xyz")
	}
}

func TestPushDriver_PermanentFailure(t *testing.T) {
	t.Parallel()

	var hits atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		hits.Add(1)
		http.Error(w, "bad payload", http.StatusBadRequest)
	}))
	defer srv.Close()

	var (
		deadCalls  atomic.Int32
		gotLastErr error
		gotPayload []byte
	)
	d := newTestDriver(t,
		WithOnDeadLetter(func(_ context.Context, _ Target, payload []byte, lastErr error) {
			deadCalls.Add(1)
			gotLastErr = lastErr
			gotPayload = payload
		}),
	)

	payload := []byte(`{"jti":"perm"}`)
	err := d.Deliver(context.Background(), Target{EndpointURL: srv.URL}, payload)
	if err == nil {
		t.Fatal("Deliver: got nil want error")
	}
	if got := hits.Load(); got != 1 {
		t.Fatalf("handler hits: got %d want 1 (4xx must not retry)", got)
	}
	if got := deadCalls.Load(); got != 1 {
		t.Fatalf("dead-letter calls: got %d want 1", got)
	}
	var httpErr *pushHTTPError
	if !errors.As(gotLastErr, &httpErr) || httpErr.StatusCode != http.StatusBadRequest {
		t.Fatalf("dead-letter lastErr: got %v want 400", gotLastErr)
	}
	if string(gotPayload) != string(payload) {
		t.Fatalf("dead-letter payload: got %q want %q", gotPayload, payload)
	}
}

func TestPushDriver_TransientThenSuccess(t *testing.T) {
	t.Parallel()

	var hits atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		n := hits.Add(1)
		if n == 1 {
			w.Header().Set("Retry-After", "0")
			w.WriteHeader(http.StatusTooManyRequests)
			return
		}
		w.WriteHeader(http.StatusAccepted)
	}))
	defer srv.Close()

	var deadCalls atomic.Int32
	d := newTestDriver(t,
		WithOnDeadLetter(func(context.Context, Target, []byte, error) { deadCalls.Add(1) }),
	)

	err := d.Deliver(context.Background(), Target{EndpointURL: srv.URL}, []byte(`{}`))
	if err != nil {
		t.Fatalf("Deliver: %v", err)
	}
	if got := hits.Load(); got != 2 {
		t.Fatalf("handler hits: got %d want 2", got)
	}
	if got := deadCalls.Load(); got != 0 {
		t.Fatalf("dead-letter calls: got %d want 0 (recovery success)", got)
	}
}

func TestPushDriver_RetriesExhausted(t *testing.T) {
	t.Parallel()

	var hits atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		hits.Add(1)
		http.Error(w, "down", http.StatusServiceUnavailable)
	}))
	defer srv.Close()

	const retries = 2
	var (
		deadCalls  atomic.Int32
		gotLastErr error
	)
	d := newTestDriver(t,
		WithMaxRetries(retries),
		WithOnDeadLetter(func(_ context.Context, _ Target, _ []byte, lastErr error) {
			deadCalls.Add(1)
			gotLastErr = lastErr
		}),
	)

	err := d.Deliver(context.Background(), Target{EndpointURL: srv.URL}, []byte(`{}`))
	if err == nil {
		t.Fatal("Deliver: got nil want error after exhaustion")
	}
	if got, want := int(hits.Load()), retries+1; got != want {
		t.Fatalf("handler hits: got %d want %d (1 + maxRetries)", got, want)
	}
	if got := deadCalls.Load(); got != 1 {
		t.Fatalf("dead-letter calls: got %d want 1", got)
	}
	var httpErr *pushHTTPError
	if !errors.As(gotLastErr, &httpErr) || httpErr.StatusCode != http.StatusServiceUnavailable {
		t.Fatalf("dead-letter lastErr: got %v want 503", gotLastErr)
	}
}

func TestPushDriver_ContextCancellationMidBackoff(t *testing.T) {
	t.Parallel()

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "down", http.StatusServiceUnavailable)
	}))
	defer srv.Close()

	// Sleep blocks forever-but-cancellable; the driver must
	// unblock on ctx cancel, not on a wakeup timer.
	d := NewPushDriver(stubSigner{},
		WithMaxRetries(5),
		WithBackoff(time.Hour, time.Hour),
	)

	ctx, cancel := context.WithCancel(context.Background())

	// Cancel shortly after the first failed POST so the driver is
	// definitely parked in the backoff sleep.
	go func() {
		time.Sleep(50 * time.Millisecond)
		cancel()
	}()

	start := time.Now()
	err := d.Deliver(ctx, Target{EndpointURL: srv.URL}, []byte(`{}`))
	elapsed := time.Since(start)

	if !errors.Is(err, context.Canceled) {
		t.Fatalf("Deliver: got %v want context.Canceled", err)
	}
	if elapsed > 5*time.Second {
		t.Fatalf("Deliver returned after %v; expected prompt cancellation, not next-retry wakeup", elapsed)
	}
}

func TestPushDriver_DefaultsApplied(t *testing.T) {
	t.Parallel()

	d := NewPushDriver(stubSigner{})
	if d.maxRetries != defaultMaxRetries {
		t.Errorf("maxRetries: got %d want %d", d.maxRetries, defaultMaxRetries)
	}
	if d.initialBackoff != defaultInitialBackoff {
		t.Errorf("initialBackoff: got %v want %v", d.initialBackoff, defaultInitialBackoff)
	}
	if d.maxBackoff != defaultMaxBackoff {
		t.Errorf("maxBackoff: got %v want %v", d.maxBackoff, defaultMaxBackoff)
	}
	if d.httpClient != http.DefaultClient {
		t.Errorf("httpClient: got %p want http.DefaultClient", d.httpClient)
	}
	if d.onDeadLetter != nil {
		t.Errorf("onDeadLetter: got non-nil want nil default")
	}
}

func TestPushDriver_NilSignerPanics(t *testing.T) {
	t.Parallel()

	defer func() {
		if r := recover(); r == nil {
			t.Fatal("NewPushDriver(nil): got no panic want panic")
		}
	}()
	_ = NewPushDriver(nil)
}

func TestPushDriver_SignerError(t *testing.T) {
	t.Parallel()

	wantErr := errors.New("kms unavailable")
	d := newTestDriver(t)
	d.signer = stubSigner{err: wantErr}

	err := d.Deliver(context.Background(), Target{EndpointURL: "http://unreachable.invalid"}, []byte(`{}`))
	if !errors.Is(err, wantErr) {
		t.Fatalf("Deliver: got %v want wrapping %v", err, wantErr)
	}
}

func TestPushDriver_EmptyEndpoint(t *testing.T) {
	t.Parallel()

	d := newTestDriver(t)
	err := d.Deliver(context.Background(), Target{EndpointURL: ""}, []byte(`{}`))
	if err == nil {
		t.Fatal("Deliver with empty endpoint: got nil want error")
	}
}

func TestPushDriver_RetryAfterSeconds(t *testing.T) {
	t.Parallel()

	d := NewPushDriver(stubSigner{})
	if got := d.parseRetryAfter("3"); got != 3*time.Second {
		t.Errorf("parseRetryAfter(\"3\"): got %v want 3s", got)
	}
	if got := d.parseRetryAfter(" 5 "); got != 5*time.Second {
		t.Errorf("parseRetryAfter(\" 5 \"): got %v want 5s", got)
	}
	if got := d.parseRetryAfter("0"); got != 0 {
		t.Errorf("parseRetryAfter(\"0\"): got %v want 0", got)
	}
	if got := d.parseRetryAfter("-1"); got != 0 {
		t.Errorf("parseRetryAfter(\"-1\"): got %v want 0", got)
	}
	if got := d.parseRetryAfter(""); got != 0 {
		t.Errorf("parseRetryAfter(empty): got %v want 0", got)
	}
	if got := d.parseRetryAfter("not a date"); got != 0 {
		t.Errorf("parseRetryAfter(garbage): got %v want 0", got)
	}
}

func TestPushDriver_RetryAfterHTTPDate(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 5, 25, 12, 0, 0, 0, time.UTC)
	d := NewPushDriver(stubSigner{})
	d.now = func() time.Time { return now }

	// 10 seconds in the future, IMF-fixdate form.
	future := now.Add(10 * time.Second).Format(http.TimeFormat)
	got := d.parseRetryAfter(future)
	if got < 9*time.Second || got > 11*time.Second {
		t.Errorf("parseRetryAfter(future): got %v want ~10s", got)
	}

	// A past date returns 0 (don't sleep into the past).
	past := now.Add(-time.Hour).Format(http.TimeFormat)
	if got := d.parseRetryAfter(past); got != 0 {
		t.Errorf("parseRetryAfter(past): got %v want 0", got)
	}
}

func TestPushDriver_NetworkErrorIsTransient(t *testing.T) {
	t.Parallel()

	// httptest server closed before the request — Dial fails.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusAccepted)
	}))
	url := srv.URL
	srv.Close()

	d := newTestDriver(t,
		WithMaxRetries(2),
	)

	err := d.Deliver(context.Background(), Target{EndpointURL: url}, []byte(`{}`))
	if err == nil {
		t.Fatal("Deliver: got nil want network error after retries")
	}
}

func TestApplyJitter(t *testing.T) {
	t.Parallel()

	d := 100 * time.Millisecond
	lo := time.Duration(float64(d) * (1 - jitterFraction))
	hi := time.Duration(float64(d) * (1 + jitterFraction))
	for range 1000 {
		got := applyJitter(d)
		if got < lo || got >= hi {
			t.Fatalf("applyJitter(%v) = %v; want in [%v, %v)", d, got, lo, hi)
		}
	}
	if got := applyJitter(0); got != 0 {
		t.Errorf("applyJitter(0): got %v want 0", got)
	}
}

func TestCapDuration(t *testing.T) {
	t.Parallel()

	cases := []struct {
		in, max, want time.Duration
	}{
		{50 * time.Millisecond, time.Second, 50 * time.Millisecond},
		{2 * time.Second, time.Second, time.Second},
		{-1 * time.Second, time.Second, 0},
	}
	for _, c := range cases {
		if got := capDuration(c.in, c.max); got != c.want {
			t.Errorf("capDuration(%v, %v): got %v want %v", c.in, c.max, got, c.want)
		}
	}
}

// Sanity: pushHTTPError surfaces both the status and a trimmed
// snippet of the body so dead-letter operators can triage.
func TestPushHTTPError_Format(t *testing.T) {
	t.Parallel()

	e := &pushHTTPError{StatusCode: 503, Body: []byte("  upstream gone\n")}
	want := "push endpoint returned status 503: upstream gone"
	if got := e.Error(); got != want {
		t.Errorf("Error(): got %q want %q", got, want)
	}

	empty := &pushHTTPError{StatusCode: 500}
	if got := empty.Error(); got != "push endpoint returned status 500" {
		t.Errorf("Error() empty body: got %q", got)
	}
}
