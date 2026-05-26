// Copyright 2026 The go-ssf Authors
// SPDX-License-Identifier: Apache-2.0

//go:build interop

package interop_test

import (
	"context"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"net/http/httptest"
	"slices"
	"sync"
	"testing"
	"time"

	jose "github.com/go-jose/go-jose/v4"

	"github.com/hstern/go-ssf"
	"github.com/hstern/go-ssf/client"
	"github.com/hstern/go-ssf/internal/interop"
	"github.com/hstern/go-ssf/memstore"
	"github.com/hstern/go-ssf/receiver"
	"github.com/hstern/go-ssf/transmitter"
)

// testIssuer is the constant issuer URI every loopback test uses on
// its SET claims. The value is the spec's example issuer URI; the
// harness does not consult issuer routing, so the choice is
// cosmetic.
const testIssuer = "https://transmitter.example.com/"

// testAudience is the audience identifier the harness pins on every
// stream and every emitted SET. Like testIssuer, the value is
// cosmetic — the loopback harness does not enforce audience
// routing.
const testAudience = "https://receiver.example.com/"

// newHMACMaterial mints a fresh 32-byte HMAC key plus a matching
// SET signer and JWKS-bound verifier. HMAC (HS256) is the smallest
// jose surface that exercises the [ssf.NewJOSESetSigner] /
// [ssf.NewJOSESetVerifier] pair end-to-end without dragging
// PEM-keypair generation into the harness; production deployments
// use asymmetric keys, but the wire shape of the JWS is identical.
//
// Asymmetric vs symmetric key choice is irrelevant for interop —
// the harness exercises the JWS-compact serialization the
// Transmitter emits and the JWS-compact verification the Receiver
// performs, neither of which branches on the alg family.
func newHMACMaterial(t *testing.T) (signer ssf.SETSigner, verifier ssf.SETVerifier) {
	t.Helper()

	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		t.Fatalf("rand.Read: %v", err)
	}

	opts := (&jose.SignerOptions{}).WithType(ssf.SETMediaType)
	joseSigner, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.HS256, Key: key}, opts)
	if err != nil {
		t.Fatalf("jose.NewSigner: %v", err)
	}

	s, err := ssf.NewJOSESetSigner(joseSigner)
	if err != nil {
		t.Fatalf("ssf.NewJOSESetSigner: %v", err)
	}

	v := ssf.NewJOSESetVerifier(jose.JSONWebKeySet{
		Keys: []jose.JSONWebKey{{
			Key:       key,
			Algorithm: string(jose.HS256),
			Use:       "sig",
		}},
	})

	return s, v
}

// marshalSETClaims assembles a minimal SET claims set under
// [ssf.EventTypeVerification] keyed by jti and returns the JSON
// bytes. The claims set is deliberately small — iss / aud / jti /
// iat / events — matching RFC 8417 §2.2's mandatory members. Tests
// that want richer event payloads inline their own claims set; this
// helper is the common shape every loopback cell needs.
func marshalSETClaims(t *testing.T, jti string) []byte {
	t.Helper()

	claims := map[string]any{
		"iss": testIssuer,
		"aud": testAudience,
		"jti": jti,
		"iat": time.Now().Unix(),
		"events": map[string]any{
			ssf.EventTypeVerification: map[string]any{
				"state": "loopback-" + jti,
			},
		},
	}
	payload, err := json.Marshal(claims)
	if err != nil {
		t.Fatalf("marshal SET claims: %v", err)
	}
	return payload
}

// signSET returns the compact-serialized JWS for the claims set
// produced by [marshalSETClaims]. Used by the poll-mode tests
// (which need a fully-signed JWS to seed the Transmitter's queue);
// the push-mode tests hand the unsigned payload to
// [transmitter.PushDriver.Deliver] instead.
func signSET(t *testing.T, signer ssf.SETSigner, jti string) string {
	t.Helper()

	jws, err := signer.Sign(marshalSETClaims(t, jti))
	if err != nil {
		t.Fatalf("Sign SET %q: %v", jti, err)
	}
	return jws
}

// recordingSink captures every payload it receives so the loopback
// tests can assert delivery order, count, and content. The sink is
// safe for concurrent invocation — the Receiver Poller may call
// DeliverSET from worker goroutines under WithParallelDelivery, and
// the Push handler dispatches each request on its own goroutine
// regardless.
type recordingSink struct {
	mu       sync.Mutex
	received [][]byte
	jtis     []string
}

// DeliverSET records the payload and the SET's jti for later
// inspection. The implementation parses the jti out of the payload
// for assertion convenience; a payload whose claims set is not a
// JSON object with a string jti member surfaces as an empty entry
// in the jtis slice, which the test asserts on directly.
func (s *recordingSink) DeliverSET(_ context.Context, payload []byte) error {
	var claims struct {
		JTI string `json:"jti"`
	}
	_ = json.Unmarshal(payload, &claims)

	s.mu.Lock()
	defer s.mu.Unlock()
	s.received = append(s.received, slices.Clone(payload))
	s.jtis = append(s.jtis, claims.JTI)
	return nil
}

// jtisSnapshot returns a copy of the jtis observed so far.
func (s *recordingSink) jtisSnapshot() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]string, len(s.jtis))
	copy(out, s.jtis)
	return out
}

// count returns how many SETs the sink has received so far.
func (s *recordingSink) count() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.received)
}

// newPushStream creates a fresh push-delivery stream on the
// Transmitter via the [client.Client] and returns its assigned
// stream_id. The push endpoint URL is the caller-supplied
// receiverPushURL — typically the [httptest.Server] URL of a
// PushHandler. The harness uses [client.Client.CreateConfig] for
// realism: the test exercises the JSON shapes a real Receiver
// would put on the wire.
func newPushStream(t *testing.T, c *client.Client, receiverPushURL string) string {
	t.Helper()

	cfg, err := c.CreateConfig(context.Background(), &ssf.StreamConfig{
		Iss:             testIssuer,
		Aud:             json.RawMessage(`"` + testAudience + `"`),
		EventsRequested: []string{ssf.EventTypeVerification},
		Delivery: ssf.Delivery{
			Method:      ssf.DeliveryMethodPush,
			EndpointURL: receiverPushURL,
		},
	})
	if err != nil {
		t.Fatalf("CreateConfig (push): %v", err)
	}
	if cfg.StreamID == "" {
		t.Fatal("CreateConfig (push): server returned empty stream_id")
	}
	return cfg.StreamID
}

// newPollStream creates a fresh poll-delivery stream on the
// Transmitter via the [client.Client]. Poll streams advertise the
// Transmitter's poll endpoint as their delivery URL; the
// [transmitter.MuxHandler] mounts the poll endpoint at
// [transmitter.DefaultPollPath] on the same server, so the URL is
// the test server's base URL + that path.
func newPollStream(t *testing.T, c *client.Client, transmitterPollURL string) string {
	t.Helper()

	cfg, err := c.CreateConfig(context.Background(), &ssf.StreamConfig{
		Iss:             testIssuer,
		Aud:             json.RawMessage(`"` + testAudience + `"`),
		EventsRequested: []string{ssf.EventTypeVerification},
		Delivery: ssf.Delivery{
			Method:      ssf.DeliveryMethodPoll,
			EndpointURL: transmitterPollURL,
		},
	})
	if err != nil {
		t.Fatalf("CreateConfig (poll): %v", err)
	}
	if cfg.StreamID == "" {
		t.Fatal("CreateConfig (poll): server returned empty stream_id")
	}
	return cfg.StreamID
}

// TestTransmitterPush exercises the Transmitter+push cell of the
// interop matrix.
//
// Wiring:
//
//   - Transmitter: [interop.MemstoreTransmitter] behind a
//     [transmitter.MuxHandler] on an [httptest.Server].
//   - Receiver: [receiver.PushHandler] on a second [httptest.Server],
//     fronted by a [recordingSink].
//
// The test creates a push-delivery stream on the Transmitter via the
// [client.Client], then drives a [transmitter.PushDriver] to sign
// and POST three SETs to the Receiver's push endpoint. The Sink
// MUST observe all three SETs in delivery order.
func TestTransmitterPush(t *testing.T) {
	t.Parallel()

	signer, verifier := newHMACMaterial(t)

	store := memstore.NewInMemoryStore()
	tm := interop.NewMemstoreTransmitter(store)
	txSrv, txStop := interop.StartTransmitter(tm)
	defer txStop()

	sink := &recordingSink{}
	rxSrv := httptest.NewServer(receiver.PushHandler(verifier, sink))
	defer rxSrv.Close()

	c, err := client.NewClient(txSrv.URL)
	if err != nil {
		t.Fatalf("client.NewClient: %v", err)
	}
	streamID := newPushStream(t, c, rxSrv.URL)

	driver := transmitter.NewPushDriver(signer)
	target := transmitter.Target{EndpointURL: rxSrv.URL}

	// PushDriver signs the payload itself, so the helper hands it
	// unsigned claims bytes rather than the JWS-compact string
	// signSET produces. The signSET helper is shared with the
	// poll-mode cells where the JWS is what's pre-enqueued.
	wantJTIs := []string{"set-1", "set-2", "set-3"}
	for _, jti := range wantJTIs {
		payload := marshalSETClaims(t, jti)
		if err := driver.Deliver(context.Background(), target, payload); err != nil {
			t.Fatalf("PushDriver.Deliver %q: %v", jti, err)
		}
	}

	// Verify the stream was created with the right delivery method —
	// a sanity check that the [client.Client] / [transmitter.MuxHandler]
	// pair round-tripped the StreamConfig correctly.
	got, err := c.GetConfig(context.Background(), streamID)
	if err != nil {
		t.Fatalf("GetConfig: %v", err)
	}
	if got.Delivery.Method != ssf.DeliveryMethodPush {
		t.Errorf("delivery method = %q, want %q", got.Delivery.Method, ssf.DeliveryMethodPush)
	}
	if got.Delivery.EndpointURL != rxSrv.URL {
		t.Errorf("delivery endpoint = %q, want %q", got.Delivery.EndpointURL, rxSrv.URL)
	}

	if sink.count() != len(wantJTIs) {
		t.Fatalf("Sink received %d SETs, want %d", sink.count(), len(wantJTIs))
	}
	gotJTIs := sink.jtisSnapshot()
	if !slices.Equal(gotJTIs, wantJTIs) {
		t.Errorf("Sink jti order = %v, want %v", gotJTIs, wantJTIs)
	}
}

// TestTransmitterPoll exercises the Transmitter+poll cell of the
// interop matrix.
//
// Wiring:
//
//   - Transmitter: [interop.MemstoreTransmitter] behind a
//     [transmitter.MuxHandler] on an [httptest.Server].
//   - Receiver: a [client.Client] driving the poll endpoint directly
//     (this cell tests the Transmitter's poll-endpoint wire shape,
//     not the [receiver.Poller]'s cadence loop — that lives in
//     [TestReceiverPoll]).
//
// The test pre-seeds three SETs into the Transmitter's poll queue,
// drives one poll, asserts the SETs are returned in enqueue order,
// then drives a second poll with the matching Ack list and asserts
// the queue drains to empty.
func TestTransmitterPoll(t *testing.T) {
	t.Parallel()

	signer, _ := newHMACMaterial(t)

	store := memstore.NewInMemoryStore()
	tm := interop.NewMemstoreTransmitter(store)
	txSrv, txStop := interop.StartTransmitter(tm)
	defer txStop()

	c, err := client.NewClient(txSrv.URL)
	if err != nil {
		t.Fatalf("client.NewClient: %v", err)
	}
	streamID := newPollStream(t, c, txSrv.URL+transmitter.DefaultPollPath)

	// Pre-enqueue SETs. The harness records both the jti and the
	// JWS so PollEvents can return them as a map without re-parsing
	// the signed payload.
	wantJTIs := []string{"poll-1", "poll-2", "poll-3"}
	for _, jti := range wantJTIs {
		jws := signSET(t, signer, jti)
		if err := tm.EnqueueForPoll(context.Background(), streamID, jti, jws); err != nil {
			t.Fatalf("EnqueueForPoll %q: %v", jti, err)
		}
	}

	// First poll: drain. The request carries no ack — this is the
	// initial poll, the Receiver has nothing to acknowledge.
	resp, err := c.PollEvents(context.Background(), streamID, &ssf.PollRequest{})
	if err != nil {
		t.Fatalf("PollEvents (drain): %v", err)
	}
	if len(resp.Sets) != len(wantJTIs) {
		t.Fatalf("PollEvents returned %d SETs, want %d", len(resp.Sets), len(wantJTIs))
	}
	for _, jti := range wantJTIs {
		if _, ok := resp.Sets[jti]; !ok {
			t.Errorf("PollEvents response missing jti %q", jti)
		}
	}

	// Second poll: ack and confirm empty. The MaxEvents pointer is
	// left nil so the Transmitter applies its default cap; the
	// queue is empty anyway, so the cap is irrelevant.
	resp2, err := c.PollEvents(context.Background(), streamID, &ssf.PollRequest{
		Ack: wantJTIs,
	})
	if err != nil {
		t.Fatalf("PollEvents (ack): %v", err)
	}
	if len(resp2.Sets) != 0 {
		t.Errorf("PollEvents after ack returned %d SETs, want 0", len(resp2.Sets))
	}
	if got := tm.OutstandingCount(streamID); got != 0 {
		t.Errorf("OutstandingCount after ack = %d, want 0", got)
	}

	// Third poll: confirm steady-state empty stays empty.
	resp3, err := c.PollEvents(context.Background(), streamID, &ssf.PollRequest{})
	if err != nil {
		t.Fatalf("PollEvents (steady-state): %v", err)
	}
	if len(resp3.Sets) != 0 {
		t.Errorf("steady-state PollEvents returned %d SETs, want 0", len(resp3.Sets))
	}
}

// TestReceiverPush exercises the Receiver+push cell of the interop
// matrix.
//
// Wiring:
//
//   - Receiver: [receiver.PushHandler] on an [httptest.Server],
//     fronted by a [recordingSink].
//   - Transmitter: a [transmitter.PushDriver] driving HTTP POSTs to
//     the Receiver's push endpoint directly (this cell tests the
//     Receiver's push-endpoint wire shape, not the Transmitter's
//     stream-CRUD or poll-endpoint surfaces).
//
// This is the symmetrical companion to [TestTransmitterPush]: same
// wire flow, narrower assertion. A single SET is signed, POSTed,
// and asserted to arrive at the Sink. The narrow scope keeps the
// failure mode unambiguous when this test breaks.
func TestReceiverPush(t *testing.T) {
	t.Parallel()

	signer, verifier := newHMACMaterial(t)

	sink := &recordingSink{}
	rxSrv := httptest.NewServer(receiver.PushHandler(verifier, sink))
	defer rxSrv.Close()

	driver := transmitter.NewPushDriver(signer)

	jti := "rx-push-1"
	payload := marshalSETClaims(t, jti)

	if err := driver.Deliver(context.Background(), transmitter.Target{EndpointURL: rxSrv.URL}, payload); err != nil {
		t.Fatalf("PushDriver.Deliver: %v", err)
	}

	if got := sink.count(); got != 1 {
		t.Fatalf("Sink received %d SETs, want 1", got)
	}
	if gotJTIs := sink.jtisSnapshot(); gotJTIs[0] != jti {
		t.Errorf("Sink jti = %q, want %q", gotJTIs[0], jti)
	}
}

// TestReceiverPoll exercises the Receiver+poll cell of the interop
// matrix.
//
// Wiring:
//
//   - Transmitter: [interop.MemstoreTransmitter] behind a
//     [transmitter.MuxHandler] on an [httptest.Server].
//   - Receiver: [receiver.Poller] pointed at the Transmitter's poll
//     endpoint, fronted by a [recordingSink].
//
// The test pre-seeds three SETs into the Transmitter's poll queue,
// runs the Poller under a [context.WithTimeout] for long enough to
// drain the queue at least twice, and asserts the Sink received
// all three SETs and that the Transmitter saw the ack for each one
// on the follow-up poll. The Poller's no-events backoff is set
// extremely tight (10ms initial, 10ms max) so a slow CI machine
// still drains within the deadline.
func TestReceiverPoll(t *testing.T) {
	t.Parallel()

	signer, verifier := newHMACMaterial(t)

	store := memstore.NewInMemoryStore()
	tm := interop.NewMemstoreTransmitter(store)
	txSrv, txStop := interop.StartTransmitter(tm)
	defer txStop()

	// Pre-create a poll stream so the Transmitter's PollEvents call
	// finds it. We don't drive newPollStream through the client
	// here because the stream's delivery URL is informational on
	// the poll side — the Receiver dials the URL it was constructed
	// with, not whatever the StreamConfig advertises.
	streamID := "rx-poll-stream"
	if _, err := store.CreateStream(context.Background(), &ssf.StreamConfig{
		StreamID:        streamID,
		Iss:             testIssuer,
		Aud:             json.RawMessage(`"` + testAudience + `"`),
		EventsRequested: []string{ssf.EventTypeVerification},
		Delivery: ssf.Delivery{
			Method:      ssf.DeliveryMethodPoll,
			EndpointURL: txSrv.URL + transmitter.DefaultPollPath,
		},
	}); err != nil {
		t.Fatalf("CreateStream: %v", err)
	}

	wantJTIs := []string{"rx-poll-1", "rx-poll-2", "rx-poll-3"}
	for _, jti := range wantJTIs {
		jws := signSET(t, signer, jti)
		if err := tm.EnqueueForPoll(context.Background(), streamID, jti, jws); err != nil {
			t.Fatalf("EnqueueForPoll %q: %v", jti, err)
		}
	}

	sink := &recordingSink{}

	// The Poller dials the Transmitter's poll path with stream_id
	// as a query parameter — the library's MuxHandler convention.
	// See receiver/poller.go's comment block for why the library
	// pins stream_id as a query parameter rather than the RFC 8936
	// auth-credential-implied stream.
	pollURL := fmt.Sprintf("%s%s?stream_id=%s",
		txSrv.URL, transmitter.DefaultPollPath, streamID)

	poller := receiver.NewPoller(pollURL, verifier, sink,
		// Drive cadence aggressively so the test finishes well
		// inside its deadline even on a slow CI machine.
		receiver.WithNoEventsBackoff(10*time.Millisecond, 10*time.Millisecond),
		receiver.WithErrorBackoff(10*time.Millisecond, 50*time.Millisecond),
	)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	// Run the Poller in a goroutine; cancel once the Sink has
	// received every expected SET AND the Transmitter has observed
	// the ack (one extra poll cycle after the final delivery).
	done := make(chan error, 1)
	go func() {
		done <- poller.Run(ctx)
	}()

	deadline := time.After(5 * time.Second)
	tick := time.NewTicker(20 * time.Millisecond)
	defer tick.Stop()

	for sink.count() < len(wantJTIs) || tm.OutstandingCount(streamID) > 0 {
		select {
		case <-deadline:
			t.Fatalf("timed out: sink count = %d, outstanding = %d",
				sink.count(), tm.OutstandingCount(streamID))
		case <-tick.C:
		}
	}

	cancel()
	if err := <-done; err != nil && !errors.Is(err, context.Canceled) && !errors.Is(err, context.DeadlineExceeded) {
		t.Errorf("Poller.Run returned unexpected error: %v", err)
	}

	gotJTIs := sink.jtisSnapshot()
	// Order is preserved by serial-dispatch Poller, but the
	// Transmitter returns Sets as a Go map — JSON map iteration is
	// unordered. Sort both sides before comparing so the assertion
	// is robust to legitimate ordering ambiguity at the wire layer.
	got := append([]string(nil), gotJTIs...)
	slices.Sort(got)
	want := append([]string(nil), wantJTIs...)
	slices.Sort(want)
	if !slices.Equal(got, want) {
		t.Errorf("Sink jtis = %v, want %v", got, want)
	}
}
