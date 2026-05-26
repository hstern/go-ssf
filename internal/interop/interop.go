// Copyright 2026 The go-ssf Authors
// SPDX-License-Identifier: Apache-2.0

//go:build interop

// Package interop is the library-vs-library conformance harness for
// OpenID Shared Signals Framework 1.0. It wires the in-tree
// transmitter package and receiver package together over an
// [net/http/httptest.Server] and exercises every cell of the
// Transmitter+push, Transmitter+poll, Receiver+push, Receiver+poll
// matrix.
//
// The matrix is the public conformance signal for the library at
// v0.1.0. The OpenID Foundation's Shared Signals Working Group runs
// periodic interop events but does not maintain an always-on
// reference Transmitter, so the loopback wiring here closes the gate
// for every-build CI; live WG interop follows post-v0.1.0.
//
// The package is test-only and built only under the `interop` build
// tag — `go test ./...` without the tag skips it entirely so the
// hermetic test surface is unaffected. CI runs the harness through
// scripts/check-interop.sh in a dedicated job.
//
// The harness deliberately does NOT ship a [transmitter.Transmitter]
// implementation in the library's public surface. The library's
// stance — see the design notes — is that the consumer owns its
// Transmitter implementation; an in-tree implementation would imply
// an opinion this library does not hold. The test
// [MemstoreTransmitter] lives here, under internal/, and exists only
// to drive the harness.
package interop

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http/httptest"
	"sync"

	"github.com/hstern/go-ssf"
	"github.com/hstern/go-ssf/memstore"
	"github.com/hstern/go-ssf/transmitter"
)

// MemstoreTransmitter is the test-only [transmitter.Transmitter]
// implementation used by the loopback harness. It delegates stream
// CRUD, status, subjects, and the enqueue side of poll-mode delivery
// to a [memstore.InMemoryStore]; the drain side (the bookkeeping
// that powers PollEvents) lives on this type because the v0.1.0
// [ssf.StreamStore] interface deliberately exposes EnqueueSET only —
// drain semantics are the Transmitter's job and are intentionally
// out of scope for the library's public surface.
//
// The drain bookkeeping is the minimum that exercises the
// [client.Client] and [receiver.Poller] poll-mode loops end-to-end:
// each stream has a FIFO of pending JWS compacts plus an outstanding
// map keyed by jti. A poll moves up to MaxEvents entries from
// pending into outstanding and returns them; the next poll's Ack
// list clears the corresponding outstanding entries; per-jti errors
// reported via SetErrs are recorded for the test to inspect but do
// not affect ack accounting.
//
// MemstoreTransmitter embeds [transmitter.NotImplementedTransmitter]
// as a fallback — every method the harness needs is overridden
// below; everything else returns [ssf.ErrNotImplemented] verbatim.
// The harness does not exercise the Verify method (the library has
// no on-the-wire verification fixtures yet) but the embedded
// fallback makes the type safe to mount behind a [transmitter.MuxHandler]
// without surprising 5xx responses if a future test grows into that
// territory.
type MemstoreTransmitter struct {
	transmitter.NotImplementedTransmitter

	store *memstore.InMemoryStore

	mu              sync.Mutex
	pending         map[string][]queueEntry
	outstanding     map[string]map[string]string // streamID -> jti -> jws
	observedSetErrs map[string]map[string]ssf.SetErr
}

// queueEntry pairs the jti the harness extracted at enqueue time
// with the compact-serialized JWS the wire carries. Carrying the
// jti separately spares PollEvents from re-parsing the SET's
// payload on every drain — the SET claims set is fixed once signed.
type queueEntry struct {
	jti string
	jws string
}

// NewMemstoreTransmitter returns a fresh harness Transmitter backed
// by store. The returned value is safe for concurrent use by the
// goroutines a [httptest.Server] dispatches.
//
// The store is borrowed, not owned: callers retain the right to
// create streams or inspect status on it directly. The harness uses
// the store as the source of truth for stream identity and
// configuration so the tests can pre-seed streams without going
// through the HTTP surface.
func NewMemstoreTransmitter(store *memstore.InMemoryStore) *MemstoreTransmitter {
	return &MemstoreTransmitter{
		store:           store,
		pending:         make(map[string][]queueEntry),
		outstanding:     make(map[string]map[string]string),
		observedSetErrs: make(map[string]map[string]ssf.SetErr),
	}
}

// EnqueueForPoll appends a SET to the harness's per-stream poll
// queue. The jti is required because the wire shape of a
// [ssf.PollResponse] is a map keyed by jti, and re-parsing the JWS
// on every poll just to recover it would obscure the test's
// intent. Tests typically sign their payload, parse the jti out of
// the claims set, and call EnqueueForPoll with both.
//
// The method also echoes the JWS into the underlying
// [memstore.InMemoryStore] via [ssf.StreamStore.EnqueueSET] so the
// store's queue inspection helpers (used elsewhere in the library's
// tests) still report a non-empty queue. The store's queue and the
// harness's queue are independent storage; the harness's drain does
// not touch the store's queue.
func (t *MemstoreTransmitter) EnqueueForPoll(ctx context.Context, streamID, jti, jws string) error {
	if err := t.store.EnqueueSET(ctx, streamID, jws); err != nil {
		return fmt.Errorf("interop: enqueue via store: %w", err)
	}

	t.mu.Lock()
	defer t.mu.Unlock()
	t.pending[streamID] = append(t.pending[streamID], queueEntry{jti: jti, jws: jws})
	return nil
}

// ObservedSetErrs returns a snapshot of the SET-delivery errors the
// Receiver has reported back to the harness on its poll requests.
// The map is keyed first by streamID then by jti; each inner entry
// is the most recent [ssf.SetErr] the Receiver reported for that jti.
//
// Tests use this to assert that a deliberately-malformed SET (or a
// Sink that returns [receiver.ErrPermanent]) surfaces the
// corresponding error code back to the Transmitter side as RFC 8936
// §2.3 prescribes.
func (t *MemstoreTransmitter) ObservedSetErrs() map[string]map[string]ssf.SetErr {
	t.mu.Lock()
	defer t.mu.Unlock()

	out := make(map[string]map[string]ssf.SetErr, len(t.observedSetErrs))
	for streamID, byJTI := range t.observedSetErrs {
		copyByJTI := make(map[string]ssf.SetErr, len(byJTI))
		for jti, setErr := range byJTI {
			copyByJTI[jti] = setErr
		}
		out[streamID] = copyByJTI
	}
	return out
}

// OutstandingCount returns the number of SETs the harness has
// delivered on prior polls but not yet seen acknowledged. A test
// that drives the poll loop to completion expects this to fall to
// zero once every delivered SET has been acked.
func (t *MemstoreTransmitter) OutstandingCount(streamID string) int {
	t.mu.Lock()
	defer t.mu.Unlock()
	return len(t.outstanding[streamID])
}

// GetConfig implements [transmitter.Transmitter] by delegating to
// the embedded [memstore.InMemoryStore].
func (t *MemstoreTransmitter) GetConfig(ctx context.Context, streamID string) (*ssf.StreamConfig, error) {
	return t.store.GetStream(ctx, streamID)
}

// ListConfig implements [transmitter.Transmitter] by delegating to
// the embedded [memstore.InMemoryStore].
func (t *MemstoreTransmitter) ListConfig(ctx context.Context, pageToken string) ([]*ssf.StreamConfig, string, error) {
	return t.store.ListStreams(ctx, pageToken)
}

// CreateConfig implements [transmitter.Transmitter] by delegating
// to the embedded [memstore.InMemoryStore].
func (t *MemstoreTransmitter) CreateConfig(ctx context.Context, cfg *ssf.StreamConfig) (*ssf.StreamConfig, error) {
	return t.store.CreateStream(ctx, cfg)
}

// UpdateConfig implements [transmitter.Transmitter] by delegating
// to the embedded [memstore.InMemoryStore].
func (t *MemstoreTransmitter) UpdateConfig(ctx context.Context, cfg *ssf.StreamConfig) (*ssf.StreamConfig, error) {
	return t.store.UpdateStream(ctx, cfg)
}

// DeleteConfig implements [transmitter.Transmitter] by delegating
// to the embedded [memstore.InMemoryStore] and clearing the
// harness-side queue and outstanding state for the stream.
func (t *MemstoreTransmitter) DeleteConfig(ctx context.Context, streamID string) error {
	t.mu.Lock()
	delete(t.pending, streamID)
	delete(t.outstanding, streamID)
	delete(t.observedSetErrs, streamID)
	t.mu.Unlock()
	return t.store.DeleteStream(ctx, streamID)
}

// GetStatus implements [transmitter.Transmitter] by delegating to
// the embedded [memstore.InMemoryStore].
func (t *MemstoreTransmitter) GetStatus(ctx context.Context, streamID string, subject json.RawMessage) (*ssf.StatusResponse, error) {
	return t.store.GetStreamStatus(ctx, streamID, subject)
}

// UpdateStatus implements [transmitter.Transmitter] by delegating
// to the embedded [memstore.InMemoryStore].
func (t *MemstoreTransmitter) UpdateStatus(ctx context.Context, streamID string, req *ssf.StatusUpdateRequest) (*ssf.StatusResponse, error) {
	return t.store.SetStreamStatus(ctx, streamID, req)
}

// AddSubject implements [transmitter.Transmitter] by delegating to
// the embedded [memstore.InMemoryStore].
func (t *MemstoreTransmitter) AddSubject(ctx context.Context, streamID string, req *ssf.AddSubjectRequest) error {
	return t.store.AddSubject(ctx, streamID, req)
}

// RemoveSubject implements [transmitter.Transmitter] by delegating
// to the embedded [memstore.InMemoryStore].
func (t *MemstoreTransmitter) RemoveSubject(ctx context.Context, streamID string, req *ssf.RemoveSubjectRequest) error {
	return t.store.RemoveSubject(ctx, streamID, req)
}

// defaultPollBatchCap is the harness's per-poll batch cap when the
// caller leaves [ssf.PollRequest.MaxEvents] nil. RFC 8936 §2.4.1
// puts the choice on the Transmitter; 64 is generous enough that no
// loopback test has to think about pagination and small enough that
// MoreAvailable signalling is still reachable from a deliberate
// large-batch test.
const defaultPollBatchCap = 64

// PollEvents implements [transmitter.Transmitter] by applying the
// caller's Ack and SetErrs against the harness-side outstanding
// bookkeeping, then moving up to req.MaxEvents (or the harness
// default cap) entries from pending into outstanding and returning
// them as the PollResponse Sets map.
//
// The maxEvents cap follows RFC 8936 §2.4.1: a non-nil pointer to
// zero is an honored "ack only, no deliveries" request. A nil
// pointer means "no caller-specified cap"; the harness picks
// [defaultPollBatchCap] so loopback tests do not have to think
// about pagination. MoreAvailable is set when the cap clipped the
// batch.
func (t *MemstoreTransmitter) PollEvents(ctx context.Context, streamID string, req *ssf.PollRequest) (*ssf.PollResponse, error) {
	if _, err := t.store.GetStream(ctx, streamID); err != nil {
		return nil, err
	}

	t.mu.Lock()
	defer t.mu.Unlock()

	// Apply acks: drop each jti from the outstanding map.
	if outstanding, ok := t.outstanding[streamID]; ok && len(req.Ack) > 0 {
		for _, jti := range req.Ack {
			delete(outstanding, jti)
		}
	}

	// Record reported SET-delivery errors for the test to inspect.
	// An error report does not affect the harness's ack accounting:
	// the Receiver SHOULD ack the jti separately when the failure
	// is terminal (see [receiver.Poller.deliverOne]).
	if len(req.SetErrs) > 0 {
		bucket, ok := t.observedSetErrs[streamID]
		if !ok {
			bucket = make(map[string]ssf.SetErr, len(req.SetErrs))
			t.observedSetErrs[streamID] = bucket
		}
		for jti, setErr := range req.SetErrs {
			bucket[jti] = setErr
		}
	}

	batchCap := defaultPollBatchCap
	if req.MaxEvents != nil {
		batchCap = *req.MaxEvents
	}
	if batchCap < 0 {
		batchCap = 0
	}

	pending := t.pending[streamID]
	take := batchCap
	if take > len(pending) {
		take = len(pending)
	}

	outstanding := t.outstanding[streamID]
	if outstanding == nil && take > 0 {
		outstanding = make(map[string]string, take)
		t.outstanding[streamID] = outstanding
	}

	sets := make(map[string]string, take)
	for i := range take {
		e := pending[i]
		sets[e.jti] = e.jws
		outstanding[e.jti] = e.jws
	}
	t.pending[streamID] = pending[take:]

	resp := &ssf.PollResponse{Sets: sets}
	if take < len(pending) {
		more := true
		resp.MoreAvailable = &more
	}
	return resp, nil
}

// StartTransmitter starts an [httptest.Server] hosting the harness
// Transmitter behind a [transmitter.MuxHandler] with
// [transmitter.AlwaysAllow] auth. The returned server's URL is the
// base URL for a [client.Client]; the returned cleanup function
// shuts the server down and SHOULD be deferred by the caller.
//
// Auth is set to [transmitter.AlwaysAllow] because authentication is
// out of scope for the loopback harness — every test runs inside a
// single process, the only client is the test itself, and RFC 8935
// / RFC 8936 leave the auth scheme to deployment. The harness's
// design point is correctness of the wire shapes and the delivery
// loops, not the choice of bearer-token or mTLS layer in front of
// them.
func StartTransmitter(tm *MemstoreTransmitter) (server *httptest.Server, cleanup func()) {
	srv := httptest.NewServer(transmitter.MuxHandler(tm, transmitter.AlwaysAllow))
	return srv, srv.Close
}
