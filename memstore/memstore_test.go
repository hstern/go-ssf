// Copyright 2026 The go-ssf Authors
// SPDX-License-Identifier: Apache-2.0

package memstore_test

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"sync"
	"testing"

	ssf "github.com/hstern/go-ssf"
	"github.com/hstern/go-ssf/memstore"
	"github.com/hstern/go-subjectid"
)

// newTestStream returns a minimal valid [ssf.StreamConfig] for tests.
// The Delivery field is populated because the marshal-strict path
// requires a method discriminator; tests that only exercise CRUD on
// the store itself never round-trip through JSON, but constructing a
// reasonable shape protects against accidental coupling to unset
// defaults if a future test does.
func newTestStream() *ssf.StreamConfig {
	return &ssf.StreamConfig{
		Iss:             "https://issuer.example",
		Aud:             json.RawMessage(`"receiver.example"`),
		EventsRequested: []string{"https://schemas.openid.net/secevent/ssf/event-type/verification"},
		Delivery: ssf.Delivery{
			Method:      ssf.DeliveryMethodPush,
			EndpointURL: "https://receiver.example/push",
		},
	}
}

func newTestSubject(t *testing.T, id string) subjectid.SubjectIdentifier {
	t.Helper()
	raw := fmt.Sprintf(`{"format":"opaque","id":%q}`, id)
	subj, err := subjectid.Parse([]byte(raw))
	if err != nil {
		t.Fatalf("parse subject: %v", err)
	}
	return subj
}

func TestCreateStreamAssignsID(t *testing.T) {
	t.Parallel()

	store := memstore.NewInMemoryStore()
	ctx := context.Background()

	cfg, err := store.CreateStream(ctx, newTestStream())
	if err != nil {
		t.Fatalf("CreateStream: %v", err)
	}
	if cfg.StreamID == "" {
		t.Fatalf("CreateStream: store did not assign a stream_id")
	}

	got, err := store.GetStream(ctx, cfg.StreamID)
	if err != nil {
		t.Fatalf("GetStream: %v", err)
	}
	if got.StreamID != cfg.StreamID {
		t.Fatalf("GetStream: stream_id round-trip mismatch: got %q, want %q",
			got.StreamID, cfg.StreamID)
	}
	if got.Iss != cfg.Iss {
		t.Fatalf("GetStream: iss round-trip mismatch: got %q, want %q",
			got.Iss, cfg.Iss)
	}
}

func TestCreateStreamRetainsCallerSuppliedID(t *testing.T) {
	t.Parallel()

	store := memstore.NewInMemoryStore()
	ctx := context.Background()

	in := newTestStream()
	in.StreamID = "preset-id"

	cfg, err := store.CreateStream(ctx, in)
	if err != nil {
		t.Fatalf("CreateStream: %v", err)
	}
	if cfg.StreamID != "preset-id" {
		t.Fatalf("CreateStream: caller-supplied stream_id not retained: got %q, want %q",
			cfg.StreamID, "preset-id")
	}
}

func TestCreateStreamDuplicateIDRejected(t *testing.T) {
	t.Parallel()

	store := memstore.NewInMemoryStore()
	ctx := context.Background()

	in := newTestStream()
	in.StreamID = "dup"
	if _, err := store.CreateStream(ctx, in); err != nil {
		t.Fatalf("CreateStream(first): %v", err)
	}
	if _, err := store.CreateStream(ctx, in); !errors.Is(err, ssf.ErrInvalidConfig) {
		t.Fatalf("CreateStream(second): want ErrInvalidConfig, got %v", err)
	}
}

func TestCreateStreamNilConfigRejected(t *testing.T) {
	t.Parallel()

	store := memstore.NewInMemoryStore()
	if _, err := store.CreateStream(context.Background(), nil); !errors.Is(err, ssf.ErrInvalidConfig) {
		t.Fatalf("CreateStream(nil): want ErrInvalidConfig, got %v", err)
	}
}

func TestCreateStreamIsolatesCallerSlice(t *testing.T) {
	t.Parallel()

	store := memstore.NewInMemoryStore()
	ctx := context.Background()

	in := newTestStream()
	in.EventsRequested = []string{"a"}

	cfg, err := store.CreateStream(ctx, in)
	if err != nil {
		t.Fatalf("CreateStream: %v", err)
	}

	// Mutating the caller's slice MUST NOT leak into the store.
	in.EventsRequested[0] = "MUTATED"

	got, err := store.GetStream(ctx, cfg.StreamID)
	if err != nil {
		t.Fatalf("GetStream: %v", err)
	}
	if got.EventsRequested[0] != "a" {
		t.Fatalf("store retained alias to caller slice: got %q", got.EventsRequested[0])
	}
}

func TestGetStreamMissing(t *testing.T) {
	t.Parallel()

	store := memstore.NewInMemoryStore()
	_, err := store.GetStream(context.Background(), "nope")
	if !errors.Is(err, ssf.ErrStreamNotFound) {
		t.Fatalf("GetStream(missing): want ErrStreamNotFound, got %v", err)
	}
}

func TestUpdateStreamRoundTrip(t *testing.T) {
	t.Parallel()

	store := memstore.NewInMemoryStore()
	ctx := context.Background()

	cfg, err := store.CreateStream(ctx, newTestStream())
	if err != nil {
		t.Fatalf("CreateStream: %v", err)
	}

	cfg.Iss = "https://other-issuer.example"
	if _, err := store.UpdateStream(ctx, cfg); err != nil {
		t.Fatalf("UpdateStream: %v", err)
	}

	got, err := store.GetStream(ctx, cfg.StreamID)
	if err != nil {
		t.Fatalf("GetStream: %v", err)
	}
	if got.Iss != "https://other-issuer.example" {
		t.Fatalf("UpdateStream: iss not persisted: got %q", got.Iss)
	}
}

func TestUpdateStreamMissing(t *testing.T) {
	t.Parallel()

	store := memstore.NewInMemoryStore()
	cfg := newTestStream()
	cfg.StreamID = "missing"
	_, err := store.UpdateStream(context.Background(), cfg)
	if !errors.Is(err, ssf.ErrStreamNotFound) {
		t.Fatalf("UpdateStream(missing): want ErrStreamNotFound, got %v", err)
	}
}

func TestUpdateStreamNilRejected(t *testing.T) {
	t.Parallel()

	store := memstore.NewInMemoryStore()
	if _, err := store.UpdateStream(context.Background(), nil); !errors.Is(err, ssf.ErrInvalidConfig) {
		t.Fatalf("UpdateStream(nil): want ErrInvalidConfig, got %v", err)
	}
}

func TestDeleteStreamIdempotent(t *testing.T) {
	t.Parallel()

	store := memstore.NewInMemoryStore()
	ctx := context.Background()

	cfg, err := store.CreateStream(ctx, newTestStream())
	if err != nil {
		t.Fatalf("CreateStream: %v", err)
	}

	// First delete removes the stream.
	if err := store.DeleteStream(ctx, cfg.StreamID); err != nil {
		t.Fatalf("DeleteStream(first): %v", err)
	}
	if _, err := store.GetStream(ctx, cfg.StreamID); !errors.Is(err, ssf.ErrStreamNotFound) {
		t.Fatalf("after DeleteStream: GetStream should report not-found, got %v", err)
	}
	// Second delete on the same ID is still a no-op.
	if err := store.DeleteStream(ctx, cfg.StreamID); err != nil {
		t.Fatalf("DeleteStream(second): %v", err)
	}
	// Delete on a never-created ID is also a no-op.
	if err := store.DeleteStream(ctx, "never-existed"); err != nil {
		t.Fatalf("DeleteStream(never-existed): %v", err)
	}
}

func TestListStreamsEmpty(t *testing.T) {
	t.Parallel()

	store := memstore.NewInMemoryStore()
	got, next, err := store.ListStreams(context.Background(), "")
	if err != nil {
		t.Fatalf("ListStreams: %v", err)
	}
	if len(got) != 0 {
		t.Fatalf("ListStreams(empty): got %d streams, want 0", len(got))
	}
	if next != "" {
		t.Fatalf("ListStreams(empty): got next-token %q, want empty", next)
	}
}

func TestListStreamsReturnsAllSorted(t *testing.T) {
	t.Parallel()

	store := memstore.NewInMemoryStore()
	ctx := context.Background()

	ids := []string{"c-id", "a-id", "b-id"}
	for _, id := range ids {
		cfg := newTestStream()
		cfg.StreamID = id
		if _, err := store.CreateStream(ctx, cfg); err != nil {
			t.Fatalf("CreateStream %q: %v", id, err)
		}
	}

	got, next, err := store.ListStreams(ctx, "")
	if err != nil {
		t.Fatalf("ListStreams: %v", err)
	}
	if next != "" {
		t.Fatalf("ListStreams: got next-token %q, want empty (single-page store)", next)
	}
	if len(got) != 3 {
		t.Fatalf("ListStreams: got %d streams, want 3", len(got))
	}
	want := []string{"a-id", "b-id", "c-id"}
	for i, cfg := range got {
		if cfg.StreamID != want[i] {
			t.Fatalf("ListStreams: position %d: got stream_id %q, want %q",
				i, cfg.StreamID, want[i])
		}
	}
}

func TestSetAndGetStreamStatusWholeStream(t *testing.T) {
	t.Parallel()

	store := memstore.NewInMemoryStore()
	ctx := context.Background()

	cfg, err := store.CreateStream(ctx, newTestStream())
	if err != nil {
		t.Fatalf("CreateStream: %v", err)
	}

	// Default whole-stream status is enabled.
	resp, err := store.GetStreamStatus(ctx, cfg.StreamID, nil)
	if err != nil {
		t.Fatalf("GetStreamStatus: %v", err)
	}
	if resp.Status != ssf.StreamStatusEnabled {
		t.Fatalf("default status: got %q, want %q", resp.Status, ssf.StreamStatusEnabled)
	}

	upd := &ssf.StatusUpdateRequest{
		Status: ssf.StreamStatusPaused,
		Reason: "scheduled maintenance",
	}
	resp, err = store.SetStreamStatus(ctx, cfg.StreamID, upd)
	if err != nil {
		t.Fatalf("SetStreamStatus: %v", err)
	}
	if resp.Status != ssf.StreamStatusPaused || resp.Reason != "scheduled maintenance" {
		t.Fatalf("SetStreamStatus: round-trip mismatch: %+v", resp)
	}

	// Re-read converges on the new state.
	resp, err = store.GetStreamStatus(ctx, cfg.StreamID, nil)
	if err != nil {
		t.Fatalf("GetStreamStatus (post-set): %v", err)
	}
	if resp.Status != ssf.StreamStatusPaused {
		t.Fatalf("post-set status: got %q, want %q", resp.Status, ssf.StreamStatusPaused)
	}
}

func TestSetAndGetStreamStatusPerSubject(t *testing.T) {
	t.Parallel()

	store := memstore.NewInMemoryStore()
	ctx := context.Background()

	cfg, err := store.CreateStream(ctx, newTestStream())
	if err != nil {
		t.Fatalf("CreateStream: %v", err)
	}

	subj1 := json.RawMessage(`{"format":"opaque","id":"u1"}`)
	subj2 := json.RawMessage(`{"format":"opaque","id":"u2"}`)

	upd := &ssf.StatusUpdateRequest{
		Status:  ssf.StreamStatusDisabled,
		Reason:  "subject opted out",
		Subject: subj1,
	}
	if _, err := store.SetStreamStatus(ctx, cfg.StreamID, upd); err != nil {
		t.Fatalf("SetStreamStatus: %v", err)
	}

	// Per-subject read on subj1 returns the disabled status.
	resp, err := store.GetStreamStatus(ctx, cfg.StreamID, subj1)
	if err != nil {
		t.Fatalf("GetStreamStatus(subj1): %v", err)
	}
	if resp.Status != ssf.StreamStatusDisabled || resp.Reason != "subject opted out" {
		t.Fatalf("per-subject read: %+v", resp)
	}

	// A different subject inherits the whole-stream status.
	resp, err = store.GetStreamStatus(ctx, cfg.StreamID, subj2)
	if err != nil {
		t.Fatalf("GetStreamStatus(subj2): %v", err)
	}
	if resp.Status != ssf.StreamStatusEnabled {
		t.Fatalf("subj2 inherited status: got %q, want %q", resp.Status, ssf.StreamStatusEnabled)
	}
}

func TestStreamStatusSubjectCanonicalization(t *testing.T) {
	t.Parallel()

	store := memstore.NewInMemoryStore()
	ctx := context.Background()

	cfg, err := store.CreateStream(ctx, newTestStream())
	if err != nil {
		t.Fatalf("CreateStream: %v", err)
	}

	// Same subject, two different on-wire encodings (key order +
	// whitespace). The store should treat them as one.
	subjOrderA := json.RawMessage(`{"format":"opaque","id":"alice"}`)
	subjOrderB := json.RawMessage(`{ "id" : "alice" , "format" : "opaque" }`)

	upd := &ssf.StatusUpdateRequest{
		Status:  ssf.StreamStatusPaused,
		Subject: subjOrderA,
	}
	if _, err := store.SetStreamStatus(ctx, cfg.StreamID, upd); err != nil {
		t.Fatalf("SetStreamStatus: %v", err)
	}

	resp, err := store.GetStreamStatus(ctx, cfg.StreamID, subjOrderB)
	if err != nil {
		t.Fatalf("GetStreamStatus (alt encoding): %v", err)
	}
	if resp.Status != ssf.StreamStatusPaused {
		t.Fatalf("canonicalization failed: got %q, want %q", resp.Status, ssf.StreamStatusPaused)
	}
}

func TestStreamStatusMissingStream(t *testing.T) {
	t.Parallel()

	store := memstore.NewInMemoryStore()
	ctx := context.Background()

	if _, err := store.GetStreamStatus(ctx, "missing", nil); !errors.Is(err, ssf.ErrStreamNotFound) {
		t.Fatalf("GetStreamStatus(missing): want ErrStreamNotFound, got %v", err)
	}
	upd := &ssf.StatusUpdateRequest{Status: ssf.StreamStatusEnabled}
	if _, err := store.SetStreamStatus(ctx, "missing", upd); !errors.Is(err, ssf.ErrStreamNotFound) {
		t.Fatalf("SetStreamStatus(missing): want ErrStreamNotFound, got %v", err)
	}
}

func TestAddRemoveSubjectRoundTrip(t *testing.T) {
	t.Parallel()

	store := memstore.NewInMemoryStore()
	ctx := context.Background()

	cfg, err := store.CreateStream(ctx, newTestStream())
	if err != nil {
		t.Fatalf("CreateStream: %v", err)
	}

	subj := newTestSubject(t, "alice")
	addReq := &ssf.AddSubjectRequest{Subject: subj}

	if err := store.AddSubject(ctx, cfg.StreamID, addReq); err != nil {
		t.Fatalf("AddSubject: %v", err)
	}

	has, err := store.HasSubject(cfg.StreamID, subj)
	if err != nil {
		t.Fatalf("HasSubject: %v", err)
	}
	if !has {
		t.Fatalf("HasSubject: want true after AddSubject")
	}

	// Re-add is a no-op.
	if err := store.AddSubject(ctx, cfg.StreamID, addReq); err != nil {
		t.Fatalf("AddSubject (re-add): %v", err)
	}

	removeReq := &ssf.RemoveSubjectRequest{Subject: subj}
	if err := store.RemoveSubject(ctx, cfg.StreamID, removeReq); err != nil {
		t.Fatalf("RemoveSubject: %v", err)
	}

	has, err = store.HasSubject(cfg.StreamID, subj)
	if err != nil {
		t.Fatalf("HasSubject (post-remove): %v", err)
	}
	if has {
		t.Fatalf("HasSubject: want false after RemoveSubject")
	}

	// Re-remove is a no-op.
	if err := store.RemoveSubject(ctx, cfg.StreamID, removeReq); err != nil {
		t.Fatalf("RemoveSubject (re-remove): %v", err)
	}
}

func TestAddSubjectMissingStream(t *testing.T) {
	t.Parallel()

	store := memstore.NewInMemoryStore()
	subj := newTestSubject(t, "alice")
	err := store.AddSubject(context.Background(), "missing", &ssf.AddSubjectRequest{Subject: subj})
	if !errors.Is(err, ssf.ErrStreamNotFound) {
		t.Fatalf("AddSubject(missing): want ErrStreamNotFound, got %v", err)
	}
}

func TestRemoveSubjectMissingStream(t *testing.T) {
	t.Parallel()

	store := memstore.NewInMemoryStore()
	subj := newTestSubject(t, "alice")
	err := store.RemoveSubject(context.Background(), "missing", &ssf.RemoveSubjectRequest{Subject: subj})
	if !errors.Is(err, ssf.ErrStreamNotFound) {
		t.Fatalf("RemoveSubject(missing): want ErrStreamNotFound, got %v", err)
	}
}

func TestAddSubjectNilRequestRejected(t *testing.T) {
	t.Parallel()

	store := memstore.NewInMemoryStore()
	ctx := context.Background()
	cfg, err := store.CreateStream(ctx, newTestStream())
	if err != nil {
		t.Fatalf("CreateStream: %v", err)
	}
	if err := store.AddSubject(ctx, cfg.StreamID, nil); !errors.Is(err, ssf.ErrInvalidConfig) {
		t.Fatalf("AddSubject(nil): want ErrInvalidConfig, got %v", err)
	}
	if err := store.RemoveSubject(ctx, cfg.StreamID, nil); !errors.Is(err, ssf.ErrInvalidConfig) {
		t.Fatalf("RemoveSubject(nil): want ErrInvalidConfig, got %v", err)
	}
}

func TestEnqueueAndDrainSETs(t *testing.T) {
	t.Parallel()

	store := memstore.NewInMemoryStore()
	ctx := context.Background()

	cfg, err := store.CreateStream(ctx, newTestStream())
	if err != nil {
		t.Fatalf("CreateStream: %v", err)
	}

	tokens := []string{"jws.one.aaa", "jws.two.bbb", "jws.three.ccc"}
	for _, tok := range tokens {
		if err := store.EnqueueSET(ctx, cfg.StreamID, tok); err != nil {
			t.Fatalf("EnqueueSET %q: %v", tok, err)
		}
	}

	got, err := store.QueuedSETs(cfg.StreamID)
	if err != nil {
		t.Fatalf("QueuedSETs: %v", err)
	}
	if len(got) != len(tokens) {
		t.Fatalf("QueuedSETs: got %d, want %d", len(got), len(tokens))
	}
	for i, tok := range tokens {
		if got[i] != tok {
			t.Fatalf("QueuedSETs[%d]: got %q, want %q (FIFO order broken)", i, got[i], tok)
		}
	}
}

func TestEnqueueSETMissingStream(t *testing.T) {
	t.Parallel()

	store := memstore.NewInMemoryStore()
	err := store.EnqueueSET(context.Background(), "missing", "jws.x.y")
	if !errors.Is(err, ssf.ErrStreamNotFound) {
		t.Fatalf("EnqueueSET(missing): want ErrStreamNotFound, got %v", err)
	}
}

// TestConcurrentAccess exercises the mutex by hammering the store
// from two goroutines on the same set of streams. Running this under
// `go test -race -shuffle=on` is the actual assertion — the body's
// explicit checks only confirm the operations succeed; the race
// detector catches any unsynchronized map access.
func TestConcurrentAccess(t *testing.T) {
	t.Parallel()

	store := memstore.NewInMemoryStore()
	ctx := context.Background()

	// Seed a small set of streams so the workers have something to
	// hit besides each other's allocations.
	const seedStreams = 4
	ids := make([]string, seedStreams)
	for i := range seedStreams {
		cfg := newTestStream()
		cfg.StreamID = fmt.Sprintf("seed-%d", i)
		if _, err := store.CreateStream(ctx, cfg); err != nil {
			t.Fatalf("CreateStream seed-%d: %v", i, err)
		}
		ids[i] = cfg.StreamID
	}

	const workers = 2
	const opsPerWorker = 100

	var wg sync.WaitGroup

	for w := range workers {
		workerID := w
		wg.Go(func() {
			subj := newTestSubject(t, fmt.Sprintf("u-%d", workerID))
			for i := range opsPerWorker {
				streamID := ids[(workerID+i)%len(ids)]

				// CRUD mix that touches every method covered by the
				// mutex.
				if _, err := store.GetStream(ctx, streamID); err != nil {
					t.Errorf("worker %d: GetStream: %v", workerID, err)
					return
				}
				if _, _, err := store.ListStreams(ctx, ""); err != nil {
					t.Errorf("worker %d: ListStreams: %v", workerID, err)
					return
				}
				if _, err := store.GetStreamStatus(ctx, streamID, nil); err != nil {
					t.Errorf("worker %d: GetStreamStatus: %v", workerID, err)
					return
				}
				upd := &ssf.StatusUpdateRequest{Status: ssf.StreamStatusEnabled}
				if _, err := store.SetStreamStatus(ctx, streamID, upd); err != nil {
					t.Errorf("worker %d: SetStreamStatus: %v", workerID, err)
					return
				}
				if err := store.AddSubject(ctx, streamID, &ssf.AddSubjectRequest{Subject: subj}); err != nil {
					t.Errorf("worker %d: AddSubject: %v", workerID, err)
					return
				}
				if err := store.RemoveSubject(ctx, streamID, &ssf.RemoveSubjectRequest{Subject: subj}); err != nil {
					t.Errorf("worker %d: RemoveSubject: %v", workerID, err)
					return
				}
				if err := store.EnqueueSET(ctx, streamID, fmt.Sprintf("jws.%d.%d", workerID, i)); err != nil {
					t.Errorf("worker %d: EnqueueSET: %v", workerID, err)
					return
				}
			}
		})
	}

	wg.Wait()
}

// TestImplementsStreamStore pins the interface satisfaction from
// outside the memstore package. The assignment alone is the
// compile-time assertion; the runtime call exercises one method to
// confirm the dispatch through the interface vtable works as expected.
func TestImplementsStreamStore(t *testing.T) {
	t.Parallel()

	var iface ssf.StreamStore = memstore.NewInMemoryStore()
	if _, _, err := iface.ListStreams(context.Background(), ""); err != nil {
		t.Fatalf("ListStreams via interface: %v", err)
	}
}
