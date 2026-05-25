// Copyright 2026 The go-ssf Authors
// SPDX-License-Identifier: Apache-2.0

// Package memstore provides an in-memory [ssf.StreamStore] for tests,
// demos, and the conformance harness. It satisfies the full
// [ssf.StreamStore] contract — streams CRUD, lifecycle status,
// subject membership, and the poll-mode SET queue — using a single
// mutex around a small set of Go maps. Correctness over throughput.
//
// The implementation is intentionally simple: every method takes the
// store's mutex for the whole call, allocates new value copies for
// returned [*ssf.StreamConfig] / [*ssf.StatusResponse] pointers so
// callers cannot mutate stored state by holding the returned pointer,
// and assigns stream IDs by counting upward. None of these choices
// scale; they exist to keep the in-memory store readable and to make
// concurrent access provably safe under `go test -race`. Production
// stores plug into the same interface with their own backends (SQL,
// Redis, etc.); none ship in this repository per the design notes.
package memstore

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"slices"
	"sync"

	ssf "github.com/hstern/go-ssf"
)

// InMemoryStore is the in-memory [ssf.StreamStore] implementation. The
// zero value is not ready for use; obtain an instance through
// [NewInMemoryStore].
//
// Field shape:
//
//   - streams maps stream_id to the stored [*ssf.StreamConfig].
//   - statuses maps stream_id to a nested map keyed by the canonical
//     JSON form of the per-subject scope. The empty-string key holds
//     the whole-stream status; non-empty keys hold per-subject statuses
//     keyed by canonical Subject Identifier JSON bytes.
//   - subjects maps stream_id to the set of canonical Subject
//     Identifier strings currently registered against the stream.
//   - queues maps stream_id to the FIFO of JWS compact serializations
//     waiting on the poll endpoint.
//   - nextID is the source of monotonically increasing default
//     stream_id values for streams the caller submits without one;
//     it is paired with a short random suffix so two instances of the
//     store do not collide on identical IDs when used together.
type InMemoryStore struct {
	mu sync.Mutex

	streams  map[string]*ssf.StreamConfig
	statuses map[string]map[string]*ssf.StatusResponse
	subjects map[string]map[string]struct{}
	queues   map[string][]string

	nextID int
	idSeed string
}

// Compile-time assertion that the in-memory store satisfies the
// interface it claims to implement. Placed at file scope so a future
// interface change surfaces here at build time.
var _ ssf.StreamStore = (*InMemoryStore)(nil)

// NewInMemoryStore returns a fresh in-memory [ssf.StreamStore] with
// every internal map allocated and ready for use. The returned store
// is safe for concurrent use by multiple goroutines.
//
// The store seeds its default stream-ID generator from a short
// crypto/rand suffix so two stores in the same process don't mint
// identical default IDs (a real concern in table-driven tests that
// spin up several stores in parallel). The seed is opaque; callers
// MUST NOT depend on its format.
func NewInMemoryStore() *InMemoryStore {
	var seedBytes [4]byte
	_, _ = rand.Read(seedBytes[:])
	return &InMemoryStore{
		streams:  make(map[string]*ssf.StreamConfig),
		statuses: make(map[string]map[string]*ssf.StatusResponse),
		subjects: make(map[string]map[string]struct{}),
		queues:   make(map[string][]string),
		idSeed:   hex.EncodeToString(seedBytes[:]),
	}
}

// CreateStream stores a copy of cfg and returns the stored value. When
// [ssf.StreamConfig.StreamID] is empty the store assigns one of the
// form "stream-<seed>-<n>"; when the caller supplies a StreamID that
// is already in use the call returns [ssf.ErrInvalidConfig] — the
// interface contract does not pin a sentinel for the duplicate-ID
// case, and reusing ErrInvalidConfig matches the spec's 400-on-bad-
// request mapping.
func (s *InMemoryStore) CreateStream(_ context.Context, cfg *ssf.StreamConfig) (*ssf.StreamConfig, error) {
	if cfg == nil {
		return nil, fmt.Errorf("memstore: CreateStream: %w: nil config", ssf.ErrInvalidConfig)
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	id := cfg.StreamID
	if id == "" {
		s.nextID++
		id = fmt.Sprintf("stream-%s-%d", s.idSeed, s.nextID)
	} else if _, exists := s.streams[id]; exists {
		return nil, fmt.Errorf("memstore: CreateStream %q: %w: stream_id already in use", id, ssf.ErrInvalidConfig)
	}

	stored := cloneStreamConfig(cfg)
	stored.StreamID = id
	s.streams[id] = stored
	s.statuses[id] = map[string]*ssf.StatusResponse{
		"": {Status: ssf.StreamStatusEnabled},
	}
	s.subjects[id] = make(map[string]struct{})
	s.queues[id] = nil

	return cloneStreamConfig(stored), nil
}

// GetStream returns a copy of the stored configuration. The returned
// pointer is independent of the store; callers may mutate it freely.
func (s *InMemoryStore) GetStream(_ context.Context, streamID string) (*ssf.StreamConfig, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	cfg, ok := s.streams[streamID]
	if !ok {
		return nil, fmt.Errorf("memstore: GetStream %q: %w", streamID, ssf.ErrStreamNotFound)
	}
	return cloneStreamConfig(cfg), nil
}

// ListStreams returns every stored stream in a single page, sorted by
// stream_id for stable iteration, and an empty continuation token.
// The pageToken argument is accepted (per the interface contract) but
// ignored — the in-memory store does not partition into pages. A
// real-store backend implementing the same interface would pick a
// page size that matches its backing index.
func (s *InMemoryStore) ListStreams(_ context.Context, _ string) ([]*ssf.StreamConfig, string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	ids := make([]string, 0, len(s.streams))
	for id := range s.streams {
		ids = append(ids, id)
	}
	slices.Sort(ids)

	out := make([]*ssf.StreamConfig, 0, len(ids))
	for _, id := range ids {
		out = append(out, cloneStreamConfig(s.streams[id]))
	}
	return out, "", nil
}

// UpdateStream replaces the stored configuration for cfg.StreamID. It
// returns [ssf.ErrStreamNotFound] when no stream with that ID exists.
// The stored value is a fresh copy of cfg; the caller's pointer is
// not retained.
func (s *InMemoryStore) UpdateStream(_ context.Context, cfg *ssf.StreamConfig) (*ssf.StreamConfig, error) {
	if cfg == nil {
		return nil, fmt.Errorf("memstore: UpdateStream: %w: nil config", ssf.ErrInvalidConfig)
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	if _, ok := s.streams[cfg.StreamID]; !ok {
		return nil, fmt.Errorf("memstore: UpdateStream %q: %w", cfg.StreamID, ssf.ErrStreamNotFound)
	}
	stored := cloneStreamConfig(cfg)
	s.streams[cfg.StreamID] = stored
	return cloneStreamConfig(stored), nil
}

// DeleteStream removes the stream and every piece of state associated
// with it. It is idempotent — a missing stream is not an error.
func (s *InMemoryStore) DeleteStream(_ context.Context, streamID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	delete(s.streams, streamID)
	delete(s.statuses, streamID)
	delete(s.subjects, streamID)
	delete(s.queues, streamID)
	return nil
}

// GetStreamStatus returns the stream's lifecycle status. When subject
// is non-empty the response is scoped to that subject; when subject
// is empty the response is the whole-stream status. The store returns
// [ssf.ErrStreamNotFound] when the stream is absent. A per-subject
// status that has never been set explicitly inherits the whole-stream
// status — the spec is silent on the inheritance question and
// inheriting matches the principle of least surprise for callers who
// only ever set whole-stream state.
func (s *InMemoryStore) GetStreamStatus(_ context.Context, streamID string, subject json.RawMessage) (*ssf.StatusResponse, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	bucket, ok := s.statuses[streamID]
	if !ok {
		return nil, fmt.Errorf("memstore: GetStreamStatus %q: %w", streamID, ssf.ErrStreamNotFound)
	}

	key, err := canonicalSubjectKey(subject)
	if err != nil {
		return nil, fmt.Errorf("memstore: GetStreamStatus %q: %w", streamID, err)
	}

	if resp, ok := bucket[key]; ok {
		return cloneStatusResponse(resp), nil
	}
	// Fall back to whole-stream status if a per-subject view has not
	// been recorded.
	if resp, ok := bucket[""]; ok {
		out := cloneStatusResponse(resp)
		out.Subject = cloneRaw(subject)
		return out, nil
	}
	// A stream with no recorded status defaults to enabled; this
	// branch is reachable only if a future code path forgets to seed
	// the whole-stream entry on create, but defending against it is
	// cheap.
	return &ssf.StatusResponse{Status: ssf.StreamStatusEnabled, Subject: cloneRaw(subject)}, nil
}

// SetStreamStatus records the transition and returns the resulting
// status. The store accepts the requested state verbatim — the
// Transmitter HTTP layer is the right place for any spec-level
// validation that might refuse or delay the transition. When
// [ssf.StatusUpdateRequest.Subject] is non-empty the change is scoped
// to that subject within the stream.
func (s *InMemoryStore) SetStreamStatus(_ context.Context, streamID string, req *ssf.StatusUpdateRequest) (*ssf.StatusResponse, error) {
	if req == nil {
		return nil, fmt.Errorf("memstore: SetStreamStatus %q: %w: nil request", streamID, ssf.ErrInvalidConfig)
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	bucket, ok := s.statuses[streamID]
	if !ok {
		return nil, fmt.Errorf("memstore: SetStreamStatus %q: %w", streamID, ssf.ErrStreamNotFound)
	}

	key, err := canonicalSubjectKey(req.Subject)
	if err != nil {
		return nil, fmt.Errorf("memstore: SetStreamStatus %q: %w", streamID, err)
	}

	resp := &ssf.StatusResponse{
		Status:  req.Status,
		Reason:  req.Reason,
		Subject: cloneRaw(req.Subject),
	}
	bucket[key] = resp
	return cloneStatusResponse(resp), nil
}

// AddSubject records the subject as a member of the stream's active
// set. The operation is idempotent: re-adding an existing subject is
// a no-op. The store returns [ssf.ErrStreamNotFound] when the stream
// does not exist.
func (s *InMemoryStore) AddSubject(_ context.Context, streamID string, req *ssf.AddSubjectRequest) error {
	if req == nil {
		return fmt.Errorf("memstore: AddSubject %q: %w: nil request", streamID, ssf.ErrInvalidConfig)
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	set, ok := s.subjects[streamID]
	if !ok {
		return fmt.Errorf("memstore: AddSubject %q: %w", streamID, ssf.ErrStreamNotFound)
	}
	key, err := canonicalSubjectKeyFromIdentifier(req.Subject)
	if err != nil {
		return fmt.Errorf("memstore: AddSubject %q: %w", streamID, err)
	}
	set[key] = struct{}{}
	return nil
}

// RemoveSubject removes the subject from the stream's active set. The
// operation is idempotent: removing an absent subject is a no-op. The
// store returns [ssf.ErrStreamNotFound] when the stream does not exist.
func (s *InMemoryStore) RemoveSubject(_ context.Context, streamID string, req *ssf.RemoveSubjectRequest) error {
	if req == nil {
		return fmt.Errorf("memstore: RemoveSubject %q: %w: nil request", streamID, ssf.ErrInvalidConfig)
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	set, ok := s.subjects[streamID]
	if !ok {
		return fmt.Errorf("memstore: RemoveSubject %q: %w", streamID, ssf.ErrStreamNotFound)
	}
	key, err := canonicalSubjectKeyFromIdentifier(req.Subject)
	if err != nil {
		return fmt.Errorf("memstore: RemoveSubject %q: %w", streamID, err)
	}
	delete(set, key)
	return nil
}

// EnqueueSET appends jwsCompact to the stream's poll-mode queue. The
// store returns [ssf.ErrStreamNotFound] when the stream does not
// exist. The token is treated as opaque — the store does not verify
// or parse it.
func (s *InMemoryStore) EnqueueSET(_ context.Context, streamID, jwsCompact string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if _, ok := s.streams[streamID]; !ok {
		return fmt.Errorf("memstore: EnqueueSET %q: %w", streamID, ssf.ErrStreamNotFound)
	}
	s.queues[streamID] = append(s.queues[streamID], jwsCompact)
	return nil
}

// HasSubject reports whether the given subject is currently a member
// of the stream's active set. It is exported as a helper for tests
// and demos that want to inspect membership without going through the
// (write-only) [InMemoryStore.AddSubject] and
// [InMemoryStore.RemoveSubject] surface. The method is not part of
// the [ssf.StreamStore] interface; it is store-local introspection.
//
// HasSubject returns (false, [ssf.ErrStreamNotFound]) when the stream
// does not exist. The subject argument may be either an
// [ssf.AddSubjectRequest], a JSON-marshalable Subject Identifier, or
// raw JSON bytes ([]byte / [json.RawMessage]); see
// canonicalSubjectKeyFromIdentifier for the dispatch.
func (s *InMemoryStore) HasSubject(streamID string, subject any) (bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	set, ok := s.subjects[streamID]
	if !ok {
		return false, fmt.Errorf("memstore: HasSubject %q: %w", streamID, ssf.ErrStreamNotFound)
	}
	key, err := canonicalSubjectKeyFromAny(subject)
	if err != nil {
		return false, fmt.Errorf("memstore: HasSubject %q: %w", streamID, err)
	}
	_, found := set[key]
	return found, nil
}

// QueuedSETs returns a copy of the stream's current poll-mode queue.
// The queue is FIFO in append order. The returned slice is
// independent of the store. It is exported as a helper for tests and
// demos; the drain side of the queue lands with the poll handler in
// a later phase, which will own a paired Drain / Ack pair on the
// interface.
//
// QueuedSETs returns (nil, [ssf.ErrStreamNotFound]) when the stream
// does not exist.
func (s *InMemoryStore) QueuedSETs(streamID string) ([]string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if _, ok := s.streams[streamID]; !ok {
		return nil, fmt.Errorf("memstore: QueuedSETs %q: %w", streamID, ssf.ErrStreamNotFound)
	}
	q := s.queues[streamID]
	out := make([]string, len(q))
	copy(out, q)
	return out, nil
}

// cloneStreamConfig returns a deep-enough copy of cfg that the caller
// cannot mutate stored state by holding the returned pointer. Slices
// and the [json.RawMessage] Aud field are duplicated; the embedded
// [ssf.Delivery] is a value type and copies cleanly via assignment.
func cloneStreamConfig(cfg *ssf.StreamConfig) *ssf.StreamConfig {
	if cfg == nil {
		return nil
	}
	out := *cfg
	out.Aud = cloneRaw(cfg.Aud)
	out.EventsSupported = cloneStrings(cfg.EventsSupported)
	out.EventsRequested = cloneStrings(cfg.EventsRequested)
	out.EventsDelivered = cloneStrings(cfg.EventsDelivered)
	return &out
}

// cloneStatusResponse returns an independent copy of resp.
func cloneStatusResponse(resp *ssf.StatusResponse) *ssf.StatusResponse {
	if resp == nil {
		return nil
	}
	out := *resp
	out.Subject = cloneRaw(resp.Subject)
	return &out
}

// cloneRaw returns an independent copy of a [json.RawMessage] slice.
// A nil or empty input returns nil so the result round-trips through
// the omitempty JSON tags identically.
func cloneRaw(raw json.RawMessage) json.RawMessage {
	if len(raw) == 0 {
		return nil
	}
	out := make(json.RawMessage, len(raw))
	copy(out, raw)
	return out
}

// cloneStrings returns an independent copy of a []string.
func cloneStrings(in []string) []string {
	if in == nil {
		return nil
	}
	out := make([]string, len(in))
	copy(out, in)
	return out
}

// canonicalSubjectKey returns the canonical-JSON form of a
// [json.RawMessage] subject for use as a map key. An empty or nil
// input returns the empty string, which is the conventional key for
// the whole-stream (non-per-subject) view. Non-empty input must be a
// valid JSON value; the function returns [ssf.ErrInvalidConfig]
// wrapping the parse error otherwise.
//
// Canonicalization recurses through JSON objects sorting member keys
// lexicographically and re-encoding via [encoding/json.Marshal].
// Arrays and primitives pass through after a parse round-trip. The
// result is byte-stable: two semantically equivalent inputs produce
// the same string regardless of input whitespace or object-key order.
func canonicalSubjectKey(raw json.RawMessage) (string, error) {
	if len(raw) == 0 {
		return "", nil
	}
	var v any
	if err := json.Unmarshal(raw, &v); err != nil {
		return "", fmt.Errorf("%w: subject is not valid JSON: %v", ssf.ErrInvalidConfig, err)
	}
	out, err := json.Marshal(v)
	if err != nil {
		return "", fmt.Errorf("%w: canonicalize subject: %v", ssf.ErrInvalidConfig, err)
	}
	return string(out), nil
}

// canonicalSubjectKeyFromIdentifier renders a typed Subject Identifier
// to its canonical-JSON form via [encoding/json.Marshal], then folds
// it through [canonicalSubjectKey] for key-order normalization. A nil
// identifier returns an error wrapping [ssf.ErrInvalidConfig] — the
// add and remove subject flows both require a non-nil subject per
// spec §7.1.3.
func canonicalSubjectKeyFromIdentifier(subj any) (string, error) {
	if subj == nil {
		return "", fmt.Errorf("%w: subject is required", ssf.ErrInvalidConfig)
	}
	raw, err := json.Marshal(subj)
	if err != nil {
		return "", fmt.Errorf("%w: marshal subject: %v", ssf.ErrInvalidConfig, err)
	}
	return canonicalSubjectKey(raw)
}

// canonicalSubjectKeyFromAny accepts any of the shapes a caller might
// hold for a subject — raw bytes, an [ssf.AddSubjectRequest], an
// [ssf.RemoveSubjectRequest], or a typed Subject Identifier — and
// returns the canonical key. The dispatch is helper-only and only
// covers shapes the exported HasSubject method advertises; other
// inputs fall through to [encoding/json.Marshal] of the value itself.
func canonicalSubjectKeyFromAny(v any) (string, error) {
	switch t := v.(type) {
	case nil:
		return "", fmt.Errorf("%w: subject is required", ssf.ErrInvalidConfig)
	case json.RawMessage:
		return canonicalSubjectKey(t)
	case []byte:
		return canonicalSubjectKey(t)
	case *ssf.AddSubjectRequest:
		if t == nil {
			return "", fmt.Errorf("%w: subject is required", ssf.ErrInvalidConfig)
		}
		return canonicalSubjectKeyFromIdentifier(t.Subject)
	case *ssf.RemoveSubjectRequest:
		if t == nil {
			return "", fmt.Errorf("%w: subject is required", ssf.ErrInvalidConfig)
		}
		return canonicalSubjectKeyFromIdentifier(t.Subject)
	default:
		return canonicalSubjectKeyFromIdentifier(t)
	}
}
