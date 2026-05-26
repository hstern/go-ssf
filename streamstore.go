// Copyright 2026 The go-ssf Authors
// SPDX-License-Identifier: Apache-2.0

package ssf

import (
	"context"
	"encoding/json"
)

// StreamStore is the persistence boundary every Transmitter implementation
// sits on top of per OpenID Shared Signals Framework 1.0 §7.1. The
// Transmitter HTTP handlers translate request bodies into typed
// arguments and route the work through this interface; the store owns
// the mapping from stream identifiers to configuration, lifecycle
// state, subject membership, and queued Security Event Tokens awaiting
// poll-mode delivery.
//
// The interface is small but covers every persistent surface the spec
// exposes:
//
//   - Streams CRUD — [StreamStore.CreateStream],
//     [StreamStore.GetStream], [StreamStore.ListStreams],
//     [StreamStore.UpdateStream], [StreamStore.DeleteStream].
//   - Per-stream status — [StreamStore.GetStreamStatus],
//     [StreamStore.SetStreamStatus]. Status can be scoped to a single
//     subject within the stream rather than the stream as a whole; the
//     [StatusResponse.Subject] and [StatusUpdateRequest.Subject] fields
//     carry the optional discriminator verbatim.
//   - Subject membership — [StreamStore.AddSubject],
//     [StreamStore.RemoveSubject].
//   - Poll-mode queue — [StreamStore.EnqueueSET]. Drain semantics for
//     the queue land alongside the poll-mode wiring in a later phase;
//     this interface intentionally records only the enqueue side so the
//     Transmitter handlers have a stable seam to call into today.
//
// Error contract. Methods named after a single resource return
// [ErrStreamNotFound] when the referenced stream does not exist. Delete
// is the exception: it MUST be idempotent (no error when the stream is
// absent) to match the HTTP DELETE idiom and to keep clients out of
// retry loops on transient duplicates. Implementations MUST wrap any
// transport- or storage-layer error so that [errors.Is] against the
// sentinels above still matches.
//
// Concurrency. Every method takes a [context.Context] and MAY be
// called concurrently from multiple goroutines. Implementations choose
// their own locking; the in-tree [github.com/hstern/go-ssf/memstore]
// implementation uses a single mutex (correctness over throughput,
// suited to tests and demos).
//
// Pagination. [StreamStore.ListStreams] uses an opaque page-token
// cursor: an empty token selects the first page, and the returned
// nextToken is empty when the cursor is exhausted. The token format
// is implementation-defined; callers MUST NOT inspect or construct
// tokens, only echo them back verbatim. The interface deliberately
// does not commit to a page-size argument — implementations pick a
// default that matches their backing store's natural batch size, and
// add a typed option in a follow-up if a caller surfaces a need.
type StreamStore interface {
	// CreateStream persists a new stream configuration and returns the
	// stored value. The store assigns [StreamConfig.StreamID] when the
	// caller leaves it empty; an implementation MAY accept a caller-
	// supplied StreamID for migrations or fixtures, but the canonical
	// flow has the store mint it. The returned [*StreamConfig] is the
	// authoritative post-create view (including any server-set fields
	// such as EventsDelivered).
	CreateStream(ctx context.Context, cfg *StreamConfig) (*StreamConfig, error)

	// GetStream returns the stored configuration for streamID. The
	// store MUST return [ErrStreamNotFound] when no such stream exists.
	// The returned pointer is owned by the caller and SHOULD NOT alias
	// internal storage — implementations either copy on read or
	// document the aliasing constraint explicitly.
	GetStream(ctx context.Context, streamID string) (*StreamConfig, error)

	// ListStreams returns a page of stored stream configurations and
	// an opaque continuation cursor. An empty pageToken selects the
	// first page; an empty nextToken in the return signals the final
	// page. Implementations are free to return all streams in a single
	// page (and an empty nextToken) until the volume warrants pagination.
	ListStreams(ctx context.Context, pageToken string) (configs []*StreamConfig, nextToken string, err error)

	// UpdateStream replaces the stored configuration for the stream
	// named by [StreamConfig.StreamID]. The store MUST return
	// [ErrStreamNotFound] when no stream with that ID exists; it MUST
	// NOT create a stream as a side effect of update. The returned
	// [*StreamConfig] is the post-update view.
	UpdateStream(ctx context.Context, cfg *StreamConfig) (*StreamConfig, error)

	// DeleteStream removes the stream with the given ID. It is
	// idempotent: a missing stream is not an error. This matches the
	// HTTP DELETE idiom and lets clients retry on network failures
	// without distinguishing "succeeded once" from "already gone".
	DeleteStream(ctx context.Context, streamID string) error

	// GetStreamStatus returns the lifecycle status for the stream.
	// When subject is non-empty, the returned status is scoped to that
	// subject within the stream rather than the stream as a whole per
	// spec §7.1.2; when subject is empty the response is the whole-
	// stream status. The store MUST return [ErrStreamNotFound] when
	// the stream does not exist. The subject parameter is the verbatim
	// Subject Identifier JSON bytes — the store compares them as JSON
	// values, not byte-equal strings, so semantically equivalent
	// encodings (whitespace, key order on the inner subject members)
	// resolve to the same per-subject entry.
	GetStreamStatus(ctx context.Context, streamID string, subject json.RawMessage) (*StatusResponse, error)

	// SetStreamStatus applies the requested lifecycle transition and
	// returns the resulting status. The Transmitter MAY honor, delay,
	// or refuse the request per spec §7.1.2; the store records the
	// outcome the Transmitter chose. When [StatusUpdateRequest.Subject]
	// is non-empty the update is scoped to that subject within the
	// stream. The store MUST return [ErrStreamNotFound] when the
	// stream does not exist.
	SetStreamStatus(ctx context.Context, streamID string, req *StatusUpdateRequest) (*StatusResponse, error)

	// AddSubject records the subject as a member of the stream's
	// active set, after which the Transmitter MAY emit SETs about it.
	// The store MUST return [ErrStreamNotFound] when the stream does
	// not exist. Adding a subject that is already a member is a no-op
	// and MUST NOT return an error — the operation is idempotent at
	// the store boundary for the same reasons DELETE is.
	AddSubject(ctx context.Context, streamID string, req *AddSubjectRequest) error

	// RemoveSubject removes the subject from the stream's active set.
	// The store MUST return [ErrStreamNotFound] when the stream does
	// not exist. Removing a subject that is not a member is a no-op
	// and MUST NOT return an error; idempotence again matches the
	// HTTP DELETE shape the Transmitter's subjects endpoint exposes.
	RemoveSubject(ctx context.Context, streamID string, req *RemoveSubjectRequest) error

	// EnqueueSET appends a signed SET (in JWS compact serialization)
	// to the stream's poll-mode queue. The Transmitter calls this when
	// it generates an event for a poll-delivery stream; the matching
	// drain side lands with the poll handler in a later phase. The
	// store MUST return [ErrStreamNotFound] when the stream does not
	// exist. The jwsCompact argument is treated as an opaque token —
	// the store does not parse or verify it.
	EnqueueSET(ctx context.Context, streamID, jwsCompact string) error
}
