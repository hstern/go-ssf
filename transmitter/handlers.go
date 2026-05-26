// Copyright 2026 The go-ssf Authors
// SPDX-License-Identifier: Apache-2.0

package transmitter

// This file declares the per-endpoint [net/http.Handler] constructors
// that translate OpenID Shared Signals Framework 1.0 §7.1 wire
// requests into [Transmitter] method calls and render the responses
// back onto the wire. Each constructor takes a [Transmitter] and an
// [AuthFunc]; the returned handler runs auth, decodes the request,
// invokes the [Transmitter] method, and writes either a JSON success
// body or an RFC 7807 problem-details JSON error.
//
// Error mapping is centralized in [writeProblem]; the per-handler
// code stays focused on request shape and routing.

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"

	"github.com/hstern/go-ssf"
)

// contentTypeJSON is the Content-Type emitted on every 2xx JSON
// success response, per spec §7. The charset is pinned at marshal
// time — Go's [encoding/json] always produces UTF-8 — so a Receiver
// using a strict parser does not have to guess.
const contentTypeJSON = "application/json; charset=utf-8"

// contentTypeProblem is the RFC 7807 problem-details media type used
// on every non-2xx response. Spec §7 mandates this media type for
// Transmitter error responses; the library uses it uniformly even on
// errors the spec does not explicitly enumerate (e.g. 405) so that
// consumers parsing the body get one stable shape.
const contentTypeProblem = "application/problem+json"

// ConfigHandler returns an [http.Handler] that serves the stream
// configuration endpoint per OpenID Shared Signals Framework 1.0
// §7.1.1. The handler multiplexes on HTTP method and on the presence
// of the stream_id query parameter:
//
//   - GET without stream_id calls [Transmitter.ListConfig] and
//     returns the page of stream configurations as a JSON array.
//     The page_token query parameter, when present, requests the
//     named continuation page; the response carries the next token
//     in a JSON envelope (see the wire shape below).
//   - GET with stream_id calls [Transmitter.GetConfig] and returns
//     the single [ssf.StreamConfig].
//   - POST decodes the body as [ssf.StreamConfig] and calls
//     [Transmitter.CreateConfig]. The server-assigned representation
//     is returned with status 201 Created.
//   - PATCH with stream_id decodes the body as [ssf.StreamConfig],
//     sets [ssf.StreamConfig.StreamID] from the query, and calls
//     [Transmitter.UpdateConfig]. The post-update representation is
//     returned with status 200.
//   - DELETE with stream_id calls [Transmitter.DeleteConfig] and
//     returns 204 No Content on success.
//
// Other methods receive 405 Method Not Allowed with an Allow header
// listing GET, POST, PATCH, DELETE.
//
// auth is invoked before any body is read. A non-nil error from auth
// turns into a 401 problem-details response via [writeAuthProblem];
// the returned [StreamScope] is currently advisory — handler code
// does not enforce per-stream restrictions, since the spec leaves
// the binding between credential and stream to the consumer's auth
// scheme. A consumer that wants stream-scope enforcement wraps
// [AuthFunc] to inspect the request URL and return [StreamScope]
// with [StreamScope.StreamID] set; future helpers may surface that
// value through the request context.
//
// List response shape:
//
//	{"streams": [ { ...StreamConfig... }, ... ], "next_page_token": "..."}
//
// next_page_token is omitted when [Transmitter.ListConfig] returns an
// empty continuation token.
func ConfigHandler(t Transmitter, auth AuthFunc) http.Handler {
	const allow = "GET, POST, PATCH, DELETE"
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !runAuth(w, r, auth) {
			return
		}

		streamID := r.URL.Query().Get("stream_id")

		switch r.Method {
		case http.MethodGet:
			if streamID == "" {
				handleListConfig(w, r, t)
				return
			}
			handleGetConfig(w, r, t, streamID)
		case http.MethodPost:
			handleCreateConfig(w, r, t)
		case http.MethodPatch:
			handleUpdateConfig(w, r, t, streamID)
		case http.MethodDelete:
			handleDeleteConfig(w, r, t, streamID)
		default:
			writeMethodNotAllowed(w, allow)
		}
	})
}

// listConfigResponse is the JSON envelope returned by
// [Transmitter.ListConfig]. Spec §7.1.1 does not pin a wire shape
// for the list response — most published examples use a
// `{streams, next_page_token}` envelope, which the library follows
// for byte-stability across implementations.
type listConfigResponse struct {
	Streams       []*ssf.StreamConfig `json:"streams"`
	NextPageToken string              `json:"next_page_token,omitempty"`
}

func handleListConfig(w http.ResponseWriter, r *http.Request, t Transmitter) {
	pageToken := r.URL.Query().Get("page_token")

	configs, next, err := t.ListConfig(r.Context(), pageToken)
	if err != nil {
		writeProblem(w, err)
		return
	}

	if configs == nil {
		configs = []*ssf.StreamConfig{}
	}
	writeJSON(w, http.StatusOK, listConfigResponse{
		Streams:       configs,
		NextPageToken: next,
	})
}

func handleGetConfig(w http.ResponseWriter, r *http.Request, t Transmitter, streamID string) {
	cfg, err := t.GetConfig(r.Context(), streamID)
	if err != nil {
		writeProblem(w, err)
		return
	}
	writeJSON(w, http.StatusOK, cfg)
}

func handleCreateConfig(w http.ResponseWriter, r *http.Request, t Transmitter) {
	var cfg ssf.StreamConfig
	if err := decodeJSONBody(r, &cfg); err != nil {
		writeProblem(w, err)
		return
	}

	got, err := t.CreateConfig(r.Context(), &cfg)
	if err != nil {
		writeProblem(w, err)
		return
	}
	writeJSON(w, http.StatusCreated, got)
}

func handleUpdateConfig(w http.ResponseWriter, r *http.Request, t Transmitter, streamID string) {
	if streamID == "" {
		writeProblem(w, missingStreamIDErr())
		return
	}

	var cfg ssf.StreamConfig
	if err := decodeJSONBody(r, &cfg); err != nil {
		writeProblem(w, err)
		return
	}
	// The query parameter is authoritative for the target stream;
	// it overrides any stream_id in the body so a caller cannot
	// retarget by smuggling a different ID into the JSON.
	cfg.StreamID = streamID

	got, err := t.UpdateConfig(r.Context(), &cfg)
	if err != nil {
		writeProblem(w, err)
		return
	}
	writeJSON(w, http.StatusOK, got)
}

func handleDeleteConfig(w http.ResponseWriter, r *http.Request, t Transmitter, streamID string) {
	if streamID == "" {
		writeProblem(w, missingStreamIDErr())
		return
	}
	if err := t.DeleteConfig(r.Context(), streamID); err != nil {
		writeProblem(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// StatusHandler returns an [http.Handler] for the stream status
// endpoint per OpenID Shared Signals Framework 1.0 §7.1.2.
//
//   - GET with stream_id (and an optional subject query parameter
//     carrying a JSON-encoded Subject Identifier) calls
//     [Transmitter.GetStatus]. The subject parameter is the JSON
//     bytes verbatim — when present they are forwarded to the
//     Transmitter as [encoding/json.RawMessage].
//   - POST with stream_id decodes the body as
//     [ssf.StatusUpdateRequest] and calls [Transmitter.UpdateStatus].
//
// Other methods receive 405 with Allow: GET, POST.
func StatusHandler(t Transmitter, auth AuthFunc) http.Handler {
	const allow = "GET, POST"
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !runAuth(w, r, auth) {
			return
		}

		streamID := r.URL.Query().Get("stream_id")
		if streamID == "" {
			writeProblem(w, missingStreamIDErr())
			return
		}

		switch r.Method {
		case http.MethodGet:
			handleGetStatus(w, r, t, streamID)
		case http.MethodPost:
			handleUpdateStatus(w, r, t, streamID)
		default:
			writeMethodNotAllowed(w, allow)
		}
	})
}

func handleGetStatus(w http.ResponseWriter, r *http.Request, t Transmitter, streamID string) {
	var subject json.RawMessage
	if s := r.URL.Query().Get("subject"); s != "" {
		// The query parameter carries JSON bytes verbatim; validate
		// they parse as a JSON object before forwarding so the
		// Transmitter receives well-formed input.
		if !json.Valid([]byte(s)) {
			writeProblem(w, &ssf.ValidationError{
				Rule:   "subject is JSON",
				Field:  "subject",
				Reason: "subject query parameter is not valid JSON",
			})
			return
		}
		subject = json.RawMessage(s)
	}

	resp, err := t.GetStatus(r.Context(), streamID, subject)
	if err != nil {
		writeProblem(w, err)
		return
	}
	writeJSON(w, http.StatusOK, resp)
}

func handleUpdateStatus(w http.ResponseWriter, r *http.Request, t Transmitter, streamID string) {
	var req ssf.StatusUpdateRequest
	if err := decodeJSONBody(r, &req); err != nil {
		writeProblem(w, err)
		return
	}
	resp, err := t.UpdateStatus(r.Context(), streamID, &req)
	if err != nil {
		writeProblem(w, err)
		return
	}
	writeJSON(w, http.StatusOK, resp)
}

// AddSubjectHandler returns an [http.Handler] for the add-subject
// endpoint per OpenID Shared Signals Framework 1.0 §7.1.3. The
// handler accepts POST with a stream_id query parameter, decodes the
// body as [ssf.AddSubjectRequest], and calls
// [Transmitter.AddSubject]. Success is 200 with an empty JSON
// object; other methods receive 405 with Allow: POST.
func AddSubjectHandler(t Transmitter, auth AuthFunc) http.Handler {
	const allow = "POST"
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !runAuth(w, r, auth) {
			return
		}
		if r.Method != http.MethodPost {
			writeMethodNotAllowed(w, allow)
			return
		}

		streamID := r.URL.Query().Get("stream_id")
		if streamID == "" {
			writeProblem(w, missingStreamIDErr())
			return
		}

		var req ssf.AddSubjectRequest
		if err := decodeJSONBody(r, &req); err != nil {
			writeProblem(w, err)
			return
		}
		if err := t.AddSubject(r.Context(), streamID, &req); err != nil {
			writeProblem(w, err)
			return
		}
		writeEmptyJSON(w, http.StatusOK)
	})
}

// RemoveSubjectHandler returns an [http.Handler] for the
// remove-subject endpoint per OpenID Shared Signals Framework 1.0
// §7.1.3. The handler accepts POST with a stream_id query parameter,
// decodes the body as [ssf.RemoveSubjectRequest], and calls
// [Transmitter.RemoveSubject]. Success is 200 with an empty JSON
// object; other methods receive 405 with Allow: POST.
func RemoveSubjectHandler(t Transmitter, auth AuthFunc) http.Handler {
	const allow = "POST"
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !runAuth(w, r, auth) {
			return
		}
		if r.Method != http.MethodPost {
			writeMethodNotAllowed(w, allow)
			return
		}

		streamID := r.URL.Query().Get("stream_id")
		if streamID == "" {
			writeProblem(w, missingStreamIDErr())
			return
		}

		var req ssf.RemoveSubjectRequest
		if err := decodeJSONBody(r, &req); err != nil {
			writeProblem(w, err)
			return
		}
		if err := t.RemoveSubject(r.Context(), streamID, &req); err != nil {
			writeProblem(w, err)
			return
		}
		writeEmptyJSON(w, http.StatusOK)
	})
}

// VerificationHandler returns an [http.Handler] for the verification
// endpoint per OpenID Shared Signals Framework 1.0 §7.1.4. The
// handler accepts POST with a stream_id query parameter, decodes the
// body as [ssf.VerificationRequest], and calls [Transmitter.Verify].
// Success is 200 with an empty JSON object — the verification SET
// itself is delivered asynchronously over the stream's configured
// delivery channel. Other methods receive 405 with Allow: POST.
func VerificationHandler(t Transmitter, auth AuthFunc) http.Handler {
	const allow = "POST"
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !runAuth(w, r, auth) {
			return
		}
		if r.Method != http.MethodPost {
			writeMethodNotAllowed(w, allow)
			return
		}

		streamID := r.URL.Query().Get("stream_id")
		if streamID == "" {
			writeProblem(w, missingStreamIDErr())
			return
		}

		var req ssf.VerificationRequest
		if err := decodeJSONBody(r, &req); err != nil {
			writeProblem(w, err)
			return
		}
		if err := t.Verify(r.Context(), streamID, &req); err != nil {
			writeProblem(w, err)
			return
		}
		writeEmptyJSON(w, http.StatusOK)
	})
}

// PollHandler returns an [http.Handler] for the poll-delivery
// endpoint per RFC 8936. The handler accepts POST with a stream_id
// query parameter, decodes the body as [ssf.PollRequest], and calls
// [Transmitter.PollEvents]. The response body is the
// [ssf.PollResponse] returned by the Transmitter. Other methods
// receive 405 with Allow: POST.
//
// The stream_id query parameter is mandatory here — unlike RFC 8936
// which leaves stream identification to the auth credential, this
// library exposes the stream as an explicit parameter so the same
// handler can serve multiple streams behind a shared auth scope.
func PollHandler(t Transmitter, auth AuthFunc) http.Handler {
	const allow = "POST"
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !runAuth(w, r, auth) {
			return
		}
		if r.Method != http.MethodPost {
			writeMethodNotAllowed(w, allow)
			return
		}

		streamID := r.URL.Query().Get("stream_id")
		if streamID == "" {
			writeProblem(w, missingStreamIDErr())
			return
		}

		var req ssf.PollRequest
		if err := decodeJSONBody(r, &req); err != nil {
			writeProblem(w, err)
			return
		}
		resp, err := t.PollEvents(r.Context(), streamID, &req)
		if err != nil {
			writeProblem(w, err)
			return
		}
		writeJSON(w, http.StatusOK, resp)
	})
}

// runAuth invokes auth on the request. On success it returns true so
// the caller proceeds with the request. On rejection it renders the
// 401 problem-details response via [Default401Handler] and returns
// false; the caller MUST stop processing.
//
// When auth is nil — which the [MuxHandler] constructor prevents but
// per-handler callers may permit by accident — the request is
// rejected as if [AlwaysReject] had been wired in. Defaulting to
// fail-closed at the boundary matches [AuthFunc]'s documented
// posture.
func runAuth(w http.ResponseWriter, r *http.Request, auth AuthFunc) bool {
	if auth == nil {
		Default401Handler(ssf.ErrUnauthorized).ServeHTTP(w, r)
		return false
	}
	if _, err := auth(r); err != nil {
		Default401Handler(err).ServeHTTP(w, r)
		return false
	}
	return true
}

// decodeJSONBody reads the request body, rejects bodies larger than
// the conservative 1 MiB limit applied by [http.MaxBytesReader], and
// JSON-decodes the result into dst. Decode errors surface as
// [*ssf.ValidationError] with Rule="JSON body decode" so the
// problem-mapper turns them into 400 responses with a stable shape.
//
// The body is fully consumed before returning so the connection is
// reusable; a hostile client that supplies a stream that never EOFs
// is bounded by the 1 MiB limit.
func decodeJSONBody(r *http.Request, dst any) error {
	const maxBody = 1 << 20 // 1 MiB

	r.Body = http.MaxBytesReader(nil, r.Body, maxBody)
	body, err := io.ReadAll(r.Body)
	if err != nil {
		return &ssf.ValidationError{
			Rule:   "JSON body size",
			Field:  "body",
			Reason: err.Error(),
		}
	}

	if len(body) == 0 {
		return &ssf.ValidationError{
			Rule:   "JSON body decode",
			Field:  "body",
			Reason: "request body is empty",
		}
	}

	if err := json.Unmarshal(body, dst); err != nil {
		return &ssf.ValidationError{
			Rule:   "JSON body decode",
			Field:  "body",
			Reason: err.Error(),
		}
	}
	return nil
}

// writeJSON serializes v to JSON and writes it as the response body
// with the given status code and the canonical [contentTypeJSON]
// Content-Type. Marshal failure is a 500 — the body the Transmitter
// produced should always marshal, and a failure here means the
// Transmitter returned an unencodable value.
func writeJSON(w http.ResponseWriter, status int, v any) {
	body, err := json.Marshal(v)
	if err != nil {
		writeProblem(w, fmt.Errorf("marshal response: %w", err))
		return
	}
	w.Header().Set("Content-Type", contentTypeJSON)
	w.WriteHeader(status)
	_, _ = w.Write(body)
}

// writeEmptyJSON writes the canonical empty-body acknowledgement
// "{}" — used by endpoints whose spec response body is empty but
// which still want a parseable JSON document on the wire (rather
// than zero bytes that some clients mishandle).
func writeEmptyJSON(w http.ResponseWriter, status int) {
	w.Header().Set("Content-Type", contentTypeJSON)
	w.WriteHeader(status)
	_, _ = w.Write([]byte("{}"))
}

// writeMethodNotAllowed renders a 405 response with the Allow header
// listing the accepted methods. The body is a problem-details
// document so callers parsing application/problem+json get one shape
// for every Transmitter error.
func writeMethodNotAllowed(w http.ResponseWriter, allow string) {
	w.Header().Set("Allow", allow)
	writeProblemStatus(w, http.StatusMethodNotAllowed, "Method Not Allowed",
		fmt.Sprintf("allowed methods: %s", allow))
}

// missingStreamIDErr is the validation error used when a handler
// requires the stream_id query parameter and the request omits it.
// Centralized so the message text is identical across every handler
// that enforces the rule.
func missingStreamIDErr() error {
	return &ssf.ValidationError{
		Rule:   "stream_id required",
		Field:  "stream_id",
		Reason: "stream_id query parameter is required",
	}
}

// writeProblem maps err onto an HTTP status code and writes the
// canonical RFC 7807 problem-details response. The mapping is:
//
//	*ssf.ValidationError    → 400 (Detail names the failing rule)
//	ssf.ErrUnauthorized     → 401
//	ssf.ErrStreamNotFound   → 404
//	ssf.ErrInvalidConfig    → 400
//	ssf.ErrNotImplemented   → 501
//	any other error         → 500
//
// On the 401 path the helper delegates to [Default401Handler] so the
// title and shape match the auth rejection path. Other statuses use
// [writeProblemStatus] for a uniform body. [*ssf.ValidationError] is
// checked first via [errors.As] so a wrapped validation error always
// surfaces its rule and field, rather than collapsing to a generic
// 400.
func writeProblem(w http.ResponseWriter, err error) {
	var ve *ssf.ValidationError
	if errors.As(err, &ve) {
		// Detail surfaces both the rule and the reason so the
		// caller does not have to scrape a single freeform string.
		detail := ve.Reason
		if ve.Rule != "" {
			detail = fmt.Sprintf("%s (rule=%q field=%q)", ve.Reason, ve.Rule, ve.Field)
		}
		writeProblemStatus(w, http.StatusBadRequest, "Validation Failed", detail)
		return
	}

	switch {
	case errors.Is(err, ssf.ErrUnauthorized):
		writeAuthProblem(w, err)
	case errors.Is(err, ssf.ErrStreamNotFound):
		writeProblemStatus(w, http.StatusNotFound, "Stream Not Found", err.Error())
	case errors.Is(err, ssf.ErrInvalidConfig):
		writeProblemStatus(w, http.StatusBadRequest, "Invalid Configuration", err.Error())
	case errors.Is(err, ssf.ErrNotImplemented):
		writeProblemStatus(w, http.StatusNotImplemented, "Not Implemented", err.Error())
	default:
		writeProblemStatus(w, http.StatusInternalServerError, "Internal Server Error", err.Error())
	}
}

// writeAuthProblem renders the 401 problem-details body. Factored
// out of [writeProblem] so the shape exactly matches the auth-time
// rejection path through [Default401Handler] — same Title, same
// Type, same body bytes — regardless of whether the rejection comes
// from [AuthFunc] or from a [Transmitter] method returning
// [ssf.ErrUnauthorized].
func writeAuthProblem(w http.ResponseWriter, err error) {
	// [Default401Handler] is documented to ignore the *http.Request
	// passed to its ServeHTTP method, so a placeholder value is
	// sufficient here. Constructing a minimal one (rather than nil)
	// stays robust against future changes to that handler that
	// might begin to inspect a header or method.
	Default401Handler(err).ServeHTTP(w, &http.Request{Header: http.Header{}})
}

// writeProblemStatus writes a problem-details response with the
// given HTTP status, title, and detail. Type is the RFC 7807 default
// "about:blank" — the library does not mint synthetic problem-type
// URIs (see [unauthorizedProblemType] for the rationale). Callers
// wanting a richer Type override the rendering wholesale.
func writeProblemStatus(w http.ResponseWriter, status int, title, detail string) {
	problem := &ssf.ProblemDetails{
		Type:   unauthorizedProblemType,
		Title:  title,
		Status: status,
		Detail: strings.TrimSpace(detail),
	}
	body, err := json.Marshal(problem)
	w.Header().Set("Content-Type", contentTypeProblem)
	w.WriteHeader(status)
	if err != nil {
		// Unreachable for the field set above: every value marshals.
		// Write an empty body so the status line still carries
		// useful information.
		return
	}
	_, _ = w.Write(body)
}
