// Copyright 2026 The go-ssf Authors
// SPDX-License-Identifier: Apache-2.0

package receiver

import (
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"

	"github.com/hstern/go-ssf"
)

// pushMediaType is the Content-Type a Transmitter MUST set on every
// push delivery per RFC 8935 §2. The handler rejects any other media
// type with 415 Unsupported Media Type.
const pushMediaType = "application/secevent+jwt"

// contentTypeProblem is the RFC 7807 problem-details media type used
// on every non-2xx response from the push handler. RFC 8935 §3.2
// mandates this shape for Transmitter-facing error responses; the
// library uses it uniformly even on errors RFC 8935 does not
// enumerate (e.g. 405 Method Not Allowed) so consumers parsing the
// body get one stable shape.
const contentTypeProblem = "application/problem+json"

// defaultMaxPushBytes caps the request body the push handler will
// read by default. SETs are signed JWS objects; a kilobyte covers
// almost every realistic event and a megabyte is generous for the
// outliers. The default is 1 MiB; callers tune via [WithMaxBytes].
const defaultMaxPushBytes int64 = 1 << 20

// pushOptions holds the resolved configuration for [PushHandler].
// Fields are unexported so the option functions remain the only
// supported way to construct a handler — adding new tunables stays
// API-additive.
type pushOptions struct {
	maxBytes int64
}

// PushOption configures a [PushHandler]. The option functions are
// declared in this file alongside the struct they mutate so the
// surface is self-contained.
type PushOption func(*pushOptions)

// WithMaxBytes overrides the maximum push-request body size, in
// bytes. The default is 1 MiB. A request whose body exceeds the
// limit is rejected with 413 Request Entity Too Large after the
// limit's worth of bytes has been consumed.
//
// A value of zero or negative disables the limit. Disabling is
// strongly discouraged in production — an unbounded reader allows
// a hostile or buggy Transmitter to exhaust the Receiver's memory —
// but is occasionally useful in tests.
func WithMaxBytes(n int64) PushOption {
	return func(o *pushOptions) {
		o.maxBytes = n
	}
}

// PushHandler returns an [http.Handler] that implements the Receiver
// side of the RFC 8935 push-delivery profile. The handler:
//
//   - Accepts only POST. Any other method receives 405 Method Not
//     Allowed with an Allow: POST header.
//   - Requires Content-Type: application/secevent+jwt per RFC 8935
//     §2. Any other media type receives 415 Unsupported Media Type.
//   - Reads the request body subject to a size cap (default 1 MiB,
//     configurable via [WithMaxBytes]). An oversized body produces
//     413 Request Entity Too Large; any other body-read failure
//     produces 400 Bad Request.
//   - Verifies the JWS via verifier, which MUST enforce the RFC
//     8417 §2.2 invariants on the SET. A verifier failure produces
//     400 Bad Request — RFC 8935 §3.2 treats this as permanent and
//     the Transmitter will not retry.
//   - Calls sink.DeliverSET with the verified payload bytes. A nil
//     return produces 202 Accepted with an empty body, the spec's
//     success response. A non-nil return that wraps [ErrPermanent]
//     produces 400 Bad Request; any other non-nil return produces
//     503 Service Unavailable so the Transmitter retries.
//
// Every non-2xx response carries an application/problem+json body
// per RFC 7807 with the appropriate status code echoed in the body
// for log/observability use. The 202 success response carries no
// body — RFC 8935 §3.2 does not require one and an empty body is
// what every published example shows.
//
// PushHandler does not perform Transmitter authentication. RFC 8935
// §3 leaves the auth scheme to the deployment (OAuth bearer token,
// mTLS, API key). Consumers compose their auth in front of the
// returned handler — for example with [http.StripPrefix] and a
// middleware that inspects the Authorization header — and the
// handler runs only on requests that auth has already accepted.
//
// The returned handler is safe for concurrent use. It does not
// retain any per-request state.
func PushHandler(verifier ssf.SETVerifier, sink Sink, opts ...PushOption) http.Handler {
	cfg := pushOptions{maxBytes: defaultMaxPushBytes}
	for _, opt := range opts {
		opt(&cfg)
	}

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			w.Header().Set("Allow", http.MethodPost)
			writeProblem(w, http.StatusMethodNotAllowed,
				"Method Not Allowed",
				"the push endpoint accepts POST only")
			return
		}

		if !hasPushMediaType(r.Header.Get("Content-Type")) {
			writeProblem(w, http.StatusUnsupportedMediaType,
				"Unsupported Media Type",
				`Content-Type must be "`+pushMediaType+`" (rfc 8935 §2)`)
			return
		}

		body, err := readPushBody(w, r, cfg.maxBytes)
		if err != nil {
			writeBodyReadProblem(w, err)
			return
		}

		jwsCompact := strings.TrimSpace(string(body))
		if jwsCompact == "" {
			writeProblem(w, http.StatusBadRequest,
				"Empty Request Body",
				"the push endpoint requires a compact-serialized JWS in the body")
			return
		}

		payload, err := verifier.Verify(jwsCompact)
		if err != nil {
			writeProblem(w, http.StatusBadRequest,
				"Invalid Security Event Token",
				err.Error())
			return
		}

		if err := sink.DeliverSET(r.Context(), payload); err != nil {
			if errors.Is(err, ErrPermanent) {
				writeProblem(w, http.StatusBadRequest,
					"Permanent Sink Failure",
					err.Error())
				return
			}
			writeProblem(w, http.StatusServiceUnavailable,
				"Transient Sink Failure",
				err.Error())
			return
		}

		w.WriteHeader(http.StatusAccepted)
	})
}

// hasPushMediaType reports whether the Content-Type header carries
// the RFC 8935 push media type. Parameters (e.g. "; charset=utf-8")
// are tolerated even though the spec does not define any — the
// library is lenient on receive per Postel's law.
func hasPushMediaType(header string) bool {
	mediaType, _, ok := strings.Cut(header, ";")
	if !ok {
		mediaType = header
	}
	return strings.EqualFold(strings.TrimSpace(mediaType), pushMediaType)
}

// readPushBody reads the request body subject to the size cap. When
// maxBytes is zero or negative the cap is disabled — the body is read
// in full via io.ReadAll. When maxBytes is positive,
// [http.MaxBytesReader] installs the cap so a hostile sender cannot
// exhaust memory; the resulting [*http.MaxBytesError] is recognized
// by [writeBodyReadProblem] and mapped to 413.
func readPushBody(w http.ResponseWriter, r *http.Request, maxBytes int64) ([]byte, error) {
	if maxBytes > 0 {
		r.Body = http.MaxBytesReader(w, r.Body, maxBytes)
	}
	return io.ReadAll(r.Body)
}

// writeBodyReadProblem maps a body-read failure to the appropriate
// problem-details response. [*http.MaxBytesError] (introduced in
// Go 1.19) is the cap-exceeded signal — that becomes 413; everything
// else collapses to 400 Bad Request.
func writeBodyReadProblem(w http.ResponseWriter, err error) {
	var maxErr *http.MaxBytesError
	if errors.As(err, &maxErr) {
		writeProblem(w, http.StatusRequestEntityTooLarge,
			"Request Body Too Large",
			err.Error())
		return
	}
	writeProblem(w, http.StatusBadRequest,
		"Bad Request",
		"read request body: "+err.Error())
}

// writeProblem renders an RFC 7807 problem-details JSON response
// with the given status, title, and detail. Type is left at the
// RFC 7807 default ("about:blank") — the library does not mint
// synthetic problem-type URIs for the Receiver any more than it
// does for the Transmitter (see transmitter/handlers.go for the
// matching rationale on that side).
func writeProblem(w http.ResponseWriter, status int, title, detail string) {
	problem := &ssf.ProblemDetails{
		Title:  title,
		Status: status,
		Detail: strings.TrimSpace(detail),
	}
	body, err := json.Marshal(problem)
	w.Header().Set("Content-Type", contentTypeProblem)
	w.WriteHeader(status)
	if err != nil {
		// Unreachable for the field set above: every value
		// marshals. Leave the body empty so the status line still
		// carries useful information for the caller.
		return
	}
	_, _ = w.Write(body)
}
