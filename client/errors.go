// Copyright 2026 The go-ssf Authors
// SPDX-License-Identifier: Apache-2.0

// Package client is the Receiver-side HTTP client for the Transmitter
// endpoints defined by OpenID Shared Signals Framework 1.0 §7.
//
// The package translates between Go method calls and the spec's HTTP
// shapes: it issues the configured request, reads the response, and
// converts non-2xx outcomes into a typed error a Receiver can route
// on. RFC 7807 problem-details bodies are decoded into the
// [ssf.ProblemDetails] structure the root package already defines;
// common status codes are wrapped with the matching root-package
// sentinel (for example [ssf.ErrUnauthorized] on 401) so callers can
// pattern-match with [errors.Is] without inspecting status codes
// directly.
//
// The full [Client] type and the per-endpoint wrappers ship in a
// follow-up commit. This file establishes [ParseHTTPError], the shared
// non-2xx-response parser those wrappers will call.
package client

import (
	"errors"
	"fmt"
	"io"
	"mime"
	"net/http"

	"github.com/hstern/go-ssf"
)

// maxErrorBodyBytes caps how many bytes [ParseHTTPError] will read
// from a non-2xx response body before truncating. The cap protects
// the client from a Transmitter that returns an unboundedly large
// error document; RFC 7807 problem-details payloads are short by
// design, and 256 KiB is comfortably above any reasonable Title +
// Detail + extension-member combination while still being a hard
// upper bound on memory the client will spend on a single error.
//
// Truncation is silent: the body is read up to the cap and the
// resulting bytes are handed to [json.Unmarshal] as-is. If the cap
// chops a problem-details document mid-object the JSON decode will
// fail and the returned [*ssf.HTTPError] carries the truncated bytes
// in Body with a nil RFC7807 field, which is the same shape as any
// other unparseable error body.
const maxErrorBodyBytes = 256 << 10

// problemDetailsMediaType is the RFC 7807 media type. [ParseHTTPError]
// only attempts to decode the response body into [ssf.ProblemDetails]
// when the response's Content-Type parses to this value, matching
// RFC 7807 §3 which reserves problem+json for the problem-details
// document.
const problemDetailsMediaType = "application/problem+json"

// ParseHTTPError converts a non-2xx HTTP response from a Transmitter
// into a typed error.
//
// On a 2xx status the function returns nil; the caller still owns
// closing resp.Body. On any other status it reads up to
// [maxErrorBodyBytes] from resp.Body, attempts to decode the body as
// RFC 7807 problem-details when the response's Content-Type indicates
// problem+json, and builds an [*ssf.HTTPError] carrying the status
// code, the raw bytes, and the parsed [*ssf.ProblemDetails] when
// available.
//
// When the status maps onto one of the library's sentinel errors
// (see the table in [mapStatusToSentinel]) the return value joins
// the [*ssf.HTTPError] with the sentinel via [errors.Join] so
// callers can pattern-match either way:
//
//	err := client.ParseHTTPError(resp)
//	var httpErr *ssf.HTTPError
//	if errors.As(err, &httpErr) { // recover status, body, problem-details
//	    log.Printf("transmitter returned %d", httpErr.StatusCode)
//	}
//	if errors.Is(err, ssf.ErrUnauthorized) { // act on the spec-level cause
//	    refreshToken()
//	}
//
// The caller is responsible for closing resp.Body. The function does
// not, because the same response may already be in the middle of a
// caller's read sequence (status-code-then-body) and the function's
// contract is "give me a useful error for this response," not "take
// ownership of the response lifetime."
func ParseHTTPError(resp *http.Response) error {
	if resp.StatusCode >= 200 && resp.StatusCode < 300 {
		return nil
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, maxErrorBodyBytes))
	if err != nil {
		// A read failure on a non-2xx response is itself an error
		// worth surfacing; wrap it with the status code so the
		// caller still knows the transport-level outcome.
		return fmt.Errorf("ssf: read error response body (status %d): %w",
			resp.StatusCode, err)
	}

	httpErr := &ssf.HTTPError{
		StatusCode: resp.StatusCode,
		Body:       body,
	}
	if isProblemDetails(resp.Header.Get("Content-Type")) {
		httpErr.RFC7807 = parseProblemDetails(body)
	}

	if sentinel := mapStatusToSentinel(resp.StatusCode); sentinel != nil {
		return errors.Join(httpErr, sentinel)
	}
	return httpErr
}

// isProblemDetails reports whether the value of a Content-Type header
// indicates an RFC 7807 problem-details document. The match is on the
// media type only — parameters such as charset are ignored — matching
// RFC 7807 §3 which defines the media type without parameters.
func isProblemDetails(contentType string) bool {
	if contentType == "" {
		return false
	}
	mediaType, _, err := mime.ParseMediaType(contentType)
	if err != nil {
		return false
	}
	return mediaType == problemDetailsMediaType
}

// parseProblemDetails decodes an RFC 7807 problem-details document.
// On any decode failure it returns nil so the caller falls back to
// the opaque-body shape — that matches the library's lenient-parse
// posture: a Transmitter that advertises problem+json but ships
// malformed JSON should not cause the client to lose the status code
// and the raw bytes, which are still useful for logging.
func parseProblemDetails(body []byte) *ssf.ProblemDetails {
	if len(body) == 0 {
		return nil
	}
	var pd ssf.ProblemDetails
	if err := pd.UnmarshalJSON(body); err != nil {
		return nil
	}
	return &pd
}

// mapStatusToSentinel returns the root-package sentinel error that
// best matches the given HTTP status code, or nil when no sentinel
// applies. The mapping covers the status codes the spec itself
// names in §7 and the codes the library's transmitter handlers emit:
//
//   - 401 Unauthorized       → [ssf.ErrUnauthorized]
//   - 404 Not Found          → [ssf.ErrStreamNotFound]
//   - 501 Not Implemented    → [ssf.ErrNotImplemented]
//
// The 404 mapping treats every 404 from a Transmitter as
// stream-not-found because the spec only authorises 404 on
// stream-scoped resources (§7.1) — a 404 on any other path would
// indicate a routing bug on the Transmitter, and the library's
// sentinel is still the most useful match for callers reacting to a
// missing stream. Codes outside this table return nil; the caller
// gets a plain [*ssf.HTTPError] with no sentinel wrapping and is
// expected to branch on StatusCode if it needs to.
func mapStatusToSentinel(status int) error {
	switch status {
	case http.StatusUnauthorized:
		return ssf.ErrUnauthorized
	case http.StatusNotFound:
		return ssf.ErrStreamNotFound
	case http.StatusNotImplemented:
		return ssf.ErrNotImplemented
	default:
		return nil
	}
}
