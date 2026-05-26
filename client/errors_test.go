// Copyright 2026 The go-ssf Authors
// SPDX-License-Identifier: Apache-2.0

package client

import (
	"bytes"
	"errors"
	"io"
	"net/http"
	"strings"
	"testing"

	"github.com/hstern/go-ssf"
)

// newResponse builds a minimal [*http.Response] for the parser under
// test. It pins the fields ParseHTTPError actually reads — StatusCode,
// Header, Body — and leaves the rest at their zero values. Tests close
// Body themselves via t.Cleanup so the response shape matches what an
// http.Client.Do caller sees.
func newResponse(t *testing.T, status int, contentType string, body []byte) *http.Response {
	t.Helper()
	resp := &http.Response{
		StatusCode: status,
		Header:     http.Header{},
		Body:       io.NopCloser(bytes.NewReader(body)),
	}
	if contentType != "" {
		resp.Header.Set("Content-Type", contentType)
	}
	t.Cleanup(func() { _ = resp.Body.Close() })
	return resp
}

func TestParseHTTPError_2xxReturnsNil(t *testing.T) {
	t.Parallel()

	for _, status := range []int{
		http.StatusOK,
		http.StatusCreated,
		http.StatusAccepted,
		http.StatusNoContent,
	} {
		resp := newResponse(t, status, "application/json", []byte(`{"ok":true}`))
		if err := ParseHTTPError(resp); err != nil {
			t.Errorf("ParseHTTPError(status=%d) = %v, want nil", status, err)
		}
	}
}

func TestParseHTTPError_401WithProblemDetails(t *testing.T) {
	t.Parallel()

	body := []byte(`{"type":"https://example.com/probs/unauth","title":"Unauthorized","status":401,"detail":"missing bearer token"}`)
	resp := newResponse(t, http.StatusUnauthorized, "application/problem+json", body)

	err := ParseHTTPError(resp)
	if err == nil {
		t.Fatal("ParseHTTPError returned nil for 401")
	}

	var httpErr *ssf.HTTPError
	if !errors.As(err, &httpErr) {
		t.Fatalf("errors.As(*ssf.HTTPError) = false; err = %v", err)
	}
	if httpErr.StatusCode != http.StatusUnauthorized {
		t.Errorf("StatusCode = %d, want 401", httpErr.StatusCode)
	}
	if httpErr.RFC7807 == nil {
		t.Fatalf("RFC7807 = nil, want populated problem-details")
	}
	if got, want := httpErr.RFC7807.Title, "Unauthorized"; got != want {
		t.Errorf("RFC7807.Title = %q, want %q", got, want)
	}
	if got, want := httpErr.RFC7807.Status, 401; got != want {
		t.Errorf("RFC7807.Status = %d, want %d", got, want)
	}
	if !bytes.Equal(httpErr.Body, body) {
		t.Errorf("Body = %q, want %q", httpErr.Body, body)
	}

	if !errors.Is(err, ssf.ErrUnauthorized) {
		t.Errorf("errors.Is(ssf.ErrUnauthorized) = false")
	}
}

func TestParseHTTPError_404MapsToStreamNotFound(t *testing.T) {
	t.Parallel()

	body := []byte(`{"type":"https://example.com/probs/stream-not-found","title":"Stream not found","status":404}`)
	resp := newResponse(t, http.StatusNotFound, "application/problem+json", body)

	err := ParseHTTPError(resp)
	if err == nil {
		t.Fatal("ParseHTTPError returned nil for 404")
	}
	if !errors.Is(err, ssf.ErrStreamNotFound) {
		t.Errorf("errors.Is(ssf.ErrStreamNotFound) = false")
	}
	var httpErr *ssf.HTTPError
	if !errors.As(err, &httpErr) {
		t.Fatalf("errors.As(*ssf.HTTPError) = false")
	}
	if httpErr.StatusCode != http.StatusNotFound {
		t.Errorf("StatusCode = %d, want 404", httpErr.StatusCode)
	}
	if httpErr.RFC7807 == nil || httpErr.RFC7807.Title != "Stream not found" {
		t.Errorf("RFC7807 = %+v, want Title=\"Stream not found\"", httpErr.RFC7807)
	}
}

func TestParseHTTPError_501MapsToNotImplemented(t *testing.T) {
	t.Parallel()

	resp := newResponse(t, http.StatusNotImplemented, "application/problem+json",
		[]byte(`{"title":"Not implemented","status":501}`))

	err := ParseHTTPError(resp)
	if err == nil {
		t.Fatal("ParseHTTPError returned nil for 501")
	}
	if !errors.Is(err, ssf.ErrNotImplemented) {
		t.Errorf("errors.Is(ssf.ErrNotImplemented) = false")
	}
}

func TestParseHTTPError_500PlaintextBody(t *testing.T) {
	t.Parallel()

	body := []byte("Internal Server Error")
	resp := newResponse(t, http.StatusInternalServerError, "text/plain; charset=utf-8", body)

	err := ParseHTTPError(resp)
	if err == nil {
		t.Fatal("ParseHTTPError returned nil for 500")
	}

	// 500 has no sentinel mapping.
	if errors.Is(err, ssf.ErrUnauthorized) ||
		errors.Is(err, ssf.ErrStreamNotFound) ||
		errors.Is(err, ssf.ErrNotImplemented) {
		t.Errorf("unexpected sentinel match on 500: %v", err)
	}

	var httpErr *ssf.HTTPError
	if !errors.As(err, &httpErr) {
		t.Fatalf("errors.As(*ssf.HTTPError) = false")
	}
	if httpErr.RFC7807 != nil {
		t.Errorf("RFC7807 = %+v, want nil for non-problem-details body", httpErr.RFC7807)
	}
	if !bytes.Equal(httpErr.Body, body) {
		t.Errorf("Body = %q, want %q", httpErr.Body, body)
	}
}

func TestParseHTTPError_MalformedProblemDetails(t *testing.T) {
	t.Parallel()

	// Content-Type advertises problem+json but the body is not valid
	// JSON. The parser must still produce an *ssf.HTTPError with the
	// raw body and a nil RFC7807, rather than failing outright.
	body := []byte(`{"title":"truncated`)
	resp := newResponse(t, http.StatusBadRequest, "application/problem+json", body)

	err := ParseHTTPError(resp)
	if err == nil {
		t.Fatal("ParseHTTPError returned nil")
	}
	var httpErr *ssf.HTTPError
	if !errors.As(err, &httpErr) {
		t.Fatalf("errors.As(*ssf.HTTPError) = false")
	}
	if httpErr.RFC7807 != nil {
		t.Errorf("RFC7807 = %+v, want nil on malformed JSON", httpErr.RFC7807)
	}
	if !bytes.Equal(httpErr.Body, body) {
		t.Errorf("Body = %q, want %q", httpErr.Body, body)
	}
	if httpErr.StatusCode != http.StatusBadRequest {
		t.Errorf("StatusCode = %d, want 400", httpErr.StatusCode)
	}
}

func TestParseHTTPError_OversizedBodyTruncated(t *testing.T) {
	t.Parallel()

	// Build a body larger than maxErrorBodyBytes. The parser must
	// return promptly with a usable error and read at most the cap.
	const oversize = maxErrorBodyBytes + 4096
	big := bytes.Repeat([]byte("x"), oversize)
	resp := newResponse(t, http.StatusBadGateway, "text/plain", big)

	err := ParseHTTPError(resp)
	if err == nil {
		t.Fatal("ParseHTTPError returned nil")
	}
	var httpErr *ssf.HTTPError
	if !errors.As(err, &httpErr) {
		t.Fatalf("errors.As(*ssf.HTTPError) = false")
	}
	if len(httpErr.Body) != maxErrorBodyBytes {
		t.Errorf("len(Body) = %d, want %d (cap)", len(httpErr.Body), maxErrorBodyBytes)
	}
	if httpErr.StatusCode != http.StatusBadGateway {
		t.Errorf("StatusCode = %d, want 502", httpErr.StatusCode)
	}
}

func TestParseHTTPError_ContentTypeParameterIgnored(t *testing.T) {
	t.Parallel()

	// RFC 7807 §3 defines the media type without parameters; many
	// servers add charset=utf-8 anyway. The parser must still
	// recognise the type and decode the body.
	body := []byte(`{"title":"Unauthorized","status":401}`)
	resp := newResponse(t, http.StatusUnauthorized,
		"application/problem+json; charset=utf-8", body)

	err := ParseHTTPError(resp)
	var httpErr *ssf.HTTPError
	if !errors.As(err, &httpErr) {
		t.Fatalf("errors.As = false")
	}
	if httpErr.RFC7807 == nil {
		t.Fatalf("RFC7807 = nil despite parameterised problem+json content type")
	}
}

func TestParseHTTPError_NoContentTypeHeader(t *testing.T) {
	t.Parallel()

	// No Content-Type at all. The body might still be JSON but the
	// parser must not speculate: it returns an *ssf.HTTPError with a
	// nil RFC7807 field.
	body := []byte(`{"title":"who knows"}`)
	resp := newResponse(t, http.StatusBadRequest, "", body)

	err := ParseHTTPError(resp)
	var httpErr *ssf.HTTPError
	if !errors.As(err, &httpErr) {
		t.Fatalf("errors.As = false")
	}
	if httpErr.RFC7807 != nil {
		t.Errorf("RFC7807 = %+v, want nil when Content-Type is absent",
			httpErr.RFC7807)
	}
}

func TestParseHTTPError_BodyReadError(t *testing.T) {
	t.Parallel()

	// A response whose Body returns an error from Read surfaces as a
	// wrapped error mentioning the status code; the function does not
	// return a nil error or panic.
	resp := &http.Response{
		StatusCode: http.StatusInternalServerError,
		Header:     http.Header{},
		Body:       io.NopCloser(errReader{err: io.ErrUnexpectedEOF}),
	}
	t.Cleanup(func() { _ = resp.Body.Close() })

	err := ParseHTTPError(resp)
	if err == nil {
		t.Fatal("ParseHTTPError returned nil on read error")
	}
	if !errors.Is(err, io.ErrUnexpectedEOF) {
		t.Errorf("errors.Is(io.ErrUnexpectedEOF) = false; err = %v", err)
	}
	if !strings.Contains(err.Error(), "500") {
		t.Errorf("error message missing status code: %v", err)
	}
}

func TestMapStatusToSentinel(t *testing.T) {
	t.Parallel()

	cases := []struct {
		status int
		want   error
	}{
		{http.StatusUnauthorized, ssf.ErrUnauthorized},
		{http.StatusNotFound, ssf.ErrStreamNotFound},
		{http.StatusNotImplemented, ssf.ErrNotImplemented},
		{http.StatusBadRequest, nil},
		{http.StatusForbidden, nil},
		{http.StatusInternalServerError, nil},
		{http.StatusBadGateway, nil},
		{http.StatusOK, nil},
	}
	for _, c := range cases {
		if got := mapStatusToSentinel(c.status); got != c.want {
			t.Errorf("mapStatusToSentinel(%d) = %v, want %v", c.status, got, c.want)
		}
	}
}

func TestParseProblemDetails_EmptyBody(t *testing.T) {
	t.Parallel()

	if got := parseProblemDetails(nil); got != nil {
		t.Errorf("parseProblemDetails(nil) = %+v, want nil", got)
	}
	if got := parseProblemDetails([]byte{}); got != nil {
		t.Errorf("parseProblemDetails([]byte{}) = %+v, want nil", got)
	}
}

// errReader is an [io.Reader] whose Read always returns a fixed
// error. Used by TestParseHTTPError_BodyReadError to simulate a
// truncated network read.
type errReader struct {
	err error
}

func (r errReader) Read(p []byte) (int, error) { return 0, r.err }
