// Copyright 2026 The go-ssf Authors
// SPDX-License-Identifier: Apache-2.0

package transmitter_test

import (
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/hstern/go-ssf"
	"github.com/hstern/go-ssf/transmitter"
)

// TestAlwaysRejectReturnsErrUnauthorized pins the fail-closed default
// [transmitter.AuthFunc]: every request maps to [ssf.ErrUnauthorized]
// with an empty [transmitter.StreamScope]. The handler set relies on
// the sentinel identity (errors.Is) when classifying the rejection.
func TestAlwaysRejectReturnsErrUnauthorized(t *testing.T) {
	t.Parallel()

	req := httptest.NewRequest(http.MethodGet, "/", nil)

	scope, err := transmitter.AlwaysReject(req)
	if !errors.Is(err, ssf.ErrUnauthorized) {
		t.Fatalf("AlwaysReject error = %v, want errors.Is(%v) = true", err, ssf.ErrUnauthorized)
	}
	if scope.StreamID != "" || scope.Subject != nil {
		t.Fatalf("AlwaysReject scope = %+v, want zero value", scope)
	}
}

// TestAlwaysAllowReturnsNil pins the test-only "permit everything"
// helper: the returned error is always nil and the [StreamScope] is
// the zero value. The handler set treats a zero StreamScope as
// "authorized for whatever the request itself names", which is the
// behaviour example servers want.
func TestAlwaysAllowReturnsNil(t *testing.T) {
	t.Parallel()

	req := httptest.NewRequest(http.MethodGet, "/", nil)

	scope, err := transmitter.AlwaysAllow(req)
	if err != nil {
		t.Fatalf("AlwaysAllow error = %v, want nil", err)
	}
	if scope.StreamID != "" || scope.Subject != nil {
		t.Fatalf("AlwaysAllow scope = %+v, want zero value", scope)
	}
}

// TestDefault401HandlerWritesProblemJSON asserts the canonical 401
// response shape: status 401, Content-Type application/problem+json,
// JSON body that round-trips through [ssf.ProblemDetails] and
// surfaces the underlying error message in Detail.
func TestDefault401HandlerWritesProblemJSON(t *testing.T) {
	t.Parallel()

	sentinel := errors.New("token missing")
	handler := transmitter.Default401Handler(sentinel)

	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/", nil))

	res := rec.Result()
	defer func() { _ = res.Body.Close() }()

	if res.StatusCode != http.StatusUnauthorized {
		t.Fatalf("status = %d, want %d", res.StatusCode, http.StatusUnauthorized)
	}

	gotCT := res.Header.Get("Content-Type")
	if gotCT != "application/problem+json" {
		t.Fatalf("Content-Type = %q, want %q", gotCT, "application/problem+json")
	}

	body, err := io.ReadAll(res.Body)
	if err != nil {
		t.Fatalf("read body: %v", err)
	}

	var got ssf.ProblemDetails
	if err := json.Unmarshal(body, &got); err != nil {
		t.Fatalf("unmarshal problem-details: %v\nbody: %s", err, body)
	}

	if got.Status != http.StatusUnauthorized {
		t.Errorf("ProblemDetails.Status = %d, want %d", got.Status, http.StatusUnauthorized)
	}
	if got.Title != "Unauthorized" {
		t.Errorf("ProblemDetails.Title = %q, want %q", got.Title, "Unauthorized")
	}
	if got.Detail != sentinel.Error() {
		t.Errorf("ProblemDetails.Detail = %q, want %q", got.Detail, sentinel.Error())
	}
	if got.Type == "" {
		t.Errorf("ProblemDetails.Type empty; want a non-empty URI reference")
	}

	// The error message also has to appear in the raw body — callers
	// scraping the response without re-parsing rely on this.
	if !strings.Contains(string(body), sentinel.Error()) {
		t.Errorf("body %q does not contain error %q", body, sentinel.Error())
	}
}

// TestDefault401HandlerNilError covers the edge case where the
// caller renders a 401 without a specific underlying error — the
// status code and Content-Type still hold, and the body is a valid
// problem-details document with an empty Detail.
func TestDefault401HandlerNilError(t *testing.T) {
	t.Parallel()

	handler := transmitter.Default401Handler(nil)

	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/", nil))

	res := rec.Result()
	defer func() { _ = res.Body.Close() }()

	if res.StatusCode != http.StatusUnauthorized {
		t.Fatalf("status = %d, want %d", res.StatusCode, http.StatusUnauthorized)
	}
	if got := res.Header.Get("Content-Type"); got != "application/problem+json" {
		t.Fatalf("Content-Type = %q, want %q", got, "application/problem+json")
	}

	body, err := io.ReadAll(res.Body)
	if err != nil {
		t.Fatalf("read body: %v", err)
	}

	var got ssf.ProblemDetails
	if err := json.Unmarshal(body, &got); err != nil {
		t.Fatalf("unmarshal problem-details: %v\nbody: %s", err, body)
	}
	if got.Detail != "" {
		t.Errorf("ProblemDetails.Detail = %q, want empty (nil error)", got.Detail)
	}
	if got.Status != http.StatusUnauthorized {
		t.Errorf("ProblemDetails.Status = %d, want %d", got.Status, http.StatusUnauthorized)
	}
	if got.Title != "Unauthorized" {
		t.Errorf("ProblemDetails.Title = %q, want %q", got.Title, "Unauthorized")
	}
}

// TestStreamScopeZeroValue documents the zero-value semantics of
// [transmitter.StreamScope] — both fields empty — so accidental
// changes to the struct are caught at compile time and the
// "authorized for whatever the request itself names" interpretation
// stays load-bearing.
func TestStreamScopeZeroValue(t *testing.T) {
	t.Parallel()

	var zero transmitter.StreamScope
	if zero.StreamID != "" {
		t.Errorf("zero StreamScope.StreamID = %q, want empty", zero.StreamID)
	}
	if zero.Subject != nil {
		t.Errorf("zero StreamScope.Subject = %v, want nil", zero.Subject)
	}
}
