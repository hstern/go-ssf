// Copyright 2026 The go-ssf Authors
// SPDX-License-Identifier: Apache-2.0

package receiver_test

import (
	"context"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	jose "github.com/go-jose/go-jose/v4"

	"github.com/hstern/go-ssf"
	"github.com/hstern/go-ssf/receiver"
)

// samplePayload is the canonical claims-set body used across these
// tests. It is the smallest set the spec accepts and is stable so
// test assertions on byte equality can be exact.
const samplePayload = `{"iss":"https://transmitter.example.com","aud":"receiver.example.com","jti":"abc","iat":1716422400,"events":{}}`

// hs256Key returns a 32-byte random HMAC key — the minimum size
// go-jose requires for HS256. The test surface stays HMAC-only to
// match the parent set_test.go conventions (no PEM, no keypair
// generation).
func hs256Key(t *testing.T) []byte {
	t.Helper()
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		t.Fatalf("rand.Read: %v", err)
	}
	return key
}

// newJOSESignerForSET builds a jose.Signer over an HS256 key with
// the SET typ header set, ready to feed [ssf.NewJOSESetSigner].
func newJOSESignerForSET(t *testing.T, key []byte) jose.Signer {
	t.Helper()
	opts := (&jose.SignerOptions{}).WithType(ssf.SETMediaType)
	signer, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.HS256, Key: key}, opts)
	if err != nil {
		t.Fatalf("jose.NewSigner: %v", err)
	}
	return signer
}

// signSET produces a compact JWS over payload using a fresh
// JOSESetSigner. Returns the JWS and the key it was signed with so
// the caller can build a matching verifier.
func signSET(t *testing.T, payload []byte) (jwsCompact string, key []byte) {
	t.Helper()
	key = hs256Key(t)
	signer, err := ssf.NewJOSESetSigner(newJOSESignerForSET(t, key))
	if err != nil {
		t.Fatalf("NewJOSESetSigner: %v", err)
	}
	jws, err := signer.Sign(payload)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	return jws, key
}

// verifierForKey wraps key in a single-entry JWKS the receiver will
// use to verify incoming SETs.
func verifierForKey(key []byte) *ssf.JOSESetVerifier {
	return ssf.NewJOSESetVerifier(jose.JSONWebKeySet{
		Keys: []jose.JSONWebKey{{Key: key, Algorithm: string(jose.HS256), Use: "sig"}},
	})
}

// newPushRequest builds a POST against /events with the SSF push
// media type set and body as the request payload. Tests that need a
// different method or content-type construct the request inline.
func newPushRequest(body string) *http.Request {
	req := httptest.NewRequest(http.MethodPost, "/events", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/secevent+jwt")
	return req
}

// TestPushHandlerAcceptsValidSET covers the happy path: a real
// HS256-signed SET is POSTed at the push endpoint, the configured
// verifier accepts it, the Sink receives the original payload bytes,
// and the handler responds 202 with an empty body.
func TestPushHandlerAcceptsValidSET(t *testing.T) {
	t.Parallel()

	jws, key := signSET(t, []byte(samplePayload))

	var got []byte
	handler := receiver.PushHandler(verifierForKey(key),
		receiver.SinkFunc(func(_ context.Context, payload []byte) error {
			got = payload
			return nil
		}))

	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, newPushRequest(jws))

	if rec.Code != http.StatusAccepted {
		t.Fatalf("status: got %d, want %d (body=%q)", rec.Code, http.StatusAccepted, rec.Body.String())
	}
	if rec.Body.Len() != 0 {
		t.Errorf("body: got %q, want empty", rec.Body.String())
	}
	if string(got) != samplePayload {
		t.Errorf("sink payload:\ngot  %s\nwant %s", got, samplePayload)
	}
}

// TestPushHandlerSinkFuncAdapter checks that the SinkFunc adapter
// satisfies the Sink interface end-to-end through the handler. The
// happy-path test above already exercises a SinkFunc; this test
// pins the contract by calling DeliverSET directly on the adapter.
func TestPushHandlerSinkFuncAdapter(t *testing.T) {
	t.Parallel()

	called := false
	var sink receiver.Sink = receiver.SinkFunc(func(_ context.Context, _ []byte) error {
		called = true
		return nil
	})
	if err := sink.DeliverSET(context.Background(), []byte("{}")); err != nil {
		t.Fatalf("DeliverSET: %v", err)
	}
	if !called {
		t.Fatal("SinkFunc was not invoked")
	}
}

// TestPushHandlerRejectsWrongMethod covers the 405 path. RFC 8935
// §3 only defines POST on the push endpoint; every other method is
// rejected with an Allow header naming POST.
func TestPushHandlerRejectsWrongMethod(t *testing.T) {
	t.Parallel()

	handler := receiver.PushHandler(verifierForKey(hs256Key(t)),
		receiver.SinkFunc(func(context.Context, []byte) error {
			t.Fatal("sink must not be called for wrong-method requests")
			return nil
		}))

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/events", nil)
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusMethodNotAllowed {
		t.Fatalf("status: got %d, want %d", rec.Code, http.StatusMethodNotAllowed)
	}
	if got := rec.Header().Get("Allow"); got != http.MethodPost {
		t.Errorf("Allow: got %q, want %q", got, http.MethodPost)
	}
	if got := rec.Header().Get("Content-Type"); got != "application/problem+json" {
		t.Errorf("Content-Type: got %q, want application/problem+json", got)
	}
}

// TestPushHandlerRejectsWrongContentType covers the 415 path. RFC
// 8935 §2 fixes the push media type at application/secevent+jwt;
// requests carrying a different type are refused before the body is
// read.
func TestPushHandlerRejectsWrongContentType(t *testing.T) {
	t.Parallel()

	handler := receiver.PushHandler(verifierForKey(hs256Key(t)),
		receiver.SinkFunc(func(context.Context, []byte) error {
			t.Fatal("sink must not be called for wrong-content-type requests")
			return nil
		}))

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/events", strings.NewReader("not-a-jws"))
	req.Header.Set("Content-Type", "application/json")
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusUnsupportedMediaType {
		t.Fatalf("status: got %d, want %d", rec.Code, http.StatusUnsupportedMediaType)
	}
}

// TestPushHandlerAcceptsContentTypeWithParameters checks the
// Postel's-law leniency: a Content-Type with parameters (which the
// spec does not define but real-world senders sometimes attach) is
// accepted as long as the base media type matches.
func TestPushHandlerAcceptsContentTypeWithParameters(t *testing.T) {
	t.Parallel()

	jws, key := signSET(t, []byte(samplePayload))

	handler := receiver.PushHandler(verifierForKey(key),
		receiver.SinkFunc(func(context.Context, []byte) error { return nil }))

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/events", strings.NewReader(jws))
	req.Header.Set("Content-Type", "application/secevent+jwt; charset=utf-8")
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusAccepted {
		t.Fatalf("status: got %d, want %d (body=%q)", rec.Code, http.StatusAccepted, rec.Body.String())
	}
}

// TestPushHandlerRejectsOversizedBody covers the 413 path. A body
// larger than the configured cap is refused after the cap's worth
// of bytes has been consumed.
func TestPushHandlerRejectsOversizedBody(t *testing.T) {
	t.Parallel()

	handler := receiver.PushHandler(verifierForKey(hs256Key(t)),
		receiver.SinkFunc(func(context.Context, []byte) error {
			t.Fatal("sink must not be called for oversized bodies")
			return nil
		}),
		receiver.WithMaxBytes(32))

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/events", strings.NewReader(strings.Repeat("a", 1024)))
	req.Header.Set("Content-Type", "application/secevent+jwt")
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("status: got %d, want %d (body=%q)", rec.Code, http.StatusRequestEntityTooLarge, rec.Body.String())
	}
}

// TestPushHandlerRejectsVerifierFailure covers the 400-from-verifier
// path. A SET signed with a different key than the verifier holds
// fails signature validation and the handler returns 400 — RFC 8935
// §3.2 treats this as permanent and the Transmitter will not retry.
func TestPushHandlerRejectsVerifierFailure(t *testing.T) {
	t.Parallel()

	jws, _ := signSET(t, []byte(samplePayload))

	// Verifier holds a different key — signature validation fails.
	wrongKey := hs256Key(t)

	handler := receiver.PushHandler(verifierForKey(wrongKey),
		receiver.SinkFunc(func(context.Context, []byte) error {
			t.Fatal("sink must not be called when verification fails")
			return nil
		}))

	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, newPushRequest(jws))

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status: got %d, want %d", rec.Code, http.StatusBadRequest)
	}
	if got := rec.Header().Get("Content-Type"); got != "application/problem+json" {
		t.Errorf("Content-Type: got %q, want application/problem+json", got)
	}
	// Body must parse as RFC 7807 problem-details and echo the status.
	body, _ := io.ReadAll(rec.Body)
	var prob ssf.ProblemDetails
	if err := json.Unmarshal(body, &prob); err != nil {
		t.Fatalf("decode problem-details body: %v (body=%q)", err, body)
	}
	if prob.Status != http.StatusBadRequest {
		t.Errorf("problem.status: got %d, want %d", prob.Status, http.StatusBadRequest)
	}
}

// TestPushHandlerSinkPermanentErrorReturns400 covers the permanent-
// failure path: a Sink that wraps [receiver.ErrPermanent] tells the
// handler the event will never succeed, so the response is 400 and
// the Transmitter is asked not to retry.
func TestPushHandlerSinkPermanentErrorReturns400(t *testing.T) {
	t.Parallel()

	jws, key := signSET(t, []byte(samplePayload))

	handler := receiver.PushHandler(verifierForKey(key),
		receiver.SinkFunc(func(context.Context, []byte) error {
			return fmt.Errorf("unsupported event type: %w", receiver.ErrPermanent)
		}))

	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, newPushRequest(jws))

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status: got %d, want %d (body=%q)", rec.Code, http.StatusBadRequest, rec.Body.String())
	}
}

// TestPushHandlerSinkTransientErrorReturns503 covers the default
// retry path: a plain non-nil error from the Sink is treated as
// transient and the handler returns 503 so RFC 8935 §3.2 directs
// the Transmitter to retry.
func TestPushHandlerSinkTransientErrorReturns503(t *testing.T) {
	t.Parallel()

	jws, key := signSET(t, []byte(samplePayload))

	handler := receiver.PushHandler(verifierForKey(key),
		receiver.SinkFunc(func(context.Context, []byte) error {
			return errors.New("database unavailable")
		}))

	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, newPushRequest(jws))

	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("status: got %d, want %d (body=%q)", rec.Code, http.StatusServiceUnavailable, rec.Body.String())
	}
}

// TestPushHandlerRejectsEmptyBody covers the corner where the
// request passes the method and content-type checks but carries no
// JWS at all. The handler returns 400 — there is nothing to verify
// and retrying will not help — without invoking the verifier.
func TestPushHandlerRejectsEmptyBody(t *testing.T) {
	t.Parallel()

	handler := receiver.PushHandler(verifierForKey(hs256Key(t)),
		receiver.SinkFunc(func(context.Context, []byte) error {
			t.Fatal("sink must not be called for empty bodies")
			return nil
		}))

	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, newPushRequest(""))

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status: got %d, want %d", rec.Code, http.StatusBadRequest)
	}
}
