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
	"time"

	jose "github.com/go-jose/go-jose/v4"

	ssf "github.com/hstern/go-ssf"
	"github.com/hstern/go-ssf/receiver"
)

// newHS256Signer is a small example helper that builds an HS256
// [ssf.SETSigner] / [ssf.SETVerifier] pair. Production deployments
// use asymmetric keys (RS, ES, EdDSA) so Receivers can verify against
// the Transmitter's published JWKS, but HS256 keeps the examples
// self-contained.
func newHS256Signer() (ssf.SETSigner, ssf.SETVerifier, error) {
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		return nil, nil, err
	}
	opts := (&jose.SignerOptions{}).WithType(ssf.SETMediaType)
	joseSigner, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.HS256, Key: key}, opts)
	if err != nil {
		return nil, nil, err
	}
	signer, err := ssf.NewJOSESetSigner(joseSigner)
	if err != nil {
		return nil, nil, err
	}
	verifier := ssf.NewJOSESetVerifier(jose.JSONWebKeySet{
		Keys: []jose.JSONWebKey{{Key: key, Algorithm: string(jose.HS256), Use: "sig"}},
	})
	return signer, verifier, nil
}

// ExamplePushHandler shows the minimal RFC 8935 push-delivery
// integration: a [ssf.SETVerifier] over the Transmitter's signing key
// and a [receiver.SinkFunc] that records the verified SET payload
// bytes for downstream processing.
func ExamplePushHandler() {
	signer, verifier, err := newHS256Signer()
	if err != nil {
		// handle err
		return
	}

	delivered := make(chan []byte, 1)
	sink := receiver.SinkFunc(func(_ context.Context, payload []byte) error {
		delivered <- payload
		return nil
	})

	srv := httptest.NewServer(receiver.PushHandler(verifier, sink))
	defer srv.Close()

	// The Transmitter would normally produce this token; for the
	// example we sign one inline.
	payload := []byte(`{"iss":"https://tx.example","jti":"abc","iat":1716422400,"events":{}}`)
	jws, err := signer.Sign(payload)
	if err != nil {
		// handle err
		return
	}

	resp, err := http.Post(srv.URL, "application/secevent+jwt", strings.NewReader(jws))
	if err != nil {
		// handle err
		return
	}
	_ = resp.Body.Close()

	fmt.Println("status:", resp.StatusCode)
	fmt.Println("delivered jti len:", len(<-delivered) > 0)

	// Output:
	// status: 202
	// delivered jti len: true
}

// ExamplePoller_Run constructs a [receiver.Poller] against a stub
// Transmitter and runs it for a short window. Run returns
// [context.Context.Err] on cancellation, which is the normal exit
// path for a long-running poller wired into a service's shutdown flow.
func ExamplePoller_Run() {
	_, verifier, err := newHS256Signer()
	if err != nil {
		// handle err
		return
	}

	// Stub Transmitter that always reports an empty poll response.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"sets":{}}`)
	}))
	defer srv.Close()

	sink := receiver.SinkFunc(func(_ context.Context, _ []byte) error { return nil })

	poller := receiver.NewPoller(srv.URL, verifier, sink,
		receiver.WithNoEventsBackoff(10*time.Millisecond, 50*time.Millisecond))

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()

	err = poller.Run(ctx)
	fmt.Println("exited on deadline:", errors.Is(err, context.DeadlineExceeded))

	// Output:
	// exited on deadline: true
}

// ExampleVerificationChallenger_Challenge initiates a spec §7.1.4
// verification handshake, simulates the Transmitter's matching SET by
// feeding the wrapped [receiver.Sink], and recovers the verification
// payload bytes.
func ExampleVerificationChallenger_Challenge() {
	chal := receiver.NewVerificationChallenger()

	// Stub Transmitter verification endpoint that accepts the POST.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Echo the Receiver-supplied state via a "matching" SET
		// payload delivered through the wrapped Sink from a
		// background goroutine.
		var req ssf.VerificationRequest
		_ = json.NewDecoder(r.Body).Decode(&req)
		go func() {
			payload := fmt.Appendf(nil,
				`{"events":{"%s":{"state":%q}}}`,
				ssf.EventTypeVerification, req.State)
			_ = chal.WrapSink(receiver.SinkFunc(func(context.Context, []byte) error {
				return nil
			})).DeliverSET(context.Background(), payload)
		}()
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()

	payload, err := chal.Challenge(ctx,
		receiver.WithEndpoint(srv.URL),
		receiver.WithState("example-state-1"),
		receiver.WithTimeout(500*time.Millisecond))
	if err != nil {
		// handle err
		return
	}

	fmt.Println("matched:", strings.Contains(string(payload), "example-state-1"))

	// Output:
	// matched: true
}
