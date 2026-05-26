// Copyright 2026 The go-ssf Authors
// SPDX-License-Identifier: Apache-2.0

package transmitter_test

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"

	jose "github.com/go-jose/go-jose/v4"

	ssf "github.com/hstern/go-ssf"
	"github.com/hstern/go-ssf/transmitter"
)

// pollOnlyTransmitter is a partial [transmitter.Transmitter] that only
// implements poll-mode delivery. Every other method falls through to
// the embedded [transmitter.NotImplementedTransmitter] and returns
// [ssf.ErrNotImplemented], which the HTTP handler layer maps to
// 501 Not Implemented.
type pollOnlyTransmitter struct {
	transmitter.NotImplementedTransmitter
}

// PollEvents overrides the embedded zero-value behavior with a real
// implementation; for the example it returns an empty response.
func (pollOnlyTransmitter) PollEvents(_ context.Context, _ string, _ *ssf.PollRequest) (*ssf.PollResponse, error) {
	return &ssf.PollResponse{Sets: map[string]string{}}, nil
}

// ExampleNotImplementedTransmitter shows the embed-and-override
// pattern: a partial [transmitter.Transmitter] implements only the
// methods that matter to it and inherits [ssf.ErrNotImplemented] for
// the rest from the embedded zero value.
func ExampleNotImplementedTransmitter() {
	var t transmitter.Transmitter = pollOnlyTransmitter{}

	// The overridden method succeeds.
	resp, err := t.PollEvents(context.Background(), "stream-1", &ssf.PollRequest{})
	fmt.Println("poll err:", err)
	fmt.Println("poll sets:", len(resp.Sets))

	// An unimplemented method returns [ssf.ErrNotImplemented].
	_, err = t.GetConfig(context.Background(), "stream-1")
	fmt.Println("get-config not implemented:", errors.Is(err, ssf.ErrNotImplemented))

	// Output:
	// poll err: <nil>
	// poll sets: 0
	// get-config not implemented: true
}

// ExampleMuxHandler wires a minimal Transmitter into the canonical
// endpoint set with [transmitter.AlwaysAllow] standing in for real
// authentication. Production deployments replace the AuthFunc with one
// that validates the deployment's chosen credential scheme.
func ExampleMuxHandler() {
	t := pollOnlyTransmitter{}

	mux := transmitter.MuxHandler(t, transmitter.AlwaysAllow)

	srv := httptest.NewServer(mux)
	defer srv.Close()

	// A request to any spec-defined path now routes through the
	// handler set; here we hit the poll endpoint and read the empty
	// JSON envelope the stub Transmitter returns.
	body := bytes.NewReader([]byte(`{}`))
	resp, err := http.Post(srv.URL+transmitter.DefaultPollPath+"?stream_id=s1",
		"application/json", body)
	if err != nil {
		// handle err
		return
	}
	defer func() { _ = resp.Body.Close() }()

	fmt.Println("status:", resp.StatusCode)

	// Output:
	// status: 200
}

// ExampleWellKnownHandler publishes a populated
// [ssf.TransmitterConfig] at [transmitter.WellKnownPath] per OpenID
// Shared Signals Framework 1.0 §3. Receivers fetch this document to
// learn the Transmitter's endpoints and supported delivery methods.
func ExampleWellKnownHandler() {
	cfg := &ssf.TransmitterConfig{
		Issuer:                   "https://transmitter.example.com",
		JWKSURI:                  "https://transmitter.example.com/jwks.json",
		DeliveryMethodsSupported: []string{ssf.DeliveryMethodPush, ssf.DeliveryMethodPoll},
		SpecVersion:              ssf.SpecVersion,
	}

	mux := http.NewServeMux()
	mux.Handle(transmitter.WellKnownPath, transmitter.WellKnownHandler(cfg))

	srv := httptest.NewServer(mux)
	defer srv.Close()

	resp, err := http.Get(srv.URL + transmitter.WellKnownPath)
	if err != nil {
		// handle err
		return
	}
	defer func() { _ = resp.Body.Close() }()

	var got ssf.TransmitterConfig
	if err := json.NewDecoder(resp.Body).Decode(&got); err != nil {
		// handle err
		return
	}

	fmt.Println("issuer:", got.Issuer)
	fmt.Println("spec:", got.SpecVersion)

	// Output:
	// issuer: https://transmitter.example.com
	// spec: 1.0
}

// ExamplePushDriver_Deliver signs a single Security Event Token and
// pushes it to a Receiver endpoint per RFC 8935. The Receiver in this
// example is an [net/http/httptest.Server] that records the request
// and returns 202 Accepted — the spec's success status for push
// delivery.
func ExamplePushDriver_Deliver() {
	// Build an HS256-backed [ssf.SETSigner]. Production deployments
	// would use an asymmetric key (RS, ES, EdDSA) so Receivers can
	// verify against the Transmitter's published JWKS.
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		// handle err
		return
	}
	opts := (&jose.SignerOptions{}).WithType(ssf.SETMediaType)
	joseSigner, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.HS256, Key: key}, opts)
	if err != nil {
		// handle err
		return
	}
	signer, err := ssf.NewJOSESetSigner(joseSigner)
	if err != nil {
		// handle err
		return
	}

	// Stand up a stub Receiver that accepts every push.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusAccepted)
	}))
	defer srv.Close()

	driver := transmitter.NewPushDriver(signer, transmitter.WithMaxRetries(0))
	payload := []byte(`{"iss":"https://tx.example","jti":"abc","iat":1716422400,"events":{}}`)

	err = driver.Deliver(context.Background(),
		transmitter.Target{EndpointURL: srv.URL},
		payload)
	fmt.Println("delivered:", err == nil)

	// Output:
	// delivered: true
}
