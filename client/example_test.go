// Copyright 2026 The go-ssf Authors
// SPDX-License-Identifier: Apache-2.0

package client_test

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"

	ssf "github.com/hstern/go-ssf"
	"github.com/hstern/go-ssf/client"
	"github.com/hstern/go-ssf/transmitter"
)

// ExampleNewClient constructs a [client.Client] pointed at a stub
// Transmitter and issues one stream-configuration call. The stub
// stands in for a real Transmitter; a production client targets the
// Transmitter's deployed origin URL.
func ExampleNewClient() {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"stream_id":"s-42","iss":"https://tx.example","delivery":{"method":"urn:ietf:rfc:8935"}}`))
	}))
	defer srv.Close()

	c, err := client.NewClient(srv.URL,
		client.WithAuthorizationHeader("Bearer demo-token"))
	if err != nil {
		// handle err
		return
	}

	cfg, err := c.GetConfig(context.Background(), "s-42")
	if err != nil {
		// handle err
		return
	}

	fmt.Println("stream:", cfg.StreamID)
	fmt.Println("iss:", cfg.Iss)

	// Output:
	// stream: s-42
	// iss: https://tx.example
}

// ExampleFetchTransmitterConfig discovers a Transmitter's metadata
// document from its well-known endpoint per OpenID Shared Signals
// Framework 1.0 §3, parses it into a [ssf.TransmitterConfig], and
// reads back a couple of fields.
func ExampleFetchTransmitterConfig() {
	want := &ssf.TransmitterConfig{
		Issuer:                   "https://transmitter.example.com",
		JWKSURI:                  "https://transmitter.example.com/jwks.json",
		DeliveryMethodsSupported: []string{ssf.DeliveryMethodPush},
		SpecVersion:              ssf.SpecVersion,
	}

	mux := http.NewServeMux()
	mux.Handle(transmitter.WellKnownPath, transmitter.WellKnownHandler(want))
	mux.HandleFunc("/", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	})

	srv := httptest.NewServer(mux)
	defer srv.Close()

	got, err := client.FetchTransmitterConfig(context.Background(), srv.URL)
	if err != nil {
		// handle err
		return
	}

	// json.Marshal turns the discovery shape into bytes the example
	// can print deterministically — the field order is fixed.
	out, _ := json.Marshal(struct {
		Iss     string `json:"issuer"`
		SpecVer string `json:"spec_version"`
	}{got.Issuer, got.SpecVersion})

	fmt.Println(string(out))

	// Output:
	// {"issuer":"https://transmitter.example.com","spec_version":"1.0"}
}
