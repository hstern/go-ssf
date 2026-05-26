// Copyright 2026 The go-ssf Authors
// SPDX-License-Identifier: Apache-2.0

package memstore_test

import (
	"context"
	"encoding/json"
	"fmt"

	ssf "github.com/hstern/go-ssf"
	"github.com/hstern/go-ssf/memstore"
)

// ExampleNewInMemoryStore exercises the [ssf.StreamStore] surface end
// to end: create a stream (the store assigns the stream_id), fetch it
// back, and confirm the round-trip. The in-memory store is the
// reference [ssf.StreamStore] for tests, demos, and the conformance
// harness.
func ExampleNewInMemoryStore() {
	store := memstore.NewInMemoryStore()
	ctx := context.Background()

	created, err := store.CreateStream(ctx, &ssf.StreamConfig{
		StreamID:        "stream-example-1",
		Iss:             "https://transmitter.example.com",
		Aud:             json.RawMessage(`"receiver.example.com"`),
		EventsRequested: []string{"https://schemas.openid.net/secevent/risc/event-type/account-disabled"},
		Delivery: ssf.Delivery{
			Method:      ssf.DeliveryMethodPush,
			EndpointURL: "https://receiver.example.com/ssf/in",
		},
	})
	if err != nil {
		// handle err
		return
	}

	got, err := store.GetStream(ctx, created.StreamID)
	if err != nil {
		// handle err
		return
	}

	fmt.Println("stream_id:", got.StreamID)
	fmt.Println("delivery method:", got.Delivery.Method)

	// Output:
	// stream_id: stream-example-1
	// delivery method: urn:ietf:rfc:8935
}
