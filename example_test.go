// Copyright 2026 The go-ssf Authors
// SPDX-License-Identifier: Apache-2.0

package ssf_test

import (
	"encoding/json"
	"errors"
	"fmt"

	"github.com/hstern/go-ssf"
)

// ExampleSpecVersion shows the spec-version constant the library
// reports to callers and embeds in [ssf.TransmitterConfig.SpecVersion]
// per OpenID Shared Signals Framework 1.0 §3.
func ExampleSpecVersion() {
	fmt.Println(ssf.SpecVersion)
	// Output: 1.0
}

// ExampleRegisterDeliveryMethod registers a hypothetical extension
// delivery method, looks the factory back out of the registry, and
// demonstrates the [ssf.ErrMethodReserved] guard that protects the
// IANA built-in URIs ([ssf.DeliveryMethodPush], [ssf.DeliveryMethodPoll]).
func ExampleRegisterDeliveryMethod() {
	const methodURI = "urn:example:webhook"

	err := ssf.RegisterDeliveryMethod(methodURI, func() ssf.Delivery {
		return ssf.Delivery{Method: methodURI}
	})
	if err != nil {
		// handle err
		return
	}

	factory, ok := ssf.LookupDeliveryMethod(methodURI)
	fmt.Println("registered:", ok)
	fmt.Println("method URI:", factory().Method)

	// Attempting to re-register a built-in URI is refused with
	// [ssf.ErrMethodReserved]; consumers detect it with [errors.Is].
	err = ssf.RegisterDeliveryMethod(ssf.DeliveryMethodPush, func() ssf.Delivery {
		return ssf.Delivery{}
	})
	fmt.Println("built-in reserved:", errors.Is(err, ssf.ErrMethodReserved))

	// Output:
	// registered: true
	// method URI: urn:example:webhook
	// built-in reserved: true
}

// ExampleUnknownDelivery demonstrates the forward-compatibility
// carrier: a [ssf.StreamConfig] whose delivery method is not in the
// library's built-in set and was not registered via
// [ssf.RegisterDeliveryMethod] decodes into a [ssf.Delivery] whose
// [ssf.Delivery.Unknown] accessor returns the raw JSON bytes verbatim.
func ExampleUnknownDelivery() {
	payload := []byte(`{"method":"urn:example:unknown-2099","endpoint_url":"https://r.example/in"}`)

	var d ssf.Delivery
	if err := json.Unmarshal(payload, &d); err != nil {
		// handle err
		return
	}

	unknown, isUnknown := d.Unknown()
	fmt.Println("known:", d.Known())
	fmt.Println("unknown:", isUnknown)
	fmt.Println("method:", unknown.Method)

	// Output:
	// known: false
	// unknown: true
	// method: urn:example:unknown-2099
}
