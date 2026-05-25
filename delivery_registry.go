// Copyright 2026 The go-ssf Authors
// SPDX-License-Identifier: Apache-2.0

package ssf

import (
	"encoding/json"
	"fmt"
	"sync"
)

// DeliveryMethodFactory is the per-method factory the registry holds.
// Each factory returns a freshly-allocated zero-valued [Delivery]
// whose Method field is set to the discriminator URI the factory
// is registered under; the codec invokes the standard JSON decoder
// against that value to fill in the method-specific fields.
//
// Factories registered for extension methods at consumer init time
// are expected to follow the same convention: return a zero-valued
// [Delivery] (or a value pre-populated with method-specific
// defaults). The registry treats the factory output as the seed
// passed to [encoding/json.Unmarshal] for the body of the delivery
// object on the wire.
type DeliveryMethodFactory func() Delivery

// deliveryRegistry is the package-global dispatch table for delivery
// methods. It is seeded at package load with the two built-in
// methods from the IANA "Security Event Token Delivery Methods"
// registry (RFC 8935 push, RFC 8936 poll) and amended at consumer
// init time via [RegisterDeliveryMethod]. The codec reads it on
// every [Delivery.UnmarshalJSON] call; the rare write path is
// [RegisterDeliveryMethod].
//
// Field order — map first, mutex second — places the (no-pointer)
// [sync.RWMutex] after the map so the garbage collector can stop
// scanning earlier on each cycle.
var deliveryRegistry = struct {
	m  map[string]DeliveryMethodFactory
	mu sync.RWMutex
}{m: builtinDeliveryMethods()}

// builtinDeliveryMethods returns a freshly-allocated map populated
// with the two delivery methods from the IANA Security Event Token
// Delivery Methods registry as of RFC 8935 / RFC 8936. A new map is
// returned per call so callers cannot mutate the package's shared
// registry by holding a reference to the initial value.
func builtinDeliveryMethods() map[string]DeliveryMethodFactory {
	return map[string]DeliveryMethodFactory{
		DeliveryMethodPush: func() Delivery { return Delivery{Method: DeliveryMethodPush} },
		DeliveryMethodPoll: func() Delivery { return Delivery{Method: DeliveryMethodPoll} },
	}
}

// builtinDeliveryMethodNames is the set of method URIs
// [builtinDeliveryMethods] populates. [RegisterDeliveryMethod]
// checks against it to detect built-in collisions without needing
// to know whether a registry entry was placed by
// builtinDeliveryMethods or by an earlier RegisterDeliveryMethod
// call.
var builtinDeliveryMethodNames = map[string]struct{}{
	DeliveryMethodPush: {},
	DeliveryMethodPoll: {},
}

// RegisterDeliveryMethod registers a [DeliveryMethodFactory] for a
// delivery-method URI outside the IANA built-in set.
//
// Call once per extension method, typically at consumer init time.
// Re-registering an already-registered extension method silently
// replaces the prior factory — a single consumer init owns each
// extension method by convention. Concurrent callers are
// serialized by an internal mutex.
//
// Returns an error wrapping [ErrMethodReserved] if methodURI
// matches one of the built-in method URIs ([DeliveryMethodPush],
// [DeliveryMethodPoll]): those cannot be overridden. Consumers
// needing different per-built-in behavior should wrap the concrete
// type rather than re-register the method. Compare the returned
// error with [errors.Is].
//
// The IANA "Security Event Token Delivery Methods" registry
// (RFC 8935 §6) is the source of truth for delivery methods; the
// library's built-in set is a snapshot, and new methods land via
// RegisterDeliveryMethod or additive minor library releases.
func RegisterDeliveryMethod(methodURI string, factory DeliveryMethodFactory) error {
	if _, builtin := builtinDeliveryMethodNames[methodURI]; builtin {
		return fmt.Errorf("%w: %q", ErrMethodReserved, methodURI)
	}
	deliveryRegistry.mu.Lock()
	defer deliveryRegistry.mu.Unlock()
	deliveryRegistry.m[methodURI] = factory
	return nil
}

// LookupDeliveryMethod returns the factory registered for the given
// method URI, or nil and false if no factory is registered. The
// codec uses LookupDeliveryMethod from [Delivery.UnmarshalJSON] to
// dispatch by method; a (nil, false) return causes the decoder to
// fall back to an [UnknownDelivery] carrier preserving the raw
// JSON bytes verbatim.
//
// Concurrent calls are safe: the registry is read-mostly and
// guarded by a [sync.RWMutex], so lookups proceed in parallel.
func LookupDeliveryMethod(methodURI string) (DeliveryMethodFactory, bool) {
	deliveryRegistry.mu.RLock()
	defer deliveryRegistry.mu.RUnlock()
	f, ok := deliveryRegistry.m[methodURI]
	return f, ok
}

// UnknownDelivery is the forward-compatibility carrier for delivery
// methods that are neither in the library's built-in set nor
// registered via [RegisterDeliveryMethod] at the time the wire
// payload is decoded. A library compiled today, decoding a
// [StreamConfig] that uses a delivery method the IANA registry
// adds in a future revision, produces an UnknownDelivery rather
// than an error so the value can still round-trip and callers can
// branch on whatever subset of methods they actually understand.
//
// The wire bytes are preserved verbatim in [UnknownDelivery.Raw]
// so re-encoding through [Delivery.MarshalJSON] (added in a later
// commit) produces the original payload byte-for-byte, modulo
// JSON whitespace canonicalization performed by
// [encoding/json.Marshal]. Raw is intentionally a
// [json.RawMessage] rather than a map[string]any: interop
// scenarios often pin exact JSON bytes, and a map reorders its
// keys on every encode.
//
// Access an UnknownDelivery via [Delivery.Unknown], which returns
// the carrier and a boolean indicating whether the [Delivery] was
// produced from an unrecognized method URI. [Delivery.Known]
// reports the inverse.
type UnknownDelivery struct {
	// Method is the value of the JSON "method" member as decoded —
	// the discriminator URI the library did not recognize.
	Method string

	// Raw is the entire JSON object that was decoded, byte-for-byte
	// as it appeared on the wire. Re-encoding through
	// [Delivery.MarshalJSON] returns these bytes unchanged modulo
	// the whitespace canonicalization [encoding/json.Marshal]
	// performs on any [json.Marshaler]'s output.
	Raw json.RawMessage
}
