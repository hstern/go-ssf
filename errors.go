// Copyright 2026 The go-ssf Authors
// SPDX-License-Identifier: Apache-2.0

package ssf

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
)

// Sentinel errors for the Transmitter, Receiver, and client surfaces.
//
// Per AGENTS.md, error sentences are lowercase, unpunctuated, and
// callers wrap with %w when adding context. Use [errors.Is] to match
// a sentinel through wrapping.
//
// The set below is the full library-internal inventory. The HTTP
// layers (the Transmitter handlers and the client) translate between
// these sentinels and the wire-level RFC 7807 problem-details JSON
// responses described in spec §7.
var (
	// ErrStreamNotFound is returned by Transmitter methods when the
	// referenced stream ID does not exist. Per spec §7.1 the HTTP
	// layer maps this to 404 Not Found with an RFC 7807 problem-
	// details body.
	ErrStreamNotFound = errors.New("stream not found")

	// ErrUnauthorized is returned when the caller is not permitted
	// to perform the requested operation on the referenced stream —
	// either no credentials were presented or the scope they carry
	// does not cover the stream. Per spec §7 the HTTP layer maps
	// this to 401 Unauthorized.
	ErrUnauthorized = errors.New("unauthorized")

	// ErrInvalidConfig is returned by [Transmitter.CreateConfig] and
	// [Transmitter.UpdateConfig] when the proposed stream configuration
	// is rejected — unknown delivery method, missing required field,
	// or a value that violates the spec's validation rules. Per spec
	// §7.1.1 the HTTP layer maps this to 400 Bad Request with an
	// RFC 7807 problem-details body.
	ErrInvalidConfig = errors.New("invalid stream configuration")

	// ErrMethodReserved is returned by RegisterDeliveryMethod when a
	// caller attempts to register a method URI that the library
	// already provides as a built-in. The IANA Security Event Token
	// Delivery Methods registry (RFC 8935 §6) is the source of truth
	// for the built-in set; extension methods are welcome but MUST
	// use a distinct URI.
	ErrMethodReserved = errors.New("delivery method reserved")

	// ErrUnsupportedDelivery is returned when the negotiating side
	// advertises a delivery method this build does not recognize, or
	// when the other side selects a method outside the locally
	// advertised set. Per spec §3 the Transmitter's
	// delivery_methods_supported and the Receiver's selection MUST
	// agree.
	ErrUnsupportedDelivery = errors.New("unsupported delivery method")

	// ErrUnsupportedEvent is returned when an event type URI is not
	// among the stream's events_supported (Transmitter side) or
	// events_delivered (Receiver side). Per spec §7.1.1 a Transmitter
	// MUST NOT deliver an event type that is not in events_delivered
	// for the stream.
	ErrUnsupportedEvent = errors.New("unsupported event type")

	// ErrVerificationTimeout is returned when a verification challenge
	// is initiated but no matching verification SET arrives within
	// the configured timeout. Per spec §7.1.4 the Receiver matches
	// the challenge's state value against the SET's event payload;
	// this error covers the case where that match never happens.
	ErrVerificationTimeout = errors.New("verification timeout")

	// ErrNotImplemented is returned by the zero value of the
	// NotImplementedTransmitter helper from every Transmitter method.
	// Embedding NotImplementedTransmitter in a partial Transmitter
	// implementation makes the unimplemented methods return this
	// sentinel, which the HTTP layer maps to 501 Not Implemented.
	// The helper type itself is wired in a later phase; the sentinel
	// is declared here so the inventory is complete.
	ErrNotImplemented = errors.New("not implemented")
)

// ValidationError is the structural-validation failure returned by
// opt-in Validate helpers on spec types. Each instance pins the rule
// that failed, the field that triggered it, and a human-readable
// reason. It implements [error] via a stable format so callers can
// compare or log it directly.
//
// ValidationError is intentionally a concrete struct (not an
// interface) — callers commonly type-assert and inspect the three
// fields. The library wraps ValidationError values with %w when
// composing them with higher-level errors so [errors.As] still
// recovers the original.
type ValidationError struct {
	// Rule names the validation rule that failed (for example
	// "events_requested non-empty" or "method required").
	Rule string

	// Field names the JSON field (or dotted path) that triggered
	// the failure. Empty when the rule applies to the document as
	// a whole.
	Field string

	// Reason is a human-readable explanation suitable for inclusion
	// in a log line or an RFC 7807 problem-details Detail.
	Reason string
}

// Error implements the error interface. The format is stable; tests
// and log scrapers can rely on it.
func (e *ValidationError) Error() string {
	return fmt.Sprintf("ssf: validation failed: rule=%q field=%q: %s",
		e.Rule, e.Field, e.Reason)
}

// HTTPError is the client-side error returned when a Transmitter
// responds with a non-2xx status. It preserves the status code, the
// raw response body, and — when the body parses as RFC 7807
// problem-details JSON — the structured [ProblemDetails]. Callers
// inspect StatusCode to decide retry behavior and consult RFC7807
// for a structured Title or Detail.
//
// The client wraps common status codes to sentinel errors before
// returning HTTPError (401 → [ErrUnauthorized], 404 on a stream
// resource → [ErrStreamNotFound]); callers wanting the underlying
// HTTPError use [errors.As].
type HTTPError struct {
	// StatusCode is the HTTP status code from the response.
	StatusCode int

	// Body is the raw response body. Preserved verbatim so callers
	// have the original bytes for logging or content-type-aware
	// rendering.
	Body []byte

	// RFC7807 is the parsed problem-details document when the
	// response body is application/problem+json and parses
	// successfully. Nil otherwise.
	RFC7807 *ProblemDetails
}

// Error implements the error interface. When RFC 7807 problem-details
// are available, the message includes the Title; otherwise it falls
// back to the raw body (truncated for readability).
func (e *HTTPError) Error() string {
	if e.RFC7807 != nil && e.RFC7807.Title != "" {
		return fmt.Sprintf("ssf: http %d: %s", e.StatusCode, e.RFC7807.Title)
	}

	const bodyLimit = 256
	body := e.Body
	suffix := ""
	if len(body) > bodyLimit {
		body = body[:bodyLimit]
		suffix = "..."
	}

	if len(body) == 0 {
		return fmt.Sprintf("ssf: http %d", e.StatusCode)
	}

	return fmt.Sprintf("ssf: http %d: %s%s", e.StatusCode, body, suffix)
}

// ProblemDetails is the RFC 7807 problem-details JSON document used
// by the Transmitter for non-2xx responses (spec §7). Field naming
// follows RFC 7807 verbatim; the Extensions field captures any
// extension members the responder included beyond the registered set.
//
// Per RFC 7807 §3.2, extension members live at the top level of the
// problem-details object alongside the registered members — not under
// a nested "extensions" key. The [ProblemDetails.MarshalJSON] and
// [ProblemDetails.UnmarshalJSON] methods on this type implement that
// flattening: on decode any member whose key is not one of the five
// registered names is captured verbatim into Extensions; on encode
// the registered members are emitted in spec-figure order followed by
// the extension members in the order they were captured.
//
// Per the project's wire-fidelity posture, Extensions is
// [json.RawMessage] rather than map[string]any — interop scenarios
// pin exact JSON bytes and a map reorders keys on marshal. The
// captured bytes form a JSON object whose members are appended into
// the top-level object on re-encode.
type ProblemDetails struct {
	// Type is a URI reference identifying the problem type. Per
	// RFC 7807 §3.1 the default when absent is "about:blank".
	Type string `json:"type,omitempty"`

	// Title is a short, human-readable summary of the problem type.
	Title string `json:"title,omitempty"`

	// Status is the HTTP status code generated by the origin server.
	Status int `json:"status,omitempty"`

	// Detail is a human-readable explanation specific to this
	// occurrence of the problem.
	Detail string `json:"detail,omitempty"`

	// Instance is a URI reference that identifies the specific
	// occurrence of the problem.
	Instance string `json:"instance,omitempty"`

	// Extensions carries every RFC 7807 extension member from the
	// top level of the source document, captured verbatim as the JSON
	// object whose keys are the extension names and whose values are
	// the original encoded bytes. On marshal these members are
	// emitted flat alongside the five registered fields rather than
	// nested under an "extensions" key. The JSON tag is "-" so the
	// default codec ignores the field; the custom MarshalJSON and
	// UnmarshalJSON methods on [ProblemDetails] own its wire shape.
	Extensions json.RawMessage `json:"-"`
}

// problemDetailsRegistered names the five RFC 7807 registered
// members. UnmarshalJSON partitions the input object into these
// versus extension members; MarshalJSON re-emits registered members
// in this order followed by the captured extensions.
var problemDetailsRegistered = map[string]struct{}{
	"type":     {},
	"title":    {},
	"status":   {},
	"detail":   {},
	"instance": {},
}

// MarshalJSON implements [json.Marshaler] for [ProblemDetails]. It
// emits the five RFC 7807 registered members in spec-figure order
// (type, title, status, detail, instance), skipping members whose Go
// value is the zero value to preserve the omit-empty semantics the
// struct tags advertise. After the registered members it appends the
// captured Extensions verbatim — each key of the Extensions object
// becomes a top-level key of the output, matching RFC 7807 §3.2.
//
// Zero-valued [ProblemDetails] marshals to "{}". Extension keys that
// collide with one of the five registered names are emitted as the
// extension wins (last-write); callers that care about that edge
// should not populate both forms.
func (p *ProblemDetails) MarshalJSON() ([]byte, error) {
	var buf bytes.Buffer
	buf.WriteByte('{')

	writeKey := func(key string) {
		if buf.Len() > 1 {
			buf.WriteByte(',')
		}
		buf.WriteByte('"')
		buf.WriteString(key)
		buf.WriteString(`":`)
	}

	if p.Type != "" {
		writeKey("type")
		encoded, err := json.Marshal(p.Type)
		if err != nil {
			return nil, err
		}
		buf.Write(encoded)
	}
	if p.Title != "" {
		writeKey("title")
		encoded, err := json.Marshal(p.Title)
		if err != nil {
			return nil, err
		}
		buf.Write(encoded)
	}
	if p.Status != 0 {
		writeKey("status")
		encoded, err := json.Marshal(p.Status)
		if err != nil {
			return nil, err
		}
		buf.Write(encoded)
	}
	if p.Detail != "" {
		writeKey("detail")
		encoded, err := json.Marshal(p.Detail)
		if err != nil {
			return nil, err
		}
		buf.Write(encoded)
	}
	if p.Instance != "" {
		writeKey("instance")
		encoded, err := json.Marshal(p.Instance)
		if err != nil {
			return nil, err
		}
		buf.Write(encoded)
	}

	if len(p.Extensions) > 0 {
		// Strip the outer { and } of the Extensions object and
		// append its members. json.Decoder preserves key order; we
		// re-emit the bytes verbatim via json.RawMessage so the
		// keys keep their original ordering and value-byte form.
		ext, err := extensionMembers(p.Extensions)
		if err != nil {
			return nil, err
		}
		for _, m := range ext {
			writeKey(m.key)
			buf.Write(m.value)
		}
	}

	buf.WriteByte('}')
	return buf.Bytes(), nil
}

// UnmarshalJSON implements [json.Unmarshaler] for [ProblemDetails].
// It walks the input object key-by-key, routing the five RFC 7807
// registered members to their typed struct fields and collecting
// every other top-level member verbatim into Extensions. Decode is
// order-preserving for the extension members so a subsequent
// MarshalJSON reproduces the original wire ordering of the
// extensions.
//
// Per the library's lenient-unmarshal posture, unknown top-level
// members are kept, not dropped — they are exactly the extension
// members RFC 7807 §3.2 says implementations MAY publish. Validation
// of values (e.g. type must parse as a URI reference) is reserved for
// the opt-in Validate helper in a later phase.
func (p *ProblemDetails) UnmarshalJSON(data []byte) error {
	// Reset the destination so a re-used pointer does not retain
	// stale state from a previous decode.
	*p = ProblemDetails{}

	dec := json.NewDecoder(bytes.NewReader(data))
	dec.UseNumber()

	tok, err := dec.Token()
	if err != nil {
		return err
	}
	if delim, ok := tok.(json.Delim); !ok || delim != '{' {
		return fmt.Errorf("ssf: ProblemDetails: expected JSON object, got %v", tok)
	}

	var extBuf bytes.Buffer
	extBuf.WriteByte('{')

	for dec.More() {
		keyTok, err := dec.Token()
		if err != nil {
			return err
		}
		key, ok := keyTok.(string)
		if !ok {
			return fmt.Errorf("ssf: ProblemDetails: non-string key %v", keyTok)
		}

		var raw json.RawMessage
		if err := dec.Decode(&raw); err != nil {
			return err
		}

		if _, isRegistered := problemDetailsRegistered[key]; isRegistered {
			if err := assignRegisteredProblemMember(p, key, raw); err != nil {
				return err
			}
			continue
		}

		// Extension member — append to the buffered Extensions
		// object in original order.
		if extBuf.Len() > 1 {
			extBuf.WriteByte(',')
		}
		extBuf.WriteByte('"')
		extBuf.WriteString(key)
		extBuf.WriteString(`":`)
		extBuf.Write(raw)
	}

	// Consume the closing '}'.
	if _, err := dec.Token(); err != nil {
		return err
	}

	if extBuf.Len() > 1 {
		extBuf.WriteByte('}')
		p.Extensions = json.RawMessage(extBuf.Bytes())
	}
	return nil
}

// assignRegisteredProblemMember decodes one of the five RFC 7807
// registered members into the matching struct field. Splitting this
// out keeps the UnmarshalJSON loop body small.
func assignRegisteredProblemMember(p *ProblemDetails, key string, raw json.RawMessage) error {
	switch key {
	case "type":
		return json.Unmarshal(raw, &p.Type)
	case "title":
		return json.Unmarshal(raw, &p.Title)
	case "status":
		return json.Unmarshal(raw, &p.Status)
	case "detail":
		return json.Unmarshal(raw, &p.Detail)
	case "instance":
		return json.Unmarshal(raw, &p.Instance)
	default:
		// Unreachable: callers pre-filter on problemDetailsRegistered.
		return fmt.Errorf("ssf: ProblemDetails: unrecognized registered member %q", key)
	}
}

// extensionMember holds one key/value pair pulled out of a captured
// Extensions object during MarshalJSON. Order matters here — the
// slice preserves the wire order of the original input.
type extensionMember struct {
	key   string
	value json.RawMessage
}

// extensionMembers parses a captured Extensions object into its
// ordered list of key/value pairs. Returns an error if the captured
// bytes are not a JSON object — that condition indicates a caller
// hand-populated Extensions with malformed input rather than a value
// produced by [ProblemDetails.UnmarshalJSON].
func extensionMembers(raw json.RawMessage) ([]extensionMember, error) {
	dec := json.NewDecoder(bytes.NewReader(raw))

	tok, err := dec.Token()
	if err != nil {
		return nil, fmt.Errorf("ssf: ProblemDetails: parse Extensions: %w", err)
	}
	if delim, ok := tok.(json.Delim); !ok || delim != '{' {
		return nil, fmt.Errorf("ssf: ProblemDetails: Extensions must be a JSON object, got %v", tok)
	}

	var out []extensionMember
	for dec.More() {
		keyTok, err := dec.Token()
		if err != nil {
			return nil, err
		}
		key, ok := keyTok.(string)
		if !ok {
			return nil, fmt.Errorf("ssf: ProblemDetails: Extensions: non-string key %v", keyTok)
		}
		var value json.RawMessage
		if err := dec.Decode(&value); err != nil {
			return nil, err
		}
		out = append(out, extensionMember{key: key, value: value})
	}
	return out, nil
}
