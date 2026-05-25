// Copyright 2026 The go-ssf Authors
// SPDX-License-Identifier: Apache-2.0

package ssf

import (
	"errors"
	"fmt"

	jose "github.com/go-jose/go-jose/v4"
)

// SETMediaType is the media type Security Event Tokens MUST carry in
// the JWS "typ" protected header per RFC 8417 §2.2. Strict verifiers
// reject SETs that present "typ": "JWT" or omit the header entirely;
// the library enforces the value on both sign and verify so callers
// don't have to remember it at every site.
const SETMediaType = "secevent+jwt"

// algNone is the JOSE algorithm identifier the library refuses to
// sign or verify. RFC 8417 §2.2 forbids unsecured Security Event
// Tokens, and the library mirrors that rule at both ends.
const algNone = "none"

// errAlgNone is returned by [NewJOSESetSigner] and the verifier when
// a Signer or incoming JWS carries the JOSE "none" algorithm. The
// sentinel lives in this file rather than errors.go because the
// errors.go inventory is owned by the type-surface phase; promotion
// to a package-level exported sentinel (alongside ErrUnsupportedDelivery
// and friends) is a follow-up.
var errAlgNone = errors.New(`alg "none" is forbidden on security event tokens (rfc 8417 §2.2)`)

// errMissingTyp is returned when a signer is configured without a typ
// header, or when an incoming JWS omits typ entirely. RFC 8417 §2.2
// requires the typ header on every SET.
var errMissingTyp = errors.New(`typ header missing; security event tokens must set typ="` + SETMediaType + `" (rfc 8417 §2.2)`)

// allowedSETAlgorithms is the snapshot of signature algorithms the
// verifier accepts when parsing an incoming SET. The list deliberately
// omits "none" — RFC 8417 §2.2 forbids it — at the parse layer so a
// malformed-on-purpose alg="none" JWS never reaches the post-parse
// invariant checks.
//
// The asymmetric algorithms (RS, PS, ES, EdDSA) are the SSF deployment
// shape: the Transmitter publishes its public JWKS, every Receiver
// can verify, and the secret stays on the Transmitter. HMAC (HS256,
// HS384, HS512) is included for the in-process and test path; a
// production Transmitter SHOULD NOT mix HMAC and asymmetric keys in
// the same JWKS — a malformed JWKS that exposes an asymmetric
// public key under "kty": "oct" enables the classic alg-confusion
// attack, where an attacker forges an HS256 SET using the public-key
// bytes as the HMAC secret. The defense is to configure an
// asymmetric-only JWKS in production; go-jose's per-verifier alg
// dispatch (rsa verifier refuses HS algs, hmac verifier refuses RS
// algs) provides the second layer.
var allowedSETAlgorithms = []jose.SignatureAlgorithm{
	jose.EdDSA,
	jose.HS256, jose.HS384, jose.HS512,
	jose.RS256, jose.RS384, jose.RS512,
	jose.ES256, jose.ES384, jose.ES512,
	jose.PS256, jose.PS384, jose.PS512,
}

// SETSigner produces a JWS-compact-serialized Security Event Token
// from a JSON payload. Implementations abstract the key material so
// consumers can plug an in-process key, a KMS, or an HSM behind the
// same shape.
//
// Implementations MUST set the JOSE "typ" protected header to
// [SETMediaType] per RFC 8417 §2.2 and MUST NOT sign with the
// "none" algorithm.
type SETSigner interface {
	// Sign returns the compact JWS serialization of payload, with the
	// Security Event Token "typ" protected header set. The payload is
	// the raw JSON bytes of the SET claims set; the implementation
	// does not parse or rewrite it.
	Sign(payload []byte) (jwsCompact string, err error)
}

// SETVerifier validates a compact-serialized JWS as a Security Event
// Token and returns the raw payload bytes. The caller is responsible
// for decoding the payload as a SET claims set; the verifier only
// enforces the JWS-layer rules from RFC 8417 §2.2 (signature
// validity, "typ" protected header, "alg" not equal to "none").
type SETVerifier interface {
	// Verify validates the compact JWS and returns the original
	// payload bytes. If signature validation, the typ header check,
	// or the alg check fails, Verify returns a non-nil error and an
	// empty payload.
	Verify(jwsCompact string) (payload []byte, err error)
}

// JOSESetSigner implements [SETSigner] over a pre-configured
// [jose.Signer] from github.com/go-jose/go-jose/v4. Consumers control
// the underlying signing key, signature algorithm, and any extra
// protected-header entries (such as "kid") by constructing the
// jose.Signer themselves and handing it to [NewJOSESetSigner]; this
// type only enforces the SET-specific layer (typ and alg rules) on
// top.
type JOSESetSigner struct {
	signer jose.Signer
}

// NewJOSESetSigner wraps signer for Security Event Token production.
// The constructor probes signer once with a one-byte payload to
// inspect the protected header it emits, then verifies two RFC 8417
// §2.2 invariants:
//
//   - The "typ" header equals [SETMediaType]. Callers configure this
//     via jose.SignerOptions.WithType(SETMediaType) before calling
//     jose.NewSigner.
//   - The "alg" header is not "none". Unsecured SETs are explicitly
//     forbidden.
//
// A signer that fails either check is rejected at construction time
// so the error surfaces during wiring rather than on the first SET
// emitted at runtime.
func NewJOSESetSigner(signer jose.Signer) (*JOSESetSigner, error) {
	if signer == nil {
		return nil, errors.New("ssf: jose signer is nil")
	}

	// Probe the configured signer once to recover the protected
	// header it emits. The jose.Signer interface does not expose the
	// recipient algorithm directly, and Signer.Options() only returns
	// the caller-supplied ExtraHeaders; serializing and re-parsing
	// the probe is the only reliable way to read both "alg" and "typ"
	// as the wire will see them.
	probe, err := signer.Sign([]byte{0})
	if err != nil {
		return nil, fmt.Errorf("ssf: jose signer rejected probe payload: %w", err)
	}
	compact, err := probe.CompactSerialize()
	if err != nil {
		return nil, fmt.Errorf("ssf: serialize probe jws: %w", err)
	}
	// Allow every algorithm at parse time — the rejection of "none"
	// is the library's policy, not go-jose's, and limiting the parse
	// set here would mask the real reason for failure on signers
	// configured with an unusual algorithm. The slice is built fresh
	// rather than appended to allowedSETAlgorithms so the latter
	// remains a constant snapshot.
	probeAlgorithms := make([]jose.SignatureAlgorithm, 0, len(allowedSETAlgorithms)+1)
	probeAlgorithms = append(probeAlgorithms, allowedSETAlgorithms...)
	probeAlgorithms = append(probeAlgorithms, jose.SignatureAlgorithm(algNone))

	parsed, err := jose.ParseSigned(compact, probeAlgorithms)
	if err != nil {
		return nil, fmt.Errorf("ssf: parse probe jws: %w", err)
	}
	if len(parsed.Signatures) == 0 {
		return nil, errors.New("ssf: probe jws has no signatures")
	}

	header := parsed.Signatures[0].Protected
	if header.Algorithm == algNone {
		return nil, errAlgNone
	}
	typ, ok := header.ExtraHeaders[jose.HeaderType]
	if !ok {
		return nil, errMissingTyp
	}
	if typ != SETMediaType {
		return nil, fmt.Errorf("ssf: jose signer typ header is %v, want %q: %w",
			typ, SETMediaType, errMissingTyp)
	}

	return &JOSESetSigner{signer: signer}, nil
}

// Sign produces the compact JWS serialization of payload as a
// Security Event Token. The "typ" and "alg" invariants are enforced
// once at construction time; on the hot path this method delegates
// to the wrapped jose.Signer.
func (s *JOSESetSigner) Sign(payload []byte) (string, error) {
	jws, err := s.signer.Sign(payload)
	if err != nil {
		return "", fmt.Errorf("ssf: sign set: %w", err)
	}

	compact, err := jws.CompactSerialize()
	if err != nil {
		return "", fmt.Errorf("ssf: serialize set: %w", err)
	}

	return compact, nil
}

// JOSESetVerifier implements [SETVerifier] against a static
// [jose.JSONWebKeySet]. The key set is the Transmitter's published
// JWKS (spec §3, "jwks_uri"); the verifier resolves the signing key
// by "kid" if the JWS carries one and otherwise tries each key in
// the set until one validates.
//
// JOSESetVerifier is safe for concurrent use once constructed; the
// embedded key set is not mutated.
type JOSESetVerifier struct {
	keys jose.JSONWebKeySet
}

// NewJOSESetVerifier returns a verifier that resolves signing keys
// from keys. The caller is responsible for keeping keys fresh —
// typically by re-fetching the Transmitter's jwks_uri on a cadence
// and constructing a new verifier — since JOSESetVerifier does not
// itself perform network I/O.
func NewJOSESetVerifier(keys jose.JSONWebKeySet) *JOSESetVerifier {
	return &JOSESetVerifier{keys: keys}
}

// Verify validates the compact JWS and returns its payload. The
// method enforces RFC 8417 §2.2 in three places before returning a
// payload:
//
//  1. jose.ParseSigned restricts the accepted algorithms to the
//     SET-appropriate set; "alg": "none" is rejected at parse time.
//  2. The protected "typ" header MUST equal [SETMediaType]; "JWT" or
//     other values are rejected so a generic JWT cannot be mistaken
//     for a SET.
//  3. jose.JSONWebSignature.Verify validates the cryptographic
//     signature against a key resolved from the configured key set.
//
// On any failure Verify returns a nil payload and a wrapped error
// naming the failed check; the original payload bytes are returned
// only on full success.
func (v *JOSESetVerifier) Verify(jwsCompact string) ([]byte, error) {
	jws, err := jose.ParseSigned(jwsCompact, allowedSETAlgorithms)
	if err != nil {
		return nil, fmt.Errorf("ssf: parse set: %w", err)
	}

	if len(jws.Signatures) == 0 {
		return nil, errors.New("ssf: set has no signatures")
	}

	sig := jws.Signatures[0]

	if sig.Protected.Algorithm == algNone {
		return nil, errAlgNone
	}

	typ, ok := sig.Protected.ExtraHeaders[jose.HeaderType]
	if !ok {
		return nil, errMissingTyp
	}
	if typ != SETMediaType {
		return nil, fmt.Errorf("ssf: set typ header is %q, want %q (rfc 8417 §2.2)", typ, SETMediaType)
	}

	payload, err := v.verifyWithKeys(jws, sig)
	if err != nil {
		return nil, fmt.Errorf("ssf: verify set signature: %w", err)
	}

	return payload, nil
}

// verifyWithKeys resolves the verification key from the configured
// JWKS and runs go-jose's signature check. When the JWS carries a
// "kid", the JWKS lookup is delegated to go-jose (which fails fast if
// no matching key is registered). When the JWS omits "kid" — a
// small-deployment shape the spec permits — each key in the set is
// tried in order until one validates, and the verifier reports the
// last error encountered if none does.
func (v *JOSESetVerifier) verifyWithKeys(jws *jose.JSONWebSignature, sig jose.Signature) ([]byte, error) {
	if len(v.keys.Keys) == 0 {
		return nil, errors.New("jwks is empty")
	}

	if sig.Protected.KeyID != "" {
		// go-jose's tryJWKS resolves the key by kid and fails with
		// ErrJWKSKidNotFound when no match exists, which is the
		// behavior we want — silent fallback would mask key-rotation
		// misconfiguration.
		return jws.Verify(&v.keys)
	}

	var lastErr error
	for i := range v.keys.Keys {
		payload, err := jws.Verify(&v.keys.Keys[i])
		if err == nil {
			return payload, nil
		}
		lastErr = err
	}

	return nil, fmt.Errorf("no key in jwks validated the signature: %w", lastErr)
}
