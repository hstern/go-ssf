// Copyright 2026 The go-ssf Authors
// SPDX-License-Identifier: Apache-2.0

package ssf_test

import (
	"bytes"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"strings"
	"testing"

	jose "github.com/go-jose/go-jose/v4"

	"github.com/hstern/go-ssf"
)

// newHS256SignerOrFatal builds a jose.Signer over an HS256 key with
// the SET typ header set. HS256 keeps the test surface small — no
// PEM, no keypair generation — while still exercising every code
// path in the verifier (parse, typ check, signature validation).
func newHS256SignerOrFatal(t *testing.T, key []byte) jose.Signer {
	t.Helper()

	opts := (&jose.SignerOptions{}).WithType(ssf.SETMediaType)
	signer, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.HS256, Key: key}, opts)
	if err != nil {
		t.Fatalf("jose.NewSigner: %v", err)
	}
	return signer
}

// hs256Key returns a 32-byte random HMAC key — the minimum size
// go-jose requires for HS256.
func hs256Key(t *testing.T) []byte {
	t.Helper()

	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		t.Fatalf("rand.Read: %v", err)
	}
	return key
}

// TestJOSESetRoundTrip exercises the happy path: a JOSESetSigner over
// an HS256 jose.Signer produces a compact JWS that JOSESetVerifier
// accepts and whose payload bytes round-trip verbatim.
func TestJOSESetRoundTrip(t *testing.T) {
	t.Parallel()

	key := hs256Key(t)
	signer, err := ssf.NewJOSESetSigner(newHS256SignerOrFatal(t, key))
	if err != nil {
		t.Fatalf("NewJOSESetSigner: %v", err)
	}

	verifier := ssf.NewJOSESetVerifier(jose.JSONWebKeySet{
		Keys: []jose.JSONWebKey{{Key: key, Algorithm: string(jose.HS256), Use: "sig"}},
	})

	payload := []byte(`{"iss":"https://transmitter.example.com","aud":"receiver.example.com","jti":"abc","iat":1716422400,"events":{}}`)

	jws, err := signer.Sign(payload)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}

	got, err := verifier.Verify(jws)
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}

	if !bytes.Equal(got, payload) {
		t.Errorf("payload mismatch:\n want %s\n  got %s", payload, got)
	}
}

// TestJOSESetRoundTripWithKid pins the realistic deploy path where
// the Transmitter advertises a JWKS, the JWS carries a kid in its
// protected header, and the verifier resolves the signing key by
// matching kid. Two keys are loaded into the JWKS; only the kid in
// the JWS should be tried.
func TestJOSESetRoundTripWithKid(t *testing.T) {
	t.Parallel()

	signingKey := hs256Key(t)
	otherKey := hs256Key(t)
	const kid = "key-2026-05"

	opts := (&jose.SignerOptions{}).
		WithType(ssf.SETMediaType).
		WithHeader(jose.HeaderKey("kid"), kid)
	joseSigner, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.HS256, Key: signingKey}, opts)
	if err != nil {
		t.Fatalf("jose.NewSigner: %v", err)
	}

	signer, err := ssf.NewJOSESetSigner(joseSigner)
	if err != nil {
		t.Fatalf("NewJOSESetSigner: %v", err)
	}

	verifier := ssf.NewJOSESetVerifier(jose.JSONWebKeySet{
		Keys: []jose.JSONWebKey{
			{Key: otherKey, KeyID: "key-2025-12", Algorithm: string(jose.HS256), Use: "sig"},
			{Key: signingKey, KeyID: kid, Algorithm: string(jose.HS256), Use: "sig"},
		},
	})

	payload := []byte(`{"jti":"kid-roundtrip","iat":1716422400,"events":{}}`)

	jws, err := signer.Sign(payload)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}

	got, err := verifier.Verify(jws)
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if !bytes.Equal(got, payload) {
		t.Errorf("payload mismatch:\n want %s\n  got %s", payload, got)
	}
}

// algNoneOpaqueSigner is a jose.OpaqueSigner that advertises the
// "none" algorithm so we can exercise the constructor's rejection
// path. go-jose's regular NewSigner refuses unknown SignatureAlgorithms,
// so OpaqueSigner is the only way to produce an alg="none" signer.
type algNoneOpaqueSigner struct{}

func (algNoneOpaqueSigner) Public() *jose.JSONWebKey {
	return &jose.JSONWebKey{}
}

func (algNoneOpaqueSigner) Algs() []jose.SignatureAlgorithm {
	return []jose.SignatureAlgorithm{"none"}
}

func (algNoneOpaqueSigner) SignPayload(_ []byte, _ jose.SignatureAlgorithm) ([]byte, error) {
	// Unsecured JWS: the spec defines the signature octet string as
	// empty for alg="none" (RFC 7515 Appendix A.5).
	return []byte{}, nil
}

// TestNewJOSESetSignerRejectsAlgNone asserts the constructor refuses
// a jose.Signer configured with alg="none". RFC 8417 §2.2 forbids
// unsecured Security Event Tokens; rejecting at wiring time prevents
// a misconfigured Transmitter from ever emitting one.
func TestNewJOSESetSignerRejectsAlgNone(t *testing.T) {
	t.Parallel()

	opts := (&jose.SignerOptions{}).WithType(ssf.SETMediaType)
	joseSigner, err := jose.NewSigner(
		jose.SigningKey{Algorithm: "none", Key: algNoneOpaqueSigner{}},
		opts,
	)
	if err != nil {
		t.Fatalf("jose.NewSigner with alg=none: %v", err)
	}

	_, err = ssf.NewJOSESetSigner(joseSigner)
	if err == nil {
		t.Fatal("NewJOSESetSigner accepted alg=none signer; want error")
	}
	if !strings.Contains(err.Error(), `"none"`) {
		t.Errorf("error does not name the forbidden algorithm: %v", err)
	}
}

// TestNewJOSESetSignerRejectsMissingTyp asserts the constructor
// refuses a signer that was never configured with the SET typ
// header. A SET without typ violates RFC 8417 §2.2, so the constructor
// fails fast rather than silently produce a non-conformant token.
func TestNewJOSESetSignerRejectsMissingTyp(t *testing.T) {
	t.Parallel()

	key := hs256Key(t)
	joseSigner, err := jose.NewSigner(
		jose.SigningKey{Algorithm: jose.HS256, Key: key},
		nil, // no SignerOptions, so no typ header
	)
	if err != nil {
		t.Fatalf("jose.NewSigner: %v", err)
	}

	if _, err := ssf.NewJOSESetSigner(joseSigner); err == nil {
		t.Fatal("NewJOSESetSigner accepted signer without typ; want error")
	}
}

// TestNewJOSESetSignerRejectsWrongTyp asserts the constructor refuses
// a signer whose typ is set to "JWT" rather than "secevent+jwt". A
// strict verifier on the other end will reject the token, so failing
// at wiring time is preferable to discovering the misconfiguration
// in production.
func TestNewJOSESetSignerRejectsWrongTyp(t *testing.T) {
	t.Parallel()

	key := hs256Key(t)
	opts := (&jose.SignerOptions{}).WithType("JWT")
	joseSigner, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.HS256, Key: key}, opts)
	if err != nil {
		t.Fatalf("jose.NewSigner: %v", err)
	}

	if _, err := ssf.NewJOSESetSigner(joseSigner); err == nil {
		t.Fatal(`NewJOSESetSigner accepted signer with typ="JWT"; want error`)
	}
}

// TestNewJOSESetSignerRejectsNilSigner pins the nil-guard so callers
// who forget to construct the underlying jose.Signer see a clear
// error rather than a runtime panic.
func TestNewJOSESetSignerRejectsNilSigner(t *testing.T) {
	t.Parallel()

	if _, err := ssf.NewJOSESetSigner(nil); err == nil {
		t.Fatal("NewJOSESetSigner accepted nil signer; want error")
	}
}

// TestVerifyRejectsAlgNone asserts the verifier refuses a JWS whose
// protected header carries alg="none". The unsecured JWS format from
// RFC 7515 Appendix A.5 has empty signature bytes; this test
// hand-crafts such a JWS to exercise the rejection path.
func TestVerifyRejectsAlgNone(t *testing.T) {
	t.Parallel()

	// {"alg":"none","typ":"secevent+jwt"}
	header := `{"alg":"none","typ":"secevent+jwt"}`
	payload := `{"jti":"x","events":{}}`
	jws := strings.Join([]string{
		base64.RawURLEncoding.EncodeToString([]byte(header)),
		base64.RawURLEncoding.EncodeToString([]byte(payload)),
		"", // empty signature per RFC 7515 Appendix A.5
	}, ".")

	verifier := ssf.NewJOSESetVerifier(jose.JSONWebKeySet{
		Keys: []jose.JSONWebKey{{Key: hs256Key(t), Algorithm: string(jose.HS256), Use: "sig"}},
	})

	if _, err := verifier.Verify(jws); err == nil {
		t.Fatal(`Verify accepted alg="none" JWS; want error`)
	}
}

// TestVerifyRejectsWrongTyp asserts the verifier refuses a JWS whose
// typ header is set to "JWT" rather than "secevent+jwt". This is the
// distinguishing rule from RFC 8417 §2.2 — a SET is a JWT plus the
// secevent+jwt typ, and the verifier MUST NOT accept a generic JWT.
func TestVerifyRejectsWrongTyp(t *testing.T) {
	t.Parallel()

	key := hs256Key(t)

	// Build a valid JWS with typ="JWT" instead of "secevent+jwt".
	opts := (&jose.SignerOptions{}).WithType("JWT")
	joseSigner, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.HS256, Key: key}, opts)
	if err != nil {
		t.Fatalf("jose.NewSigner: %v", err)
	}
	sig, err := joseSigner.Sign([]byte(`{"jti":"y","events":{}}`))
	if err != nil {
		t.Fatalf("jose Sign: %v", err)
	}
	compact, err := sig.CompactSerialize()
	if err != nil {
		t.Fatalf("CompactSerialize: %v", err)
	}

	verifier := ssf.NewJOSESetVerifier(jose.JSONWebKeySet{
		Keys: []jose.JSONWebKey{{Key: key, Algorithm: string(jose.HS256), Use: "sig"}},
	})

	_, err = verifier.Verify(compact)
	if err == nil {
		t.Fatal(`Verify accepted typ="JWT" JWS; want error`)
	}
	if !strings.Contains(err.Error(), "typ") {
		t.Errorf("error does not name the failed check: %v", err)
	}
}

// TestVerifyRejectsMissingTyp asserts the verifier refuses a JWS
// with no typ header at all. A bare JWS missing typ is structurally
// indistinguishable from any other JWT and is not a valid SET.
func TestVerifyRejectsMissingTyp(t *testing.T) {
	t.Parallel()

	key := hs256Key(t)
	joseSigner, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.HS256, Key: key}, nil)
	if err != nil {
		t.Fatalf("jose.NewSigner: %v", err)
	}
	sig, err := joseSigner.Sign([]byte(`{"jti":"z","events":{}}`))
	if err != nil {
		t.Fatalf("jose Sign: %v", err)
	}
	compact, err := sig.CompactSerialize()
	if err != nil {
		t.Fatalf("CompactSerialize: %v", err)
	}

	verifier := ssf.NewJOSESetVerifier(jose.JSONWebKeySet{
		Keys: []jose.JSONWebKey{{Key: key, Algorithm: string(jose.HS256), Use: "sig"}},
	})

	if _, err := verifier.Verify(compact); err == nil {
		t.Fatal("Verify accepted JWS without typ header; want error")
	}
}

// TestVerifyRejectsWrongKey asserts the verifier rejects a JWS signed
// by a key not present in the configured JWKS. This is the
// fundamental security property of the verifier; a regression here
// would be catastrophic.
func TestVerifyRejectsWrongKey(t *testing.T) {
	t.Parallel()

	signingKey := hs256Key(t)
	verifyingKey := hs256Key(t) // different from signingKey

	signer, err := ssf.NewJOSESetSigner(newHS256SignerOrFatal(t, signingKey))
	if err != nil {
		t.Fatalf("NewJOSESetSigner: %v", err)
	}

	verifier := ssf.NewJOSESetVerifier(jose.JSONWebKeySet{
		Keys: []jose.JSONWebKey{{Key: verifyingKey, Algorithm: string(jose.HS256), Use: "sig"}},
	})

	jws, err := signer.Sign([]byte(`{"jti":"q"}`))
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}

	if _, err := verifier.Verify(jws); err == nil {
		t.Fatal("Verify accepted JWS signed by unknown key; want error")
	}
}

// TestVerifyRejectsMalformedJWS asserts the verifier surfaces a
// useful error when the input is not a valid JWS compact
// serialization at all (rather than panicking or returning a payload).
func TestVerifyRejectsMalformedJWS(t *testing.T) {
	t.Parallel()

	verifier := ssf.NewJOSESetVerifier(jose.JSONWebKeySet{
		Keys: []jose.JSONWebKey{{Key: hs256Key(t), Algorithm: string(jose.HS256), Use: "sig"}},
	})

	cases := []string{
		"",
		"not-a-jws",
		"only.two-parts",
		"a.b.c.d.e",
	}

	for _, in := range cases {
		t.Run(in, func(t *testing.T) {
			t.Parallel()
			if _, err := verifier.Verify(in); err == nil {
				t.Fatalf("Verify accepted malformed input %q; want error", in)
			}
		})
	}
}

// TestVerifyRejectsEmptyJWKS asserts the verifier surfaces a clear
// error rather than silently accepting (or panicking on) a JWS when
// the configured key set has no keys.
func TestVerifyRejectsEmptyJWKS(t *testing.T) {
	t.Parallel()

	key := hs256Key(t)
	signer, err := ssf.NewJOSESetSigner(newHS256SignerOrFatal(t, key))
	if err != nil {
		t.Fatalf("NewJOSESetSigner: %v", err)
	}
	jws, err := signer.Sign([]byte(`{"jti":"e"}`))
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}

	verifier := ssf.NewJOSESetVerifier(jose.JSONWebKeySet{})

	_, err = verifier.Verify(jws)
	if err == nil {
		t.Fatal("Verify accepted JWS against empty JWKS; want error")
	}
	if !strings.Contains(err.Error(), "empty") {
		t.Errorf("error does not name the failure mode: %v", err)
	}
}

// TestSETMediaType pins the package-level constant — the spec value
// is load-bearing and a typo here would break interop on day one.
func TestSETMediaType(t *testing.T) {
	t.Parallel()

	if got, want := ssf.SETMediaType, "secevent+jwt"; got != want {
		t.Errorf("SETMediaType = %q, want %q", got, want)
	}
}

// Compile-time check that the package-level types satisfy the
// published interfaces. If this stops compiling, the public API
// surface has drifted.
var (
	_ ssf.SETSigner   = (*ssf.JOSESetSigner)(nil)
	_ ssf.SETVerifier = (*ssf.JOSESetVerifier)(nil)
)

// ExampleNewJOSESetSigner demonstrates the typical wiring: configure
// a jose.Signer with the SET typ header, hand it to NewJOSESetSigner,
// and pair it with a NewJOSESetVerifier over the same key for the
// in-process or test path. Production callers swap the HMAC key for
// an asymmetric private key and publish the public half via the
// Transmitter's jwks_uri.
func ExampleNewJOSESetSigner() {
	key := make([]byte, 32)
	for i := range key {
		key[i] = byte(i)
	}

	opts := (&jose.SignerOptions{}).WithType(ssf.SETMediaType)
	joseSigner, err := jose.NewSigner(
		jose.SigningKey{Algorithm: jose.HS256, Key: key},
		opts,
	)
	if err != nil {
		panic(err)
	}

	signer, err := ssf.NewJOSESetSigner(joseSigner)
	if err != nil {
		panic(err)
	}

	verifier := ssf.NewJOSESetVerifier(jose.JSONWebKeySet{
		Keys: []jose.JSONWebKey{{Key: key, Algorithm: string(jose.HS256), Use: "sig"}},
	})

	jws, err := signer.Sign([]byte(`{"jti":"42","events":{}}`))
	if err != nil {
		panic(err)
	}

	payload, err := verifier.Verify(jws)
	if err != nil {
		panic(err)
	}

	fmt.Println(string(payload))
	// Output: {"jti":"42","events":{}}
}
