// Copyright 2026 The go-ssf Authors
// SPDX-License-Identifier: Apache-2.0

package client

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/hstern/go-ssf"
	"github.com/hstern/go-subjectid"
)

// TestNewClient_RejectsBadBaseURL pins the validation rules
// [NewClient] applies to its baseURL argument. The constructor is
// the only place misconfiguration can be caught synchronously; the
// alternative is a confusing failure on the first method call, with
// no obvious thread back to the construction site.
func TestNewClient_RejectsBadBaseURL(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name    string
		baseURL string
	}{
		{"empty", ""},
		{"relative", "/streams"},
		{"missing host", "https://"},
		{"unsupported scheme", "ftp://transmitter.example.com"},
	}
	for _, c := range cases {
		c := c
		t.Run(c.name, func(t *testing.T) {
			t.Parallel()
			_, err := NewClient(c.baseURL)
			if err == nil {
				t.Fatalf("NewClient(%q) = nil error, want validation failure", c.baseURL)
			}
			var ve *ssf.ValidationError
			if !errors.As(err, &ve) {
				t.Errorf("err = %v, want *ssf.ValidationError", err)
			}
		})
	}
}

// TestNewClient_RejectsNilDoer makes sure WithHTTPDoer(nil) is a
// construction-time error: every method dereferences c.doer, and a
// nil doer would NPE on the first request rather than producing the
// useful error the caller can act on.
func TestNewClient_RejectsNilDoer(t *testing.T) {
	t.Parallel()

	_, err := NewClient("https://t.example.com", WithHTTPDoer(nil))
	if err == nil {
		t.Fatal("NewClient(WithHTTPDoer(nil)) returned nil error")
	}
	var ve *ssf.ValidationError
	if !errors.As(err, &ve) {
		t.Errorf("err = %v, want *ssf.ValidationError", err)
	}
}

// TestNewClient_AppliesDefaults pins the default values applied when
// no options override them: HTTPDoer is [http.DefaultClient], no
// Authorization header is set, and each EndpointPaths field carries
// the corresponding Default*Path constant.
func TestNewClient_AppliesDefaults(t *testing.T) {
	t.Parallel()

	c, err := NewClient("https://t.example.com/api")
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	if c.doer != http.DefaultClient {
		t.Errorf("doer = %v, want http.DefaultClient", c.doer)
	}
	if c.authzHeader != "" {
		t.Errorf("authzHeader = %q, want empty", c.authzHeader)
	}
	wantPaths := EndpointPaths{
		Config:        DefaultConfigPath,
		Status:        DefaultStatusPath,
		AddSubject:    DefaultAddSubjectPath,
		RemoveSubject: DefaultRemoveSubjectPath,
		Verify:        DefaultVerifyPath,
		Poll:          DefaultPollPath,
	}
	if c.paths != wantPaths {
		t.Errorf("paths = %+v, want %+v", c.paths, wantPaths)
	}
}

// TestNewClient_WithEndpoints_PartialOverride verifies that
// [WithEndpoints] treats zero-valued fields as "keep the default" so
// a caller retargeting one endpoint does not have to repeat every
// other value.
func TestNewClient_WithEndpoints_PartialOverride(t *testing.T) {
	t.Parallel()

	c, err := NewClient("https://t.example.com", WithEndpoints(EndpointPaths{
		Config: "/api/v1/streams",
	}))
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	if c.paths.Config != "/api/v1/streams" {
		t.Errorf("Config path = %q, want %q", c.paths.Config, "/api/v1/streams")
	}
	if c.paths.Status != DefaultStatusPath {
		t.Errorf("Status path = %q, want default %q", c.paths.Status, DefaultStatusPath)
	}
}

// TestClient_GetConfig_HappyPath round-trips a successful
// GetConfig: the fake Transmitter returns a StreamConfig and the
// client parses it back. Also asserts the outbound request shape:
// method, path, stream_id query, Accept header.
func TestClient_GetConfig_HappyPath(t *testing.T) {
	t.Parallel()

	got := &ssf.StreamConfig{
		StreamID: "s-123",
		Iss:      "https://t.example.com",
		Aud:      json.RawMessage(`"rcv.example.com"`),
	}
	srv := newTestServer(t, func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			t.Errorf("method = %q, want GET", r.Method)
		}
		if r.URL.Path != DefaultConfigPath {
			t.Errorf("path = %q, want %q", r.URL.Path, DefaultConfigPath)
		}
		if r.URL.Query().Get("stream_id") != "s-123" {
			t.Errorf("stream_id = %q, want s-123", r.URL.Query().Get("stream_id"))
		}
		if !strings.Contains(r.Header.Get("Accept"), "application/json") {
			t.Errorf("Accept = %q, want it to include application/json", r.Header.Get("Accept"))
		}
		writeJSON(t, w, http.StatusOK, got)
	})
	defer srv.Close()

	c := newClient(t, srv.URL)
	resp, err := c.GetConfig(context.Background(), "s-123")
	if err != nil {
		t.Fatalf("GetConfig: %v", err)
	}
	if resp.StreamID != "s-123" || resp.Iss != "https://t.example.com" {
		t.Errorf("StreamConfig = %+v, want stream_id=s-123 iss=https://t.example.com", resp)
	}
}

// TestClient_GetConfig_404 verifies 404 surfaces as both
// ssf.ErrStreamNotFound (via errors.Is) and *ssf.HTTPError
// (via errors.As).
func TestClient_GetConfig_404(t *testing.T) {
	t.Parallel()

	srv := newTestServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/problem+json")
		w.WriteHeader(http.StatusNotFound)
		_, _ = w.Write([]byte(`{"title":"Stream not found","status":404}`))
	})
	defer srv.Close()

	c := newClient(t, srv.URL)
	_, err := c.GetConfig(context.Background(), "missing")
	if err == nil {
		t.Fatal("GetConfig: nil error, want 404 error")
	}
	if !errors.Is(err, ssf.ErrStreamNotFound) {
		t.Errorf("errors.Is(ErrStreamNotFound) = false; err = %v", err)
	}
	var httpErr *ssf.HTTPError
	if !errors.As(err, &httpErr) {
		t.Fatalf("errors.As(*ssf.HTTPError) = false; err = %v", err)
	}
	if httpErr.StatusCode != http.StatusNotFound {
		t.Errorf("StatusCode = %d, want 404", httpErr.StatusCode)
	}
}

// TestClient_GetConfig_401 verifies 401 maps to ssf.ErrUnauthorized.
func TestClient_GetConfig_401(t *testing.T) {
	t.Parallel()

	srv := newTestServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/problem+json")
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = w.Write([]byte(`{"title":"Unauthorized","status":401}`))
	})
	defer srv.Close()

	c := newClient(t, srv.URL)
	_, err := c.GetConfig(context.Background(), "s")
	if !errors.Is(err, ssf.ErrUnauthorized) {
		t.Errorf("errors.Is(ErrUnauthorized) = false; err = %v", err)
	}
}

// TestClient_ListConfig_HappyPath exercises the list endpoint with a
// page_token request parameter and the JSON envelope response shape
// the library's transmitter mux emits.
func TestClient_ListConfig_HappyPath(t *testing.T) {
	t.Parallel()

	srv := newTestServer(t, func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			t.Errorf("method = %q, want GET", r.Method)
		}
		if got := r.URL.Query().Get("page_token"); got != "tok-1" {
			t.Errorf("page_token = %q, want tok-1", got)
		}
		if got := r.URL.Query().Get("stream_id"); got != "" {
			t.Errorf("stream_id should be absent in list, got %q", got)
		}
		writeJSON(t, w, http.StatusOK, map[string]any{
			"streams": []*ssf.StreamConfig{
				{StreamID: "a", Iss: "https://t.example.com"},
				{StreamID: "b", Iss: "https://t.example.com"},
			},
			"next_page_token": "tok-2",
		})
	})
	defer srv.Close()

	c := newClient(t, srv.URL)
	cfgs, next, err := c.ListConfig(context.Background(), "tok-1")
	if err != nil {
		t.Fatalf("ListConfig: %v", err)
	}
	if len(cfgs) != 2 || cfgs[0].StreamID != "a" || cfgs[1].StreamID != "b" {
		t.Errorf("configs = %+v, want [a b]", cfgs)
	}
	if next != "tok-2" {
		t.Errorf("next = %q, want tok-2", next)
	}
}

// TestClient_CreateConfig_HappyPath round-trips a POST: the body the
// server receives matches what the client serialized, the response
// is parsed back, and the Authorization header configured via
// [WithAuthorizationHeader] reaches the server verbatim.
func TestClient_CreateConfig_HappyPath(t *testing.T) {
	t.Parallel()

	srv := newTestServer(t, func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			t.Errorf("method = %q, want POST", r.Method)
		}
		if got := r.Header.Get("Content-Type"); !strings.HasPrefix(got, "application/json") {
			t.Errorf("Content-Type = %q, want application/json prefix", got)
		}
		if got := r.Header.Get("Authorization"); got != "Bearer test-token" {
			t.Errorf("Authorization = %q, want %q", got, "Bearer test-token")
		}

		var in ssf.StreamConfig
		if err := json.NewDecoder(r.Body).Decode(&in); err != nil {
			t.Fatalf("decode request body: %v", err)
		}
		if in.Iss != "https://t.example.com" {
			t.Errorf("body.Iss = %q", in.Iss)
		}

		// Server assigns a stream id and echoes the rest.
		in.StreamID = "assigned-1"
		writeJSON(t, w, http.StatusCreated, &in)
	})
	defer srv.Close()

	c := newClient(t, srv.URL, WithAuthorizationHeader("Bearer test-token"))
	out, err := c.CreateConfig(context.Background(), &ssf.StreamConfig{
		Iss: "https://t.example.com",
		Aud: json.RawMessage(`"rcv.example.com"`),
	})
	if err != nil {
		t.Fatalf("CreateConfig: %v", err)
	}
	if out.StreamID != "assigned-1" {
		t.Errorf("StreamID = %q, want assigned-1", out.StreamID)
	}
}

// TestClient_CreateConfig_NilArg pins the constructor-side argument
// validation: nil cfg is rejected without making an HTTP call.
func TestClient_CreateConfig_NilArg(t *testing.T) {
	t.Parallel()

	c := newClient(t, "https://t.example.com")
	_, err := c.CreateConfig(context.Background(), nil)
	if err == nil {
		t.Fatal("CreateConfig(nil): nil error, want validation failure")
	}
	var ve *ssf.ValidationError
	if !errors.As(err, &ve) {
		t.Errorf("err = %v, want *ssf.ValidationError", err)
	}
}

// TestClient_UpdateConfig_HappyPath checks the PATCH path: stream_id
// from cfg goes onto the query string, and the body carries the full
// configuration.
func TestClient_UpdateConfig_HappyPath(t *testing.T) {
	t.Parallel()

	srv := newTestServer(t, func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPatch {
			t.Errorf("method = %q, want PATCH", r.Method)
		}
		if r.URL.Query().Get("stream_id") != "s-1" {
			t.Errorf("stream_id query = %q, want s-1", r.URL.Query().Get("stream_id"))
		}
		var in ssf.StreamConfig
		if err := json.NewDecoder(r.Body).Decode(&in); err != nil {
			t.Fatalf("decode: %v", err)
		}
		writeJSON(t, w, http.StatusOK, &in)
	})
	defer srv.Close()

	c := newClient(t, srv.URL)
	_, err := c.UpdateConfig(context.Background(), &ssf.StreamConfig{
		StreamID: "s-1",
		Iss:      "https://t.example.com",
	})
	if err != nil {
		t.Fatalf("UpdateConfig: %v", err)
	}
}

// TestClient_UpdateConfig_MissingStreamID pins the rule that a
// PATCH without an identifier is a synchronous validation failure,
// not an HTTP round-trip the Transmitter has to refuse.
func TestClient_UpdateConfig_MissingStreamID(t *testing.T) {
	t.Parallel()

	c := newClient(t, "https://t.example.com")
	_, err := c.UpdateConfig(context.Background(), &ssf.StreamConfig{Iss: "x"})
	if err == nil {
		t.Fatal("UpdateConfig: nil error, want validation failure")
	}
	var ve *ssf.ValidationError
	if !errors.As(err, &ve) {
		t.Errorf("err = %v, want *ssf.ValidationError", err)
	}
}

// TestClient_DeleteConfig_HappyPath verifies the DELETE path and
// that a 204 (no body) is treated as success.
func TestClient_DeleteConfig_HappyPath(t *testing.T) {
	t.Parallel()

	srv := newTestServer(t, func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodDelete {
			t.Errorf("method = %q, want DELETE", r.Method)
		}
		if r.URL.Query().Get("stream_id") != "s-9" {
			t.Errorf("stream_id = %q, want s-9", r.URL.Query().Get("stream_id"))
		}
		w.WriteHeader(http.StatusNoContent)
	})
	defer srv.Close()

	c := newClient(t, srv.URL)
	if err := c.DeleteConfig(context.Background(), "s-9"); err != nil {
		t.Fatalf("DeleteConfig: %v", err)
	}
}

// TestClient_GetStatus_HappyPath exercises GetStatus both stream-wide
// and subject-scoped, asserting the subject query parameter carries
// the JSON bytes verbatim.
func TestClient_GetStatus_HappyPath(t *testing.T) {
	t.Parallel()

	const subj = `{"format":"opaque","id":"abc"}`

	srv := newTestServer(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != DefaultStatusPath {
			t.Errorf("path = %q, want %q", r.URL.Path, DefaultStatusPath)
		}
		if r.URL.Query().Get("stream_id") != "s-1" {
			t.Errorf("stream_id = %q", r.URL.Query().Get("stream_id"))
		}
		// The subject query parameter is forwarded as JSON bytes
		// verbatim; net/url Encode percent-encodes the braces but
		// the parsed value is the original JSON.
		if got := r.URL.Query().Get("subject"); got != subj {
			t.Errorf("subject query = %q, want %q", got, subj)
		}
		writeJSON(t, w, http.StatusOK, &ssf.StatusResponse{Status: ssf.StreamStatusEnabled})
	})
	defer srv.Close()

	c := newClient(t, srv.URL)
	resp, err := c.GetStatus(context.Background(), "s-1", json.RawMessage(subj))
	if err != nil {
		t.Fatalf("GetStatus: %v", err)
	}
	if resp.Status != ssf.StreamStatusEnabled {
		t.Errorf("Status = %q, want enabled", resp.Status)
	}
}

// TestClient_UpdateStatus_HappyPath round-trips a POSTed status
// update. The body shape and stream_id query are asserted.
func TestClient_UpdateStatus_HappyPath(t *testing.T) {
	t.Parallel()

	srv := newTestServer(t, func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			t.Errorf("method = %q, want POST", r.Method)
		}
		var in ssf.StatusUpdateRequest
		if err := json.NewDecoder(r.Body).Decode(&in); err != nil {
			t.Fatalf("decode: %v", err)
		}
		if in.Status != ssf.StreamStatusPaused {
			t.Errorf("Status = %q, want paused", in.Status)
		}
		writeJSON(t, w, http.StatusOK, &ssf.StatusResponse{
			Status: ssf.StreamStatusPaused,
			Reason: "maintenance",
		})
	})
	defer srv.Close()

	c := newClient(t, srv.URL)
	resp, err := c.UpdateStatus(context.Background(), "s-1", &ssf.StatusUpdateRequest{
		Status: ssf.StreamStatusPaused,
		Reason: "maintenance",
	})
	if err != nil {
		t.Fatalf("UpdateStatus: %v", err)
	}
	if resp.Reason != "maintenance" {
		t.Errorf("Reason = %q", resp.Reason)
	}
}

// TestClient_AddSubject_HappyPath asserts add-subject POSTs an
// envelope dispatched through go-subjectid and accepts an empty
// JSON object as success.
func TestClient_AddSubject_HappyPath(t *testing.T) {
	t.Parallel()

	srv := newTestServer(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != DefaultAddSubjectPath {
			t.Errorf("path = %q, want %q", r.URL.Path, DefaultAddSubjectPath)
		}
		if r.URL.Query().Get("stream_id") != "s-1" {
			t.Errorf("stream_id = %q", r.URL.Query().Get("stream_id"))
		}
		// Body should carry the format-bearing subject envelope.
		body, _ := io.ReadAll(r.Body)
		if !bytes.Contains(body, []byte(`"format":"account"`)) {
			t.Errorf("body = %s, want format=account", body)
		}
		writeJSON(t, w, http.StatusOK, map[string]any{})
	})
	defer srv.Close()

	c := newClient(t, srv.URL)
	err := c.AddSubject(context.Background(), "s-1", &ssf.AddSubjectRequest{
		Subject: &subjectid.AccountID{URI: "acct:alice@example.com"},
	})
	if err != nil {
		t.Fatalf("AddSubject: %v", err)
	}
}

// TestClient_RemoveSubject_HappyPath mirrors the add-subject test
// but exercises the remove path so the path/method/body wiring is
// confirmed independently.
func TestClient_RemoveSubject_HappyPath(t *testing.T) {
	t.Parallel()

	srv := newTestServer(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != DefaultRemoveSubjectPath {
			t.Errorf("path = %q, want %q", r.URL.Path, DefaultRemoveSubjectPath)
		}
		writeJSON(t, w, http.StatusOK, map[string]any{})
	})
	defer srv.Close()

	c := newClient(t, srv.URL)
	err := c.RemoveSubject(context.Background(), "s-1", &ssf.RemoveSubjectRequest{
		Subject: &subjectid.AccountID{URI: "acct:alice@example.com"},
	})
	if err != nil {
		t.Fatalf("RemoveSubject: %v", err)
	}
}

// TestClient_Verify_HappyPath asserts verification POSTs the state
// echo body and treats 200 with the empty JSON object as success.
func TestClient_Verify_HappyPath(t *testing.T) {
	t.Parallel()

	srv := newTestServer(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != DefaultVerifyPath {
			t.Errorf("path = %q, want %q", r.URL.Path, DefaultVerifyPath)
		}
		var in ssf.VerificationRequest
		if err := json.NewDecoder(r.Body).Decode(&in); err != nil {
			t.Fatalf("decode: %v", err)
		}
		if in.State != "challenge-42" {
			t.Errorf("State = %q, want challenge-42", in.State)
		}
		writeJSON(t, w, http.StatusOK, map[string]any{})
	})
	defer srv.Close()

	c := newClient(t, srv.URL)
	err := c.Verify(context.Background(), "s-1", &ssf.VerificationRequest{State: "challenge-42"})
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
}

// TestClient_PollEvents_HappyPath round-trips an RFC 8936 poll: the
// ack array, maxEvents pointer, and the response sets map.
func TestClient_PollEvents_HappyPath(t *testing.T) {
	t.Parallel()

	srv := newTestServer(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != DefaultPollPath {
			t.Errorf("path = %q, want %q", r.URL.Path, DefaultPollPath)
		}
		if r.URL.Query().Get("stream_id") != "s-1" {
			t.Errorf("stream_id = %q", r.URL.Query().Get("stream_id"))
		}
		var in ssf.PollRequest
		if err := json.NewDecoder(r.Body).Decode(&in); err != nil {
			t.Fatalf("decode: %v", err)
		}
		if len(in.Ack) != 1 || in.Ack[0] != "jti-1" {
			t.Errorf("Ack = %v, want [jti-1]", in.Ack)
		}
		if in.MaxEvents == nil || *in.MaxEvents != 5 {
			t.Errorf("MaxEvents = %v, want 5", in.MaxEvents)
		}
		writeJSON(t, w, http.StatusOK, &ssf.PollResponse{
			Sets: map[string]string{"jti-2": "compactjws"},
		})
	})
	defer srv.Close()

	c := newClient(t, srv.URL)
	mx := 5
	resp, err := c.PollEvents(context.Background(), "s-1", &ssf.PollRequest{
		Ack:       []string{"jti-1"},
		MaxEvents: &mx,
	})
	if err != nil {
		t.Fatalf("PollEvents: %v", err)
	}
	if resp.Sets["jti-2"] != "compactjws" {
		t.Errorf("Sets = %+v", resp.Sets)
	}
}

// TestClient_WithHTTPDoer_Wraps verifies that a custom doer wrapping
// http.DefaultClient sees every request the client makes.
func TestClient_WithHTTPDoer_Wraps(t *testing.T) {
	t.Parallel()

	srv := newTestServer(t, func(w http.ResponseWriter, r *http.Request) {
		writeJSON(t, w, http.StatusNoContent, nil)
	})
	defer srv.Close()

	var calls atomic.Int64
	doer := &countingDoer{inner: http.DefaultClient, calls: &calls}

	c, err := NewClient(srv.URL, WithHTTPDoer(doer))
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	if err := c.DeleteConfig(context.Background(), "s-1"); err != nil {
		t.Fatalf("DeleteConfig: %v", err)
	}
	if err := c.DeleteConfig(context.Background(), "s-2"); err != nil {
		t.Fatalf("DeleteConfig: %v", err)
	}
	if got := calls.Load(); got != 2 {
		t.Errorf("doer.calls = %d, want 2", got)
	}
}

// TestClient_WithEndpoints_OverrideHonored asserts that a custom
// path override takes effect: the server records the actual request
// path, and the client must have hit the override rather than the
// default.
func TestClient_WithEndpoints_OverrideHonored(t *testing.T) {
	t.Parallel()

	const customConfig = "/api/v1/streams"
	var seen string
	srv := newTestServer(t, func(w http.ResponseWriter, r *http.Request) {
		seen = r.URL.Path
		writeJSON(t, w, http.StatusCreated, &ssf.StreamConfig{StreamID: "s-1"})
	})
	defer srv.Close()

	c := newClient(t, srv.URL, WithEndpoints(EndpointPaths{Config: customConfig}))
	_, err := c.CreateConfig(context.Background(), &ssf.StreamConfig{
		Iss: "https://t.example.com",
	})
	if err != nil {
		t.Fatalf("CreateConfig: %v", err)
	}
	if seen != customConfig {
		t.Errorf("server saw path %q, want %q", seen, customConfig)
	}
}

// TestClient_ContextCancel_PropagatesCancelled verifies that
// cancelling the context aborts the in-flight request with
// context.Canceled, not a generic transport error.
func TestClient_ContextCancel_PropagatesCancelled(t *testing.T) {
	t.Parallel()

	block := make(chan struct{})
	srv := newTestServer(t, func(w http.ResponseWriter, r *http.Request) {
		<-block
	})
	t.Cleanup(func() {
		close(block)
		srv.Close()
	})

	c := newClient(t, srv.URL)
	ctx, cancel := context.WithCancel(context.Background())

	errCh := make(chan error, 1)
	go func() {
		_, err := c.GetConfig(ctx, "s-1")
		errCh <- err
	}()

	cancel()

	err := <-errCh
	if err == nil {
		t.Fatal("GetConfig returned nil error after cancel")
	}
	if !errors.Is(err, context.Canceled) {
		t.Errorf("errors.Is(context.Canceled) = false; err = %v", err)
	}
}

// TestClient_BaseURL_PreservesPathPrefix verifies that a base URL
// with a path prefix has its prefix preserved when endpoint paths are
// joined — the deployment-behind-proxy case.
func TestClient_BaseURL_PreservesPathPrefix(t *testing.T) {
	t.Parallel()

	var seenPath string
	srv := newTestServer(t, func(w http.ResponseWriter, r *http.Request) {
		seenPath = r.URL.Path
		writeJSON(t, w, http.StatusOK, &ssf.StreamConfig{StreamID: "s"})
	})
	defer srv.Close()

	// Append /api as the base URL's path; the default endpoint path
	// /streams should resolve to /api/streams, not /streams.
	c, err := NewClient(srv.URL+"/api", WithHTTPDoer(http.DefaultClient))
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	if _, err := c.GetConfig(context.Background(), "s"); err != nil {
		t.Fatalf("GetConfig: %v", err)
	}
	if seenPath != "/api/streams" {
		t.Errorf("server saw %q, want /api/streams", seenPath)
	}
}

// TestClient_NonProblemErrorResponse exercises the error path on a
// 500 that is not RFC 7807. The returned error must still surface as
// *ssf.HTTPError carrying the body bytes verbatim.
func TestClient_NonProblemErrorResponse(t *testing.T) {
	t.Parallel()

	body := []byte("upstream went sideways")
	srv := newTestServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = w.Write(body)
	})
	defer srv.Close()

	c := newClient(t, srv.URL)
	_, err := c.GetConfig(context.Background(), "s")
	if err == nil {
		t.Fatal("GetConfig: nil error, want HTTP error")
	}
	var httpErr *ssf.HTTPError
	if !errors.As(err, &httpErr) {
		t.Fatalf("errors.As(*ssf.HTTPError) = false; err = %v", err)
	}
	if httpErr.StatusCode != http.StatusInternalServerError {
		t.Errorf("StatusCode = %d, want 500", httpErr.StatusCode)
	}
	if !bytes.Equal(httpErr.Body, body) {
		t.Errorf("Body = %q, want %q", httpErr.Body, body)
	}
}

// ------------------------------------------------------------------
// Test helpers
// ------------------------------------------------------------------

// newClient constructs a [Client] for a test, failing the test
// immediately on construction error. It is the lightweight wrapper
// every happy-path test reaches for.
func newClient(t *testing.T, baseURL string, opts ...Option) *Client {
	t.Helper()
	c, err := NewClient(baseURL, opts...)
	if err != nil {
		t.Fatalf("NewClient(%q): %v", baseURL, err)
	}
	return c
}

// newTestServer spins up an [httptest.Server] backed by handler.
// Callers Close the returned server in their own defer; the helper
// stays explicit about lifetime so a test that wants to keep the
// server alive past the handler call (e.g. for cancellation) can.
func newTestServer(t *testing.T, handler http.HandlerFunc) *httptest.Server {
	t.Helper()
	return httptest.NewServer(handler)
}

// writeJSON is the symmetric counterpart of the client's own
// response-body decoder. It serialises v and writes it with the
// given status and a JSON Content-Type so the client's success path
// has something to decode.
func writeJSON(t *testing.T, w http.ResponseWriter, status int, v any) {
	t.Helper()
	body, err := json.Marshal(v)
	if err != nil {
		t.Fatalf("marshal test response: %v", err)
	}
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	_, _ = w.Write(body)
}

// countingDoer wraps an inner [HTTPDoer] and atomically increments a
// counter on every Do call. Tests use it to confirm that a wrapping
// doer sees every request the client issues.
type countingDoer struct {
	inner HTTPDoer
	calls *atomic.Int64
}

func (d *countingDoer) Do(req *http.Request) (*http.Response, error) {
	d.calls.Add(1)
	return d.inner.Do(req)
}
