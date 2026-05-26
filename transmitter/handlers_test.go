// Copyright 2026 The go-ssf Authors
// SPDX-License-Identifier: Apache-2.0

package transmitter_test

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/hstern/go-ssf"
	"github.com/hstern/go-ssf/transmitter"
)

// stubTransmitter is a [transmitter.Transmitter] whose methods are
// supplied per-test. Embedding [transmitter.NotImplementedTransmitter]
// makes every unused method return [ssf.ErrNotImplemented] so a test
// that exercises one endpoint does not have to populate the other
// eight.
type stubTransmitter struct {
	transmitter.NotImplementedTransmitter

	getConfig     func(ctx context.Context, id string) (*ssf.StreamConfig, error)
	listConfig    func(ctx context.Context, token string) ([]*ssf.StreamConfig, string, error)
	createConfig  func(ctx context.Context, cfg *ssf.StreamConfig) (*ssf.StreamConfig, error)
	updateConfig  func(ctx context.Context, cfg *ssf.StreamConfig) (*ssf.StreamConfig, error)
	deleteConfig  func(ctx context.Context, id string) error
	getStatus     func(ctx context.Context, id string, subject json.RawMessage) (*ssf.StatusResponse, error)
	updateStatus  func(ctx context.Context, id string, req *ssf.StatusUpdateRequest) (*ssf.StatusResponse, error)
	addSubject    func(ctx context.Context, id string, req *ssf.AddSubjectRequest) error
	removeSubject func(ctx context.Context, id string, req *ssf.RemoveSubjectRequest) error
	verify        func(ctx context.Context, id string, req *ssf.VerificationRequest) error
	pollEvents    func(ctx context.Context, id string, req *ssf.PollRequest) (*ssf.PollResponse, error)
}

func (s *stubTransmitter) GetConfig(ctx context.Context, id string) (*ssf.StreamConfig, error) {
	if s.getConfig != nil {
		return s.getConfig(ctx, id)
	}
	return s.NotImplementedTransmitter.GetConfig(ctx, id)
}

func (s *stubTransmitter) ListConfig(ctx context.Context, token string) ([]*ssf.StreamConfig, string, error) {
	if s.listConfig != nil {
		return s.listConfig(ctx, token)
	}
	return s.NotImplementedTransmitter.ListConfig(ctx, token)
}

func (s *stubTransmitter) CreateConfig(ctx context.Context, cfg *ssf.StreamConfig) (*ssf.StreamConfig, error) {
	if s.createConfig != nil {
		return s.createConfig(ctx, cfg)
	}
	return s.NotImplementedTransmitter.CreateConfig(ctx, cfg)
}

func (s *stubTransmitter) UpdateConfig(ctx context.Context, cfg *ssf.StreamConfig) (*ssf.StreamConfig, error) {
	if s.updateConfig != nil {
		return s.updateConfig(ctx, cfg)
	}
	return s.NotImplementedTransmitter.UpdateConfig(ctx, cfg)
}

func (s *stubTransmitter) DeleteConfig(ctx context.Context, id string) error {
	if s.deleteConfig != nil {
		return s.deleteConfig(ctx, id)
	}
	return s.NotImplementedTransmitter.DeleteConfig(ctx, id)
}

func (s *stubTransmitter) GetStatus(ctx context.Context, id string, subject json.RawMessage) (*ssf.StatusResponse, error) {
	if s.getStatus != nil {
		return s.getStatus(ctx, id, subject)
	}
	return s.NotImplementedTransmitter.GetStatus(ctx, id, subject)
}

func (s *stubTransmitter) UpdateStatus(ctx context.Context, id string, req *ssf.StatusUpdateRequest) (*ssf.StatusResponse, error) {
	if s.updateStatus != nil {
		return s.updateStatus(ctx, id, req)
	}
	return s.NotImplementedTransmitter.UpdateStatus(ctx, id, req)
}

func (s *stubTransmitter) AddSubject(ctx context.Context, id string, req *ssf.AddSubjectRequest) error {
	if s.addSubject != nil {
		return s.addSubject(ctx, id, req)
	}
	return s.NotImplementedTransmitter.AddSubject(ctx, id, req)
}

func (s *stubTransmitter) RemoveSubject(ctx context.Context, id string, req *ssf.RemoveSubjectRequest) error {
	if s.removeSubject != nil {
		return s.removeSubject(ctx, id, req)
	}
	return s.NotImplementedTransmitter.RemoveSubject(ctx, id, req)
}

func (s *stubTransmitter) Verify(ctx context.Context, id string, req *ssf.VerificationRequest) error {
	if s.verify != nil {
		return s.verify(ctx, id, req)
	}
	return s.NotImplementedTransmitter.Verify(ctx, id, req)
}

func (s *stubTransmitter) PollEvents(ctx context.Context, id string, req *ssf.PollRequest) (*ssf.PollResponse, error) {
	if s.pollEvents != nil {
		return s.pollEvents(ctx, id, req)
	}
	return s.NotImplementedTransmitter.PollEvents(ctx, id, req)
}

// readProblem decodes the response body as [ssf.ProblemDetails],
// failing the test on a body that does not parse. The Content-Type
// is checked alongside so a malformed problem-details emitted as
// application/json (rather than the spec-mandated
// application/problem+json) is caught at the test boundary.
func readProblem(t *testing.T, resp *http.Response) ssf.ProblemDetails {
	t.Helper()
	if got := resp.Header.Get("Content-Type"); got != "application/problem+json" {
		t.Errorf("Content-Type: got %q, want application/problem+json", got)
	}
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read body: %v", err)
	}
	var p ssf.ProblemDetails
	if err := json.Unmarshal(body, &p); err != nil {
		t.Fatalf("unmarshal problem-details: %v\nbody: %s", err, body)
	}
	return p
}

// readJSON decodes the response body as JSON into dst, failing the
// test on parse error or missing Content-Type.
func readJSON(t *testing.T, resp *http.Response, dst any) {
	t.Helper()
	if got := resp.Header.Get("Content-Type"); got != "application/json; charset=utf-8" {
		t.Errorf("Content-Type: got %q, want application/json; charset=utf-8", got)
	}
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read body: %v", err)
	}
	if err := json.Unmarshal(body, dst); err != nil {
		t.Fatalf("unmarshal body: %v\nbody: %s", err, body)
	}
}

func serve(t *testing.T, h http.Handler, req *http.Request) *http.Response {
	t.Helper()
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	resp := rec.Result()
	t.Cleanup(func() { _ = resp.Body.Close() })
	return resp
}

// ---- ConfigHandler --------------------------------------------------

func TestConfigHandler_GetOne_Success(t *testing.T) {
	t.Parallel()

	want := &ssf.StreamConfig{StreamID: "abc", Iss: "https://t.example/"}
	stub := &stubTransmitter{
		getConfig: func(_ context.Context, id string) (*ssf.StreamConfig, error) {
			if id != "abc" {
				t.Errorf("streamID: got %q, want %q", id, "abc")
			}
			return want, nil
		},
	}
	h := transmitter.ConfigHandler(stub, transmitter.AlwaysAllow)

	req := httptest.NewRequest(http.MethodGet, "/streams?stream_id=abc", nil)
	resp := serve(t, h, req)

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status: got %d, want %d", resp.StatusCode, http.StatusOK)
	}
	var got ssf.StreamConfig
	readJSON(t, resp, &got)
	if got.StreamID != want.StreamID || got.Iss != want.Iss {
		t.Errorf("body: got %+v, want %+v", got, want)
	}
}

func TestConfigHandler_List_Success(t *testing.T) {
	t.Parallel()

	cfgs := []*ssf.StreamConfig{
		{StreamID: "a"},
		{StreamID: "b"},
	}
	stub := &stubTransmitter{
		listConfig: func(_ context.Context, token string) ([]*ssf.StreamConfig, string, error) {
			if token != "page-2" {
				t.Errorf("pageToken: got %q, want %q", token, "page-2")
			}
			return cfgs, "page-3", nil
		},
	}
	h := transmitter.ConfigHandler(stub, transmitter.AlwaysAllow)

	req := httptest.NewRequest(http.MethodGet, "/streams?page_token=page-2", nil)
	resp := serve(t, h, req)

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status: got %d, want %d", resp.StatusCode, http.StatusOK)
	}
	var envelope struct {
		Streams       []*ssf.StreamConfig `json:"streams"`
		NextPageToken string              `json:"next_page_token"`
	}
	readJSON(t, resp, &envelope)
	if len(envelope.Streams) != 2 || envelope.Streams[0].StreamID != "a" || envelope.Streams[1].StreamID != "b" {
		t.Errorf("Streams: got %+v", envelope.Streams)
	}
	if envelope.NextPageToken != "page-3" {
		t.Errorf("NextPageToken: got %q, want %q", envelope.NextPageToken, "page-3")
	}
}

func TestConfigHandler_Create_Success(t *testing.T) {
	t.Parallel()

	stub := &stubTransmitter{
		createConfig: func(_ context.Context, cfg *ssf.StreamConfig) (*ssf.StreamConfig, error) {
			if cfg.Iss != "https://t.example/" {
				t.Errorf("Issuer: got %q", cfg.Iss)
			}
			cfg.StreamID = "assigned"
			return cfg, nil
		},
	}
	h := transmitter.ConfigHandler(stub, transmitter.AlwaysAllow)

	body := strings.NewReader(`{"iss":"https://t.example/"}`)
	req := httptest.NewRequest(http.MethodPost, "/streams", body)
	resp := serve(t, h, req)

	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("status: got %d, want %d", resp.StatusCode, http.StatusCreated)
	}
	var got ssf.StreamConfig
	readJSON(t, resp, &got)
	if got.StreamID != "assigned" {
		t.Errorf("StreamID: got %q, want %q", got.StreamID, "assigned")
	}
}

func TestConfigHandler_Update_Success(t *testing.T) {
	t.Parallel()

	stub := &stubTransmitter{
		updateConfig: func(_ context.Context, cfg *ssf.StreamConfig) (*ssf.StreamConfig, error) {
			// The query parameter overrides the body's stream_id so
			// a caller cannot retarget the update by smuggling a
			// different ID into the JSON payload.
			if cfg.StreamID != "abc" {
				t.Errorf("StreamID: got %q, want %q (query parameter overrides body)", cfg.StreamID, "abc")
			}
			return cfg, nil
		},
	}
	h := transmitter.ConfigHandler(stub, transmitter.AlwaysAllow)

	body := strings.NewReader(`{"stream_id":"smuggled","iss":"https://t.example/"}`)
	req := httptest.NewRequest(http.MethodPatch, "/streams?stream_id=abc", body)
	resp := serve(t, h, req)

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status: got %d, want %d", resp.StatusCode, http.StatusOK)
	}
}

func TestConfigHandler_Delete_Success(t *testing.T) {
	t.Parallel()

	called := false
	stub := &stubTransmitter{
		deleteConfig: func(_ context.Context, id string) error {
			called = true
			if id != "abc" {
				t.Errorf("streamID: got %q", id)
			}
			return nil
		},
	}
	h := transmitter.ConfigHandler(stub, transmitter.AlwaysAllow)

	req := httptest.NewRequest(http.MethodDelete, "/streams?stream_id=abc", nil)
	resp := serve(t, h, req)

	if resp.StatusCode != http.StatusNoContent {
		t.Fatalf("status: got %d, want %d", resp.StatusCode, http.StatusNoContent)
	}
	if !called {
		t.Error("DeleteConfig not invoked")
	}
}

func TestConfigHandler_WrongMethod_405(t *testing.T) {
	t.Parallel()

	h := transmitter.ConfigHandler(&stubTransmitter{}, transmitter.AlwaysAllow)
	req := httptest.NewRequest(http.MethodPut, "/streams", nil)
	resp := serve(t, h, req)

	if resp.StatusCode != http.StatusMethodNotAllowed {
		t.Fatalf("status: got %d, want %d", resp.StatusCode, http.StatusMethodNotAllowed)
	}
	if got, want := resp.Header.Get("Allow"), "GET, POST, PATCH, DELETE"; got != want {
		t.Errorf("Allow: got %q, want %q", got, want)
	}
	p := readProblem(t, resp)
	if p.Status != http.StatusMethodNotAllowed {
		t.Errorf("ProblemDetails.Status: got %d, want %d", p.Status, http.StatusMethodNotAllowed)
	}
}

func TestConfigHandler_AlwaysReject_401(t *testing.T) {
	t.Parallel()

	h := transmitter.ConfigHandler(&stubTransmitter{}, transmitter.AlwaysReject)
	req := httptest.NewRequest(http.MethodGet, "/streams", nil)
	resp := serve(t, h, req)

	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("status: got %d, want %d", resp.StatusCode, http.StatusUnauthorized)
	}
	p := readProblem(t, resp)
	if p.Status != http.StatusUnauthorized {
		t.Errorf("ProblemDetails.Status: got %d, want %d", p.Status, http.StatusUnauthorized)
	}
	if p.Title != "Unauthorized" {
		t.Errorf("ProblemDetails.Title: got %q, want %q", p.Title, "Unauthorized")
	}
}

func TestConfigHandler_NilAuth_FailsClosed(t *testing.T) {
	t.Parallel()

	// A handler constructed with a nil AuthFunc must reject every
	// request — the fail-closed default. Otherwise a wiring mistake
	// silently disables auth.
	h := transmitter.ConfigHandler(&stubTransmitter{}, nil)
	req := httptest.NewRequest(http.MethodGet, "/streams", nil)
	resp := serve(t, h, req)

	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("status: got %d, want %d (nil AuthFunc must fail closed)", resp.StatusCode, http.StatusUnauthorized)
	}
}

func TestConfigHandler_StreamNotFound_404(t *testing.T) {
	t.Parallel()

	stub := &stubTransmitter{
		getConfig: func(context.Context, string) (*ssf.StreamConfig, error) {
			return nil, ssf.ErrStreamNotFound
		},
	}
	h := transmitter.ConfigHandler(stub, transmitter.AlwaysAllow)
	req := httptest.NewRequest(http.MethodGet, "/streams?stream_id=missing", nil)
	resp := serve(t, h, req)

	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("status: got %d, want %d", resp.StatusCode, http.StatusNotFound)
	}
	p := readProblem(t, resp)
	if p.Status != http.StatusNotFound {
		t.Errorf("ProblemDetails.Status: got %d, want %d", p.Status, http.StatusNotFound)
	}
}

func TestConfigHandler_BadJSON_400(t *testing.T) {
	t.Parallel()

	h := transmitter.ConfigHandler(&stubTransmitter{}, transmitter.AlwaysAllow)
	req := httptest.NewRequest(http.MethodPost, "/streams", strings.NewReader("{not json"))
	resp := serve(t, h, req)

	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("status: got %d, want %d", resp.StatusCode, http.StatusBadRequest)
	}
	p := readProblem(t, resp)
	if p.Title != "Validation Failed" {
		t.Errorf("Title: got %q, want %q", p.Title, "Validation Failed")
	}
}

func TestConfigHandler_NotImplemented_501(t *testing.T) {
	t.Parallel()

	// The bare stub (no method overrides) is the NotImplementedTransmitter
	// surface — every call returns ssf.ErrNotImplemented.
	h := transmitter.ConfigHandler(&stubTransmitter{}, transmitter.AlwaysAllow)

	req := httptest.NewRequest(http.MethodGet, "/streams?stream_id=abc", nil)
	resp := serve(t, h, req)

	if resp.StatusCode != http.StatusNotImplemented {
		t.Fatalf("status: got %d, want %d", resp.StatusCode, http.StatusNotImplemented)
	}
	p := readProblem(t, resp)
	if p.Status != http.StatusNotImplemented {
		t.Errorf("ProblemDetails.Status: got %d, want %d", p.Status, http.StatusNotImplemented)
	}
}

func TestConfigHandler_Update_MissingStreamID_400(t *testing.T) {
	t.Parallel()

	h := transmitter.ConfigHandler(&stubTransmitter{}, transmitter.AlwaysAllow)
	req := httptest.NewRequest(http.MethodPatch, "/streams", strings.NewReader(`{}`))
	resp := serve(t, h, req)

	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("status: got %d, want %d", resp.StatusCode, http.StatusBadRequest)
	}
}

// ---- StatusHandler --------------------------------------------------

func TestStatusHandler_GetSuccess(t *testing.T) {
	t.Parallel()

	stub := &stubTransmitter{
		getStatus: func(_ context.Context, id string, subject json.RawMessage) (*ssf.StatusResponse, error) {
			if id != "abc" {
				t.Errorf("streamID: got %q", id)
			}
			if string(subject) != `{"format":"opaque","id":"x"}` {
				t.Errorf("subject: got %s", subject)
			}
			return &ssf.StatusResponse{Status: ssf.StreamStatusEnabled}, nil
		},
	}
	h := transmitter.StatusHandler(stub, transmitter.AlwaysAllow)

	req := httptest.NewRequest(http.MethodGet,
		`/streams/status?stream_id=abc&subject={"format":"opaque","id":"x"}`, nil)
	resp := serve(t, h, req)

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status: got %d, want %d", resp.StatusCode, http.StatusOK)
	}
	var got ssf.StatusResponse
	readJSON(t, resp, &got)
	if got.Status != ssf.StreamStatusEnabled {
		t.Errorf("Status: got %q, want %q", got.Status, ssf.StreamStatusEnabled)
	}
}

func TestStatusHandler_PostUpdateSuccess(t *testing.T) {
	t.Parallel()

	stub := &stubTransmitter{
		updateStatus: func(_ context.Context, id string, req *ssf.StatusUpdateRequest) (*ssf.StatusResponse, error) {
			if id != "abc" {
				t.Errorf("streamID: got %q", id)
			}
			if req.Status != ssf.StreamStatusPaused {
				t.Errorf("Status: got %q", req.Status)
			}
			return &ssf.StatusResponse{Status: req.Status, Reason: "ack"}, nil
		},
	}
	h := transmitter.StatusHandler(stub, transmitter.AlwaysAllow)

	body := strings.NewReader(`{"status":"paused"}`)
	req := httptest.NewRequest(http.MethodPost, "/streams/status?stream_id=abc", body)
	resp := serve(t, h, req)

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status: got %d, want %d", resp.StatusCode, http.StatusOK)
	}
}

func TestStatusHandler_WrongMethod_405(t *testing.T) {
	t.Parallel()

	h := transmitter.StatusHandler(&stubTransmitter{}, transmitter.AlwaysAllow)
	req := httptest.NewRequest(http.MethodDelete, "/streams/status?stream_id=abc", nil)
	resp := serve(t, h, req)

	if resp.StatusCode != http.StatusMethodNotAllowed {
		t.Fatalf("status: got %d", resp.StatusCode)
	}
	if got, want := resp.Header.Get("Allow"), "GET, POST"; got != want {
		t.Errorf("Allow: got %q, want %q", got, want)
	}
}

func TestStatusHandler_AlwaysReject_401(t *testing.T) {
	t.Parallel()

	h := transmitter.StatusHandler(&stubTransmitter{}, transmitter.AlwaysReject)
	req := httptest.NewRequest(http.MethodGet, "/streams/status?stream_id=abc", nil)
	resp := serve(t, h, req)

	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("status: got %d", resp.StatusCode)
	}
}

func TestStatusHandler_StreamNotFound_404(t *testing.T) {
	t.Parallel()

	stub := &stubTransmitter{
		getStatus: func(context.Context, string, json.RawMessage) (*ssf.StatusResponse, error) {
			return nil, ssf.ErrStreamNotFound
		},
	}
	h := transmitter.StatusHandler(stub, transmitter.AlwaysAllow)
	req := httptest.NewRequest(http.MethodGet, "/streams/status?stream_id=missing", nil)
	resp := serve(t, h, req)

	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("status: got %d", resp.StatusCode)
	}
}

func TestStatusHandler_BadJSON_400(t *testing.T) {
	t.Parallel()

	h := transmitter.StatusHandler(&stubTransmitter{}, transmitter.AlwaysAllow)
	req := httptest.NewRequest(http.MethodPost, "/streams/status?stream_id=abc",
		strings.NewReader("{not json"))
	resp := serve(t, h, req)

	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("status: got %d", resp.StatusCode)
	}
}

func TestStatusHandler_NotImplemented_501(t *testing.T) {
	t.Parallel()

	h := transmitter.StatusHandler(&stubTransmitter{}, transmitter.AlwaysAllow)
	req := httptest.NewRequest(http.MethodGet, "/streams/status?stream_id=abc", nil)
	resp := serve(t, h, req)

	if resp.StatusCode != http.StatusNotImplemented {
		t.Fatalf("status: got %d", resp.StatusCode)
	}
}

func TestStatusHandler_BadSubjectQuery_400(t *testing.T) {
	t.Parallel()

	h := transmitter.StatusHandler(&stubTransmitter{}, transmitter.AlwaysAllow)
	req := httptest.NewRequest(http.MethodGet,
		`/streams/status?stream_id=abc&subject=not-json`, nil)
	resp := serve(t, h, req)

	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("status: got %d, want %d (malformed subject query parameter)", resp.StatusCode, http.StatusBadRequest)
	}
}

func TestStatusHandler_MissingStreamID_400(t *testing.T) {
	t.Parallel()

	h := transmitter.StatusHandler(&stubTransmitter{}, transmitter.AlwaysAllow)
	req := httptest.NewRequest(http.MethodGet, "/streams/status", nil)
	resp := serve(t, h, req)

	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("status: got %d, want %d", resp.StatusCode, http.StatusBadRequest)
	}
}

// ---- AddSubjectHandler ----------------------------------------------

func TestAddSubjectHandler_PostSuccess(t *testing.T) {
	t.Parallel()

	stub := &stubTransmitter{
		addSubject: func(_ context.Context, id string, _ *ssf.AddSubjectRequest) error {
			if id != "abc" {
				t.Errorf("streamID: got %q", id)
			}
			return nil
		},
	}
	h := transmitter.AddSubjectHandler(stub, transmitter.AlwaysAllow)

	body := strings.NewReader(`{"subject":{"format":"opaque","id":"x"}}`)
	req := httptest.NewRequest(http.MethodPost, "/streams/subjects:add?stream_id=abc", body)
	resp := serve(t, h, req)

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status: got %d, want %d", resp.StatusCode, http.StatusOK)
	}
}

func TestAddSubjectHandler_WrongMethod_405(t *testing.T) {
	t.Parallel()

	h := transmitter.AddSubjectHandler(&stubTransmitter{}, transmitter.AlwaysAllow)
	req := httptest.NewRequest(http.MethodGet, "/streams/subjects:add?stream_id=abc", nil)
	resp := serve(t, h, req)

	if resp.StatusCode != http.StatusMethodNotAllowed {
		t.Fatalf("status: got %d", resp.StatusCode)
	}
	if got, want := resp.Header.Get("Allow"), "POST"; got != want {
		t.Errorf("Allow: got %q, want %q", got, want)
	}
}

func TestAddSubjectHandler_AlwaysReject_401(t *testing.T) {
	t.Parallel()

	h := transmitter.AddSubjectHandler(&stubTransmitter{}, transmitter.AlwaysReject)
	req := httptest.NewRequest(http.MethodPost, "/streams/subjects:add?stream_id=abc",
		strings.NewReader(`{}`))
	resp := serve(t, h, req)
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("status: got %d", resp.StatusCode)
	}
}

func TestAddSubjectHandler_StreamNotFound_404(t *testing.T) {
	t.Parallel()

	stub := &stubTransmitter{
		addSubject: func(context.Context, string, *ssf.AddSubjectRequest) error {
			return ssf.ErrStreamNotFound
		},
	}
	h := transmitter.AddSubjectHandler(stub, transmitter.AlwaysAllow)
	req := httptest.NewRequest(http.MethodPost, "/streams/subjects:add?stream_id=missing",
		strings.NewReader(`{"subject":{"format":"opaque","id":"x"}}`))
	resp := serve(t, h, req)

	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("status: got %d", resp.StatusCode)
	}
}

func TestAddSubjectHandler_BadJSON_400(t *testing.T) {
	t.Parallel()

	h := transmitter.AddSubjectHandler(&stubTransmitter{}, transmitter.AlwaysAllow)
	req := httptest.NewRequest(http.MethodPost, "/streams/subjects:add?stream_id=abc",
		strings.NewReader("{not json"))
	resp := serve(t, h, req)

	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("status: got %d", resp.StatusCode)
	}
}

func TestAddSubjectHandler_NotImplemented_501(t *testing.T) {
	t.Parallel()

	h := transmitter.AddSubjectHandler(&stubTransmitter{}, transmitter.AlwaysAllow)
	req := httptest.NewRequest(http.MethodPost, "/streams/subjects:add?stream_id=abc",
		strings.NewReader(`{"subject":{"format":"opaque","id":"x"}}`))
	resp := serve(t, h, req)

	if resp.StatusCode != http.StatusNotImplemented {
		t.Fatalf("status: got %d", resp.StatusCode)
	}
}

// ---- RemoveSubjectHandler ------------------------------------------

func TestRemoveSubjectHandler_PostSuccess(t *testing.T) {
	t.Parallel()

	stub := &stubTransmitter{
		removeSubject: func(_ context.Context, id string, _ *ssf.RemoveSubjectRequest) error {
			if id != "abc" {
				t.Errorf("streamID: got %q", id)
			}
			return nil
		},
	}
	h := transmitter.RemoveSubjectHandler(stub, transmitter.AlwaysAllow)

	body := strings.NewReader(`{"subject":{"format":"opaque","id":"x"}}`)
	req := httptest.NewRequest(http.MethodPost, "/streams/subjects:remove?stream_id=abc", body)
	resp := serve(t, h, req)

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status: got %d", resp.StatusCode)
	}
}

func TestRemoveSubjectHandler_WrongMethod_405(t *testing.T) {
	t.Parallel()

	h := transmitter.RemoveSubjectHandler(&stubTransmitter{}, transmitter.AlwaysAllow)
	req := httptest.NewRequest(http.MethodGet, "/streams/subjects:remove?stream_id=abc", nil)
	resp := serve(t, h, req)

	if resp.StatusCode != http.StatusMethodNotAllowed {
		t.Fatalf("status: got %d", resp.StatusCode)
	}
}

func TestRemoveSubjectHandler_AlwaysReject_401(t *testing.T) {
	t.Parallel()

	h := transmitter.RemoveSubjectHandler(&stubTransmitter{}, transmitter.AlwaysReject)
	req := httptest.NewRequest(http.MethodPost, "/streams/subjects:remove?stream_id=abc",
		strings.NewReader(`{}`))
	resp := serve(t, h, req)
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("status: got %d", resp.StatusCode)
	}
}

func TestRemoveSubjectHandler_StreamNotFound_404(t *testing.T) {
	t.Parallel()

	stub := &stubTransmitter{
		removeSubject: func(context.Context, string, *ssf.RemoveSubjectRequest) error {
			return ssf.ErrStreamNotFound
		},
	}
	h := transmitter.RemoveSubjectHandler(stub, transmitter.AlwaysAllow)
	req := httptest.NewRequest(http.MethodPost, "/streams/subjects:remove?stream_id=missing",
		strings.NewReader(`{"subject":{"format":"opaque","id":"x"}}`))
	resp := serve(t, h, req)

	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("status: got %d", resp.StatusCode)
	}
}

func TestRemoveSubjectHandler_BadJSON_400(t *testing.T) {
	t.Parallel()

	h := transmitter.RemoveSubjectHandler(&stubTransmitter{}, transmitter.AlwaysAllow)
	req := httptest.NewRequest(http.MethodPost, "/streams/subjects:remove?stream_id=abc",
		strings.NewReader("{not json"))
	resp := serve(t, h, req)

	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("status: got %d", resp.StatusCode)
	}
}

func TestRemoveSubjectHandler_NotImplemented_501(t *testing.T) {
	t.Parallel()

	h := transmitter.RemoveSubjectHandler(&stubTransmitter{}, transmitter.AlwaysAllow)
	req := httptest.NewRequest(http.MethodPost, "/streams/subjects:remove?stream_id=abc",
		strings.NewReader(`{"subject":{"format":"opaque","id":"x"}}`))
	resp := serve(t, h, req)

	if resp.StatusCode != http.StatusNotImplemented {
		t.Fatalf("status: got %d", resp.StatusCode)
	}
}

// ---- VerificationHandler -------------------------------------------

func TestVerificationHandler_PostSuccess(t *testing.T) {
	t.Parallel()

	stub := &stubTransmitter{
		verify: func(_ context.Context, id string, req *ssf.VerificationRequest) error {
			if id != "abc" {
				t.Errorf("streamID: got %q", id)
			}
			if req.State != "echo" {
				t.Errorf("State: got %q", req.State)
			}
			return nil
		},
	}
	h := transmitter.VerificationHandler(stub, transmitter.AlwaysAllow)

	body := strings.NewReader(`{"state":"echo"}`)
	req := httptest.NewRequest(http.MethodPost, "/streams/verify?stream_id=abc", body)
	resp := serve(t, h, req)

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status: got %d", resp.StatusCode)
	}
}

func TestVerificationHandler_WrongMethod_405(t *testing.T) {
	t.Parallel()

	h := transmitter.VerificationHandler(&stubTransmitter{}, transmitter.AlwaysAllow)
	req := httptest.NewRequest(http.MethodGet, "/streams/verify?stream_id=abc", nil)
	resp := serve(t, h, req)

	if resp.StatusCode != http.StatusMethodNotAllowed {
		t.Fatalf("status: got %d", resp.StatusCode)
	}
}

func TestVerificationHandler_AlwaysReject_401(t *testing.T) {
	t.Parallel()

	h := transmitter.VerificationHandler(&stubTransmitter{}, transmitter.AlwaysReject)
	req := httptest.NewRequest(http.MethodPost, "/streams/verify?stream_id=abc",
		strings.NewReader(`{}`))
	resp := serve(t, h, req)
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("status: got %d", resp.StatusCode)
	}
}

func TestVerificationHandler_StreamNotFound_404(t *testing.T) {
	t.Parallel()

	stub := &stubTransmitter{
		verify: func(context.Context, string, *ssf.VerificationRequest) error {
			return ssf.ErrStreamNotFound
		},
	}
	h := transmitter.VerificationHandler(stub, transmitter.AlwaysAllow)
	req := httptest.NewRequest(http.MethodPost, "/streams/verify?stream_id=missing",
		strings.NewReader(`{}`))
	resp := serve(t, h, req)
	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("status: got %d", resp.StatusCode)
	}
}

func TestVerificationHandler_BadJSON_400(t *testing.T) {
	t.Parallel()

	h := transmitter.VerificationHandler(&stubTransmitter{}, transmitter.AlwaysAllow)
	req := httptest.NewRequest(http.MethodPost, "/streams/verify?stream_id=abc",
		strings.NewReader("{not json"))
	resp := serve(t, h, req)

	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("status: got %d", resp.StatusCode)
	}
}

func TestVerificationHandler_NotImplemented_501(t *testing.T) {
	t.Parallel()

	h := transmitter.VerificationHandler(&stubTransmitter{}, transmitter.AlwaysAllow)
	req := httptest.NewRequest(http.MethodPost, "/streams/verify?stream_id=abc",
		strings.NewReader(`{}`))
	resp := serve(t, h, req)

	if resp.StatusCode != http.StatusNotImplemented {
		t.Fatalf("status: got %d", resp.StatusCode)
	}
}

// ---- PollHandler ----------------------------------------------------

func TestPollHandler_PostSuccess(t *testing.T) {
	t.Parallel()

	stub := &stubTransmitter{
		pollEvents: func(_ context.Context, id string, req *ssf.PollRequest) (*ssf.PollResponse, error) {
			if id != "abc" {
				t.Errorf("streamID: got %q", id)
			}
			if req.MaxEvents == nil || *req.MaxEvents != 5 {
				t.Errorf("MaxEvents: got %v, want *int=5", req.MaxEvents)
			}
			return &ssf.PollResponse{Sets: map[string]string{"jti-1": "jws"}}, nil
		},
	}
	h := transmitter.PollHandler(stub, transmitter.AlwaysAllow)

	body := strings.NewReader(`{"maxEvents":5}`)
	req := httptest.NewRequest(http.MethodPost, "/streams/poll?stream_id=abc", body)
	resp := serve(t, h, req)

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status: got %d", resp.StatusCode)
	}
	var got ssf.PollResponse
	readJSON(t, resp, &got)
	if got.Sets["jti-1"] != "jws" {
		t.Errorf("Sets: got %v", got.Sets)
	}
}

func TestPollHandler_WrongMethod_405(t *testing.T) {
	t.Parallel()

	h := transmitter.PollHandler(&stubTransmitter{}, transmitter.AlwaysAllow)
	req := httptest.NewRequest(http.MethodGet, "/streams/poll?stream_id=abc", nil)
	resp := serve(t, h, req)

	if resp.StatusCode != http.StatusMethodNotAllowed {
		t.Fatalf("status: got %d", resp.StatusCode)
	}
}

func TestPollHandler_AlwaysReject_401(t *testing.T) {
	t.Parallel()

	h := transmitter.PollHandler(&stubTransmitter{}, transmitter.AlwaysReject)
	req := httptest.NewRequest(http.MethodPost, "/streams/poll?stream_id=abc",
		strings.NewReader(`{}`))
	resp := serve(t, h, req)
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("status: got %d", resp.StatusCode)
	}
}

func TestPollHandler_StreamNotFound_404(t *testing.T) {
	t.Parallel()

	stub := &stubTransmitter{
		pollEvents: func(context.Context, string, *ssf.PollRequest) (*ssf.PollResponse, error) {
			return nil, ssf.ErrStreamNotFound
		},
	}
	h := transmitter.PollHandler(stub, transmitter.AlwaysAllow)
	req := httptest.NewRequest(http.MethodPost, "/streams/poll?stream_id=missing",
		strings.NewReader(`{}`))
	resp := serve(t, h, req)
	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("status: got %d", resp.StatusCode)
	}
}

func TestPollHandler_BadJSON_400(t *testing.T) {
	t.Parallel()

	h := transmitter.PollHandler(&stubTransmitter{}, transmitter.AlwaysAllow)
	req := httptest.NewRequest(http.MethodPost, "/streams/poll?stream_id=abc",
		strings.NewReader("{not json"))
	resp := serve(t, h, req)

	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("status: got %d", resp.StatusCode)
	}
}

func TestPollHandler_NotImplemented_501(t *testing.T) {
	t.Parallel()

	h := transmitter.PollHandler(&stubTransmitter{}, transmitter.AlwaysAllow)
	req := httptest.NewRequest(http.MethodPost, "/streams/poll?stream_id=abc",
		strings.NewReader(`{}`))
	resp := serve(t, h, req)

	if resp.StatusCode != http.StatusNotImplemented {
		t.Fatalf("status: got %d", resp.StatusCode)
	}
}

// ---- Cross-cutting --------------------------------------------------

func TestErrorMapping_InvalidConfig_400(t *testing.T) {
	t.Parallel()

	stub := &stubTransmitter{
		createConfig: func(context.Context, *ssf.StreamConfig) (*ssf.StreamConfig, error) {
			return nil, ssf.ErrInvalidConfig
		},
	}
	h := transmitter.ConfigHandler(stub, transmitter.AlwaysAllow)
	req := httptest.NewRequest(http.MethodPost, "/streams",
		strings.NewReader(`{"iss":"https://t.example/"}`))
	resp := serve(t, h, req)

	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("status: got %d, want %d", resp.StatusCode, http.StatusBadRequest)
	}
	p := readProblem(t, resp)
	if p.Title != "Invalid Configuration" {
		t.Errorf("Title: got %q", p.Title)
	}
}

func TestErrorMapping_ValidationError_400(t *testing.T) {
	t.Parallel()

	ve := &ssf.ValidationError{
		Rule:   "events_requested non-empty",
		Field:  "events_requested",
		Reason: "must list at least one event-type URI",
	}
	stub := &stubTransmitter{
		createConfig: func(context.Context, *ssf.StreamConfig) (*ssf.StreamConfig, error) {
			return nil, ve
		},
	}
	h := transmitter.ConfigHandler(stub, transmitter.AlwaysAllow)
	req := httptest.NewRequest(http.MethodPost, "/streams",
		strings.NewReader(`{"iss":"https://t.example/"}`))
	resp := serve(t, h, req)

	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("status: got %d, want %d", resp.StatusCode, http.StatusBadRequest)
	}
	p := readProblem(t, resp)
	if p.Title != "Validation Failed" {
		t.Errorf("Title: got %q, want %q", p.Title, "Validation Failed")
	}
	if !strings.Contains(p.Detail, "events_requested") {
		t.Errorf("Detail: got %q, want it to mention the failing rule/field", p.Detail)
	}
}

func TestErrorMapping_OtherError_500(t *testing.T) {
	t.Parallel()

	stub := &stubTransmitter{
		getConfig: func(context.Context, string) (*ssf.StreamConfig, error) {
			return nil, errors.New("disk on fire")
		},
	}
	h := transmitter.ConfigHandler(stub, transmitter.AlwaysAllow)
	req := httptest.NewRequest(http.MethodGet, "/streams?stream_id=abc", nil)
	resp := serve(t, h, req)

	if resp.StatusCode != http.StatusInternalServerError {
		t.Fatalf("status: got %d, want %d", resp.StatusCode, http.StatusInternalServerError)
	}
}

func TestErrorMapping_UnauthorizedFromTransmitter_401(t *testing.T) {
	t.Parallel()

	// AuthFunc passes but the Transmitter returns ErrUnauthorized;
	// the response shape must still match the auth-time 401 path.
	stub := &stubTransmitter{
		getConfig: func(context.Context, string) (*ssf.StreamConfig, error) {
			return nil, ssf.ErrUnauthorized
		},
	}
	h := transmitter.ConfigHandler(stub, transmitter.AlwaysAllow)
	req := httptest.NewRequest(http.MethodGet, "/streams?stream_id=abc", nil)
	resp := serve(t, h, req)

	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("status: got %d", resp.StatusCode)
	}
	p := readProblem(t, resp)
	if p.Title != "Unauthorized" {
		t.Errorf("Title: got %q", p.Title)
	}
}
