// Copyright 2026 The go-ssf Authors
// SPDX-License-Identifier: Apache-2.0

package transmitter_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/hstern/go-ssf"
	"github.com/hstern/go-ssf/transmitter"
)

// muxCalls records which Transmitter method a request reached so the
// routing tests can assert that each path dispatches to the correct
// handler. The recording stub returns success values so the response
// surface (status, body) is incidental to the routing check.
type muxCalls struct {
	getConfig     int
	listConfig    int
	createConfig  int
	updateConfig  int
	deleteConfig  int
	getStatus     int
	updateStatus  int
	addSubject    int
	removeSubject int
	verify        int
	pollEvents    int
}

func muxStub(c *muxCalls) *stubTransmitter {
	return &stubTransmitter{
		getConfig: func(context.Context, string) (*ssf.StreamConfig, error) {
			c.getConfig++
			return &ssf.StreamConfig{StreamID: "abc"}, nil
		},
		listConfig: func(context.Context, string) ([]*ssf.StreamConfig, string, error) {
			c.listConfig++
			return nil, "", nil
		},
		createConfig: func(_ context.Context, cfg *ssf.StreamConfig) (*ssf.StreamConfig, error) {
			c.createConfig++
			return cfg, nil
		},
		updateConfig: func(_ context.Context, cfg *ssf.StreamConfig) (*ssf.StreamConfig, error) {
			c.updateConfig++
			return cfg, nil
		},
		deleteConfig: func(context.Context, string) error { c.deleteConfig++; return nil },
		getStatus: func(context.Context, string, json.RawMessage) (*ssf.StatusResponse, error) {
			c.getStatus++
			return &ssf.StatusResponse{Status: ssf.StreamStatusEnabled}, nil
		},
		updateStatus: func(_ context.Context, _ string, req *ssf.StatusUpdateRequest) (*ssf.StatusResponse, error) {
			c.updateStatus++
			return &ssf.StatusResponse{Status: req.Status}, nil
		},
		addSubject:    func(context.Context, string, *ssf.AddSubjectRequest) error { c.addSubject++; return nil },
		removeSubject: func(context.Context, string, *ssf.RemoveSubjectRequest) error { c.removeSubject++; return nil },
		verify:        func(context.Context, string, *ssf.VerificationRequest) error { c.verify++; return nil },
		pollEvents: func(context.Context, string, *ssf.PollRequest) (*ssf.PollResponse, error) {
			c.pollEvents++
			return &ssf.PollResponse{}, nil
		},
	}
}

func TestMuxHandler_RoutesEachEndpoint(t *testing.T) {
	t.Parallel()

	calls := &muxCalls{}
	mux := transmitter.MuxHandler(muxStub(calls), transmitter.AlwaysAllow)

	cases := []struct {
		name     string
		method   string
		path     string
		body     string
		want     int
		incCheck func(c *muxCalls) bool
	}{
		{
			name: "ListConfig", method: http.MethodGet, path: "/streams", want: http.StatusOK,
			incCheck: func(c *muxCalls) bool { return c.listConfig == 1 },
		},
		{
			name: "GetConfig", method: http.MethodGet, path: "/streams?stream_id=abc", want: http.StatusOK,
			incCheck: func(c *muxCalls) bool { return c.getConfig == 1 },
		},
		{
			name: "CreateConfig", method: http.MethodPost, path: "/streams",
			body: `{"iss":"https://t.example/"}`, want: http.StatusCreated,
			incCheck: func(c *muxCalls) bool { return c.createConfig == 1 },
		},
		{
			name: "UpdateConfig", method: http.MethodPatch, path: "/streams?stream_id=abc",
			body: `{}`, want: http.StatusOK,
			incCheck: func(c *muxCalls) bool { return c.updateConfig == 1 },
		},
		{
			name: "DeleteConfig", method: http.MethodDelete, path: "/streams?stream_id=abc",
			want:     http.StatusNoContent,
			incCheck: func(c *muxCalls) bool { return c.deleteConfig == 1 },
		},
		{
			name: "GetStatus", method: http.MethodGet, path: "/streams/status?stream_id=abc",
			want:     http.StatusOK,
			incCheck: func(c *muxCalls) bool { return c.getStatus == 1 },
		},
		{
			name: "UpdateStatus", method: http.MethodPost, path: "/streams/status?stream_id=abc",
			body: `{"status":"paused"}`, want: http.StatusOK,
			incCheck: func(c *muxCalls) bool { return c.updateStatus == 1 },
		},
		{
			name: "AddSubject", method: http.MethodPost, path: "/streams/subjects:add?stream_id=abc",
			body: `{"subject":{"format":"opaque","id":"x"}}`, want: http.StatusOK,
			incCheck: func(c *muxCalls) bool { return c.addSubject == 1 },
		},
		{
			name: "RemoveSubject", method: http.MethodPost, path: "/streams/subjects:remove?stream_id=abc",
			body: `{"subject":{"format":"opaque","id":"x"}}`, want: http.StatusOK,
			incCheck: func(c *muxCalls) bool { return c.removeSubject == 1 },
		},
		{
			name: "Verify", method: http.MethodPost, path: "/streams/verify?stream_id=abc",
			body: `{}`, want: http.StatusOK,
			incCheck: func(c *muxCalls) bool { return c.verify == 1 },
		},
		{
			name: "PollEvents", method: http.MethodPost, path: "/streams/poll?stream_id=abc",
			body: `{}`, want: http.StatusOK,
			incCheck: func(c *muxCalls) bool { return c.pollEvents == 1 },
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var body *strings.Reader
			if tc.body != "" {
				body = strings.NewReader(tc.body)
			}

			var req *http.Request
			if body == nil {
				req = httptest.NewRequest(tc.method, tc.path, nil)
			} else {
				req = httptest.NewRequest(tc.method, tc.path, body)
			}
			rec := httptest.NewRecorder()
			mux.ServeHTTP(rec, req)
			resp := rec.Result()
			t.Cleanup(func() { _ = resp.Body.Close() })

			if resp.StatusCode != tc.want {
				t.Errorf("status: got %d, want %d", resp.StatusCode, tc.want)
			}
			if !tc.incCheck(calls) {
				t.Errorf("expected dispatch counter for %s did not increment; calls=%+v", tc.name, calls)
			}
		})
	}
}

func TestMuxHandler_NilTransmitterPanics(t *testing.T) {
	t.Parallel()

	defer func() {
		if r := recover(); r == nil {
			t.Fatal("expected panic on nil Transmitter, got none")
		}
	}()
	_ = transmitter.MuxHandler(nil, transmitter.AlwaysAllow)
}

func TestMuxHandler_NilAuthPanics(t *testing.T) {
	t.Parallel()

	defer func() {
		if r := recover(); r == nil {
			t.Fatal("expected panic on nil AuthFunc, got none")
		}
	}()
	_ = transmitter.MuxHandler(&stubTransmitter{}, nil)
}

func TestMuxHandler_PathOverrides(t *testing.T) {
	t.Parallel()

	calls := &muxCalls{}
	mux := transmitter.MuxHandler(muxStub(calls), transmitter.AlwaysAllow,
		transmitter.WithStreamsPath("/v2/streams"),
		transmitter.WithPollPath("/v2/poll"))

	// Old default path is unrouted; new path dispatches.
	req := httptest.NewRequest(http.MethodGet, "/streams", nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Result().StatusCode == http.StatusOK {
		t.Errorf("default /streams path still serves after override")
	}

	req = httptest.NewRequest(http.MethodGet, "/v2/streams", nil)
	rec = httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Result().StatusCode != http.StatusOK {
		t.Errorf("override path /v2/streams not routed; status=%d", rec.Result().StatusCode)
	}
	if calls.listConfig != 1 {
		t.Errorf("ListConfig dispatch counter: got %d, want 1", calls.listConfig)
	}

	req = httptest.NewRequest(http.MethodPost, "/v2/poll?stream_id=abc", strings.NewReader(`{}`))
	rec = httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Result().StatusCode != http.StatusOK {
		t.Errorf("override path /v2/poll not routed; status=%d", rec.Result().StatusCode)
	}
	if calls.pollEvents != 1 {
		t.Errorf("PollEvents dispatch counter: got %d, want 1", calls.pollEvents)
	}
}
