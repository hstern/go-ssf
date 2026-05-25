// Copyright 2026 The go-ssf Authors
// SPDX-License-Identifier: Apache-2.0

package ssf_test

import (
	"context"
	"encoding/json"
	"testing"

	ssf "github.com/hstern/go-ssf"
)

// nopStore is a do-nothing [ssf.StreamStore] implementation used only
// to assert that the interface is callable from a foreign package and
// that all ten methods compile against the documented signatures. The
// substantive behavioral tests live in the memstore subpackage; this
// file is the lightweight pinning of the interface shape itself.
type nopStore struct{}

func (nopStore) CreateStream(_ context.Context, cfg *ssf.StreamConfig) (*ssf.StreamConfig, error) {
	return cfg, nil
}

func (nopStore) GetStream(_ context.Context, _ string) (*ssf.StreamConfig, error) {
	return nil, ssf.ErrStreamNotFound
}

func (nopStore) ListStreams(_ context.Context, _ string) ([]*ssf.StreamConfig, string, error) {
	return nil, "", nil
}

func (nopStore) UpdateStream(_ context.Context, cfg *ssf.StreamConfig) (*ssf.StreamConfig, error) {
	return cfg, nil
}

func (nopStore) DeleteStream(_ context.Context, _ string) error { return nil }

func (nopStore) GetStreamStatus(_ context.Context, _ string, _ json.RawMessage) (*ssf.StatusResponse, error) {
	return &ssf.StatusResponse{Status: ssf.StreamStatusEnabled}, nil
}

func (nopStore) SetStreamStatus(_ context.Context, _ string, req *ssf.StatusUpdateRequest) (*ssf.StatusResponse, error) {
	return &ssf.StatusResponse{Status: req.Status, Reason: req.Reason, Subject: req.Subject}, nil
}

func (nopStore) AddSubject(_ context.Context, _ string, _ *ssf.AddSubjectRequest) error { return nil }

func (nopStore) RemoveSubject(_ context.Context, _ string, _ *ssf.RemoveSubjectRequest) error {
	return nil
}

func (nopStore) EnqueueSET(_ context.Context, _, _ string) error { return nil }

// Compile-time check that nopStore satisfies the interface from a
// foreign package. A package-level var is the conventional placement
// for the assertion; declaring it inside the test function would
// equally compile but lose the inventory at the file's top level.
var _ ssf.StreamStore = nopStore{}

// TestStreamStoreInterfaceCallable exercises every method on a stub
// implementation. It catches signature drift — e.g. a parameter or
// return-type change on the interface that the in-tree memstore happens
// to keep consistent with itself but that breaks foreign-package
// implementers.
func TestStreamStoreInterfaceCallable(t *testing.T) {
	t.Parallel()

	var store ssf.StreamStore = nopStore{}
	ctx := context.Background()

	if _, err := store.CreateStream(ctx, &ssf.StreamConfig{StreamID: "s1"}); err != nil {
		t.Fatalf("CreateStream: %v", err)
	}
	if _, err := store.GetStream(ctx, "missing"); err == nil {
		t.Fatalf("GetStream(missing): want error, got nil")
	}
	if _, _, err := store.ListStreams(ctx, ""); err != nil {
		t.Fatalf("ListStreams: %v", err)
	}
	if _, err := store.UpdateStream(ctx, &ssf.StreamConfig{StreamID: "s1"}); err != nil {
		t.Fatalf("UpdateStream: %v", err)
	}
	if err := store.DeleteStream(ctx, "s1"); err != nil {
		t.Fatalf("DeleteStream: %v", err)
	}
	if _, err := store.GetStreamStatus(ctx, "s1", nil); err != nil {
		t.Fatalf("GetStreamStatus: %v", err)
	}
	if _, err := store.SetStreamStatus(ctx, "s1", &ssf.StatusUpdateRequest{Status: ssf.StreamStatusEnabled}); err != nil {
		t.Fatalf("SetStreamStatus: %v", err)
	}
	if err := store.AddSubject(ctx, "s1", &ssf.AddSubjectRequest{}); err != nil {
		t.Fatalf("AddSubject: %v", err)
	}
	if err := store.RemoveSubject(ctx, "s1", &ssf.RemoveSubjectRequest{}); err != nil {
		t.Fatalf("RemoveSubject: %v", err)
	}
	if err := store.EnqueueSET(ctx, "s1", "jws.compact.value"); err != nil {
		t.Fatalf("EnqueueSET: %v", err)
	}
}
