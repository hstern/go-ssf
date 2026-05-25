// Copyright 2026 The go-ssf Authors
// SPDX-License-Identifier: Apache-2.0

package transmitter_test

import (
	"context"
	"encoding/json"
	"errors"
	"testing"

	ssf "github.com/hstern/go-ssf"
	"github.com/hstern/go-ssf/transmitter"
)

// TestNotImplementedTransmitterReturnsSentinel runs every method on
// the zero value NotImplementedTransmitter and asserts the returned
// error is, or wraps, ssf.ErrNotImplemented. The errors.Is check
// makes the test resilient to a future change that returns a wrapped
// sentinel instead of the bare value.
func TestNotImplementedTransmitterReturnsSentinel(t *testing.T) {
	t.Parallel()

	var z transmitter.NotImplementedTransmitter
	ctx := context.Background()

	t.Run("GetConfig", func(t *testing.T) {
		t.Parallel()
		cfg, err := z.GetConfig(ctx, "stream-1")
		if cfg != nil {
			t.Errorf("GetConfig returned non-nil config: %#v", cfg)
		}
		if !errors.Is(err, ssf.ErrNotImplemented) {
			t.Errorf("GetConfig error = %v, want errors.Is(err, ErrNotImplemented)", err)
		}
	})

	t.Run("ListConfig", func(t *testing.T) {
		t.Parallel()
		cfgs, next, err := z.ListConfig(ctx, "")
		if cfgs != nil {
			t.Errorf("ListConfig returned non-nil configs: %#v", cfgs)
		}
		if next != "" {
			t.Errorf("ListConfig returned non-empty nextToken: %q", next)
		}
		if !errors.Is(err, ssf.ErrNotImplemented) {
			t.Errorf("ListConfig error = %v, want errors.Is(err, ErrNotImplemented)", err)
		}
	})

	t.Run("CreateConfig", func(t *testing.T) {
		t.Parallel()
		cfg, err := z.CreateConfig(ctx, &ssf.StreamConfig{})
		if cfg != nil {
			t.Errorf("CreateConfig returned non-nil config: %#v", cfg)
		}
		if !errors.Is(err, ssf.ErrNotImplemented) {
			t.Errorf("CreateConfig error = %v, want errors.Is(err, ErrNotImplemented)", err)
		}
	})

	t.Run("UpdateConfig", func(t *testing.T) {
		t.Parallel()
		cfg, err := z.UpdateConfig(ctx, &ssf.StreamConfig{StreamID: "s"})
		if cfg != nil {
			t.Errorf("UpdateConfig returned non-nil config: %#v", cfg)
		}
		if !errors.Is(err, ssf.ErrNotImplemented) {
			t.Errorf("UpdateConfig error = %v, want errors.Is(err, ErrNotImplemented)", err)
		}
	})

	t.Run("DeleteConfig", func(t *testing.T) {
		t.Parallel()
		if err := z.DeleteConfig(ctx, "s"); !errors.Is(err, ssf.ErrNotImplemented) {
			t.Errorf("DeleteConfig error = %v, want errors.Is(err, ErrNotImplemented)", err)
		}
	})

	t.Run("GetStatus", func(t *testing.T) {
		t.Parallel()
		got, err := z.GetStatus(ctx, "s", nil)
		if got != nil {
			t.Errorf("GetStatus returned non-nil response: %#v", got)
		}
		if !errors.Is(err, ssf.ErrNotImplemented) {
			t.Errorf("GetStatus error = %v, want errors.Is(err, ErrNotImplemented)", err)
		}
	})

	t.Run("GetStatusWithSubject", func(t *testing.T) {
		t.Parallel()
		// A non-nil subject argument exercises the same code path; the
		// not-implemented sentinel should be invariant under input.
		got, err := z.GetStatus(ctx, "s", json.RawMessage(`{"format":"opaque","id":"x"}`))
		if got != nil {
			t.Errorf("GetStatus returned non-nil response: %#v", got)
		}
		if !errors.Is(err, ssf.ErrNotImplemented) {
			t.Errorf("GetStatus error = %v, want errors.Is(err, ErrNotImplemented)", err)
		}
	})

	t.Run("UpdateStatus", func(t *testing.T) {
		t.Parallel()
		got, err := z.UpdateStatus(ctx, "s", &ssf.StatusUpdateRequest{Status: ssf.StreamStatusPaused})
		if got != nil {
			t.Errorf("UpdateStatus returned non-nil response: %#v", got)
		}
		if !errors.Is(err, ssf.ErrNotImplemented) {
			t.Errorf("UpdateStatus error = %v, want errors.Is(err, ErrNotImplemented)", err)
		}
	})

	t.Run("AddSubject", func(t *testing.T) {
		t.Parallel()
		err := z.AddSubject(ctx, "s", &ssf.AddSubjectRequest{})
		if !errors.Is(err, ssf.ErrNotImplemented) {
			t.Errorf("AddSubject error = %v, want errors.Is(err, ErrNotImplemented)", err)
		}
	})

	t.Run("RemoveSubject", func(t *testing.T) {
		t.Parallel()
		err := z.RemoveSubject(ctx, "s", &ssf.RemoveSubjectRequest{})
		if !errors.Is(err, ssf.ErrNotImplemented) {
			t.Errorf("RemoveSubject error = %v, want errors.Is(err, ErrNotImplemented)", err)
		}
	})

	t.Run("Verify", func(t *testing.T) {
		t.Parallel()
		err := z.Verify(ctx, "s", &ssf.VerificationRequest{})
		if !errors.Is(err, ssf.ErrNotImplemented) {
			t.Errorf("Verify error = %v, want errors.Is(err, ErrNotImplemented)", err)
		}
	})

	t.Run("PollEvents", func(t *testing.T) {
		t.Parallel()
		got, err := z.PollEvents(ctx, "s", &ssf.PollRequest{})
		if got != nil {
			t.Errorf("PollEvents returned non-nil response: %#v", got)
		}
		if !errors.Is(err, ssf.ErrNotImplemented) {
			t.Errorf("PollEvents error = %v, want errors.Is(err, ErrNotImplemented)", err)
		}
	})
}

// partialTransmitter exercises the embed-and-override pattern: it
// embeds NotImplementedTransmitter and overrides only GetConfig.
// Every other method must still return ssf.ErrNotImplemented via
// the embedded zero value.
type partialTransmitter struct {
	transmitter.NotImplementedTransmitter

	getCfg *ssf.StreamConfig
}

func (p *partialTransmitter) GetConfig(_ context.Context, _ string) (*ssf.StreamConfig, error) {
	return p.getCfg, nil
}

// TestEmbedAndOverridePattern asserts the documented integration
// shape: a consumer embeds NotImplementedTransmitter, overrides the
// methods they support, and the rest fall through to the
// not-implemented sentinel. The compile-time assertion that
// *partialTransmitter satisfies Transmitter doubles as documentation
// of the contract.
func TestEmbedAndOverridePattern(t *testing.T) {
	t.Parallel()

	want := &ssf.StreamConfig{StreamID: "stream-7"}
	var tx transmitter.Transmitter = &partialTransmitter{getCfg: want}

	// Override hits.
	got, err := tx.GetConfig(context.Background(), "stream-7")
	if err != nil {
		t.Fatalf("GetConfig on partial: unexpected error %v", err)
	}
	if got != want {
		t.Errorf("GetConfig returned %#v, want %#v", got, want)
	}

	// Embedded fall-through still reports not implemented.
	if _, err := tx.CreateConfig(context.Background(), &ssf.StreamConfig{}); !errors.Is(err, ssf.ErrNotImplemented) {
		t.Errorf("CreateConfig on partial: error = %v, want errors.Is(err, ErrNotImplemented)", err)
	}
	if err := tx.DeleteConfig(context.Background(), "stream-7"); !errors.Is(err, ssf.ErrNotImplemented) {
		t.Errorf("DeleteConfig on partial: error = %v, want errors.Is(err, ErrNotImplemented)", err)
	}
}

// Compile-time assertion mirroring the one inside the package — if
// the Transmitter interface drifts, this catches it at the test
// boundary too.
var _ transmitter.Transmitter = (*partialTransmitter)(nil)
