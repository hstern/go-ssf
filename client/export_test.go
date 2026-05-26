// Copyright 2026 The go-ssf Authors
// SPDX-License-Identifier: Apache-2.0

package client

import "time"

// SetCacheClock replaces the time source a [*ConfigCache] uses when
// computing entry expiry. It exists for tests that need to advance
// time without sleeping; production code should never call it. The
// _test.go suffix on the file keeps the symbol out of the public
// surface — the Go toolchain compiles export_test.go only for the
// test binary.
func SetCacheClock(c *ConfigCache, now func() time.Time) {
	c.now = now
}
