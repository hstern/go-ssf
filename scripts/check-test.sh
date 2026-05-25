#!/bin/sh
# Race-enabled, shuffled test suite. Owned by the `test` CI job.
#
# -race: catches data races. Mandatory for CI on any concurrent or HTTP-handling code.
# -shuffle=on: randomizes test order so inter-test ordering dependencies surface in CI rather
#              than as flaky local repros.
# -count=1: defeats Go's test cache. CI runs every test every time — caching hides regressions
#           when only test files change but cached output is reused.
#
# `go test ./...` walks the entire module: packages come and go as the wire-types / codec /
# transmitter / receiver / client / interop surfaces grow.
set -eu

echo "==> go test -race -shuffle=on -count=1 ./..."
go test -race -shuffle=on -count=1 ./...
echo "OK: tests passed."
