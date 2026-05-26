#!/bin/sh
# Conformance / interop test runner. Owned by the `interop` CI job.
#
# Runs the library-vs-library loopback harness under internal/interop,
# which exercises every cell of the Transmitter+push, Transmitter+poll,
# Receiver+push, Receiver+poll matrix by wiring the in-tree transmitter
# package and receiver package together over httptest servers. The
# `interop` build tag gates the harness so `go test ./...` without it
# stays hermetic — the matching CI `test` job runs without the tag, this
# `interop` job runs with it.
#
# Posture matches the `test` job: -race for data-race detection,
# -shuffle=on to flush order dependencies, -count=1 to bypass the
# test cache. Live OpenID SSF working-group interop events run on
# their own cadence and are out of scope for every-build CI; the
# loopback harness here is the always-on conformance signal.
set -eu

echo "==> go test -tags interop -race -shuffle=on -count=1 ./internal/interop/..."
go test -tags interop -race -shuffle=on -count=1 ./internal/interop/...
echo "OK: interop tests passed."
