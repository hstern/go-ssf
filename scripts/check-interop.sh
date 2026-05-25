#!/bin/sh
# Conformance / interop test runner. Owned by the `interop` CI job.
#
# In phase 1 this is a stub — the matrix of Transmitter+push, Transmitter+poll,
# Receiver+push, and Receiver+poll cells against the OpenID Shared Signals
# Framework interop harness lands in phase 7. Until then the script exits 0
# with a marker line, so a regression in the workflow wiring (missing file,
# bad permissions, broken interpreter) is still visible in the job log.
#
# When the real driver lands, this script switches to:
#   go test -tags interop -race -shuffle=on -count=1 ./internal/interop/...
# matching the `-race -shuffle=on -count=1` posture of the `test` job. The
# `interop` build tag gates the network-dependent tests so a `go test ./...`
# without it stays hermetic.
set -eu

echo "==> interop stub (phase 1 — real harness lands in phase 7)"
echo "OK: interop stub passed."
