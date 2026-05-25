#!/bin/sh
# Go static checks: formatting, vet, and `go mod tidy` drift. Owned by the `static` CI job.
# Aggregates — runs ALL three and reports every failure, rather than stopping at the first, so
# one CI run surfaces everything that needs fixing (not just the earliest). Exits non-zero if
# any failed.
#
# go.sum handling: the library is pre-publication; go.sum may or may not exist depending on
# which phase has landed. The [ -f go.sum ] branch covers both cases — tidy drift is detected
# whether the file was already there or `go mod tidy` would create it.
set -u
fail=0

echo "==> gofmt -l (formatting)"
unformatted=$(gofmt -l .)
if [ -n "$unformatted" ]; then
  echo "ERROR: not gofmt-clean:" >&2
  echo "$unformatted" >&2
  fail=1
fi

echo "==> go vet"
go vet ./... || fail=1

echo "==> go mod tidy (no drift)"
cp go.mod /tmp/go.mod.pre
have_sum=0
[ -f go.sum ] && { cp go.sum /tmp/go.sum.pre; have_sum=1; }
go mod tidy
drift=0
cmp -s go.mod /tmp/go.mod.pre || drift=1
if [ "$have_sum" -eq 1 ]; then
  cmp -s go.sum /tmp/go.sum.pre || drift=1
elif [ -f go.sum ]; then
  drift=1  # tidy created go.sum where none existed
fi
if [ "$drift" -ne 0 ]; then
  echo "ERROR: 'go mod tidy' changed go.mod/go.sum — commit the tidy result." >&2
  diff -u /tmp/go.mod.pre go.mod || true
  if [ "$have_sum" -eq 1 ]; then
    diff -u /tmp/go.sum.pre go.sum || true
  fi
  cp /tmp/go.mod.pre go.mod
  [ "$have_sum" -eq 1 ] && cp /tmp/go.sum.pre go.sum
  fail=1
fi

[ "$fail" -eq 0 ] && echo "OK: gofmt + vet + tidy clean."
exit "$fail"
