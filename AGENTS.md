# AGENTS.md

Guidance for AI coding agents (Claude Code, Cursor, Aider, Copilot
Workspace, etc.) working on `go-ssf`. Human contributors will get
more out of `CONTRIBUTING.md` once it exists; this file captures the
things that are easy for an agent to get wrong if it doesn't know them
up front.

## What this project is

`go-ssf` is a Go implementation of the
[OpenID Shared Signals Framework 1.0](https://openid.net/specs/openid-sharedsignals-framework-1_0.html)
— the wire protocol for transporting Security Event Tokens between an
event Transmitter and an event Receiver, over both push (RFC 8935) and
poll (RFC 8936) delivery. The library is **library-vendor-neutral**:
it implements the spec, nothing more. It provides:

- `http.Handler` constructors over a `Transmitter` interface
  (Transmitter role).
- A push-mode delivery driver and a Receiver-side `Sink` plus push
  `http.Handler` and a `Poller` for poll mode (Receiver role).
- HTTP client wrapping the Transmitter endpoints, used by Receivers
  to manage stream configuration.
- Full type surface for every spec-defined message.
- `/.well-known/ssf-configuration` metadata document support.

It does NOT provide CAEP or RISC event-payload schemas, an opinion
about how Transmitter and Receiver authenticate beyond what the
framework specifies, or a vendor-specific adapter. Those belong in
downstream consumers.

Spec version: **1.0 Final**, published 2026. Tracked in source as
`const SpecVersion = "1.0"`.

## Repository scope rules

These rules are absolute. They are not preferences; they're correctness
constraints for what lands in the repo.

1. **The library is the subject.** Code, comments, docs, commit
   messages, and CI artifacts describe what the library does for an
   anonymous Go developer who found it via a search engine. They do not
   describe what the maintainer is using it for, where it is being
   developed, who is tracking which task, or how it relates to anything
   outside this repository.
2. **No private infrastructure references.** No internal hostnames,
   internal Git hosts, internal issue trackers, internal documentation
   sites, or any URL pointing at non-public infrastructure. If you find
   yourself wanting to cite `*.someprivate.tld`, the answer is: don't.
3. **No private-tracker identifiers.** Ticket short-codes, project
   IDs, page UUIDs, board names from any private tracker — none of it
   in source, README, CHANGELOG, or commit messages. When public issue
   tracking exists (GitHub Issues), reference its public URL only.
4. **No interim hosting paths.** `go.mod` declares the eventual
   publication module path. The interim location of the repo during
   private development MUST NOT appear in `go.mod`, README, comments,
   or CI configuration.
5. **No references to sibling private libraries.** "Matches the
   pattern in [internal-library-X]" is fine framing in a private
   conversation but MUST NOT land in the repo. Public libraries
   (`go-jose`, `go-subjectid`, `golang.org/x/oauth2`) may be cited by
   name.

If you are unsure whether something is safe to write, default to
omitting it and ask. The cost of asking is low; the cost of leaking
context that can't be deleted from git history is high.

## Copyright header

Every Go source file gets exactly this two-line header, first thing,
before the `package` declaration:

```go
// Copyright 2026 The go-ssf Authors
// SPDX-License-Identifier: Apache-2.0
```

- `The go-ssf Authors` is the collective copyright holder; contributors
  are listed in git history.
- The SPDX tag is the machine-readable license reference; license
  detectors and SBOM tools read it. The full license text is in
  `LICENSE` at the repo root.
- Year is the first publication year (`2026`). Don't roll it forward
  annually — that produces noisy churn for no legal benefit.

The header applies to every `.go` file, including tests. `AGENTS.md`,
`README.md`, `CHANGELOG.md`, workflow YAML, and `Dockerfile` files do
NOT carry the header — they aren't source files and SPDX tags add
noise without benefit.

## Go conventions for this codebase

### Dependencies

Two non-test runtime dependencies:

- `github.com/hstern/go-subjectid` — RFC 9493 Subject Identifier
  types. The framework uses these throughout the subjects endpoint
  and verification event shapes; they belong in their own library so
  every spec that consumes subject identifiers can share one
  implementation.
- `github.com/go-jose/go-jose/v4` — JWS / SET signing and
  verification. Security Event Tokens are JWS-signed JSON payloads
  per RFC 8417; a hand-rolled JOSE implementation here would be the
  wrong call.

Nothing else. The library exposes interfaces (`StreamStore`,
`SETSigner`, `SETVerifier`, `AuthFunc`, `Sink`, `HTTPDoer`) and
consumers plug their own implementations.

Test-only dependencies (e.g. `github.com/stretchr/testify`) may be
added if a real need arises; keep them under `_test.go` files.

### Style

- `gofmt`, `go vet`, `staticcheck`, `golangci-lint` all run in CI and
  must pass.
- Receivers: short, lowercase, consistent within a type.
- Errors: lowercase sentence, no trailing punctuation, wrap with
  `%w` when adding context.
- Exported symbols have godoc comments. Short, link-rich. Name the
  spec section the symbol implements.
- Examples live in `_test.go` as `Example*` functions and render in
  godoc.

### Validation posture

Lenient on unmarshal, strict at the marshal boundary. The library
validates required fields when a message is being sent over the wire,
not when it is being received. Consumers who want stricter input
validation call the explicit `Validate(...)` helper for the relevant
message type.

### JSON / wire fidelity

- Open extension fields are `json.RawMessage`, NOT `map[string]any`.
  Reason: byte-stable round-trip; Go's map iteration order is
  randomized and Shared Signals Framework interop pins exact JSON
  bytes.
- `method` (Delivery) and `format` (Subject Identifier) are
  discriminator-first in marshal output. The spec does not mandate
  ordering, but every published example puts them first; the library
  matches for byte-stable interop fixtures.
- SET signing uses `typ: secevent+jwt` per RFC 8417 §2.2. Not `JWT`.
  Some verifiers strict-check this header.
- `alg: none` is forbidden on SETs per RFC 8417 §2.2. The library
  rejects it at both sign and verify boundaries.
- Unknown delivery methods parse into `UnknownDelivery{Method, Raw}`,
  not an error. The IANA delivery-method registry is the source of
  truth; the library's built-in methods are a snapshot, and forward
  compatibility is a hard requirement.

### Interfaces vs structs

- One `Transmitter` interface, nine methods, one per Transmitter
  endpoint. Implementations embed `NotImplementedTransmitter` (a
  zero-value type whose methods all return `ErrNotImplemented`) and
  override the methods they support — the "embed and override"
  pattern that mirrors `http.ServeMux` extension.
- One `Sink` interface, one method (`DeliverSET`), for the Receiver
  side. Push handler and `Poller` both call it; the receiver does not
  need to know which delivery mode produced the event.
- Transport is pluggable via an `HTTPDoer` interface (shape:
  `Do(*http.Request) (*http.Response, error)`). Server side ships
  `http.Handler` only; no framework adapters in the core library.

## Testing

- Table-driven tests for wire round-trips. Each spec-defined message
  has a round-trip test against the example payloads in Shared Signals
  Framework §7.
- `httptest.NewServer` for handler tests; `httptest.NewRecorder` is
  fine for unit tests that don't need a full server.
- `go test -race -shuffle=on ./...` is the CI test invocation.
- No network calls in unit tests by default. The interop tests are
  gated behind a build tag so they don't flake CI when the public
  reference harness is unreachable.

## Commit messages

- Imperative present tense ("add stream config marshaller", not
  "added").
- Reference public artifacts only — public RFC numbers, spec section
  numbers, public PRs / issues, public commit SHAs. Do not reference
  private trackers (see rule 3 above).
- One logical change per commit. The phased build plan is structured
  so each phase fits in one PR (or a small series).
- Detailed bodies: explain why this change exists, what was considered
  and rejected (if non-obvious), what is NOT changing (if a careless
  reader might think it is), and any known follow-ups. The reader who
  needs this commit message is reading it because git blame led them
  here.

## CI

GitHub Actions, two workflows:

- `.github/workflows/ci.yml` — pinned tool versions, fan-out parallel
  jobs (`static`, `test`, `lint`, `interop`). One CI run surfaces
  every failure at once, not just the first.
- `.github/workflows/vuln.yml` — separate, non-blocking, runs on
  `main` push and a daily cron. `govulncheck` against `./...`.

Required checks on every `pull_request`:

- `static`: `gofmt -l`, `go vet ./...`, `go mod tidy -diff`
- `test`: `go test -race -shuffle=on ./...`
- `lint`: `golangci-lint run ./...`
- `interop`: the Shared Signals Framework interop suite,
  Transmitter and Receiver sides, both push and poll cells. Stubbed
  in phase 1; live in phase 7.

## Branch protection

`main` is protected. Direct push is rejected; all changes land via
PR with the required CI checks above passing. Branch must be up to
date with `main` before merge. Phase 1 (repo bootstrap) is the only
exception — branch protection goes live after the phase 1 gate, once
CI is wired and green on the empty surface.

## When to ask vs when to proceed

- Bug fix, refactor, doc tweak, test addition for an existing feature:
  proceed. Reference the spec section that motivates the change in the
  commit message.
- New exported API surface, new dependency, change to an interface
  signature, anything that affects backwards compatibility: ask first.
  These are forever-decisions once the library is published.
- Anything that might cross the scope rules above (1–5): ask. The
  cost of a quick check is far less than the cost of force-pushing
  history after a leak.
