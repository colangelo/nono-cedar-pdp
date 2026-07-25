---
type: design
title: "ADR-001: Rust, embedding cedar-policy; nono as dev-dependency only"
description: "Why the PDP is Rust with the cedar-policy crate embedded in-process, and why the nono crate is a dev-dependency guarding wire drift rather than a runtime dependency."
tags: [adr, rust, cedar, dependencies]
timestamp: 2026-07-25
---

# ADR-001: Rust, embedding the `cedar-policy` crate; `nono` as dev-dependency only

**Date:** 2026-07-25 · **Status:** Accepted

## Context

The PDP answers nono's `WebhookApproval` callbacks (see spec §2). Candidate stacks:
Rust + `cedar-policy` (reference engine, 4.11.x), Go + `cedar-go` (v1.8.0, trails
the reference), Python + `cedarpy` (fastest prototype), or wrapping Permit.io's
`cedar-agent` (dormant since Oct 2025).

## Decision

1. **Rust, embedding `cedar-policy` 4.x directly.**
2. **Do not depend on the `nono` crate at runtime.** Mirror the wire types in
   `wire.rs`; pin `nono` as a **dev-dependency** for a serde round-trip
   conformance test.

## Rationale

- The Rust crate is the reference implementation and gets the differentiating
  features first: schema validation, entity slicing, partial evaluation, and
  `cedar-policy-symcc` policy analysis. `cedar-go` trails on all of these.
- **Upstreamability is the prize.** A native `CedarApproval` implementing nono's
  `ApprovalBackend` trait must be Rust; this repo's `wire`/`query`/`cedar` modules
  port into that PR nearly unchanged. Go/Python would mean a rewrite at exactly the
  moment we'd want to move fast.
- The workload fits: long-lived daemon, one hot path, µs evaluation, in-process
  policy set, no FFI or second runtime. Nearest prior art in this niche
  (Sondera coding-agent-hooks) is also Rust.
- The velocity Go/Python would buy is on the HTTP plumbing — the trivial part.
- Runtime-depending on `nono` would pull sigstore verification, keyring/Keychain,
  x509 parsing, and a `typify` build script into a fail-closed security daemon for
  the sake of four structs. The conformance test provides the same drift protection
  (upstream shape change → CI failure on version bump) without the surface.
- `cedar-agent` is a full policy/data-store REST server, dormant, and shaped wrong
  for a single fail-closed decide endpoint; we borrow its API shape as reference
  only.

## Consequences

- Slower first commit than Go/Python; MSRV tracks `cedar-policy` (Rust 1.89+).
- Wire structs are hand-maintained, guarded by the conformance test against the
  pinned upstream version; the pin must be bumped deliberately on nono releases.
- If upstream ships a first-party `PolicyInput` contract (#879), we adopt it
  verbatim as the primary wire format and keep the webhook shape as a compat path.
