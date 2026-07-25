## Why

nono enforces agent sandboxing at the kernel and can already escalate a blocked action to an external decider — its stock `WebhookApproval` backend POSTs an approval request and honours the answer, fail-closed. Nothing today answers that call with real policy: the only shipped decider is an interactive terminal prompt, so every escalation costs a human interruption and leaves no machine-checkable record of *why* an action was permitted. Meanwhile no OSS local sandbox speaks a standard, analyzable policy language (see `docs/research/01-landscape.md`).

This change builds the missing decider: a fail-closed Cedar Policy Decision Point that answers nono's webhook with `allow`/`deny` derived from declarative policy. nono keeps kernel enforcement; Cedar supplies decisions that are reviewable, testable, and machine-analyzable. Design, entity model and rollout are already settled in `docs/superpowers/specs/2026-07-25-nono-cedar-pdp-design.md` (decisions D1–D8) and ADR-001; this proposal scopes their implementation.

## What Changes

- **New daemon** `nono-cedar-pdp`: a loopback HTTP service exposing one decide endpoint (`POST /v1/approve`) plus `GET /healthz`, wired into nono via a stock `[approval_backends.<name>] type = "webhook"` entry — **no fork of nono, and no upstream changes required**.
- **Cedar schema for nono approvals** (`Nono` namespace): `Caller in Session in Agent` principal hierarchy, `Command` and `HttpEndpoint` resources, `launchCommand` and `httpRequest` actions (design D3). `args` is modelled as `Set<String>` so positional argument matching is unexpressible — upstream drops non-UTF-8 argv entries, which shifts positions and makes index-based policy unsound (D6).
- **Coverage limited to the two request variants that can actually reach a webhook**: `command` and `endpoint`. `capability` (filesystem) and `network` requests never arrive in nono 0.69, and any future variant is denied as unsupported rather than misinterpreted.
- **Policy directory** of `*.cedar` files, strict-validated against the embedded schema at startup and on every hot-reload. A failed reload keeps the last-good policy set (D7); an unloadable or empty directory refuses to start rather than running as a silent deny-everything daemon.
- **JSONL decision audit log**, one owner-readable line per decision, recording the matched policy ids so a deny is traceable to the file and rule that caused it.
- **Operator surface**: TOML config (loopback bind, policy dir, audit path, approval-backend-name → Cedar `Agent` map) and three CLI subcommands — `serve`, `validate` (CI-able policy check), `check <fixture>` (evaluate a saved payload without running nono).
- **Rollout via nono's own `chain` backend** rather than a dry-run mode in the PDP: `mode = "any"` over `["cedar", "terminal"]` means Cedar denies then a human is prompted; `mode = "all"` requires both. No PDP code needed for either posture.

Fail-closed consequences are specified for every failure path: malformed body, unsupported variant, entity-construction failure, Cedar evaluation error, and unloadable policies all resolve to deny (or, for a broken PDP, a `503` that nono records as a denial with a distinguishable reason). No error path can produce `allow`.

## Capabilities

### New Capabilities

- `approval-webhook`: the nono-facing HTTP contract — envelope parsing for `command`/`endpoint` requests, the `{"decision":…}` response shape, the complete fail-closed status/deny matrix, health reporting, and the wire-conformance guarantee against the upstream `nono` crate.
- `cedar-policy-evaluation`: the Cedar schema and entity model, per-request entity slice construction, policy-directory loading with provenance-carrying policy ids, strict schema validation, hot-reload with last-good semantics, and decision/reason derivation from Cedar diagnostics.
- `decision-audit-log`: append-only JSONL record of every decision, its matched policies, and evaluation timing, with owner-only file permissions and the guarantee that a logging failure never alters a decision.
- `pdp-operations`: operator-facing configuration and CLI — config schema and strict parsing, approval-backend-name → `Agent` identity mapping, `serve`/`validate`/`check` subcommands, and the documented nono profile wiring including the `chain` rollout postures.

### Modified Capabilities

None. `openspec/specs/` is empty; this is the project's first capability set and no existing requirements change.

## Impact

- **New code**: Rust lib + bin (`src/{wire,query,adapter,cedar,decision,audit,server,watcher,config}.rs`), embedded `nono.cedarschema`, starter `policies/*.cedar`, `Justfile`, `examples/` nono profile.
- **Dependencies**: `cedar-policy` 4.11 embedded in-process (no separate policy server); `axum`/`tokio` for the loopback listener; `nono` 0.69 as a **dev-dependency only** — a runtime dependency would pull sigstore, x509 and Keychain code into a security daemon for four structs (ADR-001).
- **Upstream coupling**: pinned to nono 0.69's webhook shape. Drift is caught by a conformance test that round-trips upstream's own serialized types, so a version bump fails CI rather than silently misreading a decision.
- **Operator systems**: requires a nono profile with an approval backend pointing at the daemon; the daemon must be running before an intercepted command, or nono fails closed and blocks it.
- **Known security limitation** (accepted for v1, follow-up tracked): nono's webhook is unauthenticated in both directions, so a local process that binds the port first could answer `allow`. Mitigated by loopback-only binding; the fix is https-on-loopback with a locally-trusted certificate, which turns impersonation into a TLS failure that nono treats as a denial.
- **Out of scope**: filesystem `capability` arbitration (hardwired to nono's terminal backend upstream), PORC/ToolHive compatibility, signed decision receipts, launchd packaging, and any upstream PR — all recorded as follow-ups in the design spec §10.
