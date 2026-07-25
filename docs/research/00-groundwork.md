---
type: reference
title: "nono-cedar-pdp — groundwork research"
description: "Pre-design pass: the PEP/PDP thesis, the initial landscape scan, nono's upstream issue trail, and the discovery that the shipped WebhookApproval backend is already the integration seam."
tags: [research, nono, cedar, landscape]
timestamp: 2026-07-25
---

# nono-cedar-pdp — Groundwork Research

*Date: 2026-07-25. Compiled from web research and inspection of the upstream repo (nolabs-ai/nono @ main, shallow clone).*

## 1. Concept

Combine two capability/policy systems that sit at different layers of the same problem:

- **nono** = Policy Enforcement Point (PEP). Kernel-enforced sandboxing for AI agents via Landlock (Linux) and Seatbelt (macOS). Once applied, unauthorized operations are structurally impossible. Its broker can launch delegated tools (git, gh, kubectl, ...) in isolated child sandboxes with separate policies, credentials (credential proxy / phantom tokens), and L7 network filtering.
- **Cedar** = Policy Decision Point (PDP). Open-source authorization policy language + evaluation engine (Rust, CNCF). Purpose-built for RBAC/ABAC, human-readable, machine-analyzable (automated reasoning / SMT-based policy analysis), deny-by-default with forbid-wins semantics.

**Thesis:** the kernel layer (capabilities computed once at sandbox apply-time) gains little from Cedar's per-request model — but nono's L7 broker/approval path is exactly Cedar's shape: `permit(principal Agent, action "gh:createPR", resource Repo::"org/x") when {...}`.

## 2. Landscape findings (initial pass — deeper survey to follow)

- The macOS-local sandbox space is crowded but **Cedar-free**. Container-free OS-primitive tools dominate every recent entrant: anthropic-sandbox-runtime (srt — Seatbelt profiles on macOS, bubblewrap on Linux, HTTP/SOCKS5 proxy for network policy; the layer behind Claude Code's `/sandbox`), nono, fence, landrun, agent-seatbelt, ai-jail, yolobox, etc. All use bespoke config formats (JSON settings, TOML profiles, SBPL). None embed Cedar or OPA as their policy language.
- **The Cedar-for-agents pattern already exists one layer up, hosted:** AWS AgentCore Policy (GA March 2026) evaluates every agent tool call against Cedar policies at the AgentCore Gateway before execution, using Cedar Analysis at authoring time. Validates the architecture — but it's a managed AWS service, not self-hostable, and governs tool/MCP calls rather than kernel capabilities.
- Closest self-hostable analog: **Cedar for Kubernetes** (authz + admission), plus assorted MCP gateways experimenting with OPA/Rego. Nothing OSS occupies the intersection "local kernel-enforced sandbox + standard analyzable policy language".

**Gap confirmed:** a local, self-hostable sandbox whose broker speaks Cedar does not exist today.

## 3. Upstream (nono) findings

Repo: `nolabs-ai/nono` (migrated from `lukehinds/nono`). Apache-2.0, ~3.1k stars, default branch `main` (100+ other branches are feature/fix/dependabot — irrelevant for forking). Milestone "Release 1.0" (due 2026-07-01) fully closed.

### Issue #879 — "Add policy engine interoperability contract" ⭐

- Authored by **lukehinds (maintainer)** himself. Labeled enhancement, milestoned Release 1.0.
- Proposes: shared `PolicyInput` / `PolicyDecision` JSON schemas; a **fail-closed adapter protocol** so external policy systems participate in evaluation; an OPA/Rego proof of concept; SDK helpers for nono-py / nono-go / nono-ts.
- **Explicitly names Cedar** as a candidate engine ("Cedar-style authorization rules... map to principals, actions, resources, and context").
- Core boundary: external engines may propose/approve permissions, but **nono retains validation, canonicalization, and final OS enforcement**.
- Status: closed as *completed* on 2026-07-21 — but **zero comments, no linked PR/commit, and no interop/OPA/Cedar code exists in the tree or SDK repos**. Unclear whether the webhook approval backend is considered its realization or whether the contract is still coming.
- ➡️ **Action item: comment on #879 asking what "completed" means before investing in a schema.**

### Related issues

- #436 (closed, May 2026): approval model leveraging OPA/Rego — likely "resolved" by the generic webhook backend.
- #349 → #446: staged "capability-oriented" policy roadmap (composable policy, subtractive filesystem grants, canonical naming).
- #554 (closed): HTTP request attribute filtering (path, method, headers, query, body) in network policy — the L7 hooks a PDP decision can key on.
- #1500 (open): route unmatched proxy destinations through ApprovalBackend.
- #1345 (open): composable/reusable command-policy fragments.

### The integration point already shipped: `ApprovalBackend`

- Trait: `crates/nono/src/supervisor/mod.rs` → `pub trait ApprovalBackend: Send + Sync`.
- Implementations found: `TerminalApproval`, `NamedTerminalApproval`, **`WebhookApproval`**, `ChainApproval` (crates/nono-cli/src/approval_runtime.rs), plus an `ApprovalBackendRegistry` in nono-proxy.
- `WebhookApproval` contract (from source):
  - POSTs JSON `{ "backend": <name>, "request": <ApprovalRequest> }` to a configured URL; `Content-Type: application/json`; `User-Agent: nono-cli/<version>`; configurable `timeout_secs` (default 60); platform-verified TLS.
  - Response: either a serialized `ApprovalDecision`, or `{ "decision": "...", "reason": "..." }` where decision ∈ grant/granted/approve/approved/allow/allowed | deny/denied/reject/rejected/block/blocked | timeout/timed_out.
  - **Fail-closed:** non-2xx status → Denied; unknown decision string → error; response size capped.
- `command_policies` supports `PolicyDecisionConfig::RoutedApproval { decision, backend, timeout_secs }` → decisions routable to a named backend. Default decision is **Deny**.

**Consequence:** a Cedar PDP can integrate with stock nono TODAY as a webhook approval backend. No fork required for v1.

## 4. Decided approach

1. Standalone repo (this one) — **not** a fork. Implement the PDP in **Rust** (see ADR-001, TBD) using the `cedar-policy` crate (reference implementation; same language as nono → future upstreamability as a native `CedarApproval` backend).
2. v1 = webhook PDP service: receive `ApprovalRequest` → map to Cedar principal/action/resource/context → evaluate → `{decision, reason}`. Fail-closed by design on both sides.
3. Commit the deep landscape survey as `docs/research/01-landscape.md`.
4. Engage upstream on #879; align our schema with `PolicyInput`/`PolicyDecision` if the contract is still planned.
5. Fork nono only when there's a concrete upstream PR to make (native backend or contract implementation).

## 5. Open questions

- Real meaning of #879 "completed"; whether a `PolicyInput` schema will land upstream.
- Exact shape of `ApprovalRequest` (which attributes are available for command vs. network vs. credential approvals) — extract from source next.
- Entity model design: what are principals (agent session? profile? tool?), resources (paths, hosts, API routes, credentials), and context (cwd, tty, time, parent chain)?
- Policy distribution: local files first; later possibly nono registry profiles compiled from Cedar, or a central store.
- Latency budget: approval sits in the broker hot path — Cedar evals are sub-ms, HTTP hop dominates; consider Unix socket transport.

## 6. Sources

- https://github.com/nolabs-ai/nono (+ issues #879, #436, #446, #349, #554, #1500, #1345)
- https://docs.cedarpolicy.com / https://github.com/cedar-policy/cedar
- https://github.com/anthropics/sandbox-runtime (srt)
- https://github.com/webcoyote/awesome-AI-sandbox (landscape list)
- https://rywalker.com/research/local-agent-sandboxes (comparison, March 2026)
- AWS: "Why Policy in Amazon Bedrock AgentCore chose Cedar for securing agentic workflows" (May 2026); "Enforce least-privilege authorization in multi-agent AI chains using Cedar" (July 2026)
- https://github.com/cedar-policy/cedar-go — official Go implementation (evaluated, not chosen)
