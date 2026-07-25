# nono-cedar-pdp — Landscape: OSS Self-Hostable macOS Agent Sandboxes and Policy-Engine Integration Points

**Document:** docs/research/01-landscape.md · **Date:** 2026-07-25 · **Status:** Research draft

## TL;DR

- **No OSS, self-hostable, macOS-local agent sandbox embeds Cedar (or OPA) natively today.** nono remains the best primary integration target because its `WebhookApproval` backend is a ready-made "external PDP decides, sandbox enforces" hook; the strongest *secondary* targets are Anthropic sandbox-runtime, Agent Safehouse/sandbox-shell (Seatbelt), and cco/yoloAI (multi-backend launchers) — all of which currently lack any external decision callback and would need one added.
- **Do not build a Cedar evaluation server from scratch.** Reuse the `cedar-policy` Rust crate (v4.x, a CNCF Sandbox project accepted October 8, 2025) directly inside the PDP daemon; treat Permit.io's `cedar-agent` and Stacklok ToolHive's Cedar authorizer as reference prior art rather than dependencies. The clearest architectural precedent is Policy in Amazon Bedrock AgentCore (Cedar-at-the-gateway, GA March 3, 2026) — validated but not self-hostable.
- **The nono issue #879 premise could not be independently verified by the research pass.** Treat the PolicyInput/PolicyDecision schemas and fail-closed adapter contract as a design target to confirm upstream, not as an established, code-linked spec. Align nono-cedar-pdp's JSON contract with ToolHive's PORC (Principal-Operation-Resource-Context) HTTP-PDP model, which is the most mature open contract of this shape.

> **Note (local verification, 2026-07-25):** issue #879 *was* confirmed to exist by direct GitHub API query during the groundwork pass (see `00-groundwork.md`) — authored by lukehinds, labeled `enhancement`, milestoned "Release 1.0", closed as completed 2026-07-21 with zero comments and no linked PR or commit. The deep-research pass below could not corroborate it through public search, which is consistent with a low-visibility, uncommented issue. The substantive caveat still stands: **no implementing code exists**, so the schema is a direction, not a spec.

## Key Findings

1. **The macOS-local sandbox field is a consolidating "gold rush."** The wincent "Ask HN: The new wave of AI agent sandboxes?" thread cataloged roughly 27 tools launched within a year; the surviving macOS-native tools cluster on Apple's Seatbelt/`sandbox-exec` primitive, with a smaller VM tier (Tart/Lima/Apple Virtualization) and a microVM tier (microsandbox/libkrun).
2. **Almost none expose an external policy hook.** The near-universal pattern is *static, declarative, local config* (Seatbelt profiles or JSON allow-lists) evaluated in-process. nono is the exception: its `ApprovalBackend` trait with Terminal/Webhook/Chain implementations is a genuine request/response decision callback that an external PDP can answer.
3. **Cedar is winning agent tool-call authorization, but only in the MCP-gateway/cloud tier — not the local-sandbox tier.** ToolHive (Cedar), IBM ContextForge (Cedar/OPA/RBAC), AgentCore Policy (Cedar), Sondera coding-agent-hooks (Cedar), and ScopeBlind (Cedar) all decide-externally/enforce-at-a-choke-point. This is exactly the pattern nono-cedar-pdp wants to bring to a kernel-enforced local sandbox.
4. **Standalone OSS Cedar PDP daemons already exist** (Permit.io `cedar-agent`, the `cedar-local-agent` cache library, various TinyTodo demos), but they are HTTP policy/data-store servers, not tuned for nono's approval-webhook contract. Building a thin Rust PDP over the `cedar-policy` crate is lower-risk than wrapping `cedar-agent`, which has seen no release since October 2025.

## Details

### Task 1 — Landscape of OSS self-hostable macOS agent sandboxes

The dominant macOS isolation primitive is **Apple Seatbelt / `sandbox-exec`** (Apple's TrustedBSD-based MAC framework, present since macOS 10.5), used directly by Codex CLI and Gemini CLI and underneath Anthropic's sandbox-runtime. A second tier uses **VMs** (Tart, Lima, Apple Virtualization/`container`), and a third uses **microVMs** (microsandbox on libkrun, which uses Hypervisor.framework on Apple Silicon).

Comparison table (macOS mechanism, license, policy format, external policy hook):

| Project | macOS mechanism | License | Policy/config format | External policy hook for a PDP? | Maturity |
|---|---|---|---|---|---|
| **nono** (nolabs-ai) | Seatbelt (Landlock on Linux; WSL2 on Windows) | Apache-2.0 | Composable JSON profiles; `command_policies`, L7 endpoint policy, `on_unknown: require_approval` | **Yes** — `ApprovalBackend` trait: Terminal / **Webhook** (POST JSON ApprovalRequest → `{decision, reason}`, fail-closed) / Chain | Very active, pre-1.0; crates.io v0.68.0, 84 versions, MSRV Rust 1.95.0, ~94k all-time downloads; created Jan 31, 2026 |
| **Anthropic sandbox-runtime (srt)** | Seatbelt (+ bubblewrap on Linux) + network proxy | Open source (Anthropic) | OS-level FS/network restriction config; read-denylist | No external decision callback; no command deny rules | ~4,388 stars; "Beta Research Preview," slow PR cadence |
| **Agent Safehouse** (eugene1g) | Seatbelt (deny-first profile) | Open source | Deny-first Seatbelt profile system | No | Niche/active |
| **sandbox-shell** (agentic-dev3o) | Seatbelt shell wrapper | Open source | Deny-by-default FS profile | No | Small |
| **SandVault** (webcoyote) | Separate macOS user account + `sandbox-exec` | Open source | User-account + Seatbelt hardening; iOS-sim bridge allowlists | No (allowlist bridge only) | Active |
| **vibebox** (robcholz) | Seatbelt (fast local) | Open source | Local profile | No | Small/active |
| **yolobox** (finbarr) | Docker (also Podman/Apple Containers) | Open source | `no_network` all-or-nothing; no domain allowlists | No | Healthy; v0.18.4, 603 stars |
| **cco** (nikvdp) | Launcher over a local backend (Seatbelt/etc.) | Open source | Delegates to chosen backend | No (delegator) | Small |
| **yoloAI** (kstenerud) | Multi-backend: Seatbelt / Tart / Docker | Open source | Review/apply workflow | No (review/apply UX, not a PDP) | Small |
| **nixcage / sandnix** | `sandbox-exec` on macOS (Landlock on Linux) | Open source | Nix module wrapping | No | Small |
| **Pent** (valentinradu) | Native OS process sandbox | Open source | Config for untrusted commands | No | Small |
| **ClodPod** (webcoyote) | macOS VM (maps host projects in) | Open source | VM image config | No | Active |
| **Chamber** (cirruslabs) | Tart-based ephemeral macOS VM | Open source | VM config | No | Active |
| **lima-devbox** (recodelabs) | Lima VM | Open source | VM config | No | Small |
| **microsandbox** (superradcompany) | libkrun microVM (Apple Silicon HVF) | Apache-2.0 | Sandboxfile; programmable networking; secret injection; MCP server | No external allow/deny PDP callback (MCP tool surface only) | Pre-1.0, ~6.5k stars, active |
| **fence** (use-tusk) | (Linux-focused; native command sandbox) | Open source | Command deny rules, SSH filtering | No | Active |
| **ai-jail / other Seatbelt wrappers** | Seatbelt-based | Varies | Local profile | No | Experimental |

Key observations:

- **nono is architecturally unique** in this list: kernel-enforced (Seatbelt on macOS, Landlock on Linux, irreversible privilege drop), an L7 broker with credential proxying and per-tool child sandboxes, and — critically — an `ApprovalBackend` abstraction that already includes a Webhook implementation. That webhook is the exact seam a Cedar PDP plugs into.
- **Everyone else enforces static local policy in-process.** Seatbelt-profile tools (Agent Safehouse, sandbox-shell, SandVault, vibebox) compile a profile once and let the kernel enforce it; there is no runtime "ask an external decider" path. To integrate Cedar there, you would have to *add* a decision callback (e.g., a PreToolUse-style hook), which is net-new engineering in each project.
- **microsandbox** keeps secrets on-host and exposes an MCP server, but its isolation is VM-level and its "policy" is network allowlisting + secret substitution, not an allow/deny authorization callback.

### Task 2 — Prior art: "external policy engine decides, sandbox/gateway enforces" in self-hostable OSS

This pattern is well-established one tier up, at the **MCP gateway / tool-call firewall** layer:

- **Stacklok ToolHive** (Go, Apache-2.0, ~1.8k stars): runs MCP servers in containers and enforces **Cedar** on every tool call with a default-deny, forbid-wins model. Most importantly for nono-cedar-pdp, ToolHive defines an **HTTP PDP authorizer (`httpv1`)** that maps MCP requests to a **PORC (Principal-Operation-Resource-Context)** JSON model for *external* policy decision points — per Stacklok's authorization docs, a general-purpose authorizer intended to work with any PDP server implementing the PORC decision endpoint, designed to run the PDP as a sidecar service. Fields look like `operation: "mcp:tool:call"`, `resource: "mrn:mcp:<server>:tool:weather"`, with claim-mapper options (`mpe` for Manetu PolicyEngine, `standard` OIDC). This is the single most relevant open contract for what nono-cedar-pdp is building.
- **IBM ContextForge / mcp-context-forge** (Python, Apache-2.0, ~3.7k stars, v1.0.1 GA May 13, 2026): a unified PDP with a pluggable interface across **Cedar, OPA/Rego, native RBAC, and MAC**. Issue #2223 states the goal directly — a unified Policy Decision Point providing a single interface for all policy engines — with a `combination_mode` of `all_must_allow | any_allow | first_match` (shipped in v1.0.0-RC1). This is direct, working evidence of the multi-engine interoperability contract nono #879 proposes.
- **Sondera coding-agent-hooks** (Rust, MIT, ~207 stars): Rust hook binaries with **Cedar** policies that intercept shell/file/web actions across Claude Code, Cursor, Copilot, and Gemini CLI, normalizing tool names to a common action type — the closest analog to a local, cross-agent Cedar enforcement layer.
- **ScopeBlind protect-mcp** (TypeScript, MIT): Cedar enforcement plus Ed25519-signed decision receipts; explicitly supports delegating to OPA, Cerbos, or any HTTP policy endpoint (external-PDP model).
- **Permit.io** (`cedar-agent`, `permit-fastmcp`, MCP Gateway): OPA+OPAL+Cedar; hosted gateway plus OSS FastMCP middleware.
- **Cerbos** (Go, Apache-2.0, ~4.4k stars): standalone YAML-policy PDP with an MCP authorization demo (register tools, check per call, toggle availability).
- **Strata Maverics**: embedded OPA on MCP tool calls with RFC 8693 token exchange and 5-second task-scoped tokens (commercial).
- **Red Hat MCP Gateway (Kuadrant/Envoy)**: OPA extracting tool permissions from JWT claims.

Takeaway: the "external engine decides, choke point enforces" pattern is proven and Cedar-dominant at the gateway tier. What is **missing from the ecosystem** — and what nono-cedar-pdp uniquely fills — is that same pattern wired to a **kernel-enforced local sandbox** rather than a network gateway.

### Task 3 — Cedar tooling state

- **`cedar-policy` Rust crate:** current 4.x series (workspace version around 4.10–4.11, MSRV Rust 1.89), Apache-2.0. Ships the authorizer, schema-based **validator**, policy **templates**, **partial evaluation** (`partial-eval` feature, experimental), **entity slicing**, protobuf support, WASM bindings, and a `cedar-policy-cli` binary supporting validation/authorization/formatting. A separate `cedar-policy-symcc` symbolic compiler enables formal **policy analysis** (`analyze` feature). This is production-grade and is the right foundation to embed directly.
- **CNCF status:** Cedar was **accepted to CNCF as a Sandbox project on October 8, 2025**; already adopted by Cloudflare, MongoDB, StrongDM, and Cloudinary. The `cedar-policy` GitHub org hosts cedar, cedar-docs, cedar-local-agent, cedar-for-agents, and Kubernetes integrations. This gives nono-cedar-pdp a vendor-neutral, foundation-backed dependency.
- **Existing standalone Cedar PDP servers:**
  - **Permit.io `cedar-agent`** (Rust, ~188–195 stars, ~19 forks): HTTP server managing a policy store + data store, `is_authorized` decision API, config via env/CLI (default port 8180). **Last updated ~October 16, 2025** — effectively dormant. Usable as reference, risky as a dependency.
  - **`cedar-local-agent`** (cedar-policy org): a configurable cache for Cedar policies/entities — a library, not a server.
  - **`cedar-for-agents`** (cedar-policy org, Rust, ~25 stars): official AWS Cedar+MCP tooling — `mcp-tools-sdk`, a Cedar-schema-generator from MCP tool descriptions (v0.5.0), and a TS analysis MCP server. Focused on *analysis/schema*, not enforcement.
  - Various `cedar-authorization-service` / TinyTodo demos (explicitly "not for production").

**Recommendation on build-vs-reuse:** build the nono-cedar-pdp daemon as a thin Rust service embedding the `cedar-policy` crate. Reasons: (1) nono's contract is a *single* approval webhook returning `{decision, reason}`, far simpler than cedar-agent's full policy/data-store REST surface; (2) cedar-agent is dormant; (3) embedding the crate lets you use validation, entity slicing and partial evaluation directly, and keeps the whole path in Rust matching nono. Borrow cedar-agent's store/API shape and ToolHive's PORC field mapping as design references.

### Task 4 — nono upstream re-check and the status of issue #879

- **Verified:** `nolabs-ai/nono` is real, Apache-2.0, actively developed by maintainer **Luke Hinds (@lukehinds)** (creator of Sigstore, Stacklok co-founder, previously "Always Further," now nolabs). Per the nono README, the official registry namespace has moved from `always-further` to `nolabs-ai`. crates.io lists nono at **v0.68.0** (84 versions published, MSRV Rust 1.95.0, ~94k all-time downloads), created January 31, 2026. The README documents a composable JSON policy system with `command_policies`, credential proxy injection, L7 endpoint allow/deny (`{method, path}`), and `on_unknown: require_approval`. nolabs.ai's platform page describes routing sensitive actions for human vetting and a mediator that allows, denies, or escalates for approval the moment an action is attempted — i.e., the approval-escalation seam the PDP targets.
- **Verified upstream policy work:** issue **#446 "policy roadmap work – second phase"** (continuation of #349 "implement fully composable policy") describes evolving nono's *internal* capability/profile model (subtractive FS removals, capability provenance, runtime capability IR). Issue **#630** announces a Sigstore-signed community skill/policy registry. These confirm active investment in policy composability but concern nono's own engine, not an external-PDP contract.
- **On #879:** confirmed to exist via direct GitHub API query (groundwork pass) — proposing `PolicyInput`/`PolicyDecision` JSON schemas, a fail-closed adapter protocol, an OPA/Rego PoC, and SDK helpers, with Cedar explicitly named as a candidate engine and enforcement authority explicitly retained by nono. It was closed as *completed* on 2026-07-21 with **zero comments, no linked PR, and no implementing code anywhere in the tree or the SDK repos**. The deep-research pass could not corroborate it via public search, and flagged a conflation risk with IBM ContextForge #2223 and Microsoft's agent-governance-toolkit `PolicyDecision` abstraction — both of which describe near-identical multi-engine PDP abstractions. **Practical reading: #879 records an accepted design direction, not a shipped contract.** That is precisely the gap nono-cedar-pdp fills — and a reason to engage upstream before freezing a schema.

### Task 5 — Synthesis and recommendation

**Where a Cedar PDP fits best:** at nono's `ApprovalBackend` Webhook seam. nono already POSTs a JSON ApprovalRequest and expects `{decision, reason}` fail-closed; nono-cedar-pdp becomes the webhook target, translating the ApprovalRequest into a Cedar `Request` (principal = agent/tool identity, action = the attempted operation, resource = file/host/tool/endpoint, context = args/L7 metadata), evaluating against a Cedar `PolicySet` + entities, and returning allow/deny with the matching policy as the reason. nono enforces (kernel), Cedar decides — mirroring AgentCore's gateway model but self-hostable and kernel-backed.

**Best secondary integration targets** (in priority order): (1) **Anthropic sandbox-runtime** — highest reach, but needs a decision-callback added (it has none today); (2) **Agent Safehouse / sandbox-shell** — Seatbelt-native, would benefit from a PreToolUse-style hook; (3) **cco / yoloAI** — multi-backend launchers that could route decisions to the PDP for whichever backend they select; (4) **microsandbox** — via its MCP surface, though that is tool-call not syscall granularity. The cleaner medium-term play is to align the PDP's JSON contract with **ToolHive's PORC HTTP-PDP model** so a single nono-cedar-pdp can serve both nono and any PORC-speaking gateway.

## Recommendations

1. **Build the PDP in Rust embedding `cedar-policy` (v4.x).** Ship a single fail-closed HTTP endpoint matching nono's WebhookApproval contract (`POST` ApprovalRequest → `{decision, reason}`). Do not depend on Permit.io `cedar-agent` (dormant since Oct 2025); reuse only its API shape.
2. **Define the request mapping against two references:** nono's ApprovalRequest fields and ToolHive's PORC (Principal-Operation-Resource-Context) model. This maximizes reuse and future portability to MCP gateways. *Change trigger:* if nono ships its own PolicyInput schema upstream, adopt it verbatim as the primary contract and keep PORC as a compatibility shim.
3. **Engage upstream on #879.** Comment on the closed issue: ask what "completed" means, propose the PolicyInput/PolicyDecision schema concretely, and offer nono-cedar-pdp as the reference adapter. *Change trigger:* if upstream ships a first-party adapter or a competing schema, converge on it rather than fork.
4. **Lean on Cedar's differentiators:** schema validation at policy-authoring time, entity slicing for the small per-call entity sets nono produces, and `cedar-policy-symcc` analysis to detect conflicting/shadowed policies before deployment. These are things a Rego or ad-hoc engine cannot match and justify the Cedar choice.
5. **Stay fail-closed end-to-end.** nono already fails closed on webhook errors; ensure the PDP returns deny on any parse/validation error (Cedar's default-deny helps) and log every decision for a tamper-evident audit trail.
6. **Stage the rollout:** (a) nono webhook adapter + Cedar core; (b) a LOG_ONLY/dry-run mode mirroring AgentCore's rollout guidance to observe decisions without blocking; (c) PORC compatibility for gateways; (d) optional signed-receipt audit (ScopeBlind-style) if the audit requirement hardens.

## Caveats

- **#879's contents warrant a second look with authenticated access.** Existence and metadata are confirmed locally, but the deep-research pass could not corroborate it publicly and noted strong similarity to unrelated projects' PDP abstractions. Confirm the body directly on GitHub before treating any schema as canonical.
- **Fast-moving field.** The sandbox list is consolidating (several March-2026 tools already stalled); star counts, versions, and maintenance states cited here are point-in-time (mid-2026) and should be re-checked before commitments.
- **Some sources are AI-authored analyst reviews** (ChatForest, rywalker.com), useful for landscape shape and version signals but secondary to primary repos/docs; the primary GitHub/Stacklok/AWS/CNCF/crates.io sources are load-bearing for the specific claims.
- **AgentCore is validation, not a template to copy** — Policy in Amazon Bedrock AgentCore reached GA on March 3, 2026 (13 AWS Regions) but is a hosted AWS service; its security model was publicly critiqued (BeyondTrust/Sonrai findings on default network mode), reinforcing that "sandboxed" is a spectrum and that nono's kernel-enforcement + credential brokering is a genuine differentiator.
- **Secondary integration targets currently have no decision callback**; "integration" there means contributing a hook upstream, not just configuring an endpoint.

## Sources

- https://github.com/nolabs-ai/nono — README, issues #879, #446, #349, #630
- https://nono.sh/os-sandbox · https://nolabs.ai/
- https://crates.io/crates/nono
- https://docs.cedarpolicy.com · https://github.com/cedar-policy/cedar · https://crates.io/crates/cedar-policy
- https://www.cncf.io/projects/cedar/
- https://github.com/permitio/cedar-agent · https://github.com/cedar-policy/cedar-local-agent · https://github.com/cedar-policy/cedar-for-agents
- https://github.com/stacklok/toolhive — Cedar authorization, PORC HTTP PDP (`httpv1`)
- https://github.com/IBM/mcp-context-forge — issue #2223, unified PDP
- https://github.com/anthropics/sandbox-runtime
- https://github.com/webcoyote/awesome-AI-sandbox
- https://rywalker.com/research/local-agent-sandboxes · https://rywalker.com/research/nono
- https://chatforest.com/reviews/authorization-policy-engine-mcp-servers/
- AWS: "Why Policy in Amazon Bedrock AgentCore chose Cedar for securing agentic workflows"; "Enforce least-privilege authorization in multi-agent AI chains using Cedar"
