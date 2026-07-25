## Context

nono is a kernel-enforced sandbox for AI agents (Seatbelt on macOS, Landlock on Linux). When a sandboxed action needs escalation, it consults an `ApprovalBackend`; the shipped implementations are `TerminalApproval` (interactive prompt), `WebhookApproval` (POST to a URL, fail-closed), and `ChainApproval` (compose backends with `all`/`any`). The webhook backend is therefore an already-shipped seam for an external Policy Decision Point, with no upstream change required.

The full design, including everything verified by reading nono v0.69.0 source, lives in `docs/superpowers/specs/2026-07-25-nono-cedar-pdp-design.md`; the language and dependency choice is recorded in `docs/adr/ADR-001-rust-and-cedar-crate.md`; the ecosystem survey that establishes the gap is `docs/research/01-landscape.md`. This document summarises the architecture and the decisions that constrain implementation, and is not a substitute for those.

Constraints that come from upstream and cannot be negotiated in this change:

- Only `command` and `endpoint` approval requests reach a webhook backend. `network` requests are never constructed in nono's production code, and filesystem `capability` elevation is hardwired to the terminal backend in `supervised_runtime.rs`. Arbitrating file access requires an upstream PR.
- The payload carries no cwd, environment, timestamp, tty, or agent identity. Command requests give `command`, `args`, `caller`, `intercept_rule`; endpoint requests give `route_id`, `upstream`, `method`, `path`, `rule_label`. Both add `request_id`, `session_id`, `child_pid`, `reason`, and the envelope's `backend` name.
- `args` is lossy: nono builds it with `filter_map(|a| from_utf8(a).ok())`, so a non-UTF-8 argv entry is dropped entirely and the remaining positions shift.
- Endpoint requests hardcode `session_id: "proxy"` and `child_pid: 0`.
- Transport is `ureq` over an HTTP(S) URL with platform TLS verification. There is no Unix-socket option and no authentication in either direction.

## Goals / Non-Goals

**Goals:**

- Answer nono's approval webhook with Cedar-derived allow/deny decisions, fail-closed on every error path.
- Make the decision auditable: which policy, in which file, decided, and how long it took.
- Keep the policy-evaluation core free of HTTP concerns so it can be lifted into an upstream native `CedarApproval` backend later.
- Let policies be edited while an agent session is running, without a restart and without risk of a broken edit blocking the agent.
- Give the operator a safe rollout path from "observe" to "enforce" without building a dry-run mode.

**Non-Goals:**

- Arbitrating filesystem capability requests (upstream hardwires those to the terminal backend).
- Forking nono, or shipping any upstream change as part of this work.
- PORC / ToolHive gateway compatibility, signed decision receipts, launchd packaging, https-on-loopback hardening — all recorded as follow-ups in the design spec §10.
- A policy authoring UI, policy distribution, or a central policy store. Policies are local files.

## Decisions

**D1 — Rust, embedding the `cedar-policy` crate.** The Rust implementation is the Cedar reference and gets schema validation, entity slicing, partial evaluation and symbolic analysis first; `cedar-go` trails. Decisive factor: a native `CedarApproval` backend upstream must be Rust, so the schema, entity mapping and evaluation code port into that PR nearly unchanged. *Alternatives:* Go with `cedar-go` (faster first binary, weaker Cedar, rewrite later); Python with `cedarpy` (fastest prototype, wrong for a long-lived security daemon); wrapping Permit.io `cedar-agent` (dormant since Oct 2025, and a full policy/data-store REST surface where one decide endpoint is needed).

**D2 — `nono` is a development dependency only.** A runtime dependency would pull sigstore verification, x509 parsing, keyring/Keychain access and a `typify` build script into a fail-closed daemon for the sake of four serde structs. Instead the wire types are mirrored locally and a conformance test round-trips upstream's own serialized values, including an exact key-set assertion. Drift then fails CI on a version bump instead of silently misreading a decision. *Alternative:* depend on `nono` for exact types — rejected on attack surface and build weight.

**D3 — Principal is the caller, within a session, within an agent.** `Nono::Caller::"<caller>" in Nono::Session::"<session_id>" in Nono::Agent::"<mapped>"`. This is the only option that keeps nono's chain-of-custody distinction ("the agent ran git" vs "npm ran git") in the type system, while still allowing authored identity via the `Agent` ancestor. *Alternatives:* session-as-principal (flatter, but the trust chain becomes an advisory string and every endpoint request collapses to `Session::"proxy"`); backend-name-as-principal (most trustworthy identity but one principal per configured backend).

**D4 — Both request variants in v1, with rollout via nono's `chain` backend.** Endpoint mapping is a small increment over command mapping and the schema wants both actions from the start. Rollout safety comes from configuring `chain` with `mode = "any"` over `["cedar", "terminal"]`, which turns a Cedar denial into an interactive prompt — so the LOG_ONLY/dry-run mode the landscape research recommended building is unnecessary. *Alternative:* command-only skeleton first (defers a near-free increment); dry-run mode in the daemon (duplicates a capability nono already has).

**D5 — Respond with the friendly `{decision, reason}` shape.** nono tries its internal `ApprovalDecision` serde representation first and falls back to the friendly shape. The internal representation is private and will drift; the friendly one is a stable public contract. Verified that `{"decision":"allow"}` fails to parse as `ApprovalDecision`, so the fallback path is taken as intended.

**D6 — `args` is a Cedar `Set<String>`.** Sets have no index access, so positional argument policy is unexpressible rather than merely discouraged — which is the correct response to upstream's lossy argv. `argv_tail` (the join of `args[1..]`) and `arg_count` cover the remaining legitimate cases. Consequence documented as a policy-authoring rule: `argv_tail like "*--force*"` also matches text inside a single quoted argument, so joined-string globs are safe in `forbid` and unsound in `permit`. Confirmed empirically: `git commit -m "do not --force this"` matches. **Amended 2026-07-25 (post-implementation audit):** the joined string was originally `argv` (all of `args`, `args[0]` included). Since `args[0]` is an absolute per-run shim path, an anchored glob over it could never match at runtime — fail-open in a `forbid` — so `argv` was **removed** from the schema in favour of `argv_tail`, applying this same D6 posture to the anchoring hazard: unexpressible, not discouraged. See the design spec D12. **Amended again 2026-07-25 (security audit):** the forbid-only rule was stated too broadly. Because `argv_tail` omits `args[0]`, its first token *is* the subcommand, so an anchored test (`== "status"` / `like "status *"`) is a positional pin — the only expressible way to say "the subcommand is X", which set membership cannot say at all. Membership on a subcommand word is what let `git -c core.fsmonitor=<cmd> status` through the shipped read-only permit. So anchored `argv_tail` tests are the *sound* shape for a `permit`; only unanchored globs stay forbid-only, and the loader lint was narrowed to match.

**D7 — A failed reload keeps the last known good policy set.** A syntax error typed into a policy file while an agent is working must not deny-all that agent. Startup is the strict gate; reload is best-effort with a loud error and no generation advance. *Alternative:* fail closed to deny-all on a bad reload — rejected as hostile to the editing workflow, and no safer, since the previous set was itself reviewed.

**D8 — Loopback bind, no reverse-proxy hostname.** nono cannot authenticate the decider, so the network surface is minimised: `127.0.0.1:8181`, no portless `.localhost` name, no extra hop.

**D9 — An empty policy directory refuses to start.** Cedar's default-deny makes an empty set technically fail-closed, but a daemon that denies every action with "no policy matched" is indistinguishable from a policy bug. Refusing to start turns a misconfiguration into an immediate, named error. An operator who genuinely wants deny-all writes `forbid (principal, action, resource);`.

**D10 — Policy identifiers carry file provenance.** `<file stem>:<@id annotation or ordinal>`, so a denial reason recorded in nono's audit trail points at the file and rule to edit. Duplicate identifiers are a hard load error.

**D11 — Deny and broken are different signals.** Decision-shaped failures (malformed body, unsupported variant, evaluation error) return HTTP 200 with an explicit deny reason, because nono records the reason we supply. Daemon-level failure returns 503, so nono's recorded reason names the status and the operator can tell "policy said no" from "the PDP is broken".

## Risks / Trade-offs

- **A local process could impersonate the PDP** by binding the port first and answering `allow`, since nono sends no credential → loopback-only binding limits this to local processes; the planned fix is https-on-loopback with a locally-trusted certificate, which makes impersonation a TLS failure that nono treats as a denial. Accepted for v1 and documented.
- **The daemon becomes a hard dependency of intercepted commands**: if it is not running, nono fails closed and blocks the command → this is the correct security posture, but the operator must know it; `chain` with `mode = "any"` and a terminal fallback removes the sharp edge during rollout.
- **Upstream wire drift silently changing decisions** → the conformance test asserts the exact key set against upstream's own types, so a nono bump fails CI. The pin must be advanced deliberately.
- **Policy authors reaching for positional argument matching**, which upstream's lossy argv makes unsound → the schema makes it unexpressible; the starter policies demonstrate set membership; the authoring rule is documented.
- **`argv_tail` glob over-matching producing spurious denials** → unanchored globs are confined to `forbid` policies where over-matching is fail-safe (the loader warns about a `permit` whose `argv_tail` test is not a positional pin), and paired with the `chain` fallback so a spurious denial becomes a prompt rather than a hard block.
- **A permit that names a subcommand word instead of pinning its position** → the hole the security audit found in the shipped pack: `args.contains("status")` also matches `git -c core.fsmonitor=<cmd> status`, i.e. arbitrary execution. Fixed by anchoring the pack's permit on `argv_tail` and adding a second, independent `forbid` on git's code-executing flags, so a future membership-shaped permit cannot resurrect it. Residual cost: legitimate `git -c … status` is denied (fail-safe, and a prompt under the `chain` posture).
- **An endpoint path whose meaning depends on the upstream's normalisation** — `resource.path like "/repos/*"` was satisfied by `/repos/../user/keys` → the path is *not* normalised (that would change what the policy matches and guess at the upstream's rules); instead an ambiguous path is denied before any policy is consulted. Residual cost: an exotic-but-legitimate path (a percent-encoded non-UTF-8 segment) is denied; the raw path still reaches policy in every unambiguous case.
- **A glob anchored over the whole argv silently never matching** — fail-open in a `forbid`, because `args[0]` is a per-run shim path → the whole-argv attribute is not in the schema, so such a policy fails strict validation and cannot load (D12 amendment); a literal path in an `args` membership test, the residual form, earns a load-time lint.
- **The sandboxed agent rewriting the policies that govern it** — the shipped `policy_dir = "./policies"` sat inside the tree the documented smoke profile grants read-write, and the hot-reload adopted an injected `permit (principal, action, resource);` within the debounce (proven end-to-end: a denied `git push --force` came back `allow`) → the shipped `policy_dir` and `audit_log` are home-anchored, the repo-relative shape is a separate dev config, and the smoke recipe builds its own state outside the repository. **Residual risk, stated plainly:** nothing in the daemon can enforce this. Seatbelt and Landlock are path-based and do not change uid, so the agent runs as the same user and file modes give it no obstacle; the group/world-writable refusal at startup covers *other local users* only, and the working-directory warning is a heuristic that misses an absolute path inside a granted tree (macOS default groups grant write to `/tmp`, `$TMPDIR`, `/var/folders`) and fires when no agent exists. The control is the operator's profile, so the README gives the runnable procedure for checking one and `just smoke` asserts it.
- **The audit trail detaching on rotation** — an append handle survives `rename`/`unlink` and its writes keep succeeding, so after a rotate every decision was answered and recorded into an inode nothing can read at the configured path, with `/healthz` still green → the sink compares the path's `(st_dev, st_ino)` against its handle before every record and reopens on a mismatch, keeping the rule that an audit failure never changes a decision. Residual cost: one `stat` per decision (microseconds against a millisecond evaluation), and a reopen that itself fails keeps appending to the previous file rather than dropping the record.
- **No agent identity in the payload**: two agents routed through one backend name are indistinguishable → the supported pattern is two named webhook backends in the nono profile pointing at the same URL, since the envelope carries the backend name. Zero daemon code, documented.
- **Latency added to the sandbox hot path** → Cedar evaluation is microseconds; one loopback HTTP round trip dominates and is well inside nono's default 60 s timeout (configured to 5 s). Unix-socket transport is impossible with upstream's `ureq` client.

## Migration Plan

Greenfield: nothing to migrate, and the change is additive to the operator's machine.

Rollout, in order:

1. Run `validate` against the starter policy pack; run `check` against saved payload fixtures to confirm expected decisions offline.
2. Start the daemon; confirm `/healthz` reports the loaded generation.
3. Wire the nono profile with `approval_defaults.backend` pointing at a `chain` backend in `any` mode over `["cedar", "terminal"]`. Cedar decides; a denial prompts. Observe the audit log.
4. Tighten policies until prompts stop appearing for legitimate work.
5. Switch `approval_defaults.backend` to the bare `cedar` backend to enforce without a fallback, or to a `chain` in `all` mode where human confirmation should also be mandatory.

Rollback is configuration-only at every step: point `approval_defaults.backend` back at `terminal` and the daemon is out of the path. Stopping the daemon without changing the profile fails closed and blocks intercepted commands — that is the intended behaviour, not a rollback path.

## Open Questions

- Does nono's issue #879 ("policy engine interoperability contract") intend to ship a first-party `PolicyInput`/`PolicyDecision` schema? It was closed as completed with no implementing code. If a contract lands upstream, adopt it as the primary wire format and keep the webhook shape as a compatibility path. Resolution: ask on the issue; does not block this change.
- Should the lossy-argv `filter_map` be reported upstream as a bug (dropping an argument silently) rather than worked around? Leaning yes, as a separate issue with a suggested lossy-conversion replacement. Does not block.
- Whether endpoint approvals need their own `Agent` mapping distinct from command approvals, given both arrive on the same backend name. Deferred until real endpoint policies exist.
