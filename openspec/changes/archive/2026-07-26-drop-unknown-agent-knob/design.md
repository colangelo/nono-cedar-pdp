# Design: drop-unknown-agent-knob

## Context

`Config::unknown_agent` (default `"unknown"`) renames the identity an unmapped
approval-backend name resolves to. The shipped `00-baseline.cedar` denies
`Nono::Agent::"unknown"` literally. The two agree only while the knob is untouched;
issue #25 documents how setting it converts a fail-loud deny into a silent
fall-through.

## Goals / Non-Goals

**Goals**: make "unmapped backend ⇒ denied by the baseline" structural; make the
removal itself fail-loud for any config still carrying the key.

**Non-Goals**: validating that a *custom* policy pack still denies the unknown
agent (an operator who removes the baseline forbid owns that posture — Cedar is
default-deny, so an unmapped backend with no matching permit still denies); a
compatibility shim or deprecation period (pre-1.0, no external deployments, and a
shim would preserve exactly the silent-disable hazard being removed).

## Decisions

### D1 — Drop the knob rather than cross-validate it (issue option 1 over 2 and 3)

Option 2 (loader rejects a config whose `unknown_agent` the loaded policy set does
not forbid) couples config validation to policy-set contents: the policy set hot-
reloads, so the invariant would have to be re-checked on every reload and could
start failing mid-session for a config that loaded fine — a new class of half-up
states. Option 3 (emit the fallback into the schema so policies reference it
symbolically) adds schema surface for a name nothing needs to vary. Option 1
removes the hazard at its source; `deny_unknown_fields` already gives the breaking
change a loud, named failure mode.

### D2 — One exported constant, asserted against the shipped pack

`config::UNKNOWN_AGENT: &str = "unknown"` (pub const). `Config::agent_for` falls
back to it; the `RejectedContext` scrape path inherits it via `agent_for`. A test
reads `policies/00-baseline.cedar` and asserts the `no-unknown-agents` forbid names
`Nono::Agent::"unknown"` == the constant — the spec's "cannot drift silently"
scenario. (The policy file is the artifact operators install; asserting against the
file keeps the guard on the thing that ships, in the same spirit as `tests/docs.rs`
guarding the README.)

### D3 — Serde error text is the migration message

`#[serde(deny_unknown_fields)]` produces "unknown field `unknown_agent`, expected
one of ..." — it names the key and the surviving schema. The existing strict-config
test already asserts that shape for a typo; a new test pins it for this exact key so
the migration path (delete the line) stays discoverable from the error alone.

## Risks / Trade-offs

- **[Breaking config change]** Any config setting the knob stops loading. → It is
  the point: silently honouring it was the bug. Pre-1.0, single known deployment,
  error names the key.
- **[Operator intentionally renamed the fallback]** No demonstrated use exists; an
  operator who wants a different identity for unmapped backends maps the backend
  explicitly in `[agents]` — the supported, visible spelling of the same intent.

## Migration Plan

Delete the `unknown_agent` line from any config that has one. Nothing else moves.

## Open Questions

None.
