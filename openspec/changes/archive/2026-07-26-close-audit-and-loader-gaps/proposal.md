# Proposal: close-audit-and-loader-gaps

## Why

Three re-audit findings, batched because each closes a gap between what the code
promises and what it does, with no cross-dependencies:

- **#24** — the audit record drops `child_pid` and `intercept_rule` (and the
  endpoint counterpart `rule_label`), fields the daemon parses and hands to Cedar.
  The log is the compensating control for an unauthenticated webhook; omitting the
  rule that routed the request and the pid that made it costs exactly the context
  an investigator wants. Relatedly, the fixture corpus models only one
  `intercept_rule` shape — verified against upstream (`nolabs-ai/nono`,
  `crates/nono-cli/src/tool-sandbox/policy.rs`), real nono sends the matched rule's
  args joined with spaces (`"status"`, `"push --force"`), `"<catch-all>"` for an
  empty-args rule, and the invocation-policy labels
  `invocation_policy.approve[<index>]` / `invocation_policy.default` — so tests
  seeing only single tokens cannot catch a consumer that assumes one word.
- **#26** — `load_dir` still filters the directory listing with
  `.filter_map(Result::ok)`, silently dropping an entry whose metadata cannot be
  read — the exact silence the same function now promises not to produce ("a skip
  is never silent", commit 5c8096e). An unreadable entry is also precisely the
  shape of a tampering symptom. The daemon cannot know whether the dropped entry
  was a policy, so the sound response is refusing the load, consistent with
  "refuse to run without a usable policy set" (at reload, the last-good set is
  retained per the existing hot-reload requirement).
- **#27** — the D15 ambiguous-path deny lives inside `Engine::evaluate`, but the
  crate still publicly exports the pieces to authorize a request without passing
  it: `cedar::entities::build` plus `Decision::from_response`. No shipped path
  bypasses the guard today; the export is the same class of seam task 15.2 closed
  for `Engine::from_loaded` — left open, a future caller (including the upstream
  `CedarApproval` port these modules exist for) can find it.

## What Changes

- Audit record gains three always-present, nullable keys: `child_pid`,
  `intercept_rule` (command requests), `rule_label` (endpoint requests). Decided
  command lines carry pid + rule; decided endpoint lines carry pid (0, as sent) +
  label; rejected-request lines carry explicit nulls. The key set stays fixed —
  "not known" remains distinguishable from "not recorded".
- Fixture/test corpus gains command payloads with each verified real
  `intercept_rule` shape, driven through parse → evaluate → audit, asserting the
  value survives to the audit line byte-identically.
- `load_dir` propagates a directory-entry read failure as a load error instead of
  dropping the entry; startup refuses, reload keeps last-good and logs the error.
- `cedar::entities` and `Decision::from_response` drop out of the public API
  (crate-private); a tripwire test pins the visibility so a silent re-export fails
  loudly.

## Capabilities

### New Capabilities

None.

### Modified Capabilities

- `decision-audit-log`: "Audit lines are self-sufficient for review" — record
  gains `child_pid`, `intercept_rule`, `rule_label`.
- `cedar-policy-evaluation`: "Load policies with traceable identifiers" — an
  unenumerable directory entry fails the load rather than vanishing; "Deny
  endpoint requests whose path is ambiguous" — the guard is not bypassable through
  the crate's public surface.
- `approval-webhook`: "Guarantee wire conformance with the upstream crate" — the
  corpus models every verified real `intercept_rule` shape, not one.

## Impact

- `src/audit.rs` (`AuditRecord`, `record`, `record_rejected`), `src/query.rs` (no
  change expected — `Target` already carries the fields), `src/cedar/engine.rs`
  (`load_dir` entry iteration), `src/cedar/mod.rs` + `src/decision.rs`
  (visibility), tests in `tests/server.rs`, `tests/policies.rs`,
  `tests/fixtures/`, `tests/conformance.rs`.
- Audit-line consumers: three new keys appear; existing keys unchanged. JSONL
  consumers that ignore unknown keys are unaffected.
- Gitea: closes #24, #26, #27.
