# Design: close-audit-and-loader-gaps

## Context

Three independent re-audit findings (#24, #26, #27) against `src/audit.rs`,
`src/cedar/engine.rs::load_dir`, and the crate's public surface. No coupling
between them beyond shared verification, so one change with three work streams.

## Goals / Non-Goals

**Goals**: audit lines carry the routing context Cedar saw; no silent drop of
directory entries; the D15 guard's bypass pieces leave the public API.

**Non-Goals**: audit-log schema versioning (the key set grows once, stays fixed);
retrying unreadable entries; a `cargo public-api` CI gate (tripwire test is the
proportionate spend).

## Decisions

### D1 — Three nullable keys, not a unified `rule` field (#24)

`child_pid`, `intercept_rule`, `rule_label` as separate always-present keys.
A unified `rule` would erase which upstream concept supplied the value —
`intercept_rule` and `rule_label` are different upstream fields with different
grammars, and the audit line's job is fidelity. The record's existing invariant
("the key set never changes; absent is explicit null") extends to the new keys,
including on `record_rejected` lines. `child_pid` records what was sent (0 for
endpoint requests, as upstream hardcodes), not a synthesized absence.

### D2 — Fixture corpus pinned to upstream's rule-label grammar (#24)

Verified 2026-07-25 against `nolabs-ai/nono` `crates/nono-cli/src/tool-sandbox/
policy.rs`: `ResolvedInterceptAction::rule_label()` returns the matched rule's
`args.join(" ")`, `"<catch-all>"` for `Some([])`, and evaluate_invocation_policy
labels `invocation_policy.approve[{index}]` / `invocation_policy.default`
(upstream's own test asserts `"push --force"`). New fixtures drive each shape
through the full path (HTTP parse → evaluate → audit line) asserting byte-identical
survival — the corpus stops being able to green-light a consumer that assumes one
token. This is the "fixtures once encoded a shape nono never sends" lesson applied
in the opposite direction: shapes are sourced from upstream code, cited in the
fixture comments.

### D3 — Unreadable directory entry refuses the load (#26)

`.filter_map(Result::ok)` becomes error propagation into `PolicyLoadError::Io`
(directory-scoped: the failure belongs to enumeration, not to a named file). Warn-
and-continue was the alternative and is rejected: the daemon cannot classify what
it could not read, so "it probably wasn't a policy" is a guess, and the same
function's contract is now "a skip is never silent — and a skip is only ever a
*classified* file". At startup this refuses to serve; at reload the existing
last-known-good machinery retains the previous set and logs the error. Since a
`read_dir`-entry error cannot be produced hermetically on macOS, the entry-
handling is factored so a unit test can inject an `Err` entry (same seam style as
`audit::ByteSink`); the production call site stays one line.

### D4 — Visibility narrowing plus tripwire, no new dev-dependency (#27)

`cedar::entities` → `pub(crate) mod`; `Decision::from_response` → `pub(crate)`.
With those two gone, the public surface no longer offers a route from
`PolicyQuery` to a Cedar `Request`/`Entities` or from a raw `Response` to a
`Decision`, so external evaluation must pass `Engine::evaluate` and its guard.
`main.rs` (separate bin crate) is the visibility canary — it uses only the
intended public API and keeps compiling. Precedent: task 15.2 narrowed
`Engine::from_loaded` the same way. Enforcement against regression: a tripwire
test (in `tests/docs.rs` style: assert the source's visibility markers) rather
than `trybuild` — a compile-fail harness is a heavy dev-dependency for two
declarations, and the tripwire names the requirement in its failure message.

## Risks / Trade-offs

- **[Audit consumers see new keys]** JSONL consumers strict about unknown keys
  would break. → None exist (the house consumer is `jq`/the check tool); keys are
  additive; called out in the commit and issue close.
- **[Tripwire test is textual]** A refactor moving the items to new paths could
  dodge the grep. → The tripwire asserts on the module files by path and fails if
  the pattern is *absent*, so a move breaks it loudly and the author updates it
  consciously — the failure mode is a false alarm, not a false pass.
- **[Refusing on entry errors can refuse a whole directory over one glitch]** →
  That is the documented posture for the policy set ("refuse to run without a
  usable policy set"); transient enumeration errors on a local directory are rare
  and a retry is one reload away, while continuing without an unknown entry is
  unbounded downside.

## Migration Plan

Additive audit keys; no config change; visibility narrowing affects no shipped
binary. Rollback is a revert.

## Open Questions

None.
