# Tasks: close-audit-and-loader-gaps

TDD throughout: failing test first, watched failing for the right reason. Full and
filtered test runs must both pass.

## 1. Audit record completeness (#24)

- [x] 1.1 Failing test: a decided command request's audit line carries `child_pid` and `intercept_rule` as sent, and an explicitly null `rule_label`
- [x] 1.2 Failing test: a decided endpoint request's audit line carries `rule_label` as sent, `child_pid` 0, and an explicitly null `intercept_rule`
- [x] 1.3 Failing test: a rejected (malformed/unsupported) request's audit line still contains all three keys, each null
- [x] 1.4 Implement: extend `AuditRecord`, `record`, `record_rejected`; key set fixed, values from `query.target`

## 2. intercept_rule fixture corpus (#24)

- [x] 2.1 Failing test(s): command payloads with `intercept_rule` of each verified real shape — `"status"`, `"push --force"`, `"<catch-all>"`, `"invocation_policy.approve[0]"`, `"invocation_policy.default"` — driven through HTTP parse → evaluate → audit, asserting the value reaches the audit line byte-identically (cite the upstream source of the shapes in the fixture comments: nolabs-ai/nono crates/nono-cli/src/tool-sandbox/policy.rs `rule_label()`)
- [x] 2.2 Extend `tests/fixtures/` with at least one multi-token-rule payload so the offline `check` command exercises a non-single-token shape too

## 3. load_dir silent drop (#26)

- [x] 3.1 Refactor the directory-entry iteration behind a seam that accepts `io::Result` entries (production call site unchanged in behaviour); all existing loader tests still pass
- [x] 3.2 Failing test: an injected `Err` entry fails the load with an error naming the directory — never a silent drop; message distinguishes enumeration failure from per-file read failure
- [x] 3.3 Test: at reload, the enumeration failure retains the last-known-good set (existing retention machinery; assert the ERROR log names the directory)

## 4. Endpoint-path guard bypass (#27)

- [x] 4.1 Narrow `cedar::entities` to `pub(crate)` and `Decision::from_response` to `pub(crate)`; whole workspace (lib + bin + integration tests) compiles — the bin crate is the public-API canary
- [x] 4.2 Tripwire test asserting the two visibility markers in source, failing with a message that names the requirement ("the D15 guard's bypass pieces must not be exported")

## 5. Verification

- [x] 5.1 `just test` full and filtered (`cargo test --lib audit`, `cargo test --lib engine`, `cargo test --test server`, `cargo test --test policies`) green; `just lint` clean
- [x] 5.2 `just smoke` still green (audit-line shape change must not break the smoke recipe's assertions)
- [x] 5.3 `openspec validate --changes close-audit-and-loader-gaps` passes
