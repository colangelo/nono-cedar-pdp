# Tasks: harden-policy-dir-isolation

TDD throughout: each behaviour lands as a failing test first, watched failing for
the right reason, then the implementation. `just test` must pass both in a full run
and filtered (`cargo test --lib isolation`, `cargo test --lib watcher`) — see
`src/test_log.rs` for the tracing max-level trap that once made filtered runs lie.

## 1. Ancestor walk in `isolation::check` (startup)

- [x] 1.1 Failing test: a policy directory that is owner-only but whose parent is group-writable non-sticky refuses with `IsolationError::Writable`-class error naming the *ancestor* path and its mode
- [x] 1.2 Failing test: a world-writable **sticky** ancestor (mode `1777`) is not a refusal (the tempdir fixture chain itself must keep passing — every existing test runs under `/private/var/folders/...`)
- [x] 1.3 Failing test: a loosely-writable non-sticky ancestor of the **audit log** refuses, naming the ancestor
- [x] 1.4 Failing test: an ancestor that cannot be stat'ed refuses (fail closed, `Io`-class), not skipped
- [x] 1.5 Implement the ancestor walk over the absolutized paths (parent → root, existing components only); new error variant or extended `Writable` message must carry path, mode, who, and the sticky rationale; wire it into `check` for both `policy_dir` and `audit_log` (plus one settled nuance found by the existing suite: a **non-directory** ancestor — `/dev/null/decisions.jsonl` — is skipped by the walk, because mode bits on a file or device grant no rename power and the audit log's own open fails with the honest ENOTDIR; pinned by its own test)
- [x] 1.6 Module docs: document the ancestor rule, the sticky-exempts-ancestors-only nuance (D1), and re-state scope honesty (defends against other local users, not the agent)

## 2. Refusal core shared with the reload path

- [x] 2.1 Factor the refusal core (directory + loadable files + ancestors, no cwd warnings) into a function both `check` and the watcher call (D5); startup behaviour unchanged — existing isolation tests all still pass unmodified
- [x] 2.2 Failing test (watcher): with the daemon watching, make the policy directory group-writable and touch a policy file — the active set and generation must remain, decisions must keep flowing from the last-good set, and the captured log must contain an ERROR line naming the path and mode
- [x] 2.3 Failing test (watcher): after repairing the mode, a subsequent edit is adopted (generation advances) — the watch survived the refusal
- [x] 2.4 Implement: watcher runs the refusal core after the debounce drain, before `Engine::reload`; refusal branch logs at ERROR and skips the reload; comment states the TOCTOU window and the other-local-users scope honestly (D3/D4). (One enabling change: the watch thread now inherits its spawner's tracing dispatcher — identical in production, where `main` installs the global subscriber, but without it the thread-local captures of `src/test_log.rs` could never observe what the watch thread logs)

## 3. Documentation

- [x] 3.1 README "Keep the policy directory out of the sandbox": add the parent-chain rule and the reload re-check, keeping the existing "what these checks do and do not buy" framing — no sentence may imply mode bits constrain the sandboxed agent
- [x] 3.2 `src/isolation.rs` and `src/watcher.rs` module docs updated to the same standard; design doc D13 section gets a pointer to this change (post-implementation correction trail, same as D12/D13 did)

## 4. Verification

- [x] 4.1 `just test` (full) and filtered `cargo test isolation`/`cargo test watcher` both green; `just lint` clean
- [x] 4.2 `just smoke` against real nono still passes with the hardened checks in place (home-anchored default paths must not trip the ancestor walk on a real macOS home)
- [x] 4.3 `openspec validate --changes harden-policy-dir-isolation` passes

## 5. Remediation from the security re-audit (2026-07-26, design D6/D7)

- [ ] 5.1 Failing test: a policy directory (or loadable policy file, or existing ancestor of either state path, or existing audit-log file) owned by a uid that is neither the daemon's euid nor root refuses to serve, naming the path and owning uid (test with a fake-uid seam or by asserting the check function's logic against injected metadata — chown needs privileges the suite does not have; design D6 allows a seam in the same style the walk already uses for stat errors)
- [ ] 5.2 Implement the owner-or-root refusal in the shared refusal core (startup + reload paths both inherit it); `geteuid` via `libc` behind one commented `unsafe` block; error text explains why ownership matters when modes look tight
- [ ] 5.3 Failing test: `run_serve` resolves `policy_dir` through a symlink before the checks and hands the resolved path to engine/watcher/audit — assert via the serve wiring (e.g. healthz or `Engine::policy_dir()`) that the active path is the resolved one (D7)
- [ ] 5.4 Implement resolve-once-at-startup in `run_serve` for `policy_dir` and the existing prefix of `audit_log`; module docs state that the checked chain and the used chain are the same object and that a post-startup repoint changes nothing
- [ ] 5.5 Extend the writability refusal's remedy text: tightening the mode does not undo content added or modified while loose — review before `chmod go-w`; assert the message text
- [ ] 5.6 Watcher-level tests for the two remaining WHEN disjuncts of the reload re-check scenario: a loadable policy file going loose mid-session, and an existing ancestor going loose mid-session — both keep last-good and log ERROR
- [ ] 5.7 Pin the README documentation clauses in `tests/docs.rs`: the profile-checking procedure (`nono profile show --format manifest` + `fs_write` sweep), the sticky-ancestor rationale, and the ownership rule — silent doc regression must fail a test
- [ ] 5.8 Update README + module docs for D6/D7 with the same scope honesty (other local users, never the sandboxed agent); design doc D13 trail pointer updated
- [ ] 5.9 Full + filtered tests green, `just lint` clean, `just smoke` still green (real home chain must satisfy the ownership rule)
