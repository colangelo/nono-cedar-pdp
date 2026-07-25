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

- [ ] 3.1 README "Keep the policy directory out of the sandbox": add the parent-chain rule and the reload re-check, keeping the existing "what these checks do and do not buy" framing — no sentence may imply mode bits constrain the sandboxed agent
- [ ] 3.2 `src/isolation.rs` and `src/watcher.rs` module docs updated to the same standard; design doc D13 section gets a pointer to this change (post-implementation correction trail, same as D12/D13 did)

## 4. Verification

- [ ] 4.1 `just test` (full) and filtered `cargo test isolation`/`cargo test watcher` both green; `just lint` clean
- [ ] 4.2 `just smoke` against real nono still passes with the hardened checks in place (home-anchored default paths must not trip the ancestor walk on a real macOS home)
- [ ] 4.3 `openspec validate --changes harden-policy-dir-isolation` passes
