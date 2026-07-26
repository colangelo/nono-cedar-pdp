# Tasks: bound-the-reload-drain-and-pin-its-evidence

TDD throughout: each behaviour lands as a failing test first, watched failing for the
right reason, then the implementation. `just test` must pass both in a full run and
filtered (`cargo test --lib watcher`) — see `src/test_log.rs` for the tracing
max-level trap that once made filtered runs lie.

The two halves are sequenced #31 first, then #10, so the ceiling lands on top of tests
that can actually detect a regression rather than underneath them.

## 1. Diagnose #31 before changing anything

- [x] 1.1 Controlled experiment: inflate `DEBOUNCE` past the tests' 2 s window and record which tests fail and how. Result: exactly three fail — `a_policy_dir_loosened_…`, `a_policy_file_loosened_…`, `a_loose_ancestor_…` — all on the *presence* assertion with an empty capture (`""`), matching the one observed real failure's count of three. The issue named the first two; the third was not on the list.
- [x] 1.2 Confirm the control: the two siblings that already poll for the ERROR (`an_unlistable_policy_dir_…`, `repairing_the_mode_…`) stay green under the same inflation, which identifies assertion *order* as the variable rather than the tracing capture. Hypothesis in #31 is now a diagnosis.
- [x] 1.3 Natural repro attempt: 25 consecutive full `cargo test --lib` runs without competing load, all green. Recorded as a negative result — the flake is load-dependent and did not reproduce here; the controlled experiment is the evidence, not this.

## 2. #31 — order the evidence in the three affected tests

- [x] 2.1 `a_policy_dir_loosened_mid_session_is_refused_and_the_last_good_set_stays`: wait for the refusal on the log first, then assert absence of adoption and the explicit generation, then the mode/path content assertions (D4)
- [x] 2.2 Same reordering for `a_policy_file_loosened_mid_session_is_refused_and_the_last_good_set_stays`
- [x] 2.3 Same reordering for `a_loose_ancestor_mid_session_is_refused_when_the_next_edit_fires`
- [x] 2.4 Re-run the D1 controlled experiment (inflated `DEBOUNCE`) against the reordered tests: all three must now be **green**, proving the fix addresses the diagnosed mechanism and not merely the symptom
- [x] 2.5 Commit before mutating anything (the non-vacuity proof below destroys working state if it is not committed first)

## 3. #31 — non-vacuity gate: a broken control must still be red

- [x] 3.1 Mutation: delete the `refuse_untrusted_policy_dir` call from the watch loop so the loosened set is adopted. All three reordered tests MUST fail, and MUST fail on "no refusal was ever logged" / adoption having happened — **not** on a timeout that a slow machine would also produce. Revert.
- [x] 3.2 Record the mutation output in the commit or issue close, so the claim "these tests now pin the control" is evidenced rather than asserted

## 4. #10 — bound the drain

- [x] 4.1 Measure first, so the test cannot be vacuous: confirm that on this platform a 20 ms churn keeps an unbounded 150 ms drain alive indefinitely. Result: 853 events over the full 5 s probe, drain never terminated (D5). Without this the test could pass against unfixed code.
- [x] 4.2 Failing test: with the watcher running and a non-`*.cedar` file rewritten every 20 ms in the policy directory, a policy edit that flips a decision is adopted within the ceiling — assert on the **decision flipping**, not on the generation, since churn-driven reloads advance the generation on their own
- [x] 4.3 Failing test (same test or a sibling): the cut-short WARN reaches the log
- [x] 4.4 Implement the ceiling: each drain wait becomes `min(DEBOUNCE, ceiling_remaining)` measured from the first event of the burst, so the bound cannot be overshot by up to a debounce; WARN when the ceiling is what ended the drain (D1, D2)
- [x] 4.5 Module docs: state the ceiling, the WARN, and that this is liveness rather than correctness — a postponed reload keeps the last-good set. Do not overstate it.
- [x] 4.6 Record D3 in the module docs: events are deliberately **not** filtered by extension, because the trust re-check needs directory-level wakeups

## 5. #10 — non-vacuity gate

- [x] 5.1 Mutation: restore the unbounded `while rx.recv_timeout(DEBOUNCE).is_ok() {}`. The ceiling test MUST fail because the decision never flips. Revert.

## 6. Verify against reality, not just the suite

- [x] 6.1 `just test` full (142 lib + 8 integration suites), and filtered `cargo test --lib watcher` — both green
- [x] 6.2 `just lint` clean (clippy `-D warnings`; no `unwrap`/`expect`/`panic` outside tests)
- [x] 6.3 `just smoke` against a real `nono run` (nono 0.69.0): **SMOKE PASSED** — `git status` allowed by `10-git:git-read-only`, `git push --force` denied by `10-git:no-history-rewrites`. It fails *inside a `wt` worktree*, but not for any reason of ours: `.git` is a pointer file there and the real git dir sits outside every profile grant, so `git` itself exits 128 after the PDP has already correctly returned allow. Verified by running the same commit from a normal clone, where it passes. Filed as #32 rather than dismissed as environmental — the house default is to work in worktrees, so this hits every agent here.
- [x] 6.4 Repeat-run the full suite: 15/15 consecutive `cargo test --lib` runs green, no new flake
- [x] 6.5 `openspec validate --changes bound-the-reload-drain-and-pin-its-evidence`
- [x] 6.6 Pushed to `internal` and `origin` (local `main` was 4 commits unpushed and went with it); #31 and #10 closed with the controlled-experiment and mutation evidence
