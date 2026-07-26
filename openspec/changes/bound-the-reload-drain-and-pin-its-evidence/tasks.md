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

- [ ] 2.1 `a_policy_dir_loosened_mid_session_is_refused_and_the_last_good_set_stays`: wait for the refusal on the log first, then assert absence of adoption and the explicit generation, then the mode/path content assertions (D4)
- [ ] 2.2 Same reordering for `a_policy_file_loosened_mid_session_is_refused_and_the_last_good_set_stays`
- [ ] 2.3 Same reordering for `a_loose_ancestor_mid_session_is_refused_when_the_next_edit_fires`
- [ ] 2.4 Re-run the D1 controlled experiment (inflated `DEBOUNCE`) against the reordered tests: all three must now be **green**, proving the fix addresses the diagnosed mechanism and not merely the symptom
- [ ] 2.5 Commit before mutating anything (the non-vacuity proof below destroys working state if it is not committed first)

## 3. #31 — non-vacuity gate: a broken control must still be red

- [ ] 3.1 Mutation: delete the `refuse_untrusted_policy_dir` call from the watch loop so the loosened set is adopted. All three reordered tests MUST fail, and MUST fail on "no refusal was ever logged" / adoption having happened — **not** on a timeout that a slow machine would also produce. Revert.
- [ ] 3.2 Record the mutation output in the commit or issue close, so the claim "these tests now pin the control" is evidenced rather than asserted

## 4. #10 — bound the drain

- [x] 4.1 Measure first, so the test cannot be vacuous: confirm that on this platform a 20 ms churn keeps an unbounded 150 ms drain alive indefinitely. Result: 853 events over the full 5 s probe, drain never terminated (D5). Without this the test could pass against unfixed code.
- [ ] 4.2 Failing test: with the watcher running and a non-`*.cedar` file rewritten every 20 ms in the policy directory, a policy edit that flips a decision is adopted within the ceiling — assert on the **decision flipping**, not on the generation, since churn-driven reloads advance the generation on their own
- [ ] 4.3 Failing test (same test or a sibling): the cut-short WARN reaches the log
- [ ] 4.4 Implement the ceiling: each drain wait becomes `min(DEBOUNCE, ceiling_remaining)` measured from the first event of the burst, so the bound cannot be overshot by up to a debounce; WARN when the ceiling is what ended the drain (D1, D2)
- [ ] 4.5 Module docs: state the ceiling, the WARN, and that this is liveness rather than correctness — a postponed reload keeps the last-good set. Do not overstate it.
- [ ] 4.6 Record D3 in the module docs: events are deliberately **not** filtered by extension, because the trust re-check needs directory-level wakeups

## 5. #10 — non-vacuity gate

- [ ] 5.1 Mutation: restore the unbounded `while rx.recv_timeout(DEBOUNCE).is_ok() {}`. The ceiling test MUST fail because the decision never flips. Revert.

## 6. Verify against reality, not just the suite

- [ ] 6.1 `just test` full, and filtered `cargo test --lib watcher`
- [ ] 6.2 `just lint` clean (clippy `-D warnings`; no `unwrap`/`expect`/`panic` outside tests)
- [ ] 6.3 `just smoke` against a real `nono run` — the suite has agreed with itself and disagreed with nono three times in this project
- [ ] 6.4 Repeat-run the full suite to check the reordered tests did not introduce a new flake
- [ ] 6.5 `openspec validate --changes bound-the-reload-drain-and-pin-its-evidence`
- [ ] 6.6 Push to `internal` and `origin`; close #31 and #10 with the mutation evidence
