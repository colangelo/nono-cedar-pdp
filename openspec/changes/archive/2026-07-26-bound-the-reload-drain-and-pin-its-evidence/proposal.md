# Proposal: bound-the-reload-drain-and-pin-its-evidence

## Why

Two defects in `src/watcher.rs`, both timing, deliberately kept separate because they
are not the same kind of problem: one is about **test evidence**, the other about
**production liveness**.

### Gitea #31 — three reload-refusal tests can pass before the behaviour happens

`a_policy_dir_loosened_mid_session_is_refused_and_the_last_good_set_stays` and two
siblings prove the *absence* of a wrongly-adopted reload with
`assert!(!within(Duration::from_secs(2), …))`, which returns only after the full 2 s,
and then immediately require the captured log to contain `ERROR`, the mode and the
path. But that ERROR comes from the watch thread, which must first receive the
`notify` event, drain the 150 ms debounce and run the trust re-check. One 2 s window
is being asked to serve as both "long enough to prove nothing was adopted" and "long
enough for the refusal to have been logged", and only the first is guaranteed.

The issue filed this as a hypothesis. **It is now a diagnosis**, by controlled
experiment: inflating `DEBOUNCE` to 2500 ms so the watch thread provably cannot finish
inside the window makes exactly three tests fail — the same count as the one observed
real failure — and all three fail on the *presence* assertion with an **empty**
capture, while the absence window passes for the wrong reason. The two sibling tests
that already poll for the ERROR (`an_unlistable_policy_dir_…`,
`repairing_the_mode_…`) stay green under the same inflation, which is what identifies
the assertion order as the variable rather than the tracing capture.

This matters beyond a red run. A test that can pass because the thing under test has
not happened yet is not pinning the behaviour it claims to pin: a genuine regression in
the reload trust re-check — the control from `harden-policy-dir-isolation`, guarding
the trust boundary of epic #1 — could sit green for exactly the reason this goes red.
Fixing the flake is secondary to fixing the evidence.

### Gitea #10 — the debounce drain has no ceiling

`while rx.recv_timeout(DEBOUNCE).is_ok() {}` postpones the reload for as long as
events keep arriving. Measured on this platform (macOS, `notify` 8.2): rewriting one
non-policy file every 20 ms in the watched directory kept the drain alive for the full
5 s probe across 853 events, never once terminating. A policy edit made during such a
stream is never picked up, and nothing reports that.

Stated at its true severity: this is **liveness, not correctness**. A postponed reload
keeps the last-good set, which is fail-closed by construction, so no wrong decision is
produced. What it defeats is hot-reload itself, silently, while the operator's mental
model says the edit took effect.

## What Changes

- **#10 (behaviour).** Bound the drain: the reload SHALL run no later than a fixed
  ceiling after the *first* event of a burst, regardless of continuing traffic. When a
  drain is cut short by that ceiling, log it at WARN — continuous churn in a policy
  directory is either a misconfiguration or a symptom, and either way the operator
  should not have to infer it from reloads that seem late.
- **#31 (test evidence only, no behaviour change).** Reorder the three affected tests
  so each waits for positive evidence that the watch thread *processed the event and
  refused* before asserting anything about the log, and only then asserts the absence
  of adoption. This adopts the shape the two already-correct siblings use, which is why
  they survived the controlled experiment.

**Deliberately not done: filtering events by extension.** The handoff suggested also
ignoring events for non-`.cedar` files, since the loader would ignore them anyway. That
is unsafe here and is not in #10's scope. The trust re-check legitimately wants to run
on directory-level events — a `chmod` on the policy directory produces an event whose
path is the directory, not a `*.cedar` file — so filtering to policy files would carve
a hole in the very control #31 exists to pin. The cost the filter would save is one
directory read plus a re-validation, which the ceiling already bounds. Recorded in
design D3 rather than silently skipped.

## Capabilities

### New Capabilities

None.

### Modified Capabilities

- `cedar-policy-evaluation`: "Hot-reload policies keeping the last known good set"
  gains the debounce ceiling — an upper bound on how long a burst may postpone a
  reload, and a WARN when that bound cuts a drain short.

**No delta for `pdp-operations`.** #31 changes no behaviour: the requirement "Re-check
the state paths before adopting a reloaded policy set" already says the refusal is
logged at ERROR naming the path and mode. The specification was right; the tests were
not proving it. Fixing a test to actually pin an existing requirement is not a spec
change, and inventing a delta to make the change look bigger would misrepresent it.

## Impact

- `src/watcher.rs`: bounded drain with a cut-short WARN; three tests reordered to wait
  for the refusal before asserting absence; one new test for the ceiling.
- No change to `src/isolation.rs`, `src/cedar/`, or any decision path.
- Gitea: closes #31 and #10. Epic #1 remains open.
