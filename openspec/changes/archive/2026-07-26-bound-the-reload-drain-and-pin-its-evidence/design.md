# Design: bound-the-reload-drain-and-pin-its-evidence

Both defects live in `src/watcher.rs` and both are timing, which is why they land
together. They are reasoned about separately throughout: #31 is about whether a test
*proves* anything, #10 is about whether the daemon *reloads*. Neither is a
decision-correctness hole.

## D1 — The drain gets a ceiling measured from the first event, not a rate limit

The drain exists so an editor's multi-write save produces one reload rather than four.
The bug is that its termination condition ("150 ms of quiet") is a property of the
event stream, which an adversary or a misconfiguration controls, rather than of the
daemon.

**Chosen:** keep the 150 ms quiet-period as the *normal* exit, and add a hard ceiling
measured from the first event of the burst. The drain ends at whichever comes first.
Each wait is `min(DEBOUNCE, ceiling_remaining)`, so the ceiling cannot be overshot by
up to a debounce.

**Ceiling = 2 s.** The constraints that pick it:

- It must be far above 150 ms, or ordinary bursts get cut short and we trade a
  liveness bug for a spurious-WARN bug. `just install-policies` copying a starter pack
  is the largest legitimate burst and is sub-second.
- It must be small enough that the resulting staleness is invisible to an operator
  who just saved a policy file. 2 s is below the threshold where someone re-saves to
  check whether it took.
- Under sustained churn the daemon now reloads every ~2 s instead of never. That work
  is a directory read plus strict re-validation of the whole set — bounded, and on a
  starter-pack-sized directory, negligible. Trading "never reloads" for "reloads on a
  2 s cadence" is the right side of that trade.

**Rejected — a token bucket or minimum inter-reload interval.** Solves a problem we do
not have (reload cost) while leaving the one we do have (unbounded postponement)
untouched: a rate limiter still never fires if the drain never exits.

**Rejected — dropping the debounce entirely and reloading per event.** Restores the
four-reloads-per-save noise the debounce was added to remove, and makes a broken
intermediate save state far more likely to be read mid-write.

## D2 — A cut-short drain is WARN, not INFO and not ERROR

Continuous event traffic in a policy directory is not normal. It is either a
misconfiguration (the policy directory placed inside a tree something else writes) or a
symptom worth looking at. INFO would bury it in reload chatter; ERROR would overstate
it, since nothing has failed and the last-good set is intact — and this repo already
holds the line that ERROR means the operator must act (the reload refusal, D7).

WARN under sustained churn emits roughly one line every 2 s. That is the honest signal:
the condition really is ongoing, and a single line at the start would understate a
stream that is still running an hour later.

## D3 — Events are NOT filtered by extension

Tempting, and wrong here. The suggestion was to ignore events for paths the loader
would not load, since a `churn.txt` write causes a full read plus re-validation for
nothing.

The trust re-check runs on the same wakeups, and it cares about things no `*.cedar`
filter would let through. A `chmod` that makes the policy directory group-writable
produces an event whose path is **the directory**, not a policy file. Filtering to
policy files would mean a directory loosened mid-session is not re-checked until
someone happens to touch a `.cedar` file — reopening a narrower version of exactly the
"adopted silently" hole `harden-policy-dir-isolation` closed and #31 exists to keep
pinned.

The cost the filter would save is bounded by D1's ceiling anyway. Not worth reasoning
about a path-classification predicate that has to stay in sync with both the loader's
skip rules and the isolation check's interests, to save a directory read every 2 s.

## D4 — The three tests wait for the refusal, then assert absence

The failing shape asserts absence over a 2 s window and then reads the log, so the log
assertion inherits no timing guarantee at all. The fix inverts the order:

1. `within(generous, || capture.text().contains("ERROR"))` — positive evidence that the
   watch thread received the event, drained, ran the re-check and refused.
2. *Then* assert the absence of adoption over a shorter window, and assert the
   generation explicitly.
3. Then the content assertions (mode, path).

This is not a weaker test. Step 1 fails after the generous timeout if the re-check is
removed, because no refusal is ever logged — so a genuinely broken control is red, and
a merely slow machine is green, which is the correct discrimination and the exact one
the current code gets backwards.

**Polling the log is not a proxy for the behaviour — it is the behaviour.** The
requirement says the refusal is logged at ERROR naming the path and mode; "the operator
is told" is the deliverable. Waiting for it is waiting for the thing under test.

**Rejected — a test-only synchronisation hook on the watcher** (an event counter or a
channel the tests could block on). It would give exact synchronisation, but it adds an
observability surface to production code for the benefit of tests, and it would pin the
*internal* fact "an event was processed" rather than the *external* one "the operator
was told at ERROR". The second is what the spec requires. The two already-correct
sibling tests demonstrate the log-polling shape is sufficient.

**Rejected — simply raising 2 s to 10 s.** Makes the flake rarer without making the
test prove anything more; the absence window would still be the only thing guaranteed,
and the suite would get slower for it.

## D5 — The ceiling test is made non-vacuous by measurement, not assumption

A test that "generates continuous events" is worthless if the platform coalesces them
below the debounce rate — the unbounded drain would exit on its own and the test would
pass against unfixed code.

Measured before designing the test: on macOS with `notify` 8.2, rewriting one file
every 20 ms in the watched directory kept an unbounded 150 ms drain alive for the full
5 s probe across 853 delivered events, never terminating once. So the churn rate is
comfortably inside the margin, and the test fails against unfixed code for the right
reason. The churn file is deliberately **not** a `*.cedar` file, which also pins D3's
consequence: events the loader would ignore still drive the drain.

## D6 — #31 gets no spec delta

`pdp-operations` already requires the reload refusal to be logged at ERROR naming the
path and mode. The tests were not proving that requirement; the requirement itself was
correct and complete. Writing a delta so the change looks more substantial would put a
false entry in the audit trail. The reasoning is recorded here and in the tasks instead.

## Risks

- **The ceiling could cut short a legitimate very large burst** (an operator rsyncing a
  large policy tree in). Consequence is a reload mid-copy, which either loads a
  consistent older set or fails validation and keeps the last-good set — both
  fail-closed — followed by another reload 2 s later that picks up the finished state.
  No new failure mode, and the WARN says what happened.
- **The new test adds ~2.5 s to the suite** and holds `CAPTURE_LOCK` while it runs, so
  it serialises against the other capturing tests. Accepted: it is the only way to
  observe the cut-short WARN, and the suite is currently ~6.7 s.
