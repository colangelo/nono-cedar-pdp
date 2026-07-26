# Audit register

What was found, what was fixed, and — the part that only exists if someone writes it
down — **what was deliberately not fixed, and why**.

An accepted risk that is not recorded is indistinguishable from an oversight. That
distinction is the entire value of keeping this, so the register is organised around it
rather than around dates or severity.

## The three categories

| Category | Meaning | Follow-up |
|---|---|---|
| **Fixed** | Closed in this repository. Kept as history so a later reader can see the shape of what went wrong, not just that it went away | None. The pinning test is the guarantee |
| **Accepted — ours** | We could close it and chose not to. The reason is recorded and has to be a reason, not a shrug | Revisit if the reason stops holding |
| **Accepted — not ours to fix** | The cause is outside this repository: an upstream defect, or a property of the contract we consume. No change here closes it | Track the upstream item; re-check on version bumps |

The third category exists because its entries close by **someone else's** action. Filing
them with our own accepted risks would imply we chose to live with something we cannot
reach, and would hide the fact that a version bump might silently close them.

## Rules for an entry

- **Every accepted entry states what would have to change for it to close.** An entry
  that cannot be falsified is not a record, it is a shrug. This is what lets a later
  reader tell a live risk from a stale one.
- **Entries that became tracked work reference the tracking item** rather than restating
  it, so the register cannot drift out of sync with the backlog.
- **Where an accepted risk can be expressed as an assertion about behaviour, name the
  test that pins it.** Prose has no failure mode; a test does. Changing the behaviour
  then requires engaging with this register rather than discovering it afterwards.
- **Never overstate what a control buys.** The standing example: the state-path mode and
  ownership checks defend against *other local users*, never against the sandboxed agent
  — same uid, and Seatbelt/Landlock are path-based. Prose implying otherwise is itself a
  defect, and `tests/docs.rs` pins the wording.

## Contents

- [`2026-07-25-v1-implementation-audit.md`](2026-07-25-v1-implementation-audit.md) — the
  32 findings from the three adversarial passes over the v1 implementation, plus the
  upstream-caused residual that the argv work later added, and **A04**, the residual
  https-on-loopback introduced: a control's own preconditions, filed on the day it
  shipped rather than the day someone rediscovers them.
