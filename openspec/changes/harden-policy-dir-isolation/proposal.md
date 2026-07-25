# Proposal: harden-policy-dir-isolation

## Why

Gitea issue #23 (re-audit finding, descends from epic #1 / design D13): the startup
isolation checks on the policy directory have two gaps that leave the "another local
user rewrites the policies" vector open despite the refusal that exists to close it.

1. **The parent chain is unchecked.** `isolation::check` refuses on a group- or
   world-writable policy directory or policy file, but never inspects the ancestors.
   A loosely-writable, non-sticky ancestor lets another local user rename the policy
   directory out from under the daemon and substitute their own — the mode of the
   directory itself never mattered.
2. **The checks run at startup only.** The refusal runs once in `run_serve`; the
   ~150 ms hot-reload path re-reads and adopts policy files with no mode re-check. A
   directory that becomes loosely writable *while the daemon runs* is adopted
   silently, so the startup refusal is only as good as the moment it ran.

Scope honesty, carried from the epic and non-negotiable in every artifact of this
change: these checks defend against **other local users**. They do nothing about the
sandboxed agent, which runs as the same user as the daemon (Seatbelt/Landlock are
path-based and do not change uid). The control that stops the agent is the nono
profile not granting write access to these paths. No wording in code, specs, or docs
may imply otherwise.

## What Changes

- Extend the startup isolation check to walk the **existing ancestors** of the
  resolved policy directory and audit log path: an ancestor that is group- or
  world-writable **without the sticky bit** is a refusal to serve. (Sticky exempts
  an *ancestor* — it blocks renaming entries you do not own, which is the attack —
  unlike the policy directory itself, where creating a new `*.cedar` file is the
  attack and sticky does not help.)
- Re-run the writability checks (policy directory, policy files, parent chain) on
  the **hot-reload path**, before a reloaded policy set is adopted. On failure the
  last-known-good set is retained and the refusal is logged at ERROR naming the
  path and mode — the same fail-loud-keep-serving posture as a broken policy edit
  (D7), because the in-memory set predates the loosening and is the only trusted
  thing left.
- The reload-time check lives in the serve layer (watcher), matching where the
  startup check lives (`run_serve`) — `cedar::engine` stays free of operational
  concerns so it can lift upstream unchanged.

## Capabilities

### New Capabilities

None.

### Modified Capabilities

- `pdp-operations`: "Check the daemon's own state paths at startup, and do not
  overstate the checks" gains parent-chain scenarios and is extended to cover the
  hot-reload path (re-check before adopting a reloaded set; keep last-good and log
  at ERROR on refusal). The requirement's scope-honesty clauses (defends against
  other local users, not the agent) extend to the new checks verbatim.

## Impact

- `src/isolation.rs`: ancestor walk added to `check`; a callable subset (no cwd
  warnings) exposed for the reload path.
- `src/watcher.rs`: isolation re-check before `Engine::reload`; new failure branch
  retains last-good set with an ERROR log.
- `src/main.rs`: unchanged behaviour at startup beyond the wider check; wiring only.
- `README.md` operator docs: describe the parent-chain rule and the reload re-check
  without overstating what mode bits defend against.
- Gitea: closes #23; epic #1 remains open (profile-derived check and policy signing
  are deliberately not part of this change).
