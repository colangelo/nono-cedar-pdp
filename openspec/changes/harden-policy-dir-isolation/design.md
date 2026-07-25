# Design: harden-policy-dir-isolation

## Context

`src/isolation.rs` refuses to serve when the policy directory or a loadable policy
file is group- or world-writable, and warns when either state path resolves inside
the cwd. `run_serve` (`src/main.rs`) calls it once, before anything else. The watcher
(`src/watcher.rs`) debounces filesystem events and calls `Engine::reload`, which
re-reads the directory with no mode check at all. Issue #23 names the two gaps:
ancestors are never inspected, and the check never runs again after startup.

Constraint carried from epic #1 and the module's own docs: every artifact of this
change must keep the threat model honest. Mode checks defend against **other local
users**; the sandboxed agent runs as the same uid and is untouched by any of this.
An earlier pass had the README implying protection it did not provide — that class
of wording error is a defect here, not a nit.

## Goals / Non-Goals

**Goals**

- Refuse at startup on a loosely-writable non-sticky ancestor of either state path.
- Re-run the writability checks before any reloaded policy set is adopted; keep the
  last-known-good set and log at ERROR when refused.
- Keep `cedar::engine` free of operational concerns (it lifts upstream later).

**Non-Goals**

- The profile-derived check ("is the policy dir inside any nono write grant?") and
  policy signing — epic #1's children, deliberately still open. This change cannot
  and does not defend against the sandboxed agent.
- Watching the ancestor chain for events. The re-check runs when a policy-dir event
  fires; a mode change on an ancestor alone does not wake the watcher (see Risks).
- Re-checking the audit log mid-session. The reload gate is about the policy set;
  the audit log has its own reattach/tighten logic in `src/audit.rs`.

## Decisions

### D1 — Sticky bit exempts an ancestor, never the policy directory itself

Two different attacks. On the policy directory, the attack is **creating** a new
`*.cedar` file: sticky does not restrict creation, so `loose_writers` stays as is
(sticky deliberately not a mitigation — existing comment already says why). On an
ancestor, the attack is **renaming the directory out from under the daemon** and
substituting another; the sticky bit blocks exactly that (only the entry's owner or
the directory's owner may rename/unlink). Without the exemption, any path below
`/tmp` (mode `1777`) — including the smoke-test state dir under `$XDG_CACHE_HOME`
fallbacks and every `tempfile::tempdir()` test fixture — would refuse, which is a
false positive the epic explicitly warns breeds override flags.

Alternative considered: refusing on sticky world-writable ancestors too. Rejected:
it makes `/tmp`-anchored dev setups impossible while adding no protection against
the rename attack sticky already blocks. (A *sibling-creation* attack — pre-creating
a colliding name in a sticky dir — requires the name to be free, which it is not:
our component exists.)

### D2 — Walk the existing ancestors of the absolutized path, stop at root

`absolutize` already resolves symlinks over the existing prefix, so the walk
operates on the real chain. Every existing ancestor from the path's parent up to
`/` is stat'ed; a metadata error on an ancestor refuses (fail closed, same as the
existing `Io` variant). For a path that does not fully exist yet (the audit log
before first open), the walk covers the ancestors that do exist — the ones an
attacker could act on today.

### D3 — The reload re-check lives in the watcher, not in `Engine::reload`

`cedar::engine` is meant to lift into a native upstream backend; mode-bit policy
belongs to the serve layer, exactly where the startup check already lives
(`run_serve`). The watcher becomes: event → drain debounce → `isolation` re-check →
`engine.reload()`. Symmetry argument: `Engine::bootstrap` does not run isolation
either — a caller embedding the engine without our serve layer never had these
checks, at startup or at reload, and gains no new seam from this change.

Alternative considered: a guard closure injected into `Engine::reload`. Rejected:
couples the engine to operational policy for no closed seam — the injected guard
would be optional by construction, which is the same seam wearing a costume.

### D4 — Refusal at reload keeps the last-known-good set

The in-memory set predates the loosening, so it is the only trusted policy state
left; dropping to 503 would turn a transient `chmod` into an outage (and D7 already
establishes fail-loud-keep-serving for broken edits). ERROR-level log names path and
mode. The watch thread survives, so repairing the mode and touching a file recovers
without a restart — asserted by a spec scenario.

### D5 — Shared check function, warnings stay startup-only

`isolation::check` keeps its signature (startup: refusals + cwd warnings). The
refusal core — directory, files, ancestors — is factored into a function the watcher
calls directly (no cwd warnings at reload: they are advisory posture messages, and
repeating them every debounce is noise that trains operators to filter ERROR-adjacent
output). Same errors, same `IsolationError` variants, one implementation — the
startup path and the reload path cannot drift apart.

## Risks / Trade-offs

- **[TOCTOU]** The re-check happens before `load_dir` re-reads the files; a
  loosening between check and read is not caught until the next event. → Accepted:
  the window shrinks from "forever after startup" to "one debounce"; mode bits were
  never a boundary against the agent, and the other-local-user attacker cannot time
  a race they do not control. Documented in the module docs.
- **[No event on ancestor chmod]** `notify` watches the policy dir, so an ancestor
  going loose does not itself trigger the re-check; it is caught at the next policy
  event. → Accepted and documented: watching every ancestor is platform-fragile
  (FSEvents/inotify semantics differ) and the startup check plus next-event re-check
  bound the exposure. Noted as a known limit, not silently.
- **[False refusal on deliberately shared setups]** A team dir with `g+w` and no
  sticky on an ancestor now refuses at startup. → The message names the exact path
  and mode; the remedy (`chmod go-w` or relocate) is actionable, and a shared-group
  policy dir was already refused directly — ancestors merely close the same hole.
- **[Watcher log level]** The reload refusal must be ERROR (a WARN would let the
  "adopted silently" failure recur one level down). Spec scenario pins it.

## Migration Plan

No config or wire change. Operators whose ancestor chain is loosely writable get a
startup refusal naming the path — the same fail-loud posture the direct-mode refusal
already has. Rollback is reverting the commit; no state migrates.

## Open Questions

None — the reload failure posture (keep last-good, ERROR) and the sticky semantics
were the two open points, settled in D1/D4 above.
