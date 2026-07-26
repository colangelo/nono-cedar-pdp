# Tasks: harden-the-health-surface

TDD throughout. `just test` must pass full and filtered; `just smoke` must still pass —
its healthz probe is the one that proves a real client is unaffected by the field change.

## 1. Re-point the D7 proof before removing its observable

Deliberately first. Removing `policy_dir` while the symlink test still reads it would mean
either a red suite or, worse, deleting the assertion and quietly losing the proof.

- [ ] 1.1 Move `a_symlinked_policy_dir_is_resolved_before_serving` onto the `files` array of the `policy-set` audit line: every loaded path must sit under the resolved real directory and none may contain the symlink component (D4)
- [ ] 1.2 Confirm it still fails when the resolution is broken — this is the D7 regression guard, not a formality

## 2. The reload status cell

- [ ] 2.1 Failing test: `/healthz` reports a null last-reload outcome on a daemon that has not reloaded (D2)
- [ ] 2.2 Failing test: after an adopted reload, the outcome is `loaded` with a timestamp
- [ ] 2.3 Failing test: after a refused reload, the outcome is `refused` and the generation and count still describe the last-known-good set
- [ ] 2.4 Failing test: after a failed reload, the outcome is `failed`
- [ ] 2.5 Failing test: a daemon whose last reload failed still answers **200** (D5) — the case a future reader is most likely to "fix" the wrong way
- [ ] 2.6 Implement: `ArcSwapOption` cell updated from `Provenance`, so one call updates the trail and the health surface and they cannot disagree (D3)

## 3. The disclosure fix

- [ ] 3.1 Failing test: the healthz body contains neither the policy directory string, nor any `.cedar` path, nor reload-error text — asserted on a daemon whose reload was **refused**, since that is where an error string would leak back in
- [ ] 3.2 Implement: drop `policy_dir`, add `loaded_at` (RFC 3339 UTC — the first reader `loaded_at` has ever had)
- [ ] 3.3 Confirm nothing else reads the field (`grep -rn policy_dir`)

## 4. Documentation

- [ ] 4.1 README: the healthz section documents the new body and states plainly that the absent path is deliberate, so it is not re-added as a convenience
- [ ] 4.2 Design doc §7 pointer, matching the correction-trail convention used by D12/D13

## 5. Verify

- [ ] 5.1 Non-vacuity gate: make the health handler ignore the reload status and confirm 2.3 goes red; re-add the path and confirm 3.1 goes red. Commit first.
- [ ] 5.2 `just test` full and filtered
- [ ] 5.3 `just lint` clean
- [ ] 5.4 `just smoke` against real nono — its healthz probe must be unaffected
- [ ] 5.5 `openspec validate --changes harden-the-health-surface`
- [ ] 5.6 Merge, archive, push to `internal` and `origin`, close #7
