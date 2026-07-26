# Tasks: make-smoke-work-in-a-worktree

Tooling change: the deliverable is `just smoke` itself, so "the test" here is running
the recipe in both checkout shapes rather than a `cargo test` case.

## 1. Locate the failure correctly

- [x] 1.1 Reproduce from a worktree: `git status` exits 128 with `fatal: not a git repository`, *after* the PDP logged `allow=true matched=["10-git:git-read-only"]`. The PDP is not the failing component.
- [x] 1.2 First attempt — a run-level `nono run --read <git-common-dir>` — **rejected by measurement**. The grant appears in the capabilities banner (`r <primary>/.git (dir)`) and the run fails identically, because `git` executes in a nested tool sandbox composed from the command policy, not from run grants. Confirmed against pinned upstream v0.69.0 `crates/nono-cli/src/command_policy.rs`. Recorded in D1 so the next reader does not retry it.

## 2. Implement

- [x] 2.1 Detect a worktree by comparing `git rev-parse --absolute-git-dir` with the resolved `--git-common-dir`; equal means a normal checkout and the recipe is unchanged
- [x] 2.2 Generate the profile with `jq`, injecting the common git dir into both `.filesystem.read` and the git tool sandbox's `fs_read` (D1)
- [x] 2.3 Point `nono profile validate`, `nono profile show` and both `nono run` invocations at the generated profile, so the containment assertion inspects what the run actually uses (D2)
- [x] 2.4 Add the write-surface invariance assertion (D3)
- [x] 2.5 Avoid the `set -e` false-test trap on the normal-checkout path (D5)
- [x] 2.6 Record in the recipe why `index.lock` stays denied, so it is not read as a bug (D4)

## 3. Verify in both checkout shapes

- [x] 3.1 `just smoke` from inside a `wt` worktree: **SMOKE PASSED**, `git status` exit 0, allow from `10-git:git-read-only`, deny from `10-git:no-history-rewrites`
- [x] 3.2 `just smoke` from a normal clone of the same branch: **SMOKE PASSED**, and the worktree branch is correctly a no-op (no accommodation line printed)
- [x] 3.3 Mutation gate on the new assertion: change the `jq` filter to append to `fs_write` instead of `fs_read` — the recipe must fail naming that surface, before the daemon starts. It does. Reverted.
- [x] 3.4 `just lint` clean, including `lint-paths` (no real home path enters a tracked file — every path is computed at runtime)
- [x] 3.5 `just test` unaffected
- [x] 3.6 `openspec validate --changes make-smoke-work-in-a-worktree`

## 4. Land

- [x] 4.1 Merged to `main`, change archived, pushed to `internal` and `origin`
- [x] 4.2 #32 closed with the measurement that ruled out the command-line fix
