# Proposal: make-smoke-work-in-a-worktree

## Why

Gitea #32. `just smoke` — the one check in this repo that verifies behaviour against a
real `nono run` rather than against the test suite — fails from inside a `wt` worktree,
and fails in the shape most likely to be misread:

```
... decision ... allow=true matched=["10-git:git-read-only"]
fatal: not a git repository: (null)
Command exited with code 128.
Sandbox denial: 6 paths blocked.
  <primary>/.git/worktrees/<branch>/HEAD (read)
```

The PDP is not involved. It returns allow, correctly, and `git` then fails on its own:
in a worktree `.git` is a pointer *file* whose real git directory lives under the
primary checkout, outside every grant the smoke profile makes. What an operator sees is
exit 128 on `git status` immediately under a Cedar decision, which reads as the policy
pack denying it.

`AGENTS.md` instructs agents to work in a `wt` worktree, and the house default moved
worktrees to `~/dev/worktrees/`, so this is now the **default** path for anyone working
here — not an edge case. The cost is a full smoke run plus a diagnosis, every time, on
the check whose entire purpose is to be trustworthy about reality.

## What Changes

- The smoke recipe derives the git directory from `git rev-parse --absolute-git-dir`
  and `--git-common-dir`. When they differ it is in a worktree, and it grants the
  common git directory **read-only**. When they are the same it is a normal checkout
  and the recipe is unchanged — the accommodation is a no-op there.
- The grant goes into a **generated** profile written next to the daemon's other smoke
  state, not onto the `nono run` command line. `git` runs in a nested tool sandbox
  whose filesystem comes from the command policy rather than from the run's own grants
  (upstream v0.69.0, `crates/nono-cli/src/command_policy.rs`), so a run-level `--read`
  appears in the capabilities banner and changes nothing for `git`. That was measured,
  not assumed: the first attempt did exactly that and failed identically.
- The containment assertion — no write grant may contain the policy directory or audit
  log — now reads the **generated** profile rather than the tracked example. That is
  strictly stronger: it inspects the profile the run actually uses.
- A new assertion pins that generation only ever adds *read* surfaces: `.filesystem.
  allow`, `.workdir.access` and the git tool sandbox's `fs_write` must stay
  byte-identical to the shipped profile.

## Capabilities

### New Capabilities

None.

### Modified Capabilities

- `pdp-operations`: "Keep the policy directory and audit log outside the agent-writable
  tree" gains the rule that any checkout-shape accommodation is read-only, and that the
  containment assertion runs against the profile the smoke run actually uses.

## Impact

- `Justfile` (`smoke` recipe only). No change to the daemon, the policy pack, or
  `examples/cedar-pdp-smoke.json`, which stays the tracked, human-readable artifact.
- Gitea: closes #32.

## Not done

- **No write grant for the worktree git directory.** nono still reports one blocked
  write, `<git-dir>/index.lock`, and `git status` exits 0 regardless, because the index
  refresh behind it is an optimisation git skips when it cannot take the lock. Granting
  write would place the sandboxed agent inside the primary checkout's git database to
  buy a tidier denial report and nothing else.
- **The tracked example profile is not modified.** The path is machine-specific, and
  `just lint-paths` fails the build on a real home path in a tracked file.
