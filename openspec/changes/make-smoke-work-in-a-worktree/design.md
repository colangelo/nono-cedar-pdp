# Design: make-smoke-work-in-a-worktree

## D1 — The grant belongs in the profile, not on the command line

The obvious fix is `nono run --read <git-common-dir>`, which keeps the tracked example
profile untouched. It does not work, and it fails in a way worth recording because it
looks like it worked: the capabilities banner gains the line

```
  r   <primary>/.git (dir)
```

and `git status` still exits 128 with the identical denial. `git` is not running in the
run's sandbox — it runs in a **nested tool sandbox** built from the command policy
(`command_policies.commands.git.from.session.sandbox`), which upstream composes
independently of the run's grants (v0.69.0,
`crates/nono-cli/src/command_policy.rs` — the sandbox spec and its `dedup_append`
merge). Run-level grants bound the outer sandbox; they do not extend the inner one.

So the recipe generates a profile with `jq`, injecting the path in two places:

- `.command_policies.commands.git.from.session.sandbox.fs_read` — what actually lets
  `git` resolve the repository;
- `.filesystem.read` — so the grant is visible to `nono profile show --format manifest`,
  which is what the containment assertion reads.

**Rejected — editing `examples/cedar-pdp-smoke.json`.** The path is machine-specific;
`just lint-paths` fails the build on a real home path in a tracked file, correctly. The
example stays the readable artifact an operator copies.

**Rejected — always generating, with no worktree branch.** Possible, but it would make
every run's profile a derived file and cost the "this is exactly the tracked example"
property in the common case for no gain. Deriving both git paths and comparing them
makes the accommodation a genuine no-op in a normal checkout.

## D2 — The containment assertion moves to the generated profile

The recipe's load-bearing check is that no write grant contains the policy directory or
audit log. It read `examples/cedar-pdp-smoke.json`. Once the run uses a *different*
file, that assertion is checking something the run does not use — a check that can pass
while the property it asserts is false.

Pointing it at the generated profile is strictly stronger and is the reason the top-level
`.filesystem.read` injection exists at all: it keeps everything the run is granted
visible to the same assertion.

## D3 — Read-only is asserted, not commented

"The generation only adds read grants" is a property of the `jq` filter, and `jq`
filters get edited. So the recipe pins it: `.filesystem.allow`, `.workdir.access` and
the git tool sandbox's `fs_write` must be byte-identical between the shipped and the
generated profile, and the recipe fails naming the surface otherwise.

Verified non-vacuous by mutation — changing the filter to append to `fs_write` instead
of `fs_read` produces:

```
FAIL: the generated smoke profile changed a write surface
      (.command_policies.commands.git.from.session.sandbox.fs_write)
```

before the daemon starts.

## D4 — `index.lock` stays denied

With read-only access, nono reports one blocked write: `<git-dir>/index.lock`. `git
status` exits 0 anyway — the index refresh behind that lock is an optimisation git skips
when it cannot take it.

Granting write would clear the report and buy nothing, at the cost of putting the
sandboxed agent inside the primary checkout's git database. Recorded in the recipe so
the next reader does not file it as a bug, and left denied.

## D5 — `set -e` and the false-test idiom

`[ "$a" != "$b" ] && VAR=…` is the natural way to write the worktree test and is a trap
under `set -euo pipefail`: on the normal-checkout path the test is false, the compound
returns non-zero, and the recipe exits before doing anything. Written as a full `if`
instead. Called out because the failure would only ever appear in the *non*-worktree
case — the one less likely to be exercised while developing this.

## Risks

- The generated profile lands in the smoke state directory alongside `policy_dir` and
  the audit log. It is written by the recipe on every run, so a stale one cannot
  persist, and it is not itself a grant target.
- A future upstream change that makes run-level grants extend tool sandboxes would make
  the two-place injection redundant but not wrong.
