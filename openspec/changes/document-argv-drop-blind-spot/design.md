# Design: document-argv-drop-blind-spot

## D1 — Why this is documentation and not a fix

The tempting reading of #30 is "our policy is wrong, tighten it". It is not, and the
argument is short enough to be checked rather than believed.

Take the two invocations:

```
A.  git --exec-path=<dir whose name is not valid UTF-8> status
B.  git status
```

Upstream builds the approval request's `args` by dropping every argv entry that fails
UTF-8 validation. `--exec-path=<bad>` is **one** argv entry, so A loses it whole. What
reaches the webhook is:

```jsonc
// A, after the drop
{"command":"git","args":["<shim path>","status"], ...}
// B
{"command":"git","args":["<shim path>","status"], ...}
```

These are the same bytes. Not similar — identical. Every other field is either
independent of argv (`command`, `caller`, `child_pid`, `session_id`) or derived from
the profile rather than the request (`intercept_rule` comes from the matched rule's own
arguments via upstream's `rule_label()`, not from the argv).

A decision function is a function of its input. Two identical inputs cannot produce two
decisions. Therefore **no policy, no schema change, and no code in this daemon can
separate A from B.** Denying A necessarily denies B, i.e. denies plain `git status`,
which is the invocation the pack exists to approve.

That is why the response is disclosure. It is not that a mitigation is expensive; it is
that a mitigation does not exist at this boundary. The fix belongs where the
information was destroyed — upstream, one line per call site, `from_utf8_lossy` instead
of `filter_map` — which is filed as GHSA-p385-fvxh-xvgf.

**Consequence for how we write it down:** the documentation must not say "be careful",
because there is no care the reader can take. It must say what is unmatchable and what
therefore cannot be relied upon.

## D2 — The boundary of the claim: which layer actually survives

Overstating this would be its own defect, so the scope is stated precisely and pinned
by a test.

A dropped entry is dropped *whole*. The question for any given rule is therefore
whether the bytes it matches on live in the **same** argv entry as the invalid bytes.

| Shape | Example | Survives the drop? | Why |
|---|---|---|---|
| Membership on a flag that is its own entry | `args.contains("-c")`, `args.contains("--force")` | **Yes** | The flag token is ASCII and a separate entry; only the adjacent *value* entry is dropped |
| `argv_tail` glob on a `--flag=<value>` entry | `argv_tail like "*--exec-path*"` | **No** | Flag and value share one entry, so an invalid value takes the flag with it |
| Anchored `argv_tail` permit | `argv_tail == "status"` | Fires anyway | After the drop the tail *is* the bare subcommand |

So the pack's stated "each of the two layers denies the code-execution invocation on
its own" is true for `-c` and false for `--config-env=`, `--exec-path=`,
`--upload-pack=`, `--receive-pack=`. The requirement is amended to say so rather than
keeping an unconditional claim that measurement contradicts.

Measured, not assumed — the three payloads are run through the real evaluator in
`tests/policies.rs`.

## D3 — Why the residual gets a test and not only prose

This repo has already been bitten by a residual that was true when written and quietly
became false, and by prose that overstated a guarantee. Both are why `tests/docs.rs`
exists.

A prose residual has no failure mode: nothing breaks when it stops being true. So the
accepted risk is recorded as an **assertion about the decision the pack really makes**
— the post-drop payload allows, and the pre-drop payload denies. Two things follow:

- If someone later "hardens" the pack in a way that changes either decision, the test
  fails and they have to engage with the register entry rather than discovering it
  afterwards.
- When upstream ships the fix, the *pre-drop* payload is what we will start receiving,
  and the test that pins its deny is exactly the evidence that the residual closed. The
  test does not need rewriting to become the proof — that is deliberate.

The test asserts an **allow**, which reads wrong at a glance. Its name and doc comment
therefore carry the reason and the upstream identifier, so a reader who finds it while
grepping for a fail-open lands on the explanation and not on a bug report.

## D4 — Where the register lives, and what goes in it (#6)

`docs/audits/` beside the existing `docs/adr/` and `docs/research/`, because it is the
same kind of artifact: a decision with its reasoning, durable, and referenced from
`AGENTS.md`'s docs table.

The register's organising principle is the distinction that makes it worth keeping —
**fixed**, **accepted**, and **accepted because it is not ours to fix**. #30 is the
first entry in the third category and the reason the category exists; the v1 findings
supply the first two. Each accepted entry carries what would have to change for it to
close, so an entry is falsifiable rather than a permanent shrug.

The v1 findings are curated rather than dumped: the criticals and majors are already
fixed and are recorded as history with their fix, and the minors that became backlog
issues are recorded as pointers rather than duplicated, so the register does not drift
out of sync with Gitea.

## D5 — Wording, stated once and reused

The same sentence goes in `README.md`, `src/wire.rs`, `policies/10-git.cedar` and the
register, and `tests/docs.rs` pins the load-bearing fragments:

> An argv entry that is not valid UTF-8 is **dropped, not converted**, so it is absent
> from `args` and from `argv_tail`. A rule that names an argument cannot match one it
> cannot see: in a `forbid` that is fail-open.

The existing weaker sentence ("positions shift") is not deleted — it is still true and
still the reason `args` is a `Set` — it is *extended*, so the rationale for the set
shape does not lose its stated cause.
