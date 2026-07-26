# Proposal: document-argv-drop-blind-spot

## Why

**#30 — an argument that is not valid UTF-8 is invisible to every policy we can
write, and one of the shipped pack's two code-execution layers fails open because of
it.**

nono does not lossily convert a non-UTF-8 argv entry when it builds an approval
request; it **drops the entry entirely**
(`filter_map(|a| std::str::from_utf8(a).ok()…)`, four call sites across
`tool-sandbox/platform/{macos,linux}.rs` at 0.69.0). Reported upstream and confirmed
by their triage; tracked privately as GHSA-p385-fvxh-xvgf.

The repo already knows a weaker version of this. `src/wire.rs` says positions shift,
and `10-git.cedar` repeats it, which is why `args` is a `Set` and why there is no
indexable form. That framing is **too weak**: the entry is not merely displaced, it is
*absent* — from `args` and from `argv_tail` alike. So a `forbid` that names an
argument does not over-deny or under-deny, it **never fires**, which is fail-open in
the one place this project treats as unacceptable.

Measured against the shipped pack, not reasoned about:

| Request as sent to us | Decision |
|---|---|
| `[shim, "--exec-path=/evil", "status"]` | **deny** — `no-code-executing-git-flags` |
| `[shim, "status"]` — what arrives when the value is non-UTF-8 | **allow** — `git-read-only` |
| `[shim, "-c", "status"]` — the `-c` layer after its value is dropped | **deny** — the layer survives |

So `git --exec-path=<dir whose name is not valid UTF-8> status` reaches us as a bare
`git status`, is approved by the anchored permit, and git then loads its subcommand
binaries from an attacker-controlled directory. The pack's stated "each of the two
layers denies on its own" holds for `-c` — the flag is its own argv entry and only its
*value* is dropped — but **not** for the four `--flag=<value>` spellings that share one
entry with their value and are matched by an `argv_tail` glob.

**This is not fixable at decision time, and that needs stating as a result rather than
an excuse.** The payload for `git --exec-path=<bad> status` and the payload for a plain
`git status` are byte-identical at our boundary; nothing in the webhook carries arity,
a checksum, or any residue of the dropped entry. No policy and no code we could write
distinguishes them. Until upstream preserves arity, honest disclosure is the whole of
the available response.

**#6 — the v1 audit findings live only in a `/private/tmp` scratchpad.** Thirty-two
findings from three adversarial passes, with the accepted-and-not-fixed items being
exactly the ones a future reader cannot reconstruct. An accepted risk that is not
written down is indistinguishable from an oversight, which is the distinction that
makes an audit trail worth keeping. #30 produces a first-class instance of precisely
that kind of item, so the two are done together: #30 needs a durable home, and #6 is
the home.

## What Changes

- **Say what is actually true about a dropped argument**, in the same words in every
  place that currently says the weaker thing: it is absent, not displaced; a `forbid`
  naming an argument fails **open**; an anchored `permit` still fires because
  `argv_tail` reads as the bare subcommand.
- **State the boundary of the claim**, so the reader is not left to over-generalise:
  membership on a flag that occupies its **own** argv entry (`-c`, `--force`) still
  holds, because the flag token is ASCII and only the adjacent value is dropped. What
  fails is a `--flag=<value>` entry whose value carries the invalid bytes.
- **Make the residual executable, not just prose.** A test in `tests/policies.rs`
  asserts the allow that the pack really returns for the post-drop payload, with the
  reason and the upstream reference in its name and doc comment. A prose-only residual
  rots; a test that would have to be deliberately deleted does not.
- **Prove the undecidability rather than asserting it** — the test pins that the
  post-drop payload is byte-identical to a legitimate `git status`, which is why no
  decision-time mitigation exists.
- **Stand up `docs/audits/` as the accepted-risk register** (#6), seeded with the
  curated v1 findings and with #30's residual as its first entry under the
  upstream-caused heading.
- **Pin the new wording in `tests/docs.rs`**, the same standard already applied to the
  other never-overstate rules.

Deliberately **not** included, with reasons:

- **No policy-pack change.** There is nothing to change it *to*: the two inputs are
  indistinguishable at our boundary. Adding a `command`-only forbid for git would deny
  every git invocation, and loosening or tightening the anchor cannot see a token that
  is not there. A change that merely looks like a mitigation would be worse than the
  documented residual, because it would retire the warning without retiring the risk.
- **No attempt to infer arity.** Nothing in the payload supports it. `intercept_rule`
  is built from the *profile rule's* arguments, not the request's argv, so it carries
  no residue of the dropped entry.
- **No re-litigation of `args` as a `Set`.** The set shape is still right, and this
  finding strengthens rather than weakens it.

## Capabilities

### New Capabilities

None.

### Modified Capabilities

- `cedar-policy-evaluation`: the argument-matching hazards requirement gains the third
  hazard — a dropped argument is unmatchable by any test, so an argument-naming
  `forbid` fails open — recorded as an inherent limit of the input rather than a lint,
  because the loader cannot detect it either.
- `pdp-operations`: the shipped-pack requirement states which of its two layers
  survives the drop and which does not, so "neither layer is load-bearing alone" is no
  longer stated unconditionally; the decision-surface documentation requirement gains
  the blind spot; and a new requirement establishes the accepted-risk register.

## Impact

- `README.md`: the blind spot in the schema-caveats section; the residual in the
  security-posture section.
- `src/wire.rs`: the `args` doc comment stops saying only that positions shift.
- `policies/10-git.cedar`: the `no-history-rewrites` note and the two-layer rationale
  gain the boundary of what each layer survives.
- `tests/policies.rs`: the executable residual.
- `tests/docs.rs`: wording pins.
- `docs/audits/`: new, with the v1 register (#6).
- Gitea: closes #30 and #6. No code path changes; no behaviour change to any decision.
