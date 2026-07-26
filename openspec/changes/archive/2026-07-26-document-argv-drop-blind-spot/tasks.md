# Tasks: document-argv-drop-blind-spot

No decision path changes in this change. The executable work is assertions: the pack's
real decisions under the drop, and the wording pins. TDD still applies — write the
assertion, RUN it, watch it fail for the right reason, then make it true. `just test`
must pass full **and** filtered (`cargo test --test policies`, `cargo test --test docs`)
— see `src/test_log.rs` for the tracing max-level trap that once made filtered runs lie.

## 1. Pin the decisions the pack really makes under the drop (#30)

- [x] 1.1 Failing test in `tests/policies.rs`: `[shim, "--exec-path=/evil", "status"]` — the argv when every entry is valid UTF-8 — is **denied** and the matched list names `10-git:no-code-executing-git-flags`
- [x] 1.2 Failing test: `[shim, "status"]` — what arrives once a non-UTF-8 `--exec-path=` value is dropped — is **allowed** and the matched list names `10-git:git-read-only`. Doc comment carries the reason, the upstream reference, and why an asserted allow is correct here
- [x] 1.3 Failing test: `[shim, "-c", "status"]` — what arrives once a non-UTF-8 `-c` *value* is dropped — is **denied** by the flag forbid, pinning that this layer survives
- [x] 1.4 Failing test: the post-drop payload is byte-identical to the payload a plain `git status` produces, which is the proof that no rule can separate them
- [x] 1.5 Confirm all four fail for the right reason before touching anything else — 1.1/1.3 should already pass, 1.2/1.4 are the new claims. A test that passes immediately is only evidence once you have seen what makes it fail

## 2. Stop understating the hazard where the repo already mentions it (#30)

- [x] 2.1 Failing wording pins in `tests/docs.rs` for the new README passages: dropped-not-converted, absent from both attributes, fail-open in a `forbid`, which shapes survive, and that it closes only upstream
- [x] 2.2 `README.md` schema-caveats section: the blind spot, with the survives/does-not-survive table and the indistinguishability argument
- [x] 2.3 `README.md` security-posture section: the residual stated as a limit of the input, cross-referencing the register
- [x] 2.4 `src/wire.rs`: extend the `args` doc comment — keep "positions shift" (still true, still the reason `args` is a `Set`), add that the entry is absent entirely so a `forbid` naming it fails open
- [x] 2.5 `policies/10-git.cedar`: amend the `no-history-rewrites` note and the two-layer rationale to say which layer survives the drop and which does not
- [x] 2.6 Re-run the pins; confirm each fails before its passage exists

## 3. Stand up the accepted-risk register (#6)

- [x] 3.1 `docs/audits/README.md`: what the register is for, the three categories, and the rule that every accepted entry states what would close it
- [x] 3.2 `docs/audits/2026-07-25-v1-implementation-audit.md`: the curated v1 findings — criticals and majors as fixed-with-their-fix, minors that became issues as pointers to Gitea rather than restatements
- [x] 3.3 Add #30's residual as the first not-ours-to-fix entry: the finding, the measurement, why it is not fixable here, the upstream reference, what closes it, and the test that pins it
- [ ] 3.4 **Deferred, not done.** `AGENTS.md` docs table should gain a `docs/audits/` row,
  but the file had uncommitted changes from parallel work and the instruction was not to
  commit it. Adding the row would have left a mixed edit in someone else's file. The
  register is still reachable from `README.md` (twice) and from `src/wire.rs`

## 4. Verify against reality, not only the suite

- [x] 4.1 `just test` full, then filtered per suite. Surfaced a pre-existing intermittent
  failure in the mid-session loosening watcher tests — reproduced at `81a7f04`, so not
  from this change; filed with evidence and a mechanism as #31 rather than dismissed
- [x] 4.2 `just lint` clean (clippy `-D warnings`)
- [x] 4.3 `just smoke` still green — the pack changed only in comments, so a regression here means something else moved
- [x] 4.4 Re-read the README diff as a policy author would: does it tell someone what they can no longer rely on, without implying a care they could take that would help?

## 5. Land it

- [x] 5.1 `openspec validate --changes document-argv-drop-blind-spot`
- [x] 5.2 Granular conventional commits, `Co-Authored-By` trailer
- [x] 5.3 Push to `internal` **and** `origin`
- [x] 5.4 Close #30 and #6 with the evidence and the register link
