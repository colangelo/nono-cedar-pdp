# v1 implementation audit — 2026-07-25

Three adversarial passes over the v1 implementation, run as independent auditors with
different briefs, producing **32 findings** with evidence.

| Pass | Brief | Verdict |
|---|---|---|
| spec-coverage | does a test exist for every spec scenario? | **fail** — 15 findings |
| deviations-honesty | does the record describe what was actually built? | pass — 8 findings |
| security | can the thing be defeated? | **fail** — 9 findings |

Two passes returning *fail* on a suite that was green is the useful part: the tests
agreed with each other and disagreed with reality. That is the recurring failure mode in
this project and the reason `just smoke` runs a real `nono run`.

Findings are numbered F01–F32 in the order the passes produced them. The raw
finding/evidence pairs were recovered from the session that produced them; claims are
preserved, and every "fixed" below was re-verified against the current tree rather than
taken from the record.

---

## Fixed

### The four that mattered

**F24 (critical) — the PDP's own state sat inside the agent-writable tree.**
The shipped `nono-cedar-pdp.toml` put the hot-reloaded policy directory and the audit log
where the sandboxed agent had write access, so the agent could rewrite the policies
deciding its own approvals, and the swap was logged only at INFO. Closed by
`2026-07-26-harden-policy-dir-isolation`: shipped defaults are home-anchored, the state
paths are checked at startup **and** before adopting a reloaded set, and `just serve-dev`
is the repo-relative variant that warns loudly. This is also why AGENTS.md leads with it.

**F26 (major) — the shipped read-only git permit approved arbitrary code execution.**
`resource.args.contains("status")` is true of `git -c core.fsmonitor=<cmd> status`, and
git runs `<cmd>`. Set membership cannot express position. Closed by replacing it with an
anchored `argv_tail` test plus an independent `forbid` on the code-executing flags, and by
a loader lint that reports the mistake. Pinned by `tests/policies.rs`.

**F27 (major) — endpoint paths reached policies raw.**
`resource.path like "/repos/*"` was satisfied by `/repos/../user/keys`. Closed by denying
ambiguous paths outright, before any policy is consulted, rather than normalising and
guessing at the upstream's rules. Refinements tracked and closed as #22.

**F28 (minor by label, severe in effect) — `args[0]` was modelled as the command name.**
nono really sends an absolute per-run shim path, so every start-anchored argv pattern
silently never fired — fail-safe in a `permit`, **fail-open in a `forbid`**. The fixture
corpus had been built from upstream's *unit-test* fixture, which never reaches a webhook.
Closed by removing the whole-argv attribute from the schema entirely (a policy reading
`resource.argv` now fails strict validation), exporting `EXAMPLE_SHIM_ARGV0` so every
fixture asserts the runtime shape, and anchoring on `argv_tail`.

### Coverage gaps (F01–F15, F22)

Fifteen spec scenarios had no test, including both fail-closed startup paths (F01, F02),
the `validate`/`check` subcommands (F03, F22), any test that actually bound a socket
(F04), the audit line's `matched` and `eval_us` (F05), endpoint approvals over HTTP
(F06), and the documentation scenarios (F15). Several others asserted an error *type*
where the scenario required an error *naming* the problem (F09, F10), or proved a
behaviour through the wrong path (F11, F12, F14).

Closed by `2026-07-26-close-audit-and-loader-gaps` and the changes around it. Re-verified:
`tests/cli.rs` drives `validate` and `check` with exit codes, `tests/server.rs` binds a
real listener and asserts `matched`/`eval_us`, and `src/audit.rs` has a behavioural test
that an unwritable log changes neither the decision nor the response.

### The rest

- **F07, F16 — the "Paranoid" rollout posture named a backend the shipped profile did not
  define**, so following the README produced a profile nono rejects. Closed by defining
  `cedar-and-ask` in `examples/cedar-pdp-smoke.json`, and by `tests/docs.rs` asserting
  both directions — every documented posture exists in the profile and vice versa.
- **F19 — `load_dir` silently dropped `.cedar` files whose name starts with `.` or `#`.**
  A policy the operator wrote that decides nothing is a hole with no trace. Now each skip
  is a WARN naming the path and reason. Related: #26, unreadable directory entries now
  fail the load rather than being dropped.
- **F23 — `Engine::from_loaded` was a public constructor bypassing the zero-policy
  guard.** Now `pub(crate) from_loaded_unchecked`; `tests/public_api.rs` guards the
  surface. Related: #27.
- **F25 — the audit fd was opened once and never revalidated**, so a rotation silently
  detached the trail while `/healthz` stayed green. Now the daemon notices and reopens.
- **F30 — `/v1/approve` accepted unauthenticated audit-record injection** (#8) and
  **F31 — the INFO decision line copied full command lines to stdout** (#9). Both closed
  by `2026-07-26-harden-decide-endpoint-surface`. The remote vector is closed rather than
  mitigated; the local one is not, and is recorded below as accepted.

---

## Accepted — ours

### A01 — the v1 task record overstates in four places (F17, F18, F20, F21)

Ticked checkboxes in `openspec/changes/add-cedar-pdp-v1/tasks.md` describe things
slightly differently from what shipped: task 8.2 records `Bytes` where the handler takes
`axum::body::Body` and buffers itself (F17); task 10.4 records a simpler smoke invocation
than the stricter one shipped (F18); several verification numbers no longer reproduce
because later `fix:` commits added tests, though they were true when ticked (F20); and
commit `4088ff2` claims a starter policy pack that had actually landed four commits
earlier in `0d5fa08` (F21).

**Why accepted.** These are the historical record of a completed and archived change.
Editing an archived artifact to make a past claim retroactively true is worse than the
inaccuracy — it destroys the audit trail's only useful property. The commit message
cannot be rewritten without rewriting published history.

**What would close it.** Nothing, by design. The mitigation is forward-looking and
already in place: task records are amended when the implementation deviates (task 10.5
was, which is how the divergence was noticed at all), and this entry is where the known
inaccuracies are recorded instead.

### A02 — the webhook is unauthenticated in the local direction (F30, residual)

The header checks close the *remote* case completely: requiring
`Content-Type: application/json` forces a CORS preflight the daemon fails, so a page an
operator merely visits cannot reach the endpoint. What remains is fully open — a local
process running as the same user can present the right content-type, omit `Origin`, set
`User-Agent: nono-cli/<version>`, and forge an audit record indistinguishable from a real
one. The recorded `User-Agent` is **evidence, not verification**.

**Why accepted.** It is not closable here. Verified against nono 0.69.0
(`crates/nono-cli/src/approval_runtime.rs`): the webhook POST carries exactly two headers
and the config has no field for a token or custom headers. A shared secret is
*impossible* today, not merely unimplemented. Peer-credential checking needs a Unix
socket — macOS exposes no peer uid for TCP loopback.

**What would close it.** Upstream support for a bearer token or a Unix socket (#13), or
https on loopback with a locally-trusted certificate (#5), which at least makes a port
squatter without the key fail TLS.

**Pinned by.** `tests/docs.rs` asserts the README still says "none of this authenticates
nono" and that the `User-Agent` is "not verification" — the wording is the control here,
because the risk is a reader believing the checks buy more than they do.

### A03 — known-open minors, tracked rather than fixed

- **F29 → #7.** `/healthz` is unauthenticated and discloses the absolute policy directory
  path — precisely the target for F24 — while omitting the load time (`loaded_at` is
  written and, re-verified, still never read) and the last reload error, so a failed
  hot-reload stays 200/OK and is invisible to monitoring.
- **F32 → #10.** The watcher's debounce drain has no upper bound, so a continuous event
  stream postpones every reload for as long as it lasts.

**Why accepted for now.** Both are real and neither is a decision-correctness defect:
the daemon still fails closed in every case. They are ordered behind the trust-boundary
work rather than dismissed.

---

## Accepted — not ours to fix

### U01 — a non-UTF-8 argv entry never reaches us, so a `forbid` naming it fails open

**The finding.** nono builds the approval request's `args` by *discarding* every argv
entry that fails UTF-8 validation rather than converting it
(`filter_map(|a| std::str::from_utf8(a).ok()…)`, four call sites across
`tool-sandbox/platform/{macos,linux}.rs` at 0.69.0). The entry is dropped **whole**, so it
is absent from `args` and from `argv_tail` alike — not merely displaced, which is all this
repo used to claim.

**Measured against the shipped pack**, not reasoned about:

| Request as we receive it | Decision |
|---|---|
| `[shim, "--exec-path=/evil", "status"]` | deny — `10-git:no-code-executing-git-flags` |
| `[shim, "status"]` — what arrives when that value is not valid UTF-8 | **allow** — `10-git:git-read-only` |
| `[shim, "-c", "status"]` — the `-c` layer after its value is dropped | deny — the layer survives |

So `git --exec-path=<dir whose name is not valid UTF-8> status` reaches this daemon as a
bare `git status` and is approved. Whether a rule survives depends on one thing: does it
match bytes sharing an argv entry with the invalid bytes? Membership on a flag that
occupies its own argv entry survives; a glob over a `--flag=<value>` entry does not.

**Why it is not ours to fix, and why that is a result rather than an excuse.** The
post-drop request is **byte-identical** to one produced by a plain `git status`. Every
other field is either independent of argv or derived from the profile — `intercept_rule`
comes from the matched rule's own arguments, not from the request. A decision function is
a function of its input; two identical inputs cannot yield two decisions. So any rule that
denied the hostile request would also deny the legitimate one, i.e. deny the invocation
the pack exists to approve. No policy, schema change or code at this boundary separates
them.

**What would close it.** Upstream preserving arity — `String::from_utf8_lossy` instead of
the `filter_map`, which is what the audit path in the *same files* already does
(`fn argv_display`). Reported privately as **GHSA-p385-fvxh-xvgf** (their `SECURITY.md`
forbids public issues for vulnerabilities). Once it lands, the pre-drop argv is what we
receive and the existing `forbid` fires unchanged — **no change is needed here**, which is
why this is filed as not-ours rather than as work.

**Pinned by.** `tests/policies.rs`:
`a_dropped_argv_entry_defeats_the_glob_forbid_but_not_the_membership_forbid` asserts all
three decisions above, and
`a_dropped_argv_entry_leaves_a_request_indistinguishable_from_a_legitimate_one` derives
the collision by running upstream's own conversion over a real byte argv rather than
asserting it. Both fail if upstream starts preserving arity — deliberately: that failure
is the signal to close this entry.

**Tracked as.** #30. A second, unrelated defect found while reducing it — any non-UTF-8
argument aborts nono before it does anything (`std::env::args()` unwrap in
`cli_bootstrap.rs:22`, exit 134) — is not a vulnerability and was filed publicly as
nolabs-ai/nono#1504.

### U02 — nono sends a caller label, not a caller kind

`caller` is `"session"` for a direct agent launch, otherwise the name of the intercepted
command that chained it. A profile that intercepts a command literally named `session`
produces a payload indistinguishable from a direct launch.

**Why not ours.** Disambiguating needs a distinct field on the wire.

**What would close it.** An upstream field carrying the caller *kind* alongside the label.
Not currently filed — the collision requires an operator to intercept a command named
exactly `session`, so it is documented rather than escalated.

---

## Claims the auditors could not verify

Recorded because an unverified claim presented as a finding is its own defect:

- Whether `api.github.com` normalises `/repos/../user/keys` to `/user/keys` was never
  tested against the live upstream. The PDP-side wrong-allow was proven; the completion of
  that escape depends on origin behaviour. This did not affect the fix, which denies
  ambiguity rather than predicting the upstream.
- The TDD ordering claimed by the v1 task checkboxes cannot be confirmed from git: each
  task group is a single commit containing tests and implementation together. The claim is
  neither confirmed nor refuted by the record.
- Which validator the "documented profile is accepted by nono" scenario means — the
  `nono profile validate` CLI, or the in-crate manifest API, which rejects the profile for
  a missing `version` field because a capability manifest is a different artifact. The
  evidence rests on the installed CLI.
