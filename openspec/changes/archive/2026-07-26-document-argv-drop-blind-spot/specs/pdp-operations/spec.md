# pdp-operations — delta for document-argv-drop-blind-spot

## MODIFIED Requirements

### Requirement: The shipped policy pack approves a subcommand by position, not by word

A fresh install inherits the shipped pack's posture, so the pack is product surface rather
than an example. Its read-only git permit SHALL identify the subcommand **positionally**,
by an anchored `resource.argv_tail` test, and SHALL NOT approve on set membership of a
subcommand word: `resource.args.contains("status")` is true of
`git -c core.fsmonitor=<cmd> status`, and git runs `<cmd>`, so a membership permit
approves arbitrary command execution. Anchoring also denies otherwise read-only
invocations that place a flag before the subcommand; that is the intended direction for a
permit, and the documented `chain`/`any` posture turns such a denial into a prompt.

Independently of the permit, the pack SHALL `forbid` the git flags that execute a command
or relocate the binaries git executes — `-c`, `--config-env`, `--exec-path`,
`--upload-pack`, `--receive-pack` — using exact `args` membership where the value is a
separate argv entry and an `argv_tail` glob where git accepts a `--flag=<value>` spelling
that membership cannot see. Each of the two layers SHALL deny the code-execution
invocation on its own **for every argv the daemon can observe**, so neither is
load-bearing alone, and the pack SHALL load without tripping any of the loader's own
lints.

That qualification is load-bearing and SHALL NOT be dropped. Upstream discards an argv
entry that is not valid UTF-8 instead of converting it, and the entry is discarded whole.
The two layers therefore behave differently under that loss, and the difference SHALL be
recorded rather than averaged over:

- The `-c` layer **survives**, because git requires `-c` to take its value as a separate
  argv entry: the invalid bytes are confined to the value, the ASCII `-c` entry remains,
  and exact membership still matches.
- The `--flag=<value>` layer **does not survive**, because flag and value share one entry,
  so an invalid value removes the flag from `args` and from `argv_tail` together. The
  `argv_tail` glob then has nothing to match and the anchored permit approves, since the
  tail reads as the bare subcommand.

The pack SHALL NOT be changed in an attempt to close this. The post-drop request is
byte-identical to a legitimate request that never carried the flag, so any rule denying
the former denies the latter — that is, denies the read-only invocation the pack exists to
approve. The gap SHALL instead be recorded in the accepted-risk register and pinned by a
test asserting the decision the pack really makes, so that a later change to either
decision is visible rather than silent.

#### Scenario: A config-injecting flag before a read-only subcommand is denied

- **WHEN** an approval request carries `command` `git` and `args` `[<shim path>, "-c", "core.fsmonitor=<cmd>", "status"]`
- **THEN** the decision is deny, and the matched-policy list names the flag `forbid`

#### Scenario: Each layer holds with the other removed

- **WHEN** the flag `forbid` is removed from the loaded pack and the same request is evaluated
- **THEN** the decision is deny with an empty matched-policy list, because the anchored permit cannot fire when the subcommand is not first
- **AND WHEN** the anchored permit is instead replaced by a membership-shaped permit (`resource.args.contains("status")`)
- **THEN** the decision is still deny and the matched-policy list names the flag `forbid`

#### Scenario: Read-only invocations are still approved

- **WHEN** an approval request carries `args` `[<shim path>, "status"]`, `[<shim path>, "status", "--porcelain"]`, `[<shim path>, "log", "-n", "5"]` or `[<shim path>, "show", "HEAD"]`
- **THEN** the decision is allow and the matched-policy list names the read-only permit

#### Scenario: A read-only word elsewhere in the argv approves nothing

- **WHEN** an approval request carries `args` `[<shim path>, "commit", "-m", "status"]`, `[<shim path>, "commit", "--amend", "-m", "log"]`, `[<shim path>, "reset", "--soft", "status"]` or `[<shim path>, "clone", "ext::sh -c evil", "status"]`
- **THEN** the decision is deny and the read-only permit is not among the matched policies

#### Scenario: The dropped-argument gap is pinned as the decision it really produces

- **WHEN** an approval request carries `args` `[<shim path>, "--exec-path=/evil", "status"]`, the argv as sent when every entry is valid UTF-8
- **THEN** the decision is deny and the matched-policy list names the flag `forbid`
- **AND WHEN** the request instead carries `args` `[<shim path>, "status"]`, which is what arrives when that entry's value was not valid UTF-8 and upstream dropped it
- **THEN** the decision is allow and the matched-policy list names the read-only permit, and that payload is identical to the one a plain `git status` produces, which is why no rule can separate them
- **AND WHEN** the request carries `args` `[<shim path>, "-c", "status"]`, which is what arrives when a `-c` value was not valid UTF-8
- **THEN** the decision is deny and the matched-policy list names the flag `forbid`, because that layer's match does not share an argv entry with the dropped value

### Requirement: Document the decision-surface limits and known risks

The project documentation SHALL state the limits that follow from nono's contract: only `command` and `endpoint` approvals reach the daemon; filesystem capability elevation cannot be arbitrated; argument positions are untrustworthy so `args` is a set; an argv entry that is not valid UTF-8 is dropped rather than converted, so it is absent from both `args` and `argv_tail` and a rule naming an argument cannot match one it cannot see — fail-open in a `forbid`, and not avoidable by careful authoring because the post-drop request is indistinguishable from one that never carried the argument; `args[0]` is an absolute per-run shim path rather than the command name, so the command name is read from `command`, there is no whole-argv attribute at all, and anchored patterns belong on `argv_tail`; set membership cannot express position, so a subcommand is pinned with an anchored `argv_tail` test and a membership permit on a subcommand word approves far more than it names; *unanchored* `argv_tail` globs over-match text inside a single argument and are therefore safe only in `forbid`; endpoint paths arrive raw and unnormalised, so an ambiguous path is denied outright; endpoint requests carry no session identity; and the webhook is unauthenticated in both directions, so the daemon must bind loopback only.

#### Scenario: Argument-matching guidance is documented

- **WHEN** a policy author consults the documentation on matching command arguments
- **THEN** they are told to test flags by set membership rather than by position, to pin a subcommand with an anchored `argv_tail` test (`== "status"` or `like "status *"`) because membership cannot express position, and that an `argv_tail` glob beginning with a wildcard belongs only in a `forbid`

#### Scenario: The dropped-argument blind spot is documented

- **WHEN** a policy author consults the documentation on what `args` and `argv_tail` can be relied upon to contain
- **THEN** they are told that an argv entry which is not valid UTF-8 is dropped rather than lossily converted, that it is therefore absent from both attributes, that a `forbid` naming such an argument does not fire and is fail-open, and that an anchored `permit` still approves because the tail reads as the bare subcommand
- **AND** they are told which shapes survive it — membership on a flag occupying its own argv entry — and which do not — a glob over a `--flag=<value>` entry whose value carries the invalid bytes
- **AND** the documentation states that this is not fixable at the decision boundary, because the post-drop request is byte-identical to a legitimate one, and names preserving arity upstream as the only close

#### Scenario: The raw-path caveat is documented

- **WHEN** a policy author consults the documentation on matching `resource.path`
- **THEN** they are told the path is the raw request target (unnormalised, still percent-encoded, query string included), that the daemon does not normalise it, and that a path whose meaning depends on normalisation — a `.`/`..` segment at any decode depth, an undecodable escape — is denied before any policy is consulted

#### Scenario: The shim-path shape of args[0] is documented

- **WHEN** a policy author consults the documentation on the payload nono sends
- **THEN** the example payload shows `args[0]` as an absolute per-run shim path, and the documentation states that `command` carries the command name, that a pattern anchored over the whole argv could never match at runtime — fail-safe in a `permit` and fail-open in a `forbid` — that the whole-argv attribute is therefore removed rather than deprecated (a policy reading `resource.argv` fails validation), and that `argv_tail` is the anchoring target

#### Scenario: Impersonation risk is documented

- **WHEN** an operator reviews the security posture
- **THEN** the documentation states that nono cannot authenticate the decider, that binding is loopback-only for that reason, and that https-on-loopback is the planned mitigation

## ADDED Requirements

### Requirement: Maintain a durable in-repo register of accepted risks

Findings that were reviewed and deliberately **not** fixed SHALL be recorded in the
repository, not left in session scratch or in an issue tracker alone. An accepted risk
that is not written down is indistinguishable from an oversight, and that distinction is
the whole value of an audit trail.

The register SHALL separate what was **fixed**, what was **accepted as ours and not
fixed**, and what was **accepted because it is not ours to fix** — an upstream defect or a
property of the contract we consume. The third category exists because its entries close
by someone else's action, so they need a different follow-up than the second.

Every accepted entry SHALL state what would have to change for it to close, so that the
entry is falsifiable and a later reader can tell a still-live risk from a stale one.
Entries that became tracked work SHALL reference the tracking item rather than restating
it, so the register cannot drift out of sync with the backlog.

Where an accepted risk can be expressed as an assertion about behaviour, the register
SHALL name the test that pins it, so that changing the behaviour requires engaging with
the register rather than discovering it afterwards.

#### Scenario: An accepted risk survives the session that found it

- **WHEN** a reviewer looks for the reasoning behind a known-unfixed finding
- **THEN** the register in the repository states the finding, why it was accepted, what would close it, and the tracking item or pinning test if either exists

#### Scenario: An upstream-caused residual is distinguishable from our own

- **WHEN** a reviewer reads an entry that this project cannot fix at its own boundary
- **THEN** the entry is filed under the not-ours-to-fix category, names the upstream defect it depends on, and states what changes here once that defect closes
