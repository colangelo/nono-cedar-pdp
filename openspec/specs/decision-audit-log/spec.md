# decision-audit-log

## Purpose

The record of what was decided. Because nono's webhook is unauthenticated in both
directions, this log is the compensating control: it is how anyone reconstructs what was asked,
who asked, what was decided, and which rule decided it. This capability owns the line format, the
file's permissions and its survival across rotation, and the rule that a logging failure never
changes a decision.
## Requirements
### Requirement: Record every decision as one JSONL line

The service SHALL append exactly one JSON object per line to the configured audit log for every decision it returns, including denials produced by malformed or unsupported input where a request context is available. Parent directories SHALL be created if absent.

The log SHALL carry more than one record shape, and every line SHALL name its shape in a
`kind` field. Two shapes in one stream without a discriminator force a consumer to infer
the shape from which keys happen to be present, which is the guessing the fixed key set
exists to prevent. The shapes are `decision` and `policy-set`.

#### Scenario: Two decisions produce two lines

- **WHEN** two approval requests are decided
- **THEN** the audit log contains exactly two lines, each independently parseable as JSON

#### Scenario: Missing parent directory is created

- **WHEN** the configured audit log path names a directory that does not exist
- **THEN** the directory is created and the log is opened successfully

#### Scenario: Every line names its shape

- **WHEN** any line is appended to the audit log
- **THEN** it carries a `kind` field naming its shape, so a consumer selects records by an explicit value rather than by inferring from which keys are present

### Requirement: Audit lines are self-sufficient for review

Each audit line SHALL carry an RFC 3339 UTC timestamp, the nono `request_id` and `session_id`, the approval backend name, the resolved agent, the Cedar principal, the action, a resource summary, the child pid, the intercept rule (for command requests) or route rule label (for endpoint requests), the observed `User-Agent`, the decision, the matched policy identifiers, the decision reason, and the evaluation time. This is sufficient to answer "what was asked, who asked, **what routed the request here**, **what the caller presented itself as**, what was decided, and which rule decided it" without consulting any other source. The key set SHALL be identical on every line **of a given `kind`**: a value the request did not carry is an explicit `null`, so a consumer can tell "not known" from "not recorded" — command lines carry a null `rule_label`, endpoint lines a null `intercept_rule`, and rejected-request lines null for all three of `child_pid`, `intercept_rule` and `rule_label`. `child_pid` SHALL record the value the wire carried for both request variants (real nono sends `0` for endpoint requests; a sender claiming otherwise leaves its claim on the record rather than having it silently rewritten). Request-derived text recorded in audit values — the intercept rule, rule label and User-Agent included — SHALL have control characters escaped at the recording boundary, the same rule the resource summary already follows: JSON string encoding escapes only C0 controls, so DEL and C1 controls (CSI among them) would otherwise reach an operator's terminal raw when the trail is read.

The `User-Agent` SHALL be recorded as **evidence, not verification**, and SHALL be described that way wherever it appears. A genuine request carries `nono-cli/<version>`; browser JavaScript cannot set the header at all; a local process can set it to anything. So a line whose User-Agent is absent or unexpected is a signal worth having, and a line whose User-Agent looks right proves nothing. Recording it SHALL NOT be presented as authenticating the caller.

#### Scenario: Audit line fields for a decided command request

- **WHEN** a `git status` command request from session `s1` on backend `cedar` with intercept rule `status` and child pid `42` is denied
- **THEN** the line records the RFC 3339 timestamp, `request_id`, `session_id` `s1`, backend `cedar`, the resolved agent, principal `Nono::Caller::"session"`, action `launchCommand`, a resource summary naming `git`, `child_pid` `42`, `intercept_rule` `status`, a null `rule_label`, the observed `user_agent`, decision `deny`, the matched policy identifiers, the reason, and the evaluation time

#### Scenario: Audit line fields for a decided endpoint request

- **WHEN** an endpoint request routed by rule label `endpoint_policy.approve[GET /repos/*]` with child pid `0` is decided
- **THEN** the line records `rule_label` exactly as sent, `child_pid` `0`, and a null `intercept_rule`

#### Scenario: The observed User-Agent is recorded as sent

- **WHEN** a request presents `User-Agent: nono-cli/0.69.0`
- **THEN** the audit line records that value verbatim; and when a request presents no `User-Agent`, the line records an explicit `null` rather than omitting the key

#### Scenario: A rejected request keeps the fixed key set

- **WHEN** a malformed or unsupported request is denied without ever becoming a policy query
- **THEN** the line still contains the `child_pid`, `intercept_rule` and `rule_label` keys, each explicitly `null`, and records the observed `user_agent` if the request carried one

#### Scenario: Control bytes in request-derived fields cannot reach a terminal raw

- **WHEN** any request-derived audit value — `intercept_rule`, `rule_label`, `request_id`, `session_id`, `backend`, or `user_agent` — carries control characters that JSON string encoding does not escape (DEL, or a C1 control such as CSI)
- **THEN** the recorded value has them escaped on the raw bytes of the audit file, so reading the trail in a terminal cannot execute them

### Requirement: Protect the audit log from other users

The audit log SHALL be created with owner-only read and write permissions, because it records the full command lines and API paths an agent attempted.

#### Scenario: Newly created log is owner-only

- **WHEN** the audit log file is created
- **THEN** its permissions are `0600`

### Requirement: Never let logging change a decision

A failure to serialize or write an audit record SHALL be logged as an error and otherwise ignored. It SHALL NOT alter, delay past the request, or fail the decision returned to nono.

#### Scenario: Write failure does not change the response

- **WHEN** the audit log cannot be written
- **THEN** the error is logged and the decision already computed is still returned to nono unchanged

### Requirement: Keep recording at the configured path across a rotation

An append handle survives a `rename` or `unlink` of the file it was opened on, and
writes to the detached inode keep succeeding, so a rotated log silently stops
recording anything an operator can read at the configured path while `/healthz`
stays green. Before every record the service SHALL check that the handle still
refers to the configured path — comparing the `st_dev`/`st_ino` of the path against
the open handle — and SHALL reopen it when it does not, applying the same
owner-only permissions as a first-time open. A reopen that itself fails SHALL be
logged as an error and SHALL keep the record on the handle already held, since
appending to the previous file loses less than dropping the line. Neither the check
nor a failed reopen SHALL change a decision.

#### Scenario: A renamed log is reopened

- **WHEN** the audit log is renamed while the daemon is running and a further approval request is decided
- **THEN** the decision is returned unchanged, a file at the configured path holds the record of that decision with `0600` permissions, and the renamed file receives nothing further

#### Scenario: A deleted log is recreated

- **WHEN** the audit log is deleted while the daemon is running and a further approval request is decided
- **THEN** a file at the configured path is created and holds the record of that decision

#### Scenario: A truncated log is reported

- **WHEN** the audit log is truncated in place — the same inode, fewer bytes — and a further approval request is decided
- **THEN** the record is written at the configured path and the shrink is logged as a warning, because an append-only log cannot shrink by itself

### Requirement: Record the provenance of every policy set that loads or fails to load

The service SHALL append a `policy-set` line to the audit log for the bootstrap load and
for every reload attempt, carrying the generation, the outcome, the list of policy files,
a content hash of the loaded set, and whether the startup at-risk warnings fired.

The content hash SHALL be computed over the bytes the loader actually parsed, during the
load, and SHALL NOT be produced by re-reading the directory afterwards: a re-read is a
different moment and can describe content the daemon never enforced, which is worse than
recording nothing. The framing SHALL be unambiguous — each file's name and contents
length-prefixed — so that two different sets cannot digest alike, and SHALL include file
names, because a rename with identical content changes the policy ids a decision reports.
The recorded value SHALL name its algorithm, so a future change of algorithm cannot be
mistaken for a change of content.

Reload attempts that adopt nothing SHALL be recorded too, and SHALL be distinguishable by
outcome: a set that loaded, a reload refused by the pre-reload trust re-check, and a
reload that was attempted and failed. Recording only successful loads would leave a
policy-directory compromise as silent in the durable record as it is today, which is the
gap this requirement exists to close — the refusal is the detection event. On an outcome
that adopted nothing the content hash SHALL be `null`, because there is no set to name,
and the generation recorded SHALL be the one still deciding.

This record is **evidence, not an integrity control**, and SHALL be described that way
wherever it appears. A hash written by the same process that loaded the files supports
later comparison and says nothing about authorship; policy signing is the control, and is
a separate unbuilt capability. Wording that implies otherwise is forbidden for the same
reason it is forbidden for the observed `User-Agent`.

The provenance record SHALL NOT be exposed on the health endpoint. It belongs in the trail
that lies outside every write grant the sandboxed agent holds — which is what makes it
survive the tampering it exists to evidence — not on an unauthenticated surface.

#### Scenario: The bootstrap load is recorded

- **WHEN** the daemon starts and loads its policy directory successfully
- **THEN** a `policy-set` line records outcome `loaded`, generation 1, the loaded file list, a content hash naming its algorithm, and whether the startup at-risk warnings fired

#### Scenario: An adopted reload is recorded with a different hash

- **WHEN** a policy file is edited such that the set's content changes, and the reload is adopted
- **THEN** a further `policy-set` line records outcome `loaded` with the advanced generation and a content hash differing from the previous line's

#### Scenario: A reload refused by the trust re-check is recorded

- **WHEN** the pre-reload trust re-check refuses because a state path became loosely writable mid-session
- **THEN** a `policy-set` line records outcome `refused` with a null content hash, the generation still deciding, and the reason — so the detection event survives in the trail rather than only on stdout

#### Scenario: A failed reload is recorded

- **WHEN** a reload is attempted and fails, for instance on invalid Cedar
- **THEN** a `policy-set` line records outcome `failed` with a null content hash and the generation still deciding

#### Scenario: Every decision can be tied to the set that produced it

- **WHEN** an auditor reads the trail and selects the most recent `policy-set` line with outcome `loaded` before a given decision line
- **THEN** that line names the content hash and file list of the policy set that produced the decision, without consulting the policy directory

