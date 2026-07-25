## ADDED Requirements

### Requirement: Record every decision as one JSONL line

The service SHALL append exactly one JSON object per line to the configured audit log for every decision it returns, including denials produced by malformed or unsupported input where a request context is available. Parent directories SHALL be created if absent.

#### Scenario: Two decisions produce two lines

- **WHEN** two approval requests are decided
- **THEN** the audit log contains exactly two lines, each independently parseable as JSON

#### Scenario: Missing parent directory is created

- **WHEN** the configured audit log path names a directory that does not exist
- **THEN** the directory is created and the log is opened successfully

### Requirement: Audit lines are self-sufficient for review

Each audit line SHALL carry an RFC 3339 UTC timestamp, the nono `request_id` and `session_id`, the approval backend name, the resolved agent, the Cedar principal, the action, a resource summary, the decision, the matched policy identifiers, the decision reason, and the evaluation time. This is sufficient to answer "what was asked, who asked, what was decided, and which rule decided it" without consulting any other source.

#### Scenario: Audit line fields for a decided command request

- **WHEN** a `git status` command request from session `s1` on backend `cedar` is denied
- **THEN** the line records the RFC 3339 timestamp, `request_id`, `session_id` `s1`, backend `cedar`, the resolved agent, principal `Nono::Caller::"session"`, action `launchCommand`, a resource summary naming `git`, decision `deny`, the matched policy identifiers, the reason, and the evaluation time

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
