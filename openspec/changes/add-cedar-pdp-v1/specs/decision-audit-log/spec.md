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
