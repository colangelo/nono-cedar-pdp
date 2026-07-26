# pdp-operations — delta for harden-decide-endpoint-surface

## ADDED Requirements

### Requirement: Operational output is telemetry, not the decision record

The daemon's stdout and the audit log carry the same request-derived content but have
nothing like the same protection: the audit log is created `0600`, tightened if it was
looser, and re-attached across rotation, while stdout goes wherever the operator
redirected it — a shared journal, a log aggregator, terminal scrollback — none of
which inherit those permissions. The decision detail therefore SHALL NOT be written to
stdout by default.

At INFO, the per-decision line SHALL carry the identifiers and the outcome and nothing
request-derived beyond them: `request_id`, `session_id`, `backend`, the action, the
allow/deny outcome, the matched policy identifiers, and the evaluation time. That is
enough to correlate a decision with its audit line and to watch the daemon work.

The resource summary — the command line an agent attempted, or the API path it
requested — SHALL be logged only at DEBUG. It remains available deliberately, for
development and for diagnosing a policy that will not match, but it is off by default
and the operator opts in.

"Only at DEBUG" binds **every** default-level event about a request, not just the
per-decision line. In particular the refusal of an ambiguous endpoint path stays at
WARN — an operator should see a refused path without opting in — but SHALL name the
ambiguity it found and the `request_id`, not the path: nono's proxy forwards the
request target verbatim, query string included, and for a credential proxy the query
string is the sensitive part. The deny reason handed to nono, and therefore the audit
line, SHALL still carry the whole target as sent.

The audit log is unchanged and remains the complete record: nothing is *lost* by this
requirement, only relocated to the file that has permissions.

Documentation SHALL state that raising the level to DEBUG puts attempted command lines
and API paths into an unprotected stream, i.e. DEBUG output inherits the audit log's
sensitivity without its permissions.

#### Scenario: The default decision line carries identifiers, not the command line

- **WHEN** a command request is decided at the default log level
- **THEN** the emitted line names the `request_id`, `session_id`, `backend`, action, outcome, matched policy identifiers and timing, and does **not** contain the attempted command line or its arguments

#### Scenario: The default decision line carries identifiers, not the requested API path

- **WHEN** an endpoint request is decided at the default log level
- **THEN** the emitted line names the identifiers, action, outcome, matched policy identifiers and timing, and does **not** contain the request target or its query string

#### Scenario: A refused ambiguous path is reported by cause, not by path

- **WHEN** an endpoint request is refused at the default log level because its path is ambiguous
- **THEN** the WARN names the ambiguity found and the `request_id` and contains no part of the path
- **AND** the deny reason returned to nono and the audit line still carry the whole target as sent, so nothing is lost

#### Scenario: The resource summary is available at DEBUG

- **WHEN** the operator raises the log level to DEBUG and a request is decided
- **THEN** the resource summary is emitted, control-escaped as before

#### Scenario: The audit log still records the full detail at any log level

- **WHEN** a request is decided at the default log level
- **THEN** the audit line still contains the complete resource summary, so relocating the detail does not reduce what is recorded
