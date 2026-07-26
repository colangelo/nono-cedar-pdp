# decision-audit-log — delta for close-audit-and-loader-gaps

## MODIFIED Requirements

### Requirement: Audit lines are self-sufficient for review

Each audit line SHALL carry an RFC 3339 UTC timestamp, the nono `request_id` and `session_id`, the approval backend name, the resolved agent, the Cedar principal, the action, a resource summary, the child pid, the intercept rule (for command requests) or route rule label (for endpoint requests), the decision, the matched policy identifiers, the decision reason, and the evaluation time. This is sufficient to answer "what was asked, who asked, **what routed the request here**, what was decided, and which rule decided it" without consulting any other source. The key set SHALL be identical on every line: a value the request did not carry is an explicit `null`, so a consumer can tell "not known" from "not recorded" — command lines carry a null `rule_label`, endpoint lines a null `intercept_rule`, and rejected-request lines null for all three of `child_pid`, `intercept_rule` and `rule_label`. `child_pid` SHALL record the value the wire carried for both request variants (real nono sends `0` for endpoint requests; a sender claiming otherwise leaves its claim on the record rather than having it silently rewritten). Request-derived text recorded in audit values — the intercept rule and rule label included — SHALL have control characters escaped at the recording boundary, the same rule the resource summary already follows: JSON string encoding escapes only C0 controls, so DEL and C1 controls (CSI among them) would otherwise reach an operator's terminal raw when the trail is read.

#### Scenario: Audit line fields for a decided command request

- **WHEN** a `git status` command request from session `s1` on backend `cedar` with intercept rule `status` and child pid `42` is denied
- **THEN** the line records the RFC 3339 timestamp, `request_id`, `session_id` `s1`, backend `cedar`, the resolved agent, principal `Nono::Caller::"session"`, action `launchCommand`, a resource summary naming `git`, `child_pid` `42`, `intercept_rule` `status`, a null `rule_label`, decision `deny`, the matched policy identifiers, the reason, and the evaluation time

#### Scenario: Audit line fields for a decided endpoint request

- **WHEN** an endpoint request routed by rule label `endpoint_policy.approve[GET /repos/*]` with child pid `0` is decided
- **THEN** the line records `rule_label` exactly as sent, `child_pid` `0`, and a null `intercept_rule`

#### Scenario: A rejected request keeps the fixed key set

- **WHEN** a malformed or unsupported request is denied without ever becoming a policy query
- **THEN** the line still contains the `child_pid`, `intercept_rule` and `rule_label` keys, each explicitly `null`

#### Scenario: Control bytes in request-derived fields cannot reach a terminal raw

- **WHEN** any request-derived audit value — `intercept_rule`, `rule_label`, `request_id`, `session_id`, or `backend` — carries control characters that JSON string encoding does not escape (DEL, or a C1 control such as CSI)
- **THEN** the recorded value has them escaped on the raw bytes of the audit file, so reading the trail in a terminal cannot execute them
