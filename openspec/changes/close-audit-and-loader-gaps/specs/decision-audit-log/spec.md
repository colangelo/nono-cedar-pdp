# decision-audit-log — delta for close-audit-and-loader-gaps

## MODIFIED Requirements

### Requirement: Audit lines are self-sufficient for review

Each audit line SHALL carry an RFC 3339 UTC timestamp, the nono `request_id` and `session_id`, the approval backend name, the resolved agent, the Cedar principal, the action, a resource summary, the child pid, the intercept rule (for command requests) or route rule label (for endpoint requests), the decision, the matched policy identifiers, the decision reason, and the evaluation time. This is sufficient to answer "what was asked, who asked, **what routed the request here**, what was decided, and which rule decided it" without consulting any other source. The key set SHALL be identical on every line: a value the request did not carry is an explicit `null`, so a consumer can tell "not known" from "not recorded" — command lines carry a null `rule_label`, endpoint lines a null `intercept_rule`, and rejected-request lines null for all three of `child_pid`, `intercept_rule` and `rule_label`.

#### Scenario: Audit line fields for a decided command request

- **WHEN** a `git status` command request from session `s1` on backend `cedar` with intercept rule `status` and child pid `42` is denied
- **THEN** the line records the RFC 3339 timestamp, `request_id`, `session_id` `s1`, backend `cedar`, the resolved agent, principal `Nono::Caller::"session"`, action `launchCommand`, a resource summary naming `git`, `child_pid` `42`, `intercept_rule` `status`, a null `rule_label`, decision `deny`, the matched policy identifiers, the reason, and the evaluation time

#### Scenario: Audit line fields for a decided endpoint request

- **WHEN** an endpoint request routed by rule label `endpoint_policy.approve[GET /repos/*]` with child pid `0` is decided
- **THEN** the line records `rule_label` exactly as sent, `child_pid` `0`, and a null `intercept_rule`

#### Scenario: A rejected request keeps the fixed key set

- **WHEN** a malformed or unsupported request is denied without ever becoming a policy query
- **THEN** the line still contains the `child_pid`, `intercept_rule` and `rule_label` keys, each explicitly `null`
