# approval-webhook — delta for harden-decide-endpoint-surface

## ADDED Requirements

### Requirement: Refuse requests that cannot have come from nono

nono sends no credential and cannot authenticate itself, so the service SHALL NOT
claim to identify its caller. It SHALL, however, refuse requests whose shape proves
they did not come from nono's webhook client, before any policy is consulted and
before any audit line is written as though a decision had been requested.

Verified against nono 0.69.0 (`crates/nono-cli/src/approval_runtime.rs`), the webhook
POST carries exactly two headers: `Content-Type: application/json` and
`User-Agent: nono-cli/<version>`. Therefore:

- A request whose `Content-Type` is absent, or is not `application/json`, SHALL be
  refused. This is the load-bearing control rather than a formality: a CORS-*simple*
  cross-origin POST may only carry `text/plain`,
  `application/x-www-form-urlencoded` or `multipart/form-data`, so requiring JSON
  forces a preflight, and the service sends no CORS headers, so the preflight fails
  and the request never reaches the handler. This closes the one vector that does not
  already require local code execution — a page the operator merely visits.
- A request carrying an `Origin` header SHALL be refused. nono never sends one and a
  browser always does. This SHALL be enforced independently of the content-type
  check, so that neither alone is load-bearing.
- Parameters on the media type (`application/json; charset=utf-8`) SHALL be
  tolerated, since a future client may add them.

These refusals are **not** decision-shaped: nothing was asked by nono, so no deny
reason is owed to it and no audit line claiming a decision SHALL be written. They
SHALL return a 4xx status and SHALL be logged at WARN with the reason and the
observed header values, control-escaped, so an operator can see the endpoint being
probed.

The service SHALL state plainly, wherever this is described, that **none of this
authenticates nono**: a local process running as the same user can still present a
correct content-type and no `Origin`, and therefore can still forge an audit record.
That residual is inherent while the webhook carries no credential, and closing it
requires an upstream change (a bearer token or a unix socket).

#### Scenario: A request without a JSON content-type is refused

- **WHEN** a POST to the decide endpoint carries no `Content-Type`, or one that is not `application/json` — `text/plain`, `application/x-www-form-urlencoded` or `multipart/form-data`, the three a CORS-simple request may use
- **THEN** the service refuses it with a 4xx status, writes no audit line claiming a decision, and logs the refusal at WARN naming the observed content-type

#### Scenario: A media type with parameters is accepted

- **WHEN** the content-type is `application/json; charset=utf-8`
- **THEN** the request is evaluated normally, because a client may legitimately add parameters

#### Scenario: A request carrying an Origin header is refused

- **WHEN** a POST carries an `Origin` header, as any browser-issued request does
- **THEN** the service refuses it with a 4xx status even if its content-type is `application/json`, and writes no audit line claiming a decision

#### Scenario: A genuine nono request is still accepted

- **WHEN** the request carries `Content-Type: application/json` and no `Origin`, as nono's webhook client sends
- **THEN** it is evaluated and answered exactly as before, and the end-to-end path against a real `nono run` is unaffected

#### Scenario: A decision-shaped failure is still a 200 deny

- **WHEN** a request passes the header checks but its body is malformed, oversized, or an unsupported variant
- **THEN** the existing fail-closed behaviour is unchanged: HTTP 200 with an explicit deny reason nono can record, and an audit line for the denial
