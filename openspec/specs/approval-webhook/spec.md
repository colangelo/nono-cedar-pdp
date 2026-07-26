# approval-webhook

## Purpose

The nono-facing HTTP contract. This capability owns everything between nono's
`WebhookApproval` backend and a decision: parsing the approval envelope for the two request
variants that can reach a webhook (`command` and `endpoint`), emitting the response shape nono
parses, keeping every failure path closed, and distinguishing "policy said no" from "this
decider is broken". It also owns the guarantee that the wire types stay faithful to upstream —
a nono version bump must fail CI rather than silently misread a security decision.
## Requirements
### Requirement: Accept nono approval webhook envelopes

The service SHALL accept `POST /v1/approve` carrying nono's approval envelope `{"backend": <string>, "request": <object>}`, where the request object is internally tagged by `capability_type`. It SHALL support the `command` and `endpoint` variants, which are the only variants that can reach a webhook approval backend in nono 0.69.

#### Scenario: Command approval request is accepted

- **WHEN** the body is `{"backend":"cedar","request":{"capability_type":"command","request_id":"tool-sandbox-approve-git-1784990893285791000","command":"git","args":["/private/tmp/nono-tool-sandbox-13819-1784990893285791000-a4d3bceb3ec061c0/shims/git","push"],"caller":"session","intercept_rule":"push","reason":null,"child_pid":13820,"session_id":"35abc0894927242e"}}`
- **THEN** the service parses it as a command approval for `git` — command name from `command`, never from `args[0]`, which here is the per-run shim path — with `argv_tail` `"push"`, caller `session`, and session `35abc0894927242e`, and returns a decision with HTTP 200

#### Scenario: Endpoint approval request is accepted with proxy identity

- **WHEN** the body carries `"capability_type":"endpoint"` with `route_id`, `upstream`, `method`, `path`, `rule_label`, `session_id":"proxy"` and `child_pid":0`
- **THEN** the service parses it as an L7 endpoint approval and returns a decision with HTTP 200

### Requirement: Emit nono's friendly decision shape

The service SHALL respond with `{"decision":"allow"}` on allow and `{"decision":"deny","reason":<string>}` on deny. It SHALL NOT emit nono's internal `ApprovalDecision` serde representation (`"Granted"`, `{"Denied":{...}}`), because that shape is upstream's private representation and will drift.

#### Scenario: Allow response body

- **WHEN** policy permits the request
- **THEN** the response body is exactly `{"decision":"allow"}`

#### Scenario: Deny response carries a reason

- **WHEN** policy denies the request
- **THEN** the response body is `{"decision":"deny","reason":<non-empty string>}`

#### Scenario: Response cannot be mistaken for upstream's enum shape

- **WHEN** the emitted allow body is parsed as nono's `ApprovalDecision` type
- **THEN** parsing fails, so nono falls through to its friendly-shape parser as intended

### Requirement: Fail closed on unusable input

Every input the service cannot confidently evaluate SHALL resolve to a denial. The service SHALL NOT return allow on any error path.

#### Scenario: Malformed JSON body is denied with our own reason

- **WHEN** the request body is not valid JSON
- **THEN** the service responds HTTP 200 with `{"decision":"deny","reason":<text mentioning malformed>}` so that nono records the specific reason rather than a generic HTTP status

#### Scenario: Unsupported request variant is denied

- **WHEN** the request carries a `capability_type` the service does not evaluate, such as `capability` or `network`
- **THEN** the service responds HTTP 200 with a denial whose reason states the variant is unsupported

#### Scenario: Internal construction failure is denied

- **WHEN** the service cannot build a policy request from an otherwise well-formed payload
- **THEN** the service logs the error and responds with a denial rather than propagating an error to nono

### Requirement: Tolerate upstream field additions

Wire parsing SHALL ignore unknown fields in both the envelope and the request object, so that a nono release adding a field does not turn every decision into a denial.

#### Scenario: Unknown fields do not break parsing

- **WHEN** the envelope or request object contains fields the service does not know
- **THEN** the known fields are parsed normally and a decision is returned

### Requirement: Guarantee wire conformance with the upstream crate

The test suite SHALL verify the wire types against nono's own types by serializing upstream request values and asserting both that they deserialize into the service's mirrors and that their exact key set is unchanged. The `nono` crate SHALL be a development dependency only.

The command-request corpus SHALL model every `intercept_rule` shape the upstream tool sandbox actually produces, verified against upstream's rule-label construction rather than assumed: the matched intercept rule's arguments joined with spaces (single token `status`, multi-token `push --force`), the `<catch-all>` label of an empty-args rule, and the invocation-policy label forms `invocation_policy.approve[<index>]` and `invocation_policy.default`. A corpus that models only the single-token shape SHALL be treated as a defect, because it cannot catch a policy or audit consumer that assumes one word.

#### Scenario: Upstream key set change fails the build

- **WHEN** a nono version bump changes the field set of a `command` or `endpoint` approval request
- **THEN** the conformance test fails, rather than the daemon silently misreading a security decision

#### Scenario: Filesystem capability requests are classified unsupported

- **WHEN** a `capability` approval request produced by upstream's own types is parsed
- **THEN** it is classified as unsupported, which resolves to a denial

#### Scenario: The fixture corpus models the real intercept_rule shapes

- **WHEN** the command-request test corpus is enumerated
- **THEN** it contains payloads whose `intercept_rule` is a single token, a space-joined multi-token rule, the `<catch-all>` label, and an `invocation_policy.*` label — each driven through parse, evaluation and audit with the value surviving to the audit line byte-identically (none of the real shapes contains a control character; hostile control bytes are escaped at the audit boundary like every other request-derived field)

### Requirement: Report health distinctly from denial

The service SHALL expose `GET /healthz` reporting the loaded policy generation, policy count, and policy directory. A broken decider SHALL be distinguishable from a policy denial: when no policies are loaded the service SHALL respond `503` rather than a `200` denial, so nono's recorded reason names the HTTP status.

#### Scenario: Healthy daemon reports its policy generation

- **WHEN** `GET /healthz` is called on a daemon with a loaded policy set
- **THEN** the response is HTTP 200 with the current generation and policy count

#### Scenario: Daemon with no policies reports unavailable

- **WHEN** the loaded policy set contains no policies
- **THEN** `/healthz` responds 503 and `/v1/approve` responds 503 instead of deciding

### Requirement: Bind loopback only

The service SHALL bind a loopback address by default and SHALL NOT be reachable from other hosts, because nono sends no credential and cannot authenticate the decider.

#### Scenario: Default bind address

- **WHEN** no bind address is configured
- **THEN** the service listens on `127.0.0.1:8181`

### Requirement: Contain handler panics

A panic while handling a request SHALL be converted into an HTTP error response rather than dropping the connection, so nono records a definite failure instead of an opaque transport error.

#### Scenario: Panic becomes an error response

- **WHEN** a request handler panics
- **THEN** the client receives a 5xx response and the daemon stays available

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

