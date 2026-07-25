## ADDED Requirements

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

#### Scenario: Upstream key set change fails the build

- **WHEN** a nono version bump changes the field set of a `command` or `endpoint` approval request
- **THEN** the conformance test fails, rather than the daemon silently misreading a security decision

#### Scenario: Filesystem capability requests are classified unsupported

- **WHEN** a `capability` approval request produced by upstream's own types is parsed
- **THEN** it is classified as unsupported, which resolves to a denial

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
