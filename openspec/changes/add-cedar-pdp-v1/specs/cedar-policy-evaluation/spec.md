## ADDED Requirements

### Requirement: Cedar schema models the nono approval domain

The service SHALL embed a Cedar schema in the `Nono` namespace declaring a `Caller in Session in Agent` principal hierarchy, a `Command` resource (`command`, `args`, `argv`, `arg_count`), an `HttpEndpoint` resource (`route_id`, `upstream`, `method`, `path`), and the actions `launchCommand` and `httpRequest` with their respective context types. The schema SHALL compile at startup and SHALL be the validation target for all policies.

#### Scenario: Embedded schema compiles

- **WHEN** the daemon starts
- **THEN** the embedded schema compiles and exposes the actions `launchCommand` and `httpRequest`

#### Scenario: Well-formed policy validates strictly

- **WHEN** a policy tests `resource.command` and `resource.args.contains(...)` for the `launchCommand` action
- **THEN** strict validation against the schema passes

### Requirement: Positional argument matching is unexpressible

Because nono drops non-UTF-8 argv entries before sending them, argument positions are not trustworthy. The schema SHALL model `args` as `Set<String>`, which has no index access, so index-based argument policy cannot be written. Policies referencing attributes absent from the payload SHALL fail validation.

#### Scenario: Set-membership argument policy is accepted

- **WHEN** a policy tests `resource.args.contains("--force")`
- **THEN** strict validation passes

#### Scenario: Policy referencing an unavailable attribute is rejected

- **WHEN** a policy references an attribute the payload does not carry, such as `resource.cwd`
- **THEN** strict validation fails and the policy set is refused

### Requirement: Derive the principal hierarchy from request identity

For a `command` request the service SHALL build `Nono::Caller::"<caller>"` as a member of `Nono::Session::"<session_id>"` as a member of the resolved `Nono::Agent`. For an `endpoint` request, where nono supplies no session identity, the service SHALL use `Nono::Caller::"proxy"` in `Nono::Session::"proxy"`. Entity attribute values SHALL be escaped so that a crafted command or session name cannot alter the entity identifier.

#### Scenario: Direct session launch is distinguishable from a chained launch

- **WHEN** a command request has `caller` `"session"`
- **THEN** the principal is `Nono::Caller::"session"` and `caller_kind` context is `"session"`
- **AND WHEN** the same request has `caller` `"npm"`
- **THEN** the principal is `Nono::Caller::"npm"` and `caller_kind` context is `"command"`

#### Scenario: Endpoint requests carry proxy identity

- **WHEN** an endpoint request is evaluated
- **THEN** the principal is `Nono::Caller::"proxy"` within `Nono::Session::"proxy"`

### Requirement: Resolve agent identity from the approval backend name

The service SHALL map the envelope's `backend` name to a Cedar `Agent` identifier using operator configuration, and SHALL fall back to a configured unknown-agent identifier when the name is not mapped.

#### Scenario: Mapped backend name yields its agent

- **WHEN** configuration maps backend `cedar` to agent `claude-code` and a request arrives with backend `cedar`
- **THEN** the principal's agent ancestor is `Nono::Agent::"claude-code"`

#### Scenario: Unmapped backend name falls back

- **WHEN** a request arrives with a backend name absent from configuration
- **THEN** the agent ancestor is the configured unknown-agent identifier, which policy can deny explicitly

### Requirement: Load policies with traceable identifiers

The service SHALL load every `*.cedar` file in the configured policy directory and assign each policy an identifier of the form `<file stem>:<id annotation or ordinal>`, so a decision names the file and rule that produced it. Duplicate identifiers SHALL be a load failure, never a silent overwrite. Files without the `.cedar` extension SHALL be ignored.

#### Scenario: Policy identifiers carry file provenance

- **WHEN** `10-git.cedar` contains a policy annotated `@id("no-history-rewrites")` and one without an annotation
- **THEN** the loaded identifiers are `10-git:no-history-rewrites` and `10-git:<ordinal>`

#### Scenario: Duplicate identifiers fail the load

- **WHEN** two policies resolve to the same identifier
- **THEN** loading fails with an error naming the file

#### Scenario: Non-policy files are ignored

- **WHEN** the policy directory also contains a `README.md`
- **THEN** it is not loaded and does not affect validation

### Requirement: Refuse to run without a usable policy set

The service SHALL strict-validate the whole policy set against the embedded schema before serving, and SHALL refuse to start when the policy directory is unreadable, contains a syntax error, fails validation, or contains no policies. An empty directory SHALL NOT be treated as a valid deny-everything configuration, because refusing to start is equally fail-closed and far more diagnosable.

#### Scenario: Syntax error prevents startup and names the file

- **WHEN** a policy file contains invalid Cedar
- **THEN** startup fails with an error identifying that file

#### Scenario: Empty policy directory prevents startup

- **WHEN** the policy directory contains no `*.cedar` files
- **THEN** startup fails rather than serving a policy set that denies everything

### Requirement: Hot-reload policies keeping the last known good set

The service SHALL watch the policy directory and reload on change. A successful reload SHALL atomically replace the active policy set and advance a generation counter. A failed reload SHALL retain the previously active set and log the error, so that a mid-session editing mistake cannot brick a running agent.

#### Scenario: Valid edit takes effect

- **WHEN** a policy file is edited such that a previously permitted command is now forbidden
- **THEN** the generation advances and subsequent evaluations return the new decision

#### Scenario: Broken edit retains previous decisions

- **WHEN** a policy file is edited to contain invalid Cedar, or to violate the schema
- **THEN** the reload fails, the generation does not advance, and evaluations continue to use the last known good policy set

### Requirement: Derive decisions and human-readable reasons

The service SHALL evaluate each request against the active policy set and report the determining policy identifiers. An allow SHALL name the permitting policies. A deny caused by a forbid SHALL name the forbidding policies. A deny where no policy matched SHALL state explicitly that no policy permitted the request, because Cedar reports no determining policy in that case and an empty reason would be useless in nono's audit trail.

#### Scenario: Allow names the permitting policy

- **WHEN** a permit policy matches
- **THEN** the decision is allow and the reason names that policy identifier

#### Scenario: Forbid names the forbidding policy

- **WHEN** a forbid policy matches
- **THEN** the decision is deny and the reason names that policy identifier

#### Scenario: Default deny states that nothing matched

- **WHEN** no policy matches the request
- **THEN** the decision is deny, the matched-policy list is empty, and the reason states that no policy permitted the request

#### Scenario: Evaluation timing is recorded

- **WHEN** a request is evaluated
- **THEN** the elapsed evaluation time is recorded with the decision

### Requirement: Fail closed on evaluation errors

When Cedar reports any policy evaluation error, the service SHALL return a denial even if the computed decision was allow, because an errored policy may have been a forbid that was therefore not applied.

#### Scenario: Evaluation error overrides an allow

- **WHEN** evaluation produces an allow decision together with one or more evaluation errors
- **THEN** the service returns deny with a reason naming the evaluation errors
