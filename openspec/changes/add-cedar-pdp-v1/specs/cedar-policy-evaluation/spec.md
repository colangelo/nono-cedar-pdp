## ADDED Requirements

### Requirement: Cedar schema models the nono approval domain

The service SHALL embed a Cedar schema in the `Nono` namespace declaring a `Caller in Session in Agent` principal hierarchy, a `Command` resource (`command`, `args`, `argv`, `argv_tail`, `arg_count`), an `HttpEndpoint` resource (`route_id`, `upstream`, `method`, `path`), and the actions `launchCommand` and `httpRequest` with their respective context types. The schema SHALL compile at startup and SHALL be the validation target for all policies.

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

### Requirement: Expose an argument tail that excludes the shim path

nono sends `args` as the shim process's raw argv, so `args[0]` is whatever the exec caller
placed in `argv[0]` — in the observed `nono run` path an absolute per-run shim path such
as `/private/tmp/nono-tool-sandbox-<pid>-<nanos>-<hex>/shims/git` — and never reliably the
command name. The schema SHALL therefore declare an `argv_tail` attribute on `Command`
holding `args[1..]` joined by a single space, while `args` and `argv` remain faithful to
what nono sent (`args[0]` included, nothing normalised away). `argv_tail` SHALL be the
empty string when `args` carries fewer than two entries. The command name SHALL be read
from `resource.command`, which is a separate wire field and is unaffected.

#### Scenario: argv_tail omits the per-run shim path

- **WHEN** a command request arrives with `args` `["/private/tmp/nono-tool-sandbox-13819-1784990893285791000-a4d3bceb3ec061c0/shims/git", "status", "--porcelain"]`
- **THEN** `resource.argv_tail` is `"status --porcelain"`
- **AND** `resource.argv` still contains the shim path verbatim, and `resource.command` is `"git"`

#### Scenario: A tail with nothing in it is empty, not absent

- **WHEN** a command request arrives with `args` `["/private/tmp/nono-tool-sandbox-1-2-3/shims/git"]` or with an empty `args`
- **THEN** `resource.argv_tail` is `""`, the attribute is still present, and no `like` pattern beginning with a literal matches it

#### Scenario: A policy reading argv_tail validates strictly

- **WHEN** a policy tests `resource.argv_tail like "commit *"` for the `launchCommand` action
- **THEN** strict validation against the schema passes

### Requirement: Anchor argument patterns on argv_tail, never on argv

Because `args[0]` is an unpredictable per-run path, a `like` pattern anchored at the
start of `argv` cannot match a runtime payload: in a `permit` it is fail-safe (the permit
never fires and the request falls through to default deny), but in a `forbid` it fails
open — the forbid never fires and any permit that matched still allows the launch. Policy
authoring guidance, the shipped policy pack and the schema comments SHALL direct anchored
matching at `argv_tail`. The loader SHALL report a load-time diagnostic, naming the file
and policy identifier, for any policy whose `argv` glob is anchored at the start (no
leading wildcard), and SHALL extend its existing `permit`-reads-`argv` lint to
`argv_tail`, which inherits the same flattened-string over-matching caveat.

#### Scenario: An anchored pattern matches the runtime payload only via argv_tail

- **WHEN** a request whose `args` are `["/private/tmp/nono-tool-sandbox-13819-1784990893285791000-a4d3bceb3ec061c0/shims/git", "commit", "--amend"]` is evaluated against a forbid guarded by `resource.argv_tail like "commit *"`
- **THEN** the forbid fires and the decision is deny
- **AND WHEN** the same request is evaluated against a forbid guarded by `resource.argv like "git commit *"`
- **THEN** that forbid does not fire, which is the fail-open shape the diagnostic below exists to catch

#### Scenario: A start-anchored argv glob is reported at load time

- **WHEN** the policy directory contains a policy whose condition is `resource.argv like "git commit *"`
- **THEN** loading reports a diagnostic naming that file and policy identifier and stating that an anchored `argv` pattern cannot match at runtime because `args[0]` is a per-run shim path, and directing the author to `argv_tail`

#### Scenario: A permit reading argv_tail is linted like a permit reading argv

- **WHEN** the policy directory contains a `permit` whose condition reads `resource.argv_tail`
- **THEN** loading reports the over-matching lint for that policy, exactly as it does for a `permit` reading `resource.argv`

### Requirement: Deny endpoint requests whose path is ambiguous

nono's proxy sends the raw upstream path: not normalised and still percent-encoded. A
prefix glob such as `resource.path like "/repos/*"` is therefore satisfied by
`/repos/../user/keys`, `/repos/%2e%2e/user/keys` and `/repos/..;/user/keys`, which a
normalising origin resolves elsewhere. The service SHALL NOT normalise the path (that
would guess at the upstream's behaviour); instead it SHALL deny an endpoint request whose
path contains an ambiguous segment — any segment that is `.` or `..` after one
percent-decode pass and after stripping `;`-parameters — or whose path contains a
malformed percent-escape, **before any policy is consulted**, with a deny reason naming
the ambiguous path. Unambiguous paths SHALL continue to be evaluated with the raw path
value.

#### Scenario: A literal traversal segment is denied without policy evaluation

- **WHEN** an endpoint request carries `path` `/repos/../user/keys` and the policy set contains a permit guarded by `resource.path like "/repos/*"`
- **THEN** the decision is deny, the matched-policy list is empty, and the reason names the path as ambiguous rather than naming that permit

#### Scenario: A percent-encoded or parameterised traversal segment is denied

- **WHEN** an endpoint request carries `path` `/repos/%2e%2e/user/keys`, or `/repos/..;/user/keys`, or `/repos/%2E%2E%2Fuser/keys`
- **THEN** the decision is deny with the ambiguous-path reason, for the same reason as a literal `..`

#### Scenario: An undecodable path is denied rather than guessed at

- **WHEN** an endpoint request carries a path containing a malformed percent-escape such as `/repos/%zz/foo`
- **THEN** the decision is deny with a reason naming the path as ambiguous, because the daemon cannot know what the upstream will make of it

#### Scenario: An unambiguous path is still decided by policy

- **WHEN** an endpoint request carries `path` `/repos/foo/bar` and a permit guarded by `resource.path like "/repos/*"` matches
- **THEN** the decision is allow and the reason names that permit

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
