## ADDED Requirements

### Requirement: Cedar schema models the nono approval domain

The service SHALL embed a Cedar schema in the `Nono` namespace declaring a `Caller in Session in Agent` principal hierarchy, a `Command` resource (`command`, `args`, `argv_tail`, `arg_count`), an `HttpEndpoint` resource (`route_id`, `upstream`, `method`, `path`), and the actions `launchCommand` and `httpRequest` with their respective context types. The schema SHALL compile at startup and SHALL be the validation target for all policies.

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
holding `args[1..]` joined by a single space, while `args` remains faithful to what nono
sent (`args[0]` included, nothing normalised away). `argv_tail` SHALL be the empty string
when `args` carries fewer than two entries. The command name SHALL be read from
`resource.command`, which is a separate wire field and is unaffected.

#### Scenario: argv_tail omits the per-run shim path

- **WHEN** a command request arrives with `args` `["/private/tmp/nono-tool-sandbox-13819-1784990893285791000-a4d3bceb3ec061c0/shims/git", "status", "--porcelain"]`
- **THEN** `resource.argv_tail` is `"status --porcelain"`
- **AND** `resource.args` still carries the shim path verbatim, `resource.arg_count` is 3, and `resource.command` is `"git"`

#### Scenario: A tail with nothing in it is empty, not absent

- **WHEN** a command request arrives with `args` `["/private/tmp/nono-tool-sandbox-1-2-3/shims/git"]` or with an empty `args`
- **THEN** `resource.argv_tail` is `""`, the attribute is still present, and no `like` pattern beginning with a literal matches it

#### Scenario: A policy reading argv_tail validates strictly

- **WHEN** a policy tests `resource.argv_tail like "commit *"` for the `launchCommand` action
- **THEN** strict validation against the schema passes

### Requirement: Make whole-argv matching unexpressible, not merely discouraged

Because `args[0]` is an unpredictable per-run path, a `like` pattern anchored at the start
of the whole argv cannot match a runtime payload: in a `permit` it is fail-safe (the permit
never fires and the request falls through to default deny), but in a `forbid` it fails
open — the forbid never fires and any permit that matched still allows the launch. A
joined string over the whole argv has no use that `argv_tail` does not serve at least as
well: unanchored globs behave identically, because the shim path carries no
caller-controlled text, and matching `args[0]` itself is impossible. The schema SHALL
therefore declare **no whole-argv attribute**, so that a policy referencing `resource.argv`
is refused by strict validation rather than warned about. Policy authoring guidance, the
shipped policy pack and the schema comments SHALL direct anchored matching at `argv_tail`.

#### Scenario: A policy referencing resource.argv is refused

- **WHEN** the policy directory contains a policy whose condition is `resource.argv like "git commit *"`
- **THEN** strict validation fails, the policy set is refused, and (at startup) the daemon does not serve — the fail-open pattern cannot be loaded at all

#### Scenario: An anchored pattern matches the runtime payload via argv_tail

- **WHEN** a request whose `args` are `["/private/tmp/nono-tool-sandbox-13819-1784990893285791000-a4d3bceb3ec061c0/shims/git", "commit", "--amend"]` is evaluated against a forbid guarded by `resource.argv_tail like "commit *"`
- **THEN** the forbid fires and the decision is deny
- **AND WHEN** the same request carries `args` `[<the same shim path>, "status"]`
- **THEN** that forbid does not fire and a permit on `resource.command == "git"` still allows the launch

### Requirement: Report the argument-matching hazards that survive the schema

Removing the whole-argv attribute eliminates the anchoring hazard only. Two hazards remain
and SHALL be reported as load-time diagnostics naming the policy identifier (which carries
its file), advisory rather than fatal:

1. **Flattening.** `argv_tail` is still a joined string, so it cannot distinguish
   `["push --force"]` from `["push", "--force"]`, and `git commit -m "do not --force this"`
   still matches `*--force*`. Over-matching is fail-safe in a `forbid` and unsound in a
   `permit`. An **anchored** test is not affected: because `argv_tail` omits `args[0]`, a
   pattern anchored at the start (`like "status *"`) or an equality test (`== "status"`)
   pins the first token of `args[1..]` — the subcommand — which is the one thing set
   membership cannot express, and is therefore the sound shape for a `permit`. The loader
   SHALL report a `permit` whose `resource.argv_tail` test is **not** such a positional
   pin, and SHALL NOT report one that is.
2. **Unmatchable `args` literals.** `args` still holds the per-run shim path, so an `args`
   membership test against a value containing a path separator can never match the
   program — fail-open when it appears in a `forbid`. The loader SHALL report such a test
   for either effect and direct the author at `resource.command`.

#### Scenario: A permit with an unanchored argv_tail glob is reported

- **WHEN** the policy directory contains a `permit` whose condition is `resource.argv_tail like "*push*"`
- **THEN** loading reports the over-matching lint naming that policy, telling the author to anchor the pattern, and the policy set still loads

#### Scenario: A permit that pins a position is not reported

- **WHEN** a `permit` tests `resource.argv_tail == "status"`, or `resource.argv_tail like "status *"`, or a disjunction of both forms over several subcommands
- **THEN** no lint is reported, because the test pins the subcommand rather than searching the joined string
- **AND WHEN** the same `permit` also contains an unanchored test such as `resource.argv_tail like "*--porcelain*"`
- **THEN** the lint is reported, because the unanchored half is what can over-match into an approval

#### Scenario: An args membership test against a path literal is reported

- **WHEN** a policy tests `resource.args.contains("/usr/bin/git")`, or `resource.args.containsAny(["/bin/sh", "--force"])`, in either a `permit` or a `forbid`
- **THEN** loading reports a lint naming that policy, stating that `args[0]` is a per-run shim path no literal can match, and directing the author to `resource.command`
- **AND WHEN** the literal contains no path separator, such as `resource.args.contains("--force")`
- **THEN** no lint is reported

### Requirement: Deny endpoint requests whose path is ambiguous

nono's proxy sends the raw upstream path: not normalised and still percent-encoded. A
prefix glob such as `resource.path like "/repos/*"` is therefore satisfied by
`/repos/../user/keys`, `/repos/%2e%2e/user/keys` and `/repos/..;/user/keys`, which a
normalising origin resolves elsewhere. The service SHALL NOT normalise the path (that
would both change what a policy matches and guess at the upstream's behaviour); instead
it SHALL deny an endpoint request whose path's meaning depends on normalisation rules,
**before any policy is consulted**, with a deny reason naming the ambiguity and the path
as sent. Unambiguous paths SHALL continue to be evaluated with the raw path value.

A path SHALL be treated as ambiguous when, over the part of the target before any `?` or
`#`:

1. a segment is `.` or `..` after stripping `;`-parameters, at **any** percent-decode
   depth up to a bound the service SHALL declare — not merely the first, because the
   service cannot know how many decode hops sit between it and the origin, so
   `%252e%252e` is refused for the same reason as `%2e%2e`;
2. the path **as sent** contains a malformed percent-escape (a `%` not followed by two
   hex digits), or decodes to bytes that are not UTF-8 — an overlong encoding such as
   `%c0%ae` is a `.` to some servers; or
3. its percent-encoding nests deeper than the declared bound, so the traversal check
   above could not be completed.

Ambiguity SHALL NOT be inferred from the query string (a `..` in a query value cannot
change which resource the origin routes to, and `?path=../x` is an ordinary API
parameter), from dots inside a segment (`/repos/foo..bar`), or from an undecodable escape
that appears only *after* the first decode pass — `/x/50%25-done` legitimately decodes to
`50%-done`, whose stray `%` is data.

#### Scenario: A literal traversal segment is denied without policy evaluation

- **WHEN** an endpoint request carries `path` `/repos/../user/keys` and the policy set contains a permit guarded by `resource.path like "/repos/*"`
- **THEN** the decision is deny, the matched-policy list is empty, and the reason names the path as ambiguous rather than naming that permit

#### Scenario: A percent-encoded or parameterised traversal segment is denied

- **WHEN** an endpoint request carries `path` `/repos/%2e%2e/user/keys`, or `/repos/%2E%2e/user/keys`, or `/repos/..;/user/keys`, or `/repos/%2E%2E%2Fuser/keys`, or the double-encoded `/repos/%252e%252e/user/keys`
- **THEN** the decision is deny with the ambiguous-path reason, for the same reason as a literal `..`

#### Scenario: An undecodable path is denied rather than guessed at

- **WHEN** an endpoint request carries a path containing a malformed percent-escape such as `/repos/%zz/foo`, or one that decodes to non-UTF-8 bytes such as `/repos/%c0%ae%c0%ae/user/keys`
- **THEN** the decision is deny with a reason naming the path as ambiguous, because the daemon cannot know what the upstream will make of it

#### Scenario: An unambiguous path is still decided by policy

- **WHEN** an endpoint request carries `path` `/repos/foo/bar` and a permit guarded by `resource.path like "/repos/*"` matches
- **THEN** the decision is allow and the reason names that permit
- **AND WHEN** the path is `/repos/foo/bar?path=../x`, `/repos/foo..bar/x` or `/repos/50%25-done`
- **THEN** the request is still decided by policy, because none of those can move which resource the origin routes to

#### Scenario: The ambiguity refusal is reproducible offline

- **WHEN** an operator runs the `check` subcommand on a saved endpoint payload whose path contains a traversal segment
- **THEN** the command reports a deny whose reason names the ambiguity and the path as sent, and exits non-zero

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
