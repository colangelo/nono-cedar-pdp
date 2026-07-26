# cedar-policy-evaluation

## Purpose

The decision itself. This capability owns the Cedar schema and what it deliberately makes
unexpressible, the per-request entity slice, policy loading with traceable identifiers, strict
validation against the schema, hot-reload that keeps the last known good set, and the derivation
of a decision plus a reason an operator can act on. Its recurring theme: where a policy could be
written in an unsound way, make it fail to load or fail to validate rather than documenting a
caution.
## Requirements
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

Removing the whole-argv attribute eliminates the anchoring hazard only. Three hazards
remain. The first two SHALL be reported as load-time diagnostics naming the policy
identifier (which carries its file), advisory rather than fatal. The third is not
detectable at load time or at decision time and SHALL be documented instead:

1. **Flattening.** `argv_tail` is still a joined string, so it cannot distinguish
   `["push --force"]` from `["push", "--force"]`, and `git commit -m "do not --force this"`
   still matches `*--force*`. Over-matching is fail-safe in a `forbid` and unsound in a
   `permit`. A test that **pins a whole token** is not affected: because `argv_tail` omits
   `args[0]`, a pattern anchored at the start whose literal ends at the separating space
   (`like "status *"`), a pattern with no wildcard at all, or an equality test
   (`== "status"`) all pin the first token of `args[1..]` — the subcommand — which is the
   one thing set membership cannot express, and is therefore the sound shape for a
   `permit`. The loader SHALL report a `permit` whose `resource.argv_tail` test is **not**
   such a pin, and SHALL NOT report one that is. A pattern that is anchored but stops
   mid-token SHALL be reported, because `like "diff*"` also matches
   `difftool --extcmd=<cmd>`, which executes `<cmd>`.
2. **Unmatchable `args` literals.** `args` still holds the per-run shim path, so an `args`
   membership test against a value containing a path separator can never match the
   program — fail-open when it appears in a `forbid`. The loader SHALL report such a test
   for either effect and direct the author at `resource.command`.
3. **Dropped arguments.** Upstream builds `args` by discarding every argv entry that is
   not valid UTF-8 rather than converting it, so such an entry is **absent** from `args`
   and from `argv_tail` alike — not displaced, absent. A rule cannot match an argument it
   cannot see, so a `forbid` naming an argument **fails open** for that invocation, and an
   anchored `permit` still fires because the tail reads as the bare subcommand. The
   dropped entry is dropped whole, so what matters is whether the matched bytes share an
   argv entry with the invalid bytes: membership on a flag occupying its own entry
   survives, while a glob over a `--flag=<value>` entry does not.

   This hazard SHALL NOT be reported as a lint, because no policy exhibits it — the defect
   is in the input, not in the rule. It SHALL NOT be presented as avoidable by careful
   authoring either: the post-drop request is byte-identical to a legitimate request that
   never carried the argument, so no policy, schema or code at this boundary can
   distinguish them, and any rule that denied one would deny the other. It SHALL be
   documented as an inherent limit of the decision input, naming what becomes
   unreliable, and it closes only upstream, by preserving arity.

#### Scenario: A permit with an unanchored argv_tail glob is reported

- **WHEN** the policy directory contains a `permit` whose condition is `resource.argv_tail like "*push*"`
- **THEN** loading reports the over-matching lint naming that policy, telling the author to anchor the pattern, and the policy set still loads

#### Scenario: A permit that pins a position is not reported

- **WHEN** a `permit` tests `resource.argv_tail == "status"`, or `resource.argv_tail like "status *"`, or a disjunction of both forms over several subcommands
- **THEN** no lint is reported, because the test pins the subcommand rather than searching the joined string
- **AND WHEN** the same `permit` also contains an unanchored test such as `resource.argv_tail like "*--porcelain*"`
- **THEN** the lint is reported, because the unanchored half is what can over-match into an approval
- **AND WHEN** a `permit` tests `resource.argv_tail like "diff*"`, which is anchored but stops mid-token
- **THEN** the lint is reported and names the token boundary, because that pattern also approves `git difftool --extcmd=<cmd>`

#### Scenario: An args membership test against a path literal is reported

- **WHEN** a policy tests `resource.args.contains("/usr/bin/git")`, or `resource.args.containsAny(["/bin/sh", "--force"])`, in either a `permit` or a `forbid`
- **THEN** loading reports a lint naming that policy, stating that `args[0]` is a per-run shim path no literal can match, and directing the author to `resource.command`
- **AND WHEN** the literal contains no path separator, such as `resource.args.contains("--force")`
- **THEN** no lint is reported

#### Scenario: A dropped argument is not reported as a policy defect

- **WHEN** the policy directory contains a `forbid` naming an argument, such as `resource.argv_tail like "*--exec-path*"`
- **THEN** no lint is reported for the dropped-argument hazard, because the rule is well formed and the loader has no request to inspect
- **AND** the documented guidance states that such a `forbid` does not fire when the argument's own entry carried invalid UTF-8, and that this is fail-open

### Requirement: Deny endpoint requests whose path is ambiguous

nono's proxy sends the raw upstream path: not normalised and still percent-encoded. A
prefix glob such as `resource.path like "/repos/*"` is therefore satisfied by
`/repos/../user/keys`, `/repos/%2e%2e/user/keys` and `/repos/..;/user/keys`, which a
normalising origin resolves elsewhere. The service SHALL NOT normalise the path (that
would both change what a policy matches and guess at the upstream's behaviour); instead
it SHALL deny an endpoint request whose path's meaning depends on normalisation rules,
**before any policy is consulted**, with a deny reason naming the ambiguity and the path
as sent. Unambiguous paths SHALL continue to be evaluated with the raw path value.

The guard SHALL NOT be bypassable through the library's public surface: the pieces
that build an authorization request from a policy query and the pieces that convert a
raw authorizer response into a decision SHALL NOT be publicly exported, so this
library offers no route from a policy query to a decision that skips the ambiguity
check. (A caller re-implementing entity construction against the `cedar-policy` crate
directly is outside this guarantee — they are not on this library's decision path,
and no visibility rule can bind code that does not call it.) This is the same
closed-seam property the engine's constructors already have.

The examined part of the target SHALL be everything before the first raw `?`, and no
other truncation SHALL be applied. RFC 3986 §5.2.4 defines `remove_dot_segments` over the
path component alone, so excluding the query is a specified boundary rather than an
assumption about the upstream. In particular a raw `#` SHALL NOT end the scan: an
origin-form request target carries no fragment (RFC 9112 §3.2.1), so whether an upstream
treats a raw `#` as a delimiter is exactly the kind of upstream-dependent meaning this
requirement refuses to guess at.

A path SHALL be treated as ambiguous when, over that part of the target:

1. a segment is `.` or `..` after stripping `;`-parameters — where segments are separated
   by `/` **or `\`**, the WHATWG URL standard folding a backslash onto a forward slash for
   http(s) — at **any** percent-decode
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
parameter), from dots inside a segment (`/repos/foo..bar`), from a `#` or `\` that is not
part of a `.`/`..` segment (`/issues/issue#5`, `/repos/foo\bar`), or from an undecodable
escape that appears only *after* the first decode pass — `/x/50%25-done` legitimately
decodes to `50%-done`, whose stray `%` is data.

#### Scenario: A traversal after a raw `#` is denied

- **WHEN** an endpoint request's path is `/repos/foo#/../../user/keys`
- **THEN** the decision is deny, because the scan does not stop at the `#` — treating it as a fragment delimiter would let everything after it escape inspection while an upstream that does not treat it as one still resolves the traversal

#### Scenario: A traversal built from backslash separators is denied

- **WHEN** an endpoint request's path is `/repos/..%5C../user/keys` or `/repos/\..\user/keys`
- **THEN** the decision is deny, because `\` separates segments wherever `/` does

#### Scenario: A traversal inside the query string is not denied

- **WHEN** an endpoint request's path is `/search?q=..%2F..%2Fetc`
- **THEN** the query part triggers no ambiguity refusal and the request is decided by policy on the raw path

#### Scenario: A literal traversal segment is denied without policy evaluation

- **WHEN** an endpoint request's path contains a literal `..` segment, such as `/repos/../user/keys`
- **THEN** the decision is deny, the reason names the ambiguity and the path, and no policy is credited with the decision

#### Scenario: A percent-encoded or parameterised traversal segment is denied

- **WHEN** an endpoint request's path encodes a traversal segment at any decode depth within the declared bound (`/repos/%2e%2e/user/keys`, `/repos/%252e%252e/user/keys`) or hides it behind `;`-parameters (`/repos/..;/user/keys`)
- **THEN** the decision is deny with the ambiguity named in the reason

#### Scenario: An undecodable path is denied rather than guessed at

- **WHEN** an endpoint request's path contains a malformed percent-escape as sent (`/repos/%zz/foo`) or decodes to non-UTF-8 bytes (`/repos/%c0%ae/foo`)
- **THEN** the decision is deny, because the service cannot know what the upstream will resolve without guessing

#### Scenario: An unambiguous path is still decided by policy

- **WHEN** an endpoint request's path is `/repos/foo/bar` and a permit matches `resource.path like "/repos/*"`
- **THEN** the decision is allow, with the raw path value visible to the policy

#### Scenario: The ambiguity refusal is reproducible offline

- **WHEN** an operator replays a denied ambiguous-path request through the offline check command
- **THEN** the same deny and reason are produced, because the check runs inside evaluation rather than in the HTTP layer

#### Scenario: The bypass pieces are not exported

- **WHEN** the library's public surface is inspected from outside the crate
- **THEN** no public item builds a Cedar authorization request from a policy query or converts a raw authorizer response into a decision, and a visibility tripwire fails the suite if either is re-exported

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

The service SHALL map the envelope's `backend` name to a Cedar `Agent` identifier using operator configuration, and SHALL fall back to the fixed identifier `unknown` when the name is not mapped. The fallback SHALL NOT be configurable: the shipped baseline policy forbids `Nono::Agent::"unknown"` by that exact name, and the value the resolver falls back to and the value the baseline denies SHALL be the same constant, so an unmapped backend name is always an explicit, attributable deny rather than a fall-through to whatever else permits.

#### Scenario: Mapped backend name yields its agent

- **WHEN** configuration maps backend `cedar` to agent `claude-code` and a request arrives with backend `cedar`
- **THEN** the principal's agent ancestor is `Nono::Agent::"claude-code"`

#### Scenario: Unmapped backend name falls back

- **WHEN** a request arrives with a backend name absent from configuration
- **THEN** the agent ancestor is `Nono::Agent::"unknown"`, the identity the shipped baseline forbid denies explicitly

#### Scenario: The fallback and the baseline forbid share one constant

- **WHEN** the shipped baseline pack and the resolver's fallback are compared
- **THEN** the identifier the baseline's `no-unknown-agents` forbid names is the same exported constant the resolver falls back to, so the two cannot drift apart silently

### Requirement: Load policies with traceable identifiers

The service SHALL load every `*.cedar` file in the configured policy directory and assign each policy an identifier of the form `<file stem>:<id annotation or ordinal>`, so a decision names the file and rule that produced it. Duplicate identifiers SHALL be a load failure, never a silent overwrite. Files without the `.cedar` extension SHALL be ignored.

Two shapes of `*.cedar` path SHALL be skipped rather than failing the load: a name starting with `.` or `#` (what editors give lock files and backups, which would otherwise abort every reload for the duration of an editing session), and anything that is not a regular file (a directory, a socket, a symlink with no target). Each skip SHALL be logged at WARN naming the path and the reason, because a skipped file is a policy the operator wrote that decides nothing — a silently ignored `.baseline.cedar` is a hole in the policy set with no trace.

A directory entry the listing itself fails to yield — an entry whose name or metadata cannot be read — SHALL fail the load with an error naming the directory, never be silently dropped: the service cannot classify what it could not read, so it cannot know the entry was not a policy, and an unreadable entry in a policy directory is the shape of a tampering symptom. (At reload, the existing last-known-good requirement applies: the previous set is retained and the failure is logged.)

#### Scenario: Policy identifiers carry file provenance

- **WHEN** `10-git.cedar` contains a policy annotated `@id("no-history-rewrites")` and one without an annotation
- **THEN** the loaded identifiers are `10-git:no-history-rewrites` and `10-git:<ordinal>`

#### Scenario: Duplicate identifiers fail the load

- **WHEN** two policies resolve to the same identifier
- **THEN** loading fails with an error naming the file

#### Scenario: Non-policy files are ignored

- **WHEN** the policy directory also contains a `README.md`
- **THEN** it is not loaded and does not affect validation

#### Scenario: A skipped policy file is named in the log

- **WHEN** the policy directory contains `.baseline.cedar`, an editor lock file `.#10-git.cedar`, or a directory named `archive.cedar`
- **THEN** the load succeeds without them and each skip is logged at WARN naming the path and why it is not in force

#### Scenario: An unreadable directory entry fails the load

- **WHEN** enumerating the policy directory yields an entry that cannot be read
- **THEN** the load fails with an error naming the directory, rather than continuing without the entry as though it did not exist

### Requirement: Refuse to run without a usable policy set

The service SHALL strict-validate the whole policy set against the embedded schema before serving, and SHALL refuse to start when the policy directory is unreadable, contains a syntax error, fails validation, or contains no policies. An empty directory SHALL NOT be treated as a valid deny-everything configuration, because refusing to start is equally fail-closed and far more diagnosable.

The guard SHALL be a property of construction, not of one entry point: every way of building a decision engine that is reachable from outside this crate — from a directory or from a policy set assembled in memory — SHALL apply the non-empty and strict-validation checks. A constructor that skips them SHALL NOT exist in the library's public API, even as a test seam.

#### Scenario: An in-memory policy set goes through the same guards

- **WHEN** a caller builds an engine from a policy set it assembled itself
- **THEN** an empty set is refused and a set that fails strict validation is refused, with the same errors the directory loader reports

#### Scenario: Syntax error prevents startup and names the file

- **WHEN** a policy file contains invalid Cedar
- **THEN** startup fails with an error identifying that file

#### Scenario: Empty policy directory prevents startup

- **WHEN** the policy directory contains no `*.cedar` files
- **THEN** startup fails rather than serving a policy set that denies everything

### Requirement: Hot-reload policies keeping the last known good set

The service SHALL watch the policy directory and reload on change. A successful reload SHALL atomically replace the active policy set and advance a generation counter. A failed reload SHALL retain the previously active set and log the error, so that a mid-session editing mistake cannot brick a running agent.

The watch SHALL debounce bursts, because one editor save produces several filesystem
events and each would otherwise be its own reload. That debounce SHALL have an **upper
bound measured from the first event of a burst**: the reload SHALL run no later than
that bound regardless of how long events keep arriving. A quiet-period debounce alone
terminates on a property of the event stream rather than of the daemon, so a continuous
stream — a misconfigured directory, an unrelated writer, a deliberate one — postpones
every reload for as long as it lasts, and a policy edit made during it is never picked
up. That is a liveness failure, not a correctness one: the postponed reload leaves the
last-known-good set deciding, which is fail-closed by construction. What it defeats is
hot-reload itself, silently, while the operator believes the edit took effect.

When the bound cuts a drain short, the service SHALL log it at WARN, naming that the
drain was truncated. Sustained event traffic in a policy directory is either a
misconfiguration or a symptom, and the operator SHALL NOT have to infer it from reloads
that merely seem late. WARN and not ERROR: nothing has failed and the active set is
intact.

The watch SHALL NOT filter events by whether the loader would load the named path.
A mode change on the policy directory produces an event naming the **directory**, and
the pre-reload trust re-check (see `pdp-operations`) depends on being woken by it;
filtering to `*.cedar` paths would defer that re-check until something happened to
touch a policy file.

#### Scenario: Valid edit takes effect

- **WHEN** a policy file is edited such that a previously permitted command is now forbidden
- **THEN** the generation advances and subsequent evaluations return the new decision

#### Scenario: Broken edit retains previous decisions

- **WHEN** a policy file is edited to contain invalid Cedar, or to violate the schema
- **THEN** the reload fails, the generation does not advance, and evaluations continue to use the last known good policy set

#### Scenario: A continuous event stream cannot postpone a reload indefinitely

- **WHEN** filesystem events arrive in the policy directory faster than the debounce quiet-period, continuously, and a policy file is edited such that a previously permitted command is now forbidden
- **THEN** the edit is adopted and subsequent evaluations return the new decision within the debounce upper bound, rather than waiting for the stream to stop

#### Scenario: A truncated drain is reported

- **WHEN** the debounce upper bound ends a drain that continuing events would otherwise have extended
- **THEN** a WARN log line records that the drain was cut short, so sustained traffic in the policy directory is visible to the operator rather than inferred

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

