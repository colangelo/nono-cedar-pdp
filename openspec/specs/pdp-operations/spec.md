# pdp-operations

## Purpose

The operator's surface. Configuration and its strict parsing, the mapping from nono
approval-backend names to Cedar agent identities, the `serve`/`validate`/`check` commands, the
documented nono profile wiring and rollout postures, and the requirement that the daemon's own
state — policy directory and audit log — lives outside any tree the sandboxed agent can write.
Also owns keeping the documentation honest about the limits of the decision surface.
## Requirements
### Requirement: Strict operator configuration

The service SHALL read a TOML configuration file declaring the bind address, policy directory, audit log path, and the approval-backend-name to Cedar `Agent` map. Unknown configuration keys SHALL be a load error, because a silently ignored typo in a security daemon's configuration is worse than a failed start. The unknown-agent fallback identity SHALL NOT be configurable: the shipped baseline policy denies `Nono::Agent::"unknown"` by that exact name, and a knob that renames the fallback silently disables the deny. A leading `~/` in a path SHALL be expanded to the user's home directory.

#### Scenario: Minimal configuration applies documented defaults

- **WHEN** the configuration declares only `policy_dir`
- **THEN** the bind address defaults to `127.0.0.1:8181` and the agent map is empty

#### Scenario: Misspelled key fails the load

- **WHEN** the configuration contains a key the schema does not define
- **THEN** loading fails with a parse error naming the problem

#### Scenario: A configuration carrying the removed unknown_agent key fails loudly

- **WHEN** a configuration sets `unknown_agent`, the key that once renamed the fallback identity
- **THEN** loading fails with a parse error naming `unknown_agent`, so the operator learns the knob is gone rather than having the setting silently ignored

#### Scenario: Home-relative paths are expanded

- **WHEN** a path is written as `~/policies`
- **THEN** the resolved path is absolute and contains no `~`

### Requirement: Validate policies without running the daemon

The service SHALL provide a `validate` subcommand that loads and strict-validates the configured policy directory, reports the number of policies loaded, and exits non-zero on failure, so policy changes can be gated in CI or a pre-commit hook.

#### Scenario: Valid policy directory reports success

- **WHEN** `validate` runs against a directory of schema-valid policies
- **THEN** it prints the policy count and exits zero

#### Scenario: Invalid policy directory fails the command

- **WHEN** `validate` runs against a directory containing a policy that fails validation
- **THEN** it prints the validation errors and exits non-zero

### Requirement: Evaluate a saved payload offline

The service SHALL provide a `check` subcommand that evaluates a saved approval payload file against the configured policies and reports the decision, matched policies, and evaluation time. This SHALL be usable to reproduce a production decision without running nono.

#### Scenario: Saved payload reproduces a decision

- **WHEN** `check` is given a file containing a nono approval envelope
- **THEN** it prints whether the request is allowed or denied together with the reason, and exits zero for allow and non-zero for deny

### Requirement: Run as a daemon

The service SHALL provide a `serve` subcommand that loads configuration, compiles the schema, loads and validates policies, opens the audit log, starts watching the policy directory, and listens on the configured loopback address. Any failure in that startup sequence SHALL prevent the daemon from listening.

#### Scenario: Startup failure prevents listening

- **WHEN** policies fail to load at startup
- **THEN** `serve` reports the failure and exits non-zero without binding a port

#### Scenario: Successful startup serves decisions

- **WHEN** startup completes
- **THEN** the daemon answers `POST /v1/approve` and `GET /healthz` on the configured loopback address

### Requirement: Document nono wiring and staged rollout

The project SHALL document the nono profile configuration that routes approvals to the daemon, including the three supported postures: Cedar alone, Cedar with a terminal fallback via nono's `chain` backend in `any` mode, and Cedar plus mandatory human confirmation via `chain` in `all` mode. The documentation SHALL state that the `chain` postures are the intended safe-rollout mechanism, so no dry-run mode exists in the daemon.

#### Scenario: Documented profile is accepted by nono

- **WHEN** the documented example profile is checked with nono's own profile validator
- **THEN** validation succeeds

#### Scenario: Fallback posture is documented

- **WHEN** an operator wants Cedar decisions without being blocked by a policy gap
- **THEN** the documentation directs them to a `chain` backend in `any` mode over the Cedar and terminal backends, where a Cedar denial results in an interactive prompt

### Requirement: Keep the policy directory and audit log outside the agent-writable tree

The policy directory is hot-reloaded and the audit log is the compensating control for an
unauthenticated webhook, so write access to either is write access to the daemon's own
trust boundary: a sandboxed agent that can create a `*.cedar` file has the PDP adopt
`permit (principal, action, resource);` within a debounce interval, and one that can write
the audit log can truncate or forge the record of what was decided. The shipped
configuration, the documented quick start and the end-to-end smoke recipe SHALL therefore
resolve `policy_dir` and `audit_log` outside any directory a sandboxed agent can write —
which excludes CWD-relative paths, because the documented smoke path runs
`nono run --allow-cwd` with a read-write workdir grant in the repository root. The shipped
defaults SHALL be home-anchored: `~/.config/nono-cedar-pdp/policies` and
`~/.local/state/nono-cedar-pdp/decisions.jsonl`.

#### Scenario: Shipped configuration is not CWD-relative

- **WHEN** the shipped configuration file is loaded
- **THEN** `policy_dir` and `audit_log` resolve to absolute home-anchored paths — `~/.config/nono-cedar-pdp/policies` and `~/.local/state/nono-cedar-pdp/decisions.jsonl` — and neither is relative to the working directory nor inside the repository working tree

#### Scenario: The agent's write grants do not reach the policy directory

- **WHEN** the documented example nono profile grants the agent read-write access to its workdir and an agent process writes everywhere that grant allows
- **THEN** the configured policy directory and audit log lie outside that grant, so no policy file can be created, replaced or removed and no audit line can be altered from inside the sandbox

#### Scenario: The smoke recipe uses the configured paths

- **WHEN** the end-to-end smoke recipe runs
- **THEN** it starts the daemon with a configuration whose policy directory and audit log sit outside the sandboxed workdir, and it reads its assertions from that configured audit-log path rather than from a repository-root file

### Requirement: Check the daemon's own state paths at startup, and do not overstate the checks

`serve` SHALL, before loading policies, opening the audit log or binding a socket,
refuse to start when the policy directory or any policy file the loader would load is
group- or world-writable, naming the path, the mode and the `chmod go-w` remedy; a
`.cedar` name the loader skips (an editor lock file or backup) SHALL NOT be a reason to
refuse. It SHALL also refuse to start when any **existing ancestor** of the resolved
policy directory or of the resolved audit log is group- or world-writable **without the
sticky bit**, naming the ancestor path and mode: a loosely-writable non-sticky ancestor
lets another local user rename the directory out from under the daemon and substitute
their own, so the mode of the directory itself never mattered. The sticky bit exempts
an *ancestor* — it prevents renaming or unlinking entries owned by someone else, which
is the ancestor attack — but SHALL NOT exempt the policy directory itself, where the
attack is creating a new `*.cedar` file and sticky does not prevent creation.

Mode bits alone are not the whole check, because an owner may change them at will:
`serve` SHALL also refuse to start when the policy directory, a loadable policy file,
an existing ancestor of either state path, or the audit log file itself (when it
exists) is **owned by neither the daemon's effective user nor root**, naming the path
and the owning uid. A component another local user owns passes every mode test while
that user retains the power to loosen, rename or rewrite it — the sticky bit stops
renames of entries you do not own, but it does not stop an attacker *pre-creating* a
component and owning it, and ownership is the check that closes that half.

The refusal checks and the policy loader SHALL operate on the **same resolved path**:
`serve` resolves the configured `policy_dir` (and the existing prefix of `audit_log`)
once at startup, before the checks, and every later load, watch and reload re-check
uses the resolved path — so a symlink on the configured path cannot be repointed after
startup to redirect a load to a tree the checks never saw, and a symlink already
pointing at an attacker-owned tree is caught by the ownership refusal on the resolved
components.

A writability refusal's remedy text SHALL NOT overpromise: alongside `chmod go-w` it
SHALL tell the operator that content added or modified while the path was writable by
others is not undone by tightening the mode, so the directory's contents need review
before the remedy is applied.

It SHALL also fail closed when the policy directory, a policy file, or an ancestor
cannot be inspected at all. Separately it SHALL warn — loudly, naming the risk — when
the policy directory or the audit log resolves inside the current working directory, so
that the repo-relative development configuration keeps working while being impossible
to mistake for a deployment.

Both checks SHALL be documented for what they actually buy, wherever they are
described:

- The group/world-writable refusal — on the paths themselves and on their ancestors —
  does **nothing** about the sandboxed agent. nono's sandboxes are path-based
  (Seatbelt, Landlock) and do not change uid, so the agent runs as the **same user**
  as this daemon and owner-write is exactly the access it has. The refusal defends
  against a **different and weaker** threat: another local user.
- The working-directory warning is a **heuristic proxy** and is wrong in both
  directions: it misses an absolute `policy_dir` that happens to sit inside a granted
  tree (on macOS the default profile groups grant write to `/tmp`, `$TMPDIR` and
  `/var/folders`), and it fires on a development run where no agent exists.
- The only control that actually prevents the escalation is the nono profile not
  granting write access to those paths, so the documentation SHALL give a reader the
  concrete procedure for checking a profile against that rule: the resolved write grants
  (`nono profile show <profile> --format manifest`, filtered to grants whose access
  includes write — which covers `filesystem.allow`/`write`/`allow_file`/`write_file`,
  `workdir.access: "readwrite"`, `--allow-cwd` and any group-supplied grant) plus every
  `command_policies.commands.*.from.*.sandbox.fs_write` and `fs_write_file` entry in the
  profile, which the resolved manifest does **not** include.

#### Scenario: A group-writable policy directory refuses to start

- **WHEN** `serve` is given a policy directory whose mode grants write to group or other
- **THEN** it exits non-zero without binding a port, and the message names the path, the mode and the `chmod go-w` remedy

#### Scenario: A loosely-writable non-sticky ancestor of the policy directory refuses to start

- **WHEN** `serve` is given a policy directory that is itself owner-only but has an existing ancestor whose mode grants write to group or other without the sticky bit
- **THEN** it exits non-zero without binding a port, and the message names the ancestor path and its mode

#### Scenario: A sticky world-writable ancestor is not a refusal

- **WHEN** the resolved policy directory or audit log sits below an ancestor whose mode is world-writable with the sticky bit set (`/tmp`-style, mode `1777`)
- **THEN** that ancestor is not a reason to refuse, because the sticky bit prevents another user from renaming or unlinking entries they do not own

#### Scenario: A loosely-writable non-sticky ancestor of the audit log refuses to start

- **WHEN** `serve` resolves an audit log whose existing ancestor chain contains a directory writable by group or other without the sticky bit
- **THEN** it exits non-zero without binding a port, and the message names the ancestor path and its mode — a substituted audit directory silently redirects the record of what was decided

#### Scenario: A state-path component owned by another user refuses to start

- **WHEN** the policy directory, a loadable policy file, an existing ancestor of either state path, or an existing audit log file is owned by a uid that is neither the daemon's effective user nor root — for example a policy directory another local user pre-created under a sticky world-writable ancestor, with modes that look tight
- **THEN** `serve` exits non-zero without binding a port, and the message names the path and the owning uid, because an owner can loosen, rename or rewrite the component regardless of its current mode

#### Scenario: A symlinked policy path is resolved once, before the checks

- **WHEN** `policy_dir` is configured through a symlink
- **THEN** the daemon resolves the path before the startup checks and uses the resolved path for loading, watching and every reload re-check, so repointing the symlink after startup does not redirect any later load to a tree the checks never inspected

#### Scenario: The writability remedy warns about content changed while loose

- **WHEN** a writability refusal is reported for the policy directory or a policy file
- **THEN** the message tells the operator that tightening the mode does not undo content added or modified while the path was writable, so the contents need review before `chmod go-w` is applied

#### Scenario: A loose file the loader ignores is not a refusal

- **WHEN** the policy directory contains a group-writable `.cedar` name the loader skips, such as an editor lock file
- **THEN** startup is not refused on account of that file

#### Scenario: A policy directory inside the working directory warns

- **WHEN** `serve` resolves `policy_dir` or `audit_log` inside the current working directory
- **THEN** it logs a warning that names the path, the profile keys that would grant an agent write access to it, that file modes cannot prevent the escalation because the sandbox runs as the same user, and that the check is a proxy that cannot read the profile — and then continues to serve

### Requirement: The shipped policy pack approves a subcommand by position, not by word

A fresh install inherits the shipped pack's posture, so the pack is product surface rather
than an example. Its read-only git permit SHALL identify the subcommand **positionally**,
by an anchored `resource.argv_tail` test, and SHALL NOT approve on set membership of a
subcommand word: `resource.args.contains("status")` is true of
`git -c core.fsmonitor=<cmd> status`, and git runs `<cmd>`, so a membership permit
approves arbitrary command execution. Anchoring also denies otherwise read-only
invocations that place a flag before the subcommand; that is the intended direction for a
permit, and the documented `chain`/`any` posture turns such a denial into a prompt.

Independently of the permit, the pack SHALL `forbid` the git flags that execute a command
or relocate the binaries git executes — `-c`, `--config-env`, `--exec-path`,
`--upload-pack`, `--receive-pack` — using exact `args` membership where the value is a
separate argv entry and an `argv_tail` glob where git accepts a `--flag=<value>` spelling
that membership cannot see. Each of the two layers SHALL deny the code-execution
invocation on its own, so neither is load-bearing alone, and the pack SHALL load without
tripping any of the loader's own lints.

#### Scenario: A config-injecting flag before a read-only subcommand is denied

- **WHEN** an approval request carries `command` `git` and `args` `[<shim path>, "-c", "core.fsmonitor=<cmd>", "status"]`
- **THEN** the decision is deny, and the matched-policy list names the flag `forbid`

#### Scenario: Each layer holds with the other removed

- **WHEN** the flag `forbid` is removed from the loaded pack and the same request is evaluated
- **THEN** the decision is deny with an empty matched-policy list, because the anchored permit cannot fire when the subcommand is not first
- **AND WHEN** the anchored permit is instead replaced by a membership-shaped permit (`resource.args.contains("status")`)
- **THEN** the decision is still deny and the matched-policy list names the flag `forbid`

#### Scenario: Read-only invocations are still approved

- **WHEN** an approval request carries `args` `[<shim path>, "status"]`, `[<shim path>, "status", "--porcelain"]`, `[<shim path>, "log", "-n", "5"]` or `[<shim path>, "show", "HEAD"]`
- **THEN** the decision is allow and the matched-policy list names the read-only permit

#### Scenario: A read-only word elsewhere in the argv approves nothing

- **WHEN** an approval request carries `args` `[<shim path>, "commit", "-m", "status"]`, `[<shim path>, "commit", "--amend", "-m", "log"]`, `[<shim path>, "reset", "--soft", "status"]` or `[<shim path>, "clone", "ext::sh -c evil", "status"]`
- **THEN** the decision is deny and the read-only permit is not among the matched policies

### Requirement: Documented rollout postures exist in the shipped example profile

Every approval backend the documentation tells an operator to select SHALL be defined in
the shipped example nono profile, because nono's profile validator rejects an
`approval_defaults.backend` that names an undefined backend — a posture the documentation
names but the profile does not define is a step the operator cannot take. The documented
postures and the example profile SHALL be consistent in both directions.

#### Scenario: Every documented posture names a defined backend

- **WHEN** the documented rollout-posture table names the backends for the fallback, enforce and mandatory-confirmation postures
- **THEN** the shipped example profile defines a backend with each of those exact names, including the `chain` backend in `all` mode used by the mandatory-confirmation posture

#### Scenario: Switching to the documented posture yields a valid profile

- **WHEN** an operator follows the documentation and switches `approval_defaults.backend` in the shipped example profile to the backend named for the mandatory-confirmation posture
- **THEN** nono's own profile validator accepts the result, rather than failing with an unknown-approval-backend error

### Requirement: Document the decision-surface limits and known risks

The project documentation SHALL state the limits that follow from nono's contract: only `command` and `endpoint` approvals reach the daemon; filesystem capability elevation cannot be arbitrated; argument positions are untrustworthy so `args` is a set; `args[0]` is an absolute per-run shim path rather than the command name, so the command name is read from `command`, there is no whole-argv attribute at all, and anchored patterns belong on `argv_tail`; set membership cannot express position, so a subcommand is pinned with an anchored `argv_tail` test and a membership permit on a subcommand word approves far more than it names; *unanchored* `argv_tail` globs over-match text inside a single argument and are therefore safe only in `forbid`; endpoint paths arrive raw and unnormalised, so an ambiguous path is denied outright; endpoint requests carry no session identity; and the webhook is unauthenticated in both directions, so the daemon must bind loopback only.

#### Scenario: Argument-matching guidance is documented

- **WHEN** a policy author consults the documentation on matching command arguments
- **THEN** they are told to test flags by set membership rather than by position, to pin a subcommand with an anchored `argv_tail` test (`== "status"` or `like "status *"`) because membership cannot express position, and that an `argv_tail` glob beginning with a wildcard belongs only in a `forbid`

#### Scenario: The raw-path caveat is documented

- **WHEN** a policy author consults the documentation on matching `resource.path`
- **THEN** they are told the path is the raw request target (unnormalised, still percent-encoded, query string included), that the daemon does not normalise it, and that a path whose meaning depends on normalisation — a `.`/`..` segment at any decode depth, an undecodable escape — is denied before any policy is consulted

#### Scenario: The shim-path shape of args[0] is documented

- **WHEN** a policy author consults the documentation on the payload nono sends
- **THEN** the example payload shows `args[0]` as an absolute per-run shim path, and the documentation states that `command` carries the command name, that a pattern anchored over the whole argv could never match at runtime — fail-safe in a `permit` and fail-open in a `forbid` — that the whole-argv attribute is therefore removed rather than deprecated (a policy reading `resource.argv` fails validation), and that `argv_tail` is the anchoring target

#### Scenario: Impersonation risk is documented

- **WHEN** an operator reviews the security posture
- **THEN** the documentation states that nono cannot authenticate the decider, that binding is loopback-only for that reason, and that https-on-loopback is the planned mitigation

### Requirement: Re-check the state paths before adopting a reloaded policy set

The hot-reload path SHALL re-run the writability and ownership checks — the policy
directory, every policy file the loader would load, and the existing ancestor chain —
before a freshly loaded policy set replaces the active one. When the re-check refuses, the daemon SHALL
retain the last-known-good policy set, SHALL NOT adopt any file content read from the
offending directory, and SHALL log the refusal at ERROR naming the path and mode — the
same containment posture as a broken policy edit, because the in-memory set predates
the loosening and is the only trusted policy state left. The watch SHALL survive the
refusal: once the mode is repaired, a subsequent edit SHALL be adopted normally.

The re-check carries the same scope honesty as the startup check, in code comments and
operator documentation: it defends against other local users, and says nothing about
the sandboxed agent, which runs as the same user as the daemon and is bounded only by
its nono profile's write grants.

#### Scenario: A policy directory that becomes loosely writable mid-session is not adopted

- **WHEN** the policy directory, a loadable policy file, or an existing ancestor becomes group- or world-writable (non-sticky, for ancestors) while the daemon is running, and a filesystem event triggers a reload
- **THEN** the active policy set and its generation are unchanged, decisions keep flowing from the last-known-good set, and an ERROR log line names the offending path and its mode

#### Scenario: The watcher survives a reload-time refusal

- **WHEN** a reload was refused because a state path was loosely writable, and the operator then repairs the mode and edits a policy file
- **THEN** the subsequent reload is adopted, proving the refusal neither stopped the daemon nor killed the watch

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

