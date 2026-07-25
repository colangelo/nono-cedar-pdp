## ADDED Requirements

### Requirement: Strict operator configuration

The service SHALL read a TOML configuration file declaring the bind address, policy directory, audit log path, the approval-backend-name to Cedar `Agent` map, and the unknown-agent identifier. Unknown configuration keys SHALL be a load error, because a silently ignored typo in a security daemon's configuration is worse than a failed start. A leading `~/` in a path SHALL be expanded to the user's home directory.

#### Scenario: Minimal configuration applies documented defaults

- **WHEN** the configuration declares only `policy_dir`
- **THEN** the bind address defaults to `127.0.0.1:8181`, the unknown-agent identifier defaults to `unknown`, and the agent map is empty

#### Scenario: Misspelled key fails the load

- **WHEN** the configuration contains a key the schema does not define
- **THEN** loading fails with a parse error naming the problem

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
refuse. It SHALL also fail closed when the policy directory cannot be inspected at all.
Separately it SHALL warn — loudly, naming the risk — when the policy directory or the
audit log resolves inside the current working directory, so that the repo-relative
development configuration keeps working while being impossible to mistake for a
deployment.

Both checks SHALL be documented for what they actually buy, wherever they are
described:

- The group/world-writable refusal does **nothing** about the sandboxed agent. nono's
  sandboxes are path-based (Seatbelt, Landlock) and do not change uid, so the agent runs
  as the **same user** as this daemon and owner-write is exactly the access it has. The
  refusal defends against a **different and weaker** threat: another local user.
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
