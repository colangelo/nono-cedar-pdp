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

### Requirement: Document the decision-surface limits and known risks

The project documentation SHALL state the limits that follow from nono's contract: only `command` and `endpoint` approvals reach the daemon; filesystem capability elevation cannot be arbitrated; argument positions are untrustworthy so `args` is a set; `argv` substring globs over-match text inside a single argument and are therefore safe only in `forbid`; endpoint requests carry no session identity; and the webhook is unauthenticated in both directions, so the daemon must bind loopback only.

#### Scenario: Argument-matching guidance is documented

- **WHEN** a policy author consults the documentation on matching command arguments
- **THEN** they are told to use set membership rather than position, and that `argv` globs belong only in `forbid` policies

#### Scenario: Impersonation risk is documented

- **WHEN** an operator reviews the security posture
- **THEN** the documentation states that nono cannot authenticate the decider, that binding is loopback-only for that reason, and that https-on-loopback is the planned mitigation
