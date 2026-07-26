# pdp-operations — delta for drop-unknown-agent-knob

## MODIFIED Requirements

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
