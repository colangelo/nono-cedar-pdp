# pdp-operations — delta for make-smoke-work-in-a-worktree

## MODIFIED Requirements

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

The smoke recipe MAY accommodate the shape of the checkout it runs in — notably a git
worktree, where `.git` is a pointer file and the real git directory lies under the
primary checkout, outside every grant the profile makes. Any such accommodation SHALL
grant **read** access only, and SHALL NOT widen any write surface of the profile. This
is asserted mechanically rather than stated: the write-granting surfaces of the profile
the run uses SHALL be byte-identical to the shipped example, and the recipe SHALL fail
if they are not. The reason is the requirement above — a write grant added for the
convenience of a tool is indistinguishable, to the agent inside the sandbox, from one
added on purpose.

Where the recipe generates a profile rather than using the tracked example verbatim,
the containment assertion SHALL read the **generated** profile, because the grants that
matter are the ones the run actually makes. An assertion that inspects a profile the
run does not use would pass while the run reached the daemon's own state.

#### Scenario: Shipped configuration is not CWD-relative

- **WHEN** the shipped configuration file is loaded
- **THEN** `policy_dir` and `audit_log` resolve to absolute home-anchored paths — `~/.config/nono-cedar-pdp/policies` and `~/.local/state/nono-cedar-pdp/decisions.jsonl` — and neither is relative to the working directory nor inside the repository working tree

#### Scenario: The agent's write grants do not reach the policy directory

- **WHEN** the documented example nono profile grants the agent read-write access to its workdir and an agent process writes everywhere that grant allows
- **THEN** the configured policy directory and audit log lie outside that grant, so no policy file can be created, replaced or removed and no audit line can be altered from inside the sandbox

#### Scenario: The smoke recipe uses the configured paths

- **WHEN** the end-to-end smoke recipe runs
- **THEN** it starts the daemon with a configuration whose policy directory and audit log sit outside the sandboxed workdir, and it reads its assertions from that configured audit-log path rather than from a repository-root file

#### Scenario: The smoke recipe runs from a git worktree

- **WHEN** the end-to-end smoke recipe runs from a git worktree, where the real git directory lies outside the sandboxed workdir
- **THEN** the sandboxed command is granted read-only access to the git directory and the run reaches a real Cedar decision, rather than the command failing on repository discovery after the decision was already made

#### Scenario: A checkout-shape accommodation cannot widen a write grant

- **WHEN** the profile the smoke run uses is generated, and generation would change any write-granting surface of the shipped example
- **THEN** the recipe fails naming the surface, before the daemon is started or any sandboxed command runs
