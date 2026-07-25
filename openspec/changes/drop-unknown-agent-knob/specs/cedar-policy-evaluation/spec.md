# cedar-policy-evaluation — delta for drop-unknown-agent-knob

## MODIFIED Requirements

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
