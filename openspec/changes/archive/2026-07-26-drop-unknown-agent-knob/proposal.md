# Proposal: drop-unknown-agent-knob

## Why

Gitea issue #25: the shipped `00-baseline:no-unknown-agents` forbid hard-codes
`Nono::Agent::"unknown"`, but the `unknown_agent` config key renames the fallback
identity an unmapped backend resolves to. Setting it turns a fail-loud
misconfiguration (an unmapped backend name is denied by an explicit rule, with the
rule's id in the reason) into a silent fail-open: the fallback agent no longer
matches the forbid, and unmapped backends fall through to whatever else permits
them. A config knob whose only effect is to disable a shipped security policy —
with no demonstrated use — is a trap, not a feature.

## What Changes

- **BREAKING (config):** remove the `unknown_agent` key from the configuration
  schema. Because config parsing is strict (`deny_unknown_fields`), any existing
  config still carrying the key fails to load with an error naming it — the removal
  is fail-loud by construction, which is exactly the posture the knob violated.
- The fallback identity for an unmapped backend becomes the fixed constant
  `unknown`, exported from `config` so the adapter, the entity builder and the
  tests all reference one value — the same value the shipped baseline forbid
  denies. The contract "unmapped backend ⇒ an identity the baseline denies" stops
  being a coincidence of two defaults agreeing and becomes structural.
- README loses the commented `# unknown_agent = "unknown"` example line and gains
  one sentence: the fallback is fixed and the shipped baseline denies it, so an
  unmapped backend name is always a loud deny, not a quiet pass-through.

Of the three options in the issue (drop the knob; make the loader reject a config
whose `unknown_agent` no policy forbids; emit the fallback into the schema), this
takes the first: the second couples config validation to policy-set contents — a
moving target the loader cannot soundly pin — and the third adds schema surface to
express a name nothing legitimately needs to vary.

## Capabilities

### New Capabilities

None.

### Modified Capabilities

- `pdp-operations`: "Strict operator configuration" — the configuration no longer
  declares an unknown-agent identifier; a config carrying the removed key fails
  loudly.
- `cedar-policy-evaluation`: "Resolve agent identity from the approval backend
  name" — the fallback is the fixed identifier `unknown` the shipped baseline
  forbids, not a configured one.

## Impact

- `src/config.rs`: field, default fn and knob-specific test removed; `agent_for`
  falls back to the exported constant.
- `src/adapter/nono_webhook.rs`, `src/server.rs`, `src/audit.rs` tests: struct
  literals updated (field gone).
- `README.md`: example config line replaced by the fixed-fallback sentence.
- Operators (pre-1.0, no known deployments beyond this house): a config with
  `unknown_agent` set stops loading and names the key; deleting the line restores
  the shipped, fail-loud behaviour.
- Gitea: closes #25.
