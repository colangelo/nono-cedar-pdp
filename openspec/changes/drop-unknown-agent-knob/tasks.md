# Tasks: drop-unknown-agent-knob

TDD throughout: failing test first, watched failing for the right reason.

## 1. Constant and config removal

- [x] 1.1 Failing test: a config setting `unknown_agent = "anything"` fails to load and the error text names `unknown_agent` (pin the serde deny_unknown_fields message for this key)
- [x] 1.2 Failing test: the shipped `policies/00-baseline.cedar` `no-unknown-agents` forbid names exactly `Nono::Agent::"<config::UNKNOWN_AGENT>"` — the constant and the shipped pack cannot drift apart
- [x] 1.3 Implement: add `pub const UNKNOWN_AGENT: &str = "unknown"` to `config`; remove the `unknown_agent` field, its serde default fn, and its default-value assertion; `agent_for` falls back to the constant
- [x] 1.4 Update every `Config { .. }` struct literal in tests (`adapter/nono_webhook.rs`, `server.rs`, `audit.rs`) — the compiler enumerates them; no test may re-introduce the field (it also enumerated `tests/server.rs` and `tests/policies.rs`)

## 2. Documentation

- [x] 2.1 README: remove the `# unknown_agent = "unknown"` example line; add the one-sentence contract (fallback is fixed; shipped baseline denies it; unmapped backend is always a loud deny)

## 3. Verification

- [ ] 3.1 `just test` full and filtered (`cargo test --lib config`) green; `just lint` clean
- [ ] 3.2 `openspec validate --changes drop-unknown-agent-knob` passes
