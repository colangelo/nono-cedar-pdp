# Tasks

Implementation detail — exact code, exact test bodies, and verified API signatures — lives in `docs/superpowers/plans/2026-07-25-nono-cedar-pdp-v1.md`. Task groups below map 1:1 to that plan's tasks. Every group is TDD: the failing test comes first.

Global gate for every group: `just lint && just test` must pass before the group's commit.

## 1. Scaffold and configuration

- [x] 1.1 Write failing `Config` tests in `src/config.rs`: minimal config applies defaults, backend→agent map with fallback, unknown key rejected, `~/` expanded. Verify: `cargo test --lib config` → fails with "cannot find type `Config`"
- [x] 1.2 Create `Cargo.toml` with the pinned dependency set, `[lib]` + `[[bin]]`, and the `clippy::unwrap_used`/`expect_used`/`panic` denials. Confirm `nono` appears only under `[dev-dependencies]`
- [x] 1.3 Implement `Config`, `ConfigError`, `expand_tilde`, `Config::agent_for`. Verify: `cargo test --lib config` → 4 passed
- [x] 1.4 Add `Justfile` (default recipe `just --list`, plus `check`/`test`/`lint`/`fmt`/`serve`) and `.gitignore`. Verify: `just check && just test && just lint` → all pass
- [x] 1.5 Commit: `feat: project scaffold and config loading`

## 2. Wire types and upstream conformance guard

- [x] 2.1 Write failing `src/wire.rs` tests using the real captured payloads: command envelope parses, endpoint envelope parses with proxy identity, unknown `capability_type` maps to `Unsupported`, unknown fields tolerated, response serializes to `{"decision":"allow"}` / `{"decision":"deny","reason":…}`. Verify: `cargo test --lib wire` → fails
- [x] 2.2 Implement `WebhookEnvelope`, `ApprovalRequest` (internally tagged on `capability_type`, `#[serde(other)]` → `Unsupported`), `CommandRequest`, `EndpointRequest`, `WebhookResponse`. No `deny_unknown_fields` anywhere in this module. Verify: `cargo test --lib wire` → 5 passed
- [x] 2.3 Write `tests/conformance.rs`: serialize `nono::ApprovalRequest::{Command,Endpoint,Capability}` with upstream's own serde, assert exact key sets, assert our mirrors round-trip, assert `capability` classifies as `Unsupported`, and assert `{"decision":"allow"}` does not parse as `nono::ApprovalDecision`. Verify: `cargo test --test conformance` → 4 passed (first run compiles the `nono` dev-dep, ~30 s)
- [x] 2.4 Commit: `feat: nono wire types with upstream conformance guard`

## 3. PolicyQuery boundary and webhook adapter

- [x] 3.1 Write failing `src/adapter/nono_webhook.rs` tests: command mapping, `caller_kind` derivation for a chained launch, unmapped backend falls back to unknown agent, endpoint mapping with proxy identity, unsupported variant errors with a deny reason, malformed body errors with a deny reason. Verify: `cargo test --lib adapter` → fails
- [x] 3.2 Implement `src/query.rs`: `PolicyQuery`, `Target`, `CallerKind`, `action_name()`, `resource_summary()`
- [x] 3.3 Implement `parse(body, config) -> Result<PolicyQuery, AdaptError>` and `AdaptError::deny_reason()`. Verify: `cargo test --lib` → all pass, including 6 adapter tests
- [x] 3.4 Commit: `feat: PolicyQuery boundary and nono webhook adapter`

## 4. Cedar schema

- [x] 4.1 Create `nono.cedarschema` exactly as given in the plan: `Caller in Session in Agent`, `Command` with `args: Set<String>`, `HttpEndpoint`, actions `launchCommand`/`httpRequest` with optional `reason?` context
- [x] 4.2 Write failing `src/cedar/schema.rs` tests: schema compiles and exposes both actions, a well-formed policy strict-validates, a set-membership argument policy validates, a policy referencing `resource.cwd` fails validation. Verify: `cargo test --lib cedar::schema` → fails
- [x] 4.3 Implement `SCHEMA_SRC` (`include_str!`), `load()` surfacing `SchemaWarning`s via `tracing::warn`, `SchemaLoadError`. Verify: `cargo test --lib cedar::schema` → 4 passed
- [x] 4.4 Commit: `feat: embedded Cedar schema for nono approval requests`

## 5. Policy loading, validation, and the validate CLI

- [x] 5.1 Write failing `src/cedar/engine.rs` loader tests: provenance ids from `@id`/ordinal, non-`.cedar` files ignored, empty dir is `PolicyLoadError::Empty`, syntax error names the file, schema violation is `Validation`, duplicate ids in one file are `Duplicate`, `bootstrap` exposes a snapshot at generation 1. Verify: `cargo test --lib cedar::engine` → fails
- [x] 5.2 Implement `LoadedPolicies`, `PolicyLoadError`, `load_dir(dir, schema, generation)` using `PolicySet::from_str` per file plus `Policy::new_id` (no manual `;` splitting), then `Validator::new(schema.clone()).validate(…, ValidationMode::Strict)`
- [x] 5.3 Implement `Engine::{bootstrap, snapshot, schema, policy_dir, reload}` over `ArcSwap<LoadedPolicies>`. Verify: `cargo test --lib cedar::engine` → 7 passed
- [x] 5.4 Add the clap CLI skeleton in `src/main.rs` with the `validate` subcommand and `tracing_subscriber` init. Verify: `cargo run -- validate --config ./nono-cedar-pdp.toml` against a one-policy dir → `OK: 1 policies loaded and validated`, exit 0
- [x] 5.5 Commit: `feat: policy loading with strict validation and validate CLI`

## 6. Entity building, decisions, and the check CLI

- [x] 6.1 Write failing evaluation tests in `src/cedar/engine.rs`: allow names the permitting policy (`matrix:allow-git`), forbid names the forbidding policy, nothing-matched gives an empty matched list and a "no policy" reason, unmapped agent denied, endpoint GET allowed and DELETE denied, `eval_us > 0`. Verify: `cargo test --lib cedar::engine` → fails
- [x] 6.2 Implement `src/decision.rs`: `Decision{allow, matched, reason, eval_us}`, `deny()`, `from_response()` (sorted matched ids; **evaluation errors force deny even on Allow**), `to_wire()`
- [x] 6.3 Implement `src/cedar/entities.rs`: `build(query, schema) -> (Request, Entities)` with the `Caller in Session in Agent` slice, resource attributes, context pairs (omitting `reason` when absent), and identifier escaping of `\` and `"`
- [x] 6.4 Implement `Engine::evaluate` — never returns an error; entity-build failure becomes a logged deny. Verify: `cargo test --lib` → all pass
- [x] 6.5 Add the `check <fixture>` subcommand; create `tests/fixtures/git-status.json`. Verify: `cargo run -- check --config ./nono-cedar-pdp.toml tests/fixtures/git-status.json` → `ALLOW: permitted by …`
- [x] 6.6 Commit: `feat: cedar entity building, decisions, and check CLI`

## 7. Decision audit log

- [ ] 7.1 Write failing `src/audit.rs` tests: two decisions produce two parseable lines with the full field set and an RFC 3339 timestamp; the created file is mode `0600`; a missing parent directory is created. Verify: `cargo test --lib audit` → fails
- [ ] 7.2 Implement `AuditLog::open` (creates parents, `0600`, append) and `AuditLog::record` (serialize failure and write failure are logged and swallowed, never altering a decision), plus `AuditRecord`. Verify: `cargo test --lib audit` → 2 passed
- [ ] 7.3 Wire the audit log into `check`. Verify: run `check`, then `tail -1 ./decisions.jsonl` → a line containing `"decision":"allow"`
- [ ] 7.4 Commit: `feat: JSONL decision audit log`

## 8. HTTP decision endpoint

- [ ] 8.1 Write failing `tests/server.rs`: permitted command → `200 {"decision":"allow"}`; unpermitted → `200` deny with a "no policy" reason; malformed body → **`200` deny, not 4xx**; unsupported variant → `200` deny; every decision audited (exactly one line); `/healthz` reports generation 1 and 1 policy. Verify: `cargo test --test server` → fails
- [ ] 8.2 Implement `src/server.rs`: `AppState`, `router()` with `CatchPanicLayer`, `POST /v1/approve` taking `Bytes` (**not** `Json<T>`, so a malformed body yields our deny reason instead of axum's 400), `GET /healthz`, and the defensive empty-policy-set `503` guard
- [ ] 8.3 Implement `serve()` binding a `TcpListener` and add the `serve` subcommand with a tokio runtime. Verify: `cargo test --test server` → 6 passed
- [ ] 8.4 Manual smoke: start `serve`, then `curl /healthz`, `curl -d @tests/fixtures/git-status.json /v1/approve`, `curl -d 'garbage' /v1/approve`. Verify: health JSON, `{"decision":"allow"}`, `{"decision":"deny","reason":"malformed…"}`
- [ ] 8.5 Commit: `feat: fail-closed HTTP decision endpoint with health check`

## 9. Policy hot-reload

- [ ] 9.1 Write failing reload tests in `src/cedar/engine.rs`: a valid edit advances the generation and changes the decision; a syntax-error edit keeps the last-good set and does not advance the generation; a schema-violating edit likewise. Verify: `cargo test --lib cedar::engine::tests::reload` → these three are the D7 contract and must pass
- [ ] 9.2 Write a failing `src/watcher.rs` test: an edit to a policy file causes a reload within 5 s. Verify: `cargo test --lib watcher` → fails
- [ ] 9.3 Implement `watcher::spawn(engine)` — `notify` watcher on the policy dir, 150 ms debounce draining the editor's event burst, reload errors logged without replacing the active set. Verify: `cargo test --lib watcher` → passes
- [ ] 9.4 Wire the watcher into `serve`, bound to `_watcher` so it is not dropped immediately. Verify manually: `/healthz` shows generation 1, append a valid policy → generation 2, append broken Cedar → still generation 2
- [ ] 9.5 Commit: `feat: policy hot-reload keeping last-good set on failure`

## 10. Starter policies, nono wiring, and end-to-end proof

- [ ] 10.1 Write `policies/00-baseline.cedar` (session-launches-only forbid; deny unmapped `Agent::"unknown"`) and `policies/10-git.cedar` (read-only git permit; forbid `--force`/`--force-with-lease`/`--hard` by set membership). Remove the scratch `policies/starter.cedar` with `trash`. Verify: `cargo run -- validate --config ./nono-cedar-pdp.toml` → `OK: 4 policies loaded and validated`
- [ ] 10.2 Add `tests/fixtures/git-force-push.json`. Verify: `check` on `git-status.json` → `ALLOW: permitted by 10-git:git-read-only`; `check` on `git-force-push.json` → `DENY: denied by 10-git:no-history-rewrites`
- [ ] 10.3 Generate the nono profile with `nono profile init cedar-pdp-smoke`, merge in the `command_policies` block (webhook + chain + terminal backends, `approval_defaults.backend`, `git` intercept rules on `status` and `push`), copy to `examples/cedar-pdp-smoke.json`. Verify: `nono profile validate examples/cedar-pdp-smoke.json` → OK. nono's own schema is authoritative over the plan if they disagree
- [ ] 10.4 Add the `just smoke` recipe: start the daemon, wait for `/healthz`, run `nono run --profile cedar-pdp-smoke -- git status` (expect success), run `nono run … -- git push --force` (expect block), assert both an allow and a deny line in the audit log. Verify: `just smoke` → `SMOKE PASSED`
- [ ] 10.5 Write `README.md` covering: what it is (nono = PEP, Cedar = PDP); the verified contract with a real payload; quick start; the nono profile snippet; the three rollout postures; **the three schema caveats** (`args` is a set so no positional matching, `argv` globs are forbid-only — the loader now warns about any `permit` that reads `argv` — endpoint requests have no session identity, so the daemon *pins* `Caller/Session::"proxy"` instead of trusting the payload); the identity limitation that nono sends a caller *label* not a kind, so a profile intercepting a command literally named `session` is indistinguishable from a direct launch; the unauthenticated-webhook risk and the https-on-loopback follow-up; pointers to spec, ADR and research docs
- [ ] 10.6 Final gate: `just fmt && just lint && just test && just smoke` → all green. Commit: `feat: starter policy pack, nono profile, README, e2e smoke test`
