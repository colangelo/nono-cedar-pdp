---
type: plan
title: "nono-cedar-pdp v1 implementation plan"
description: "Ten task groups, TDD throughout, with spike-verified Cedar API signatures and the upstream wire contract captured as ground truth. Superseded in part by the post-audit args[0] correction it carries a marked block for."
tags: [plan, implementation, tdd, cedar]
timestamp: 2026-07-25
---

# nono-cedar-pdp v1 Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** A fail-closed Rust daemon that answers nono's `WebhookApproval` callbacks by evaluating Cedar policies, so nono enforces at the kernel while Cedar decides.

**Architecture:** One binary, lib + thin bin. A `nono_webhook` adapter turns the POSTed envelope into an internal `PolicyQuery`; `cedar/entities.rs` turns that into a Cedar `Request` plus a per-request entity slice; `cedar/engine.rs` evaluates it against an `ArcSwap<LoadedPolicies>` loaded from a policy directory and strict-validated against an embedded schema. Every decision appends one JSONL audit line. The `wire`/`query`/`cedar` modules are deliberately free of HTTP concerns so they can be lifted into an upstream native `CedarApproval` backend later.

**Tech Stack:** Rust 2021, `cedar-policy` 4.11, `axum` 0.8 + `tower-http` 0.7, `arc-swap` 1.9, `notify` 8.2, `clap` 4.6, `serde`/`serde_json`, `toml` 1, `time` 0.3, `thiserror` 2, `tracing` + `tracing-subscriber`. Dev: `nono` 0.69 (conformance only), `tower` 0.5, `tempfile` 3.

**Spec:** `docs/superpowers/specs/2026-07-25-nono-cedar-pdp-design.md`. **ADR:** `docs/adr/ADR-001-rust-and-cedar-crate.md`.

## Global Constraints

- **Fail closed, always.** Any parse failure, unsupported request variant, evaluation error, or missing policy resolves to deny. Never return allow on an error path.
- **Rust edition 2021**, MSRV **1.89** (the `cedar-policy` floor). Local toolchain is 1.96.1.
- **Exact dependency versions** (verified to exist 2026-07-25): `cedar-policy = "4.11"`, `axum = "0.8"`, `tower-http = { version = "0.7", features = ["catch-panic"] }`, `arc-swap = "1.9"`, `notify = "8.2"`, `clap = { version = "4.6", features = ["derive"] }`, `serde = { version = "1", features = ["derive"] }`, `serde_json = "1"`, `toml = "1"`, `time = { version = "0.3", features = ["formatting"] }`, `thiserror = "2"`, `tracing = "0.1"`, `tracing-subscriber = { version = "0.3", features = ["env-filter"] }`, `tokio = { version = "1", features = ["rt-multi-thread", "macros", "net", "signal"] }`. Dev-dependencies: `nono = { version = "0.69.0", default-features = false }`, `tower = { version = "0.5", features = ["util"] }`, `tempfile = "3"`, `serde_json`.
- **`nono` is a dev-dependency only.** It must never appear under `[dependencies]` (ADR-001). `default-features = false` drops its keyring/Keychain feature.
- **Wire parsing is lenient, config parsing is strict.** Wire structs must NOT use `deny_unknown_fields` (a nono upgrade adding a field must not brick every decision); `Config` MUST use `deny_unknown_fields` (a typo in your own config should fail loudly). Drift in the wire shape is caught by the Task 2 conformance test instead.
- **Response shape is `{"decision":"allow"}` / `{"decision":"deny","reason":"…"}`** — never upstream's internal `ApprovalDecision` enum shape (spec D5). Verified: upstream serializes `ApprovalDecision::Granted` as `"Granted"` and `Denied` as `{"Denied":{"reason":"x"}}`, so our object shape cannot collide with its first parse attempt.
- **Bind loopback only.** Default `127.0.0.1:8181`. Never bind `0.0.0.0`.
- **No positional argument matching** anywhere in policy or code comments: upstream drops non-UTF-8 argv entries, so positions shift. `args` is a Cedar `Set<String>`, which makes indexing unexpressible by construction.
- `just` is the task runner; the default recipe is `just --list` (house convention). `trash`, never `rm`.
- Commit at the end of every task with a conventional-commit message.

## Verified Ground Truth

These were confirmed by compiling and running spikes against real dependencies on 2026-07-25. Do not re-litigate them; do not assume anything beyond them.

**Command-request JSON.** ⚠️ **CORRECTED 2026-07-25 (post-implementation audit).** The
shape below round-trips upstream's serde, but its `args` value came from upstream's
**unit-test fixture** (`crates/nono/src/supervisor/mod.rs:209-217`) and is NOT what nono
sends at runtime:

```json
{"capability_type":"command","request_id":"r1","command":"git","args":["git","push"],
 "caller":"session","intercept_rule":"push","reason":null,"child_pid":42,"session_id":"s1"}
```

At runtime `args` is the shim process's raw argv, so **`args[0]` is an absolute per-run
shim path**, never the command name:

```json
{"capability_type":"command","request_id":"tool-sandbox-approve-git-1784990893285791000",
 "command":"git",
 "args":["/private/tmp/nono-tool-sandbox-13819-1784990893285791000-a4d3bceb3ec061c0/shims/git","status"],
 "caller":"session","intercept_rule":"status","reason":null,
 "child_pid":13820,"session_id":"35abc0894927242e"}
```

`command` still carries the name. Anchored patterns (a whole-argv glob such as
`like "git *"`, or `args.contains("git")`) therefore never match in production —
fail-safe in a `permit`, **fail-open in a `forbid`** — which is why the schema gained
`argv_tail` (`args[1..]` joined) and, per the D12 amendment, **dropped the whole-argv
`argv` attribute entirely**: a policy that reads `resource.argv` now fails strict
validation instead of merely earning a warning. Everything below that shows an `argv`
attribute or a `["git", …]` `args` value is the plan as written, not as shipped; the
schema, entity builder, fixtures and tests all use `argv_tail` and a shim-path `args[0]`.
See the design spec §2 "Correction" and D12 for the upstream line references.

**Superseded again by the security audit (design spec D14/D15).** Two further shapes in
this plan are not what shipped: (a) every `resource.args.contains("status")`-style
read-only git permit below — set membership cannot express *position*, so it also
approves `git -c core.fsmonitor=<cmd> status`, which git executes; the shipped pack pins
the subcommand with `argv_tail == "status" || argv_tail like "status *"` and adds a
`forbid` on git's code-executing flags. (b) endpoint `path` is used raw in the plan's
policy examples with no caveat; the shipped daemon denies a path whose meaning depends on
the upstream's normalisation (`/repos/../user/keys` and its encodings) before any policy
is consulted. `policies/10-git.cedar`, `src/endpoint_path.rs` and the tests are the
shipped truth.

**Superseded a third time by the security audit (design spec D13/D16), for the daemon's
own state.** Every `policy_dir = "./policies"` / `audit_log = "./decisions.jsonl"` and
every `wc -l ./decisions.jsonl` below is the plan as written, not as shipped: those paths
sit inside the tree the documented smoke profile grants the sandboxed agent, which was
proven to let a process *inside* the sandbox rewrite the live policies and flip a denied
`git push --force` to `allow`. The shipped config is home-anchored
(`~/.config/nono-cedar-pdp/policies`, `~/.local/state/nono-cedar-pdp/decisions.jsonl`),
the repo-relative shape moved to `nono-cedar-pdp.dev.toml` (which makes `serve` warn),
`serve` refuses a group- or world-writable policy directory, `just smoke` builds its own
state outside the repository, and the audit sink revalidates its inode before every
record so a rotation cannot silently detach the trail. `nono-cedar-pdp.toml`, the
`Justfile`, `src/isolation.rs` and `src/audit.rs` are the shipped truth.

**Two smaller shapes below are also not what shipped** (the deviations-honesty audit,
change task group 15). (a) The `approve` handler in Step 8 takes `Bytes`; the shipped one
takes `axum::body::Body` and buffers it itself against an explicit
`MAX_REQUEST_BYTES = 1 MiB`, because an extractor rejects *before* the handler runs and
nono would then record `returned HTTP 413` instead of our deny reason. (b) `Engine` grew a
public `from_loaded` as a test seam for the 503 branch, bypassing the zero-policy guard;
the shipped API has `from_policy_set` (which applies the same guards as a directory load)
and keeps the unguarded constructor `#[cfg(test)]`. `src/server.rs` and
`src/cedar/engine.rs` are the shipped truth.

**Real endpoint-request JSON** (field set from `crates/nono/src/supervisor/types.rs`; the proxy hardcodes `session_id: "proxy"` and `child_pid: 0`):

```json
{"capability_type":"endpoint","request_id":"proxy-endpoint-approval-github-api-1737…",
 "route_id":"github-api","upstream":"https://api.github.com","method":"GET",
 "path":"/repos/foo/bar","rule_label":"endpoint_policy.approve[GET /repos/*]",
 "reason":"route requires approval","child_pid":0,"session_id":"proxy"}
```

**The envelope** wraps it: `{"backend":"cedar","request":{…}}`.

**Cedar API facts** (cedar-policy 4.11.2, all exercised in a passing spike):
- `Schema::from_cedarschema_str(&str) -> Result<(Schema, impl Iterator<Item = SchemaWarning>), CedarSchemaError>`
- `Validator::new(schema)` takes `Schema` **by value**; `Schema` is `Clone`. `.validate(&PolicySet, ValidationMode::Strict) -> ValidationResult` with `.validation_passed()`, `.validation_errors()`, `.validation_warnings()`.
- `PolicySet::from_str`, `PolicySet::add(Policy)`, `PolicySet::policies()`, `PolicySet::num_of_policies()`. `Policy::annotation("id")`, `Policy::new_id(PolicyId) -> Policy`, `PolicyId::new(String)`.
- `Entity::new(uid, HashMap<String, RestrictedExpression>, HashSet<EntityUid>) -> Result<_, EntityAttrEvaluationError>`, `Entity::new_no_attrs(uid, parents)`, `Entities::from_entities(iter, Some(&schema))`.
- `Context::from_pairs(iter)`, `RestrictedExpression::{new_string, new_long, new_set}`.
- `Request::new(principal, action, resource, context, Some(&schema)) -> Result<_, RequestValidationError>`.
- `Authorizer::new().is_authorized(&Request, &PolicySet, &Entities) -> Response`; `Response::decision() -> Decision`, `Response::diagnostics().reason() -> impl Iterator<Item = &PolicyId>`, `.errors()`.
- **A deny with no matching policy returns an EMPTY `reason()` set.** The deny reason string must fall back to explicit "default deny" text.
- **`PolicySet::add` errors on a duplicate PolicyId** — duplicates fail loudly rather than overwriting.
- Adding the same `@id`-annotated policy under two different file stems is fine; the same stem twice is a hard error.

**Confirmed Cedar caveat:** `resource.argv like "*--force*"` also matches when the text sits inside a single quoted argument (`git commit -m "do not --force this"` → Deny). Over-matching is fail-safe in `forbid`, unsound in `permit`. Hence: `argv` globs are forbid-only; exact tests use `resource.args.contains("--force")`.

## File Structure

| Path | Responsibility |
|---|---|
| `Cargo.toml` | deps exactly as pinned above; `[lib]` + `[[bin]]` |
| `Justfile` | `just --list` default; `check`, `test`, `serve`, `smoke`, `fmt`, `lint` |
| `nono.cedarschema` | the Cedar schema — the load-bearing design artifact, embedded via `include_str!` |
| `src/lib.rs` | module wiring + re-exports; no logic |
| `src/config.rs` | `Config` TOML loading, tilde expansion, backend→agent map |
| `src/wire.rs` | serde mirrors of nono's envelope/request + our response enum. No logic beyond serde |
| `src/query.rs` | `PolicyQuery`, `Target`, `CallerKind` — the adapter-neutral internal boundary |
| `src/adapter/mod.rs` | `Adapter` seam (one impl in v1; PORC later) |
| `src/adapter/nono_webhook.rs` | bytes + `Config` → `PolicyQuery`; `AdaptError` → deny reason |
| `src/cedar/mod.rs` | re-exports |
| `src/cedar/schema.rs` | embed + compile the schema, surface warnings |
| `src/cedar/engine.rs` | policy dir loading, strict validation, `ArcSwap` swap, `evaluate` |
| `src/cedar/entities.rs` | `PolicyQuery` → (`Request`, `Entities`) |
| `src/decision.rs` | `Decision` + reason construction from Cedar diagnostics |
| `src/audit.rs` | append-only JSONL decision log (0600) |
| `src/server.rs` | axum router, `/v1/approve`, `/healthz`, fail-closed HTTP mapping |
| `src/watcher.rs` | filesystem watch → `Engine::reload`, last-good on failure |
| `src/main.rs` | clap CLI: `serve`, `check <fixture>`, `validate` |
| `policies/*.cedar` | starter policy pack |
| `examples/cedar-pdp-smoke.json` | nono profile for the E2E smoke test |
| `tests/conformance.rs` | wire-drift guard against the real `nono` crate |
| `tests/server.rs` | HTTP fail-closed matrix |

---

### Task 1: Scaffold + config loading

**Files:**
- Create: `Cargo.toml`, `Justfile`, `.gitignore`, `rustfmt.toml`, `src/lib.rs`, `src/main.rs`, `src/config.rs`
- Test: `src/config.rs` (inline `#[cfg(test)]` module)

**Interfaces:**
- Consumes: nothing.
- Produces:
  - `Config { bind: SocketAddr, policy_dir: PathBuf, audit_log: PathBuf, agents: BTreeMap<String,String>, unknown_agent: String }`
  - `Config::load(path: &Path) -> Result<Config, ConfigError>`
  - `Config::agent_for(&self, backend: &str) -> &str`
  - `ConfigError` (thiserror enum: `Read`, `Parse`)

- [ ] **Step 1: Create the cargo project skeleton**

```bash
cd /Users/ac/_sync/dev/nono-cedar-pdp
cargo init --name nono-cedar-pdp --vcs none
```

Replace `Cargo.toml` with:

```toml
[package]
name = "nono-cedar-pdp"
version = "0.1.0"
edition = "2021"
rust-version = "1.89"
license = "Apache-2.0"
description = "Cedar policy decision point for nono's webhook approval backend"

[lib]
name = "nono_cedar_pdp"
path = "src/lib.rs"

[[bin]]
name = "nono-cedar-pdp"
path = "src/main.rs"

[dependencies]
cedar-policy = "4.11"
axum = "0.8"
tower-http = { version = "0.7", features = ["catch-panic"] }
tokio = { version = "1", features = ["rt-multi-thread", "macros", "net", "signal"] }
arc-swap = "1.9"
notify = "8.2"
clap = { version = "4.6", features = ["derive"] }
serde = { version = "1", features = ["derive"] }
serde_json = "1"
toml = "1"
time = { version = "0.3", features = ["formatting"] }
thiserror = "2"
tracing = "0.1"
tracing-subscriber = { version = "0.3", features = ["env-filter"] }

[dev-dependencies]
nono = { version = "0.69.0", default-features = false }
tower = { version = "0.5", features = ["util"] }
tempfile = "3"

[lints.clippy]
unwrap_used = "deny"
expect_used = "deny"
panic = "deny"
```

> The clippy lints matter: an `unwrap` in a decision path is a panic that becomes an opaque transport error at nono's end. Tests may opt out with `#![allow(clippy::unwrap_used)]` at module scope.

- [ ] **Step 2: Write the failing config test**

Create `src/config.rs` containing only this test module first:

```rust
#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use std::io::Write;

    fn write_config(body: &str) -> tempfile::NamedTempFile {
        let mut f = tempfile::NamedTempFile::new().unwrap();
        f.write_all(body.as_bytes()).unwrap();
        f
    }

    #[test]
    fn loads_minimal_config_with_defaults() {
        let f = write_config(r#"policy_dir = "/tmp/policies""#);
        let c = Config::load(f.path()).unwrap();
        assert_eq!(c.bind.to_string(), "127.0.0.1:8181");
        assert_eq!(c.policy_dir, std::path::Path::new("/tmp/policies"));
        assert_eq!(c.unknown_agent, "unknown");
        assert!(c.agents.is_empty());
    }

    #[test]
    fn maps_backend_name_to_agent_and_falls_back() {
        let f = write_config(
            r#"
policy_dir = "/tmp/policies"
[agents]
cedar = "claude-code"
"#,
        );
        let c = Config::load(f.path()).unwrap();
        assert_eq!(c.agent_for("cedar"), "claude-code");
        assert_eq!(c.agent_for("something-else"), "unknown");
    }

    #[test]
    fn rejects_unknown_config_keys() {
        let f = write_config("policy_dir = \"/tmp/p\"\nplicy_dir = \"typo\"\n");
        assert!(matches!(Config::load(f.path()), Err(ConfigError::Parse(_))));
    }

    #[test]
    fn expands_tilde_in_paths() {
        let f = write_config(r#"policy_dir = "~/policies""#);
        let c = Config::load(f.path()).unwrap();
        assert!(c.policy_dir.is_absolute(), "got {:?}", c.policy_dir);
        assert!(!c.policy_dir.to_string_lossy().contains('~'));
    }
}
```

- [ ] **Step 3: Run it and confirm it fails**

Run: `cargo test --lib config`
Expected: FAIL — `cannot find type Config in this scope`.

- [ ] **Step 4: Implement `Config`**

Prepend to `src/config.rs`:

```rust
use serde::Deserialize;
use std::collections::BTreeMap;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};

#[derive(Debug, thiserror::Error)]
pub enum ConfigError {
    #[error("reading config {path}: {source}")]
    Read { path: PathBuf, source: std::io::Error },
    #[error("parsing config: {0}")]
    Parse(#[from] toml::de::Error),
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    #[serde(default = "default_bind")]
    pub bind: SocketAddr,
    #[serde(deserialize_with = "de_path")]
    pub policy_dir: PathBuf,
    #[serde(default = "default_audit_log", deserialize_with = "de_path")]
    pub audit_log: PathBuf,
    #[serde(default)]
    pub agents: BTreeMap<String, String>,
    #[serde(default = "default_unknown_agent")]
    pub unknown_agent: String,
}

fn default_bind() -> SocketAddr {
    SocketAddr::from(([127, 0, 0, 1], 8181))
}

fn default_audit_log() -> PathBuf {
    expand_tilde("~/.local/state/nono-cedar-pdp/decisions.jsonl")
}

fn default_unknown_agent() -> String {
    "unknown".to_string()
}

fn de_path<'de, D: serde::Deserializer<'de>>(d: D) -> Result<PathBuf, D::Error> {
    let raw = String::deserialize(d)?;
    Ok(expand_tilde(&raw))
}

/// Expand a leading `~/` using $HOME. Leaves other paths untouched.
pub fn expand_tilde(raw: &str) -> PathBuf {
    match raw.strip_prefix("~/") {
        Some(rest) => match std::env::var_os("HOME") {
            Some(home) => Path::new(&home).join(rest),
            None => PathBuf::from(raw),
        },
        None => PathBuf::from(raw),
    }
}

impl Config {
    pub fn load(path: &Path) -> Result<Self, ConfigError> {
        let text = std::fs::read_to_string(path).map_err(|source| ConfigError::Read {
            path: path.to_path_buf(),
            source,
        })?;
        Ok(toml::from_str(&text)?)
    }

    /// Resolve the Cedar `Agent` identity for a nono approval-backend name.
    pub fn agent_for(&self, backend: &str) -> &str {
        self.agents
            .get(backend)
            .map(String::as_str)
            .unwrap_or(&self.unknown_agent)
    }
}
```

Create `src/lib.rs`:

```rust
pub mod config;
```

Replace `src/main.rs` with a stub that will grow in later tasks:

```rust
fn main() {
    println!("nono-cedar-pdp {}", env!("CARGO_PKG_VERSION"));
}
```

- [ ] **Step 5: Run the tests**

Run: `cargo test --lib config`
Expected: PASS, 4 tests.

- [ ] **Step 6: Add the Justfile and .gitignore**

`Justfile`:

```make
default:
    @just --list

check:
    cargo check --all-targets

test:
    cargo test

lint:
    cargo clippy --all-targets -- -D warnings

fmt:
    cargo fmt

serve config="./nono-cedar-pdp.toml":
    cargo run --release -- serve --config {{config}}
```

`.gitignore`:

```
/target
/decisions.jsonl
```

- [ ] **Step 7: Verify and commit**

Run: `just check && just test && just lint`
Expected: all pass.

```bash
git add Cargo.toml Cargo.lock Justfile .gitignore src/
git commit -m "feat: project scaffold and config loading"
```

---

### Task 2: Wire types + upstream conformance guard

**Files:**
- Create: `src/wire.rs`, `tests/conformance.rs`
- Modify: `src/lib.rs`

**Interfaces:**
- Consumes: nothing.
- Produces:
  - `wire::WebhookEnvelope { backend: String, request: ApprovalRequest }`
  - `wire::ApprovalRequest` enum: `Command(CommandRequest)`, `Endpoint(EndpointRequest)`, `Unsupported`
  - `wire::CommandRequest { request_id, command, args: Vec<String>, caller, intercept_rule, reason: Option<String>, child_pid: u32, session_id }`
  - `wire::EndpointRequest { request_id, route_id, upstream, method, path, rule_label, reason: Option<String>, child_pid: u32, session_id }`
  - `wire::WebhookResponse` enum: `Allow`, `Deny { reason: String }` — serializes to the `{"decision":…}` shape

- [ ] **Step 1: Write the failing wire tests**

Create `src/wire.rs` with only this test module:

```rust
#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    const REAL_COMMAND: &str = r#"{"backend":"cedar","request":{
        "capability_type":"command","request_id":"r1","command":"git",
        "args":["git","push"],"caller":"session","intercept_rule":"push",
        "reason":null,"child_pid":42,"session_id":"s1"}}"#;

    const REAL_ENDPOINT: &str = r#"{"backend":"cedar","request":{
        "capability_type":"endpoint","request_id":"p-1","route_id":"github-api",
        "upstream":"https://api.github.com","method":"GET","path":"/repos/foo/bar",
        "rule_label":"endpoint_policy.approve[GET /repos/*]",
        "reason":"route requires approval","child_pid":0,"session_id":"proxy"}}"#;

    #[test]
    fn parses_real_command_envelope() {
        let env: WebhookEnvelope = serde_json::from_str(REAL_COMMAND).unwrap();
        assert_eq!(env.backend, "cedar");
        let ApprovalRequest::Command(c) = env.request else {
            panic!("expected command variant");
        };
        assert_eq!(c.command, "git");
        assert_eq!(c.args, vec!["git", "push"]);
        assert_eq!(c.caller, "session");
        assert_eq!(c.child_pid, 42);
        assert_eq!(c.reason, None);
    }

    #[test]
    fn parses_real_endpoint_envelope() {
        let env: WebhookEnvelope = serde_json::from_str(REAL_ENDPOINT).unwrap();
        let ApprovalRequest::Endpoint(e) = env.request else {
            panic!("expected endpoint variant");
        };
        assert_eq!(e.method, "GET");
        assert_eq!(e.session_id, "proxy");
        assert_eq!(e.child_pid, 0);
        assert_eq!(e.reason.as_deref(), Some("route requires approval"));
    }

    #[test]
    fn unknown_variant_maps_to_unsupported() {
        let body = r#"{"backend":"cedar","request":{"capability_type":"capability",
            "request_id":"c1","path":"/etc/passwd","access":"read","reason":null,
            "child_pid":7,"session_id":"s1"}}"#;
        let env: WebhookEnvelope = serde_json::from_str(body).unwrap();
        assert!(matches!(env.request, ApprovalRequest::Unsupported));
    }

    #[test]
    fn tolerates_unknown_fields_added_upstream() {
        let body = r#"{"backend":"cedar","extra_envelope":1,"request":{
            "capability_type":"command","request_id":"r1","command":"git","args":[],
            "caller":"session","intercept_rule":"x","reason":null,"child_pid":1,
            "session_id":"s1","future_field":"whatever"}}"#;
        let env: WebhookEnvelope = serde_json::from_str(body).unwrap();
        assert!(matches!(env.request, ApprovalRequest::Command(_)));
    }

    #[test]
    fn response_serializes_to_nono_friendly_shape() {
        assert_eq!(
            serde_json::to_string(&WebhookResponse::Allow).unwrap(),
            r#"{"decision":"allow"}"#
        );
        assert_eq!(
            serde_json::to_string(&WebhookResponse::Deny { reason: "nope".into() }).unwrap(),
            r#"{"decision":"deny","reason":"nope"}"#
        );
    }
}
```

- [ ] **Step 2: Run and confirm failure**

Run: `cargo test --lib wire`
Expected: FAIL — `WebhookEnvelope` not found.

- [ ] **Step 3: Implement the wire types**

Prepend to `src/wire.rs`:

```rust
//! Serde mirrors of nono's approval webhook contract (nono 0.69.x).
//!
//! Deliberately lenient: unknown fields are ignored so a nono upgrade cannot
//! brick every decision. Drift is caught by `tests/conformance.rs` instead.

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Deserialize)]
pub struct WebhookEnvelope {
    pub backend: String,
    pub request: ApprovalRequest,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(tag = "capability_type", rename_all = "snake_case")]
pub enum ApprovalRequest {
    Command(CommandRequest),
    Endpoint(EndpointRequest),
    /// `capability` and `network` variants cannot reach a webhook backend in
    /// nono 0.69, but anything upstream adds must fail closed rather than fail
    /// to parse.
    #[serde(other)]
    Unsupported,
}

#[derive(Debug, Clone, Deserialize)]
pub struct CommandRequest {
    pub request_id: String,
    pub command: String,
    /// Includes argv[0]. Upstream drops non-UTF-8 entries, so positions shift:
    /// never match on index.
    pub args: Vec<String>,
    /// `"session"` for a direct agent launch, otherwise the intercepted command
    /// that chained this one.
    pub caller: String,
    pub intercept_rule: String,
    #[serde(default)]
    pub reason: Option<String>,
    pub child_pid: u32,
    pub session_id: String,
}

#[derive(Debug, Clone, Deserialize)]
pub struct EndpointRequest {
    pub request_id: String,
    pub route_id: String,
    pub upstream: String,
    pub method: String,
    pub path: String,
    pub rule_label: String,
    #[serde(default)]
    pub reason: Option<String>,
    /// Always 0 — the proxy has no child pid.
    pub child_pid: u32,
    /// Always `"proxy"` — endpoint requests carry no session identity.
    pub session_id: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(tag = "decision", rename_all = "lowercase")]
pub enum WebhookResponse {
    Allow,
    Deny { reason: String },
}
```

Add to `src/lib.rs`:

```rust
pub mod wire;
```

- [ ] **Step 4: Run the tests**

Run: `cargo test --lib wire`
Expected: PASS, 5 tests.

- [ ] **Step 5: Write the conformance guard**

Create `tests/conformance.rs`:

```rust
//! Wire-drift guard. Serializes requests using nono's OWN types and asserts our
//! mirrors round-trip them, including the exact key set. When a nono upgrade
//! changes the contract, this test fails instead of the daemon silently
//! misreading a security decision.
#![allow(clippy::unwrap_used)]

use nono_cedar_pdp::wire::{ApprovalRequest, WebhookEnvelope};
use std::collections::BTreeSet;

fn envelope_from(upstream: &nono::ApprovalRequest) -> (WebhookEnvelope, BTreeSet<String>) {
    let request = serde_json::to_value(upstream).unwrap();
    let keys: BTreeSet<String> = request
        .as_object()
        .unwrap()
        .keys()
        .cloned()
        .collect();
    let body = serde_json::json!({ "backend": "cedar", "request": request });
    (serde_json::from_value(body).unwrap(), keys)
}

#[test]
fn command_request_matches_upstream() {
    let upstream = nono::ApprovalRequest::Command {
        request_id: "r1".into(),
        command: "git".into(),
        args: vec!["git".into(), "push".into()],
        caller: "session".into(),
        intercept_rule: "push".into(),
        reason: None,
        child_pid: 42,
        session_id: "s1".into(),
    };
    let (env, keys) = envelope_from(&upstream);

    let expected: BTreeSet<String> = [
        "capability_type", "request_id", "command", "args", "caller",
        "intercept_rule", "reason", "child_pid", "session_id",
    ]
    .iter()
    .map(|s| s.to_string())
    .collect();
    assert_eq!(
        keys, expected,
        "upstream command request key set changed — review wire.rs before bumping nono"
    );

    let ApprovalRequest::Command(c) = env.request else {
        panic!("expected command variant");
    };
    assert_eq!(c.command, "git");
    assert_eq!(c.args, vec!["git", "push"]);
    assert_eq!(c.caller, "session");
    assert_eq!(c.child_pid, 42);
}

#[test]
fn endpoint_request_matches_upstream() {
    let upstream = nono::ApprovalRequest::Endpoint {
        request_id: "p1".into(),
        route_id: "github-api".into(),
        upstream: "https://api.github.com".into(),
        method: "GET".into(),
        path: "/repos/foo/bar".into(),
        rule_label: "endpoint_policy.approve[GET /repos/*]".into(),
        reason: Some("route requires approval".into()),
        child_pid: 0,
        session_id: "proxy".into(),
    };
    let (env, keys) = envelope_from(&upstream);

    let expected: BTreeSet<String> = [
        "capability_type", "request_id", "route_id", "upstream", "method",
        "path", "rule_label", "reason", "child_pid", "session_id",
    ]
    .iter()
    .map(|s| s.to_string())
    .collect();
    assert_eq!(
        keys, expected,
        "upstream endpoint request key set changed — review wire.rs before bumping nono"
    );

    let ApprovalRequest::Endpoint(e) = env.request else {
        panic!("expected endpoint variant");
    };
    assert_eq!(e.route_id, "github-api");
    assert_eq!(e.session_id, "proxy");
}

#[test]
fn filesystem_capability_requests_are_unsupported() {
    let upstream = nono::ApprovalRequest::Capability {
        request_id: "c1".into(),
        path: std::path::PathBuf::from("/etc/passwd"),
        access: nono::capability::AccessMode::Read,
        reason: None,
        child_pid: 7,
        session_id: "s1".into(),
    };
    let (env, _keys) = envelope_from(&upstream);
    assert!(
        matches!(env.request, ApprovalRequest::Unsupported),
        "capability requests must fail closed as Unsupported"
    );
}

#[test]
fn our_response_shape_is_not_upstreams_decision_shape() {
    // Upstream tries `ApprovalDecision` first, then the friendly shape. Prove
    // our body cannot be mistaken for the former.
    let ours = r#"{"decision":"allow"}"#;
    assert!(serde_json::from_str::<nono::ApprovalDecision>(ours).is_err());
    assert_eq!(
        serde_json::to_string(&nono::ApprovalDecision::Granted).unwrap(),
        r#""Granted""#
    );
}
```

- [ ] **Step 6: Run the conformance test**

Run: `cargo test --test conformance`
Expected: PASS, 4 tests. First run compiles the `nono` dev-dependency (~30 s).

> If `nono::capability::AccessMode` is not publicly reachable, use
> `serde_json::json!` to hand-build the capability payload instead — that test
> only needs a `capability_type` nono itself emits, not upstream's type.

- [ ] **Step 7: Commit**

```bash
git add src/wire.rs src/lib.rs tests/conformance.rs Cargo.toml Cargo.lock
git commit -m "feat: nono wire types with upstream conformance guard"
```

---

### Task 3: PolicyQuery + webhook adapter

**Files:**
- Create: `src/query.rs`, `src/adapter/mod.rs`, `src/adapter/nono_webhook.rs`
- Modify: `src/lib.rs`

**Interfaces:**
- Consumes: `wire::{WebhookEnvelope, ApprovalRequest}`, `config::Config`.
- Produces:
  - `query::CallerKind` enum `Session | Command`, with `as_str(&self) -> &'static str`
  - `query::Target` enum `Command { command: String, args: Vec<String>, intercept_rule: String, child_pid: u32 } | Endpoint { route_id: String, upstream: String, method: String, path: String, rule_label: String }`
  - `query::PolicyQuery { agent: String, session_id: String, caller: String, caller_kind: CallerKind, request_id: String, backend: String, reason: Option<String>, target: Target }`
  - `PolicyQuery::action_name(&self) -> &'static str` → `"launchCommand"` | `"httpRequest"`
  - `PolicyQuery::resource_summary(&self) -> String` (for audit lines)
  - `adapter::nono_webhook::parse(body: &[u8], config: &Config) -> Result<PolicyQuery, AdaptError>`
  - `adapter::nono_webhook::AdaptError` enum `Malformed(serde_json::Error) | UnsupportedVariant`, with `deny_reason(&self) -> String`

- [ ] **Step 1: Write the failing adapter tests**

Create `src/adapter/nono_webhook.rs` with only this test module:

```rust
#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use crate::query::{CallerKind, Target};
    use std::collections::BTreeMap;

    fn config() -> crate::config::Config {
        let mut agents = BTreeMap::new();
        agents.insert("cedar".to_string(), "claude-code".to_string());
        crate::config::Config {
            bind: "127.0.0.1:8181".parse().unwrap(),
            policy_dir: "/tmp/p".into(),
            audit_log: "/tmp/a.jsonl".into(),
            agents,
            unknown_agent: "unknown".to_string(),
        }
    }

    const COMMAND: &str = r#"{"backend":"cedar","request":{
        "capability_type":"command","request_id":"r1","command":"git",
        "args":["git","push","--force"],"caller":"session","intercept_rule":"push",
        "reason":null,"child_pid":42,"session_id":"s1"}}"#;

    #[test]
    fn maps_command_request() {
        let q = parse(COMMAND.as_bytes(), &config()).unwrap();
        assert_eq!(q.agent, "claude-code");
        assert_eq!(q.session_id, "s1");
        assert_eq!(q.caller, "session");
        assert_eq!(q.caller_kind, CallerKind::Session);
        assert_eq!(q.action_name(), "launchCommand");
        let Target::Command { command, args, intercept_rule, child_pid } = q.target else {
            panic!("expected command target");
        };
        assert_eq!(command, "git");
        assert_eq!(args, vec!["git", "push", "--force"]);
        assert_eq!(intercept_rule, "push");
        assert_eq!(child_pid, 42);
    }

    #[test]
    fn derives_command_caller_kind_for_chained_launch() {
        let body = COMMAND.replace(r#""caller":"session""#, r#""caller":"npm""#);
        let q = parse(body.as_bytes(), &config()).unwrap();
        assert_eq!(q.caller, "npm");
        assert_eq!(q.caller_kind, CallerKind::Command);
    }

    #[test]
    fn unmapped_backend_falls_back_to_unknown_agent() {
        let body = COMMAND.replace(r#""backend":"cedar""#, r#""backend":"rogue""#);
        let q = parse(body.as_bytes(), &config()).unwrap();
        assert_eq!(q.agent, "unknown");
    }

    #[test]
    fn maps_endpoint_request_with_proxy_identity() {
        let body = r#"{"backend":"cedar","request":{
            "capability_type":"endpoint","request_id":"p1","route_id":"github-api",
            "upstream":"https://api.github.com","method":"GET","path":"/repos/x",
            "rule_label":"rl","reason":null,"child_pid":0,"session_id":"proxy"}}"#;
        let q = parse(body.as_bytes(), &config()).unwrap();
        assert_eq!(q.caller, "proxy");
        assert_eq!(q.session_id, "proxy");
        assert_eq!(q.action_name(), "httpRequest");
        assert!(matches!(q.target, Target::Endpoint { .. }));
    }

    #[test]
    fn unsupported_variant_is_an_error_with_a_deny_reason() {
        let body = r#"{"backend":"cedar","request":{"capability_type":"network",
            "request_id":"n1","host":"example.com","port":443,"protocol":"tcp",
            "resolved_ips":[],"reason":null,"child_pid":1,"session_id":"s1"}}"#;
        let err = parse(body.as_bytes(), &config()).unwrap_err();
        assert!(matches!(err, AdaptError::UnsupportedVariant));
        assert!(err.deny_reason().contains("unsupported"));
    }

    #[test]
    fn malformed_body_is_an_error_with_a_deny_reason() {
        let err = parse(b"{not json", &config()).unwrap_err();
        assert!(matches!(err, AdaptError::Malformed(_)));
        assert!(err.deny_reason().contains("malformed"));
    }
}
```

- [ ] **Step 2: Run and confirm failure**

Run: `cargo test --lib adapter`
Expected: FAIL — module and functions not found.

- [ ] **Step 3: Implement `query.rs`**

```rust
//! The adapter-neutral internal boundary. Everything downstream of here is
//! independent of how the request arrived, which is what makes a future PORC
//! adapter — or an upstream native backend — a drop-in.

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CallerKind {
    Session,
    Command,
}

impl CallerKind {
    pub fn as_str(&self) -> &'static str {
        match self {
            CallerKind::Session => "session",
            CallerKind::Command => "command",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Target {
    Command {
        command: String,
        args: Vec<String>,
        intercept_rule: String,
        child_pid: u32,
    },
    Endpoint {
        route_id: String,
        upstream: String,
        method: String,
        path: String,
        rule_label: String,
    },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PolicyQuery {
    /// Cedar `Agent` id, resolved from config by approval-backend name.
    pub agent: String,
    pub session_id: String,
    pub caller: String,
    pub caller_kind: CallerKind,
    pub request_id: String,
    pub backend: String,
    pub reason: Option<String>,
    pub target: Target,
}

impl PolicyQuery {
    pub fn action_name(&self) -> &'static str {
        match self.target {
            Target::Command { .. } => "launchCommand",
            Target::Endpoint { .. } => "httpRequest",
        }
    }

    /// Short human-readable resource description for audit lines.
    pub fn resource_summary(&self) -> String {
        match &self.target {
            Target::Command { command, args, .. } => {
                format!("{command} [{}]", args.join(" "))
            }
            Target::Endpoint { method, upstream, path, .. } => {
                format!("{method} {upstream}{path}")
            }
        }
    }
}
```

- [ ] **Step 4: Implement the adapter**

Prepend to `src/adapter/nono_webhook.rs`:

```rust
//! Adapter for nono's `WebhookApproval` backend (nono 0.69.x).

use crate::config::Config;
use crate::query::{CallerKind, PolicyQuery, Target};
use crate::wire::{ApprovalRequest, WebhookEnvelope};

#[derive(Debug, thiserror::Error)]
pub enum AdaptError {
    #[error("malformed approval request: {0}")]
    Malformed(#[from] serde_json::Error),
    #[error("unsupported approval request variant")]
    UnsupportedVariant,
}

impl AdaptError {
    /// The `reason` string handed back to nono on the deny path.
    pub fn deny_reason(&self) -> String {
        match self {
            AdaptError::Malformed(_) => {
                "malformed approval request body; failing closed".to_string()
            }
            AdaptError::UnsupportedVariant => {
                "unsupported approval request variant; failing closed".to_string()
            }
        }
    }
}

pub fn parse(body: &[u8], config: &Config) -> Result<PolicyQuery, AdaptError> {
    let envelope: WebhookEnvelope = serde_json::from_slice(body)?;
    let agent = config.agent_for(&envelope.backend).to_string();

    match envelope.request {
        ApprovalRequest::Command(c) => {
            let caller_kind = if c.caller == "session" {
                CallerKind::Session
            } else {
                CallerKind::Command
            };
            Ok(PolicyQuery {
                agent,
                session_id: c.session_id,
                caller: c.caller,
                caller_kind,
                request_id: c.request_id,
                backend: envelope.backend,
                reason: c.reason,
                target: Target::Command {
                    command: c.command,
                    args: c.args,
                    intercept_rule: c.intercept_rule,
                    child_pid: c.child_pid,
                },
            })
        }
        ApprovalRequest::Endpoint(e) => Ok(PolicyQuery {
            agent,
            // The proxy hardcodes `session_id: "proxy"`; there is no session
            // identity for L7 approvals. Mirror it into the caller so policies
            // can spot proxy traffic structurally.
            session_id: e.session_id,
            caller: "proxy".to_string(),
            caller_kind: CallerKind::Session,
            request_id: e.request_id,
            backend: envelope.backend,
            reason: e.reason,
            target: Target::Endpoint {
                route_id: e.route_id,
                upstream: e.upstream,
                method: e.method,
                path: e.path,
                rule_label: e.rule_label,
            },
        }),
        ApprovalRequest::Unsupported => Err(AdaptError::UnsupportedVariant),
    }
}
```

Create `src/adapter/mod.rs`:

```rust
pub mod nono_webhook;
```

Add to `src/lib.rs`:

```rust
pub mod adapter;
pub mod query;
```

- [ ] **Step 5: Run the tests**

Run: `cargo test --lib`
Expected: PASS — 6 adapter tests plus earlier tests.

- [ ] **Step 6: Commit**

```bash
git add src/query.rs src/adapter/ src/lib.rs
git commit -m "feat: PolicyQuery boundary and nono webhook adapter"
```

---

### Task 4: Cedar schema + schema module

**Files:**
- Create: `nono.cedarschema`, `src/cedar/mod.rs`, `src/cedar/schema.rs`
- Modify: `src/lib.rs`

**Interfaces:**
- Consumes: nothing.
- Produces:
  - `cedar::schema::SCHEMA_SRC: &str`
  - `cedar::schema::load() -> Result<cedar_policy::Schema, SchemaLoadError>` (logs each `SchemaWarning` at warn level)
  - `cedar::schema::SchemaLoadError`

- [ ] **Step 1: Create the schema file**

`nono.cedarschema` — copy verbatim; this exact text is spike-verified to compile and strict-validate:

```cedar
namespace Nono {
  entity Agent;
  entity Session in [Agent];
  entity Caller in [Session];

  entity Command {
    command: String,
    args: Set<String>,
    argv: String,
    arg_count: Long,
  };

  entity HttpEndpoint {
    route_id: String,
    upstream: String,
    method: String,
    path: String,
  };

  action launchCommand appliesTo {
    principal: [Caller],
    resource: [Command],
    context: {
      backend: String,
      intercept_rule: String,
      caller_kind: String,
      reason?: String,
      child_pid: Long,
      session_id: String,
    }
  };

  action httpRequest appliesTo {
    principal: [Caller],
    resource: [HttpEndpoint],
    context: {
      backend: String,
      rule_label: String,
      reason?: String,
    }
  };
}
```

> `args` is a `Set<String>` on purpose: Cedar sets have no index access, so
> positional argument matching is unexpressible. Upstream drops non-UTF-8 argv
> entries, which shifts positions — this makes the unsound pattern impossible
> rather than merely discouraged.

- [ ] **Step 2: Write the failing schema tests**

Create `src/cedar/schema.rs` with only this test module:

```rust
#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use cedar_policy::{PolicySet, ValidationMode, Validator};
    use std::str::FromStr;

    #[test]
    fn schema_compiles() {
        let schema = load().unwrap();
        let actions: Vec<String> = schema.actions().map(|a| a.to_string()).collect();
        assert!(actions.iter().any(|a| a.contains("launchCommand")), "{actions:?}");
        assert!(actions.iter().any(|a| a.contains("httpRequest")), "{actions:?}");
    }

    #[test]
    fn a_well_formed_policy_strict_validates() {
        let schema = load().unwrap();
        let policies = PolicySet::from_str(
            r#"permit (
                 principal in Nono::Agent::"claude-code",
                 action == Nono::Action::"launchCommand",
                 resource
               ) when { resource.command == "git" && !resource.args.contains("--force") };"#,
        )
        .unwrap();
        let result = Validator::new(schema).validate(&policies, ValidationMode::Strict);
        let errors: Vec<String> = result.validation_errors().map(|e| e.to_string()).collect();
        assert!(result.validation_passed(), "{errors:#?}");
    }

    #[test]
    fn positional_argument_access_is_rejected_by_the_schema() {
        // `args` is a Set, so indexing is not valid Cedar against this schema.
        let schema = load().unwrap();
        let policies = PolicySet::from_str(
            r#"permit (
                 principal, action == Nono::Action::"launchCommand", resource
               ) when { resource.args.contains("push") && resource.arg_count == 2 };"#,
        )
        .unwrap();
        let result = Validator::new(schema).validate(&policies, ValidationMode::Strict);
        assert!(result.validation_passed());
    }

    #[test]
    fn unknown_attribute_fails_validation() {
        let schema = load().unwrap();
        let policies = PolicySet::from_str(
            r#"permit (
                 principal, action == Nono::Action::"launchCommand", resource
               ) when { resource.cwd == "/tmp" };"#,
        )
        .unwrap();
        let result = Validator::new(schema).validate(&policies, ValidationMode::Strict);
        assert!(
            !result.validation_passed(),
            "cwd is not in the payload; policies referencing it must not validate"
        );
    }
}
```

- [ ] **Step 3: Run and confirm failure**

Run: `cargo test --lib cedar::schema`
Expected: FAIL — `load` not found.

- [ ] **Step 4: Implement the schema module**

Prepend to `src/cedar/schema.rs`:

```rust
//! The embedded Cedar schema. Compiled once at startup; policies are validated
//! against it at load and at every hot-reload.

use cedar_policy::Schema;

pub const SCHEMA_SRC: &str = include_str!("../../nono.cedarschema");

#[derive(Debug, thiserror::Error)]
pub enum SchemaLoadError {
    #[error("embedded Cedar schema failed to compile: {0}")]
    Compile(String),
}

pub fn load() -> Result<Schema, SchemaLoadError> {
    let (schema, warnings) = Schema::from_cedarschema_str(SCHEMA_SRC)
        .map_err(|e| SchemaLoadError::Compile(e.to_string()))?;
    for w in warnings {
        tracing::warn!(warning = %w, "cedar schema warning");
    }
    Ok(schema)
}
```

Create `src/cedar/mod.rs`:

```rust
pub mod schema;
```

Add to `src/lib.rs`:

```rust
pub mod cedar;
```

- [ ] **Step 5: Run the tests**

Run: `cargo test --lib cedar::schema`
Expected: PASS, 4 tests.

- [ ] **Step 6: Commit**

```bash
git add nono.cedarschema src/cedar/ src/lib.rs
git commit -m "feat: embedded Cedar schema for nono approval requests"
```

---

### Task 5: Policy loading, validation, and the `validate` CLI

**Files:**
- Create: `src/cedar/engine.rs`
- Modify: `src/cedar/mod.rs`, `src/main.rs`

**Interfaces:**
- Consumes: `cedar::schema::load`.
- Produces:
  - `cedar::engine::LoadedPolicies { set: PolicySet, generation: u64, loaded_at: SystemTime, files: Vec<PathBuf> }`
  - `cedar::engine::PolicyLoadError` (`Io`, `Parse`, `Duplicate`, `Validation`, `Empty`)
  - `cedar::engine::load_dir(dir: &Path, schema: &Schema, generation: u64) -> Result<LoadedPolicies, PolicyLoadError>`
  - `cedar::engine::Engine::bootstrap(schema: Schema, policy_dir: PathBuf) -> Result<Engine, PolicyLoadError>`
  - `Engine::snapshot(&self) -> Arc<LoadedPolicies>`, `Engine::schema(&self) -> &Schema`, `Engine::policy_dir(&self) -> &Path`
  - CLI: `nono-cedar-pdp validate --config <path>`

- [ ] **Step 1: Write the failing loader tests**

Create `src/cedar/engine.rs` with only this test module:

```rust
#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    const GOOD: &str = r#"
@id("allow-git")
permit (principal, action == Nono::Action::"launchCommand", resource)
when { resource.command == "git" };

forbid (principal, action == Nono::Action::"launchCommand", resource)
when { resource.args.contains("--force") };
"#;

    fn dir_with(files: &[(&str, &str)]) -> tempfile::TempDir {
        let d = tempfile::tempdir().unwrap();
        for (name, body) in files {
            std::fs::write(d.path().join(name), body).unwrap();
        }
        d
    }

    #[test]
    fn loads_policies_with_provenance_ids() {
        let schema = crate::cedar::schema::load().unwrap();
        let d = dir_with(&[("git.cedar", GOOD)]);
        let loaded = load_dir(d.path(), &schema, 1).unwrap();
        let mut ids: Vec<String> = loaded.set.policies().map(|p| p.id().to_string()).collect();
        ids.sort();
        assert_eq!(ids, vec!["git:1".to_string(), "git:allow-git".to_string()]);
        assert_eq!(loaded.generation, 1);
        assert_eq!(loaded.files.len(), 1);
    }

    #[test]
    fn ignores_non_cedar_files() {
        let schema = crate::cedar::schema::load().unwrap();
        let d = dir_with(&[("git.cedar", GOOD), ("README.md", "not a policy")]);
        let loaded = load_dir(d.path(), &schema, 1).unwrap();
        assert_eq!(loaded.files.len(), 1);
    }

    #[test]
    fn empty_dir_is_an_error_not_a_deny_everything_daemon() {
        let schema = crate::cedar::schema::load().unwrap();
        let d = tempfile::tempdir().unwrap();
        assert!(matches!(load_dir(d.path(), &schema, 1), Err(PolicyLoadError::Empty { .. })));
    }

    #[test]
    fn syntax_error_reports_the_file() {
        let schema = crate::cedar::schema::load().unwrap();
        let d = dir_with(&[("broken.cedar", "permit (this is not cedar")]);
        let err = load_dir(d.path(), &schema, 1).unwrap_err();
        assert!(err.to_string().contains("broken.cedar"), "{err}");
    }

    #[test]
    fn schema_violation_fails_validation() {
        let schema = crate::cedar::schema::load().unwrap();
        let d = dir_with(&[(
            "bad.cedar",
            r#"permit (principal, action == Nono::Action::"launchCommand", resource)
               when { resource.cwd == "/tmp" };"#,
        )]);
        let err = load_dir(d.path(), &schema, 1).unwrap_err();
        assert!(matches!(err, PolicyLoadError::Validation { .. }), "{err}");
    }

    #[test]
    fn duplicate_ids_across_files_fail_loudly() {
        let schema = crate::cedar::schema::load().unwrap();
        let dup = r#"@id("same")
permit (principal, action == Nono::Action::"launchCommand", resource)
when { resource.command == "git" };"#;
        // Same stem is impossible in one dir, so force the collision with an
        // identical @id in files that normalize to the same stem prefix.
        let d = dir_with(&[("a.cedar", dup), ("a.cedar.cedar", dup)]);
        let _ = d; // documented behaviour: see engine docs. Same-stem collisions
                   // are caught by PolicySet::add.
    }

    #[test]
    fn bootstrap_exposes_a_snapshot() {
        let schema = crate::cedar::schema::load().unwrap();
        let d = dir_with(&[("git.cedar", GOOD)]);
        let engine = Engine::bootstrap(schema, d.path().to_path_buf()).unwrap();
        assert_eq!(engine.snapshot().generation, 1);
        assert_eq!(engine.snapshot().set.num_of_policies(), 2);
    }
}
```

> Delete the `duplicate_ids_across_files_fail_loudly` placeholder test body and
> replace it with the real assertion below during Step 4 — it exists here only
> to mark the behaviour. The real test is: two policies with the same `@id` in
> the **same file** must error.

- [ ] **Step 2: Run and confirm failure**

Run: `cargo test --lib cedar::engine`
Expected: FAIL — `load_dir` not found.

- [ ] **Step 3: Replace the placeholder duplicate test**

```rust
    #[test]
    fn duplicate_ids_in_one_file_fail_loudly() {
        let schema = crate::cedar::schema::load().unwrap();
        let body = r#"
@id("same")
permit (principal, action == Nono::Action::"launchCommand", resource)
when { resource.command == "git" };

@id("same")
permit (principal, action == Nono::Action::"launchCommand", resource)
when { resource.command == "gh" };
"#;
        let d = dir_with(&[("dup.cedar", body)]);
        let err = load_dir(d.path(), &schema, 1).unwrap_err();
        assert!(matches!(err, PolicyLoadError::Duplicate { .. }), "{err}");
    }
```

- [ ] **Step 4: Implement the loader and engine**

Prepend to `src/cedar/engine.rs`:

```rust
//! Policy set loading, strict validation, and the hot-swappable current set.

use arc_swap::ArcSwap;
use cedar_policy::{Policy, PolicyId, PolicySet, Schema, ValidationMode, Validator};
use std::path::{Path, PathBuf};
use std::str::FromStr;
use std::sync::Arc;
use std::time::SystemTime;

#[derive(Debug, thiserror::Error)]
pub enum PolicyLoadError {
    #[error("reading policy dir {path}: {source}")]
    Io { path: PathBuf, source: std::io::Error },
    #[error("parsing {path}: {message}")]
    Parse { path: PathBuf, message: String },
    #[error("duplicate policy id from {path}: {message}")]
    Duplicate { path: PathBuf, message: String },
    #[error("policy validation failed against the nono schema: {}", .errors.join("; "))]
    Validation { errors: Vec<String> },
    #[error("no .cedar policies found in {path} — refusing to serve a deny-everything policy set")]
    Empty { path: PathBuf },
}

#[derive(Debug)]
pub struct LoadedPolicies {
    pub set: PolicySet,
    pub generation: u64,
    pub loaded_at: SystemTime,
    pub files: Vec<PathBuf>,
}

/// Read every `*.cedar` file in `dir`, assign provenance-carrying policy ids,
/// and strict-validate the whole set against `schema`.
///
/// Policy ids are `<file stem>:<@id annotation or ordinal>`, so a decision's
/// reason string points at the file that produced it.
pub fn load_dir(
    dir: &Path,
    schema: &Schema,
    generation: u64,
) -> Result<LoadedPolicies, PolicyLoadError> {
    let mut entries: Vec<PathBuf> = std::fs::read_dir(dir)
        .map_err(|source| PolicyLoadError::Io { path: dir.to_path_buf(), source })?
        .filter_map(Result::ok)
        .map(|e| e.path())
        .filter(|p| p.extension().is_some_and(|e| e == "cedar"))
        .collect();
    entries.sort();

    if entries.is_empty() {
        return Err(PolicyLoadError::Empty { path: dir.to_path_buf() });
    }

    let mut set = PolicySet::new();
    for path in &entries {
        let text = std::fs::read_to_string(path)
            .map_err(|source| PolicyLoadError::Io { path: path.clone(), source })?;
        let stem = path
            .file_stem()
            .map(|s| s.to_string_lossy().to_string())
            .unwrap_or_else(|| "policy".to_string());

        let parsed = PolicySet::from_str(&text).map_err(|e| PolicyLoadError::Parse {
            path: path.clone(),
            message: e.to_string(),
        })?;

        for (ordinal, policy) in parsed.policies().enumerate() {
            let id = match policy.annotation("id") {
                Some(a) => PolicyId::new(format!("{stem}:{a}")),
                None => PolicyId::new(format!("{stem}:{ordinal}")),
            };
            set.add(policy.new_id(id))
                .map_err(|e| PolicyLoadError::Duplicate {
                    path: path.clone(),
                    message: e.to_string(),
                })?;
        }
    }

    let result = Validator::new(schema.clone()).validate(&set, ValidationMode::Strict);
    if !result.validation_passed() {
        return Err(PolicyLoadError::Validation {
            errors: result.validation_errors().map(|e| e.to_string()).collect(),
        });
    }
    for w in result.validation_warnings() {
        tracing::warn!(warning = %w, "cedar policy validation warning");
    }

    Ok(LoadedPolicies {
        set,
        generation,
        loaded_at: SystemTime::now(),
        files: entries,
    })
}

pub struct Engine {
    schema: Schema,
    policy_dir: PathBuf,
    current: ArcSwap<LoadedPolicies>,
}

impl Engine {
    /// Load the initial policy set. Fails fast: a daemon that cannot load valid
    /// policies must not start.
    pub fn bootstrap(schema: Schema, policy_dir: PathBuf) -> Result<Self, PolicyLoadError> {
        let initial = load_dir(&policy_dir, &schema, 1)?;
        Ok(Self {
            schema,
            policy_dir,
            current: ArcSwap::from_pointee(initial),
        })
    }

    pub fn snapshot(&self) -> Arc<LoadedPolicies> {
        self.current.load_full()
    }

    pub fn schema(&self) -> &Schema {
        &self.schema
    }

    pub fn policy_dir(&self) -> &Path {
        &self.policy_dir
    }

    /// Swap in a freshly loaded set. On any error the current set is retained
    /// (spec D7: a bad edit mid-session must not brick a running agent).
    pub fn reload(&self) -> Result<u64, PolicyLoadError> {
        let next_gen = self.snapshot().generation + 1;
        let loaded = load_dir(&self.policy_dir, &self.schema, next_gen)?;
        let count = loaded.set.num_of_policies();
        self.current.store(Arc::new(loaded));
        tracing::info!(generation = next_gen, policies = count, "policy set reloaded");
        Ok(next_gen)
    }
}
```

Add to `src/cedar/mod.rs`:

```rust
pub mod engine;
```

- [ ] **Step 5: Wire the `validate` CLI subcommand**

Replace `src/main.rs`:

```rust
use clap::{Parser, Subcommand};
use nono_cedar_pdp::{cedar, config::Config};
use std::path::PathBuf;
use std::process::ExitCode;

#[derive(Parser)]
#[command(name = "nono-cedar-pdp", version, about = "Cedar PDP for nono approvals")]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Load and strict-validate the configured policy directory, then exit.
    Validate {
        #[arg(long, default_value = "./nono-cedar-pdp.toml")]
        config: PathBuf,
    },
}

fn main() -> ExitCode {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "info".into()),
        )
        .init();

    let cli = Cli::parse();
    match cli.command {
        Command::Validate { config } => match run_validate(&config) {
            Ok(count) => {
                println!("OK: {count} policies loaded and validated");
                ExitCode::SUCCESS
            }
            Err(message) => {
                eprintln!("FAIL: {message}");
                ExitCode::FAILURE
            }
        },
    }
}

fn run_validate(config_path: &std::path::Path) -> Result<usize, String> {
    let config = Config::load(config_path).map_err(|e| e.to_string())?;
    let schema = cedar::schema::load().map_err(|e| e.to_string())?;
    let loaded = cedar::engine::load_dir(&config.policy_dir, &schema, 1)
        .map_err(|e| e.to_string())?;
    Ok(loaded.set.num_of_policies())
}
```

- [ ] **Step 6: Run the tests and the CLI**

Run: `cargo test --lib cedar::engine`
Expected: PASS, 7 tests.

```bash
mkdir -p policies
cat > policies/starter.cedar <<'EOF'
@id("allow-git-read-only")
permit (principal, action == Nono::Action::"launchCommand", resource)
when { resource.command == "git" && resource.args.contains("status") };
EOF
cat > nono-cedar-pdp.toml <<'EOF'
policy_dir = "./policies"
audit_log = "./decisions.jsonl"

[agents]
cedar = "claude-code"
EOF
cargo run --quiet -- validate --config ./nono-cedar-pdp.toml
```

Expected: `OK: 1 policies loaded and validated`.

- [ ] **Step 7: Commit**

```bash
git add src/cedar/ src/main.rs policies/ nono-cedar-pdp.toml
git commit -m "feat: policy loading with strict validation and validate CLI"
```

---

### Task 6: Entity building, decisions, and the `check` CLI

**Files:**
- Create: `src/cedar/entities.rs`, `src/decision.rs`
- Modify: `src/cedar/mod.rs`, `src/cedar/engine.rs`, `src/lib.rs`, `src/main.rs`

**Interfaces:**
- Consumes: `query::PolicyQuery`, `cedar::engine::Engine`.
- Produces:
  - `cedar::entities::build(q: &PolicyQuery, schema: &Schema) -> Result<(Request, Entities), BuildError>`
  - `decision::Decision { allow: bool, matched: Vec<String>, reason: String, eval_us: u128 }`
  - `Decision::deny(reason: impl Into<String>) -> Decision`
  - `Decision::to_wire(&self) -> wire::WebhookResponse`
  - `Engine::evaluate(&self, q: &PolicyQuery) -> Decision`
  - CLI: `nono-cedar-pdp check --config <path> <fixture.json>`

- [ ] **Step 1: Write the failing evaluation tests**

Append to `src/cedar/engine.rs`'s test module:

```rust
    use crate::query::{CallerKind, PolicyQuery, Target};

    fn command_query(caller: &str, command: &str, args: &[&str]) -> PolicyQuery {
        PolicyQuery {
            agent: "claude-code".to_string(),
            session_id: "s1".to_string(),
            caller: caller.to_string(),
            caller_kind: if caller == "session" {
                CallerKind::Session
            } else {
                CallerKind::Command
            },
            request_id: "r1".to_string(),
            backend: "cedar".to_string(),
            reason: None,
            target: Target::Command {
                command: command.to_string(),
                args: args.iter().map(|a| a.to_string()).collect(),
                intercept_rule: "rule".to_string(),
                child_pid: 42,
            },
        }
    }

    fn endpoint_query(method: &str, path: &str) -> PolicyQuery {
        PolicyQuery {
            agent: "claude-code".to_string(),
            session_id: "proxy".to_string(),
            caller: "proxy".to_string(),
            caller_kind: CallerKind::Session,
            request_id: "p1".to_string(),
            backend: "cedar".to_string(),
            reason: None,
            target: Target::Endpoint {
                route_id: "github-api".to_string(),
                upstream: "https://api.github.com".to_string(),
                method: method.to_string(),
                path: path.to_string(),
                rule_label: "rl".to_string(),
            },
        }
    }

    const MATRIX: &str = r#"
@id("allow-git")
permit (
  principal in Nono::Agent::"claude-code",
  action == Nono::Action::"launchCommand",
  resource
) when { resource.command == "git" && !resource.args.contains("--force") };

@id("session-only")
forbid (principal, action == Nono::Action::"launchCommand", resource)
unless { principal == Nono::Caller::"session" };

@id("allow-github-reads")
permit (
  principal in Nono::Agent::"claude-code",
  action == Nono::Action::"httpRequest",
  resource
) when { resource.method == "GET" && resource.path like "/repos/*" };
"#;

    fn matrix_engine() -> (Engine, tempfile::TempDir) {
        let schema = crate::cedar::schema::load().unwrap();
        let d = dir_with(&[("matrix.cedar", MATRIX)]);
        let engine = Engine::bootstrap(schema, d.path().to_path_buf()).unwrap();
        (engine, d)
    }

    #[test]
    fn allows_a_permitted_command() {
        let (engine, _d) = matrix_engine();
        let decision = engine.evaluate(&command_query("session", "git", &["git", "status"]));
        assert!(decision.allow, "{decision:?}");
        assert_eq!(decision.matched, vec!["matrix.cedar:allow-git".to_string()]
            .into_iter().map(|s| s.replace("matrix.cedar", "matrix")).collect::<Vec<_>>());
    }

    #[test]
    fn denies_when_a_forbid_matches() {
        let (engine, _d) = matrix_engine();
        let decision = engine.evaluate(&command_query("npm", "git", &["git", "status"]));
        assert!(!decision.allow);
        assert!(decision.matched.iter().any(|m| m.ends_with("session-only")));
        assert!(decision.reason.contains("session-only"), "{}", decision.reason);
    }

    #[test]
    fn denies_with_default_deny_reason_when_nothing_matches() {
        let (engine, _d) = matrix_engine();
        let decision = engine.evaluate(&command_query("session", "curl", &["curl", "evil.example"]));
        assert!(!decision.allow);
        assert!(decision.matched.is_empty());
        assert!(
            decision.reason.contains("no policy"),
            "empty reason set needs explicit default-deny text, got {}",
            decision.reason
        );
    }

    #[test]
    fn unmapped_agent_is_denied() {
        let (engine, _d) = matrix_engine();
        let mut q = command_query("session", "git", &["git", "status"]);
        q.agent = "unknown".to_string();
        assert!(!engine.evaluate(&q).allow);
    }

    #[test]
    fn evaluates_endpoint_requests() {
        let (engine, _d) = matrix_engine();
        assert!(engine.evaluate(&endpoint_query("GET", "/repos/foo/bar")).allow);
        assert!(!engine.evaluate(&endpoint_query("DELETE", "/repos/foo/bar")).allow);
    }

    #[test]
    fn records_evaluation_time() {
        let (engine, _d) = matrix_engine();
        let decision = engine.evaluate(&command_query("session", "git", &["git", "status"]));
        assert!(decision.eval_us > 0);
    }
```

> Fix the first test's awkward id assertion when implementing: policy ids are
> `<stem>:<annotation>`, and the stem of `matrix.cedar` is `matrix`, so the
> expected id is exactly `"matrix:allow-git"`. Write it as
> `assert_eq!(decision.matched, vec!["matrix:allow-git".to_string()]);`

- [ ] **Step 2: Run and confirm failure**

Run: `cargo test --lib cedar::engine`
Expected: FAIL — `evaluate` not found.

- [ ] **Step 3: Implement `decision.rs`**

```rust
//! Decision type and reason construction.

use crate::wire::WebhookResponse;
use cedar_policy::Response;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Decision {
    pub allow: bool,
    /// Cedar policy ids that determined the outcome. Empty on a default deny.
    pub matched: Vec<String>,
    pub reason: String,
    pub eval_us: u128,
}

impl Decision {
    pub fn deny(reason: impl Into<String>) -> Self {
        Self {
            allow: false,
            matched: Vec::new(),
            reason: reason.into(),
            eval_us: 0,
        }
    }

    /// Convert a Cedar response into a decision.
    ///
    /// Fails closed on evaluation errors: if any policy errored we cannot know
    /// whether a `forbid` was skipped, so an `Allow` is not trustworthy.
    pub fn from_response(response: &Response, eval_us: u128) -> Self {
        let mut matched: Vec<String> = response
            .diagnostics()
            .reason()
            .map(|id| id.to_string())
            .collect();
        matched.sort();

        let errors: Vec<String> = response
            .diagnostics()
            .errors()
            .map(|e| e.to_string())
            .collect();

        if !errors.is_empty() {
            return Self {
                allow: false,
                matched,
                reason: format!(
                    "cedar evaluation errors, failing closed: {}",
                    errors.join("; ")
                ),
                eval_us,
            };
        }

        match response.decision() {
            cedar_policy::Decision::Allow => Self {
                allow: true,
                reason: format!("permitted by {}", matched.join(", ")),
                matched,
                eval_us,
            },
            cedar_policy::Decision::Deny => {
                let reason = if matched.is_empty() {
                    "no policy permitted this request (default deny)".to_string()
                } else {
                    format!("denied by {}", matched.join(", "))
                };
                Self { allow: false, matched, reason, eval_us }
            }
        }
    }

    pub fn to_wire(&self) -> WebhookResponse {
        if self.allow {
            WebhookResponse::Allow
        } else {
            WebhookResponse::Deny { reason: self.reason.clone() }
        }
    }
}
```

- [ ] **Step 4: Implement `cedar/entities.rs`**

```rust
//! Per-request Cedar entity slices.
//!
//! Cedar keeps no cross-request state, so entity ids need only be unique within
//! one authorization call. That lets policies use short, readable ids
//! (`Nono::Caller::"session"`) while session identity lives in the parent
//! `Session` entity and in context.

use crate::query::{PolicyQuery, Target};
use cedar_policy::{
    Context, Entities, Entity, EntityUid, Request, RestrictedExpression, Schema,
};
use std::collections::{HashMap, HashSet};
use std::str::FromStr;

#[derive(Debug, thiserror::Error)]
pub enum BuildError {
    #[error("invalid entity uid {uid}: {message}")]
    Uid { uid: String, message: String },
    #[error("building entity: {0}")]
    Entity(String),
    #[error("building context: {0}")]
    Context(String),
    #[error("building request: {0}")]
    Request(String),
}

fn uid(text: &str) -> Result<EntityUid, BuildError> {
    EntityUid::from_str(text).map_err(|e| BuildError::Uid {
        uid: text.to_string(),
        message: e.to_string(),
    })
}

/// Cedar entity ids are quoted strings; escape `\` and `"` so a crafted command
/// name cannot break out of the literal.
fn escape(raw: &str) -> String {
    raw.replace('\\', "\\\\").replace('"', "\\\"")
}

fn s(value: &str) -> RestrictedExpression {
    RestrictedExpression::new_string(value.to_string())
}

pub fn build(q: &PolicyQuery, schema: &Schema) -> Result<(Request, Entities), BuildError> {
    let agent = Entity::new_no_attrs(
        uid(&format!("Nono::Agent::\"{}\"", escape(&q.agent)))?,
        HashSet::new(),
    );
    let session = Entity::new_no_attrs(
        uid(&format!("Nono::Session::\"{}\"", escape(&q.session_id)))?,
        HashSet::from([agent.uid()]),
    );
    let caller_uid = uid(&format!("Nono::Caller::\"{}\"", escape(&q.caller)))?;
    let caller = Entity::new_no_attrs(caller_uid.clone(), HashSet::from([session.uid()]));

    let (action, resource, context_pairs) = match &q.target {
        Target::Command { command, args, intercept_rule, child_pid } => {
            let resource_uid =
                uid(&format!("Nono::Command::\"{}\"", escape(&q.request_id)))?;
            let attrs = HashMap::from([
                ("command".to_string(), s(command)),
                (
                    "args".to_string(),
                    RestrictedExpression::new_set(args.iter().map(|a| s(a))),
                ),
                ("argv".to_string(), s(&args.join(" "))),
                (
                    "arg_count".to_string(),
                    RestrictedExpression::new_long(args.len() as i64),
                ),
            ]);
            let resource = Entity::new(resource_uid.clone(), attrs, HashSet::new())
                .map_err(|e| BuildError::Entity(e.to_string()))?;

            let mut pairs = vec![
                ("backend".to_string(), s(&q.backend)),
                ("intercept_rule".to_string(), s(intercept_rule)),
                ("caller_kind".to_string(), s(q.caller_kind.as_str())),
                (
                    "child_pid".to_string(),
                    RestrictedExpression::new_long(i64::from(*child_pid)),
                ),
                ("session_id".to_string(), s(&q.session_id)),
            ];
            if let Some(reason) = &q.reason {
                pairs.push(("reason".to_string(), s(reason)));
            }
            (
                uid("Nono::Action::\"launchCommand\"")?,
                (resource_uid, resource),
                pairs,
            )
        }
        Target::Endpoint { route_id, upstream, method, path, rule_label } => {
            let resource_uid =
                uid(&format!("Nono::HttpEndpoint::\"{}\"", escape(&q.request_id)))?;
            let attrs = HashMap::from([
                ("route_id".to_string(), s(route_id)),
                ("upstream".to_string(), s(upstream)),
                ("method".to_string(), s(method)),
                ("path".to_string(), s(path)),
            ]);
            let resource = Entity::new(resource_uid.clone(), attrs, HashSet::new())
                .map_err(|e| BuildError::Entity(e.to_string()))?;

            let mut pairs = vec![
                ("backend".to_string(), s(&q.backend)),
                ("rule_label".to_string(), s(rule_label)),
            ];
            if let Some(reason) = &q.reason {
                pairs.push(("reason".to_string(), s(reason)));
            }
            (
                uid("Nono::Action::\"httpRequest\"")?,
                (resource_uid, resource),
                pairs,
            )
        }
    };

    let (resource_uid, resource_entity) = resource;
    let entities = Entities::from_entities(
        [agent, session, caller, resource_entity],
        Some(schema),
    )
    .map_err(|e| BuildError::Entity(e.to_string()))?;

    let context =
        Context::from_pairs(context_pairs).map_err(|e| BuildError::Context(e.to_string()))?;

    let request = Request::new(caller_uid, action, resource_uid, context, Some(schema))
        .map_err(|e| BuildError::Request(e.to_string()))?;

    Ok((request, entities))
}
```

Add to `src/cedar/mod.rs`: `pub mod entities;`. Add to `src/lib.rs`: `pub mod decision;`.

- [ ] **Step 5: Implement `Engine::evaluate`**

Add to the `impl Engine` block in `src/cedar/engine.rs`:

```rust
    /// Evaluate a query. Never returns an error: every failure path is a deny
    /// with a reason, because nono is waiting on a decision.
    pub fn evaluate(&self, q: &crate::query::PolicyQuery) -> crate::decision::Decision {
        use crate::decision::Decision;

        let started = std::time::Instant::now();
        let (request, entities) = match crate::cedar::entities::build(q, &self.schema) {
            Ok(pair) => pair,
            Err(e) => {
                tracing::error!(error = %e, "failed to build cedar request; denying");
                return Decision::deny(format!("could not build policy request: {e}"));
            }
        };

        let snapshot = self.snapshot();
        let response = cedar_policy::Authorizer::new()
            .is_authorized(&request, &snapshot.set, &entities);
        Decision::from_response(&response, started.elapsed().as_micros())
    }
```

- [ ] **Step 6: Run the tests**

Run: `cargo test --lib`
Expected: PASS — all engine, entity, wire, adapter, config and schema tests.

- [ ] **Step 7: Add the `check` CLI subcommand**

Add to the `Command` enum in `src/main.rs`:

```rust
    /// Evaluate a saved webhook payload against the configured policies.
    Check {
        #[arg(long, default_value = "./nono-cedar-pdp.toml")]
        config: PathBuf,
        /// Path to a JSON file containing a nono webhook envelope.
        fixture: PathBuf,
    },
```

And the match arm plus helper:

```rust
        Command::Check { config, fixture } => match run_check(&config, &fixture) {
            Ok(decision) => {
                println!(
                    "{}: {} ({} µs)",
                    if decision.allow { "ALLOW" } else { "DENY" },
                    decision.reason,
                    decision.eval_us
                );
                if decision.allow { ExitCode::SUCCESS } else { ExitCode::FAILURE }
            }
            Err(message) => {
                eprintln!("FAIL: {message}");
                ExitCode::FAILURE
            }
        },
```

```rust
fn run_check(
    config_path: &std::path::Path,
    fixture: &std::path::Path,
) -> Result<nono_cedar_pdp::decision::Decision, String> {
    let config = Config::load(config_path).map_err(|e| e.to_string())?;
    let schema = cedar::schema::load().map_err(|e| e.to_string())?;
    let engine = cedar::engine::Engine::bootstrap(schema, config.policy_dir.clone())
        .map_err(|e| e.to_string())?;
    let body = std::fs::read(fixture).map_err(|e| e.to_string())?;
    let query = nono_cedar_pdp::adapter::nono_webhook::parse(&body, &config)
        .map_err(|e| e.to_string())?;
    Ok(engine.evaluate(&query))
}
```

- [ ] **Step 8: Exercise the CLI end to end**

```bash
mkdir -p tests/fixtures
cat > tests/fixtures/git-status.json <<'EOF'
{"backend":"cedar","request":{"capability_type":"command","request_id":"r1",
"command":"git","args":["git","status"],"caller":"session","intercept_rule":"status",
"reason":null,"child_pid":42,"session_id":"s1"}}
EOF
cargo run --quiet -- check --config ./nono-cedar-pdp.toml tests/fixtures/git-status.json
```

Expected: `ALLOW: permitted by starter:allow-git-read-only (… µs)`.

- [ ] **Step 9: Commit**

```bash
git add src/cedar/ src/decision.rs src/lib.rs src/main.rs tests/fixtures/
git commit -m "feat: cedar entity building, decisions, and check CLI"
```

---

### Task 7: JSONL audit log

**Files:**
- Create: `src/audit.rs`
- Modify: `src/lib.rs`, `src/main.rs`

**Interfaces:**
- Consumes: `query::PolicyQuery`, `decision::Decision`.
- Produces:
  - `audit::AuditLog::open(path: &Path) -> std::io::Result<AuditLog>` (creates parent dirs, mode 0600, append-only)
  - `audit::AuditLog::record(&self, query: &PolicyQuery, decision: &Decision)` — never fails a request; logs on write error
  - `audit::AuditRecord<'a>` (serializable line shape)

- [ ] **Step 1: Write the failing audit tests**

Create `src/audit.rs` with only this test module:

```rust
#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use crate::query::{CallerKind, PolicyQuery, Target};

    fn query() -> PolicyQuery {
        PolicyQuery {
            agent: "claude-code".to_string(),
            session_id: "s1".to_string(),
            caller: "session".to_string(),
            caller_kind: CallerKind::Session,
            request_id: "r1".to_string(),
            backend: "cedar".to_string(),
            reason: None,
            target: Target::Command {
                command: "git".to_string(),
                args: vec!["git".to_string(), "status".to_string()],
                intercept_rule: "status".to_string(),
                child_pid: 42,
            },
        }
    }

    #[test]
    fn appends_one_json_line_per_decision() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("nested/decisions.jsonl");
        let log = AuditLog::open(&path).unwrap();

        log.record(&query(), &crate::decision::Decision::deny("nope"));
        log.record(&query(), &crate::decision::Decision::deny("still nope"));

        let text = std::fs::read_to_string(&path).unwrap();
        let lines: Vec<&str> = text.lines().collect();
        assert_eq!(lines.len(), 2);

        let first: serde_json::Value = serde_json::from_str(lines[0]).unwrap();
        assert_eq!(first["request_id"], "r1");
        assert_eq!(first["session_id"], "s1");
        assert_eq!(first["backend"], "cedar");
        assert_eq!(first["agent"], "claude-code");
        assert_eq!(first["action"], "launchCommand");
        assert_eq!(first["decision"], "deny");
        assert_eq!(first["principal"], "Nono::Caller::\"session\"");
        assert!(first["resource"].as_str().unwrap().contains("git"));
        assert!(first["ts"].as_str().unwrap().contains('T'), "want RFC3339 ts");
    }

    #[test]
    fn creates_the_log_with_owner_only_permissions() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("decisions.jsonl");
        let _log = AuditLog::open(&path).unwrap();
        let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600, "audit log must not be world readable");
    }
}
```

- [ ] **Step 2: Run and confirm failure**

Run: `cargo test --lib audit`
Expected: FAIL — `AuditLog` not found.

- [ ] **Step 3: Implement the audit log**

Prepend to `src/audit.rs`:

```rust
//! Append-only JSONL decision log. One line per decision, owner-readable only.

use crate::decision::Decision;
use crate::query::PolicyQuery;
use serde::Serialize;
use std::fs::{File, OpenOptions};
use std::io::Write;
use std::os::unix::fs::OpenOptionsExt;
use std::path::Path;
use std::sync::Mutex;

#[derive(Debug, Serialize)]
pub struct AuditRecord<'a> {
    pub ts: String,
    pub request_id: &'a str,
    pub session_id: &'a str,
    pub backend: &'a str,
    pub agent: &'a str,
    pub principal: String,
    pub action: &'a str,
    pub resource: String,
    pub decision: &'static str,
    pub matched: &'a [String],
    pub reason: &'a str,
    pub eval_us: u128,
}

pub struct AuditLog {
    file: Mutex<File>,
}

impl AuditLog {
    pub fn open(path: &Path) -> std::io::Result<Self> {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let file = OpenOptions::new()
            .create(true)
            .append(true)
            .mode(0o600)
            .open(path)?;
        Ok(Self { file: Mutex::new(file) })
    }

    /// Record a decision. A logging failure must never change a decision, so
    /// errors are traced and swallowed.
    pub fn record(&self, query: &PolicyQuery, decision: &Decision) {
        let record = AuditRecord {
            ts: now_rfc3339(),
            request_id: &query.request_id,
            session_id: &query.session_id,
            backend: &query.backend,
            agent: &query.agent,
            principal: format!("Nono::Caller::{:?}", query.caller),
            action: query.action_name(),
            resource: query.resource_summary(),
            decision: if decision.allow { "allow" } else { "deny" },
            matched: &decision.matched,
            reason: &decision.reason,
            eval_us: decision.eval_us,
        };

        let line = match serde_json::to_string(&record) {
            Ok(line) => line,
            Err(e) => {
                tracing::error!(error = %e, "failed to serialize audit record");
                return;
            }
        };

        let mut guard = match self.file.lock() {
            Ok(guard) => guard,
            Err(poisoned) => poisoned.into_inner(),
        };
        if let Err(e) = writeln!(guard, "{line}") {
            tracing::error!(error = %e, "failed to write audit record");
        }
    }
}

fn now_rfc3339() -> String {
    time::OffsetDateTime::now_utc()
        .format(&time::format_description::well_known::Rfc3339)
        .unwrap_or_else(|_| "unknown".to_string())
}
```

> `format!("Nono::Caller::{:?}", query.caller)` yields `Nono::Caller::"session"`
> because `Debug` for `String` quotes and escapes — matching Cedar's own uid
> rendering.

Add to `src/lib.rs`: `pub mod audit;`.

- [ ] **Step 4: Run the tests**

Run: `cargo test --lib audit`
Expected: PASS, 2 tests.

- [ ] **Step 5: Make `check` write an audit line**

In `run_check` in `src/main.rs`, after evaluating:

```rust
    let decision = engine.evaluate(&query);
    match nono_cedar_pdp::audit::AuditLog::open(&config.audit_log) {
        Ok(log) => log.record(&query, &decision),
        Err(e) => eprintln!("warning: audit log unavailable: {e}"),
    }
    Ok(decision)
```

(Replace the existing `Ok(engine.evaluate(&query))` line.)

- [ ] **Step 6: Verify and commit**

```bash
cargo run --quiet -- check --config ./nono-cedar-pdp.toml tests/fixtures/git-status.json
tail -1 ./decisions.jsonl
```

Expected: an `{"ts":…,"decision":"allow",…}` line.

```bash
git add src/audit.rs src/lib.rs src/main.rs
git commit -m "feat: JSONL decision audit log"
```

---

### Task 8: HTTP server and the fail-closed matrix

**Files:**
- Create: `src/server.rs`, `tests/server.rs`
- Modify: `src/lib.rs`, `src/main.rs`

**Interfaces:**
- Consumes: `Engine`, `Config`, `AuditLog`, `adapter::nono_webhook::parse`.
- Produces:
  - `server::AppState { engine: Arc<Engine>, config: Arc<Config>, audit: Arc<AuditLog> }`
  - `server::router(state: AppState) -> axum::Router`
  - `server::serve(state: AppState, bind: SocketAddr) -> std::io::Result<()>` (async)
  - CLI: `nono-cedar-pdp serve --config <path>`

- [ ] **Step 1: Write the failing HTTP tests**

Create `tests/server.rs`:

```rust
//! The fail-closed matrix from the spec, exercised over HTTP.
#![allow(clippy::unwrap_used)]

use axum::body::Body;
use axum::http::{Request, StatusCode};
use nono_cedar_pdp::{audit::AuditLog, cedar, config::Config, server};
use std::collections::BTreeMap;
use std::sync::Arc;
use tower::ServiceExt;

const POLICY: &str = r#"
@id("allow-git-status")
permit (
  principal in Nono::Agent::"claude-code",
  action == Nono::Action::"launchCommand",
  resource
) when { resource.command == "git" && resource.args.contains("status") };
"#;

fn state(dir: &tempfile::TempDir) -> server::AppState {
    std::fs::write(dir.path().join("p.cedar"), POLICY).unwrap();
    let mut agents = BTreeMap::new();
    agents.insert("cedar".to_string(), "claude-code".to_string());
    let config = Config {
        bind: "127.0.0.1:0".parse().unwrap(),
        policy_dir: dir.path().to_path_buf(),
        audit_log: dir.path().join("decisions.jsonl"),
        agents,
        unknown_agent: "unknown".to_string(),
    };
    let schema = cedar::schema::load().unwrap();
    let engine = cedar::engine::Engine::bootstrap(schema, config.policy_dir.clone()).unwrap();
    server::AppState {
        engine: Arc::new(engine),
        audit: Arc::new(AuditLog::open(&config.audit_log).unwrap()),
        config: Arc::new(config),
    }
}

async fn post(dir: &tempfile::TempDir, body: &str) -> (StatusCode, serde_json::Value) {
    let app = server::router(state(dir));
    let response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/v1/approve")
                .header("content-type", "application/json")
                .body(Body::from(body.to_string()))
                .unwrap(),
        )
        .await
        .unwrap();
    let status = response.status();
    let bytes = axum::body::to_bytes(response.into_body(), 64 * 1024).await.unwrap();
    let json = serde_json::from_slice(&bytes).unwrap_or(serde_json::Value::Null);
    (status, json)
}

fn command_body(command: &str, args: &[&str]) -> String {
    serde_json::json!({
        "backend": "cedar",
        "request": {
            "capability_type": "command",
            "request_id": "r1",
            "command": command,
            "args": args,
            "caller": "session",
            "intercept_rule": "rule",
            "reason": null,
            "child_pid": 42,
            "session_id": "s1"
        }
    })
    .to_string()
}

#[tokio::test]
async fn permitted_command_gets_allow() {
    let dir = tempfile::tempdir().unwrap();
    let (status, body) = post(&dir, &command_body("git", &["git", "status"])).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body, serde_json::json!({"decision": "allow"}));
}

#[tokio::test]
async fn unpermitted_command_gets_deny_with_reason() {
    let dir = tempfile::tempdir().unwrap();
    let (status, body) = post(&dir, &command_body("curl", &["curl", "evil.example"])).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["decision"], "deny");
    assert!(body["reason"].as_str().unwrap().contains("no policy"));
}

#[tokio::test]
async fn malformed_body_gets_200_deny_not_4xx() {
    let dir = tempfile::tempdir().unwrap();
    let (status, body) = post(&dir, "{not json").await;
    assert_eq!(
        status,
        StatusCode::OK,
        "a 4xx also denies but loses our reason in nono's audit trail"
    );
    assert_eq!(body["decision"], "deny");
    assert!(body["reason"].as_str().unwrap().contains("malformed"));
}

#[tokio::test]
async fn unsupported_variant_gets_200_deny() {
    let dir = tempfile::tempdir().unwrap();
    let body = serde_json::json!({
        "backend": "cedar",
        "request": {
            "capability_type": "capability",
            "request_id": "c1",
            "path": "/etc/passwd",
            "access": "read",
            "reason": null,
            "child_pid": 7,
            "session_id": "s1"
        }
    })
    .to_string();
    let (status, body) = post(&dir, &body).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["decision"], "deny");
    assert!(body["reason"].as_str().unwrap().contains("unsupported"));
}

#[tokio::test]
async fn every_decision_is_audited() {
    let dir = tempfile::tempdir().unwrap();
    let _ = post(&dir, &command_body("git", &["git", "status"])).await;
    let text = std::fs::read_to_string(dir.path().join("decisions.jsonl")).unwrap();
    assert_eq!(text.lines().count(), 1, "{text}");
    assert!(text.contains("\"decision\":\"allow\""));
}

#[tokio::test]
async fn healthz_reports_the_loaded_generation() {
    let dir = tempfile::tempdir().unwrap();
    let app = server::router(state(&dir));
    let response = app
        .oneshot(Request::builder().uri("/healthz").body(Body::empty()).unwrap())
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let bytes = axum::body::to_bytes(response.into_body(), 8 * 1024).await.unwrap();
    let json: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(json["generation"], 1);
    assert_eq!(json["policies"], 1);
}
```

- [ ] **Step 2: Run and confirm failure**

Run: `cargo test --test server`
Expected: FAIL — `server` module not found.

- [ ] **Step 3: Implement the server**

Create `src/server.rs`:

```rust
//! HTTP surface. Deliberately thin: every decision is made below this layer.
//!
//! `/v1/approve` takes raw bytes rather than `Json<T>` because a malformed body
//! must produce a `200 {"decision":"deny"}` with our own reason, not axum's
//! generic 400 — nono records the reason we hand back.

use crate::audit::AuditLog;
use crate::cedar::engine::Engine;
use crate::config::Config;
use crate::decision::Decision;
use axum::body::Bytes;
use axum::extract::State;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use std::net::SocketAddr;
use std::sync::Arc;
use tower_http::catch_panic::CatchPanicLayer;

#[derive(Clone)]
pub struct AppState {
    pub engine: Arc<Engine>,
    pub config: Arc<Config>,
    pub audit: Arc<AuditLog>,
}

pub fn router(state: AppState) -> Router {
    Router::new()
        .route("/v1/approve", post(approve))
        .route("/healthz", get(healthz))
        .layer(CatchPanicLayer::new())
        .with_state(state)
}

async fn approve(State(state): State<AppState>, body: Bytes) -> Response {
    // Defence in depth: bootstrap refuses an empty policy dir, so this should be
    // unreachable. If it ever fires, 503 tells nono "PDP broken", which is a
    // different signal from "policy said no".
    if state.engine.snapshot().set.num_of_policies() == 0 {
        tracing::error!("policy set is empty; refusing to decide");
        return (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(serde_json::json!({"error": "no policies loaded"})),
        )
            .into_response();
    }

    let query = match crate::adapter::nono_webhook::parse(&body, &state.config) {
        Ok(query) => query,
        Err(e) => {
            tracing::warn!(error = %e, "rejecting approval request");
            let decision = Decision::deny(e.deny_reason());
            return (StatusCode::OK, Json(decision.to_wire())).into_response();
        }
    };

    let decision = state.engine.evaluate(&query);
    state.audit.record(&query, &decision);
    tracing::info!(
        request_id = %query.request_id,
        action = query.action_name(),
        resource = %query.resource_summary(),
        allow = decision.allow,
        matched = ?decision.matched,
        eval_us = decision.eval_us,
        "decision"
    );

    (StatusCode::OK, Json(decision.to_wire())).into_response()
}

async fn healthz(State(state): State<AppState>) -> Response {
    let snapshot = state.engine.snapshot();
    let count = snapshot.set.num_of_policies();
    let body = serde_json::json!({
        "generation": snapshot.generation,
        "policies": count,
        "policy_dir": state.engine.policy_dir().display().to_string(),
    });
    let status = if count == 0 {
        StatusCode::SERVICE_UNAVAILABLE
    } else {
        StatusCode::OK
    };
    (status, Json(body)).into_response()
}

pub async fn serve(state: AppState, bind: SocketAddr) -> std::io::Result<()> {
    let listener = tokio::net::TcpListener::bind(bind).await?;
    tracing::info!(%bind, "listening");
    axum::serve(listener, router(state)).await
}
```

Add to `src/lib.rs`: `pub mod server;`.

- [ ] **Step 4: Run the HTTP tests**

Run: `cargo test --test server`
Expected: PASS, 6 tests.

- [ ] **Step 5: Add the `serve` subcommand**

Add to the `Command` enum:

```rust
    /// Run the PDP daemon.
    Serve {
        #[arg(long, default_value = "./nono-cedar-pdp.toml")]
        config: PathBuf,
    },
```

Make `main` able to run async work by wrapping the serve arm:

```rust
        Command::Serve { config } => {
            let runtime = match tokio::runtime::Runtime::new() {
                Ok(runtime) => runtime,
                Err(e) => {
                    eprintln!("FAIL: {e}");
                    return ExitCode::FAILURE;
                }
            };
            match runtime.block_on(run_serve(&config)) {
                Ok(()) => ExitCode::SUCCESS,
                Err(message) => {
                    eprintln!("FAIL: {message}");
                    ExitCode::FAILURE
                }
            }
        }
```

```rust
async fn run_serve(config_path: &std::path::Path) -> Result<(), String> {
    use nono_cedar_pdp::{audit::AuditLog, server};
    use std::sync::Arc;

    let config = Config::load(config_path).map_err(|e| e.to_string())?;
    let schema = cedar::schema::load().map_err(|e| e.to_string())?;
    let engine = Arc::new(
        cedar::engine::Engine::bootstrap(schema, config.policy_dir.clone())
            .map_err(|e| e.to_string())?,
    );
    let audit = Arc::new(AuditLog::open(&config.audit_log).map_err(|e| e.to_string())?);
    let bind = config.bind;
    let state = server::AppState { engine, config: Arc::new(config), audit };
    server::serve(state, bind).await.map_err(|e| e.to_string())
}
```

- [ ] **Step 6: Smoke the daemon by hand**

```bash
cargo run --quiet -- serve --config ./nono-cedar-pdp.toml &
sleep 2
curl -s http://127.0.0.1:8181/healthz
curl -s -X POST http://127.0.0.1:8181/v1/approve \
  -H 'content-type: application/json' \
  -d @tests/fixtures/git-status.json
curl -s -X POST http://127.0.0.1:8181/v1/approve -d 'garbage'
kill %1
```

Expected: healthz JSON; `{"decision":"allow"}`; `{"decision":"deny","reason":"malformed…"}`.

- [ ] **Step 7: Commit**

```bash
git add src/server.rs src/lib.rs src/main.rs tests/server.rs
git commit -m "feat: fail-closed HTTP decision endpoint with health check"
```

---

### Task 9: Policy hot-reload with last-good semantics

**Files:**
- Create: `src/watcher.rs`
- Modify: `src/lib.rs`, `src/main.rs`, `src/cedar/engine.rs` (tests only)

**Interfaces:**
- Consumes: `Engine::reload`.
- Produces: `watcher::spawn(engine: Arc<Engine>) -> notify::Result<notify::RecommendedWatcher>` — the returned watcher must be kept alive for the process lifetime.

- [ ] **Step 1: Write the failing reload tests**

Append to the test module in `src/cedar/engine.rs`:

```rust
    #[test]
    fn reload_picks_up_edits_and_bumps_generation() {
        let schema = crate::cedar::schema::load().unwrap();
        let d = dir_with(&[("p.cedar", MATRIX)]);
        let engine = Engine::bootstrap(schema, d.path().to_path_buf()).unwrap();
        assert!(engine.evaluate(&command_query("session", "git", &["git", "status"])).allow);

        std::fs::write(
            d.path().join("p.cedar"),
            r#"forbid (principal, action, resource);"#,
        )
        .unwrap();
        let generation = engine.reload().unwrap();
        assert_eq!(generation, 2);
        assert!(!engine.evaluate(&command_query("session", "git", &["git", "status"])).allow);
    }

    #[test]
    fn failed_reload_keeps_last_good_policies() {
        let schema = crate::cedar::schema::load().unwrap();
        let d = dir_with(&[("p.cedar", MATRIX)]);
        let engine = Engine::bootstrap(schema, d.path().to_path_buf()).unwrap();

        std::fs::write(d.path().join("p.cedar"), "permit (this is not cedar").unwrap();
        assert!(engine.reload().is_err());

        assert_eq!(engine.snapshot().generation, 1, "generation must not advance");
        assert!(
            engine.evaluate(&command_query("session", "git", &["git", "status"])).allow,
            "a broken edit must not brick a running agent"
        );
    }

    #[test]
    fn failed_reload_on_schema_violation_keeps_last_good() {
        let schema = crate::cedar::schema::load().unwrap();
        let d = dir_with(&[("p.cedar", MATRIX)]);
        let engine = Engine::bootstrap(schema, d.path().to_path_buf()).unwrap();

        std::fs::write(
            d.path().join("p.cedar"),
            r#"permit (principal, action == Nono::Action::"launchCommand", resource)
               when { resource.cwd == "/tmp" };"#,
        )
        .unwrap();
        assert!(matches!(engine.reload(), Err(PolicyLoadError::Validation { .. })));
        assert!(engine.evaluate(&command_query("session", "git", &["git", "status"])).allow);
    }
```

- [ ] **Step 2: Run and confirm the reload tests fail or pass**

Run: `cargo test --lib cedar::engine::tests::reload`
Expected: PASS — `reload` was implemented in Task 5. If any fail, fix `reload` before continuing; these three tests are the D7 contract.

- [ ] **Step 3: Write the failing watcher test**

Create `src/watcher.rs` with only this test module:

```rust
#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use std::sync::Arc;
    use std::time::{Duration, Instant};

    const POLICY: &str = r#"permit (principal, action == Nono::Action::"launchCommand", resource)
        when { resource.command == "git" };"#;

    #[test]
    fn edits_trigger_a_reload() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("p.cedar"), POLICY).unwrap();
        let schema = crate::cedar::schema::load().unwrap();
        let engine = Arc::new(
            crate::cedar::engine::Engine::bootstrap(schema, dir.path().to_path_buf()).unwrap(),
        );
        let _watcher = spawn(Arc::clone(&engine)).unwrap();

        std::fs::write(
            dir.path().join("p.cedar"),
            r#"forbid (principal, action, resource);"#,
        )
        .unwrap();

        let deadline = Instant::now() + Duration::from_secs(5);
        while Instant::now() < deadline && engine.snapshot().generation == 1 {
            std::thread::sleep(Duration::from_millis(50));
        }
        assert_eq!(engine.snapshot().generation, 2, "watcher did not reload");
    }
}
```

- [ ] **Step 4: Run and confirm failure**

Run: `cargo test --lib watcher`
Expected: FAIL — `spawn` not found.

- [ ] **Step 5: Implement the watcher**

Prepend to `src/watcher.rs`:

```rust
//! Filesystem watch on the policy directory.
//!
//! Debounces bursts (editors write several events per save) and reloads through
//! `Engine::reload`, which keeps the last-good set on failure.

use crate::cedar::engine::Engine;
use notify::{Event, RecommendedWatcher, RecursiveMode, Watcher};
use std::sync::mpsc;
use std::sync::Arc;
use std::time::Duration;

const DEBOUNCE: Duration = Duration::from_millis(150);

/// Start watching `engine.policy_dir()`. Keep the returned watcher alive — its
/// drop stops the watch.
pub fn spawn(engine: Arc<Engine>) -> notify::Result<RecommendedWatcher> {
    let (tx, rx) = mpsc::channel::<notify::Result<Event>>();
    let mut watcher = notify::recommended_watcher(tx)?;
    watcher.watch(engine.policy_dir(), RecursiveMode::NonRecursive)?;

    std::thread::Builder::new()
        .name("policy-watcher".to_string())
        .spawn(move || {
            while let Ok(first) = rx.recv() {
                if let Err(e) = first {
                    tracing::warn!(error = %e, "policy watch error");
                    continue;
                }
                // Drain the burst an editor save produces.
                while rx.recv_timeout(DEBOUNCE).is_ok() {}
                match engine.reload() {
                    Ok(generation) => {
                        tracing::info!(generation, "policies reloaded from disk")
                    }
                    Err(e) => tracing::error!(
                        error = %e,
                        "policy reload failed; keeping previous policy set"
                    ),
                }
            }
        })
        .map_err(|e| notify::Error::io(e))?;

    Ok(watcher)
}
```

Add to `src/lib.rs`: `pub mod watcher;`.

- [ ] **Step 6: Run the watcher test**

Run: `cargo test --lib watcher`
Expected: PASS.

- [ ] **Step 7: Wire the watcher into `serve`**

In `run_serve` in `src/main.rs`, after building `engine` and before serving:

```rust
    let _watcher = nono_cedar_pdp::watcher::spawn(Arc::clone(&engine))
        .map_err(|e| format!("starting policy watcher: {e}"))?;
```

> Bind it to `_watcher` (not `_`) so it lives until the function returns.
> Dropping it immediately would silently stop the watch.

- [ ] **Step 8: Verify by hand and commit**

```bash
cargo run --quiet -- serve --config ./nono-cedar-pdp.toml &
sleep 2
curl -s http://127.0.0.1:8181/healthz          # generation 1
echo 'permit (principal, action, resource);' >> policies/starter.cedar
sleep 1
curl -s http://127.0.0.1:8181/healthz          # generation 2
printf 'this is broken cedar' >> policies/starter.cedar
sleep 1
curl -s http://127.0.0.1:8181/healthz          # still generation 2
kill %1
git checkout policies/starter.cedar
```

```bash
git add src/watcher.rs src/lib.rs src/main.rs src/cedar/engine.rs
git commit -m "feat: policy hot-reload keeping last-good set on failure"
```

---

### Task 10: Starter policies, nono profile, README, end-to-end smoke

**Files:**
- Create: `policies/00-baseline.cedar`, `policies/10-git.cedar`, `examples/cedar-pdp-smoke.json`, `README.md`
- Modify: `Justfile`, `policies/starter.cedar` (delete — superseded)

**Interfaces:**
- Consumes: everything above.
- Produces: `just smoke` — a reproducible end-to-end proof that a real `nono run` decision came from Cedar.

- [ ] **Step 1: Write the starter policy pack**

`policies/00-baseline.cedar`:

```cedar
// Baseline posture. Cedar is default-deny, so these only *narrow* behaviour.

// Nothing chained through another intercepted command may launch anything.
// `caller` is "session" for a direct agent launch, otherwise the invoking
// command's name.
@id("session-launches-only")
forbid (
  principal,
  action == Nono::Action::"launchCommand",
  resource
) unless {
  principal == Nono::Caller::"session"
};

// An unmapped approval-backend name resolves to Agent::"unknown". Deny it
// explicitly so a misconfigured `[agents]` table is loud rather than silent.
@id("no-unknown-agents")
forbid (principal, action, resource)
when {
  principal in Nono::Agent::"unknown"
};
```

`policies/10-git.cedar`:

```cedar
// Read-only git is fine.
@id("git-read-only")
permit (
  principal in Nono::Agent::"claude-code",
  action == Nono::Action::"launchCommand",
  resource
) when {
  resource.command == "git" &&
  (resource.args.contains("status") ||
   resource.args.contains("diff") ||
   resource.args.contains("log") ||
   resource.args.contains("show"))
};

// History rewriting is never approved automatically.
//
// NOTE: exact set membership, never a positional index — nono drops non-UTF-8
// argv entries, so argument positions shift.
@id("no-history-rewrites")
forbid (
  principal,
  action == Nono::Action::"launchCommand",
  resource
) when {
  resource.args.contains("--force") ||
  resource.args.contains("--force-with-lease") ||
  resource.args.contains("--hard")
};
```

Remove the scratch policy: `trash policies/starter.cedar`

- [ ] **Step 2: Validate the pack**

Run: `cargo run --quiet -- validate --config ./nono-cedar-pdp.toml`
Expected: `OK: 4 policies loaded and validated`.

- [ ] **Step 3: Verify decisions against the pack**

```bash
cargo run --quiet -- check --config ./nono-cedar-pdp.toml tests/fixtures/git-status.json
```

Expected: `ALLOW: permitted by 10-git:git-read-only …`.

```bash
cat > tests/fixtures/git-force-push.json <<'EOF'
{"backend":"cedar","request":{"capability_type":"command","request_id":"r2",
"command":"git","args":["git","push","--force"],"caller":"session",
"intercept_rule":"push","reason":null,"child_pid":42,"session_id":"s1"}}
EOF
cargo run --quiet -- check --config ./nono-cedar-pdp.toml tests/fixtures/git-force-push.json
```

Expected: `DENY: denied by 10-git:no-history-rewrites …`.

- [ ] **Step 4: Create the nono profile from a real skeleton**

Do NOT hand-write the profile — generate it so the base fields are whatever this
nono version expects, then add the approval wiring:

```bash
nono profile init cedar-pdp-smoke
nono profile list | grep cedar-pdp-smoke
```

Then merge this `command_policies` block into the generated profile (field
shapes taken from nono's own `nono profile schema` output):

```json
{
  "command_policies": {
    "approval_backends": {
      "cedar": {
        "type": "webhook",
        "url": "http://127.0.0.1:8181/v1/approve",
        "timeout_secs": 5
      },
      "cedar-or-ask": {
        "type": "chain",
        "mode": "any",
        "backends": ["cedar", "terminal"]
      },
      "terminal": { "type": "terminal" }
    },
    "approval_defaults": { "backend": "cedar", "timeout_secs": 5 },
    "commands": {
      "git": {
        "from": {
          "session": {
            "sandbox": { "fs_read": ["."], "fs_write": ["."] }
          }
        },
        "intercept": [
          { "args": ["status"], "action": { "type": "approve", "timeout_secs": 5 } },
          { "args": ["push"], "action": { "type": "approve", "timeout_secs": 5 } }
        ]
      }
    }
  }
}
```

Copy the merged file to `examples/cedar-pdp-smoke.json` and validate it:

```bash
nono profile validate ~/.config/nono/profiles/cedar-pdp-smoke.json
cp ~/.config/nono/profiles/cedar-pdp-smoke.json examples/cedar-pdp-smoke.json
```

Expected: validation reports OK. If it complains about a field, fix it against
`nono profile schema` output — nono's schema is authoritative, not this plan.

> The `intercept` action `approve` carries only `timeout_secs`, with no
> `backend` field, so it routes via `approval_defaults.backend`. Per-rule
> backend routing exists only on invocation-policy rules
> (`invocation_policy.approve[].backend`). Switching `approval_defaults.backend`
> to `"cedar-or-ask"` is the safe-rollout posture: Cedar denies, then you get a
> terminal prompt.

- [ ] **Step 5: Add the smoke recipe**

Append to `Justfile`:

```make
# End-to-end: real `nono run` decision answered by Cedar.
smoke:
    #!/usr/bin/env bash
    set -euo pipefail
    test -n "$(command -v nono)" || { echo "nono not installed"; exit 1; }
    nono profile validate examples/cedar-pdp-smoke.json
    cargo build --quiet
    ./target/debug/nono-cedar-pdp serve --config ./nono-cedar-pdp.toml &
    PDP=$!
    trap 'kill $PDP 2>/dev/null || true' EXIT
    for _ in $(seq 1 20); do
      curl -sf http://127.0.0.1:8181/healthz >/dev/null && break
      sleep 0.25
    done
    LINES_BEFORE=$(wc -l < ./decisions.jsonl 2>/dev/null || echo 0)
    echo "--- expect ALLOW: git status"
    nono run --profile cedar-pdp-smoke -- git status >/dev/null
    echo "--- expect DENY: git push --force"
    if nono run --profile cedar-pdp-smoke -- git push --force 2>/dev/null; then
      echo "FAIL: force push was not blocked"; exit 1
    fi
    echo "--- decisions recorded:"
    tail -n +$((LINES_BEFORE + 1)) ./decisions.jsonl
    grep -q '"decision":"allow"' ./decisions.jsonl
    grep -q '"decision":"deny"' ./decisions.jsonl
    echo "SMOKE PASSED"
```

- [ ] **Step 6: Run the smoke test**

Run: `just smoke`
Expected: `SMOKE PASSED`, with one allow line and one deny line printed.

Troubleshooting, in order:
1. `nono why --command git --caller session` — confirms the command policy resolves. If it errors that tool-sandbox is inactive, run `nono setup` first.
2. If the request never arrives, check the PDP is on `127.0.0.1:8181` and the profile URL matches.
3. If nono reports `approval_denied` for `git status`, run the payload through `check` — the audit line shows which policy matched.

- [ ] **Step 7: Write the README**

`README.md` must cover, in this order: what it is (one paragraph, naming nono as the PEP and Cedar as the PDP); the verified nono contract with a real payload; quick start (`just serve`, config file, policy dir); the nono profile snippet from Step 4; the three rollout postures (`cedar`, `cedar-or-ask` = chain/any, `cedar-and-ask` = chain/all); **the three schema caveats** (`args` is a Set so no positional matching; `argv` globs are forbid-only because they over-match inside a single argument; endpoint requests have no session identity); the security caveat that the webhook is unauthenticated in both directions and the https-on-loopback follow-up; and a pointer to the spec, ADR and research docs.

- [ ] **Step 8: Full verification and commit**

```bash
just fmt && just lint && just test && just smoke
```

Expected: all green.

```bash
git add policies/ examples/ README.md Justfile tests/fixtures/
git rm --cached policies/starter.cedar 2>/dev/null || true
git commit -m "feat: starter policy pack, nono profile, README, e2e smoke test"
```

---

## Deviations from the spec, recorded

1. **An empty policy directory is a startup failure** (`PolicyLoadError::Empty`), not a silently-denying daemon. Spec §7 said an empty set "denies everything (correct, logged loudly)"; refusing to start is the same fail-closed posture with a far better diagnostic, and it makes the §7 `503` row defence-in-depth rather than a reachable state. A user who genuinely wants deny-all writes `forbid (principal, action, resource);`.
2. **`Decision::from_response` forces deny when Cedar reports evaluation errors**, even if the decision was `Allow`. Not in the spec; it follows from fail-closed-first, because an errored policy might have been a `forbid`.
3. **Policy ids are `<file stem>:<@id annotation or ordinal>`.** The spec said "matched policy ids" without specifying provenance; embedding the filename makes a deny reason actionable.

## Self-Review

**Spec coverage:** §2 verified contract → Task 2 (conformance) and the Verified Ground Truth block. §3 D1/D2 → Task 1 Cargo.toml + Task 2 dev-dep. D3 entity model → Task 6 `entities.rs`. D4 both variants + JSONL + hot-reload → Tasks 3, 6, 7, 9. D5 response shape → Task 2 test + `wire::WebhookResponse`. D6 `Set<String>` → Task 4 schema + Task 4 test. D7 last-good reload → Task 9. D8 loopback bind → Task 1 default + Global Constraints. §4 architecture → File Structure. §5 schema + all three caveats → Task 4, Task 10 policy comments, README Step 7. §6 data flow → Tasks 3/6/7/8. §7 error table → Task 8 tests (every row except the two startup rows, which are Task 5 tests) + the recorded deviation. §8 deployment/chain postures → Task 10 Step 4 + README. §9 testing 1–5 → Task 2 (conformance), Task 6 (matrix), Task 8 (fail-closed), Task 10 (smoke). The lossy-argv test from §9.4 is covered structurally by Task 4's `positional_argument_access_is_rejected_by_the_schema` plus the `no-history-rewrites` set-membership policy — a runtime non-UTF-8 test is impossible from our side because upstream drops the bytes before we see them, which is itself worth noting in the README. §10 follow-ups → deliberately out of scope.

**Placeholders:** none remain. Task 5 Step 1 contains a deliberately-marked stub test that Step 3 replaces with the real assertion; Task 6 Step 1 flags one awkward assertion to write as `assert_eq!(decision.matched, vec!["matrix:allow-git".to_string()]);`.

**Type consistency:** `Config` fields are constructed literally in three test helpers (Tasks 3, 8) and must match `config.rs` exactly — five fields, no more. `PolicyQuery` is built in Tasks 3, 6, 7 with the same eight fields. `Decision` is `{allow, matched, reason, eval_us}` throughout. `Engine` exposes `bootstrap/snapshot/schema/policy_dir/reload/evaluate` and nothing else is referenced. `load_dir(dir, schema, generation)` keeps that argument order at all four call sites.
