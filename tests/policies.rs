//! The policy pack this repo ships is part of the product: a fresh install
//! inherits its posture, and nothing in the service layer second-guesses it.
//! These assertions pin the decisions it has to make.
#![allow(clippy::unwrap_used)]

use nono_cedar_pdp::decision::Decision;
use nono_cedar_pdp::{adapter::nono_webhook, cedar, config::Config};
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

/// `args[0]` as nono really sends it: an absolute per-run shim path.
const SHIM_GIT: &str = nono_cedar_pdp::wire::EXAMPLE_SHIM_ARGV0;

const POLICY_DIR: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/policies");
const FIXTURES: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures");

fn config() -> Config {
    let mut agents = BTreeMap::new();
    agents.insert("cedar".to_string(), "claude-code".to_string());
    Config {
        bind: "127.0.0.1:8181".parse().unwrap(),
        policy_dir: PathBuf::from(POLICY_DIR),
        audit_log: PathBuf::from("/dev/null"),
        agents,
        unknown_agent: "unknown".to_string(),
    }
}

fn decide(body: &[u8]) -> Decision {
    let config = config();
    let schema = cedar::schema::load().unwrap();
    let engine = cedar::engine::Engine::bootstrap(schema, PathBuf::from(POLICY_DIR)).unwrap();
    let query = nono_webhook::parse(body, &config).unwrap();
    engine.evaluate(&query)
}

fn decide_fixture(name: &str) -> Decision {
    let body = std::fs::read(Path::new(FIXTURES).join(name)).unwrap();
    decide(&body)
}

fn command_body(backend: &str, caller: &str, args: &[&str]) -> Vec<u8> {
    serde_json::json!({
        "backend": backend,
        "request": {
            "capability_type": "command",
            "request_id": "r1",
            "command": "git",
            "args": args,
            "caller": caller,
            "intercept_rule": "rule",
            "reason": null,
            "child_pid": 42,
            "session_id": "s1"
        }
    })
    .to_string()
    .into_bytes()
}

#[test]
fn the_shipped_pack_loads_and_strict_validates() {
    let schema = cedar::schema::load().unwrap();
    let loaded = cedar::engine::load_dir(Path::new(POLICY_DIR), &schema, 1).unwrap();
    assert_eq!(loaded.set.num_of_policies(), 4, "{:?}", loaded.files);
}

#[test]
fn read_only_git_is_permitted() {
    let decision = decide_fixture("git-status.json");
    assert!(decision.allow, "{decision:?}");
    assert_eq!(decision.matched, vec!["10-git:git-read-only".to_string()]);
}

#[test]
fn history_rewrites_are_denied() {
    let decision = decide_fixture("git-force-push.json");
    assert!(!decision.allow, "{decision:?}");
    assert!(
        decision
            .matched
            .contains(&"10-git:no-history-rewrites".to_string()),
        "{decision:?}"
    );
}

/// An approval-backend name that is not in the `[agents]` map resolves to
/// `Agent::"unknown"`. Nothing in the service layer denies that — it is the
/// baseline policy's job, so the shipped pack has to do it.
#[test]
fn an_unmapped_approval_backend_is_denied() {
    let decision = decide(&command_body("rogue", "session", &[SHIM_GIT, "status"]));
    assert!(
        !decision.allow,
        "an unmapped backend must not inherit a mapped agent's rights: {decision:?}"
    );
    assert!(
        decision
            .matched
            .contains(&"00-baseline:no-unknown-agents".to_string()),
        "{decision:?}"
    );
}

/// `caller` is `"session"` for a direct agent launch and otherwise the
/// intercepted command that chained this one; only the former is approved.
#[test]
fn a_chained_command_launch_is_denied() {
    let decision = decide(&command_body("cedar", "npm", &[SHIM_GIT, "status"]));
    assert!(!decision.allow, "{decision:?}");
    assert!(
        decision
            .matched
            .contains(&"00-baseline:session-launches-only".to_string()),
        "{decision:?}"
    );
}
