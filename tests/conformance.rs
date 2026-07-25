//! Wire-drift guard. Serializes requests using nono's OWN types and asserts our
//! mirrors round-trip them, including the exact key set. When a nono upgrade
//! changes the contract, this test fails instead of the daemon silently
//! misreading a security decision.
#![allow(clippy::unwrap_used, clippy::panic)]

use nono_cedar_pdp::wire::{ApprovalRequest, WebhookEnvelope, EXAMPLE_SHIM_ARGV0};
use std::collections::BTreeSet;

fn envelope_from(upstream: &nono::ApprovalRequest) -> (WebhookEnvelope, BTreeSet<String>) {
    let request = serde_json::to_value(upstream).unwrap();
    let keys: BTreeSet<String> = request.as_object().unwrap().keys().cloned().collect();
    let body = serde_json::json!({ "backend": "cedar", "request": request });
    (serde_json::from_value(body).unwrap(), keys)
}

/// The key set is the drift guard; the VALUES here are the runtime shape. Upstream
/// carries a unit-test fixture with `args: ["git", "push"]`
/// (`crates/nono/src/supervisor/mod.rs:209-217`) that never reaches a webhook — the
/// shim sends its own `args_os()`, so `args[0]` is a per-run shim path.
#[test]
fn command_request_matches_upstream() {
    let upstream = nono::ApprovalRequest::Command {
        request_id: "r1".into(),
        command: "git".into(),
        args: vec![EXAMPLE_SHIM_ARGV0.into(), "push".into()],
        caller: "session".into(),
        intercept_rule: "push".into(),
        reason: None,
        child_pid: 42,
        session_id: "s1".into(),
    };
    let (env, keys) = envelope_from(&upstream);

    let expected: BTreeSet<String> = [
        "capability_type",
        "request_id",
        "command",
        "args",
        "caller",
        "intercept_rule",
        "reason",
        "child_pid",
        "session_id",
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
    assert_eq!(c.args, vec![EXAMPLE_SHIM_ARGV0, "push"]);
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
        "capability_type",
        "request_id",
        "route_id",
        "upstream",
        "method",
        "path",
        "rule_label",
        "reason",
        "child_pid",
        "session_id",
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
