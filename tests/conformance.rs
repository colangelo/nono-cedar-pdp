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

/// The *header* half of the upstream contract, pinned as far as it can be from here.
///
/// The decide endpoint now requires `Content-Type: application/json`, which makes a
/// header nono sends load-bearing: if a future nono stopped sending it, every
/// decision would be refused — fail-closed, but a total outage. The two header values
/// were read from nono 0.69.0's webhook client,
/// `crates/nono-cli/src/approval_runtime.rs`, which builds the POST as
///
/// ```text
/// .post(&self.url)
/// .header("Content-Type", "application/json")
/// .header("User-Agent", &format!("nono-cli/{}", env!("CARGO_PKG_VERSION")))
/// .send(body)
/// ```
///
/// **That client is not reachable from the dev-dependency, so the header values
/// themselves cannot be asserted.** `nono` is the sandboxing *library* (dev-only, per
/// ADR-001); the webhook POST lives in the `nono-cli` binary crate, which publishes no
/// library target. `nono 0.69.0` exposes the approval *types* the tests above
/// round-trip and no HTTP client, no `reqwest` builder and no header constant of any
/// kind — verified by grepping the vendored crate source for `Content-Type` and
/// `User-Agent`, which match nothing. Rather than skip silently, this pins the three
/// things that *are* reachable, so a version bump breaks something visible:
///
/// 1. the dev-dependency version the headers were read from — bumping `nono` fails
///    here and sends the bumper back to `approval_runtime.rs`;
/// 2. that nono's own request type serializes to a JSON *object*, so
///    `application/json` is a truthful description of the body the client posts —
///    the gate demands what the payload actually is, not a convention;
/// 3. that the gate accepts the upstream literal and refuses the three content types
///    a CORS-simple cross-origin POST may carry, which is the mechanism that closes
///    the browser vector (design D1).
///
/// What *does* observe the real values is `just smoke`, and that is deliberate: a real
/// `nono run` drives the endpoint there, so a client that stopped sending the
/// content-type would fail it with a 415 and no audit line, and the recipe additionally
/// greps the resulting audit line for `"user_agent":"nono-cli/`. Both halves are
/// therefore empirically checked once per smoke run — verified on nono 0.69.0, whose
/// lines read `"user_agent":"nono-cli/0.69.0"` — while this test is what fails in CI
/// on a version bump alone.
///
/// The `User-Agent` is recorded as evidence only (design D5) and nothing depends on
/// its value, so there is nothing to fail closed if it changes.
#[test]
fn the_webhook_header_contract_is_pinned_to_the_nono_version_it_was_read_from() {
    const MANIFEST: &str = include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/Cargo.toml"));
    assert!(
        MANIFEST.contains(r#"nono = { version = "0.69.0""#),
        "the nono dev-dependency moved off 0.69.0. The decide endpoint's header gate \
         requires the `Content-Type: application/json` that nono 0.69.0's webhook \
         client sends from crates/nono-cli/src/approval_runtime.rs — re-read that \
         file's `.header(...)` calls before bumping, because a client that stopped \
         sending the header would have every decision refused with 415"
    );

    // (2) The body really is a JSON object, so the content type the gate demands
    // describes the payload rather than a convention we hope holds.
    let upstream = nono::ApprovalRequest::Command {
        request_id: "r1".into(),
        command: "git".into(),
        args: vec![EXAMPLE_SHIM_ARGV0.into(), "status".into()],
        caller: "session".into(),
        intercept_rule: "status".into(),
        reason: None,
        child_pid: 42,
        session_id: "s1".into(),
    };
    let body = serde_json::json!({ "backend": "cedar", "request": serde_json::to_value(&upstream).unwrap() });
    assert!(
        body.is_object(),
        "nono's own approval request no longer serializes to a JSON object, so \
         `application/json` no longer describes the body: {body}"
    );

    // (3) The gate itself, against the upstream literal and against the three types a
    // CORS-simple cross-origin POST may use — the ones a drive-by page is limited to.
    assert!(
        nono_cedar_pdp::server::is_json_content_type(Some("application/json")),
        "the gate must accept the exact literal nono's client sends, or every real \
         decision is refused"
    );
    for cors_simple in [
        "text/plain",
        "application/x-www-form-urlencoded",
        "multipart/form-data",
    ] {
        assert!(
            !nono_cedar_pdp::server::is_json_content_type(Some(cors_simple)),
            "{cors_simple:?} is a content type a CORS-simple cross-origin POST may \
             send without a preflight; accepting it reopens the drive-by vector"
        );
    }
    assert!(
        !nono_cedar_pdp::server::is_json_content_type(None),
        "a request with no content-type cannot have come from nono's client"
    );
    // A future client may add parameters, and RFC 9110 makes the type
    // case-insensitive; neither may turn a real request into a refusal.
    assert!(nono_cedar_pdp::server::is_json_content_type(Some(
        "application/json; charset=utf-8"
    )));
    assert!(nono_cedar_pdp::server::is_json_content_type(Some(
        "APPLICATION/JSON"
    )));
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
