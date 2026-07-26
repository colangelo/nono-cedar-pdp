//! The fail-closed matrix from the spec, exercised over HTTP.
//!
//! One row of it is not here: the zero-policy 503. Reaching that state needs an
//! engine built past the load guards, and that constructor is `#[cfg(test)]` so no
//! production caller can skip them — so the test lives in `src/server.rs`'s unit
//! tests (`a_daemon_with_no_policies_reports_unavailable`).
#![allow(clippy::unwrap_used, clippy::panic)]

use axum::body::Body;
use axum::http::{Request, StatusCode};
use nono_cedar_pdp::{audit::AuditLog, cedar, config::Config, server};
use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};
use tower::ServiceExt;

/// nono sends `args[0]` as an absolute per-run shim path, not the command name.
/// Every request body here uses that shape so the suite cannot green-light a
/// policy pattern that production never matches.
const SHIM_GIT: &str = nono_cedar_pdp::wire::EXAMPLE_SHIM_ARGV0;
const SHIM_CURL: &str =
    "/private/tmp/nono-tool-sandbox-13819-1784990893285791000-a4d3bceb3ec061c0/shims/curl";

const POLICY: &str = r#"
@id("allow-git-status")
permit (
  principal in Nono::Agent::"claude-code",
  action == Nono::Action::"launchCommand",
  resource
) when { resource.command == "git" && resource.args.contains("status") };

@id("allow-github-repo-reads")
permit (
  principal in Nono::Agent::"claude-code",
  action == Nono::Action::"httpRequest",
  resource
) when { resource.method == "GET" && resource.path like "/repos/*" };
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
    post_to(&server::router(state(dir)), body).await
}

/// Post to an existing router, so a test can send two requests to *one* daemon
/// — the only way to observe what happens to long-lived state between decisions.
async fn post_to(app: &axum::Router, body: &str) -> (StatusCode, serde_json::Value) {
    let response = app
        .clone()
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
    let bytes = axum::body::to_bytes(response.into_body(), 64 * 1024)
        .await
        .unwrap();
    let json = serde_json::from_slice(&bytes).unwrap_or(serde_json::Value::Null);
    (status, json)
}

fn command_body(command: &str, args: &[&str]) -> String {
    command_body_with_request_id("r1", command, args)
}

fn command_body_with_request_id(request_id: &str, command: &str, args: &[&str]) -> String {
    command_body_with_rule(request_id, "rule", command, args)
}

/// A command body whose `intercept_rule` the test chooses: the corpus of real rule
/// shapes needs to vary exactly this field.
fn command_body_with_rule(
    request_id: &str,
    intercept_rule: &str,
    command: &str,
    args: &[&str],
) -> String {
    serde_json::json!({
        "backend": "cedar",
        "request": {
            "capability_type": "command",
            "request_id": request_id,
            "command": command,
            "args": args,
            "caller": "session",
            "intercept_rule": intercept_rule,
            "reason": null,
            "child_pid": 42,
            "session_id": "s1"
        }
    })
    .to_string()
}

/// An `endpoint` approval request, as nono's credential proxy sends one: the raw
/// request target, unnormalised and still percent-encoded.
fn endpoint_body(request_id: &str, path: &str) -> String {
    serde_json::json!({
        "backend": "cedar",
        "request": {
            "capability_type": "endpoint",
            "request_id": request_id,
            "route_id": "github-api",
            "upstream": "https://api.github.com",
            "method": "GET",
            "path": path,
            "rule_label": "endpoint_policy.approve[GET /repos/*]",
            "reason": "route requires approval",
            "child_pid": 0,
            "session_id": "proxy"
        }
    })
    .to_string()
}

/// A `capability` approval request: a variant the daemon refuses to evaluate,
/// but one that still carries full identifying context on the wire.
fn capability_body(request_id: &str) -> String {
    serde_json::json!({
        "backend": "cedar",
        "request": {
            "capability_type": "capability",
            "request_id": request_id,
            "path": "/Users/agent/.ssh/id_ed25519",
            "access": "read",
            "reason": null,
            "child_pid": 7,
            "session_id": "s1"
        }
    })
    .to_string()
}

/// Every audit line, parsed. Panics naming the offending line if any line is not
/// independently parseable JSON.
fn audit_lines(dir: &tempfile::TempDir) -> Vec<serde_json::Value> {
    let path = dir.path().join("decisions.jsonl");
    let text = std::fs::read_to_string(&path).unwrap_or_default();
    text.lines()
        .map(|line| {
            serde_json::from_str(line)
                .unwrap_or_else(|e| panic!("unparseable audit line {line:?}: {e}"))
        })
        .collect()
}

/// One HTTP/1.1 exchange over a real socket, `Connection: close` so the read ends
/// at the response. Synchronous on purpose: the test that uses it runs on a
/// multi-threaded runtime, so `serve` keeps making progress on another worker while
/// this blocks.
fn http(addr: std::net::SocketAddr, request: &str) -> String {
    use std::io::{Read, Write};
    let mut stream =
        std::net::TcpStream::connect_timeout(&addr, std::time::Duration::from_secs(5)).unwrap();
    stream
        .set_read_timeout(Some(std::time::Duration::from_secs(10)))
        .unwrap();
    stream.write_all(request.as_bytes()).unwrap();
    stream.flush().unwrap();
    let mut response = Vec::new();
    stream.read_to_end(&mut response).unwrap();
    String::from_utf8_lossy(&response).to_string()
}

/// `server::serve` — the function that actually binds — has no other test caller:
/// every HTTP test here drives the `Router` through `oneshot`, which never creates
/// a socket, never runs `axum::serve`, and would keep passing if the listener were
/// removed entirely.
///
/// An ephemeral port, not the documented default `127.0.0.1:8181`: 8181 is where an
/// operator runs their own daemon, so a test that claimed it would fail on a
/// developer's machine. What matters here is that the address `serve` is handed is
/// the address that answers.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_real_listener_answers_a_posted_envelope() {
    let dir = tempfile::tempdir().unwrap();
    let state = state(&dir);

    // Take an ephemeral port and release it, so `serve` does its own bind.
    let probe = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = probe.local_addr().unwrap();
    drop(probe);

    let serving = tokio::spawn(async move { server::serve(state, addr).await });

    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
    while std::net::TcpStream::connect_timeout(&addr, std::time::Duration::from_millis(200))
        .is_err()
    {
        assert!(
            std::time::Instant::now() < deadline,
            "serve never accepted a connection on {addr}"
        );
        assert!(!serving.is_finished(), "serve returned instead of serving");
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
    }

    let body = command_body("git", &[SHIM_GIT, "status"]);
    let response = tokio::task::spawn_blocking(move || {
        let health = http(
            addr,
            &format!("GET /healthz HTTP/1.1\r\nHost: {addr}\r\nConnection: close\r\n\r\n"),
        );
        let approve = http(
            addr,
            &format!(
                "POST /v1/approve HTTP/1.1\r\nHost: {addr}\r\n\
                 Content-Type: application/json\r\nContent-Length: {}\r\n\
                 Connection: close\r\n\r\n{body}",
                body.len()
            ),
        );
        (health, approve)
    })
    .await
    .unwrap();
    let (health, approve) = response;

    serving.abort();

    assert!(health.starts_with("HTTP/1.1 200 OK"), "{health:?}");
    assert!(health.contains("\"generation\":1"), "{health:?}");
    assert!(approve.starts_with("HTTP/1.1 200 OK"), "{approve:?}");
    assert!(
        approve.ends_with("{\"decision\":\"allow\"}"),
        "the decision must survive the real wire, not just the Router: {approve:?}"
    );

    // And the decision a socket produced is on the record.
    let lines = audit_lines(&dir);
    assert_eq!(lines.len(), 1, "{lines:#?}");
    assert_eq!(lines[0]["decision"], "allow");
}

#[tokio::test]
async fn permitted_command_gets_allow() {
    let dir = tempfile::tempdir().unwrap();
    let (status, body) = post(&dir, &command_body("git", &[SHIM_GIT, "status"])).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body, serde_json::json!({"decision": "allow"}));
}

#[tokio::test]
async fn unpermitted_command_gets_deny_with_reason() {
    let dir = tempfile::tempdir().unwrap();
    let (status, body) = post(&dir, &command_body("curl", &[SHIM_CURL, "evil.example"])).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["decision"], "deny");
    assert!(body["reason"].as_str().unwrap().contains("no policy"));
}

/// The endpoint half of the wrong-allow matrix: a permit written the way the design
/// and the README write it (`path like "/repos/*"`) must not be satisfiable by a
/// traversal, and the deny nono records has to say *why*.
#[tokio::test]
async fn a_traversal_endpoint_path_gets_200_deny_naming_the_ambiguity() {
    let dir = tempfile::tempdir().unwrap();
    let (status, body) = post(&dir, &endpoint_body("p1", "/repos/../user/keys")).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["decision"], "deny", "{body}");
    let reason = body["reason"].as_str().unwrap();
    assert!(reason.contains("ambiguous endpoint path"), "{reason}");
    assert!(reason.contains("/repos/../user/keys"), "{reason}");

    // The same permit still decides an unambiguous path, so the guard has not simply
    // turned every endpoint approval into a deny.
    let (status, body) = post(&dir, &endpoint_body("p2", "/repos/foo/bar")).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body, serde_json::json!({"decision": "allow"}), "{body}");
}

/// A refused path is still a decision nono acts on, so it is on the record with the
/// path as sent — the audit trail is where an operator sees what was attempted.
#[tokio::test]
async fn an_ambiguous_endpoint_path_is_audited_with_the_raw_path() {
    let dir = tempfile::tempdir().unwrap();
    post(&dir, &endpoint_body("p1", "/repos/%2e%2e/user/keys")).await;
    let lines = audit_lines(&dir);
    assert_eq!(lines.len(), 1, "{lines:?}");
    assert_eq!(lines[0]["decision"], "deny");
    assert_eq!(lines[0]["matched"], serde_json::json!([]));
    assert!(
        lines[0]["resource"]
            .as_str()
            .unwrap()
            .contains("/repos/%2e%2e/user/keys"),
        "{}",
        lines[0]
    );
    assert!(
        lines[0]["reason"]
            .as_str()
            .unwrap()
            .contains("ambiguous endpoint path"),
        "{}",
        lines[0]
    );
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
    let _ = post(&dir, &command_body("git", &[SHIM_GIT, "status"])).await;
    let text = std::fs::read_to_string(dir.path().join("decisions.jsonl")).unwrap();
    assert_eq!(text.lines().count(), 1, "{text}");
    assert!(text.contains("\"decision\":\"allow\""));
}

/// "Which rule decided it" is the question the audit trail exists to answer, and
/// `eval_us` is the other half of the same line. Both are absent from every other
/// audit assertion in this repo: the unit test feeds a synthetic `Decision::deny`,
/// whose `matched` is empty and `eval_us` zero by construction, and the rejection
/// tests only ever see an empty `matched`. Dropping `matched` from `AuditRecord`
/// entirely would leave every one of those green.
#[tokio::test]
async fn the_audit_line_names_the_rule_that_decided_and_the_evaluation_time() {
    let dir = tempfile::tempdir().unwrap();
    let (_, body) = post(
        &dir,
        &command_body_with_request_id("decided", "git", &[SHIM_GIT, "status"]),
    )
    .await;
    assert_eq!(body, serde_json::json!({"decision": "allow"}));

    let lines = audit_lines(&dir);
    assert_eq!(lines.len(), 1, "{lines:#?}");
    let line = &lines[0];
    assert_eq!(line["request_id"], "decided");
    assert_eq!(line["decision"], "allow");
    assert_eq!(
        line["matched"],
        serde_json::json!(["p:allow-git-status"]),
        "the line must name the policy that permitted it: {line:#?}"
    );
    assert!(
        line["reason"]
            .as_str()
            .unwrap()
            .contains("p:allow-git-status"),
        "{line:#?}"
    );
    assert!(
        line["eval_us"].as_u64().is_some_and(|us| us > 0),
        "a real evaluation takes measurable time: {line:#?}"
    );
    assert_eq!(line["action"], "launchCommand");
    assert_eq!(line["principal"], "Nono::Caller::\"session\"");

    // A default deny is the other shape of the same field: nothing matched, so the
    // list is empty rather than missing, and the reason says why.
    let (_, body) = post(
        &dir,
        &command_body_with_request_id("undecided", "curl", &[SHIM_CURL, "evil.example"]),
    )
    .await;
    assert_eq!(body["decision"], "deny");
    let lines = audit_lines(&dir);
    assert_eq!(lines.len(), 2, "{lines:#?}");
    assert_eq!(
        lines[1]["matched"],
        serde_json::json!([]),
        "{:#?}",
        lines[1]
    );
    assert!(
        lines[1]["eval_us"].as_u64().is_some_and(|us| us > 0),
        "{:#?}",
        lines[1]
    );
}

/// Every `intercept_rule` shape real nono sends, driven through the full path —
/// HTTP parse → evaluate → audit — asserting the value reaches the audit line
/// byte-identically. The shapes are verified upstream facts, not guesses: in
/// nolabs-ai/nono `crates/nono-cli/src/tool-sandbox/policy.rs`,
/// `ResolvedInterceptAction::rule_label()` returns the matched rule's args joined
/// with spaces (upstream's own test asserts `"push --force"`), `"<catch-all>"` for
/// an empty-args rule, and `evaluate_invocation_policy` produces the labels
/// `invocation_policy.approve[<index>]` and `invocation_policy.default`. A corpus
/// that only ever sends single tokens cannot catch a consumer that assumes one
/// word.
#[tokio::test]
async fn every_real_intercept_rule_shape_survives_to_the_audit_line() {
    let dir = tempfile::tempdir().unwrap();
    let app = server::router(state(&dir));
    let shapes = [
        "status",                       // one rule arg
        "push --force",                 // args joined with spaces
        "<catch-all>",                  // the label of an empty-args rule
        "invocation_policy.approve[0]", // invocation-policy approve label
        "invocation_policy.default",    // invocation-policy default label
    ];
    for (index, rule) in shapes.iter().enumerate() {
        let (status, _) = post_to(
            &app,
            &command_body_with_rule(&format!("rule-{index}"), rule, "git", &[SHIM_GIT, "status"]),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{rule}");
    }

    let lines = audit_lines(&dir);
    assert_eq!(lines.len(), shapes.len(), "{lines:#?}");
    for (line, rule) in lines.iter().zip(shapes) {
        assert_eq!(
            line["intercept_rule"],
            serde_json::json!(rule),
            "the rule that routed the request must survive to the audit line \
             byte-identically: {line:#?}"
        );
        assert_eq!(line["child_pid"], 42, "{line:#?}");
        assert!(
            line.as_object().unwrap().contains_key("rule_label") && line["rule_label"].is_null(),
            "a command line carries rule_label as an explicit null: {line:#?}"
        );
    }
}

/// The endpoint half of the wire had no end-to-end coverage at all: the adapter and
/// the engine each had a unit test, but nothing posted an `endpoint` envelope to
/// `/v1/approve` and looked at what was recorded. `httpRequest` is the whole L7
/// surface — the credential proxy's decisions — so a break anywhere between the
/// router and the audit line would have gone unnoticed.
#[tokio::test]
async fn an_endpoint_envelope_is_decided_and_audited_over_http() {
    let dir = tempfile::tempdir().unwrap();
    let (status, body) = post(&dir, &endpoint_body("proxy-1", "/repos/foo/bar")).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body, serde_json::json!({"decision": "allow"}), "{body}");

    let lines = audit_lines(&dir);
    assert_eq!(lines.len(), 1, "{lines:#?}");
    let line = &lines[0];
    assert_eq!(line["request_id"], "proxy-1");
    assert_eq!(line["action"], "httpRequest");
    assert_eq!(line["decision"], "allow");
    assert_eq!(
        line["matched"],
        serde_json::json!(["p:allow-github-repo-reads"]),
        "{line:#?}"
    );
    // nono sends no session identity for an endpoint request, so the daemon pins
    // the proxy identity itself — and the audit line has to show that, not a
    // borrowed session.
    assert_eq!(line["session_id"], "proxy");
    assert_eq!(line["principal"], "Nono::Caller::\"proxy\"");
    assert_eq!(line["backend"], "cedar");
    assert_eq!(line["agent"], "claude-code");
    assert_eq!(
        line["resource"], "GET https://api.github.com/repos/foo/bar",
        "the line must say what was asked: {line:#?}"
    );
    assert!(
        line["eval_us"].as_u64().is_some_and(|us| us > 0),
        "{line:#?}"
    );
    // What routed the request here: the route rule label exactly as sent, the pid
    // exactly as the wire carried it (this body sends the 0 real nono hardcodes
    // for its proxy), and an explicitly null intercept_rule — the key set is
    // identical on every line kind.
    assert_eq!(
        line["rule_label"], "endpoint_policy.approve[GET /repos/*]",
        "the label must survive as sent: {line:#?}"
    );
    assert_eq!(line["child_pid"], 0, "{line:#?}");
    assert!(
        line.as_object().unwrap().contains_key("intercept_rule")
            && line["intercept_rule"].is_null(),
        "an endpoint line carries intercept_rule as an explicit null: {line:#?}"
    );

    // A method the permit does not cover is denied, so the permit is not a
    // blanket endpoint allow.
    let denied = serde_json::json!({
        "backend": "cedar",
        "request": {
            "capability_type": "endpoint",
            "request_id": "proxy-2",
            "route_id": "github-api",
            "upstream": "https://api.github.com",
            "method": "DELETE",
            "path": "/repos/foo/bar",
            "rule_label": "endpoint_policy.approve[DELETE /repos/*]",
            "reason": "route requires approval",
            "child_pid": 0,
            "session_id": "proxy"
        }
    })
    .to_string();
    let (status, body) = post(&dir, &denied).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["decision"], "deny", "{body}");
    let lines = audit_lines(&dir);
    assert_eq!(lines.len(), 2, "{lines:#?}");
    assert_eq!(lines[1]["action"], "httpRequest");
    assert_eq!(lines[1]["decision"], "deny");
    assert_eq!(
        lines[1]["matched"],
        serde_json::json!([]),
        "{:#?}",
        lines[1]
    );
}

/// Fidelity, not paraphrase: real nono hardcodes `child_pid: 0` for its proxy's
/// endpoint requests, but the audit line records what the wire actually carried.
/// The first implementation pinned `Some(0)` for endpoints, which *rewrote* the
/// claim rather than recording it — a sender asserting a pid must leave that
/// assertion on the record, where an investigator can see it (and see that it is
/// not what real nono sends).
#[tokio::test]
async fn an_endpoint_child_pid_is_recorded_as_sent_not_rewritten_to_zero() {
    let dir = tempfile::tempdir().unwrap();
    let body = serde_json::json!({
        "backend": "cedar",
        "request": {
            "capability_type": "endpoint",
            "request_id": "claimed-pid",
            "route_id": "github-api",
            "upstream": "https://api.github.com",
            "method": "GET",
            "path": "/repos/foo/bar",
            "rule_label": "endpoint_policy.approve[GET /repos/*]",
            "reason": "route requires approval",
            "child_pid": 7,
            "session_id": "proxy"
        }
    })
    .to_string();

    let (status, _) = post(&dir, &body).await;
    assert_eq!(status, StatusCode::OK);

    let lines = audit_lines(&dir);
    assert_eq!(lines.len(), 1, "{lines:#?}");
    assert_eq!(
        lines[0]["child_pid"], 7,
        "the wire claimed pid 7, so the line must record 7 — recording the claim, \
         not rewriting it to the 0 real nono would have sent: {:#?}",
        lines[0]
    );
}

/// Rotation happens to a *running* daemon: `logrotate` or an operator renames the
/// log while the process holds it open. Writes to the renamed inode keep
/// succeeding, so nothing errors — every later decision is answered and recorded
/// nowhere an operator can read, while `/healthz` stays green. One daemon, two
/// requests, a rename in between.
#[tokio::test]
async fn decisions_after_a_log_rotation_still_land_at_the_configured_path() {
    let dir = tempfile::tempdir().unwrap();
    let app = server::router(state(&dir));
    let path = dir.path().join("decisions.jsonl");
    let rotated = dir.path().join("decisions.jsonl.1");

    let (status, body) = post_to(
        &app,
        &command_body_with_request_id("before-rotation", "git", &[SHIM_GIT, "status"]),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["decision"], "allow");

    std::fs::rename(&path, &rotated).unwrap();

    let (status, body) = post_to(
        &app,
        &command_body_with_request_id("after-rotation", "git", &[SHIM_GIT, "status"]),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::OK,
        "an audit failure never changes a decision"
    );
    assert_eq!(body["decision"], "allow");

    let lines = audit_lines(&dir);
    assert_eq!(
        lines.len(),
        1,
        "the reopened log holds exactly the decision made after the rotation: {lines:#?}"
    );
    assert_eq!(lines[0]["request_id"], "after-rotation");

    let archived = std::fs::read_to_string(&rotated).unwrap();
    assert!(archived.contains("before-rotation"), "{archived:?}");
    assert!(
        !archived.contains("after-rotation"),
        "nothing may be appended to the detached inode: {archived:?}"
    );
}

/// An oversized body must be refused the same way every other unusable input is:
/// HTTP 200 with our own reason. Upstream maps any non-2xx to
/// `"approval webhook … returned HTTP {status}"`, which is exactly the generic
/// status outcome the contract exists to avoid — and axum's default extractor
/// limit produces a plain-text 413 with no audit line at all.
#[tokio::test]
async fn an_oversized_body_gets_200_deny_and_is_audited() {
    let dir = tempfile::tempdir().unwrap();
    let padding = "a".repeat(server::MAX_REQUEST_BYTES);
    let body = serde_json::json!({
        "backend": "cedar",
        "padding": padding,
        "request": {
            "capability_type": "command",
            "request_id": "r1",
            "command": "git",
            "args": [SHIM_GIT, "status"],
            "caller": "session",
            "intercept_rule": "rule",
            "reason": null,
            "child_pid": 42,
            "session_id": "s1"
        }
    })
    .to_string();
    assert!(body.len() > server::MAX_REQUEST_BYTES);

    let (status, body) = post(&dir, &body).await;
    assert_eq!(
        status,
        StatusCode::OK,
        "a 413 denies too, but nono then records only the HTTP status"
    );
    assert_eq!(body["decision"], "deny");
    assert!(
        body["reason"].as_str().unwrap().contains("limit"),
        "{body:#?}"
    );

    let lines = audit_lines(&dir);
    assert_eq!(lines.len(), 1, "{lines:#?}");
    assert_eq!(lines[0]["decision"], "deny");
}

/// The cap is generous on purpose: a long argv must never be mistaken for an
/// attack, so a body well inside the limit is still decided on its merits.
#[tokio::test]
async fn a_large_but_permitted_body_is_still_decided() {
    let dir = tempfile::tempdir().unwrap();
    let long_arg = "a".repeat(server::MAX_REQUEST_BYTES / 2);
    let body = command_body("git", &[SHIM_GIT, "status", &long_arg]);
    assert!(body.len() < server::MAX_REQUEST_BYTES);
    let (status, body) = post(&dir, &body).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["decision"], "allow");
}

/// A denial the caller receives but that leaves no audit line is a decision with
/// no reviewable record. The rejection paths — unsupported variant, malformed
/// body, oversized body — are exactly the ones a hostile caller controls.
#[tokio::test]
async fn rejected_requests_are_audited_too() {
    let dir = tempfile::tempdir().unwrap();

    let (_, allowed) = post(&dir, &command_body("git", &[SHIM_GIT, "status"])).await;
    let (_, policy_denied) = post(&dir, &command_body("curl", &[SHIM_CURL, "evil.example"])).await;
    let (_, unsupported) = post(&dir, &capability_body("cap-1")).await;
    let (_, malformed) = post(&dir, "{").await;

    assert_eq!(allowed["decision"], "allow");
    assert_eq!(policy_denied["decision"], "deny");
    assert_eq!(unsupported["decision"], "deny");
    assert_eq!(malformed["decision"], "deny");

    let lines = audit_lines(&dir);
    assert_eq!(
        lines.len(),
        4,
        "4 decisions were returned to the caller, so 4 audit lines must exist: {lines:#?}"
    );
    let decisions: Vec<&str> = lines
        .iter()
        .map(|l| l["decision"].as_str().unwrap())
        .collect();
    assert_eq!(decisions, vec!["allow", "deny", "deny", "deny"]);
}

/// The wire context of a rejected request is what makes its audit line
/// reviewable: a `capability` request carries `request_id`, `session_id` and the
/// backend even though the daemon refuses to evaluate it.
#[tokio::test]
async fn an_unsupported_variant_is_audited_with_its_wire_context() {
    let dir = tempfile::tempdir().unwrap();
    let (status, body) = post(&dir, &capability_body("cap-1")).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["decision"], "deny");

    let lines = audit_lines(&dir);
    assert_eq!(lines.len(), 1, "{lines:#?}");
    let line = &lines[0];
    assert_eq!(line["request_id"], "cap-1");
    assert_eq!(line["session_id"], "s1");
    assert_eq!(line["backend"], "cedar");
    assert_eq!(line["agent"], "claude-code");
    assert_eq!(line["decision"], "deny");
    assert!(
        line["reason"].as_str().unwrap().contains("unsupported"),
        "{line:#?}"
    );
    assert!(
        line["ts"].as_str().unwrap().contains('T'),
        "want an RFC 3339 timestamp: {line:#?}"
    );
    assert!(
        line["resource"]
            .as_str()
            .unwrap_or_default()
            .contains("capability"),
        "the refused variant is the only 'what was asked' we have: {line:#?}"
    );
}

/// A body that is not JSON at all yields no context — but the denial still has to
/// be on the record, with the fields it cannot fill left explicitly null.
#[tokio::test]
async fn a_malformed_body_is_audited_without_context() {
    let dir = tempfile::tempdir().unwrap();
    let (_, body) = post(&dir, "{not json").await;
    assert_eq!(body["decision"], "deny");

    let lines = audit_lines(&dir);
    assert_eq!(lines.len(), 1, "{lines:#?}");
    assert_eq!(lines[0]["decision"], "deny");
    assert!(lines[0]["request_id"].is_null(), "{:#?}", lines[0]);
    assert!(
        lines[0]["reason"].as_str().unwrap().contains("malformed"),
        "{:#?}",
        lines[0]
    );
    // The fixed key set holds on the rejection path too: nothing routed a request
    // that never parsed, so all three routing keys are explicit nulls, not absent.
    for key in ["child_pid", "intercept_rule", "rule_label"] {
        assert!(
            lines[0].as_object().unwrap().contains_key(key),
            "a rejected line must carry {key} as an explicit null: {:#?}",
            lines[0]
        );
        assert!(lines[0][key].is_null(), "{key}: {:#?}", lines[0]);
    }
}

/// Upstream builds `request_id` as `…-approve-{command}-{nanos}`, so the agent
/// picks part of it. Raw `ESC`/`CR` in an operator-facing log line lets a crafted
/// name erase and rewrite the decision an operator is reading.
#[tokio::test]
async fn logged_identifiers_carry_no_raw_control_bytes() {
    let hostile = "approve-git\u{1b}[2K\rINFO forged_line allow=true";
    let sink = CapturedLog::default();
    let subscriber = tracing_subscriber::fmt()
        .with_ansi(false)
        .with_writer(sink.clone())
        .finish();

    let dir = tempfile::tempdir().unwrap();
    let allowed = command_body_with_request_id(hostile, "git", &[SHIM_GIT, "status"]);
    let refused = capability_body(hostile);
    {
        let _guard = tracing::subscriber::set_default(subscriber);
        let _ = post(&dir, &allowed).await;
        let _ = post(&dir, &refused).await;
    }

    let text = sink.text();
    assert!(
        text.contains("approve-git"),
        "the decision must be logged at all: {text:?}"
    );
    assert!(
        !text.contains('\u{1b}'),
        "raw ESC reached the operator log: {text:?}"
    );
    assert!(
        !text.contains('\r'),
        "raw CR reached the operator log: {text:?}"
    );
    assert!(
        text.contains("\\u{001b}"),
        "the escape must be visible, not dropped: {text:?}"
    );
}

/// "Internal construction failure is denied" was covered only incidentally, by a
/// test written and named for ANSI injection: it asserted a deny and the absence of
/// control bytes, so the coverage rested on Cedar's uid escaping rather than on any
/// intention, and nothing asserted the *reason* names a construction failure or that
/// the error is logged. A well-formed payload the entity builder cannot use has to
/// deny like everything else it cannot evaluate — with our reason, on the record, and
/// visible to the operator.
#[tokio::test]
async fn a_payload_that_cannot_become_a_cedar_request_is_denied_and_logged() {
    // Well-formed JSON, valid wire shape, but a raw CR cannot appear in the Cedar
    // string literal the session entity's uid is built from.
    let body = serde_json::json!({
        "backend": "cedar",
        "request": {
            "capability_type": "command",
            "request_id": "unbuildable",
            "command": "git",
            "args": [SHIM_GIT, "status"],
            "caller": "session",
            "intercept_rule": "status",
            "reason": null,
            "child_pid": 42,
            "session_id": "s1\rINFO forged allow=true"
        }
    })
    .to_string();

    let sink = CapturedLog::default();
    let subscriber = tracing_subscriber::fmt()
        .with_ansi(false)
        .with_writer(sink.clone())
        .finish();

    let dir = tempfile::tempdir().unwrap();
    let (status, response) = {
        let _guard = tracing::subscriber::set_default(subscriber);
        post(&dir, &body).await
    };
    let logs = sink.text();

    assert_eq!(
        status,
        StatusCode::OK,
        "an internal failure must not propagate as an error to nono: {response}"
    );
    assert_eq!(response["decision"], "deny", "{response}");
    let reason = response["reason"].as_str().unwrap();
    assert!(
        reason.contains("could not build policy request"),
        "the reason must say the request could not be built, not imply a policy \
         refused it: {reason}"
    );
    assert!(
        !reason.chars().any(char::is_control),
        "the reason travels into nono's audit trail: {reason:?}"
    );
    assert!(
        logs.contains("failed to build cedar request"),
        "the operator must see the error that caused the deny: {logs:?}"
    );
    assert!(
        !logs.contains('\r'),
        "raw CR reached the operator log: {logs:?}"
    );

    let lines = audit_lines(&dir);
    assert_eq!(lines.len(), 1, "{lines:#?}");
    assert_eq!(lines[0]["request_id"], "unbuildable");
    assert_eq!(lines[0]["decision"], "deny");
    assert_eq!(
        lines[0]["matched"],
        serde_json::json!([]),
        "{:#?}",
        lines[0]
    );
    assert!(
        lines[0]["reason"]
            .as_str()
            .unwrap()
            .contains("could not build policy request"),
        "{:#?}",
        lines[0]
    );
}

/// A panic must reach nono as a definite HTTP failure, not as a dropped
/// connection it can only report as a transport error.
#[tokio::test]
async fn a_panicking_handler_becomes_an_error_response() {
    async fn boom() -> &'static str {
        panic!("handler panic")
    }

    let app = server::with_middleware(
        axum::Router::new()
            .route("/boom", axum::routing::get(boom))
            .route("/ok", axum::routing::get(|| async { "fine" })),
    );

    let response = app
        .clone()
        .oneshot(Request::builder().uri("/boom").body(Body::empty()).unwrap())
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::INTERNAL_SERVER_ERROR);

    let after = app
        .oneshot(Request::builder().uri("/ok").body(Body::empty()).unwrap())
        .await
        .unwrap();
    assert_eq!(
        after.status(),
        StatusCode::OK,
        "the daemon must stay available after a panic"
    );
}

/// `tracing` output captured into memory, so a test can assert what an operator
/// tailing the log would actually see.
#[derive(Clone, Default)]
struct CapturedLog(Arc<Mutex<Vec<u8>>>);

impl CapturedLog {
    fn text(&self) -> String {
        let guard = match self.0.lock() {
            Ok(guard) => guard,
            Err(poisoned) => poisoned.into_inner(),
        };
        String::from_utf8_lossy(&guard).to_string()
    }
}

impl std::io::Write for CapturedLog {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        let mut guard = match self.0.lock() {
            Ok(guard) => guard,
            Err(poisoned) => poisoned.into_inner(),
        };
        guard.extend_from_slice(buf);
        Ok(buf.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

impl<'a> tracing_subscriber::fmt::MakeWriter<'a> for CapturedLog {
    type Writer = CapturedLog;

    fn make_writer(&'a self) -> Self::Writer {
        self.clone()
    }
}

#[tokio::test]
async fn healthz_reports_the_loaded_generation() {
    let dir = tempfile::tempdir().unwrap();
    let app = server::router(state(&dir));
    let response = app
        .oneshot(
            Request::builder()
                .uri("/healthz")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let bytes = axum::body::to_bytes(response.into_body(), 8 * 1024)
        .await
        .unwrap();
    let json: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(json["generation"], 1);
    assert_eq!(json["policies"], 2, "{json}");
}
