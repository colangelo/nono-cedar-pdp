//! The fail-closed matrix from the spec, exercised over HTTP.
#![allow(clippy::unwrap_used, clippy::panic)]

use axum::body::Body;
use axum::http::{Request, StatusCode};
use nono_cedar_pdp::{audit::AuditLog, cedar, config::Config, server};
use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};
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
    serde_json::json!({
        "backend": "cedar",
        "request": {
            "capability_type": "command",
            "request_id": request_id,
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

/// A `capability` approval request: a variant the daemon refuses to evaluate,
/// but one that still carries full identifying context on the wire.
fn capability_body(request_id: &str) -> String {
    serde_json::json!({
        "backend": "cedar",
        "request": {
            "capability_type": "capability",
            "request_id": request_id,
            "path": "/Users/ac/.ssh/id_ed25519",
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
            "args": ["git", "status"],
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
    let body = command_body("git", &["git", "status", &long_arg]);
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

    let (_, allowed) = post(&dir, &command_body("git", &["git", "status"])).await;
    let (_, policy_denied) = post(&dir, &command_body("curl", &["curl", "evil.example"])).await;
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
    let allowed = command_body_with_request_id(hostile, "git", &["git", "status"]);
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
    assert_eq!(json["policies"], 1);
}
