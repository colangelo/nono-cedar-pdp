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
    let bytes = axum::body::to_bytes(response.into_body(), 64 * 1024)
        .await
        .unwrap();
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
