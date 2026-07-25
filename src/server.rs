//! HTTP surface. Deliberately thin: every decision is made below this layer.
//!
//! `/v1/approve` reads the body itself rather than through `Json<T>` or `Bytes`
//! because every unusable body — malformed, unsupported, oversized — must produce
//! a `200 {"decision":"deny"}` carrying our own reason. nono records the reason
//! we hand back; for any non-2xx it records only `returned HTTP <status>`.

use crate::adapter::nono_webhook::RejectedContext;
use crate::audit::AuditLog;
use crate::cedar::engine::Engine;
use crate::config::Config;
use crate::decision::Decision;
use axum::body::Body;
use axum::extract::{DefaultBodyLimit, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use std::net::SocketAddr;
use std::sync::Arc;
use tower_http::catch_panic::CatchPanicLayer;

/// Placeholder for a log field the refused body did not carry. `tracing` has no
/// null, and an empty value reads as "we forgot to log it".
const UNKNOWN: &str = "-";

/// Largest approval body the daemon will buffer.
///
/// Explicit, not inherited from axum's default extractor limit: the threshold
/// that decides whether nono records our reason or a bare `413` must not move on
/// a dependency bump. Generous next to a real envelope (a few hundred bytes) so
/// that a long argv is never mistaken for an attack.
pub const MAX_REQUEST_BYTES: usize = 1024 * 1024;

#[derive(Clone)]
pub struct AppState {
    pub engine: Arc<Engine>,
    pub config: Arc<Config>,
    pub audit: Arc<AuditLog>,
}

pub fn router(state: AppState) -> Router {
    with_middleware(
        Router::new()
            .route("/v1/approve", post(approve))
            .route("/healthz", get(healthz))
            // Belt and braces: `approve` enforces MAX_REQUEST_BYTES itself, but if
            // a later refactor reaches for `Bytes` or `Json<T>` this keeps the
            // limit ours rather than axum's default.
            .layer(DefaultBodyLimit::max(MAX_REQUEST_BYTES))
            .with_state(state),
    )
}

/// The middleware every route runs behind. Separate from [`router`] so a test can
/// prove a panicking handler becomes a 5xx instead of a dropped connection —
/// nono must record a definite failure, not an opaque transport error.
pub fn with_middleware(router: Router) -> Router {
    router.layer(CatchPanicLayer::new())
}

async fn approve(State(state): State<AppState>, body: Body) -> Response {
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

    let body = match axum::body::to_bytes(body, MAX_REQUEST_BYTES).await {
        Ok(bytes) => bytes,
        Err(e) => {
            // No context at all: the body was never readable. Still a decision the
            // caller acts on, so still one audit line.
            let decision = Decision::deny(format!(
                "approval request body was unreadable or above the \
                 {MAX_REQUEST_BYTES}-byte limit; failing closed"
            ));
            state
                .audit
                .record_rejected(&RejectedContext::default(), &decision);
            tracing::warn!(
                error = %crate::sanitize::control_escape(&e.to_string()),
                limit = MAX_REQUEST_BYTES,
                "refusing an unreadable or oversized approval request"
            );
            return (StatusCode::OK, Json(decision.to_wire())).into_response();
        }
    };

    let query = match crate::adapter::nono_webhook::parse(&body, &state.config) {
        Ok(query) => query,
        Err(e) => {
            // A denial the caller acts on is a decision, so it goes on the record
            // with whatever context the refused body still yields.
            let context = crate::adapter::nono_webhook::scrape_context(&body, &state.config);
            let decision = Decision::deny(e.deny_reason());
            state.audit.record_rejected(&context, &decision);
            tracing::warn!(
                // Cedar and serde error text can quote request-supplied values.
                error = %crate::sanitize::control_escape(&e.to_string()),
                request_id = context.request_id.as_deref().unwrap_or(UNKNOWN),
                session_id = context.session_id.as_deref().unwrap_or(UNKNOWN),
                backend = context.backend.as_deref().unwrap_or(UNKNOWN),
                capability_type = context.capability_type.as_deref().unwrap_or(UNKNOWN),
                "rejecting approval request"
            );
            return (StatusCode::OK, Json(decision.to_wire())).into_response();
        }
    };

    let decision = state.engine.evaluate(&query);
    state.audit.record(&query, &decision);
    tracing::info!(
        // Upstream builds `request_id` from the intercepted command name, so an
        // agent chooses part of it: escape before it reaches an operator's
        // terminal, where a raw ESC/CR would rewrite the line being read.
        request_id = %crate::sanitize::control_escape(&query.request_id),
        session_id = %crate::sanitize::control_escape(&query.session_id),
        backend = %crate::sanitize::control_escape(&query.backend),
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

/// The fail-closed matrix is exercised over HTTP in `tests/server.rs`. What lives
/// here is the one branch that cannot be driven from outside the crate: the
/// zero-policy 503. Reaching it needs an `Engine` built past the load guards, and
/// that constructor is `#[cfg(test)]` precisely so a daemon cannot be built that way
/// (see [`crate::cedar::engine::Engine::from_loaded_unchecked`]).
#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use tower::ServiceExt;

    /// A policy set no loader can produce: `bootstrap`, `from_policy_set` and
    /// `reload` all refuse it.
    fn unavailable_state(dir: &tempfile::TempDir) -> AppState {
        let mut agents = std::collections::BTreeMap::new();
        agents.insert("cedar".to_string(), "claude-code".to_string());
        let config = Config {
            bind: "127.0.0.1:0".parse().unwrap(),
            policy_dir: dir.path().to_path_buf(),
            audit_log: dir.path().join("decisions.jsonl"),
            agents,
        };
        let empty = crate::cedar::engine::LoadedPolicies {
            set: cedar_policy::PolicySet::new(),
            generation: 0,
            loaded_at: std::time::SystemTime::now(),
            files: Vec::new(),
        };
        let engine = Engine::from_loaded_unchecked(
            crate::cedar::schema::load().unwrap(),
            config.policy_dir.clone(),
            empty,
        );
        AppState {
            engine: Arc::new(engine),
            audit: Arc::new(AuditLog::open(&config.audit_log).unwrap()),
            config: Arc::new(config),
        }
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
                "intercept_rule": "status",
                "reason": null,
                "child_pid": 42,
                "session_id": "s1"
            }
        })
        .to_string()
    }

    /// A denial says "policy refused this". A 503 says "the decider is broken, do
    /// not treat my answer as a policy decision". Collapsing the second into the
    /// first is how a misconfigured PDP silently becomes a deny-everything one.
    #[tokio::test]
    async fn a_daemon_with_no_policies_reports_unavailable() {
        let dir = tempfile::tempdir().unwrap();

        let health = router(unavailable_state(&dir))
            .oneshot(
                axum::http::Request::builder()
                    .uri("/healthz")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(health.status(), StatusCode::SERVICE_UNAVAILABLE);
        let bytes = axum::body::to_bytes(health.into_body(), 8 * 1024)
            .await
            .unwrap();
        let json: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(json["policies"], 0);

        let approve = router(unavailable_state(&dir))
            .oneshot(
                axum::http::Request::builder()
                    .method("POST")
                    .uri("/v1/approve")
                    .header("content-type", "application/json")
                    .body(Body::from(command_body(
                        "git",
                        &[crate::wire::EXAMPLE_SHIM_ARGV0, "status"],
                    )))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(approve.status(), StatusCode::SERVICE_UNAVAILABLE);
        let bytes = axum::body::to_bytes(approve.into_body(), 8 * 1024)
            .await
            .unwrap();
        let json: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        assert!(
            json["decision"].is_null(),
            "a broken decider must not look like a policy denial: {json}"
        );
    }
}
