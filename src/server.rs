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
