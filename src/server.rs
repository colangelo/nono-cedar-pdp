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

/// Placeholder for a log field the refused body did not carry. `tracing` has no
/// null, and an empty value reads as "we forgot to log it".
const UNKNOWN: &str = "-";

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
