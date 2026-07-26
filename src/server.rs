//! HTTP surface. Deliberately thin: every decision is made below this layer.
//!
//! `/v1/approve` reads the body itself rather than through `Json<T>` or `Bytes`
//! because every unusable body — malformed, unsupported, oversized — must produce
//! a `200 {"decision":"deny"}` carrying our own reason. nono records the reason
//! we hand back; for any non-2xx it records only `returned HTTP <status>`.
//!
//! # The header gate, and why both halves of it exist
//!
//! The webhook carries no credential, so nothing here identifies the caller — and
//! nothing here claims to. What the gate does is refuse requests whose *shape* proves
//! they did not come from nono's client, before the body is read.
//!
//! **`Content-Type: application/json` is the load-bearing control, not a formality.**
//! The CORS "simple request" exemption — the one that needs no preflight — permits
//! only `text/plain`, `application/x-www-form-urlencoded` and `multipart/form-data`.
//! To send `application/json` cross-origin a browser must first preflight with
//! `OPTIONS`; this service serves no CORS headers and no `OPTIONS` route, so the
//! preflight fails and the POST is never issued. **Requiring JSON is therefore what
//! closes the only vector that does not already require local code execution: a page
//! the operator merely visits.** Relaxing it to "accept anything" reopens that vector
//! silently, because every unit test about *bodies* would keep passing.
//!
//! **`Origin` is refused independently, and the redundancy is the point.** nono never
//! sends `Origin`; a browser-issued cross-origin request always does. Today the check
//! is redundant with the content-type one — but if a future nono changed its
//! content-type, that check would have to be relaxed and this one would still hold.
//! Two independent controls, neither load-bearing alone; do not collapse them.
//!
//! Neither check authenticates nono. A local process running as the same user
//! presents a correct content-type and no `Origin` trivially, and can therefore still
//! forge an audit record. That residual is inherent while the webhook carries no
//! credential; closing it needs an upstream bearer token or a unix socket.

use crate::adapter::nono_webhook::RejectedContext;
use crate::audit::AuditLog;
use crate::cedar::engine::Engine;
use crate::config::Config;
use crate::decision::Decision;
use axum::body::Body;
use axum::extract::{DefaultBodyLimit, State};
use axum::http::header::{HeaderMap, HeaderName, CONTENT_TYPE, ORIGIN, USER_AGENT};
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

/// The `Content-Type` nono's webhook client sends, verified against nono 0.69.0
/// (`crates/nono-cli/src/approval_runtime.rs`).
const NONO_CONTENT_TYPE: &str = "application/json";

/// Whether a `Content-Type` value describes the JSON body nono's webhook client
/// posts. `None` is an absent header, which is a refusal: nono always sends one.
///
/// Media-type parameters are tolerated (`application/json; charset=utf-8`) because
/// the essence is the type and a future client may add a charset, and the type is
/// compared case-insensitively per RFC 9110 §8.3.1. Public so
/// `tests/conformance.rs` can pin the gate against the upstream literal and against
/// the three types a CORS-simple cross-origin POST may carry, without standing up a
/// router.
pub fn is_json_content_type(value: Option<&str>) -> bool {
    let Some(value) = value else {
        return false;
    };
    // `split(';')` always yields at least one item, so the default is unreachable;
    // it exists because `unwrap` is denied outside tests.
    let media_type = value.split(';').next().unwrap_or("").trim();
    media_type.eq_ignore_ascii_case(NONO_CONTENT_TYPE)
}

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
    /// The most recent reload attempt, written by the watcher through
    /// `watcher::Provenance` — the same call that writes the audit record, so the
    /// health surface and the trail cannot disagree about it. `None` until a reload
    /// has been attempted.
    pub last_reload: Arc<arc_swap::ArcSwapOption<crate::watcher::LastReload>>,
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

/// The value of `name` as the caller sent it, lossily decoded.
///
/// Lossy UTF-8 rather than `HeaderValue::to_str`, which accepts only visible ASCII: a
/// header value carrying a C1 control (`0xC2 0x9B`, CSI) passes hyper's parser, and
/// collapsing such a value to `None` would hide exactly the request an investigator
/// most wants to see. Not escaped here — each destination escapes at its own boundary
/// (the audit record in [`crate::audit`], the WARN lines below), so no caller can
/// receive a value that has been quietly rewritten.
fn observed(headers: &HeaderMap, name: HeaderName) -> Option<String> {
    headers
        .get(name)
        .map(|value| String::from_utf8_lossy(value.as_bytes()).into_owned())
}

/// Refuse a request whose shape proves it did not come from nono's webhook client.
/// Runs before the body is read and before anything is recorded; see the module docs
/// for why each of the two checks exists and why neither may be dropped.
///
/// **A 4xx here does not violate "deny and broken are different signals."** That rule
/// covers *decision-shaped* failures: a malformed or oversized body is a question nono
/// asked, so it gets a `200` with our deny reason, because nono records our reason and
/// reduces any non-2xx to a bare `returned HTTP <status>`. A request that fails this
/// gate is the third case — **it was not a question nono asked**. There is no nono
/// waiting on a reason, so none is owed, and no audit line claiming a decision may be
/// written: doing so would recreate the unauthenticated audit-record injection this
/// gate closes, differing only in the label on the line. The refusal body is
/// deliberately *not* decision-shaped for the same reason.
///
/// Both refusals are logged at WARN with the observed values control-escaped, so an
/// operator can see the endpoint being probed.
///
/// Returns the refusal to send back, or `None` when the request may proceed. (An
/// `Option`, not a `Result`: the success case carries nothing, and a `Result` whose
/// error is a whole `Response` trips `clippy::result_large_err`.)
fn header_gate(headers: &HeaderMap) -> Option<Response> {
    let content_type = observed(headers, CONTENT_TYPE);
    let user_agent = observed(headers, USER_AGENT);
    // Header text is caller-chosen and lands in an operator's terminal, so it is
    // escaped here exactly like every other request-derived value we log.
    let escaped = |value: Option<&String>| {
        value
            .map(|value| crate::sanitize::control_escape(value))
            .unwrap_or_else(|| UNKNOWN.to_string())
    };

    if !is_json_content_type(content_type.as_deref()) {
        tracing::warn!(
            content_type = %escaped(content_type.as_ref()),
            user_agent = %escaped(user_agent.as_ref()),
            "refusing a request whose content-type is not application/json: \
             nono's webhook client always sends it, so this did not come from nono"
        );
        return Some(
            (
                StatusCode::UNSUPPORTED_MEDIA_TYPE,
                Json(serde_json::json!({
                    "error": format!("this endpoint requires Content-Type: {NONO_CONTENT_TYPE}"),
                })),
            )
                .into_response(),
        );
    }

    // Checked independently of the content-type above, on purpose (module docs): a
    // correct content-type must not excuse an `Origin`.
    if let Some(origin) = observed(headers, ORIGIN) {
        tracing::warn!(
            origin = %crate::sanitize::control_escape(&origin),
            content_type = %escaped(content_type.as_ref()),
            user_agent = %escaped(user_agent.as_ref()),
            "refusing a request carrying an Origin header: nono never sends one and \
             a browser always does"
        );
        return Some(
            (
                StatusCode::FORBIDDEN,
                Json(serde_json::json!({
                    "error": "this endpoint refuses requests carrying an Origin header",
                })),
            )
                .into_response(),
        );
    }

    None
}

async fn approve(State(state): State<AppState>, headers: HeaderMap, body: Body) -> Response {
    // First, before the body is read and before any audit line exists: a request that
    // cannot have come from nono is not a decision to make, and recording it would be
    // the injection the gate closes.
    if let Some(refusal) = header_gate(&headers) {
        return refusal;
    }
    // Recorded on every line below as evidence and trusted for nothing — see
    // `AuditRecord::user_agent`.
    let user_agent = observed(&headers, USER_AGENT);

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
            state.audit.record_rejected(
                &RejectedContext::default(),
                &decision,
                user_agent.as_deref(),
            );
            // Safe at the default level, unlike the parse failure below: this `e` is
            // axum's body error — a length-limit refusal or a transport failure — so it
            // describes how reading stopped and cannot quote bytes from a body that was
            // never parsed. Escaped anyway, since it is still not ours.
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
            state
                .audit
                .record_rejected(&context, &decision, user_agent.as_deref());
            // The cause, not the content. serde's error text quotes the offending
            // value verbatim — `invalid type: string "…", expected a sequence` — and
            // that value came off the wire, so putting it here would leak an argv
            // fragment to stdout at the default level through a field called `error`
            // rather than one called `resource`. `deny_reason()` is one of our own
            // fixed strings, so it names what went wrong without echoing what was
            // sent. The full text is one event below, at DEBUG.
            tracing::warn!(
                cause = %decision.reason,
                request_id = context.request_id.as_deref().unwrap_or(UNKNOWN),
                session_id = context.session_id.as_deref().unwrap_or(UNKNOWN),
                backend = context.backend.as_deref().unwrap_or(UNKNOWN),
                capability_type = context.capability_type.as_deref().unwrap_or(UNKNOWN),
                "rejecting approval request"
            );
            tracing::debug!(
                request_id = context.request_id.as_deref().unwrap_or(UNKNOWN),
                error = %crate::sanitize::control_escape(&e.to_string()),
                "approval request parse failure detail"
            );
            return (StatusCode::OK, Json(decision.to_wire())).into_response();
        }
    };

    let decision = state.engine.evaluate(&query);
    state.audit.record(&query, &decision, user_agent.as_deref());
    // Upstream builds `request_id` from the intercepted command name, so an agent
    // chooses part of it: escape before it reaches an operator's terminal, where a
    // raw ESC/CR would rewrite the line being read.
    let request_id = crate::sanitize::control_escape(&query.request_id);
    // Telemetry, not the decision record. stdout goes wherever the operator
    // redirected it — a shared journal, a log aggregator, terminal scrollback — none
    // of which inherit the audit log's 0600, so this line carries the identifiers and
    // the outcome and nothing request-derived beyond them. The audit log is
    // unchanged and remains the complete record: the detail is relocated, not lost.
    tracing::info!(
        request_id = %request_id,
        session_id = %crate::sanitize::control_escape(&query.session_id),
        backend = %crate::sanitize::control_escape(&query.backend),
        action = query.action_name(),
        allow = decision.allow,
        matched = ?decision.matched,
        eval_us = decision.eval_us,
        "decision"
    );
    // A *separate* event rather than one more field above, because `tracing` fields
    // are fixed per event: the resource summary — the command line an agent
    // attempted, or the API path it requested — is the first thing wanted when a
    // policy will not match, so it stays available, but only when an operator opts
    // in. It repeats `request_id` on purpose: without it this cannot be joined to
    // the decision line above, and joining is what makes relocating the detail
    // costless.
    tracing::debug!(
        request_id = %request_id,
        resource = %query.resource_summary(),
        "decision detail"
    );

    (StatusCode::OK, Json(decision.to_wire())).into_response()
}

/// The health surface: "is this daemon serving what you think it is".
///
/// **No path, and no reload-error text.** This endpoint is unauthenticated like
/// everything on the loopback listener, and the absolute policy directory is
/// precisely the target of the policy-rewrite escalation the isolation checks exist
/// to close — it used to be reported here. A reload error names the file it failed
/// on, so carrying one would give the same thing away by another route; the outcome
/// says *that* a reload was refused and the audit trail's `policy-set` record says
/// *what*, from behind filesystem permissions. Reducing the path to a basename or a
/// hash is not a fix: the set of real policy directory paths is small and
/// enumerable, so neither withholds it from a local attacker while both read as
/// though they do.
///
/// **A failed reload does not make this 503.** Such a daemon is healthy: it answers
/// correctly from the last-known-good set, which is the designed behaviour. 503
/// invites an orchestrator to restart it, and a restart re-runs the *bootstrap* load
/// against the same broken directory, fails startup and exits — after which nono
/// gets connection refused and fails closed on everything. The remedy would be far
/// worse than the condition, and would fire exactly when an operator has mistyped a
/// policy file. Monitoring keys on `last_reload.outcome`, not on the status code.
/// Zero policies stays 503 because that daemon really is not serving: it denies
/// everything.
async fn healthz(State(state): State<AppState>) -> Response {
    let snapshot = state.engine.snapshot();
    let count = snapshot.set.num_of_policies();
    let body = serde_json::json!({
        "generation": snapshot.generation,
        "policies": count,
        "loaded_at": rfc3339(snapshot.loaded_at),
        "last_reload": state.last_reload.load().as_deref(),
    });
    let status = if count == 0 {
        StatusCode::SERVICE_UNAVAILABLE
    } else {
        StatusCode::OK
    };
    (status, Json(body)).into_response()
}

/// A `SystemTime` as RFC 3339 UTC, or `null` for a clock before the epoch — which
/// is not a reason to fail a health check.
fn rfc3339(t: std::time::SystemTime) -> Option<String> {
    let unix = t.duration_since(std::time::UNIX_EPOCH).ok()?;
    let odt = time::OffsetDateTime::from_unix_timestamp_nanos(unix.as_nanos() as i128).ok()?;
    odt.format(&time::format_description::well_known::Rfc3339)
        .ok()
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
            content_hash: "sha256:test-fixture".to_string(),
        };
        let engine = Engine::from_loaded_unchecked(
            crate::cedar::schema::load().unwrap(),
            config.policy_dir.clone(),
            empty,
        );
        AppState {
            last_reload: Arc::new(arc_swap::ArcSwapOption::empty()),
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
