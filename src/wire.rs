//! Serde mirrors of nono's approval webhook contract (nono 0.69.x).
//!
//! Deliberately lenient: unknown fields are ignored so a nono upgrade cannot
//! brick every decision. Drift is caught by `tests/conformance.rs` instead.

use serde::{Deserialize, Serialize};

/// The shape `args[0]` really has on the wire: an absolute **per-run** shim path,
/// not the command name. Verbatim from an audit line of the end-to-end smoke run
/// (`<base>/nono-tool-sandbox-<pid>-<unix nanos>-<hex nonce>/shims/<command>`).
///
/// Exported so every fixture and test asserts the runtime shape. The `["git",
/// "push"]` shape this project used to model came from upstream's *unit-test*
/// fixture (`crates/nono/src/supervisor/mod.rs:209-217`) and never reaches a
/// webhook; a suite built on it green-lit start-anchored patterns that cannot
/// match in production.
pub const EXAMPLE_SHIM_ARGV0: &str =
    "/private/tmp/nono-tool-sandbox-13819-1784990893285791000-a4d3bceb3ec061c0/shims/git";

#[derive(Debug, Clone, Deserialize)]
pub struct WebhookEnvelope {
    pub backend: String,
    pub request: ApprovalRequest,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(tag = "capability_type", rename_all = "snake_case")]
pub enum ApprovalRequest {
    Command(CommandRequest),
    Endpoint(EndpointRequest),
    /// `capability` and `network` variants cannot reach a webhook backend in
    /// nono 0.69, but anything upstream adds must fail closed rather than fail
    /// to parse.
    #[serde(other)]
    Unsupported,
}

#[derive(Debug, Clone, Deserialize)]
pub struct CommandRequest {
    pub request_id: String,
    pub command: String,
    /// Includes argv[0]. Upstream drops non-UTF-8 entries, so positions shift:
    /// never match on index.
    pub args: Vec<String>,
    /// `"session"` for a direct agent launch, otherwise the intercepted command
    /// that chained this one.
    pub caller: String,
    pub intercept_rule: String,
    #[serde(default)]
    pub reason: Option<String>,
    pub child_pid: u32,
    pub session_id: String,
}

#[derive(Debug, Clone, Deserialize)]
pub struct EndpointRequest {
    pub request_id: String,
    pub route_id: String,
    pub upstream: String,
    pub method: String,
    pub path: String,
    pub rule_label: String,
    #[serde(default)]
    pub reason: Option<String>,
    /// Always 0 — the proxy has no child pid.
    pub child_pid: u32,
    /// Always `"proxy"` — endpoint requests carry no session identity.
    pub session_id: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(tag = "decision", rename_all = "lowercase")]
pub enum WebhookResponse {
    Allow,
    Deny { reason: String },
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::panic)]
mod tests {
    use super::*;

    /// `args[0]` is the per-run shim path nono really sends, not the command
    /// name — see `EXAMPLE_SHIM_ARGV0`.
    const REAL_COMMAND: &str = r#"{"backend":"cedar","request":{
        "capability_type":"command","request_id":"r1","command":"git",
        "args":["/private/tmp/nono-tool-sandbox-13819-1784990893285791000-a4d3bceb3ec061c0/shims/git","push"],
        "caller":"session","intercept_rule":"push",
        "reason":null,"child_pid":42,"session_id":"s1"}}"#;

    const REAL_ENDPOINT: &str = r#"{"backend":"cedar","request":{
        "capability_type":"endpoint","request_id":"p-1","route_id":"github-api",
        "upstream":"https://api.github.com","method":"GET","path":"/repos/foo/bar",
        "rule_label":"endpoint_policy.approve[GET /repos/*]",
        "reason":"route requires approval","child_pid":0,"session_id":"proxy"}}"#;

    #[test]
    fn parses_real_command_envelope() {
        let env: WebhookEnvelope = serde_json::from_str(REAL_COMMAND).unwrap();
        assert_eq!(env.backend, "cedar");
        let ApprovalRequest::Command(c) = env.request else {
            panic!("expected command variant");
        };
        assert_eq!(c.command, "git");
        assert_eq!(c.args, vec![EXAMPLE_SHIM_ARGV0, "push"]);
        assert_eq!(c.caller, "session");
        assert_eq!(c.child_pid, 42);
        assert_eq!(c.reason, None);
    }

    #[test]
    fn parses_real_endpoint_envelope() {
        let env: WebhookEnvelope = serde_json::from_str(REAL_ENDPOINT).unwrap();
        let ApprovalRequest::Endpoint(e) = env.request else {
            panic!("expected endpoint variant");
        };
        assert_eq!(e.method, "GET");
        assert_eq!(e.session_id, "proxy");
        assert_eq!(e.child_pid, 0);
        assert_eq!(e.reason.as_deref(), Some("route requires approval"));
    }

    #[test]
    fn unknown_variant_maps_to_unsupported() {
        let body = r#"{"backend":"cedar","request":{"capability_type":"capability",
            "request_id":"c1","path":"/etc/passwd","access":"read","reason":null,
            "child_pid":7,"session_id":"s1"}}"#;
        let env: WebhookEnvelope = serde_json::from_str(body).unwrap();
        assert!(matches!(env.request, ApprovalRequest::Unsupported));
    }

    #[test]
    fn tolerates_unknown_fields_added_upstream() {
        let body = r#"{"backend":"cedar","extra_envelope":1,"request":{
            "capability_type":"command","request_id":"r1","command":"git","args":[],
            "caller":"session","intercept_rule":"x","reason":null,"child_pid":1,
            "session_id":"s1","future_field":"whatever"}}"#;
        let env: WebhookEnvelope = serde_json::from_str(body).unwrap();
        assert!(matches!(env.request, ApprovalRequest::Command(_)));
    }

    #[test]
    fn response_serializes_to_nono_friendly_shape() {
        assert_eq!(
            serde_json::to_string(&WebhookResponse::Allow).unwrap(),
            r#"{"decision":"allow"}"#
        );
        assert_eq!(
            serde_json::to_string(&WebhookResponse::Deny {
                reason: "nope".into()
            })
            .unwrap(),
            r#"{"decision":"deny","reason":"nope"}"#
        );
    }
}
