//! Adapter for nono's `WebhookApproval` backend (nono 0.69.x).

use crate::config::Config;
use crate::query::{CallerKind, PolicyQuery, Target};
use crate::wire::{ApprovalRequest, WebhookEnvelope};

/// Caller and session id used for `endpoint` approvals, which carry no session
/// identity of their own (spec: `Nono::Caller::"proxy"` in `Nono::Session::"proxy"`).
const PROXY_IDENTITY: &str = "proxy";

#[derive(Debug, thiserror::Error)]
pub enum AdaptError {
    #[error("malformed approval request: {0}")]
    Malformed(#[from] serde_json::Error),
    #[error("unsupported approval request variant")]
    UnsupportedVariant,
}

impl AdaptError {
    /// The `reason` string handed back to nono on the deny path.
    pub fn deny_reason(&self) -> String {
        match self {
            AdaptError::Malformed(_) => {
                "malformed approval request body; failing closed".to_string()
            }
            AdaptError::UnsupportedVariant => {
                "unsupported approval request variant; failing closed".to_string()
            }
        }
    }
}

/// What is still known about a request the daemon refused to evaluate.
///
/// A denial produced by a malformed or unsupported body is still a decision the
/// caller acts on, so it needs an audit line (`decision-audit-log`: "including
/// denials produced by malformed or unsupported input where a request context is
/// available"). `ApprovalRequest::Unsupported` cannot carry that context —
/// serde's `#[serde(other)]` only accepts a unit variant — so it is scraped
/// separately. Every field is optional: the body may be truncated, oversized, or
/// not JSON at all.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct RejectedContext {
    pub backend: Option<String>,
    /// Resolved from `backend` through the config's agent map, so a rejected
    /// line names the same agent a decided line would.
    pub agent: Option<String>,
    pub capability_type: Option<String>,
    pub request_id: Option<String>,
    pub session_id: Option<String>,
}

/// Best-effort scrape of the identifying fields of a body we would not evaluate.
///
/// Never fails and never partially parses into something a policy could see:
/// the result is audit-and-log material only. Values are control-escaped here,
/// at the single point they enter the daemon, because everything downstream
/// (log lines, the JSONL trail) is read by an operator.
pub fn scrape_context(body: &[u8], config: &Config) -> RejectedContext {
    let Ok(value) = serde_json::from_slice::<serde_json::Value>(body) else {
        return RejectedContext::default();
    };
    let text = |parent: &serde_json::Value, key: &str| -> Option<String> {
        parent
            .get(key)?
            .as_str()
            .map(crate::sanitize::control_escape)
    };
    let backend = text(&value, "backend");
    let agent = backend
        .as_deref()
        .map(|backend| config.agent_for(backend).to_string());
    let request = value.get("request");
    RejectedContext {
        backend,
        agent,
        capability_type: request.and_then(|r| text(r, "capability_type")),
        request_id: request.and_then(|r| text(r, "request_id")),
        session_id: request.and_then(|r| text(r, "session_id")),
    }
}

pub fn parse(body: &[u8], config: &Config) -> Result<PolicyQuery, AdaptError> {
    let envelope: WebhookEnvelope = serde_json::from_slice(body)?;
    let agent = config.agent_for(&envelope.backend).to_string();

    match envelope.request {
        ApprovalRequest::Command(c) => {
            // nono sends the caller *label*, not a caller kind: `"session"` for a
            // direct agent launch, otherwise the intercepted command's name
            // (upstream `caller_label()`). The match is deliberately exact, so no
            // near-miss label widens into `Session`. Known v1 limitation: a
            // profile that intercepts a command literally named `session`
            // produces a payload indistinguishable from a direct launch;
            // disambiguating needs a distinct kind field upstream.
            let caller_kind = if c.caller == "session" {
                CallerKind::Session
            } else {
                CallerKind::Command
            };
            Ok(PolicyQuery {
                agent,
                session_id: c.session_id,
                caller: c.caller,
                caller_kind,
                request_id: c.request_id,
                backend: envelope.backend,
                reason: c.reason,
                target: Target::Command {
                    command: c.command,
                    args: c.args,
                    intercept_rule: c.intercept_rule,
                    child_pid: c.child_pid,
                },
            })
        }
        ApprovalRequest::Endpoint(e) => Ok(PolicyQuery {
            agent,
            // Endpoint approvals carry no session identity: nono's proxy
            // hardcodes `session_id: "proxy"`. Pin both halves of the identity
            // rather than echoing the wire value, so a payload claiming a real
            // session id cannot place the proxy caller inside that session's
            // hierarchy and satisfy session-scoped policy.
            session_id: PROXY_IDENTITY.to_string(),
            caller: PROXY_IDENTITY.to_string(),
            caller_kind: CallerKind::Session,
            request_id: e.request_id,
            backend: envelope.backend,
            reason: e.reason,
            target: Target::Endpoint {
                route_id: e.route_id,
                upstream: e.upstream,
                method: e.method,
                path: e.path,
                rule_label: e.rule_label,
            },
        }),
        ApprovalRequest::Unsupported => Err(AdaptError::UnsupportedVariant),
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::panic)]
mod tests {
    use super::*;
    use crate::query::{CallerKind, Target};
    use std::collections::BTreeMap;

    fn config() -> crate::config::Config {
        let mut agents = BTreeMap::new();
        agents.insert("cedar".to_string(), "claude-code".to_string());
        crate::config::Config {
            bind: "127.0.0.1:8181".parse().unwrap(),
            policy_dir: "/tmp/p".into(),
            audit_log: "/tmp/a.jsonl".into(),
            agents,
        }
    }

    /// `args[0]` is the per-run shim path nono really sends
    /// (`crate::wire::EXAMPLE_SHIM_ARGV0`), not the command name.
    const COMMAND: &str = r#"{"backend":"cedar","request":{
        "capability_type":"command","request_id":"r1","command":"git",
        "args":["/private/tmp/nono-tool-sandbox-13819-1784990893285791000-a4d3bceb3ec061c0/shims/git","push","--force"],
        "caller":"session","intercept_rule":"push",
        "reason":null,"child_pid":42,"session_id":"s1"}}"#;

    #[test]
    fn maps_command_request() {
        let q = parse(COMMAND.as_bytes(), &config()).unwrap();
        assert_eq!(q.agent, "claude-code");
        assert_eq!(q.session_id, "s1");
        assert_eq!(q.caller, "session");
        assert_eq!(q.caller_kind, CallerKind::Session);
        assert_eq!(q.action_name(), "launchCommand");
        let Target::Command {
            command,
            args,
            intercept_rule,
            child_pid,
        } = q.target
        else {
            panic!("expected command target");
        };
        assert_eq!(command, "git");
        assert_eq!(
            args,
            vec![crate::wire::EXAMPLE_SHIM_ARGV0, "push", "--force"],
            "args must reach policy exactly as nono sent them, shim path included"
        );
        assert_eq!(intercept_rule, "push");
        assert_eq!(child_pid, 42);
    }

    #[test]
    fn derives_command_caller_kind_for_chained_launch() {
        let body = COMMAND.replace(r#""caller":"session""#, r#""caller":"npm""#);
        let q = parse(body.as_bytes(), &config()).unwrap();
        assert_eq!(q.caller, "npm");
        assert_eq!(q.caller_kind, CallerKind::Command);
    }

    #[test]
    fn unmapped_backend_falls_back_to_unknown_agent() {
        let body = COMMAND.replace(r#""backend":"cedar""#, r#""backend":"rogue""#);
        let q = parse(body.as_bytes(), &config()).unwrap();
        assert_eq!(q.agent, "unknown");
    }

    #[test]
    fn maps_endpoint_request_with_proxy_identity() {
        let body = r#"{"backend":"cedar","request":{
            "capability_type":"endpoint","request_id":"p1","route_id":"github-api",
            "upstream":"https://api.github.com","method":"GET","path":"/repos/x",
            "rule_label":"rl","reason":null,"child_pid":0,"session_id":"proxy"}}"#;
        let q = parse(body.as_bytes(), &config()).unwrap();
        assert_eq!(q.caller, "proxy");
        assert_eq!(q.session_id, "proxy");
        assert_eq!(q.action_name(), "httpRequest");
        assert!(matches!(q.target, Target::Endpoint { .. }));
    }

    /// nono 0.69 always sends `session_id: "proxy"` for endpoint approvals, but a
    /// payload that claims a real session id must not place the proxy caller
    /// inside that session's hierarchy: the identity is pinned, not echoed.
    #[test]
    fn endpoint_session_identity_is_pinned_not_taken_from_the_wire() {
        let body = r#"{"backend":"cedar","request":{
            "capability_type":"endpoint","request_id":"p1","route_id":"github-api",
            "upstream":"https://api.github.com","method":"GET","path":"/repos/x",
            "rule_label":"rl","reason":null,"child_pid":0,"session_id":"s1"}}"#;
        let q = parse(body.as_bytes(), &config()).unwrap();
        assert_eq!(q.session_id, "proxy");
        assert_eq!(q.caller, "proxy");
    }

    /// Documented v1 limitation: the wire carries the caller *label*, not a
    /// caller *kind* — `"session"` for a direct agent launch, otherwise the
    /// intercepted command's name. A profile that intercepts a command literally
    /// named `session` therefore produces a payload indistinguishable from a
    /// direct launch; disambiguating needs an upstream field. What we can pin is
    /// that the match is exact, so no near-miss label widens into `Session`.
    #[test]
    fn session_caller_kind_requires_an_exact_label_match() {
        for name in ["session ", " session", "Session", "sessions", "ses"] {
            let body = COMMAND.replace(r#""caller":"session""#, &format!(r#""caller":"{name}""#));
            let q = parse(body.as_bytes(), &config()).unwrap();
            assert_eq!(q.caller, name);
            assert_eq!(q.caller_kind, CallerKind::Command, "{name:?}");
        }
    }

    #[test]
    fn unsupported_variant_is_an_error_with_a_deny_reason() {
        let body = r#"{"backend":"cedar","request":{"capability_type":"network",
            "request_id":"n1","host":"example.com","port":443,"protocol":"tcp",
            "resolved_ips":[],"reason":null,"child_pid":1,"session_id":"s1"}}"#;
        let err = parse(body.as_bytes(), &config()).unwrap_err();
        assert!(matches!(err, AdaptError::UnsupportedVariant));
        assert!(err.deny_reason().contains("unsupported"));
    }

    #[test]
    fn malformed_body_is_an_error_with_a_deny_reason() {
        let err = parse(b"{not json", &config()).unwrap_err();
        assert!(matches!(err, AdaptError::Malformed(_)));
        assert!(err.deny_reason().contains("malformed"));
    }

    /// A refused request still carries the context that makes its denial
    /// reviewable: which backend asked, which request id, which session.
    #[test]
    fn scrapes_the_context_of_a_refused_request() {
        let body = r#"{"backend":"cedar","request":{"capability_type":"capability",
            "request_id":"cap-1","path":"/Users/ac/.ssh/id_ed25519","access":"read",
            "reason":null,"child_pid":7,"session_id":"s1"}}"#;
        let ctx = scrape_context(body.as_bytes(), &config());
        assert_eq!(ctx.backend.as_deref(), Some("cedar"));
        assert_eq!(ctx.agent.as_deref(), Some("claude-code"));
        assert_eq!(ctx.capability_type.as_deref(), Some("capability"));
        assert_eq!(ctx.request_id.as_deref(), Some("cap-1"));
        assert_eq!(ctx.session_id.as_deref(), Some("s1"));
    }

    #[test]
    fn scraping_a_body_that_is_not_json_yields_an_empty_context() {
        assert_eq!(
            scrape_context(b"{not json", &config()),
            RejectedContext::default()
        );
        // Valid JSON of the wrong shape must not panic or half-fill either.
        assert_eq!(
            scrape_context(br#"{"backend":42,"request":"nope"}"#, &config()),
            RejectedContext::default()
        );
    }

    /// The scraped values go straight into log lines and the audit trail, so
    /// control bytes are escaped at this boundary.
    #[test]
    fn scraped_context_is_control_escaped() {
        let body = serde_json::json!({
            "backend": "cedar",
            "request": {
                "capability_type": "capability",
                "request_id": "cap\u{1b}[2K\rINFO forged allow=true",
                "session_id": "s1",
            }
        })
        .to_string();
        let ctx = scrape_context(body.as_bytes(), &config());
        let request_id = ctx.request_id.unwrap();
        assert!(!request_id.chars().any(char::is_control), "{request_id:?}");
        assert!(request_id.contains("\\u{001b}"), "{request_id}");
    }

    #[test]
    fn an_unmapped_backend_scrapes_to_the_unknown_agent() {
        let body = r#"{"backend":"rogue","request":{"capability_type":"network"}}"#;
        let ctx = scrape_context(body.as_bytes(), &config());
        assert_eq!(ctx.backend.as_deref(), Some("rogue"));
        assert_eq!(ctx.agent.as_deref(), Some("unknown"));
    }
}
