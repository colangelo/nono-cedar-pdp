//! Adapter for nono's `WebhookApproval` backend (nono 0.69.x).

use crate::config::Config;
use crate::query::{CallerKind, PolicyQuery, Target};
use crate::wire::{ApprovalRequest, WebhookEnvelope};

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

pub fn parse(body: &[u8], config: &Config) -> Result<PolicyQuery, AdaptError> {
    let envelope: WebhookEnvelope = serde_json::from_slice(body)?;
    let agent = config.agent_for(&envelope.backend).to_string();

    match envelope.request {
        ApprovalRequest::Command(c) => {
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
            // The proxy hardcodes `session_id: "proxy"`; there is no session
            // identity for L7 approvals. Mirror it into the caller so policies
            // can spot proxy traffic structurally.
            session_id: e.session_id,
            caller: "proxy".to_string(),
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
            unknown_agent: "unknown".to_string(),
        }
    }

    const COMMAND: &str = r#"{"backend":"cedar","request":{
        "capability_type":"command","request_id":"r1","command":"git",
        "args":["git","push","--force"],"caller":"session","intercept_rule":"push",
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
        assert_eq!(args, vec!["git", "push", "--force"]);
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
}
