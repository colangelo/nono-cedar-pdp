//! The adapter-neutral internal boundary. Everything downstream of here is
//! independent of how the request arrived, which is what makes a future PORC
//! adapter — or an upstream native backend — a drop-in.

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CallerKind {
    Session,
    Command,
}

impl CallerKind {
    pub fn as_str(&self) -> &'static str {
        match self {
            CallerKind::Session => "session",
            CallerKind::Command => "command",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Target {
    Command {
        command: String,
        args: Vec<String>,
        intercept_rule: String,
        child_pid: u32,
    },
    Endpoint {
        route_id: String,
        upstream: String,
        method: String,
        path: String,
        rule_label: String,
    },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PolicyQuery {
    /// Cedar `Agent` id, resolved from config by approval-backend name.
    pub agent: String,
    pub session_id: String,
    pub caller: String,
    pub caller_kind: CallerKind,
    pub request_id: String,
    pub backend: String,
    pub reason: Option<String>,
    pub target: Target,
}

impl PolicyQuery {
    pub fn action_name(&self) -> &'static str {
        match self.target {
            Target::Command { .. } => "launchCommand",
            Target::Endpoint { .. } => "httpRequest",
        }
    }

    /// Short human-readable resource description for audit lines. Control
    /// characters are escaped: this text is request-derived and ends up in the
    /// audit trail and in operator-facing log lines.
    pub fn resource_summary(&self) -> String {
        let raw = match &self.target {
            Target::Command { command, args, .. } => {
                format!("{command} [{}]", args.join(" "))
            }
            Target::Endpoint {
                method,
                upstream,
                path,
                ..
            } => {
                format!("{method} {upstream}{path}")
            }
        };
        crate::sanitize::control_escape(&raw)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn resource_summary_escapes_control_bytes_from_the_command_line() {
        let q = PolicyQuery {
            agent: "claude-code".to_string(),
            session_id: "s1".to_string(),
            caller: "session".to_string(),
            caller_kind: CallerKind::Session,
            request_id: "r1".to_string(),
            backend: "cedar".to_string(),
            reason: None,
            target: Target::Command {
                command: "git".to_string(),
                args: vec![
                    crate::wire::EXAMPLE_SHIM_ARGV0.to_string(),
                    "commit\u{1b}[2K\r-m".to_string(),
                    "ok".to_string(),
                ],
                intercept_rule: "commit".to_string(),
                child_pid: 1,
            },
        };
        let summary = q.resource_summary();
        assert!(
            !summary.chars().any(char::is_control),
            "audit text must not carry raw control bytes: {summary:?}"
        );
        assert!(summary.contains("\\u{001b}"), "{summary}");
    }
}
