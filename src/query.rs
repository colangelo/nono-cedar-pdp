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

    /// Short human-readable resource description for audit lines.
    pub fn resource_summary(&self) -> String {
        match &self.target {
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
        }
    }
}
