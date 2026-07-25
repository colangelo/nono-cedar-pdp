//! Append-only JSONL decision log. One line per decision, owner-readable only.

use crate::decision::Decision;
use crate::query::PolicyQuery;
use serde::Serialize;
use std::fs::{File, OpenOptions};
use std::io::Write;
use std::os::unix::fs::OpenOptionsExt;
use std::path::Path;
use std::sync::Mutex;

#[derive(Debug, Serialize)]
pub struct AuditRecord<'a> {
    pub ts: String,
    pub request_id: &'a str,
    pub session_id: &'a str,
    pub backend: &'a str,
    pub agent: &'a str,
    pub principal: String,
    pub action: &'a str,
    pub resource: String,
    pub decision: &'static str,
    pub matched: &'a [String],
    pub reason: &'a str,
    pub eval_us: u128,
}

pub struct AuditLog {
    file: Mutex<File>,
}

impl AuditLog {
    pub fn open(path: &Path) -> std::io::Result<Self> {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let file = OpenOptions::new()
            .create(true)
            .append(true)
            .mode(0o600)
            .open(path)?;
        Ok(Self {
            file: Mutex::new(file),
        })
    }

    /// Record a decision. A logging failure must never change a decision, so
    /// errors are traced and swallowed.
    pub fn record(&self, query: &PolicyQuery, decision: &Decision) {
        let record = AuditRecord {
            ts: now_rfc3339(),
            request_id: &query.request_id,
            session_id: &query.session_id,
            backend: &query.backend,
            agent: &query.agent,
            principal: format!("Nono::Caller::{:?}", query.caller),
            action: query.action_name(),
            resource: query.resource_summary(),
            decision: if decision.allow { "allow" } else { "deny" },
            matched: &decision.matched,
            reason: &decision.reason,
            eval_us: decision.eval_us,
        };

        let line = match serde_json::to_string(&record) {
            Ok(line) => line,
            Err(e) => {
                tracing::error!(error = %e, "failed to serialize audit record");
                return;
            }
        };

        let mut guard = match self.file.lock() {
            Ok(guard) => guard,
            Err(poisoned) => poisoned.into_inner(),
        };
        if let Err(e) = writeln!(guard, "{line}") {
            tracing::error!(error = %e, "failed to write audit record");
        }
    }
}

fn now_rfc3339() -> String {
    time::OffsetDateTime::now_utc()
        .format(&time::format_description::well_known::Rfc3339)
        .unwrap_or_else(|_| "unknown".to_string())
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use crate::query::{CallerKind, PolicyQuery, Target};

    fn query() -> PolicyQuery {
        PolicyQuery {
            agent: "claude-code".to_string(),
            session_id: "s1".to_string(),
            caller: "session".to_string(),
            caller_kind: CallerKind::Session,
            request_id: "r1".to_string(),
            backend: "cedar".to_string(),
            reason: None,
            target: Target::Command {
                command: "git".to_string(),
                args: vec!["git".to_string(), "status".to_string()],
                intercept_rule: "status".to_string(),
                child_pid: 42,
            },
        }
    }

    #[test]
    fn appends_one_json_line_per_decision() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("nested/decisions.jsonl");
        let log = AuditLog::open(&path).unwrap();

        log.record(&query(), &crate::decision::Decision::deny("nope"));
        log.record(&query(), &crate::decision::Decision::deny("still nope"));

        let text = std::fs::read_to_string(&path).unwrap();
        let lines: Vec<&str> = text.lines().collect();
        assert_eq!(lines.len(), 2);

        let first: serde_json::Value = serde_json::from_str(lines[0]).unwrap();
        assert_eq!(first["request_id"], "r1");
        assert_eq!(first["session_id"], "s1");
        assert_eq!(first["backend"], "cedar");
        assert_eq!(first["agent"], "claude-code");
        assert_eq!(first["action"], "launchCommand");
        assert_eq!(first["decision"], "deny");
        assert_eq!(first["principal"], "Nono::Caller::\"session\"");
        assert!(first["resource"].as_str().unwrap().contains("git"));
        assert!(
            first["ts"].as_str().unwrap().contains('T'),
            "want RFC3339 ts"
        );
    }

    #[test]
    fn creates_the_log_with_owner_only_permissions() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("decisions.jsonl");
        let _log = AuditLog::open(&path).unwrap();
        let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600, "audit log must not be world readable");
    }
}
