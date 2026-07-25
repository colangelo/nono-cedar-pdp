//! Append-only JSONL decision log. One line per decision, owner-readable only.

use crate::adapter::nono_webhook::RejectedContext;
use crate::decision::Decision;
use crate::query::PolicyQuery;
use serde::Serialize;
use std::fs::{File, OpenOptions, Permissions};
use std::io::Write;
use std::os::unix::fs::{FileExt, OpenOptionsExt, PermissionsExt};
use std::path::Path;
use std::sync::Mutex;

/// One audit line.
///
/// The fields a decided request always has are `Option` because a *rejected*
/// request — malformed body, unsupported variant — still gets a line, and only
/// some of its context survives. The key set never changes: an absent value is an
/// explicit `null`, so a consumer can tell "not known" from "not recorded".
#[derive(Debug, Serialize)]
pub struct AuditRecord<'a> {
    pub ts: String,
    pub request_id: Option<&'a str>,
    pub session_id: Option<&'a str>,
    pub backend: Option<&'a str>,
    pub agent: Option<&'a str>,
    pub principal: Option<String>,
    pub action: Option<&'a str>,
    pub resource: Option<String>,
    pub decision: &'static str,
    pub matched: &'a [String],
    pub reason: &'a str,
    pub eval_us: u128,
}

/// Where audit lines go. A trait so the partial-write recovery path can be
/// tested without an out-of-space filesystem; `File` is the only production impl.
trait ByteSink: Send {
    fn append(&mut self, buf: &[u8]) -> std::io::Result<()>;
    fn size(&self) -> std::io::Result<u64>;
    fn truncate(&mut self, len: u64) -> std::io::Result<()>;
}

impl ByteSink for File {
    fn append(&mut self, buf: &[u8]) -> std::io::Result<()> {
        self.write_all(buf)
    }

    fn size(&self) -> std::io::Result<u64> {
        Ok(self.metadata()?.len())
    }

    fn truncate(&mut self, len: u64) -> std::io::Result<()> {
        self.set_len(len)
    }
}

struct Sink {
    bytes: Box<dyn ByteSink>,
    /// The last record did not make it out whole, so the file ends mid-line.
    /// The next record closes that line before starting its own.
    unterminated: bool,
}

pub struct AuditLog {
    sink: Mutex<Sink>,
}

impl AuditLog {
    pub fn open(path: &Path) -> std::io::Result<Self> {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        // Read access is wanted only so the last byte can be inspected below (the
        // mode is 0600 either way), but an append-only log we cannot read is a
        // legitimate setup — and a daemon that refuses to start cannot decide
        // anything. Fall back to write-only; `ends_mid_line` then reports why.
        let file = match open_append(path, true) {
            Ok(file) => file,
            Err(_) => open_append(path, false)?,
        };
        // `mode` above only applies when the file is created. A log that already
        // exists keeps whatever permissions it had, and it records the full
        // command lines and API paths an agent attempted.
        tighten_permissions(path, &file);
        // A previous run may have died mid-record (full disk, SIGKILL), leaving
        // the file ending without a newline.
        let unterminated = match ends_mid_line(&file) {
            Ok(unterminated) => unterminated,
            Err(e) => {
                tracing::warn!(
                    path = %path.display(),
                    error = %e,
                    "could not tell whether the audit log ends mid-record"
                );
                false
            }
        };
        if unterminated {
            tracing::warn!(
                path = %path.display(),
                "audit log ends mid-record; the next line starts after it"
            );
        }
        Ok(Self::with_sink(Box::new(file), unterminated))
    }

    fn with_sink(bytes: Box<dyn ByteSink>, unterminated: bool) -> Self {
        Self {
            sink: Mutex::new(Sink {
                bytes,
                unterminated,
            }),
        }
    }

    /// Record a decision. A logging failure must never change a decision, so
    /// errors are traced and swallowed.
    pub fn record(&self, query: &PolicyQuery, decision: &Decision) {
        self.append(&AuditRecord {
            ts: now_rfc3339(),
            request_id: Some(&query.request_id),
            session_id: Some(&query.session_id),
            backend: Some(&query.backend),
            agent: Some(&query.agent),
            principal: Some(format!("Nono::Caller::{:?}", query.caller)),
            action: Some(query.action_name()),
            resource: Some(query.resource_summary()),
            decision: if decision.allow { "allow" } else { "deny" },
            matched: &decision.matched,
            reason: &decision.reason,
            eval_us: decision.eval_us,
        });
    }

    /// Record a denial for a request that never became a `PolicyQuery`: a
    /// malformed body, an unsupported variant, a body over the size cap. There is
    /// no Cedar principal or action for these, so those fields are null; the
    /// refused variant stands in as the resource, because it is the only "what was
    /// asked" the wire gave us.
    pub fn record_rejected(&self, context: &RejectedContext, decision: &Decision) {
        self.append(&AuditRecord {
            ts: now_rfc3339(),
            request_id: context.request_id.as_deref(),
            session_id: context.session_id.as_deref(),
            backend: context.backend.as_deref(),
            agent: context.agent.as_deref(),
            principal: None,
            action: None,
            resource: context
                .capability_type
                .as_deref()
                .map(|variant| format!("capability_type={variant}")),
            decision: if decision.allow { "allow" } else { "deny" },
            matched: &decision.matched,
            reason: &decision.reason,
            eval_us: decision.eval_us,
        });
    }

    fn append(&self, record: &AuditRecord<'_>) {
        let line = match serde_json::to_string(record) {
            Ok(line) => line,
            Err(e) => {
                tracing::error!(error = %e, "failed to serialize audit record");
                return;
            }
        };

        let mut sink = match self.sink.lock() {
            Ok(guard) => guard,
            Err(poisoned) => poisoned.into_inner(),
        };

        // One write per record, newline included: nothing else can interleave, and
        // a short write is visible as a single failure to react to.
        let mut buf = Vec::with_capacity(line.len() + 2);
        if sink.unterminated {
            buf.push(b'\n');
        }
        buf.extend_from_slice(line.as_bytes());
        buf.push(b'\n');

        let size_before = sink.bytes.size().ok();
        match sink.bytes.append(&buf) {
            Ok(()) => sink.unterminated = false,
            Err(e) => {
                tracing::error!(error = %e, "failed to write audit record");
                // A short write leaves a partial record. Roll it back so every line
                // in the log stays independently parseable; if that is impossible,
                // remember to close the broken line before the next record instead
                // of fusing the two.
                let rolled_back = matches!(
                    size_before.map(|len| sink.bytes.truncate(len)),
                    Some(Ok(()))
                );
                sink.unterminated = !rolled_back;
            }
        }
    }
}

fn open_append(path: &Path, read: bool) -> std::io::Result<File> {
    OpenOptions::new()
        .create(true)
        .append(true)
        .read(read)
        .mode(0o600)
        .open(path)
}

/// True when the file is non-empty and does not end with a newline, i.e. its last
/// record was never finished.
fn ends_mid_line(file: &File) -> std::io::Result<bool> {
    let len = file.metadata()?.len();
    if len == 0 {
        return Ok(false);
    }
    let mut last = [0u8; 1];
    file.read_exact_at(&mut last, len - 1)?;
    Ok(last[0] != b'\n')
}

/// Restrict an existing audit log to owner-only access. Logged either way: an
/// operator who widened the mode deliberately needs to know it was narrowed, and
/// one who cannot narrow it needs to know the trail is exposed.
fn tighten_permissions(path: &Path, file: &File) {
    let Ok(metadata) = file.metadata() else {
        return;
    };
    let mode = metadata.permissions().mode() & 0o7777;
    // Anything beyond owner read/write: group, other, or the execute bit.
    if mode & 0o177 == 0 {
        return;
    }
    match file.set_permissions(Permissions::from_mode(0o600)) {
        Ok(()) => tracing::warn!(
            path = %path.display(),
            previous_mode = format!("{mode:04o}"),
            "audit log was not owner-only; tightened to 0600"
        ),
        Err(e) => tracing::error!(
            path = %path.display(),
            mode = format!("{mode:04o}"),
            error = %e,
            "audit log is not owner-only and could not be tightened"
        ),
    }
}

fn now_rfc3339() -> String {
    time::OffsetDateTime::now_utc()
        .format(&time::format_description::well_known::Rfc3339)
        .unwrap_or_else(|_| "unknown".to_string())
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::panic)]
mod tests {
    use super::*;
    use crate::query::{CallerKind, PolicyQuery, Target};
    use std::sync::Arc;

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
                args: vec![
                    crate::wire::EXAMPLE_SHIM_ARGV0.to_string(),
                    "status".to_string(),
                ],
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

    /// `OpenOptions::mode` only applies at creation. A log that already exists with
    /// looser permissions would otherwise keep them, and it records the full
    /// command lines and API paths an agent attempted.
    #[test]
    fn looser_permissions_on_an_existing_log_are_tightened() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("decisions.jsonl");
        std::fs::write(&path, "").unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();

        let log = AuditLog::open(&path).unwrap();
        log.record(&query(), &crate::decision::Decision::deny("nope"));

        let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(
            mode, 0o600,
            "a pre-existing audit log must not stay readable by other users"
        );
    }

    /// A sink that accepts a fixed budget of bytes and then reports a full disk,
    /// so the partial-write path can be exercised without an out-of-space
    /// filesystem. `truncate` mirrors `File::set_len`.
    #[derive(Clone, Default)]
    struct FullDisk {
        data: Arc<Mutex<Vec<u8>>>,
        budget: Arc<Mutex<usize>>,
    }

    impl FullDisk {
        fn with_budget(bytes: usize) -> Self {
            let disk = Self::default();
            disk.set_budget(bytes);
            disk
        }

        fn set_budget(&self, bytes: usize) {
            *self.budget.lock().unwrap() = bytes;
        }

        fn text(&self) -> String {
            String::from_utf8_lossy(&self.data.lock().unwrap()).to_string()
        }
    }

    impl ByteSink for FullDisk {
        fn append(&mut self, buf: &[u8]) -> std::io::Result<()> {
            let mut budget = self.budget.lock().unwrap();
            let accepted = buf.len().min(*budget);
            self.data
                .lock()
                .unwrap()
                .extend_from_slice(&buf[..accepted]);
            *budget -= accepted;
            if accepted < buf.len() {
                return Err(std::io::Error::other("no space left on device"));
            }
            Ok(())
        }

        fn size(&self) -> std::io::Result<u64> {
            Ok(self.data.lock().unwrap().len() as u64)
        }

        fn truncate(&mut self, len: u64) -> std::io::Result<()> {
            self.data.lock().unwrap().truncate(len as usize);
            Ok(())
        }
    }

    /// A write that fails halfway leaves a partial record. It must not be left for
    /// the next record to append onto: one unparseable line would swallow a real
    /// decision. The decision itself is unaffected either way.
    #[test]
    fn a_partial_write_never_fuses_two_records_into_one_line() {
        let disk = FullDisk::with_budget(120);
        let log = AuditLog::with_sink(Box::new(disk.clone()), false);

        log.record(&query(), &crate::decision::Decision::deny("full disk"));
        disk.set_budget(usize::MAX);
        log.record(&query(), &crate::decision::Decision::deny("after recovery"));

        let text = disk.text();
        for line in text.lines() {
            serde_json::from_str::<serde_json::Value>(line)
                .unwrap_or_else(|e| panic!("unparseable audit line {line:?}: {e}"));
        }
        assert!(
            text.contains("after recovery"),
            "the record written after recovery must survive: {text:?}"
        );
    }

    /// Reading the last byte needs read access, but an append-only log is a
    /// legitimate setup. A log we can write but not read must still open — a
    /// daemon that refuses to start cannot decide anything.
    #[test]
    fn a_write_only_log_still_opens() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("decisions.jsonl");
        std::fs::write(&path, "").unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o200)).unwrap();

        let log = AuditLog::open(&path).unwrap();
        log.record(&query(), &crate::decision::Decision::deny("nope"));

        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
        let text = std::fs::read_to_string(&path).unwrap();
        assert_eq!(text.lines().count(), 1, "{text:?}");
    }

    /// An interrupted write — a full disk, a killed daemon — leaves a record with
    /// no closing newline. Appending straight onto it fuses two records into one
    /// unparseable line and silently swallows a real decision.
    #[test]
    fn a_truncated_final_line_is_closed_before_the_next_record() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("decisions.jsonl");
        let truncated = r#"{"ts":"2026-07-25T00:00:00Z","request_id":"full-6","princ"#;
        std::fs::write(&path, truncated).unwrap();

        let log = AuditLog::open(&path).unwrap();
        log.record(&query(), &crate::decision::Decision::deny("after recovery"));

        let text = std::fs::read_to_string(&path).unwrap();
        let lines: Vec<&str> = text.lines().collect();
        assert_eq!(lines.len(), 2, "{text:?}");
        assert_eq!(lines[0], truncated, "the truncated line stays as evidence");
        let recovered: serde_json::Value = serde_json::from_str(lines[1]).unwrap_or_else(|e| {
            panic!("the record after recovery must parse: {e}: {:?}", lines[1])
        });
        assert_eq!(recovered["reason"], "after recovery");
    }
}
