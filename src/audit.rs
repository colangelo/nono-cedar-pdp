//! Append-only JSONL decision log. One line per decision, owner-readable only.

use crate::adapter::nono_webhook::RejectedContext;
use crate::decision::Decision;
use crate::query::PolicyQuery;
use serde::Serialize;
use std::fs::{File, OpenOptions, Permissions};
use std::io::Write;
use std::os::unix::fs::{FileExt, MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
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
/// tested without an out-of-space filesystem; [`LogFile`] is the only production
/// impl.
trait ByteSink: Send {
    fn append(&mut self, buf: &[u8]) -> std::io::Result<()>;
    fn size(&self) -> std::io::Result<u64>;
    fn truncate(&mut self, len: u64) -> std::io::Result<()>;
    /// Check that this sink still writes to the place the operator configured, and
    /// re-point it if it does not. Called before every record.
    ///
    /// Default: nothing to check. A sink with no path — the in-memory test sink —
    /// cannot be detached from one.
    fn reattach(&mut self) -> Reattach {
        Reattach::Unchanged
    }
}

/// What [`ByteSink::reattach`] found.
enum Reattach {
    /// The sink still writes where it was configured to.
    Unchanged,
    /// A fresh handle was opened. `ends_mid_line` describes the file now held, and
    /// the caller's byte accounting for the previous one no longer applies.
    Reopened { ends_mid_line: bool },
}

/// The production sink: an append handle plus the identity of the inode it was
/// opened on.
///
/// The identity is the whole point. A `rename` — `logrotate`, an operator
/// archiving the trail — leaves this handle attached to an inode that no longer
/// has the configured name, and an `unlink` leaves it attached to one with no name
/// at all. Writes keep succeeding, so nothing surfaces as an error: every later
/// decision is answered and recorded nowhere an operator will look. Since the
/// audit log is the compensating control for an unauthenticated webhook, a
/// silently detached trail is the failure that matters most here.
struct LogFile {
    path: PathBuf,
    file: File,
    /// `(st_dev, st_ino)` of the inode `file` refers to.
    inode: (u64, u64),
}

impl LogFile {
    /// Open (creating if needed) the log at `path`. Returns the handle and whether
    /// the file it found ends mid-record.
    fn open(path: &Path) -> std::io::Result<(Self, bool)> {
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
        let metadata = file.metadata()?;
        Ok((
            Self {
                path: path.to_path_buf(),
                file,
                inode: (metadata.dev(), metadata.ino()),
            },
            unterminated,
        ))
    }

    /// The name-to-inode binding we opened on, re-read from the filesystem.
    fn still_attached(&self) -> std::io::Result<bool> {
        let metadata = std::fs::metadata(&self.path)?;
        Ok((metadata.dev(), metadata.ino()) == self.inode)
    }
}

impl ByteSink for LogFile {
    fn append(&mut self, buf: &[u8]) -> std::io::Result<()> {
        self.file.write_all(buf)
    }

    fn size(&self) -> std::io::Result<u64> {
        Ok(self.file.metadata()?.len())
    }

    fn truncate(&mut self, len: u64) -> std::io::Result<()> {
        self.file.set_len(len)
    }

    fn reattach(&mut self) -> Reattach {
        let detached = match self.still_attached() {
            Ok(true) => return Reattach::Unchanged,
            Ok(false) => "the configured path now names a different file",
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                "the configured path no longer exists"
            }
            Err(e) => {
                // Cannot tell. Keep the handle we have — it is the only place a
                // record can still go — and say so rather than reopening blindly.
                tracing::warn!(
                    path = %self.path.display(),
                    error = %e,
                    "could not check whether the audit log is still at the configured path"
                );
                return Reattach::Unchanged;
            }
        };
        match Self::open(&self.path) {
            Ok((reopened, ends_mid_line)) => {
                tracing::warn!(
                    path = %self.path.display(),
                    reason = detached,
                    previous_inode = self.inode.1,
                    inode = reopened.inode.1,
                    "audit log was rotated or replaced; reopened at the configured path"
                );
                *self = reopened;
                Reattach::Reopened { ends_mid_line }
            }
            Err(e) => {
                // Appending to the handle we still hold keeps the record; dropping
                // it would not. Either way the decision is unaffected.
                tracing::error!(
                    path = %self.path.display(),
                    reason = detached,
                    error = %e,
                    "audit log is detached and could not be reopened; \
                     still appending to the previous file"
                );
                Reattach::Unchanged
            }
        }
    }
}

struct Sink {
    bytes: Box<dyn ByteSink>,
    /// The last record did not make it out whole, so the file ends mid-line.
    /// The next record closes that line before starting its own.
    unterminated: bool,
    /// Size of the sink after the last record this process wrote, when known. A
    /// smaller size later means something outside removed lines — rotation by
    /// truncation (`logrotate copytruncate`), or tampering.
    last_size: Option<u64>,
}

pub struct AuditLog {
    sink: Mutex<Sink>,
}

impl AuditLog {
    pub fn open(path: &Path) -> std::io::Result<Self> {
        let (file, unterminated) = LogFile::open(path)?;
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
                last_size: None,
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

        // Before every record, not periodically: one `stat` is nothing next to the
        // Cedar evaluation that produced this record (milliseconds), and "periodic"
        // means a window in which decisions are answered but recorded nowhere at the
        // configured path. A reopened file is a different file, so both the
        // mid-record state and the byte accounting start over.
        if let Reattach::Reopened { ends_mid_line } = sink.bytes.reattach() {
            sink.unterminated = ends_mid_line;
            sink.last_size = None;
        }

        // One write per record, newline included: nothing else can interleave, and
        // a short write is visible as a single failure to react to.
        let mut buf = Vec::with_capacity(line.len() + 2);
        if sink.unterminated {
            buf.push(b'\n');
        }
        buf.extend_from_slice(line.as_bytes());
        buf.push(b'\n');

        let size_before = sink.bytes.size().ok();
        // Same inode, fewer bytes: nothing this daemon did can shrink an append-only
        // log, so lines were removed from underneath it.
        if let (Some(before), Some(last)) = (size_before, sink.last_size) {
            if before < last {
                tracing::warn!(
                    bytes_removed = last - before,
                    size = before,
                    "audit log shrank since the last record; \
                     it was truncated or rewritten by something else"
                );
            }
        }
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
        sink.last_size = sink.bytes.size().ok();
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

    /// The guarantee is about the *response*, not about the log: nono is waiting on
    /// a decision, and a full disk is not a reason to change it or to withhold it.
    /// Nothing asserted that before — `record` returning `()` made it true by
    /// construction, so a future `record` that returned a `Result` and got
    /// `?`-propagated out of the handler would have broken the scenario silently
    /// (and turned every decision into a 500, which nono records as a bare HTTP
    /// status rather than a reason).
    ///
    /// Driven through the real HTTP handler because that is where the decision is
    /// returned from; the failing sink is only reachable from inside this module.
    #[tokio::test]
    async fn a_write_failure_changes_neither_the_decision_nor_the_response() {
        use tower::ServiceExt;

        let dir = tempfile::tempdir().unwrap();
        std::fs::write(
            dir.path().join("p.cedar"),
            "@id(\"allow-git\")\npermit (principal, action == Nono::Action::\"launchCommand\", \
             resource) when { resource.command == \"git\" };",
        )
        .unwrap();
        let schema = crate::cedar::schema::load().unwrap();
        let engine =
            crate::cedar::engine::Engine::bootstrap(schema, dir.path().to_path_buf()).unwrap();
        let mut agents = std::collections::BTreeMap::new();
        agents.insert("cedar".to_string(), "claude-code".to_string());
        let config = crate::config::Config {
            bind: "127.0.0.1:0".parse().unwrap(),
            policy_dir: dir.path().to_path_buf(),
            audit_log: dir.path().join("unused.jsonl"),
            agents,
        };
        // Zero bytes of space: every record fails, and there is nothing to roll back.
        let full = FullDisk::with_budget(0);
        let state = crate::server::AppState {
            engine: Arc::new(engine),
            config: Arc::new(config),
            audit: Arc::new(AuditLog::with_sink(Box::new(full.clone()), false)),
        };

        let body = serde_json::json!({
            "backend": "cedar",
            "request": {
                "capability_type": "command",
                "request_id": "r1",
                "command": "git",
                "args": [crate::wire::EXAMPLE_SHIM_ARGV0, "status"],
                "caller": "session",
                "intercept_rule": "status",
                "reason": null,
                "child_pid": 42,
                "session_id": "s1"
            }
        })
        .to_string();

        let (response, log_text) = {
            let capture = crate::test_log::capture();
            let response = crate::server::router(state)
                .oneshot(
                    axum::http::Request::builder()
                        .method("POST")
                        .uri("/v1/approve")
                        .header("content-type", "application/json")
                        .body(axum::body::Body::from(body))
                        .unwrap(),
                )
                .await
                .unwrap();
            let text = capture.text();
            (response, text)
        };

        assert_eq!(
            response.status(),
            axum::http::StatusCode::OK,
            "an unwritable audit log must not become an HTTP failure"
        );
        let bytes = axum::body::to_bytes(response.into_body(), 8 * 1024)
            .await
            .unwrap();
        let json: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(
            json,
            serde_json::json!({"decision": "allow"}),
            "the decision already computed must reach nono unchanged"
        );
        assert_eq!(full.text(), "", "the premise is that nothing was written");
        assert!(
            log_text.contains("failed to write audit record"),
            "the operator must be told the trail is not being written: {log_text:?}"
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

    /// Rotation — `logrotate`, an operator archiving the trail — renames the file
    /// out from under the open handle. Appending to the renamed (or unlinked) inode
    /// answers decisions that nothing at the configured path records: the audit
    /// trail silently detaches, and `/healthz` stays green. Subsequent decisions
    /// must land in a readable file at the configured path.
    #[test]
    fn a_rotated_log_is_reopened_at_the_configured_path() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("decisions.jsonl");
        let rotated = dir.path().join("decisions.jsonl.1");

        let (_, log_text) = crate::test_log::with_captured_log(|| {
            let log = AuditLog::open(&path).unwrap();
            log.record(
                &query(),
                &crate::decision::Decision::deny("before rotation"),
            );
            std::fs::rename(&path, &rotated).unwrap();
            log.record(&query(), &crate::decision::Decision::deny("after rotation"));
        });

        let current = std::fs::read_to_string(&path)
            .unwrap_or_else(|e| panic!("nothing readable at the configured path: {e}"));
        assert!(
            current.contains("after rotation"),
            "the decision after the rotation must be recorded at the configured path: {current:?}"
        );
        assert!(
            !current.contains("before rotation"),
            "the reopened file must not replay the archived records: {current:?}"
        );
        for line in current.lines() {
            serde_json::from_str::<serde_json::Value>(line)
                .unwrap_or_else(|e| panic!("unparseable audit line {line:?}: {e}"));
        }

        let archived = std::fs::read_to_string(&rotated).unwrap();
        assert!(
            archived.contains("before rotation"),
            "the archived file keeps what it already had: {archived:?}"
        );
        assert!(
            !archived.contains("after rotation"),
            "nothing may be appended to the detached inode: {archived:?}"
        );

        let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600, "the reopened log must not be world readable");

        assert!(
            log_text.contains("reopened"),
            "the operator must see that the log was replaced: {log_text:?}"
        );
        assert!(
            log_text.contains("decisions.jsonl"),
            "the warning must name the path: {log_text:?}"
        );
    }

    /// The same detachment, one step further: the file is gone rather than renamed.
    /// Every later decision would be written to an inode with no name at all.
    #[test]
    fn a_deleted_log_is_recreated_at_the_configured_path() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("decisions.jsonl");

        let log = AuditLog::open(&path).unwrap();
        log.record(&query(), &crate::decision::Decision::deny("before delete"));
        std::fs::remove_file(&path).unwrap();
        log.record(&query(), &crate::decision::Decision::deny("after delete"));

        let current = std::fs::read_to_string(&path)
            .unwrap_or_else(|e| panic!("nothing readable at the configured path: {e}"));
        assert_eq!(current.lines().count(), 1, "{current:?}");
        assert!(current.contains("after delete"), "{current:?}");
        let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600, "the recreated log must not be world readable");
    }

    /// A rotation the daemon cannot follow — the directory is no longer writable —
    /// must not lose the record and must not change a decision. Appending to the
    /// handle we still hold is strictly better than dropping the line, so long as
    /// the operator is told the trail is no longer at the configured path.
    #[test]
    fn a_reopen_that_fails_keeps_recording_and_says_so() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("decisions.jsonl");
        let rotated = dir.path().join("decisions.jsonl.1");

        let (_, log_text) = crate::test_log::with_captured_log(|| {
            let log = AuditLog::open(&path).unwrap();
            log.record(
                &query(),
                &crate::decision::Decision::deny("before rotation"),
            );
            std::fs::rename(&path, &rotated).unwrap();
            // Owner-execute only: the directory can be traversed but nothing new
            // created in it, so the reopen cannot succeed.
            std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o500)).unwrap();
            log.record(&query(), &crate::decision::Decision::deny("after rotation"));
            std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        });

        assert!(
            !path.exists(),
            "the test premise is that the reopen could not create the file"
        );
        let archived = std::fs::read_to_string(&rotated).unwrap();
        assert!(
            archived.contains("after rotation"),
            "a record must never be dropped just because the reopen failed: {archived:?}"
        );
        // Match the reopen failure specifically: a bare "could not" is also produced by
        // the unrelated "could not tell whether the audit log ends mid-record" warning,
        // so the loose form would pass while proving nothing.
        assert!(
            log_text.contains("could not be reopened"),
            "the operator must be told the trail is detached: {log_text:?}"
        );
    }

    /// Rotation by truncation (`logrotate copytruncate`) keeps the same inode, so
    /// there is nothing to reopen — but records vanished from under us, and an
    /// operator reading a short log needs to know it was cut rather than quiet.
    #[test]
    fn an_externally_truncated_log_is_reported() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("decisions.jsonl");

        let (_, log_text) = crate::test_log::with_captured_log(|| {
            let log = AuditLog::open(&path).unwrap();
            log.record(
                &query(),
                &crate::decision::Decision::deny("before truncate"),
            );
            File::create(&path).unwrap(); // O_TRUNC on the same inode
            log.record(&query(), &crate::decision::Decision::deny("after truncate"));
        });

        let current = std::fs::read_to_string(&path).unwrap();
        assert!(current.contains("after truncate"), "{current:?}");
        assert!(
            log_text.contains("shrank"),
            "the operator must see that lines were removed: {log_text:?}"
        );
    }
}
