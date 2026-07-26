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
    /// Always `"decision"`. The log carries more than one record shape, and a
    /// consumer must select on an explicit value rather than infer the shape from
    /// which keys happen to be present — the same reason the key set within a shape
    /// is fixed. See [`PolicySetRecord`] for the other shape.
    pub kind: &'static str,
    pub ts: String,
    pub request_id: Option<&'a str>,
    pub session_id: Option<&'a str>,
    pub backend: Option<&'a str>,
    pub agent: Option<&'a str>,
    pub principal: Option<String>,
    pub action: Option<&'a str>,
    pub resource: Option<String>,
    /// The pid of the intercepted child, as sent — echoed from the wire for both
    /// request variants. Real nono hardcodes 0 for its proxy's endpoint requests;
    /// a sender claiming otherwise leaves its claim on the record rather than
    /// having it silently rewritten. Null only on a rejected line, where no
    /// request was ever parsed.
    pub child_pid: Option<u32>,
    /// The intercept rule that routed a *command* request here — the matched
    /// rule's args joined with spaces (`"status"`, `"push --force"`),
    /// `"<catch-all>"`, or an `invocation_policy.*` label. Byte-identical to
    /// what was sent except that control characters arrive escaped (none of the
    /// real shapes contains one). Null on endpoint and rejected lines.
    pub intercept_rule: Option<&'a str>,
    /// The route rule label that routed an *endpoint* request here
    /// (`endpoint_policy.approve[GET /repos/*]`), control-escaped like
    /// `intercept_rule`. Null on command and rejected lines. Kept separate from
    /// `intercept_rule` on purpose: they are different upstream fields with
    /// different grammars, and the line's job is fidelity.
    pub rule_label: Option<&'a str>,
    /// The `User-Agent` the request presented, control-escaped, as sent. A real
    /// request carries `nono-cli/<version>`.
    ///
    /// **Evidence, not verification.** Both halves are true and both matter: browser
    /// JavaScript cannot set this header at all, so a line whose agent is absent or
    /// unexpected is a signal worth having; a local process running as the same user
    /// sets it to whatever it likes, so a line whose agent looks right proves
    /// nothing. Recording it does not authenticate the caller and must never be
    /// described as doing so — a field that *looks* like authentication is worse
    /// than no field at all.
    ///
    /// Null when the request carried no `User-Agent`, and on lines written by
    /// something other than an HTTP request (the `check` CLI's what-if).
    pub user_agent: Option<&'a str>,
    pub decision: &'static str,
    pub matched: &'a [String],
    pub reason: &'a str,
    pub eval_us: u128,
}

/// One `policy-set` line: which policy set became — or failed to become — the one
/// deciding.
///
/// The trail could already say which policy *id* decided a request and not which
/// content that id had, so after a hot reload nothing answered "which policies were
/// live when this decision was made". This line answers it, and it survives the
/// tampering it evidences because the audit log sits outside every write grant the
/// sandboxed agent holds (D13) — an agent that rewrites the policy directory cannot
/// erase the record of having done so.
///
/// **Evidence, not an integrity control.** The hash is written by the same process
/// that read the files, so it supports later comparison and says nothing about
/// authorship. Policy signing is the control and is unbuilt. This must never be
/// described as verifying anything, for the reason [`AuditRecord::user_agent`]
/// already gives: a field that looks like authentication is worse than no field.
#[derive(Debug, Serialize)]
pub struct PolicySetRecord<'a> {
    /// Always `"policy-set"`. See [`AuditRecord::kind`].
    pub kind: &'static str,
    pub ts: String,
    /// `"loaded"`, `"refused"` or `"failed"` — see [`PolicySetOutcome`].
    pub outcome: &'static str,
    /// On `loaded`, the generation that just became active. On the two outcomes that
    /// adopt nothing, the generation still deciding.
    pub generation: u64,
    /// `sha256:<hex>` of the adopted set, or `null` when nothing was adopted:
    /// there is no set to name, and inventing one would be a false alibi.
    pub content_hash: Option<&'a str>,
    /// The loaded policy files, or `null` when nothing was adopted. Control-escaped:
    /// a file name in the policy directory is attacker-influenced in exactly the way
    /// the recording-boundary rule anticipates.
    pub files: Option<Vec<String>>,
    /// Whether the startup isolation check produced advisory warnings — the policy
    /// directory sitting somewhere an agent may write. A property of the process, so
    /// it is carried on every line rather than only the first: an audit line is
    /// supposed to be self-sufficient.
    pub at_risk: bool,
    /// Why a reload adopted nothing, control-escaped. `null` on `loaded`.
    pub reason: Option<String>,
}

/// What a load attempt did, and the evidence that goes with it.
///
/// Attempts that adopt nothing are recorded too, and that is deliberate rather than
/// incidental: a reload refused by the trust re-check *is* the detection event for a
/// policy-directory compromise. Recording only successes would leave it exactly as
/// silent in the durable record as it was before this existed — visible only on
/// stdout, which `pdp-operations` classifies as telemetry rather than the record.
pub enum PolicySetOutcome<'a> {
    /// A set was read, validated and adopted.
    Loaded {
        content_hash: &'a str,
        files: &'a [PathBuf],
    },
    /// The pre-reload trust re-check refused before anything was read.
    Refused { reason: String },
    /// A reload was attempted and failed — invalid Cedar, an unreadable directory.
    Failed { reason: String },
}

impl PolicySetOutcome<'_> {
    /// The wire name, shared by the audit record and the health surface so the two
    /// cannot drift into describing the same event differently.
    pub fn name(&self) -> &'static str {
        match self {
            Self::Loaded { .. } => "loaded",
            Self::Refused { .. } => "refused",
            Self::Failed { .. } => "failed",
        }
    }
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
    ///
    /// `user_agent` is the header the request presented, or `None` when there was no
    /// HTTP request behind the call (the `check` CLI's what-if). It is recorded as
    /// **evidence, not verification** — see [`AuditRecord::user_agent`] for both
    /// halves of why.
    pub fn record(&self, query: &PolicyQuery, decision: &Decision, user_agent: Option<&str>) {
        // The boundary rule: every request-derived value on the line is
        // control-escaped here, at the recording boundary, rather than left to
        // serde — JSON string encoding escapes only C0 controls (U+0000..U+001F),
        // so a DEL or C1 control (CSI among them) would land in the JSONL raw
        // and replay in the terminal of whoever reads the trail. That covers the
        // routing fields below, the wire-chosen identifiers (`request_id`,
        // `session_id`, `backend`) and the observed `user_agent`, which arrives from
        // a *header* and is therefore the one such value that never passed through
        // the body-scraping boundary; the remaining values are covered elsewhere:
        // `agent` comes from our own config, `principal` goes through `{:?}`
        // (which escapes controls), and `resource` is escaped inside
        // `resource_summary`. Honest values contain no control bytes, so they
        // are byte-identical either way. (`record_rejected` is the other
        // recording path: its rule fields are always null, and its scraped
        // context is escaped at the adapter boundary by `scrape_context`.)
        let request_id = crate::sanitize::control_escape(&query.request_id);
        let session_id = crate::sanitize::control_escape(&query.session_id);
        let backend = crate::sanitize::control_escape(&query.backend);
        let user_agent = user_agent.map(crate::sanitize::control_escape);
        let (child_pid, intercept_rule, rule_label) = match &query.target {
            crate::query::Target::Command {
                intercept_rule,
                child_pid,
                ..
            } => (
                Some(*child_pid),
                Some(crate::sanitize::control_escape(intercept_rule)),
                None,
            ),
            crate::query::Target::Endpoint {
                rule_label,
                child_pid,
                ..
            } => (
                Some(*child_pid),
                None,
                Some(crate::sanitize::control_escape(rule_label)),
            ),
        };
        self.append(&AuditRecord {
            kind: "decision",
            ts: now_rfc3339(),
            request_id: Some(&request_id),
            session_id: Some(&session_id),
            backend: Some(&backend),
            agent: Some(&query.agent),
            principal: Some(format!("Nono::Caller::{:?}", query.caller)),
            action: Some(query.action_name()),
            resource: Some(query.resource_summary()),
            child_pid,
            intercept_rule: intercept_rule.as_deref(),
            rule_label: rule_label.as_deref(),
            user_agent: user_agent.as_deref(),
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
    pub fn record_rejected(
        &self,
        context: &RejectedContext,
        decision: &Decision,
        user_agent: Option<&str>,
    ) {
        // Escaped here, on this path too: the context's own fields were escaped at
        // the adapter boundary by `scrape_context`, but the agent never went through
        // it — it comes from a header, not the body.
        let user_agent = user_agent.map(crate::sanitize::control_escape);
        self.append(&AuditRecord {
            kind: "decision",
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
            // Nothing routed a request that was never parsed into a query: the
            // key set stays fixed, so all three are explicit nulls.
            child_pid: None,
            intercept_rule: None,
            rule_label: None,
            user_agent: user_agent.as_deref(),
            decision: if decision.allow { "allow" } else { "deny" },
            matched: &decision.matched,
            reason: &decision.reason,
            eval_us: decision.eval_us,
        });
    }

    /// Record which policy set is deciding, or that an attempt to change it adopted
    /// nothing. Called for the bootstrap load and every reload attempt.
    ///
    /// Like [`Self::record`], a logging failure never changes anything: a reload
    /// that cannot be recorded still took effect, because refusing to serve on a
    /// logging error would convert an observability failure into an outage.
    pub fn record_policy_set(
        &self,
        generation: u64,
        at_risk: bool,
        outcome: &PolicySetOutcome<'_>,
    ) {
        // Escaped at the recording boundary like every other value derived from
        // outside our own config: policy file names are chosen by whoever can write
        // the policy directory, and a reload error string quotes the path it failed
        // on. JSON encoding escapes only C0, so DEL and C1 (CSI among them) would
        // otherwise replay in the terminal of whoever reads the trail.
        let (outcome_name, content_hash, files, reason) = match outcome {
            PolicySetOutcome::Loaded {
                content_hash,
                files,
            } => (
                outcome.name(),
                Some(*content_hash),
                Some(
                    files
                        .iter()
                        .map(|p| crate::sanitize::control_escape(&p.display().to_string()))
                        .collect(),
                ),
                None,
            ),
            PolicySetOutcome::Refused { reason } => (
                outcome.name(),
                None,
                None,
                Some(crate::sanitize::control_escape(reason)),
            ),
            PolicySetOutcome::Failed { reason } => (
                outcome.name(),
                None,
                None,
                Some(crate::sanitize::control_escape(reason)),
            ),
        };
        self.append(&PolicySetRecord {
            kind: "policy-set",
            ts: now_rfc3339(),
            outcome: outcome_name,
            generation,
            content_hash,
            files,
            at_risk,
            reason,
        });
    }

    /// Generic over the record shape so both kinds go through the same reattach,
    /// shrink-detection and short-write rollback path. A second writer would be a
    /// second place for those to drift.
    fn append<R: Serialize>(&self, record: &R) {
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

pub(crate) fn now_rfc3339() -> String {
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

    fn endpoint_query() -> PolicyQuery {
        PolicyQuery {
            agent: "claude-code".to_string(),
            session_id: "proxy".to_string(),
            caller: "proxy".to_string(),
            caller_kind: CallerKind::Session,
            request_id: "p1".to_string(),
            backend: "cedar".to_string(),
            reason: None,
            target: Target::Endpoint {
                route_id: "github-api".to_string(),
                upstream: "https://api.github.com".to_string(),
                method: "GET".to_string(),
                path: "/repos/foo/bar".to_string(),
                rule_label: "endpoint_policy.approve[GET /repos/*]".to_string(),
                child_pid: 0,
            },
        }
    }

    /// Every audit line at `path`, parsed.
    fn lines(path: &Path) -> Vec<serde_json::Value> {
        std::fs::read_to_string(path)
            .unwrap()
            .lines()
            .map(|line| serde_json::from_str(line).unwrap())
            .collect()
    }

    /// The routing context Cedar saw — the pid that asked and the intercept rule
    /// that routed the request here — has to be on the line, or an investigator
    /// reconstructs it from nono's own logs instead of ours. `rule_label` is the
    /// endpoint counterpart and stays an explicit null on a command line: the key
    /// set never changes, so "not known" stays distinguishable from "not recorded".
    #[test]
    fn a_decided_command_line_carries_the_pid_and_rule_that_routed_it() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("decisions.jsonl");
        let log = AuditLog::open(&path).unwrap();

        log.record(&query(), &crate::decision::Decision::deny("nope"), None);

        let line = &lines(&path)[0];
        assert_eq!(line["child_pid"], 42, "{line:#}");
        assert_eq!(line["intercept_rule"], "status", "{line:#}");
        // `line["rule_label"]` is Null for a *missing* key too, so presence is
        // asserted separately: an explicit null is the contract.
        assert!(
            line.as_object().unwrap().contains_key("rule_label"),
            "a command line must carry rule_label as an explicit null, not omit \
             the key: {line:#}"
        );
        assert!(line["rule_label"].is_null(), "{line:#}");
    }

    /// The endpoint half of the same requirement: the route rule label exactly as
    /// sent, the pid as the wire carried it (real nono sends 0 for its proxy),
    /// and an explicitly null `intercept_rule`.
    #[test]
    fn a_decided_endpoint_line_carries_the_rule_label_and_the_proxys_pid() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("decisions.jsonl");
        let log = AuditLog::open(&path).unwrap();

        log.record(
            &endpoint_query(),
            &crate::decision::Decision::deny("nope"),
            None,
        );

        let line = &lines(&path)[0];
        assert_eq!(
            line["rule_label"], "endpoint_policy.approve[GET /repos/*]",
            "the label must survive as sent: {line:#}"
        );
        assert_eq!(line["child_pid"], 0, "{line:#}");
        assert!(
            line.as_object().unwrap().contains_key("intercept_rule"),
            "an endpoint line must carry intercept_rule as an explicit null, not \
             omit the key: {line:#}"
        );
        assert!(line["intercept_rule"].is_null(), "{line:#}");
    }

    /// serde's JSON string encoding escapes only C0 controls (U+0000..U+001F), so
    /// a DEL or C1 control in a request-derived routing field — U+009B is CSI, the
    /// one-byte form of `ESC [` — would land in the file raw and replay in any
    /// terminal that reads the trail. The recording boundary has to escape them
    /// itself, exactly like the resource summary. Asserting on parsed JSON would
    /// prove nothing (parsing folds the escape back), so this reads the raw bytes.
    #[test]
    fn del_and_c1_controls_in_the_routing_fields_never_reach_the_file_raw() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("decisions.jsonl");
        let log = AuditLog::open(&path).unwrap();

        let mut hostile_command = query();
        if let Target::Command { intercept_rule, .. } = &mut hostile_command.target {
            *intercept_rule = "status\u{9b}31mDENY OVERRIDDEN".to_string();
        }
        let mut hostile_endpoint = endpoint_query();
        if let Target::Endpoint { rule_label, .. } = &mut hostile_endpoint.target {
            *rule_label = "rl\u{7f}\u{9b}0m".to_string();
        }

        log.record(
            &hostile_command,
            &crate::decision::Decision::deny("nope"),
            None,
        );
        log.record(
            &hostile_endpoint,
            &crate::decision::Decision::deny("nope"),
            None,
        );

        let raw = std::fs::read(&path).unwrap();
        let csi = "\u{9b}".as_bytes(); // 0xC2 0x9B in UTF-8
        assert!(
            !raw.windows(csi.len()).any(|window| window == csi),
            "a raw CSI byte reached the audit file: {:?}",
            String::from_utf8_lossy(&raw)
        );
        assert!(
            !raw.contains(&0x7f),
            "a raw DEL byte reached the audit file: {:?}",
            String::from_utf8_lossy(&raw)
        );

        // The value must arrive escaped, not truncated or dropped.
        let lines = lines(&path);
        assert_eq!(
            lines[0]["intercept_rule"], "status\\u{009b}31mDENY OVERRIDDEN",
            "{:#}",
            lines[0]
        );
        assert_eq!(
            lines[1]["rule_label"], "rl\\u{007f}\\u{009b}0m",
            "{:#}",
            lines[1]
        );
    }

    /// The same boundary rule, for the identifier fields the first fix stopped
    /// short of: the delta spec's SHALL covers *every* request-derived value, and
    /// `request_id`, `session_id` and `backend` are wire-chosen text a decided
    /// line always carries. serde escapes C0 only, so a C0-based test would pass
    /// while DEL and C1 (CSI, U+009B) still reach the file raw — which is exactly
    /// how the gap survived the first round. Raw file bytes again, decided path.
    #[test]
    fn del_and_c1_controls_in_the_identifier_fields_never_reach_the_file_raw() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("decisions.jsonl");
        let log = AuditLog::open(&path).unwrap();

        let mut hostile = query();
        hostile.request_id = "r1\u{9b}31mDENY OVERRIDDEN".to_string();
        hostile.session_id = "s\u{7f}1".to_string();
        hostile.backend = "cedar\u{9b}0m\u{7f}".to_string();

        log.record(&hostile, &crate::decision::Decision::deny("nope"), None);

        let raw = std::fs::read(&path).unwrap();
        let csi = "\u{9b}".as_bytes(); // 0xC2 0x9B in UTF-8
        assert!(
            !raw.windows(csi.len()).any(|window| window == csi),
            "a raw CSI byte reached the audit file: {:?}",
            String::from_utf8_lossy(&raw)
        );
        assert!(
            !raw.contains(&0x7f),
            "a raw DEL byte reached the audit file: {:?}",
            String::from_utf8_lossy(&raw)
        );

        // Escaped, not truncated or dropped: the identifiers must still identify
        // the request when the trail is reviewed.
        let line = &lines(&path)[0];
        assert_eq!(
            line["request_id"], "r1\\u{009b}31mDENY OVERRIDDEN",
            "{line:#}"
        );
        assert_eq!(line["session_id"], "s\\u{007f}1", "{line:#}");
        assert_eq!(line["backend"], "cedar\\u{009b}0m\\u{007f}", "{line:#}");
    }

    /// The `User-Agent` is request-derived text like any other, so the delta spec's
    /// escape SHALL covers it — and it is the one such value that arrives from a
    /// *header* rather than a body, i.e. from a different module. Pinned at the
    /// recording boundary, on the raw file bytes, on **both** record paths: DEL is
    /// unreachable through a real header (HTTP parsers reject 0x7F) while C1 is not,
    /// so a test that only sent what a socket can carry would leave the DEL half of
    /// the rule unasserted — and the rule has to hold for whatever the extraction
    /// path becomes, not only for what today's parser admits.
    #[test]
    fn del_and_c1_controls_in_the_user_agent_never_reach_the_file_raw() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("decisions.jsonl");
        let log = AuditLog::open(&path).unwrap();

        let hostile = "nono-cli/0.69.0\u{9b}31mDENY\u{7f} OVERRIDDEN";
        log.record(
            &query(),
            &crate::decision::Decision::deny("nope"),
            Some(hostile),
        );
        log.record_rejected(
            &crate::adapter::nono_webhook::RejectedContext::default(),
            &crate::decision::Decision::deny("unsupported"),
            Some(hostile),
        );

        let raw = std::fs::read(&path).unwrap();
        let csi = "\u{9b}".as_bytes(); // 0xC2 0x9B in UTF-8
        assert!(
            !raw.windows(csi.len()).any(|window| window == csi),
            "a raw CSI byte reached the audit file: {:?}",
            String::from_utf8_lossy(&raw)
        );
        assert!(
            !raw.contains(&0x7f),
            "a raw DEL byte reached the audit file: {:?}",
            String::from_utf8_lossy(&raw)
        );

        // Escaped, not truncated or dropped: an odd User-Agent is exactly the
        // evidence an investigator came for.
        let lines = lines(&path);
        let escaped = "nono-cli/0.69.0\\u{009b}31mDENY\\u{007f} OVERRIDDEN";
        assert_eq!(lines[0]["user_agent"], escaped, "{:#}", lines[0]);
        assert_eq!(lines[1]["user_agent"], escaped, "{:#}", lines[1]);
    }

    /// The rejected path's escaping lives in `scrape_context`, one module away
    /// from the sink it protects — exactly the distance a refactor forgets. So
    /// this pin is end to end: hostile bytes enter as a wire body and are
    /// asserted absent from the file's raw bytes. DEL and C1 specifically,
    /// because serde escapes C0 on its own — a C0-only assertion here would stay
    /// green with no escaping at all, which is how the decided-path gap survived
    /// a whole remediation round.
    #[test]
    fn del_and_c1_controls_on_a_rejected_line_never_reach_the_file_raw() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("decisions.jsonl");
        let log = AuditLog::open(&path).unwrap();
        let config = crate::config::Config {
            bind: "127.0.0.1:0".parse().unwrap(),
            policy_dir: dir.path().to_path_buf(),
            audit_log: path.clone(),
            agents: std::collections::BTreeMap::new(),
        };

        let body = serde_json::json!({
            "backend": "ced\u{9b}31mar",
            "request": {
                "capability_type": "netw\u{7f}ork",
                "request_id": "n1\u{9b}0m",
                "session_id": "s\u{7f}1",
            }
        })
        .to_string();
        let context = crate::adapter::nono_webhook::scrape_context(body.as_bytes(), &config);
        log.record_rejected(
            &context,
            &crate::decision::Decision::deny("unsupported"),
            None,
        );

        let raw = std::fs::read(&path).unwrap();
        let csi = "\u{9b}".as_bytes(); // 0xC2 0x9B in UTF-8
        assert!(
            !raw.windows(csi.len()).any(|window| window == csi),
            "a raw CSI byte reached the audit file: {:?}",
            String::from_utf8_lossy(&raw)
        );
        assert!(
            !raw.contains(&0x7f),
            "a raw DEL byte reached the audit file: {:?}",
            String::from_utf8_lossy(&raw)
        );

        // Escaped, not truncated or dropped.
        let line = &lines(&path)[0];
        assert_eq!(line["backend"], "ced\\u{009b}31mar", "{line:#}");
        assert_eq!(line["request_id"], "n1\\u{009b}0m", "{line:#}");
        assert_eq!(line["session_id"], "s\\u{007f}1", "{line:#}");
        assert_eq!(
            line["resource"], "capability_type=netw\\u{007f}ork",
            "{line:#}"
        );
    }

    /// A rejected request never became a `PolicyQuery`, so none of the three
    /// routing fields is known — and each must still be an explicit null, because
    /// the fixed key set is the invariant a consumer leans on. All three line
    /// kinds go through one log so the equality is asserted, not implied. The first
    /// line carries a `User-Agent` and the others do not, so key-set parity is
    /// asserted across lines whose *values* differ: a key that appeared only when
    /// its value was known would break every consumer that reads a fixed schema.
    #[test]
    fn every_line_kind_carries_the_same_key_set_with_nulls_for_the_unknown() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("decisions.jsonl");
        let log = AuditLog::open(&path).unwrap();

        log.record(
            &query(),
            &crate::decision::Decision::deny("command"),
            Some("nono-cli/0.69.0"),
        );
        log.record(
            &endpoint_query(),
            &crate::decision::Decision::deny("endpoint"),
            None,
        );
        log.record_rejected(
            &crate::adapter::nono_webhook::RejectedContext::default(),
            &crate::decision::Decision::deny("rejected"),
            None,
        );

        let lines = lines(&path);
        assert_eq!(lines.len(), 3, "{lines:#?}");
        assert_eq!(lines[0]["user_agent"], "nono-cli/0.69.0", "{:#}", lines[0]);

        let rejected = &lines[2];
        for key in ["child_pid", "intercept_rule", "rule_label", "user_agent"] {
            assert!(
                rejected.as_object().unwrap().contains_key(key),
                "a rejected line must still carry {key} as an explicit null: {rejected:#}"
            );
            assert!(
                rejected[key].is_null(),
                "{key} on a rejected line: {rejected:#}"
            );
        }

        let key_set = |line: &serde_json::Value| -> Vec<String> {
            let mut keys: Vec<String> = line.as_object().unwrap().keys().cloned().collect();
            keys.sort();
            keys
        };
        assert_eq!(
            key_set(&lines[0]),
            key_set(&lines[1]),
            "command and endpoint lines must have the same key set"
        );
        assert_eq!(
            key_set(&lines[0]),
            key_set(&lines[2]),
            "a rejected line must have the same key set as a decided one"
        );
    }

    #[test]
    fn appends_one_json_line_per_decision() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("nested/decisions.jsonl");
        let log = AuditLog::open(&path).unwrap();

        log.record(&query(), &crate::decision::Decision::deny("nope"), None);
        log.record(
            &query(),
            &crate::decision::Decision::deny("still nope"),
            None,
        );

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
        log.record(&query(), &crate::decision::Decision::deny("nope"), None);

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

        log.record(
            &query(),
            &crate::decision::Decision::deny("full disk"),
            None,
        );
        disk.set_budget(usize::MAX);
        log.record(
            &query(),
            &crate::decision::Decision::deny("after recovery"),
            None,
        );

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
            last_reload: Arc::new(arc_swap::ArcSwapOption::empty()),
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
        log.record(&query(), &crate::decision::Decision::deny("nope"), None);

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
        log.record(
            &query(),
            &crate::decision::Decision::deny("after recovery"),
            None,
        );

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
                None,
            );
            std::fs::rename(&path, &rotated).unwrap();
            log.record(
                &query(),
                &crate::decision::Decision::deny("after rotation"),
                None,
            );
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
        log.record(
            &query(),
            &crate::decision::Decision::deny("before delete"),
            None,
        );
        std::fs::remove_file(&path).unwrap();
        log.record(
            &query(),
            &crate::decision::Decision::deny("after delete"),
            None,
        );

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
                None,
            );
            std::fs::rename(&path, &rotated).unwrap();
            // Owner-execute only: the directory can be traversed but nothing new
            // created in it, so the reopen cannot succeed.
            std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o500)).unwrap();
            log.record(
                &query(),
                &crate::decision::Decision::deny("after rotation"),
                None,
            );
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
                None,
            );
            File::create(&path).unwrap(); // O_TRUNC on the same inode
            log.record(
                &query(),
                &crate::decision::Decision::deny("after truncate"),
                None,
            );
        });

        let current = std::fs::read_to_string(&path).unwrap();
        assert!(current.contains("after truncate"), "{current:?}");
        assert!(
            log_text.contains("shrank"),
            "the operator must see that lines were removed: {log_text:?}"
        );
    }

    #[test]
    fn every_decision_line_names_its_shape() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("decisions.jsonl");
        let log = AuditLog::open(&path).unwrap();
        log.record(&query(), &crate::decision::Decision::deny("nope"), None);

        let text = std::fs::read_to_string(&path).unwrap();
        let line: serde_json::Value = serde_json::from_str(text.lines().next().unwrap()).unwrap();
        assert_eq!(
            line["kind"], "decision",
            "a consumer must select records by an explicit value, not by guessing \
             from which keys are present"
        );
    }

    #[test]
    fn a_loaded_policy_set_records_its_hash_files_and_generation() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("decisions.jsonl");
        let log = AuditLog::open(&path).unwrap();
        log.record_policy_set(
            7,
            true,
            &PolicySetOutcome::Loaded {
                content_hash: "sha256:abc",
                files: &[PathBuf::from("/policies/10-git.cedar")],
            },
        );

        let text = std::fs::read_to_string(&path).unwrap();
        let line: serde_json::Value = serde_json::from_str(text.lines().next().unwrap()).unwrap();
        assert_eq!(line["kind"], "policy-set");
        assert_eq!(line["outcome"], "loaded");
        assert_eq!(line["generation"], 7);
        assert_eq!(line["content_hash"], "sha256:abc");
        assert_eq!(line["files"][0], "/policies/10-git.cedar");
        assert_eq!(line["at_risk"], true);
        assert!(line["reason"].is_null(), "nothing failed, so no reason");
    }

    /// The outcome that matters most: a refused reload is the detection event for a
    /// policy-directory compromise, and before this line existed it lived only on
    /// stdout — which `pdp-operations` classifies as telemetry, not the record.
    #[test]
    fn a_refused_reload_records_a_null_hash_and_the_generation_still_deciding() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("decisions.jsonl");
        let log = AuditLog::open(&path).unwrap();
        log.record_policy_set(
            3,
            false,
            &PolicySetOutcome::Refused {
                reason: "mode 0770 on /policies".to_string(),
            },
        );

        let text = std::fs::read_to_string(&path).unwrap();
        let line: serde_json::Value = serde_json::from_str(text.lines().next().unwrap()).unwrap();
        assert_eq!(line["outcome"], "refused");
        assert_eq!(
            line["generation"], 3,
            "the generation recorded is the one still deciding"
        );
        assert!(
            line["content_hash"].is_null(),
            "nothing was adopted, so there is no set to name — inventing one would \
             be a false alibi"
        );
        assert!(line["files"].is_null(), "nothing was adopted");
        assert!(line["reason"].as_str().unwrap().contains("0770"));
    }

    #[test]
    fn a_failed_reload_records_a_null_hash() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("decisions.jsonl");
        let log = AuditLog::open(&path).unwrap();
        log.record_policy_set(
            2,
            false,
            &PolicySetOutcome::Failed {
                reason: "unexpected token".to_string(),
            },
        );

        let text = std::fs::read_to_string(&path).unwrap();
        let line: serde_json::Value = serde_json::from_str(text.lines().next().unwrap()).unwrap();
        assert_eq!(line["outcome"], "failed");
        assert_eq!(line["generation"], 2);
        assert!(line["content_hash"].is_null());
    }

    /// Asserted on the **raw file bytes**, with DEL and a C1 control rather than
    /// `\u{1b}`. The trap AGENTS.md names: a C0-only assertion stays green with the
    /// escaping removed, because JSON encoding escapes C0 anyway. A policy file name
    /// and a reload error's quoted path are both chosen by whoever can write the
    /// policy directory, which is exactly the attacker this escaping is for.
    #[test]
    fn control_bytes_in_a_provenance_line_cannot_reach_a_terminal_raw() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("decisions.jsonl");
        let log = AuditLog::open(&path).unwrap();
        log.record_policy_set(
            1,
            false,
            &PolicySetOutcome::Refused {
                // DEL (U+007F) and CSI (U+009B): neither is escaped by JSON string
                // encoding, so both would land in the file raw without the boundary.
                reason: "bad \u{7f} path \u{9b}31m".to_string(),
            },
        );
        log.record_policy_set(
            1,
            false,
            &PolicySetOutcome::Loaded {
                content_hash: "sha256:abc",
                files: &[PathBuf::from("/p/evil\u{7f}\u{9b}31m.cedar")],
            },
        );

        let raw = std::fs::read(&path).unwrap();
        assert!(
            !raw.contains(&0x7f),
            "a raw DEL reached the audit file: reading the trail in a terminal \
             would replay it"
        );
        // C1 CSI is U+009B, which is 0xc2 0x9b in UTF-8.
        assert!(
            !raw.windows(2).any(|w| w == [0xc2, 0x9b]),
            "a raw C1 CSI reached the audit file"
        );
        // And the line is still parseable, i.e. escaping did not corrupt it.
        let text = String::from_utf8(raw).unwrap();
        for line in text.lines() {
            serde_json::from_str::<serde_json::Value>(line).unwrap();
        }
    }
}
