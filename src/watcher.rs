//! Filesystem watch on the policy directory.
//!
//! Debounces bursts (editors write several events per save), re-checks that the
//! directory is still trusted (`isolation::refuse_untrusted_policy_dir` — modes
//! and owner-or-root ownership on the directory, the loadable files and the
//! ancestor chain alike; the serve layer's concern, kept out of `cedar::engine`
//! so the engine can lift upstream unchanged), and reloads through
//! `Engine::reload`, which keeps the last-good set on failure. Sharing the
//! startup refusal core means a file another user *planted* while the directory
//! was transiently loose stays refused by ownership even after the mode is
//! repaired.
//!
//! The re-check exists because the startup refusal is only as good as the moment
//! it ran: a policy directory that becomes group-writable *mid-session* would
//! otherwise be re-read and adopted silently on the next edit. Two honest limits,
//! accepted and documented rather than hidden: the check runs before the reload
//! reads the files, so a loosening *between* check and read is not caught until
//! the next event (the TOCTOU window shrinks from "forever after startup" to one
//! debounce — and the other-local-user attacker this defends against cannot time
//! a race they do not control); and `notify` watches the policy directory only,
//! so an ancestor going loose does not itself wake the watcher — it is caught at
//! the next policy event. Like the startup check, all of this defends against
//! **other local users**: the sandboxed agent runs as the same uid as the daemon
//! and was never constrained by mode bits, only by its nono profile's write
//! grants.
//!
//! The debounce is bounded at both ends: it ends on [`DEBOUNCE`] of quiet, or at
//! [`DEBOUNCE_CEILING`] from the burst's first event, whichever comes first, and a
//! drain the ceiling ends is reported at WARN. Only the quiet period is under the
//! daemon's control, so without the ceiling a continuous event stream postponed
//! every reload for as long as it lasted and a policy edit made during one was
//! never picked up (Gitea #10). Kept in proportion: that is **liveness, not
//! correctness** — a postponed reload leaves the last-known-good set deciding,
//! which is fail-closed by construction, so no wrong decision is produced. What it
//! defeats is hot-reload itself, silently, while the operator believes the edit
//! took effect.
//!
//! Events are deliberately **not** filtered to the `*.cedar` paths the loader would
//! actually load, even though that would skip a directory read per unrelated write.
//! The trust re-check runs on the same wakeups and cares about things no such filter
//! would pass: a `chmod` that loosens the policy directory produces an event naming
//! the *directory*, not a policy file. Filtering would defer that re-check until
//! something happened to touch a `.cedar` file — a narrower version of the "adopted
//! silently" hole the re-check exists to close. The ceiling already bounds the cost
//! the filter would have saved.

use crate::cedar::engine::Engine;
use notify::{Event, RecommendedWatcher, RecursiveMode, Watcher};
use std::sync::mpsc;
use std::sync::Arc;
use std::time::{Duration, Instant};

/// Quiet period that ends a burst under normal conditions.
const DEBOUNCE: Duration = Duration::from_millis(150);

/// Upper bound on how long a burst may postpone a reload, measured from its first
/// event.
///
/// [`DEBOUNCE`] alone ends the drain on a property of the *event stream* rather than
/// of the daemon, so a stream that never goes quiet postpones every reload for as long
/// as it lasts (Gitea #10). Well above `DEBOUNCE`, so an ordinary multi-write save —
/// or `just install-policies` copying the starter pack, the largest legitimate burst —
/// never reaches it; low enough that the resulting staleness stays under the threshold
/// where an operator re-saves a policy file to check whether it took. Under sustained
/// churn the daemon now reloads on this cadence instead of never, which is a bounded
/// directory read plus a re-validation.
const DEBOUNCE_CEILING: Duration = Duration::from_secs(2);

/// Everything needed to write a `policy-set` provenance line, bundled so the
/// watcher takes one argument rather than growing a parameter per field.
///
/// `at_risk` is established once, by `isolation::check` at startup, and never
/// changes for the life of the process — but it is carried on every line rather
/// than looked up, because an audit line is supposed to be self-sufficient for
/// review. A reader should not have to find the first line of the run to learn
/// whether this daemon's policy directory sat somewhere an agent could write.
#[derive(Clone)]
pub struct Provenance {
    pub audit: Arc<crate::audit::AuditLog>,
    pub at_risk: bool,
    /// The most recent reload attempt, for the health surface. `None` until one has
    /// been attempted — the bootstrap load is described by the generation and load
    /// time `/healthz` already reports, and synthesising a reload record for it
    /// would make "has anything happened since startup" unanswerable.
    pub last_reload: Arc<arc_swap::ArcSwapOption<LastReload>>,
}

/// What happened to the policy set most recently, as `/healthz` reports it.
///
/// No reason text and no path, deliberately. `/healthz` is unauthenticated, and a
/// reload error names the file it failed on — carrying it here would re-introduce
/// the absolute-path disclosure that removing `policy_dir` exists to close. The
/// outcome says *that* something was refused; the audit trail's `policy-set` record
/// and stdout say *what*, and both sit behind filesystem permissions.
#[derive(Debug, Clone, serde::Serialize)]
pub struct LastReload {
    /// `"loaded"`, `"refused"` or `"failed"`.
    pub outcome: &'static str,
    /// RFC 3339 UTC.
    pub at: String,
}

impl Provenance {
    /// Record what a load attempt did, to **both** surfaces that report it.
    ///
    /// One call updating the trail and the health status is the point rather than a
    /// convenience: there is no code path that writes one without the other, so
    /// `/healthz` and the audit record cannot disagree about the last reload. Two
    /// independent updates would be two things to keep in step, and the failure —
    /// monitoring saying "loaded" while the trail says "refused" — would be silent
    /// and would discredit both.
    pub fn record(&self, generation: u64, outcome: &crate::audit::PolicySetOutcome<'_>) {
        self.audit
            .record_policy_set(generation, self.at_risk, outcome);
        self.last_reload.store(Some(Arc::new(LastReload {
            outcome: outcome.name(),
            at: crate::audit::now_rfc3339(),
        })));
    }

    /// Record an adopted **reload** from the engine's own snapshot, which is the only
    /// place the hash and the file list are guaranteed to belong to the same load.
    pub fn record_loaded(&self, loaded: &crate::cedar::engine::LoadedPolicies) {
        self.record(
            loaded.generation,
            &crate::audit::PolicySetOutcome::Loaded {
                content_hash: &loaded.content_hash,
                files: &loaded.files,
            },
        );
    }

    /// Record the **bootstrap** load: the trail only, never the reload status.
    ///
    /// `/healthz` already describes this load with `generation` and `loaded_at`.
    /// Recording it as a reload as well would leave no way to ask "has anything
    /// happened since startup", which is the question the field exists to answer.
    pub fn record_bootstrap(&self, loaded: &crate::cedar::engine::LoadedPolicies) {
        self.audit.record_policy_set(
            loaded.generation,
            self.at_risk,
            &crate::audit::PolicySetOutcome::Loaded {
                content_hash: &loaded.content_hash,
                files: &loaded.files,
            },
        );
    }
}

/// Start watching `engine.policy_dir()`. Keep the returned watcher alive — its
/// drop stops the watch.
///
/// Takes the provenance recorder because a watcher that swaps the deciding policy
/// set without being able to record what it adopted cannot satisfy
/// `decision-audit-log`'s provenance requirement — including, and especially, on
/// the attempts that adopt nothing.
pub fn spawn(
    engine: Arc<Engine>,
    provenance: Provenance,
) -> notify::Result<RecommendedWatcher> {
    let (tx, rx) = mpsc::channel::<notify::Result<Event>>();
    let mut watcher = notify::recommended_watcher(tx)?;
    watcher.watch(engine.policy_dir(), RecursiveMode::NonRecursive)?;

    // The watch thread logs with whatever dispatcher its spawner had. A bare
    // `thread::spawn` would fall back to the process-global default — identical in
    // production, where `main` installs the global subscriber before anything else,
    // but it would silently bypass a thread-local one, and "the operator is told at
    // ERROR" is a behaviour the reload-refusal tests have to be able to observe.
    let dispatch = tracing::dispatcher::get_default(|current| current.clone());
    std::thread::Builder::new()
        .name("policy-watcher".to_string())
        .spawn(move || {
            let _dispatch = tracing::dispatcher::set_default(&dispatch);
            while let Ok(first) = rx.recv() {
                if let Err(e) = first {
                    tracing::warn!(error = %e, "policy watch error");
                    continue;
                }
                // Drain the burst an editor save produces — but never past the
                // ceiling. `while rx.recv_timeout(DEBOUNCE).is_ok() {}` exits only on
                // quiet, which the event stream controls and the daemon does not, so a
                // stream that never goes quiet postponed every reload for as long as
                // it lasted. Waiting `min(DEBOUNCE, remaining)` rather than a flat
                // `DEBOUNCE` matters: without it the bound could be overshot by up to
                // one debounce on the last iteration.
                let burst_started = Instant::now();
                let cut_short = loop {
                    let elapsed = burst_started.elapsed();
                    if elapsed >= DEBOUNCE_CEILING {
                        break true;
                    }
                    let wait = DEBOUNCE.min(DEBOUNCE_CEILING - elapsed);
                    if rx.recv_timeout(wait).is_err() {
                        // A wait the ceiling had to truncate is not the debounce's
                        // quiet period, so it counts as the ceiling ending the drain
                        // rather than the burst ending on its own.
                        break wait < DEBOUNCE;
                    }
                };
                if cut_short {
                    // WARN, not INFO and not ERROR: nothing has failed and the active
                    // set is intact, so ERROR would overstate it and break this repo's
                    // rule that ERROR means the operator must act — but continuous
                    // traffic in a policy directory is either a misconfiguration or a
                    // symptom, and INFO would bury it in reload chatter. One line per
                    // truncated drain, because the condition really is ongoing.
                    tracing::warn!(
                        ceiling = ?DEBOUNCE_CEILING,
                        "policy reload debounce cut short by its ceiling; the policy \
                         directory is producing continuous filesystem events"
                    );
                }
                // Re-check trust after the drain and BEFORE the reload touches the
                // directory, so nothing read from a loosened tree can become the
                // active set. On refusal the in-memory set predates the loosening
                // and is the only trusted policy state left, so it stays (same
                // posture as a broken edit, D7) and the watch survives — repairing
                // the mode and editing again recovers without a restart. ERROR,
                // not WARN: a quieter level would let the "adopted silently"
                // failure this closes recur one level down. See the module docs
                // for the TOCTOU window and the other-local-users scope.
                if let Err(e) = crate::isolation::refuse_untrusted_policy_dir(engine.policy_dir()) {
                    tracing::error!(
                        error = %e,
                        "policy directory is no longer trusted; keeping the \
                         last-good policy set"
                    );
                    // To the trail as well as to stdout, and this is the line that
                    // matters most: a refusal is the *detection event* for someone
                    // having changed the policy directory. stdout is telemetry and
                    // goes wherever the operator redirected it; the audit log sits
                    // outside every write grant the agent holds, so this record
                    // survives the tampering it evidences.
                    provenance.record(
                        engine.snapshot().generation,
                        &crate::audit::PolicySetOutcome::Refused {
                            reason: e.to_string(),
                        },
                    );
                    continue;
                }
                match engine.reload() {
                    Ok(generation) => {
                        tracing::info!(generation, "policies reloaded from disk");
                        // From the snapshot, not from `generation` plus a re-read:
                        // the hash and the file list have to come from the same load
                        // that just became active, or the line describes a set that
                        // never decided anything.
                        provenance.record_loaded(&engine.snapshot());
                    }
                    Err(e) => {
                        tracing::error!(
                            error = %e,
                            "policy reload failed; keeping previous policy set"
                        );
                        provenance.record(
                            engine.snapshot().generation,
                            &crate::audit::PolicySetOutcome::Failed {
                                reason: e.to_string(),
                            },
                        );
                    }
                }
            }
        })
        .map_err(notify::Error::io)?;

    Ok(watcher)
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use std::sync::Arc;
    use std::time::{Duration, Instant};

    const POLICY: &str = r#"permit (principal, action == Nono::Action::"launchCommand", resource)
        when { resource.command == "git" };"#;

    #[test]
    fn edits_trigger_a_reload() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("p.cedar"), POLICY).unwrap();
        let schema = crate::cedar::schema::load().unwrap();
        let engine = Arc::new(
            crate::cedar::engine::Engine::bootstrap(schema, dir.path().to_path_buf()).unwrap(),
        );
        let (prov, _audit_dir, _audit_path) = provenance();
        let _watcher = spawn(Arc::clone(&engine), prov).unwrap();

        std::fs::write(
            dir.path().join("p.cedar"),
            r#"forbid (principal, action, resource);"#,
        )
        .unwrap();

        let deadline = Instant::now() + Duration::from_secs(5);
        while Instant::now() < deadline && engine.snapshot().generation == 1 {
            std::thread::sleep(Duration::from_millis(50));
        }
        assert_eq!(engine.snapshot().generation, 2, "watcher did not reload");
    }

    /// A `git status` a policy in this module's `POLICY` permits, so a decision can
    /// stand in for "which policy set is active".
    fn git_status() -> crate::query::PolicyQuery {
        crate::query::PolicyQuery {
            agent: "claude-code".to_string(),
            session_id: "s1".to_string(),
            caller: "session".to_string(),
            caller_kind: crate::query::CallerKind::Session,
            request_id: "r1".to_string(),
            backend: "cedar".to_string(),
            reason: None,
            target: crate::query::Target::Command {
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


    /// A provenance recorder writing to a real audit log, plus the path so a test
    /// can read back what the watcher recorded.
    ///
    /// The log gets its **own** temp dir, never the policy directory. That is the
    /// production rule (D13 — the trail must sit outside anything the agent can
    /// write), and here it is also load-bearing for the test itself: an audit log
    /// inside the watched directory would make every recorded line a filesystem
    /// event, and the watcher would reload forever off its own output.
    fn provenance() -> (Provenance, tempfile::TempDir, std::path::PathBuf) {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("decisions.jsonl");
        let audit = Arc::new(crate::audit::AuditLog::open(&path).unwrap());
        (
            Provenance {
                audit,
                at_risk: false,
                last_reload: Arc::new(arc_swap::ArcSwapOption::empty()),
            },
            dir,
            path,
        )
    }

    /// The `policy-set` lines in a trail, in order.
    fn policy_set_lines(path: &std::path::Path) -> Vec<serde_json::Value> {
        let text = std::fs::read_to_string(path).unwrap_or_default();
        text.lines()
            .filter_map(|l| serde_json::from_str::<serde_json::Value>(l).ok())
            .filter(|v| v["kind"] == "policy-set")
            .collect()
    }

    /// Wait until `predicate` holds, or give up. Returns whether it held.
    fn within(timeout: Duration, predicate: impl Fn() -> bool) -> bool {
        let deadline = Instant::now() + timeout;
        while Instant::now() < deadline {
            if predicate() {
                return true;
            }
            std::thread::sleep(Duration::from_millis(25));
        }
        predicate()
    }

    /// Block until the watch thread has processed an event and refused the reload.
    ///
    /// **Call this before asserting the absence of an adoption, never after.** The
    /// refusal tests below prove a negative — that a policy set read from a loosened
    /// tree was not adopted — and a negative is only evidence once the thing that
    /// would have adopted it has actually run. The watch thread has to receive the
    /// `notify` event, drain the debounce and run the trust re-check before it can
    /// refuse, so a bare `!within(…)` over the adoption predicate returns "nothing was
    /// adopted" just as readily when nothing has happened *yet*.
    ///
    /// That was Gitea #31: one window was serving as both "long enough to prove
    /// nothing was adopted" and "long enough for the refusal to have been logged", and
    /// only the first was guaranteed. It failed ~1 run in 10-20 under load, and — the
    /// reason it was worth fixing beyond the red run — it would equally have sat
    /// *green* through a genuine regression in the re-check, because the test could
    /// pass before the behaviour happened.
    ///
    /// The timeout is deliberately generous. A slow machine must stay green; only a
    /// re-check that never refuses may go red. Waiting on the log is not a proxy for
    /// the behaviour under test — `pdp-operations` requires the refusal to reach the
    /// operator at ERROR, so "the operator was told" *is* the deliverable.
    fn await_refusal_at_error(capture: &crate::test_log::Capture) {
        assert!(
            within(Duration::from_secs(10), || capture.text().contains("ERROR")),
            "no refusal ever reached the log at ERROR: either the trust re-check did \
             not run, or it ran and did not refuse. Captured log: {:?}",
            capture.text()
        );
    }

    /// The mid-session typo an operator actually makes takes the *watcher's* failure
    /// branch, not a direct `Engine::reload` call. Retention is covered at the engine
    /// level, but nothing exercised the watcher thread's own error path: a `?` or a
    /// `panic!` there — or an `unwrap` on the reload result — would take the whole
    /// watch down with it, and every later edit would be silently ignored until a
    /// restart while the daemon kept answering from the stale set.
    ///
    /// The repair at the end is what proves the failure was *survived* rather than
    /// merely slept through: only a live watcher thread can pick it up.
    #[test]
    fn a_broken_edit_through_the_watcher_keeps_the_last_good_policies() {
        let dir = tempfile::tempdir().unwrap();
        let policy = dir.path().join("p.cedar");
        std::fs::write(&policy, POLICY).unwrap();
        let schema = crate::cedar::schema::load().unwrap();
        let engine = Arc::new(
            crate::cedar::engine::Engine::bootstrap(schema, dir.path().to_path_buf()).unwrap(),
        );
        let (prov, _audit_dir, _audit_path) = provenance();
        let _watcher = spawn(Arc::clone(&engine), prov).unwrap();

        assert!(
            engine.evaluate(&git_status()).allow,
            "the last-good set permits git before the broken edit"
        );

        std::fs::write(&policy, "permit (principal, action").unwrap();
        // Give the watcher longer than its debounce to fail the reload, then hold the
        // assertion for a while: a set that is replaced late is as bad as one
        // replaced now.
        assert!(
            !within(Duration::from_secs(2), || engine.snapshot().generation != 1
                || !engine.evaluate(&git_status()).allow),
            "a syntax error mid-session must not change the active policy set: \
             generation {}",
            engine.snapshot().generation
        );

        // The watcher is still alive: repair the file and the next edit takes effect.
        std::fs::write(&policy, r#"forbid (principal, action, resource);"#).unwrap();
        assert!(
            within(Duration::from_secs(5), || engine.snapshot().generation == 2),
            "the watcher stopped watching after the failed reload; generation {}",
            engine.snapshot().generation
        );
        assert!(
            !engine.evaluate(&git_status()).allow,
            "the repaired policy set must be the one deciding"
        );
    }

    fn chmod(path: &std::path::Path, mode: u32) {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode)).unwrap();
    }

    /// The startup refusal is only as good as the moment it ran: a policy directory
    /// that becomes group-writable *while the daemon runs* used to be re-read and
    /// adopted silently ~150 ms after the next edit. The re-check runs here in the
    /// watcher, after the debounce drain and before `Engine::reload` touches the
    /// directory, so nothing read from the loosened tree can become the active set.
    /// Same containment posture as a broken edit: keep the last-good set, tell the
    /// operator at ERROR — a WARN would let the "adopted silently" failure recur one
    /// level down. (Like the startup check, this defends against other local users;
    /// the sandboxed agent runs as the same uid and was never stopped by mode bits.)
    #[test]
    fn a_policy_dir_loosened_mid_session_is_refused_and_the_last_good_set_stays() {
        let dir = tempfile::tempdir().unwrap();
        let policy = dir.path().join("p.cedar");
        std::fs::write(&policy, POLICY).unwrap();
        let schema = crate::cedar::schema::load().unwrap();
        let engine = Arc::new(
            crate::cedar::engine::Engine::bootstrap(schema, dir.path().to_path_buf()).unwrap(),
        );
        // Capture before the spawn: the watch thread logs on its own thread and
        // inherits the dispatcher of whoever spawned it, so a capture installed
        // later would never see its refusal.
        let capture = crate::test_log::capture();
        let (prov, _audit_dir, _audit_path) = provenance();
        let _watcher = spawn(Arc::clone(&engine), prov).unwrap();
        assert!(
            engine.evaluate(&git_status()).allow,
            "the last-good set permits git status before the loosening"
        );

        // Loosen the directory, then make an edit that would flip the decision if
        // the reload were wrongly adopted.
        chmod(dir.path(), 0o770);
        std::fs::write(&policy, r#"forbid (principal, action, resource);"#).unwrap();

        // Order matters — see `await_refusal_at_error`. The refusal is the proof that
        // the watcher reached the re-check at all; only then does "nothing was
        // adopted" mean the re-check held rather than that nothing has happened yet.
        await_refusal_at_error(&capture);
        assert!(
            !within(Duration::from_secs(1), || engine.snapshot().generation != 1
                || !engine.evaluate(&git_status()).allow),
            "a policy set read from a loosened directory must not be adopted, and a \
             set adopted late is as bad as one adopted now: generation {}",
            engine.snapshot().generation
        );
        assert_eq!(
            engine.snapshot().generation,
            1,
            "the last-good set must still be the active one"
        );
        let log = capture.text();
        assert!(log.contains("0770"), "the mode must be named: {log:?}");
        assert!(
            log.contains(&dir.path().display().to_string()),
            "the offending path must be named: {log:?}"
        );
    }

    /// The second WHEN disjunct of the reload re-check scenario: a loadable
    /// policy *file* going loose mid-session, with the directory's own mode
    /// still tight. A file another local user can rewrite in place is a policy
    /// someone else authors, so the re-check must refuse before the reload
    /// adopts what was read — same containment as the directory case: last-good
    /// set stays, ERROR names the file and its mode.
    #[test]
    fn a_policy_file_loosened_mid_session_is_refused_and_the_last_good_set_stays() {
        let dir = tempfile::tempdir().unwrap();
        let policy = dir.path().join("p.cedar");
        std::fs::write(&policy, POLICY).unwrap();
        let schema = crate::cedar::schema::load().unwrap();
        let engine = Arc::new(
            crate::cedar::engine::Engine::bootstrap(schema, dir.path().to_path_buf()).unwrap(),
        );
        let capture = crate::test_log::capture();
        let (prov, _audit_dir, _audit_path) = provenance();
        let _watcher = spawn(Arc::clone(&engine), prov).unwrap();
        assert!(
            engine.evaluate(&git_status()).allow,
            "the last-good set permits git status before the loosening"
        );

        // Loosen the file, then give it content that would flip the decision if
        // the reload were wrongly adopted. `std::fs::write` truncates in place,
        // so the loosened mode survives the edit.
        chmod(&policy, 0o660);
        std::fs::write(&policy, r#"forbid (principal, action, resource);"#).unwrap();

        // Order matters — see `await_refusal_at_error`.
        await_refusal_at_error(&capture);
        assert!(
            !within(Duration::from_secs(1), || engine.snapshot().generation != 1
                || !engine.evaluate(&git_status()).allow),
            "a policy set read past a loosened file must not be adopted, and a set \
             adopted late is as bad as one adopted now: generation {}",
            engine.snapshot().generation
        );
        assert_eq!(
            engine.snapshot().generation,
            1,
            "the last-good set must still be the active one"
        );
        let log = capture.text();
        assert!(log.contains("0660"), "the mode must be named: {log:?}");
        assert!(
            log.contains(&policy.display().to_string()),
            "the offending file must be named, not just the directory: {log:?}"
        );
    }

    /// The third WHEN disjunct: an existing *ancestor* going loose mid-session.
    /// A mode change on the ancestor alone does not wake the watcher (`notify`
    /// watches the policy directory only — documented limit), so the refusal
    /// lands when the next policy-directory event fires; what matters is that
    /// the loosened chain is refused before anything read through it becomes
    /// the active set.
    #[test]
    fn a_loose_ancestor_mid_session_is_refused_when_the_next_edit_fires() {
        let root = tempfile::tempdir().unwrap();
        let holder = root.path().join("holder");
        std::fs::create_dir(&holder).unwrap();
        let dir = holder.join("policies");
        std::fs::create_dir(&dir).unwrap();
        let policy = dir.join("p.cedar");
        std::fs::write(&policy, POLICY).unwrap();
        let schema = crate::cedar::schema::load().unwrap();
        let engine =
            Arc::new(crate::cedar::engine::Engine::bootstrap(schema, dir.clone()).unwrap());
        let capture = crate::test_log::capture();
        let (prov, _audit_dir, _audit_path) = provenance();
        let _watcher = spawn(Arc::clone(&engine), prov).unwrap();
        assert!(
            engine.evaluate(&git_status()).allow,
            "the last-good set permits git status before the loosening"
        );

        chmod(&holder, 0o770);
        std::fs::write(&policy, r#"forbid (principal, action, resource);"#).unwrap();

        // Order matters — see `await_refusal_at_error`. #31 named two tests; this one
        // has the same shape and was found by the controlled experiment that
        // reproduced the mechanism, not by the intermittent failure.
        await_refusal_at_error(&capture);
        assert!(
            !within(Duration::from_secs(1), || engine.snapshot().generation != 1
                || !engine.evaluate(&git_status()).allow),
            "a policy set below a loosened ancestor must not be adopted, and a set \
             adopted late is as bad as one adopted now: generation {}",
            engine.snapshot().generation
        );
        assert_eq!(
            engine.snapshot().generation,
            1,
            "the last-good set must still be the active one"
        );
        let log = capture.text();
        assert!(log.contains("0770"), "the mode must be named: {log:?}");
        assert!(
            log.contains(&holder.display().to_string()),
            "the ancestor must be named — the operator would otherwise stare at a \
             tight policy dir wondering what to fix: {log:?}"
        );
    }

    /// The reload half of "an unenumerable listing is never a silent drop", from
    /// the operator's chair: the policy directory stops being listable
    /// mid-session. The last-good set must keep deciding and the refusal must be
    /// on the log at ERROR naming the directory. In the serve path the pre-reload
    /// trust re-check reads the same listing and refuses first, so that is the
    /// branch that usually fires here; retention on the reload error itself is
    /// pinned at the engine level
    /// (`a_reload_that_cannot_enumerate_the_directory_keeps_the_last_good_set`).
    #[test]
    fn an_unlistable_policy_dir_mid_session_keeps_last_good_and_logs_error() {
        let dir = tempfile::tempdir().unwrap();
        let policy = dir.path().join("p.cedar");
        std::fs::write(&policy, POLICY).unwrap();
        let schema = crate::cedar::schema::load().unwrap();
        let engine = Arc::new(
            crate::cedar::engine::Engine::bootstrap(schema, dir.path().to_path_buf()).unwrap(),
        );
        let capture = crate::test_log::capture();
        let (prov, _audit_dir, _audit_path) = provenance();
        let _watcher = spawn(Arc::clone(&engine), prov).unwrap();

        // Write+execute, no read: a new file can still be created (the watch
        // event), but the listing fails with EACCES — the closest hermetic
        // stand-in for an enumeration failure at reload time. The new file is
        // deliberately not valid Cedar, so even a straggling event after the
        // repair below cannot advance the generation and race the assertions.
        chmod(dir.path(), 0o300);
        std::fs::write(dir.path().join("q.cedar"), "not cedar at all").unwrap();

        assert!(
            within(Duration::from_secs(5), || capture.text().contains("ERROR")),
            "the refusal must reach the log at ERROR, not a level an operator \
             filters out: {:?}",
            capture.text()
        );
        chmod(dir.path(), 0o700);

        let log = capture.text();
        assert!(
            log.contains(&dir.path().display().to_string()),
            "the ERROR must name the directory: {log:?}"
        );
        assert_eq!(
            engine.snapshot().generation,
            1,
            "the last-good set must stay active: {log:?}"
        );
        assert!(
            engine.evaluate(&git_status()).allow,
            "the last-good set must keep deciding"
        );
    }

    /// A refusal must not take the watch down with it: the loosening may be a
    /// transient `chmod`, and a dead watcher would freeze the daemon on the
    /// last-good set forever while looking healthy. Repairing the mode and editing
    /// again must be adopted without a restart.
    #[test]
    fn repairing_the_mode_lets_the_watcher_adopt_the_next_edit() {
        let dir = tempfile::tempdir().unwrap();
        let policy = dir.path().join("p.cedar");
        std::fs::write(&policy, POLICY).unwrap();
        let schema = crate::cedar::schema::load().unwrap();
        let engine = Arc::new(
            crate::cedar::engine::Engine::bootstrap(schema, dir.path().to_path_buf()).unwrap(),
        );
        let capture = crate::test_log::capture();
        let (prov, _audit_dir, _audit_path) = provenance();
        let _watcher = spawn(Arc::clone(&engine), prov).unwrap();

        chmod(dir.path(), 0o770);
        std::fs::write(&policy, r#"forbid (principal, action, resource);"#).unwrap();
        // Wait until the refusal is on the record, so the repair below is provably
        // a recovery from it and not a race that never saw the loose mode.
        assert!(
            within(Duration::from_secs(5), || capture.text().contains("ERROR")),
            "no refusal was ever logged: {:?}",
            capture.text()
        );

        chmod(dir.path(), 0o700);
        std::fs::write(&policy, r#"forbid (principal, action, resource);"#).unwrap();
        assert!(
            within(Duration::from_secs(5), || engine.snapshot().generation >= 2),
            "the watcher stopped watching after the refusal; generation {}",
            engine.snapshot().generation
        );
        assert!(
            !engine.evaluate(&git_status()).allow,
            "the repaired edit must be the one deciding"
        );
    }

    /// The drain used to end only on `DEBOUNCE` of quiet, which is a property of the
    /// event stream and not of the daemon: while events kept arriving the reload was
    /// postponed indefinitely, so a policy edit made during a stream was never picked
    /// up and nothing said so (Gitea #10).
    ///
    /// Severity, stated honestly rather than inflated: this is **liveness, not
    /// correctness**. A postponed reload leaves the last-known-good set deciding,
    /// which is fail-closed by construction, so no wrong decision is ever produced.
    /// What it defeats is hot-reload itself, silently, while the operator's mental
    /// model says the edit took effect.
    ///
    /// The churn file is deliberately **not** a `*.cedar` file: events the loader
    /// would ignore still drive the drain, which is half of what made the unbounded
    /// version so easy to trip. It is also why the assertion is on the **decision**
    /// rather than the generation — churn-driven reloads advance the generation on
    /// their own, so only a flipped decision proves *this edit* was adopted.
    ///
    /// The 20 ms churn rate is not a guess. Measured on this platform before the test
    /// was written: it kept an unbounded 150 ms drain alive across 853 delivered
    /// events for a full 5 s probe, never once terminating. Without that margin the
    /// test could pass against unfixed code and prove nothing.
    #[test]
    fn a_continuous_event_stream_cannot_postpone_a_reload_forever() {
        use std::sync::atomic::{AtomicBool, Ordering};

        let dir = tempfile::tempdir().unwrap();
        let policy = dir.path().join("p.cedar");
        std::fs::write(&policy, POLICY).unwrap();
        let schema = crate::cedar::schema::load().unwrap();
        let engine = Arc::new(
            crate::cedar::engine::Engine::bootstrap(schema, dir.path().to_path_buf()).unwrap(),
        );
        let capture = crate::test_log::capture();
        let (prov, _audit_dir, _audit_path) = provenance();
        let _watcher = spawn(Arc::clone(&engine), prov).unwrap();

        let stop = Arc::new(AtomicBool::new(false));
        let churn = {
            let stop = Arc::clone(&stop);
            let churn_file = dir.path().join("churn.txt");
            std::thread::spawn(move || {
                let mut i = 0u32;
                while !stop.load(Ordering::Relaxed) {
                    // Ignored: the tempdir may already be gone if the test panicked.
                    let _ = std::fs::write(&churn_file, i.to_string());
                    i = i.wrapping_add(1);
                    std::thread::sleep(Duration::from_millis(20));
                }
            })
        };

        // Let the drain be well underway before the edit lands, so the edit is made
        // into a stream rather than before one.
        std::thread::sleep(Duration::from_millis(300));
        std::fs::write(&policy, r#"forbid (principal, action, resource);"#).unwrap();

        let adopted = within(Duration::from_secs(5), || {
            !engine.evaluate(&git_status()).allow
        });
        // Stop the churn before asserting: a live thread writing into a tempdir being
        // dropped by a panicking unwind is a distraction in the failure output.
        stop.store(true, Ordering::Relaxed);
        churn.join().unwrap();

        assert!(
            adopted,
            "a policy edit made during a continuous event stream must still be \
             adopted within the debounce ceiling, not held until the stream stops; \
             generation {}",
            engine.snapshot().generation
        );
        let log = capture.text();
        assert!(
            log.contains("cut short"),
            "a drain ended by the ceiling must be reported, so sustained traffic in \
             the policy directory is visible rather than inferred from reloads that \
             merely seem late: {log:?}"
        );
    }

    /// The trail could name which policy *id* decided a request and not which
    /// content that id had, so after a reload nothing answered "which policies were
    /// live when this decision was made". These tests pin that every load attempt
    /// leaves that answer behind — including the attempts that adopt nothing, which
    /// is where the value is: a refusal is the detection event for someone having
    /// changed the policy directory.
    #[test]
    fn an_adopted_reload_records_a_loaded_line_with_a_changed_hash() {
        let dir = tempfile::tempdir().unwrap();
        let policy = dir.path().join("p.cedar");
        std::fs::write(&policy, POLICY).unwrap();
        let schema = crate::cedar::schema::load().unwrap();
        let engine = Arc::new(
            crate::cedar::engine::Engine::bootstrap(schema, dir.path().to_path_buf()).unwrap(),
        );
        let before = engine.snapshot().content_hash.clone();
        let (prov, _audit_dir, audit_path) = provenance();
        let _watcher = spawn(Arc::clone(&engine), prov).unwrap();

        std::fs::write(&policy, r#"forbid (principal, action, resource);"#).unwrap();
        assert!(
            within(Duration::from_secs(5), || !policy_set_lines(&audit_path)
                .is_empty()),
            "the adopted reload was never recorded"
        );

        let lines = policy_set_lines(&audit_path);
        let last = lines.last().unwrap();
        assert_eq!(last["kind"], "policy-set");
        assert_eq!(last["outcome"], "loaded");
        assert_eq!(last["generation"], 2);
        assert_ne!(
            last["content_hash"].as_str().unwrap(),
            before,
            "the content changed, so the recorded hash must differ — otherwise the \
             line cannot distinguish the set that decided"
        );
        assert!(last["files"]
            .as_array()
            .unwrap()
            .iter()
            .any(|f| f.as_str().unwrap().ends_with("p.cedar")));
    }

    /// The line that matters most. Before this existed, a refused reload was
    /// visible only on stdout — which `pdp-operations` classifies as telemetry
    /// rather than the record, and which goes wherever the operator redirected it.
    #[test]
    fn a_refused_reload_is_recorded_in_the_trail_not_only_on_stdout() {
        let dir = tempfile::tempdir().unwrap();
        let policy = dir.path().join("p.cedar");
        std::fs::write(&policy, POLICY).unwrap();
        let schema = crate::cedar::schema::load().unwrap();
        let engine = Arc::new(
            crate::cedar::engine::Engine::bootstrap(schema, dir.path().to_path_buf()).unwrap(),
        );
        let (prov, _audit_dir, audit_path) = provenance();
        let _watcher = spawn(Arc::clone(&engine), prov).unwrap();

        chmod(dir.path(), 0o770);
        std::fs::write(&policy, r#"forbid (principal, action, resource);"#).unwrap();

        assert!(
            within(Duration::from_secs(10), || !policy_set_lines(&audit_path)
                .is_empty()),
            "the refusal never reached the audit trail"
        );
        let lines = policy_set_lines(&audit_path);
        let last = lines.last().unwrap();
        assert_eq!(last["outcome"], "refused");
        assert!(
            last["content_hash"].is_null(),
            "nothing was adopted, so there is no set to name"
        );
        assert_eq!(
            last["generation"], 1,
            "the generation recorded is the one still deciding"
        );
        assert!(
            last["reason"].as_str().unwrap().contains("0770"),
            "the reason must name the offending mode: {last}"
        );
    }

    #[test]
    fn a_failed_reload_is_recorded_in_the_trail() {
        let dir = tempfile::tempdir().unwrap();
        let policy = dir.path().join("p.cedar");
        std::fs::write(&policy, POLICY).unwrap();
        let schema = crate::cedar::schema::load().unwrap();
        let engine = Arc::new(
            crate::cedar::engine::Engine::bootstrap(schema, dir.path().to_path_buf()).unwrap(),
        );
        let (prov, _audit_dir, audit_path) = provenance();
        let _watcher = spawn(Arc::clone(&engine), prov).unwrap();

        std::fs::write(&policy, "permit (principal, action").unwrap();

        assert!(
            within(Duration::from_secs(10), || !policy_set_lines(&audit_path)
                .is_empty()),
            "the failed reload never reached the audit trail"
        );
        let lines = policy_set_lines(&audit_path);
        let last = lines.last().unwrap();
        assert_eq!(last["outcome"], "failed");
        assert!(last["content_hash"].is_null());
        assert_eq!(
            last["generation"], 1,
            "the generation recorded is the one still deciding"
        );
    }

    /// The link between the two halves of #7: the watcher's refusal has to reach the
    /// health surface, not just the trail. Both ends are tested elsewhere — the
    /// `policy-set` line here, the `/healthz` body in `tests/server.rs` — and without
    /// this the *connection* between them is the untested part.
    ///
    /// It also pins the property that makes them trustworthy: one recording call
    /// updates both, so monitoring cannot report "loaded" while the trail says
    /// "refused".
    #[test]
    fn a_refusal_reaches_the_health_surface_and_agrees_with_the_trail() {
        let dir = tempfile::tempdir().unwrap();
        let policy = dir.path().join("p.cedar");
        std::fs::write(&policy, POLICY).unwrap();
        let schema = crate::cedar::schema::load().unwrap();
        let engine = Arc::new(
            crate::cedar::engine::Engine::bootstrap(schema, dir.path().to_path_buf()).unwrap(),
        );
        let (prov, _audit_dir, audit_path) = provenance();
        let status = Arc::clone(&prov.last_reload);
        assert!(
            status.load().is_none(),
            "nothing has been reloaded yet, so the health surface must say so"
        );
        let _watcher = spawn(Arc::clone(&engine), prov).unwrap();

        chmod(dir.path(), 0o770);
        std::fs::write(&policy, r#"forbid (principal, action, resource);"#).unwrap();

        assert!(
            within(Duration::from_secs(10), || status.load().is_some()),
            "the refusal never reached the health surface"
        );
        let reported = status.load().as_ref().unwrap().outcome;
        assert_eq!(reported, "refused");

        let trail = policy_set_lines(&audit_path);
        assert_eq!(
            trail.last().unwrap()["outcome"], reported,
            "the health surface and the trail must never disagree about the last \
             reload: one call writes both"
        );
    }
}
