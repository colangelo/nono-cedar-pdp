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

use crate::cedar::engine::Engine;
use notify::{Event, RecommendedWatcher, RecursiveMode, Watcher};
use std::sync::mpsc;
use std::sync::Arc;
use std::time::Duration;

const DEBOUNCE: Duration = Duration::from_millis(150);

/// Start watching `engine.policy_dir()`. Keep the returned watcher alive — its
/// drop stops the watch.
pub fn spawn(engine: Arc<Engine>) -> notify::Result<RecommendedWatcher> {
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
                // Drain the burst an editor save produces.
                while rx.recv_timeout(DEBOUNCE).is_ok() {}
                // Re-check trust after the drain and BEFORE the reload touches the
                // directory, so nothing read from a loosened tree can become the
                // active set. On refusal the in-memory set predates the loosening
                // and is the only trusted policy state left, so it stays (same
                // posture as a broken edit, D7) and the watch survives — repairing
                // the mode and editing again recovers without a restart. ERROR,
                // not WARN: a quieter level would let the "adopted silently"
                // failure this closes recur one level down. See the module docs
                // for the TOCTOU window and the other-local-users scope.
                if let Err(e) = crate::isolation::refuse_untrusted_policy_dir(engine.policy_dir())
                {
                    tracing::error!(
                        error = %e,
                        "policy directory is no longer trusted; keeping the \
                         last-good policy set"
                    );
                    continue;
                }
                match engine.reload() {
                    Ok(generation) => {
                        tracing::info!(generation, "policies reloaded from disk")
                    }
                    Err(e) => tracing::error!(
                        error = %e,
                        "policy reload failed; keeping previous policy set"
                    ),
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
        let _watcher = spawn(Arc::clone(&engine)).unwrap();

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
        let _watcher = spawn(Arc::clone(&engine)).unwrap();

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
        let _watcher = spawn(Arc::clone(&engine)).unwrap();
        assert!(
            engine.evaluate(&git_status()).allow,
            "the last-good set permits git status before the loosening"
        );

        // Loosen the directory, then make an edit that would flip the decision if
        // the reload were wrongly adopted.
        chmod(dir.path(), 0o770);
        std::fs::write(&policy, r#"forbid (principal, action, resource);"#).unwrap();

        assert!(
            !within(Duration::from_secs(2), || engine.snapshot().generation != 1
                || !engine.evaluate(&git_status()).allow),
            "a policy set read from a loosened directory must not be adopted: \
             generation {}",
            engine.snapshot().generation
        );
        let log = capture.text();
        assert!(
            log.contains("ERROR"),
            "the refusal must be ERROR, not a level an operator filters out: {log:?}"
        );
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
        let _watcher = spawn(Arc::clone(&engine)).unwrap();
        assert!(
            engine.evaluate(&git_status()).allow,
            "the last-good set permits git status before the loosening"
        );

        // Loosen the file, then give it content that would flip the decision if
        // the reload were wrongly adopted. `std::fs::write` truncates in place,
        // so the loosened mode survives the edit.
        chmod(&policy, 0o660);
        std::fs::write(&policy, r#"forbid (principal, action, resource);"#).unwrap();

        assert!(
            !within(Duration::from_secs(2), || engine.snapshot().generation != 1
                || !engine.evaluate(&git_status()).allow),
            "a policy set read past a loosened file must not be adopted: generation {}",
            engine.snapshot().generation
        );
        let log = capture.text();
        assert!(
            log.contains("ERROR"),
            "the refusal must be ERROR, not a level an operator filters out: {log:?}"
        );
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
        let _watcher = spawn(Arc::clone(&engine)).unwrap();
        assert!(
            engine.evaluate(&git_status()).allow,
            "the last-good set permits git status before the loosening"
        );

        chmod(&holder, 0o770);
        std::fs::write(&policy, r#"forbid (principal, action, resource);"#).unwrap();

        assert!(
            !within(Duration::from_secs(2), || engine.snapshot().generation != 1
                || !engine.evaluate(&git_status()).allow),
            "a policy set below a loosened ancestor must not be adopted: generation {}",
            engine.snapshot().generation
        );
        let log = capture.text();
        assert!(
            log.contains("ERROR"),
            "the refusal must be ERROR, not a level an operator filters out: {log:?}"
        );
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
        let _watcher = spawn(Arc::clone(&engine)).unwrap();

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
        let _watcher = spawn(Arc::clone(&engine)).unwrap();

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
}
