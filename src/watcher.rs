//! Filesystem watch on the policy directory.
//!
//! Debounces bursts (editors write several events per save) and reloads through
//! `Engine::reload`, which keeps the last-good set on failure.

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

    std::thread::Builder::new()
        .name("policy-watcher".to_string())
        .spawn(move || {
            while let Ok(first) = rx.recv() {
                if let Err(e) = first {
                    tracing::warn!(error = %e, "policy watch error");
                    continue;
                }
                // Drain the burst an editor save produces.
                while rx.recv_timeout(DEBOUNCE).is_ok() {}
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
}
