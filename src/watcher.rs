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
}
