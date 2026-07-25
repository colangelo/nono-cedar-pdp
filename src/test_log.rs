//! `tracing` output captured in memory, so a test can assert what an operator
//! tailing the daemon's log would actually see.
//!
//! Test-only (`#[cfg(test)]` in `lib.rs`): several modules answer a failure with a
//! log line and nothing else — a skipped policy file, an audit write that could not
//! land — and "the operator is told" is the whole behaviour there. Asserting it
//! needs the real subscriber output, not a mock.

use std::sync::{Arc, Mutex, MutexGuard};

/// Serializes log-capturing tests against each other.
///
/// `set_default` installs a subscriber *thread-locally*, which looks like enough for
/// parallel tests — but `tracing` also keeps a **process-wide max-level hint**, and it is
/// recalculated whenever any thread installs or drops a subscriber. A second capturing
/// test finishing mid-run can therefore lower the hint and silence ours, so the events
/// never reach our sink and the capture comes back empty.
///
/// That is not hypothetical: `a_rotated_log_is_reopened_at_the_configured_path` and
/// `a_deleted_log_is_recreated_at_the_configured_path` passed alone and failed 3/3 when
/// run together, with an empty capture. Holding this lock for the whole capture window
/// serializes only the capturing tests — the rest of the suite still runs in parallel.
static CAPTURE_LOCK: Mutex<()> = Mutex::new(());

fn lock_capture() -> MutexGuard<'static, ()> {
    match CAPTURE_LOCK.lock() {
        Ok(guard) => guard,
        // A panicking capture test must not wedge every later one.
        Err(poisoned) => poisoned.into_inner(),
    }
}

/// Pin the process-wide max-level hint to TRACE for the whole test binary.
///
/// The lock above is not sufficient on its own, because the race is not only between
/// *capturing* tests. A test that merely logs — `a_deleted_log_is_recreated_at_the_
/// configured_path` exercises the same reopen path without capturing — runs on a thread
/// with no subscriber, and `tracing` recalculates the global hint down to OFF, which
/// short-circuits the capturing thread's events *before* they reach its thread-local
/// subscriber. Installing a permanent global default that discards output keeps the hint
/// at TRACE, so thread-local capture always receives events no matter what other threads
/// are doing. Discarding, not printing: this must not add noise to test output.
fn pin_global_level() {
    static ONCE: std::sync::Once = std::sync::Once::new();
    ONCE.call_once(|| {
        // Ignore the error: another harness may legitimately have set one first.
        let _ = tracing::subscriber::set_global_default(
            tracing_subscriber::fmt()
                .with_ansi(false)
                .with_max_level(tracing::Level::TRACE)
                .with_writer(std::io::sink)
                .finish(),
        );
    });
}

#[derive(Clone, Default)]
pub(crate) struct CapturedLog(Arc<Mutex<Vec<u8>>>);

impl CapturedLog {
    pub(crate) fn text(&self) -> String {
        let guard = match self.0.lock() {
            Ok(guard) => guard,
            Err(poisoned) => poisoned.into_inner(),
        };
        String::from_utf8_lossy(&guard).to_string()
    }
}

impl std::io::Write for CapturedLog {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        let mut guard = match self.0.lock() {
            Ok(guard) => guard,
            Err(poisoned) => poisoned.into_inner(),
        };
        guard.extend_from_slice(buf);
        Ok(buf.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

impl<'a> tracing_subscriber::fmt::MakeWriter<'a> for CapturedLog {
    type Writer = CapturedLog;

    fn make_writer(&'a self) -> Self::Writer {
        self.clone()
    }
}

/// Run `body` with every `tracing` event captured. Serialized against other capturing
/// tests via [`CAPTURE_LOCK`] — see its docs for why thread-locality alone is not enough.
pub(crate) fn with_captured_log<T>(body: impl FnOnce() -> T) -> (T, String) {
    let session = capture();
    let out = body();
    (out, session.text())
}

/// A live capture window, for the async cases where the body cannot be a plain closure
/// and the caller has to hold the guards itself. Capture ends when this is dropped, so
/// read [`Self::text`] before then.
pub(crate) struct Capture {
    sink: CapturedLog,
    // Declaration order is drop order: release the subscriber before the lock, so no
    // other capturing test can start while ours is still installed.
    _subscriber: tracing::subscriber::DefaultGuard,
    _serialized: MutexGuard<'static, ()>,
}

impl Capture {
    pub(crate) fn text(&self) -> String {
        self.sink.text()
    }
}

/// Begin capturing `tracing` output on this thread.
pub(crate) fn capture() -> Capture {
    pin_global_level();
    let serialized = lock_capture();
    let sink = CapturedLog::default();
    let subscriber = tracing::subscriber::set_default(
        tracing_subscriber::fmt()
            .with_ansi(false)
            .with_writer(sink.clone())
            .finish(),
    );
    Capture {
        sink,
        _subscriber: subscriber,
        _serialized: serialized,
    }
}
