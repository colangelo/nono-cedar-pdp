//! `tracing` output captured in memory, so a test can assert what an operator
//! tailing the daemon's log would actually see.
//!
//! Test-only (`#[cfg(test)]` in `lib.rs`): several modules answer a failure with a
//! log line and nothing else — a skipped policy file, an audit write that could not
//! land — and "the operator is told" is the whole behaviour there. Asserting it
//! needs the real subscriber output, not a mock.

use std::sync::{Arc, Mutex};

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

/// Run `body` with every `tracing` event captured. The subscriber is thread-local
/// (`set_default`), so parallel tests do not capture each other's output.
pub(crate) fn with_captured_log<T>(body: impl FnOnce() -> T) -> (T, String) {
    let sink = CapturedLog::default();
    let out = {
        let _guard = tracing::subscriber::set_default(subscriber(&sink));
        body()
    };
    (out, sink.text())
}

/// A subscriber writing into `sink`, for the async cases where the body cannot be
/// a plain closure and the caller has to hold the guard itself.
pub(crate) fn subscriber(sink: &CapturedLog) -> impl tracing::Subscriber {
    tracing_subscriber::fmt()
        .with_ansi(false)
        .with_writer(sink.clone())
        .finish()
}
