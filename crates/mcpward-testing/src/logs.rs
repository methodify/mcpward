use std::{
    io::Write,
    sync::{Arc, Mutex},
};

use tracing_subscriber::fmt::MakeWriter;

/// Captures `tracing` output (all levels, JSON) for the current thread while the guard lives.
///
/// Use with a current-thread runtime (the `#[tokio::test]` default) so spawned tasks log to the
/// same capture.
#[derive(Clone, Default)]
pub struct LogCapture {
    buf: Arc<Mutex<Vec<u8>>>,
}

/// The writer behind [`LogCapture`].
pub struct CaptureWriter(Arc<Mutex<Vec<u8>>>);

impl Write for CaptureWriter {
    fn write(&mut self, b: &[u8]) -> std::io::Result<usize> {
        if let Ok(mut g) = self.0.lock() {
            g.extend_from_slice(b);
        }
        Ok(b.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

impl<'a> MakeWriter<'a> for LogCapture {
    type Writer = CaptureWriter;
    fn make_writer(&'a self) -> CaptureWriter {
        CaptureWriter(self.buf.clone())
    }
}

impl LogCapture {
    /// Starts capturing. Logs go to the capture until the returned guard drops.
    pub fn start() -> (LogCapture, tracing::subscriber::DefaultGuard) {
        // tracing-core computes callsite interest from the registering thread's default
        // dispatcher while only one dispatcher exists, so a callsite first hit on another
        // test's thread (with no subscriber) would be cached as "never". A second, permanent
        // dispatcher makes it consult every live dispatcher instead.
        static KEEPALIVE: std::sync::OnceLock<tracing::Dispatch> = std::sync::OnceLock::new();
        KEEPALIVE.get_or_init(|| tracing::Dispatch::new(tracing::subscriber::NoSubscriber::default()));
        let cap = LogCapture::default();
        let sub = tracing_subscriber::fmt()
            .json()
            .with_max_level(tracing::Level::TRACE)
            .with_current_span(true)
            .with_span_list(true)
            .with_writer(cap.clone())
            .finish();
        let guard = tracing::subscriber::set_default(sub);
        // Callsites first hit on another thread with no subscriber may have cached "never";
        // recompute interest now that this thread has one.
        tracing::callsite::rebuild_interest_cache();
        (cap, guard)
    }

    /// Everything captured so far.
    pub fn contents(&self) -> String {
        self.buf.lock().map(|b| String::from_utf8_lossy(&b).into_owned()).unwrap_or_default()
    }
}
