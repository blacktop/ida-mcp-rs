//! Bounded stderr logging that cannot block an MCP supervisor's executor.

use std::io::{self, Write};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{mpsc, Arc};
use std::thread::{self, JoinHandle};
use std::time::Duration;
use tracing_subscriber::fmt::MakeWriter;

const QUEUED_EVENTS: usize = 256;
const MAX_EVENT_BYTES: usize = 16 * 1024;
const TRUNCATED: &[u8] = b" [truncated]\n";
const SHUTDOWN_TIMEOUT: Duration = Duration::from_secs(1);

#[derive(Clone)]
pub(crate) struct LogWriter {
    sender: mpsc::SyncSender<Vec<u8>>,
    closed: Arc<AtomicBool>,
}

pub(crate) struct LogLine {
    writer: LogWriter,
    bytes: Vec<u8>,
    truncated: bool,
}

pub(crate) struct LogGuard {
    closed: Arc<AtomicBool>,
    finished: mpsc::Receiver<()>,
    worker: Option<JoinHandle<io::Result<()>>>,
}

pub(crate) fn stderr() -> io::Result<(LogWriter, LogGuard)> {
    non_blocking(io::stderr())
}

fn non_blocking(mut output: impl Write + Send + 'static) -> io::Result<(LogWriter, LogGuard)> {
    let (sender, receiver) = mpsc::sync_channel::<Vec<u8>>(QUEUED_EVENTS);
    let (finished_tx, finished) = mpsc::sync_channel(1);
    let closed = Arc::new(AtomicBool::new(false));
    let worker_closed = closed.clone();
    let worker = thread::Builder::new()
        .name("ida-mcp-stderr".to_string())
        .spawn(move || {
            // Signal completion during unwinding as well, so shutdown can
            // join and report a failed logging thread.
            struct Finished(mpsc::SyncSender<()>);
            impl Drop for Finished {
                fn drop(&mut self) {
                    let _ = self.0.try_send(());
                }
            }
            let _finished = Finished(finished_tx);
            loop {
                match receiver.recv_timeout(Duration::from_millis(50)) {
                    Ok(bytes) => output.write_all(&bytes)?,
                    Err(mpsc::RecvTimeoutError::Timeout)
                        if !worker_closed.load(Ordering::Acquire) => {}
                    Err(_) => return output.flush(),
                }
            }
        })?;
    Ok((
        LogWriter {
            sender,
            closed: closed.clone(),
        },
        LogGuard {
            closed,
            finished,
            worker: Some(worker),
        },
    ))
}

impl<'a> MakeWriter<'a> for LogWriter {
    type Writer = LogLine;

    fn make_writer(&'a self) -> Self::Writer {
        LogLine {
            writer: self.clone(),
            bytes: Vec::new(),
            truncated: false,
        }
    }
}

impl Write for LogLine {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        let available = MAX_EVENT_BYTES
            .saturating_sub(TRUNCATED.len())
            .saturating_sub(self.bytes.len());
        let kept = bytes.len().min(available);
        if let Some(prefix) = bytes.get(..kept) {
            self.bytes.extend_from_slice(prefix);
        }
        self.truncated |= kept != bytes.len();
        Ok(bytes.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

impl Drop for LogLine {
    fn drop(&mut self) {
        if self.bytes.is_empty() || self.writer.closed.load(Ordering::Acquire) {
            return;
        }
        if self.truncated {
            self.bytes.extend_from_slice(TRUNCATED);
        }
        // Diagnostics are best-effort once the bounded queue is full. The
        // request, cancellation and worker watchdog must always keep running.
        let _ = self.writer.sender.try_send(std::mem::take(&mut self.bytes));
    }
}

impl LogGuard {
    /// Flush pending events when possible. A blocked stderr consumer must not
    /// hold process shutdown open; `false` reports that bounded wait expiring.
    pub(crate) fn shutdown(&mut self) -> io::Result<bool> {
        self.closed.store(true, Ordering::Release);
        let Some(worker) = self.worker.as_ref() else {
            return Ok(true);
        };
        if !worker.is_finished()
            && self.finished.recv_timeout(SHUTDOWN_TIMEOUT).is_err()
            && !worker.is_finished()
        {
            return Ok(false);
        }
        if let Some(worker) = self.worker.take() {
            worker
                .join()
                .map_err(|_| io::Error::other("stderr logging worker panicked"))??;
        }
        Ok(true)
    }
}

impl Drop for LogGuard {
    fn drop(&mut self) {
        // Never report logging failures through stdout: it carries MCP.
        if !self.closed.load(Ordering::Acquire)
            || self.worker.as_ref().is_some_and(JoinHandle::is_finished)
        {
            let _ = self.shutdown();
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::logging::{non_blocking, MAX_EVENT_BYTES, QUEUED_EVENTS};
    use std::io::{self, Write};
    use std::sync::{mpsc, Arc, Mutex};
    use std::time::{Duration, Instant};
    use tracing_subscriber::fmt::MakeWriter;

    struct BlockedWriter {
        entered: mpsc::SyncSender<()>,
        release: mpsc::Receiver<()>,
        largest: Arc<Mutex<usize>>,
    }

    impl Write for BlockedWriter {
        fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
            let _ = self.entered.try_send(());
            self.release.recv().map_err(io::Error::other)?;
            let mut largest = self.largest.lock().expect("test mutex");
            *largest = (*largest).max(bytes.len());
            Ok(bytes.len())
        }

        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    #[test]
    fn blocked_stderr_bounds_events_queue_and_shutdown() {
        let (entered_tx, entered) = mpsc::sync_channel(1);
        let (release, release_rx) = mpsc::channel();
        let largest = Arc::new(Mutex::new(0));
        let (writer, mut guard) = non_blocking(BlockedWriter {
            entered: entered_tx,
            release: release_rx,
            largest: largest.clone(),
        })
        .expect("start logger");
        writer.make_writer().write_all(b"first\n").expect("log");
        entered
            .recv_timeout(Duration::from_secs(2))
            .expect("writer blocked");
        let started = Instant::now();
        for _ in 0..QUEUED_EVENTS + 10 {
            writer
                .make_writer()
                .write_all(&vec![b'x'; MAX_EVENT_BYTES * 2])
                .expect("log");
        }
        assert!(started.elapsed() < Duration::from_secs(1));
        assert!(!guard.shutdown().expect("bounded shutdown"));
        for _ in 0..QUEUED_EVENTS + 1 {
            release.send(()).expect("unblock logger");
        }
        assert!(guard.shutdown().expect("join logger"));
        assert_eq!(*largest.lock().expect("test mutex"), MAX_EVENT_BYTES);
    }
}
