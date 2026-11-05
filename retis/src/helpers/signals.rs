/// # Signals
///
/// Provides a simple way for both registering signal handlers or
/// simply notify terminations to the threads.
use std::{
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc, Mutex,
    },
    thread,
    time::Duration,
};

use anyhow::{anyhow, Result};
use log::info;
use signal_hook::iterator::Signals;

/// Unified timeout to use when using blocking calls.
pub(crate) const CALL_TIMEOUT_MS: u64 = 200;

/// Provides a blocking call similar to `crossbeam_channel::Sender<T>::send`
/// while handling potential `Running` completion.
pub(crate) fn channel_send<T: Send + Sync>(
    txc: &crossbeam_channel::Sender<T>,
    run: &Running,
    mut msg: T,
) -> Result<()> {
    loop {
        let res = txc.send_timeout(msg, Duration::from_millis(CALL_TIMEOUT_MS));

        // Continue trying sending the message if we're not shutting down.
        if run.running() {
            if let Err(crossbeam_channel::SendTimeoutError::Timeout(unsent)) = res {
                msg = unsent;
                continue;
            }
        // Forward the disconnected error only if we're not shutting down.
        } else if matches!(
            res,
            Err(crossbeam_channel::SendTimeoutError::Disconnected(_))
        ) {
            return Err(anyhow!("Channel disconnected"));
        }

        return Ok(());
    }
}

#[derive(Clone)]
pub(crate) struct Running {
    condition: Arc<AtomicBool>,
    // Callbacks to be run on `Drop`.
    #[allow(clippy::type_complexity)]
    callbacks: Arc<Mutex<Vec<Box<dyn FnOnce() + Send + Sync>>>>,
}

impl Running {
    // Create a new Running instance.
    //
    // - Helps handling loops in various threads to synchonize termination.
    // - This instance will also stop upon receiving one of the termination
    //   signals (e.g. SIGTERM).
    pub(crate) fn new() -> Result<Running> {
        let mut sigs = Signals::new(signal_hook::consts::TERM_SIGNALS)?;

        let run = Self::ignore_signals();
        let condition = Arc::clone(&run.condition);

        let thread = thread::Builder::new().name("retis-signals-handler".to_string());
        thread.spawn(move || {
            sigs.wait();
            condition.store(true, Ordering::Relaxed);
            info!("Received signal, terminating...");
        })?;

        Ok(run)
    }

    // Same as `new()` but without handling termination signals. Termination
    // *must* be manually handlded here.
    pub(crate) fn ignore_signals() -> Running {
        Self {
            condition: Arc::new(AtomicBool::new(false)),
            callbacks: Arc::new(Mutex::new(Vec::new())),
        }
    }

    // Add a new callback to be run on `Drop`.
    pub(crate) fn add_drop_cb<F>(&mut self, cb: F)
    where
        F: FnOnce() + Send + Sync + 'static,
    {
        self.callbacks.lock().unwrap().push(Box::new(cb))
    }

    pub(crate) fn running(&self) -> bool {
        !self.condition.load(Ordering::Relaxed)
    }

    pub(crate) fn terminate(&self) {
        self.condition.store(true, Ordering::Relaxed);
    }
}

impl Drop for Running {
    fn drop(&mut self) {
        self.callbacks.lock().unwrap().drain(..).for_each(|cb| cb())
    }
}
