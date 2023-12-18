/// # Signals
///
/// Provides a simple way for both registering signal handlers or
/// simply notify terminations to the threads.
use std::{
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    },
    thread,
};

use anyhow::Result;
use log::info;
use signal_hook::iterator::Signals;

#[derive(Clone)]
pub(crate) struct Running(Arc<AtomicBool>);

impl Running {
    pub(crate) fn new() -> Running {
        Running(Arc::new(AtomicBool::new(false)))
    }

    /// Register termination signals so the current Running instance will stop
    /// upon receiving one of those signals (SIGTERM, etc). This can only work
    /// from the main thread.
    pub(crate) fn register_term_signals(&self) -> Result<()> {
        let mut sigs = Signals::new(signal_hook::consts::TERM_SIGNALS)?;
        let myself = self.clone();

        thread::spawn(move || {
            sigs.wait();
            myself.terminate();
            info!("Received signal, terminating...");
        });

        Ok(())
    }

    pub(crate) fn running(&self) -> bool {
        !self.0.load(Ordering::Relaxed)
    }

    pub(crate) fn terminate(&self) {
        self.0.store(true, Ordering::Relaxed);
    }
}

impl Default for Running {
    fn default() -> Self {
        Running::new()
    }
}
