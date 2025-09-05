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
};

use anyhow::Result;
use log::info;
use signal_hook::iterator::Signals;

#[derive(Clone)]
pub(crate) struct Running {
    condition: Arc<AtomicBool>,
    // Callbacks to be run on `Drop`.
    #[allow(clippy::type_complexity)]
    callbacks: Arc<Mutex<Vec<Box<dyn FnOnce() + Send + Sync>>>>,
}

impl Running {
    pub(crate) fn new() -> Running {
        Self {
            condition: Arc::new(AtomicBool::new(false)),
            callbacks: Arc::new(Mutex::new(Vec::new())),
        }
    }

    /// Add a new callback to be run on `Drop`.
    pub(crate) fn add_drop_cb<F>(&mut self, cb: F)
    where
        F: FnOnce() + Send + Sync + 'static,
    {
        self.callbacks.lock().unwrap().push(Box::new(cb))
    }

    /// Register termination signals so the current Running instance will stop
    /// upon receiving one of those signals (SIGTERM, etc). This can only work
    /// from the main thread.
    pub(crate) fn register_term_signals(&self) -> Result<()> {
        let mut sigs = Signals::new(signal_hook::consts::TERM_SIGNALS)?;
        let condition = Arc::clone(&self.condition);

        thread::spawn(move || {
            sigs.wait();
            condition.store(true, Ordering::Relaxed);
            info!("Received signal, terminating...");
        });

        Ok(())
    }

    pub(crate) fn running(&self) -> bool {
        !self.condition.load(Ordering::Relaxed)
    }

    pub(crate) fn terminate(&self) {
        self.condition.store(true, Ordering::Relaxed);
    }
}

impl Default for Running {
    fn default() -> Self {
        Running::new()
    }
}

impl Drop for Running {
    fn drop(&mut self) {
        self.callbacks.lock().unwrap().drain(..).for_each(|cb| cb())
    }
}
