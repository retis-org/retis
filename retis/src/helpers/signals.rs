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
    // Create a new Running instance.
    //
    // - Helps handling loops in various threads to synchonize termination.
    // - This instance will also stop upon receiving one of the termination
    //   signals (e.g. SIGTERM).
    pub(crate) fn new() -> Result<Running> {
        let mut sigs = Signals::new(signal_hook::consts::TERM_SIGNALS)?;

        let run = Self::ignore_signals();
        let condition = Arc::clone(&run.condition);

        thread::spawn(move || {
            sigs.wait();
            condition.store(true, Ordering::Relaxed);
            info!("Received signal, terminating...");
        });

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
