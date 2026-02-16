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
use once_cell::sync::OnceCell;
use signal_hook::iterator::Signals;

/// Callbacks called at program exit time.
static EXIT_CALLBACKS: OnceCell<Callbacks> = OnceCell::new();

/// Add an exit callback to call at program exit time (TERM signal or program
/// exit if not).
pub(crate) fn add_exit_cb<F>(cb: F) -> Result<()>
where
    F: FnOnce() + Send + Sync + 'static,
{
    let cbs = EXIT_CALLBACKS.get_or_try_init(|| -> Result<Callbacks> {
        let mut sigs = Signals::new(signal_hook::consts::TERM_SIGNALS)?;
        let callbacks = Callbacks(Mutex::new(Vec::new()));

        thread::spawn(move || {
            sigs.wait();
            info!("Received signal, terminating...");
            run_exit_callbacks();
        });

        unsafe {
            libc::atexit(run_exit_callbacks);
        }

        Ok(callbacks)
    })?;

    cbs.add(cb);
    Ok(())
}

extern "C" fn run_exit_callbacks() {
    if let Some(callbacks) = EXIT_CALLBACKS.get() {
        callbacks.run();
    }
}

/// List of callbacks that can be registered and called at a later time.
/// Callbacks are run either explicilty or at drop time.
struct Callbacks(Mutex<Vec<Box<dyn FnOnce() + Send + Sync>>>);

impl Callbacks {
    /// Add a new callback to the list.
    fn add<F>(&self, cb: F)
    where
        F: FnOnce() + Send + Sync + 'static,
    {
        self.0.lock().unwrap().push(Box::new(cb))
    }

    /// Run (and consume) all registered callbacks.
    fn run(&self) {
        self.0.lock().unwrap().drain(..).for_each(|cb| cb())
    }
}

impl Drop for Callbacks {
    fn drop(&mut self) {
        self.run()
    }
}

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
        let myself = self.clone();
        add_exit_cb(move || myself.terminate())
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
