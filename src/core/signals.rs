/// # Signals
///
/// Provides a simple way for both registering signal handlers or
/// simply notify terminations to the threads.
use std::sync::{
    atomic::{AtomicBool, Ordering},
    Arc,
};

use anyhow::Result;

#[derive(Clone)]
pub(crate) struct Running(Arc<AtomicBool>);

impl Running {
    pub(crate) fn new() -> Running {
        Running(Arc::new(AtomicBool::new(false)))
    }

    pub(crate) fn register_signal(&mut self, signal: libc::c_int) -> Result<()> {
        signal_hook::flag::register(signal, self.0.clone())?;
        Ok(())
    }

    pub(crate) fn running(&self) -> bool {
        !self.0.load(Ordering::Relaxed)
    }

    pub(crate) fn terminate(&mut self) {
        self.0.store(true, Ordering::Relaxed);
    }
}

impl Default for Running {
    fn default() -> Self {
        Running::new()
    }
}
