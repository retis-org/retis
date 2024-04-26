use std::{env, path::PathBuf};

use pager::Pager;

use crate::core::logger::Logger;

/// If successful, enables the pager for all output to stdout following this
/// call. Useful in some commands when the output is quite long and we want to
/// enable searching and scrolling.
///
/// We're using less if no pager (PAGER env variable) is defined. `-F` makes the
/// pager to only take effect if the output length is > the terminal one, `-R`
/// enables interpretation of color sequences and `-X` makes the output to not
/// be cleared on exit.
pub(crate) fn try_enable_pager(logger: &Logger) {
    // Always try to use `PAGER` and if we can, use our own pager as a fallback.
    if env::var("PAGER").is_ok() || can_use_own_pager() {
        let mut pager = Pager::with_default_pager("less -FRX");
        pager.setup();

        // When the pager is enabled we need to output the error messages on
        // stdout so they're also caught; otherwise they would be hidden at
        // least until returning from the pager.
        //
        // It's OK to do this after enabling the pager as this is done early w/o
        // other threads running.
        if pager.is_on() {
            logger.switch_to_stdout();
        }
    }
}

/// Checks if the pager can be used by checking the `less` command is available
/// in the $PATH and executable.
fn can_use_own_pager() -> bool {
    if let Ok(path_env) = env::var("PATH") {
        for path in path_env.split(':') {
            let mut pbuf = PathBuf::new();
            pbuf.push(path);
            pbuf.push("less");

            if pbuf.as_path().is_file() {
                return true;
            }
        }
    }
    false
}
