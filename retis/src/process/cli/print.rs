//! # Print
//!
//! Print is a simple post-processing command that just parses events and prints them back to
//! stdout
use std::io::stdout;

use anyhow::Result;
use clap::Parser;

use crate::{
    cli::*,
    helpers::signals::Running,
    process::{display::*, print::*},
};

#[derive(Parser, Debug, Default)]
#[command(name = "print", about = "Print stored events to stdout.")]
pub(crate) struct Print {
    #[command(flatten)]
    args: PrintArgs,
}

impl SubCommandParserRunner for Print {
    fn run(&mut self, _: &MainConfig) -> Result<()> {
        do_print(
            &self.args,
            Running::new()?,
            vec![PrintSeries::new(
                Box::new(stdout()),
                EventFormat::Text(get_print_format(&self.args)),
            )],
            false,
        )
    }
}
