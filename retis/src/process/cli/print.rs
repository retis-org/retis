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
        let run = Running::new()?;
        do_print(
            &self.args,
            run.clone(),
            vec![ItemDisplayPipe::new(
                ItemFormatter::new(
                    EventFormat::Text(self.args.get_print_format()),
                    1,
                    run.clone(),
                ),
                Box::new(stdout()),
            )],
            false,
        )
    }
}
