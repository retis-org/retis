//! # Sort
//!
//! Sort rearranges the events so they are grouped by skb tracking id (or OVS queue_id if present)

use std::{
    fs::OpenOptions,
    io::{stdout, BufWriter},
    path::PathBuf,
};

use anyhow::{bail, Result};
use clap::Parser;

use crate::{
    cli::*,
    helpers::signals::Running,
    process::{display::*, print::*},
};

#[derive(Parser, Debug, Default)]
#[command(
    name = "sort",
    about = "Sort stored events in series based on tracking id.",
    long_about = "Sort stored events in series based on tracking id.

Reads events and arranges them by tracking id. The output is a number of \"event sets\". An event set is a list of events that share the same tracking id (i.e: belong to the same packet)."
)]
pub(crate) struct Sort {
    #[command(flatten)]
    args: PrintArgs,
    #[arg(
        short,
        long,
        help = "Write event series to a file rather than to stdout"
    )]
    pub(super) out: Option<PathBuf>,
    #[arg(long, help = "Write events to stdout even if --out is used")]
    pub(super) print: bool,
}

impl SubCommandParserRunner for Sort {
    fn run(&mut self, _: &MainConfig) -> Result<()> {
        let mut printers = Vec::new();
        if let Some(out) = &self.out {
            // Try to detect if the same file is used for the input and the
            // output, as this would result in the deletion of the original
            // file and the loss of data.
            //
            // Due to the default input file logic and the range format, we
            // only due this check best-effort.
            if let Ok(input) = self
                .args
                .input
                .clone()
                .unwrap_or_default()
                .0
                .path
                .canonicalize()
            {
                let out = match out.canonicalize() {
                    Ok(out) => out,
                    // If the file doesn't exist we can't use fs::canonicalize() but it is not needed
                    // as that means it is not the input file.
                    Err(_) => out.to_path_buf(),
                };

                if out.eq(&input) {
                    bail!("Cannot sort a file in-place. Please specify an output file that's different to the input one.");
                }
            }

            printers.push(PrintSeries::new(
                Box::new(BufWriter::new(
                    OpenOptions::new()
                        .create(true)
                        .write(true)
                        .truncate(true)
                        .open(out)
                        .or_else(|_| bail!("Could not create or open '{}'", out.display()))?,
                )),
                EventFormat::Json,
            ));
        }

        if self.out.is_none() || self.print {
            printers.push(PrintSeries::new(
                Box::new(stdout()),
                EventFormat::Text(get_print_format(&self.args)),
            ));
        }

        do_print(&self.args, Running::new()?, printers, true)
    }
}
