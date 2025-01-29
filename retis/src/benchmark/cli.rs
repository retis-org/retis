use anyhow::{bail, Result};
use clap::{arg, builder::PossibleValuesParser, Parser};

use crate::{benchmark::*, cli::*};

/// Benchmark parts of Retis
#[derive(Parser, Debug, Default)]
#[command(name = "benchmark")]
pub(crate) struct Benchmark {
    #[arg(
        value_parser=PossibleValuesParser::new(["events_parsing", "events_output"]),
        help = "Benchmark to run",
    )]
    pub(super) r#type: String,
    #[arg(
        long,
        default_value = "false",
        help = "Run fake benchmarks to ensure there is no runtime issue"
    )]
    pub(super) ci: bool,
}

impl SubCommandParserRunner for Benchmark {
    fn run(&mut self) -> Result<()> {
        match self.r#type.as_str() {
            "events_parsing" => events_parsing::bench(self.ci)?,
            "events_output" => events_output::bench(self.ci)?,
            x => bail!("Unknown benchmark '{x}'"),
        }

        Ok(())
    }
}
