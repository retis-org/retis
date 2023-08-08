use anyhow::{bail, Result};
use clap::{arg, builder::PossibleValuesParser, Parser};

use crate::{benchmark::*, cli::*, module::Modules};

/// Benchmark parts of Retis
#[derive(Parser, Debug, Default)]
#[command(name = "benchmark")]
pub(crate) struct Benchmark {
    #[arg(
        value_parser=PossibleValuesParser::new(["events_parsing", "events_output"]),
        help = "Benchmark to run",
    )]
    pub(super) r#type: String,
}

impl SubCommandParserRunner for Benchmark {
    fn run(&mut self, _: Modules) -> Result<()> {
        match self.r#type.as_str() {
            "events_parsing" => events_parsing::bench()?,
            "events_output" => events_output::bench()?,
            x => bail!("Unknown benchmark '{x}'"),
        }

        Ok(())
    }
}
