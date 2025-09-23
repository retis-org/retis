//! # Schema
//!
//! Print the json-schema definition of the retis event file

use anyhow::Result;
use clap::Parser;
use schemars::schema_for;

use crate::{cli::*, events::Event};

#[derive(Parser, Debug, Default)]
#[command(
    name = "schema",
    about = "Print the json-schema of event files produced by retis"
)]
pub(crate) struct PrintSchema {}

impl SubCommandParserRunner for PrintSchema {
    fn run(&mut self, _: &MainConfig) -> Result<()> {
        let schema = schema_for!(Event);
        print!("{}", serde_json::to_string_pretty(&schema)?);
        Ok(())
    }
}
