use anyhow::Result;
use clap::{arg, Parser};

use crate::{
    cli::*,
    collect::collector::get_known_types,
    core::{kernel::Symbol, probe::kernel::utils::probe_from_cli},
};

/// Inspect the current machine.
#[derive(Parser, Debug, Default)]
#[command(name = "inspect", arg_required_else_help = true)]
pub(crate) struct Inspect {
    #[arg(
        short,
        long,
        num_args = 0..=1,
        default_missing_value = "*",
        help = "List all probes matching the pattern, or all probes if no pattern is given.
Only probes compatible with Retis probing are returned. The pattern supports wildcards. If
no probe type is given 'kprobe' is used. Note that listing probes might take some time as
a compatibility check is performed for each one.
Eg. '-p tp:*'. See `retis collect --help` for more details on the probe format."
    )]
    pub(crate) probe: Option<String>,
}

impl SubCommandParserRunner for Inspect {
    fn run(&mut self) -> Result<()> {
        if let Some(probe) = &self.probe {
            let known_types = get_known_types()?;

            match probe.as_str() {
                probe if !probe.contains(':') => {
                    ["kprobe", "tp"].iter().try_for_each(|r#type| {
                        inspect_probe(&format!("{type}:{probe}"), &known_types)
                    })?
                }
                probe => inspect_probe(probe, &known_types)?,
            }
        }

        Ok(())
    }
}

fn inspect_probe(probe: &str, known_types: &[&str]) -> Result<()> {
    // Only display probes compatible with the collectors.
    let filter = |symbol: &Symbol| {
        known_types.iter().any(|t| {
            symbol
                .parameter_offset(t)
                .is_ok_and(|offset| offset.is_some())
        })
    };

    // Get & list probes.
    let mut probes: Vec<String> = probe_from_cli(probe, filter)?
        .iter()
        .map(|p| format!("{p}"))
        .collect();
    probes.sort();
    probes.iter().for_each(|p| println!("{p}"));
    Ok(())
}
