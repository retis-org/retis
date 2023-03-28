use anyhow::{bail, Result};
use log::error;
use simplelog::{ColorChoice, Config, LevelFilter, TermLogger, TerminalMode};

mod cli;
mod collect;
mod core;
mod module;
use crate::{
    cli::get_cli,
    collect::Collectors,
    core::{events::bpf::BpfEventsFactory, Retis},
    module::get_modules,
};

// Re-export derive macros.
use retis_derive::*;

fn main() -> Result<()> {
    // Step 1: get the cli parameters.
    let mut cli = get_cli()?.build()?;

    // Step 2: handle the log & terminal options.
    let log_level = match cli.main_config.log_level.as_str() {
        "error" => LevelFilter::Error,
        "warn" => LevelFilter::Warn,
        "info" => LevelFilter::Info,
        "debug" => LevelFilter::Debug,
        x => bail!("Invalid log_level: {}", x),
    };
    TermLogger::init(
        log_level,
        Config::default(),
        TerminalMode::Stderr, // Use stderr so logs do not conflict w/ other output.
        ColorChoice::Auto,
    )?;

    // Step 3: get the modules.
    let mut modules = get_modules()?;

    // Step 4: dispatch the command.
    let command = cli.get_subcommand_mut()?;
    match command.name() {
        "collect" => {
            // Initialize the BPF factory for the collect command and store its
            // events map fd for reuse by all probes.
            let factory = BpfEventsFactory::new()?;
            let event_map_fd = factory.map_fd();
            let mut retis = Retis::new(Box::new(factory));

            // We do enable probing when collecting events.
            retis.enable_probes(&mut modules, event_map_fd)?;

            // Finally we can start working with the collectors.
            let mut collectors = Collectors::new(modules, retis, cli)?;

            collectors.init()?;
            collectors.start()?;

            // Starts a loop.
            collectors.process()?;
        }
        _ => {
            error!("not implemented");
        }
    }
    Ok(())
}
