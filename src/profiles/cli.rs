//! # Profile
//!
//! Profiles is a CLI subcommand that allows listing and inspecting
//! profiles.

use std::path::Path;

use anyhow::Result;
use clap::{Parser, Subcommand};
use log::debug;

use super::Profile;

use crate::{cli::*, module::Modules};

//FIXME: Change
const DEFAULT_PROFILES_PATH: &str = "test_data/profiles/";

#[derive(Debug, Default, Subcommand)]
enum ProfileSubCommand {
    /// List available profiles
    #[default]
    List,
}

/// Manage Profiles
#[derive(Parser, Debug, Default)]
#[command(name = "profile")]
pub(crate) struct ProfileCmd {
    #[command(subcommand)]
    command: ProfileSubCommand,
}

impl SubCommandParserRunner for ProfileCmd {
    fn run(&mut self, _: Modules) -> Result<()> {
        match &self.command {
            ProfileSubCommand::List => {
                for entry in Path::new(DEFAULT_PROFILES_PATH).read_dir()? {
                    let entry = entry?;
                    match Profile::load(entry.path()) {
                        Ok(profile) => println!(
                            "{}: {}",
                            profile.name,
                            profile.about.unwrap_or(String::new()),
                        ),
                        Err(err) => {
                            debug!("Skipping invalid profile {}: {err}", entry.path().display())
                        }
                    }
                }
            }
        }
        Ok(())
    }
}
