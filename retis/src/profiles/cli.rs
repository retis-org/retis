//! # Profile
//!
//! Profiles is a CLI subcommand that allows listing and inspecting
//! profiles.

use anyhow::Result;
use clap::{Parser, Subcommand};
use log::warn;

use super::{get_profile_paths, Profile};

use crate::{cli::*, module::Modules};

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
                for path in get_profile_paths()?.iter().filter(|p| p.as_path().exists()) {
                    for entry in path.read_dir()? {
                        let entry = entry?;
                        match Profile::load(entry.path()) {
                            Ok(mut profiles) => {
                                if !profiles.is_empty() {
                                    println!("{}:", entry.path().to_str().unwrap_or("unknown"));
                                }
                                for profile in profiles.drain(..) {
                                    println!(
                                        "  {: <20} {}",
                                        profile.name,
                                        profile.about.unwrap_or(String::new()),
                                    );
                                }
                            }
                            Err(err) => {
                                warn!("Skipping invalid file {}: {err}", entry.path().display())
                            }
                        }
                    }
                }
            }
        }
        Ok(())
    }
}
