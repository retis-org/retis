//! # Profile
//!
//! Profiles is a CLI subcommand that allows listing and inspecting
//! profiles.
use std::path::Path;

use anyhow::Result;
use clap::{Parser, Subcommand};
use log::warn;

use super::{get_profile_paths, Profile};

use crate::cli::*;

#[derive(Debug, Default, Subcommand)]
enum ProfileSubCommand {
    /// List available profiles.
    #[default]
    List,
}

#[derive(Parser, Debug, Default)]
#[command(
    name = "profile",
    about = "Manage profiles.",
    long_about = "Manage profiles.

Profiles are a predefined set of cli arguments. Profiles are meant to improve user experience to provide a comprehensive and consistent configuration to Retis aimed at operating on pre-defined topics."
)]
pub(crate) struct ProfileCmd {
    #[command(subcommand)]
    command: ProfileSubCommand,
}

impl SubCommandParserRunner for ProfileCmd {
    fn run(&mut self, main_config: &MainConfig) -> Result<()> {
        match &self.command {
            ProfileSubCommand::List => {
                for path in get_profile_paths(main_config.extra_profiles_dir.as_ref())
                    .iter()
                    .filter(|p| p.as_path().exists())
                {
                    Self::list_path(path)?;
                }
            }
        }
        Ok(())
    }
}

impl ProfileCmd {
    fn list_path(path: &Path) -> Result<()> {
        for entry in path.read_dir()? {
            let entry = entry?.path();

            // Skip non-YAML files.
            if !entry.extension().is_some_and(|e| e == "yaml" || e == "yml") {
                continue;
            }

            match Profile::from_file(entry.clone()) {
                Ok(mut profiles) => {
                    if !profiles.is_empty() {
                        println!("{}:", entry.to_str().unwrap_or("unknown"));
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
                    warn!("Skipping invalid file {}: {err}", entry.display());
                }
            }
        }
        Ok(())
    }
}
