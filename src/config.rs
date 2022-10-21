//! # Configuration
//!
//! This module is in charge of defining and parsing the program's configuration.
//!
//! TBD
//!

#![allow(dead_code)] // FIXME

use anyhow::{bail, Result};
use std::{
    collections::{HashMap, HashSet},
    env,
    ffi::OsString,
    fmt::Debug,
    fs,
    path::PathBuf,
};

use clap::{value_parser, Arg, ArgAction, ArgMatches, Args, Command, FromArgMatches};

use serde::Deserialize;

pub(crate) struct Cli {
    command: Command,

    sections: HashSet<String>,
    matches: Option<ArgMatches>,
    profile: HashMap<String, toml::Value>,
}

impl Cli {
    /// Allocate and return a new Cli object adding the main arguments.
    pub(crate) fn new() -> Result<Self> {
        let command = Command::new("packet-tracer")
            .about("Trace packets in the Linux Kernel")
            .arg(
                Arg::new("profile")
                    .short('p')
                    .long("profile")
                    .action(ArgAction::Set)
                    .value_name("FILE")
                    .help("Provides a config profile packet-tracerl")
                    .value_parser(value_parser!(PathBuf)),
            );

        Ok(Cli {
            command,
            sections: HashSet::new(),
            matches: None,
            profile: HashMap::new(),
        })
    }

    /// Register a new configuration section under a specific section name augmenting the Cli's
    /// arguments with those of the configuration section.
    pub(crate) fn register_config<T>(&mut self, name: &'static str) -> Result<()>
    where
        T: Args,
    {
        let name = String::from(name);
        if self.sections.get(&name).is_some() {
            bail!("config with name {} already registered", name);
        }
        self.sections.insert(name);
        self.command = T::augment_args_for_update(self.command.clone());

        Ok(())
    }

    /// Parse binary arguments.
    pub(crate) fn parse(&mut self) -> Result<()> {
        self.parse_from(&mut env::args_os(), false)
    }

    /// Parse an interator of strings as input arguments. Useful for testing.
    fn parse_from<I, T>(&mut self, iter: I, try_get: bool) -> Result<()>
    where
        I: IntoIterator<Item = T>,
        T: Into<OsString> + Clone,
    {
        // augment_args places the struct's documentation comments (///) at the program's help
        // string replacing whatever was there originally. In order to keep a reasonable help
        // string while allowing modules to write documentation comments on their configuration
        // section structs, use the MainConfig to augment the args last.
        if self.sections.get("main").is_none() {
            self.command = MainConfig::augment_args(self.command.to_owned());
            self.sections.insert("main".to_string());
        }

        let matches = match try_get {
            true => self.command.clone().try_get_matches_from(iter)?,
            false => self.command.clone().get_matches_from(iter),
        };

        if let Some(config_path) = matches.get_one::<PathBuf>("profile") {
            self.init_from_file(config_path)?;
        }
        self.matches = Some(matches);
        Ok(())
    }

    /// On an alrady parsed Cli object, retrieve a specific configuration Section by name (and type).
    /// The configuration coming from the profile and the cli arguments are merged (cli has
    /// preference).
    pub(crate) fn get_section<'a, T>(&mut self, name: &str) -> Result<T>
    where
        T: Debug + Default + Args + Deserialize<'a> + FromArgMatches,
    {
        let name = self.sections.get(name).expect("section not registered");
        let matches = self.matches.as_ref().expect("cli not parsed");
        let mut target = match self.profile.get(name) {
            Some(config) => config.clone().try_into()?,
            None => T::default(),
        };
        target.update_from_arg_matches(matches)?;
        Ok(target)
    }

    /// Initialize the profile from a toml configuration file.
    ///
    /// The file is parsed and stored in self as a toml::Value().
    fn init_from_file(&mut self, config_file: &PathBuf) -> Result<()> {
        let content = fs::read_to_string(config_file).expect("Cannot open config file");
        let toml_content: toml::Value = toml::from_str(&content).expect("Failed to parse profile");
        for section in &self.sections {
            if let Some(config) = toml_content.get(section) {
                self.profile.insert(section.clone(), config.clone());
            }
        }
        Ok(())
    }
}

/// Trace packets on the Linux kernel
///
/// Insert a whole lot of ebpf programs into the Linux kernel (and OvS) to find packets wherever
/// thy are.
#[derive(Debug, Args, Default, Deserialize)]
#[serde(rename_all = "kebab-case")]
// One clap+serde integration problem is casing.
// Serde will CamelCase enums and keep field names untouched (i.e: snake_case). However, clap will
// kebab-case field names and enums. We can force serde to also kebab-case but a proper integration
// should hide this.
#[serde(default)]
pub(crate) struct MainConfig {
    /// Prints libbpf debugging information to stderr
    #[arg(short, long, default_value_t = false)]
    pub ebpf_debug: bool,
    // TODO: Add subcommands here.
}

#[cfg(test)]
mod tests {
    use super::*;

    use clap::ValueEnum;

    #[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Debug, Deserialize, ValueEnum)]
    #[serde(rename_all = "kebab-case")]
    enum Mod1Opts {
        Foo,
        Bar,
        Baz,
    }

    #[derive(Clone, Debug, Args, Deserialize)]
    #[serde(rename_all = "kebab-case")]
    #[serde(default)]
    struct Mod1 {
        /// Module 1 someopt
        #[arg(id = "mod1-someopt", long)]
        someopt: Option<String>,

        /// Module 1 some other opts
        #[arg(id = "mod1-choice", long)]
        choice: Option<Mod1Opts>,

        /// Module 1 has a flag true by default
        #[arg(id = "mod1-flag", long)]
        flag: Option<bool>,
    }

    impl Default for Mod1 {
        fn default() -> Self {
            Mod1 {
                someopt: None,
                choice: Some(Mod1Opts::Foo),
                flag: Some(true),
            }
        }
    }

    #[derive(Clone, Debug, Default, Args, Deserialize)]
    #[serde(rename_all = "kebab-case")]
    #[serde(default)]
    struct Mod2 {
        /// Mod2 also has someopt
        #[arg(id = "mod2-someopt", long)]
        someopt: Option<String>,
    }

    #[test]
    fn register_sections() -> Result<()> {
        let mut cli = Cli::new()?;
        assert!(cli.register_config::<Mod1>("mod1").is_ok());
        assert!(cli.register_config::<Mod2>("mod2").is_ok());
        Ok(())
    }

    #[test]
    fn register_uniqueness() -> Result<()> {
        let mut cli = Cli::new()?;
        assert!(cli.register_config::<Mod1>("mod1").is_ok());
        assert!(cli.register_config::<Mod1>("mod1").is_err());
        Ok(())
    }

    #[test]
    fn cli_parse() -> Result<()> {
        let mut cli = Cli::new()?;
        assert!(cli.register_config::<Mod1>("mod1").is_ok());
        assert!(cli.register_config::<Mod2>("mod2").is_ok());
        assert!(cli.parse_from(["--help"], true).is_ok());
        Ok(())
    }

    #[test]
    fn cli_parse_args() -> Result<()> {
        let mut cli = Cli::new()?;
        assert!(cli.register_config::<Mod1>("mod1").is_ok());
        assert!(cli.register_config::<Mod2>("mod2").is_ok());
        assert!(cli
            .parse_from(
                vec![
                    "packet-tracer",
                    "--mod1-someopt",
                    "foo",
                    "--mod2-someopt",
                    "bar"
                ],
                true
            )
            .is_ok());

        let mod1 = cli.get_section::<Mod1>("mod1");
        let mod2 = cli.get_section::<Mod2>("mod2");
        assert!(mod1.is_ok());
        assert!(mod2.is_ok());

        let mod1 = mod1.unwrap();
        let mod2 = mod2.unwrap();

        assert!(mod1.someopt == Some("foo".to_string()));
        assert!(mod2.someopt == Some("bar".to_string()));
        // Default values:
        assert!(mod1.flag == Some(true));
        assert!(mod1.choice == Some(Mod1Opts::Foo));

        Ok(())
    }

    #[test]
    fn cli_parse_args_err() -> Result<()> {
        let mut cli = Cli::new()?;
        assert!(cli.register_config::<Mod1>("mod1").is_ok());
        assert!(cli.register_config::<Mod2>("mod2").is_ok());
        assert!(cli
            .parse_from(vec!["packet-tracer", "--no-exixts", "foo"], true)
            .is_err());
        assert!(cli
            .parse_from(vec!["packet-tracer", "--mod2-flag", "true"], true)
            .is_err());
        Ok(())
    }

    #[test]
    fn cli_parse_args_enum() -> Result<()> {
        let mut cli = Cli::new()?;
        assert!(cli.register_config::<Mod1>("mod1").is_ok());
        assert!(cli
            .parse_from(vec!["packet-tracer", "--mod1-choice", "baz"], true)
            .is_ok());
        let mod1 = cli.get_section::<Mod1>("mod1");
        assert!(mod1.is_ok());
        let mod1 = mod1.unwrap();

        assert!(mod1.choice == Some(Mod1Opts::Baz));

        Ok(())
    }

    #[test]
    fn cli_parse_args_enum_err() -> Result<()> {
        let mut cli = Cli::new()?;
        assert!(cli.register_config::<Mod1>("mod1").is_ok());
        assert!(cli.register_config::<Mod2>("mod2").is_ok());
        assert!(cli
            .parse_from(vec!["packet-tracer", "--mod1-choice", "wrong"], true)
            .is_err());
        Ok(())
    }

    #[test]
    fn cli_parse_profile() -> Result<()> {
        let mut cli = Cli::new()?;
        assert!(cli.register_config::<Mod1>("mod1").is_ok());
        assert!(cli.register_config::<Mod2>("mod2").is_ok());
        assert!(cli
            .parse_from(vec!["packet-tracer", "-p", "test_data/profile1.toml"], true)
            .is_ok());

        let mod1 = cli.get_section::<Mod1>("mod1");
        let mod2 = cli.get_section::<Mod2>("mod2");
        assert!(mod1.is_ok());
        assert!(mod2.is_ok());

        let mod1 = mod1.unwrap();
        let mod2 = mod2.unwrap();

        assert!(mod1.someopt == Some("foo".to_string()));
        assert!(mod1.flag == Some(false));
        assert!(mod1.choice == Some(Mod1Opts::Bar));
        assert!(mod2.someopt == Some("baz".to_string()));

        Ok(())
    }

    #[test]
    fn cli_parse_profile_priority() -> Result<()> {
        let mut cli = Cli::new()?;
        assert!(cli.register_config::<Mod1>("mod1").is_ok());
        assert!(cli.register_config::<Mod2>("mod2").is_ok());
        assert!(cli
            .parse_from(
                vec![
                    "packet-tracer",
                    "-p",
                    "test_data/profile1.toml",
                    "--mod1-someopt",
                    "bar",
                    "--mod1-choice",
                    "baz"
                ],
                true
            )
            .is_ok());

        let mod1 = cli.get_section::<Mod1>("mod1");
        let mod2 = cli.get_section::<Mod2>("mod2");
        assert!(mod1.is_ok());
        assert!(mod2.is_ok());

        let mod1 = mod1.unwrap();
        let mod2 = mod2.unwrap();

        assert!(mod1.someopt == Some("bar".to_string()));
        assert!(mod1.flag == Some(false));
        assert!(mod1.choice == Some(Mod1Opts::Baz));
        assert!(mod2.someopt == Some("baz".to_string()));

        Ok(())
    }

    #[test]
    fn cli_parse_profile_err() -> Result<()> {
        let mut cli = Cli::new()?;
        assert!(cli.register_config::<Mod1>("mod1").is_ok());
        assert!(cli.register_config::<Mod2>("mod2").is_ok());
        assert!(cli
            .parse_from(
                vec!["packet-tracer", "-p", "test_data/profile_err.toml"],
                true
            )
            .is_ok());

        assert!(cli.get_section::<Mod1>("mod1").is_err());
        assert!(cli.get_section::<Mod2>("mod2").is_ok());
        Ok(())
    }
}
