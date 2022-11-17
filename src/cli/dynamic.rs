//! # Dynamic
//!
//! Wrapper around clap's Command that allows for dynamic registration of modules.
//! Each registered module will have its own section in the final long help.
#![allow(dead_code)] // FIXME

use std::{collections::HashSet, fmt::Debug};

use anyhow::{bail, Result};
use clap::{ArgMatches, Args, Command, FromArgMatches};

/// DynamicCommand is a wrapper around clap's Command that supports modules all around the code
/// base to dynamically register arguments using clap's derive interface.
///
/// Due to how clap argument augmentation works, the main Command's about is overwritten with the
/// documentation comments of each module that gets registered. Therefore, before consuming the
/// resulting Command, and after all modules have been registered, "about" and "long_about"
/// have to be set explicitly.
#[derive(Debug)]
pub(crate) struct DynamicCommand {
    modules: HashSet<String>,
    command: Command,
    heading: String,
    matches: Option<ArgMatches>,
}

impl DynamicCommand {
    /// Creates a new instance of DynamicCommand with a heading name around the provided command.
    ///
    /// When a module is registered, its command line arguments will be arranged into an
    /// independent section with a section heading, that is built using `heading`.
    ///
    /// {heading_name} {module_name}:
    ///     --arg1          Does something
    ///     --arg2          Does something else
    ///
    /// The heading name is the name to give to modules in the help string.
    pub(crate) fn new(command: Command, heading: &'static str) -> Result<Self> {
        Ok(DynamicCommand {
            modules: HashSet::new(),
            command,
            heading: String::from(heading),
            matches: None,
        })
    }

    /// Register a set of module arguments with a module name.
    ///
    /// The module name has to be unique.
    pub(crate) fn register_module<T>(&mut self, name: &'static str) -> Result<()>
    where
        T: Args,
    {
        self.register_module_noargs(name)?;

        let command = self
            .command
            .to_owned()
            .next_help_heading(format!("{} {}", self.heading, name));

        self.command = T::augment_args_for_update(command);
        Ok(())
    }

    /// Register a module with no arguments
    ///
    /// The module name has to be unique.
    pub(crate) fn register_module_noargs(&mut self, name: &'static str) -> Result<()> {
        let name = String::from(name);
        if self.modules.get(&name).is_some() {
            bail!("module with name {} already registered", name);
        }
        self.modules.insert(name);
        Ok(())
    }

    /// Stores a copy of the ArgMatches that will be used to render module section arguments.
    pub(crate) fn set_matches(&mut self, matches: &ArgMatches) -> Result<&mut Self> {
        self.matches = Some(matches.clone());
        Ok(self)
    }

    /// Returns the internal command to be consumed.
    pub(crate) fn command(&self) -> &Command {
        &self.command
    }

    /// Returns a mutable reference to the internal command to be consumed.
    pub(crate) fn command_mut(&mut self) -> &mut Command {
        &mut self.command
    }

    /// Returns the module name list.
    pub(crate) fn modules(&self) -> &HashSet<String> {
        &self.modules
    }

    /// Creates a new instance of module arguments M based on the stored ArgMatches.
    pub(crate) fn get_section<M>(&self, name: &str) -> Result<M>
    where
        M: Default + FromArgMatches,
    {
        if self.modules.get(name).is_none() {
            bail!("module {} not registered", name);
        }
        let mut target = M::default();
        match &self.matches {
            Some(matches) => target.update_from_arg_matches(matches)?,
            None => bail!("matches not set. Make sure set_matches has been called before"),
        }
        Ok(target)
    }

    /// Creates a new instance of main arguments T based on the stored ArgMatches.
    pub(crate) fn get_main<T>(&self) -> Result<T>
    where
        T: Default + FromArgMatches,
    {
        let mut target = T::default();
        match &self.matches {
            Some(matches) => target.update_from_arg_matches(matches)?,
            None => bail!("matches not set"),
        }
        Ok(target)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::error::ErrorKind;

    #[derive(Clone, Args)]
    struct Main {
        /// Main option
        #[arg(id = "someopt", long)]
        opt: Option<String>,

        /// Main flag
        #[arg(id = "flag", long)]
        flag: Option<bool>,
    }
    impl Default for Main {
        fn default() -> Self {
            Main {
                opt: None,
                flag: Some(false),
            }
        }
    }

    #[derive(Clone, Args)]
    struct Mod1 {
        /// Module 1 someopt
        #[arg(id = "mod1-someopt", long)]
        someopt: Option<String>,

        /// Module 1 has a flag true by default
        #[arg(id = "mod1-flag", long)]
        flag: Option<bool>,
    }

    impl Default for Mod1 {
        fn default() -> Self {
            Mod1 {
                someopt: None,
                flag: Some(true),
            }
        }
    }

    #[derive(Clone, Args)]
    struct Mod2 {
        /// Module 2 someopt
        #[arg(id = "mod2-someopt", long)]
        someopt: Option<String>,

        /// Module 2 has a flag
        #[arg(id = "mod2-flag", long)]
        flag: Option<bool>,
    }

    impl Default for Mod2 {
        fn default() -> Self {
            Mod2 {
                someopt: None,
                flag: Some(false),
            }
        }
    }

    #[test]
    fn dynamic_create() -> Result<()> {
        assert!(
            DynamicCommand::new(Main::augment_args(Command::new("mycommand")), "stuff").is_ok()
        );
        Ok(())
    }

    #[test]
    fn dynamic_register() -> Result<()> {
        let cmd = DynamicCommand::new(Main::augment_args(Command::new("mycommand")), "stuff");
        assert!(cmd.is_ok());
        let mut cmd = cmd?;

        assert!(cmd.register_module::<Mod1>("mod1").is_ok());
        assert!(cmd.register_module::<Mod1>("mod1").is_err());
        assert!(cmd.register_module::<Mod2>("mod2").is_ok());
        assert!(cmd.register_module_noargs("mod3").is_ok());
        assert!(cmd.register_module_noargs("mod3").is_err());
        assert!(cmd.modules().contains("mod1"));
        assert!(cmd.modules().contains("mod2"));
        assert!(cmd.modules().contains("mod3"));
        Ok(())
    }

    #[test]
    fn dynamic_parse() -> Result<()> {
        let cmd = DynamicCommand::new(Main::augment_args(Command::new("mycommand")), "stuff");
        assert!(cmd.is_ok());
        let mut cmd = cmd?;

        assert!(cmd.register_module::<Mod1>("mod1").is_ok());
        assert!(cmd.register_module::<Mod2>("mod2").is_ok());

        let err = cmd
            .command_mut()
            .try_get_matches_from_mut(vec!["mycommand", "--help"]);
        assert!(err.is_err() && err.unwrap_err().kind() == ErrorKind::DisplayHelp);

        let err = cmd
            .command()
            .clone()
            .try_get_matches_from(vec!["mycommand", "--help"]);
        assert!(err.is_err() && err.unwrap_err().kind() == ErrorKind::DisplayHelp);

        // Parse main arguments.
        let err = cmd
            .command_mut()
            .try_get_matches_from_mut(vec!["mycommand", "--someopt", "foo"]);
        assert!(err.is_ok());

        let err = cmd
            .command_mut()
            .try_get_matches_from_mut(vec!["mycommand", "--flag", "true"]);
        assert!(err.is_ok());

        let err =
            cmd.command_mut()
                .try_get_matches_from_mut(vec!["mycommand", "--noexists", "foo"]);
        assert!(err.is_err() && err.unwrap_err().kind() == ErrorKind::UnknownArgument);

        // Parse module arguments.
        let matches = cmd.command_mut().try_get_matches_from_mut(vec![
            "mycommand",
            "--mod1-someopt",
            "foo",
            "--mod2-flag",
            "true",
        ]);
        assert!(matches.is_ok());

        let err =
            cmd.command_mut()
                .try_get_matches_from_mut(vec!["mycommand", "--mod1-noexists", "foo"]);
        assert!(err.is_err() && err.unwrap_err().kind() == ErrorKind::UnknownArgument);

        let err = cmd.command_mut().try_get_matches_from_mut(vec![
            "mycommand",
            "--mod2-flag",
            "wrongvalue",
        ]);
        assert!(err.is_err() && err.unwrap_err().kind() == ErrorKind::InvalidValue);
        Ok(())
    }

    #[test]
    fn dynamic_get_main() -> Result<()> {
        let cmd = DynamicCommand::new(Main::augment_args(Command::new("mycommand")), "stuff");
        assert!(cmd.is_ok());
        let mut cmd = cmd?;

        assert!(cmd.register_module::<Mod1>("mod1").is_ok());
        assert!(cmd.register_module::<Mod2>("mod2").is_ok());

        let matches = cmd.command_mut().try_get_matches_from_mut(vec![
            "mycommand",
            "--someopt",
            "foo",
            "--flag",
            "true",
        ]);
        assert!(matches.is_ok());
        let matches = matches.unwrap();
        assert!(cmd.set_matches(&matches).is_ok());

        assert!(cmd.get_main::<Main>().is_ok());
        assert!(cmd.get_main::<Main>().unwrap().opt == Some("foo".to_string()));
        assert!(cmd.get_main::<Main>().unwrap().flag == Some(true));

        Ok(())
    }
    #[test]
    fn dynamic_get_section() -> Result<()> {
        let cmd = DynamicCommand::new(Main::augment_args(Command::new("mycommand")), "stuff");
        assert!(cmd.is_ok());
        let mut cmd = cmd?;

        assert!(cmd.register_module::<Mod1>("mod1").is_ok());
        assert!(cmd.register_module::<Mod2>("mod2").is_ok());

        let matches = cmd.command_mut().try_get_matches_from_mut(vec![
            "mycommand",
            "--mod1-someopt",
            "foo",
            "--mod2-flag",
            "true",
        ]);
        assert!(matches.is_ok());
        let matches = matches.unwrap();
        assert!(cmd.set_matches(&matches).is_ok());
        assert!(cmd.get_section::<Mod1>("mod1").is_ok());
        assert!(cmd.get_section::<Mod1>("mod1").unwrap().someopt == Some("foo".to_string()));
        assert!(cmd.get_section::<Mod1>("mod1").unwrap().flag == Some(true)); // default value is true.
        assert!(cmd.get_section::<Mod2>("mod2").unwrap().flag == Some(true));

        Ok(())
    }
}
