use std::{env, path::PathBuf};

use anyhow::{bail, Result};
use clap::Parser;

use crate::{cli::*, events::python_embed::shell_execute};

#[derive(Parser, Debug, Default)]
#[command(name = "python", about = "Runs Python scripts with events imported.")]
pub(crate) struct PythonCli {
    #[arg(
        long,
        short,
        default_value = "retis.data",
        help = "File from which to read events"
    )]
    pub(super) input: PathBuf,
    #[arg(
        help = "Python script to execute. Omit to drop into an interactive shell. Alternatively scripts can be stored in $HOME/.config/retis/python and /usr/share/retis/python, in which case the file name only (without the .py extension) can be provided."
    )]
    pub(super) script: Option<PathBuf>,
    #[arg(help = "Arguments for the Python script (available in `sys.argv`).")]
    pub(super) args: Vec<String>,
}

impl SubCommandParserRunner for PythonCli {
    fn run(&mut self, _: &MainConfig) -> Result<()> {
        let mut script_path = None;

        if let Some(script) = &self.script {
            match script.try_exists() {
                Ok(true) => script_path = Some(script.clone()),
                _ => {
                    for path in get_python_paths() {
                        let path = path.join(script).with_extension("py");
                        match path.try_exists() {
                            Ok(true) => {
                                script_path = Some(path);
                                break;
                            }
                            _ => continue,
                        }
                    }

                    if script_path.is_none() {
                        bail!("Python script named {} not found", script.display());
                    }
                }
            }
        }

        shell_execute(self.input.clone(), script_path.as_ref(), &self.args)
    }
}

fn get_python_paths() -> Vec<PathBuf> {
    let mut paths = Vec::new();
    if cfg!(debug_assertions) {
        paths.push(PathBuf::from("retis/python/"));
    }
    if let Ok(home) = env::var("HOME") {
        paths.push(PathBuf::from(home).join(".config/retis/python/"));
    }
    paths.push(PathBuf::from("/usr/share/retis/python/"));
    paths
}
