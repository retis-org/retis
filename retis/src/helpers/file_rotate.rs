/// # Writer handling file rotation
use std::{path::PathBuf, str::FromStr};

use anyhow::{anyhow, bail, Result};
use regex::Regex;

use crate::events::file::{rotate::*, *};

/// Convert an str representation of a limit to a `RotationPolicy`.
/// Accepted values are numbers suffixed with a unit size (MB or GB).
pub(crate) fn rotation_policy_from_str(limit: &str) -> Result<RotationPolicy> {
    let re = Regex::new(r"(\d+)(M|G)B")?;
    let matches = re
        .captures(limit)
        .ok_or_else(|| anyhow!("Invalid limit format ({limit})"))?;

    // Unwrap as the regex already checked the second group was mandatory.
    let factor = match matches.get(2).unwrap().as_str() {
        "M" => 1000 * 1000,
        "G" => 1000 * 1000 * 1000,
        _ => 1,
    };

    // Unwrap as the regex already checked the first group was mandatory.
    let limit = usize::from_str(matches.get(1).unwrap().as_str())? * factor;

    if limit == 0 {
        bail!("Invalid limit value (0)");
    }

    Ok(RotationPolicy::Size { limit })
}

// Custom argument type to represent the input file. This automatically handles
// the rotation logic, if any. Can be used within `clap` directly.
#[derive(Clone, Debug)]
pub(crate) struct InputDataFile {
    pub(crate) path: PathBuf,
    use_rotation: bool,
    try_split: bool,
}

impl InputDataFile {
    // Help text to be used in the cli argument directly.
    pub(crate) fn help() -> &'static str {
        "File from which to read events:
- If a file name is given, it is read and processing stops at EOF. E.g. 'retis.data'.
- If '..' is appended to a file name, it is read and if it is a split file following ones will be read at EOF (if any). E.g. 'retis.data.2..'.
[default: 'retis.data', then 'retis.data.0..']"
    }

    pub(crate) fn to_factory(&self) -> Result<FileEventsFactory> {
        if self.use_rotation {
            FileEventsFactory::new(Box::new(RotateReader::new(
                self.path.clone(),
                self.try_split,
            )?))
        } else {
            let path_str = self
                .path
                .to_str()
                .ok_or_else(|| anyhow!("Cannot convert path to str"))?;
            FileEventsFactory::from_path(path_str)
        }
    }
}

impl Default for InputDataFile {
    fn default() -> Self {
        Self {
            path: PathBuf::from("retis.data"),
            use_rotation: true,
            try_split: true,
        }
    }
}

impl FromStr for InputDataFile {
    type Err = String;

    fn from_str(path: &str) -> std::result::Result<Self, Self::Err> {
        let input = match path.strip_suffix("..") {
            Some(path_first) => Self {
                path: PathBuf::from(path_first),
                use_rotation: true,
                try_split: false,
            },
            None => Self {
                path: PathBuf::from(path),
                use_rotation: false,
                try_split: false,
            },
        };

        if !&input.path.exists() {
            return Err("No such file or directory".to_string());
        }

        Ok(input)
    }
}
