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

    Ok(RotationPolicy::Size(limit))
}

/// Given an "input" command line option (e.g. from the "print" or "sort"
/// sub-commands), returns a `FileEventsFactory`. This handles the following
/// cases:
/// - No input is given: use the default behavior ("retis.data.." then
///   "retis.data.0..").
/// - A range is given: use `RotateReader` as the underlying reader.
/// - A single file is given: use a non-rotate reader.
pub(crate) fn factory_from_retis_data(input: Option<&PathBuf>) -> Result<FileEventsFactory> {
    match input {
        Some(input) => {
            let input = input
                .to_str()
                .ok_or_else(|| anyhow!("Cannot convert input file to str"))?;

            match input.strip_suffix("..") {
                // E.g. "retis.data.."
                Some(input) => FileEventsFactory::new(Box::new(RotateReader::new(
                    PathBuf::from(input),
                    false,
                )?)),
                // E.g. "retis.data"
                None => FileEventsFactory::from_path(input),
            }
        }
        // Default behavior.
        None => FileEventsFactory::new(Box::new(RotateReader::new(
            PathBuf::from("retis.data"),
            true,
        )?)),
    }
}
