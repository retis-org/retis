#![allow(dead_code)] // FIXME
use std::{fs::read_to_string, path::PathBuf};

use anyhow::Result;
use serde::Deserialize;

/// Profile information.
#[derive(Deserialize, Debug)]
#[serde(rename_all = "snake_case")]
pub(crate) struct Profile {
    /// Name of the profile.
    pub(crate) name: String,
    /// Version of the Profile API that is being used.
    pub(crate) version: String,
    /// Information about the profile in human readable format.
    pub(crate) about: Option<String>,
}

impl Profile {
    /// Load a profile from a path.
    pub fn load(path: PathBuf) -> Result<Profile> {
        let contents = read_to_string(path)?;
        let profile = Profile::from_str(contents.as_str())?;
        Ok(profile)
    }

    /// Load a profile from a string.
    pub fn from_str(contents: &str) -> Result<Profile> {
        Ok(serde_yaml::from_str(contents)?)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn load_file() {
        let p = Profile::load(PathBuf::from("test_data/profiles/example.yaml")).unwrap();
        assert_eq!(p.name, "example-profile");
        assert_eq!(p.version, "1.0.0");
    }
}
