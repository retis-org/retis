#![allow(dead_code)] // FIXME
use std::{collections::BTreeMap, env, ffi::OsString, fs::read_to_string, path::PathBuf};

use anyhow::{bail, Result};
use log::{debug, info, warn};
use serde::{Deserialize, Serialize};

use crate::core::{
    inspect::{
        inspector,
        kernel_version::{KernelVersion, KernelVersionReq},
    },
    kernel::symbol::Symbol,
};

/// Specifies a condition on the kernel version.
#[derive(Deserialize, Debug)]
pub(crate) struct VersionCondition {
    version: KernelVersionReq,
}

impl VersionCondition {
    fn matches(&self) -> Result<bool> {
        Ok(self.matches_ver(inspector()?.kernel.version()))
    }

    fn matches_ver(&self, ver: &KernelVersion) -> bool {
        self.version.matches(ver)
    }
}

/// Specifies a condition on the existance of a symbol.
#[derive(Deserialize, Serialize, Debug)]
pub(crate) struct SymbolCondition {
    /// Name of the target symbol, e.g: "skb:kfree_skb", "consume_skb".
    pub(crate) name: String,
    /// Whether the symbol must exist or not.
    #[serde(default = "default_true")]
    pub(crate) exists: bool,
}

fn default_true() -> bool {
    true
}

impl SymbolCondition {
    fn matches(&self) -> Result<bool> {
        Ok(Symbol::from_name(&self.name).is_ok() == self.exists)
    }
}

/// Specifies a condition that must be met for a CollectProfile to be applied.
#[derive(Deserialize, Debug)]
#[serde(tag = "type")]
pub(crate) enum CollectCondition {
    #[serde(rename = "version")]
    Version(VersionCondition),
    #[serde(rename = "symbol")]
    Symbol(SymbolCondition),
}

impl CollectCondition {
    fn matches(&self) -> Result<bool> {
        match self {
            CollectCondition::Version(v) => v.matches(),
            CollectCondition::Symbol(s) => s.matches(),
        }
    }
}

#[derive(Deserialize, Serialize, Debug)]
#[serde(untagged)]
pub(crate) enum ArgValue {
    Single(String),
    Sequence(Vec<String>),
    Flag,
}

/// Collect profile.
#[derive(Deserialize, Debug)]
#[serde(rename_all = "snake_case")]
pub(crate) struct CollectProfile {
    /// Name of this collect profile
    #[serde(default = "default_name")]
    pub(crate) name: String,
    /// Set of conditions associated with the profile
    #[serde(default = "Vec::default")]
    pub(crate) when: Vec<CollectCondition>,
    /// Arguments to be appended to the CLI if this profile is active
    pub(crate) args: BTreeMap<String, ArgValue>,
}

impl CollectProfile {
    fn matches(&self) -> Result<bool> {
        if self.when.is_empty() {
            return Ok(true);
        }
        for c in self.when.iter() {
            if !c.matches()? {
                return Ok(false);
            }
        }
        Ok(true)
    }
}

fn default_name() -> String {
    "Default".to_string()
}

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
    /// Collect Profiles
    #[serde(default = "Vec::new")]
    pub(crate) collect: Vec<CollectProfile>,
}

impl Profile {
    /// Find a profile
    pub fn find(name: &str) -> Result<Profile> {
        for path in get_profile_paths()?.iter().filter(|p| p.as_path().exists()) {
            for entry in path.read_dir()? {
                let entry = entry?;
                match Profile::load(entry.path()) {
                    Ok(profile) => {
                        if profile.name.eq(name) {
                            return Ok(profile);
                        }
                    }
                    Err(err) => {
                        debug!("Skipping invalid profile {}: {err}", entry.path().display())
                    }
                }
            }
        }
        bail!("Profile with name {name} not found");
    }

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

    /// Evaluate collect profiles and return the one that matches.
    pub fn match_collect(&self) -> Result<Option<&CollectProfile>> {
        if self.collect.is_empty() {
            return Ok(None);
        }

        for p in self.collect.iter() {
            if p.matches()? {
                return Ok(Some(p));
            }
        }
        Ok(None)
    }

    /// Generate cli arguments from a profile. The result is a list of arguments that can be
    /// concatenated to the ones provided by the user.
    pub fn cli_args(&self, subcommand: &str) -> Result<Vec<OsString>> {
        let mut result = Vec::new();
        let args = match subcommand {
            "collect" => {
                let collect = match self.match_collect()? {
                    None => {
                        warn!(
                            "None of the collect profiles defined in {} were selected",
                            self.name
                        );
                        return Ok(result);
                    }
                    Some(collect) => collect,
                };
                info!("Applying profile {}: {}", self.name, collect.name);
                &collect.args
            }
            _ => bail!("Subcommand {subcommand} does not support profile enhancement"),
        };

        args.iter()
            .map(|(k, v)| (format!("--{}", &k.replace('_', "-")), v))
            .for_each(|(k, v)| match v {
                ArgValue::Single(s) => {
                    result.push(k.into());
                    result.push(s.into())
                }
                ArgValue::Sequence(sec) => {
                    for value in sec.iter() {
                        result.push(k.clone().into());
                        result.push(value.into())
                    }
                }
                ArgValue::Flag => result.push(k.into()),
            });

        Ok(result)
    }
}

/// Return the list of paths to be used for profile lookup.
pub(super) fn get_profile_paths() -> Result<Vec<PathBuf>> {
    // Paths are inspected in order so keep them ordered by (descending) priority.
    let mut paths = Vec::new();
    if cfg!(debug_assertions) {
        paths.push(PathBuf::from("test_data/profiles/"));
    }
    if let Ok(home) = env::var("HOME") {
        paths.push(PathBuf::from(home).join(".config/retis/profiles/"));
    }
    paths.push(PathBuf::from("/etc/retis/profiles/"));
    Ok(paths)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn load_file() {
        let p = Profile::load(PathBuf::from("test_data/profiles/example.yaml")).unwrap();
        assert_eq!(p.name, "example-profile");
        assert_eq!(p.version, "1.0");
    }

    #[test]
    fn collect_when_version() {
        fn version_cond(s: &'static str) -> VersionCondition {
            match Profile::from_str(s)
                .unwrap()
                .collect
                .pop()
                .unwrap()
                .when
                .pop()
                .unwrap()
            {
                CollectCondition::Version(v) => return v,
                _ => panic!("Wrong condition type"),
            }
        }

        let w = version_cond(
            r#"
version: 1.0.0
name: test
collect:
  - when:
      - type: version
        version: "=4.6.1"
    args:
"#,
        );
        assert!(w.matches_ver(&KernelVersion::parse("4.6.1").unwrap()));
        assert!(!w.matches_ver(&KernelVersion::parse("4.6.2").unwrap()));

        let w = version_cond(
            r#"
version: 1.0.0
name: test
collect:
  - when:
      - type: version
        version: ">4.6.1"
    args:
"#,
        );
        assert!(!w.matches_ver(&KernelVersion::parse("4.6.1").unwrap()));
        assert!(w.matches_ver(&KernelVersion::parse("4.6.2").unwrap()));

        let w = version_cond(
            r#"
version: 1.0.0
name: test
collect:
  - when:
      - type: version
        version: ">4.6.1, <5.1.1"
    args:
"#,
        );
        assert!(!w.matches_ver(&KernelVersion::parse("4.6.1").unwrap()));
        assert!(w.matches_ver(&KernelVersion::parse("4.6.2").unwrap()));
        assert!(w.matches_ver(&KernelVersion::parse("5.1.0").unwrap()));
        assert!(!w.matches_ver(&KernelVersion::parse("5.1.1").unwrap()));
    }

    #[test]
    fn collect_when_symbol() {
        assert!(!&Profile::from_str(
            r#"
version: 1.0.0
name: test
collect:
  - when:
      - type: symbol
        name: foo
    args:
"#
        )
        .unwrap()
        .collect[0]
            .when[0]
            .matches()
            .unwrap());

        assert!(&Profile::from_str(
            r#"
version: 1.0.0
name: test
collect:
  - when:
      - type: symbol
        name: foo
        exists: false
    args:
"#
        )
        .unwrap()
        .collect[0]
            .when[0]
            .matches()
            .unwrap());

        assert!(&Profile::from_str(
            r#"
version: 1.0.0
name: test
collect:
  - when:
      - type: symbol
        name: consume_skb
    args:
"#
        )
        .unwrap()
        .collect[0]
            .when[0]
            .matches()
            .unwrap());

        assert!(!&Profile::from_str(
            r#"
version: 1.0.0
name: test
collect:
  - when:
      - type: symbol
        name: consume_skb
        exists: false
    args:
"#
        )
        .unwrap()
        .collect[0]
            .when[0]
            .matches()
            .unwrap());
    }

    #[test]
    fn collect_match() {
        assert!(&Profile::from_str(
            r#"
version: 1.0.0
name: test
collect:
  - name: Too old
    when:
      - type: version
        version: "= 3"
    args:
  - name: Too new
    when:
      - type: version
        version: "> 9"
    args:
  - name: Symbol exsists
    when:
      - type: symbol
        name: unexisting_symbol
    args:
  - name: Symbol does not exist
    when:
      - type: symbol
        name: skb:kfree_skb
        exists: false
    args:
  - name: Correct
    args:
"#,
        )
        .expect("parsing")
        .match_collect()
        .expect("matching")
        .unwrap()
        .name
        .eq("Correct"));

        assert!(&Profile::from_str(
            r#"
version: 1.0.0
name: test
collect:
  - name: First
    when:
      - type: version
        version: "> 6.0.0 <= 7"
    args:
  - name: Last
    args:
"#
        )
        .expect("parsing")
        .match_collect()
        .expect("matching")
        .unwrap()
        .name
        .eq("First"));
    }

    #[test]
    fn collect_args() {
        assert!(&Profile::from_str(
            r#"
version: 1.0.0
name: test
collect:
  - name: Default
    args:
      probe:
        - kprobe:ip_rcv
        - kprobe:ip_finish_output2
        - kprobe:napi_gro_receive
        - kprobe:inet_gro_receive
      skb_sections:
       - l3
       - tcp
"#,
        )
        .expect("parsing")
        .cli_args("collect")
        .and_then(|e| {
            println!("{:?}", e);
            Ok(e)
        })
        .unwrap()
        .eq(&vec![
            "--probe",
            "kprobe:ip_rcv",
            "--probe",
            "kprobe:ip_finish_output2",
            "--probe",
            "kprobe:napi_gro_receive",
            "--probe",
            "kprobe:inet_gro_receive",
            "--skb-sections",
            "l3",
            "--skb-sections",
            "tcp"
        ]));

        assert!(&Profile::from_str(
            r#"
version: 1.0.0
name: test
collect:
  - name: Default
    args:
      probe: kprobe:ip_rcv
      skb_sections: l3,tcp
      ovs-track: ~
"#,
        )
        .expect("parsing")
        .cli_args("collect")
        .and_then(|e| {
            println!("{:?}", e);
            Ok(e)
        })
        .unwrap()
        .eq(&vec![
            "--ovs-track",
            "--probe",
            "kprobe:ip_rcv",
            "--skb-sections",
            "l3,tcp",
        ]));
    }
}
