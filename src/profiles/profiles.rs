#![allow(dead_code)] // FIXME
use std::{fs::read_to_string, path::PathBuf};

use anyhow::Result;
use serde::Deserialize;
use serde::Serialize;

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
  - name: Too new
    when:
      - type: version
        version: "> 9"
  - name: Symbol exsists
    when:
      - type: symbol
        name: unexisting_symbol
  - name: Symbol does not exist
    when:
      - type: symbol
        name: skb:kfree_skb
        exists: false
  - name: Correct
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
  - name: Last
"#
        )
        .expect("parsing")
        .match_collect()
        .expect("matching")
        .unwrap()
        .name
        .eq("First"));
    }
}
