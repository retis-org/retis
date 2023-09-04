#![allow(dead_code)] // FIXME

use std::{cmp::Ordering, fmt};

use anyhow::{anyhow, bail, Result};
#[cfg(not(test))]
use nix::sys::utsname::uname;
use regex::Regex;

/// Represents a kernel version, eg. 6.2.14-300.fc38.x86_64
pub(crate) struct KernelVersion {
    /// Major number, eg. 6.
    major: u32,
    /// Minor number, eg. 2.
    minor: u32,
    /// Patch number, eg. 14.
    patch: u32,
    /// Build number, eg. 300.
    build: Option<u32>,
    /// Full kernel release version, same as `$(uname -r)`, eg.
    /// 6.2.14-300.fc38.x86_64.
    pub(crate) full: String,
}

impl KernelVersion {
    pub(super) fn new() -> Result<Self> {
        Self::parse(
            #[cfg(not(test))]
            uname()
                .map_err(|e| anyhow!("Failed to get kernel version information: {e}"))?
                .release()
                .to_str()
                .ok_or_else(|| anyhow!("Could not convert kernel version to str"))?,
            #[cfg(test)]
            "6.2.14-300.fc38.x86_64",
        )
    }

    /// Parse a version string of the `$(uname -r)` form into a KernelVersion.
    pub(crate) fn parse(version: &str) -> Result<Self> {
        let mut parts = version.split('.');

        let major: u32 = parts
            .next()
            .ok_or_else(|| anyhow!("Could not get kernel major version from {version}"))?
            .parse()?;
        let minor: u32 = parts
            .next()
            .ok_or_else(|| anyhow!("Could not get kernel minor version from {version}"))?
            .parse()?;
        let mut tmp = parts
            .next()
            .ok_or_else(|| anyhow!("Could not get kernel patch-build version from {version}"))?
            .split('-');
        let patch: u32 = tmp
            .next()
            .ok_or_else(|| anyhow!("Could not get kernel patch version from {version}"))?
            .trim_end_matches('+')
            .parse()?;

        // Build can be in any position of the remaining string, e.g:
        // 6.2.0-20-generic or 6.4.12-arch1-1.
        let build = tmp.find_map(|s| s.parse::<u32>().ok());

        Ok(KernelVersion {
            major,
            minor,
            patch,
            build,
            full: version.to_string(),
        })
    }
}

/// Represents requirements for testing kernel versions. Can hold up to two
/// comparators to express things like "> 6.2, <= 6.5"
#[derive(Debug)]
pub(crate) struct KernelVersionReq(Vec<KernelVersionCmp>);

impl KernelVersionReq {
    /// Parse a requirement str into a kernel version requirement obj.
    ///
    /// The requirement str is defined as follows:
    /// - Supported operators are: =, >, <, >=, <= and !=.
    /// - Kernel versions are expressed in the "major.minor.patch-build" form,
    ///   only the major number is mandatory.
    /// - One requirement must follow: "<op><version>" with optional spaces
    ///   after the operation identifier.
    /// - Two requirements can be combined using a comma (,) as follows:
    ///   "<req1>,<req2>" with optional spaces around the requirements.
    ///
    /// Examples:
    /// ```
    /// KernelVersionReq::parse("= 6.2.14-300");
    /// KernelVersionReq::parse(">= 6.2.14-300");
    /// KernelVersionReq::parse("> 6.2");
    /// KernelVersionReq::parse("!= 5");
    /// KernelVersionReq::parse("> 6, <= 6.3");
    /// ```
    pub(crate) fn parse(req: &str) -> Result<Self> {
        let cmps = match req.split_once(',') {
            Some((a, b)) => vec![
                KernelVersionCmp::parse(a.trim())?,
                KernelVersionCmp::parse(b.trim())?,
            ],
            None => vec![KernelVersionCmp::parse(req)?],
        };

        Ok(KernelVersionReq(cmps))
    }

    /// Matches a kernel version against version requirements, return true if
    /// the kernel version matches the requirements.
    pub(crate) fn matches(&self, version: &KernelVersion) -> bool {
        for cmp in self.0.iter() {
            if !cmp.compare(version) {
                return false;
            }
        }
        true
    }
}

impl<'de> serde::Deserialize<'de> for KernelVersionReq {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        struct ReqVisitor;

        impl<'de> serde::de::Visitor<'de> for ReqVisitor {
            type Value = KernelVersionReq;

            fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
                formatter.write_str("kernel version requirement")
            }

            fn visit_str<E>(self, value: &str) -> Result<Self::Value, E>
            where
                E: serde::de::Error,
            {
                match KernelVersionReq::parse(value) {
                    Ok(v) => Ok(v),
                    Err(_) => Err(serde::de::Error::invalid_value(
                        serde::de::Unexpected::Str(value),
                        &self,
                    )),
                }
            }
        }

        deserializer.deserialize_str(ReqVisitor)
    }
}

/// Represents a kernel version comparator. See documentation of
/// `KernelVersion` for a description of the members.
#[derive(Debug)]
pub(crate) struct KernelVersionCmp {
    op: Operator,
    major: u32,
    minor: Option<u32>,
    patch: Option<u32>,
    build: Option<u32>,
}

impl KernelVersionCmp {
    /// Parse one requirement expression and convert it to a kernel comparison
    /// operator. See `KernelVersionReq::parse` for more information on the
    /// requirement str format.
    fn parse(req: &str) -> Result<Self> {
        let re =
            Regex::new(r"(=|>|<|>=|<=|!=)(?:\s*)?(\d+)(?:.(\d+))?(?:.(\d+))?-?(?:(\d+))?(?:\**)?")?;
        let matches = re
            .captures(req)
            .ok_or_else(|| anyhow!("Couldn't capture version members in {req}"))?;

        let op = match matches.get(1) {
            Some(op) => match op.as_str() {
                "=" => Operator::Eq,
                "!=" => Operator::Ne,
                ">" => Operator::Gt,
                "<" => Operator::Lt,
                ">=" => Operator::Ge,
                "<=" => Operator::Le,
                x => bail!("Invalid operator {x}"),
            },
            None => bail!("No operator found in version comparator"),
        };

        let convert = |from: Option<regex::Match>| -> Result<Option<u32>> {
            Ok(match from {
                Some(x) => Some(x.as_str().parse()?),
                None => None,
            })
        };

        let major = match matches.get(2) {
            Some(major) => major.as_str().parse()?,
            None => bail!("Invalid version comparator, no major version found"),
        };

        Ok(KernelVersionCmp {
            op,
            major,
            minor: convert(matches.get(3))?,
            patch: convert(matches.get(4))?,
            build: convert(matches.get(5))?,
        })
    }

    /// Compare a kernel version againt the comparator. Returns true if the
    /// kernel version matches the requirements.
    fn compare(&self, version: &KernelVersion) -> bool {
        self.op.matches_order(self.order(version))
    }

    fn order(&self, version: &KernelVersion) -> Ordering {
        if version.major != self.major {
            return version.major.cmp(&self.major);
        }

        match self.minor {
            Some(minor) => {
                if version.minor != minor {
                    return version.minor.cmp(&minor);
                }
            }
            None => return Ordering::Equal,
        }

        match self.patch {
            Some(patch) => {
                if version.patch != patch {
                    return version.patch.cmp(&patch);
                }
            }
            None => return Ordering::Equal,
        }

        match (self.build, version.build) {
            (Some(a), Some(b)) => b.cmp(&a),
            (Some(_), None) => Ordering::Greater,
            _ => Ordering::Equal,
        }
    }
}

#[derive(Debug, PartialEq)]
enum Operator {
    Eq,
    Ne,
    Gt,
    Lt,
    Ge,
    Le,
}

impl Operator {
    /// Checks of the current operator matches its Ordering counterpart.
    fn matches_order(&self, ord: Ordering) -> bool {
        match self {
            Operator::Eq => ord == Ordering::Equal,
            Operator::Ne => ord != Ordering::Equal,
            Operator::Gt => ord == Ordering::Greater,
            Operator::Lt => ord == Ordering::Less,
            Operator::Ge => ord == Ordering::Greater || ord == Ordering::Equal,
            Operator::Le => ord == Ordering::Less || ord == Ordering::Equal,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn kernel_version() {
        let version = KernelVersion::new().unwrap();
        assert_eq!(version.major, 6);
        assert_eq!(version.minor, 2);
        assert_eq!(version.patch, 14);
        assert_eq!(version.build, Some(300));
        assert_eq!(version.full, "6.2.14-300.fc38.x86_64");

        let version = KernelVersion::parse("6.2.0-20-generic").unwrap();
        assert_eq!(version.major, 6);
        assert_eq!(version.minor, 2);
        assert_eq!(version.patch, 0);
        assert_eq!(version.build, Some(20));
        assert_eq!(version.full, "6.2.0-20-generic");

        let version = KernelVersion::parse("6.2.14.fc38.x86_64").unwrap();
        assert_eq!(version.major, 6);
        assert_eq!(version.minor, 2);
        assert_eq!(version.patch, 14);
        assert_eq!(version.build, None);
        assert_eq!(version.full, "6.2.14.fc38.x86_64");

        let version = KernelVersion::parse("6.4.12-arch1-1").unwrap();
        assert_eq!(version.major, 6);
        assert_eq!(version.minor, 4);
        assert_eq!(version.patch, 12);
        assert_eq!(version.build, Some(1));
        assert_eq!(version.full, "6.4.12-arch1-1");

        assert!(KernelVersion::parse("6.2").is_err());
    }

    #[test]
    fn kernel_version_match() {
        let version = KernelVersion::parse("6.2.14-300.fc38.x86_64").unwrap();

        let req = KernelVersionReq::parse("= 6.2.14-300").unwrap();
        assert_eq!(req.matches(&version), true);
        let req = KernelVersionReq::parse("= 6.2.14").unwrap();
        assert_eq!(req.matches(&version), true);
        let req = KernelVersionReq::parse("= 6.2.15").unwrap();
        assert_eq!(req.matches(&version), false);
        let req = KernelVersionReq::parse("= 6.2").unwrap();
        assert_eq!(req.matches(&version), true);
        let req = KernelVersionReq::parse("= 6").unwrap();
        assert_eq!(req.matches(&version), true);
        let req = KernelVersionReq::parse("= 7").unwrap();
        assert_eq!(req.matches(&version), false);

        let req = KernelVersionReq::parse("!= 6.2.14-301").unwrap();
        assert_eq!(req.matches(&version), true);
        let req = KernelVersionReq::parse("!= 6.3").unwrap();
        assert_eq!(req.matches(&version), true);
        let req = KernelVersionReq::parse("!= 5").unwrap();
        assert_eq!(req.matches(&version), true);
        let req = KernelVersionReq::parse("!= 6.2.14").unwrap();
        assert_eq!(req.matches(&version), false);

        let req = KernelVersionReq::parse("> 6.2.14-200").unwrap();
        assert_eq!(req.matches(&version), true);
        let req = KernelVersionReq::parse("> 6.1").unwrap();
        assert_eq!(req.matches(&version), true);
        let req = KernelVersionReq::parse("> 5").unwrap();
        assert_eq!(req.matches(&version), true);
        let req = KernelVersionReq::parse("> 6.2").unwrap();
        assert_eq!(req.matches(&version), false);

        let req = KernelVersionReq::parse(">= 6.2.14-200").unwrap();
        assert_eq!(req.matches(&version), true);
        let req = KernelVersionReq::parse(">= 6.2.14-300").unwrap();
        assert_eq!(req.matches(&version), true);
        let req = KernelVersionReq::parse(">= 6.2.14").unwrap();
        assert_eq!(req.matches(&version), true);
        let req = KernelVersionReq::parse(">= 6.2.10").unwrap();
        assert_eq!(req.matches(&version), true);
        let req = KernelVersionReq::parse(">= 6.2").unwrap();
        assert_eq!(req.matches(&version), true);
        let req = KernelVersionReq::parse(">= 5.14").unwrap();
        assert_eq!(req.matches(&version), true);
        let req = KernelVersionReq::parse(">= 6").unwrap();
        assert_eq!(req.matches(&version), true);
        let req = KernelVersionReq::parse(">= 5").unwrap();
        assert_eq!(req.matches(&version), true);
    }

    #[test]
    fn deserialize_version_req() {
        let req: KernelVersionReq = serde_json::from_str("\"= 6.2\"").unwrap();
        let cmp = req.0.get(0).unwrap();

        assert_eq!(cmp.op, Operator::Eq);
        assert_eq!(cmp.major, 6);
        assert_eq!(cmp.minor, Some(2));
        assert_eq!(cmp.patch, None);
        assert_eq!(cmp.build, None);
    }
}
