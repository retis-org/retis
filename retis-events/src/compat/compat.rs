#![allow(dead_code)] // Not everything is used in all versions.

use anyhow::{anyhow, bail, Result};
use semver::{Version, VersionReq};

/// When making breaking changes in the event, fixups should be added.
use CompatFixup::*;
const FIXUPS: &[&[CompatFixup]] = &[
    /* CompatVersion::V0 */
    &[],
    /* CompatVersion::V1 */
    &[
        Add("ct/ct_status", CompatValue::Uint(0)),
        Move("skb/packet/packet", "skb/packet/raw"),
        Move("skb/ns/netns", "skb/ns/inum"),
        Move("skb/packet", "packet"),
        Move("skb/dev", "dev"),
        Move("skb/ns", "netns"),
        Move("packet/raw", "packet/data"),
    ],
];

enum CompatFixup<'a> {
    Remove(&'a str),
    Add(&'a str, CompatValue),
    Move(&'a str, &'a str),
}

pub(crate) enum CompatStrategy {
    Backward(CompatVersion /* from */),
    Forward(CompatVersion /* to */),
}

/// Representation of the event version we should be compatible with. This is an
/// internal only representation and is usually derived from the Retis version
/// itself. Multiple Retis versions can be translated to the same internal
/// compatibility version, if no breaking change was made.
///
/// When breaking changes are made to the event in a given y-stream version,
/// this should be reflected here.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub(crate) enum CompatVersion {
    /* v1.5.x; we start the backward compatibility effort with v1.5.0 */
    V0 = 0,
    /* v1.6.x.. */
    V1,
}

// Retis versions to internal compat version table.
const VERSION_MATCHES: &[(&str, CompatVersion)] = &[
    (">= 1.5.0, < 1.6.0", CompatVersion::V0),
    (">= 1.6.0", CompatVersion::V1),
];

impl CompatVersion {
    pub const LATEST: Self = Self::V1;

    /// Create a compatibility version representation given a Retis version.
    pub(crate) fn from_retis_version(retis_version: &str) -> Result<Self> {
        let retis_version = parse_version(retis_version)?;

        for (req, version) in VERSION_MATCHES {
            let req = VersionReq::parse(req)?;
            if req.matches(&retis_version) {
                log::debug!("Detected compatibility version {version:?}");
                return Ok(*version);
            }
        }

        Err(anyhow!("Unsupported Retis version ({retis_version})"))
    }
}

// Parse a Retis version str into a semver::Version.
fn parse_version(retis_version: &str) -> Result<Version> {
    // Version should start with 'v'. Let's be flexible.
    let mut from = 0;
    if retis_version.starts_with("v") {
        from = 1;
    }

    // During development versions can include '-' and '+' with extra
    // trailing chars; remove them.
    let mut to = retis_version.len();
    if let Some(offset) = retis_version.find('-') {
        to = offset;
    }
    if let Some(offset) = retis_version.find('+') {
        if offset < to {
            to = offset;
        }
    }
    if from >= to {
        bail!("Invalid Retis version string ({retis_version})");
    }

    Ok(Version::parse(&retis_version[from..to])?)
}

/// Main entry point for applying compatibility fixups to event representations
/// implementing the `EventCompatibility` trait. The fixups are will be applied
/// given a specific `version` target using a specific `strategy`.
pub(crate) fn compatibility_fixup(
    event: &mut dyn EventCompatibility,
    strategy: CompatStrategy,
) -> Result<()> {
    // Which fixups to keep?
    let boundary = match &strategy {
        CompatStrategy::Backward(from) => *from as usize,
        CompatStrategy::Forward(to) => *to as usize,
    };

    // Gather the list of fixups to apply.
    let fixups = FIXUPS
        .iter()
        .enumerate()
        .filter_map(|(i, fixup)| match i {
            x if x >= boundary => Some(fixup),
            _ => None,
        })
        .flat_map(|fixup| fixup.iter())
        .collect::<Vec<&CompatFixup>>();

    // Apply fixups, following the current strategy.
    match strategy {
        CompatStrategy::Backward(_) => fixups.iter().try_for_each(|fix| match fix {
            CompatFixup::Remove(target) => event.remove(target),
            CompatFixup::Add(target, value) => event.add(target, value.clone()),
            CompatFixup::Move(from, to) => event.r#move(from, to),
        }),
        CompatStrategy::Forward(_) => fixups.iter().rev().try_for_each(|fix| match fix {
            CompatFixup::Remove(target) => event.add(target, CompatValue::Null),
            CompatFixup::Add(target, _) => event.remove(target),
            CompatFixup::Move(from, to) => event.r#move(to, from),
        }),
    }
}

/// Trait providing common helpers to fixup events for compatibility reasons.
pub(crate) trait EventCompatibility {
    /// Removes the field/section pointed by `target`.
    fn remove(&mut self, target: &str) -> Result<()>;
    /// Adds a new field/section pointed by `target` with a provided value.
    fn add(&mut self, target: &str, value: CompatValue) -> Result<()>;
    /// Moves a field/section to a new location.
    fn r#move(&mut self, from: &str, to: &str) -> Result<()>;
}

/// Values fields being added as part of the compatibility logic.
#[derive(Clone)]
pub(crate) enum CompatValue {
    Null,
    Bool(bool),
    Int(i64),
    Uint(u64),
    String(String),
    // TODO: event sections?
}

/// Fields to remove/add/move are pointed by `target`s. They are expressed as a
/// path to the field/section, separated by '/'. This returns a Vec containing
/// each part of the `target` path.
///
/// e.g. "common/task/pid", "skb/meta" and "packet".
pub(super) fn parse_target(target: &str) -> Result<Vec<&str>> {
    Ok(target.split('/').collect::<Vec<&str>>())
}

#[cfg(test)]
mod tests {
    use anyhow::Result;

    fn check_version(version: &str, req: &str) -> Result<bool> {
        let version = super::parse_version(version)?;
        let req = semver::VersionReq::parse(req)?;

        Ok(req.matches(&version))
    }

    #[test]
    fn version() {
        assert_eq!(check_version("1.5.0", "= 1.5.0").unwrap(), true);
        assert_eq!(check_version("1.5.0", "= 1.5.0").unwrap(), true);
        assert_eq!(check_version("1.5.0+1.4.0", "= 1.5.0").unwrap(), true);
        assert_eq!(check_version("1.5.0-", "= 1.5.0").unwrap(), true);
        assert_eq!(
            check_version("1.5.0-31584d349ace", "= 1.5.0").unwrap(),
            true
        );
        assert_eq!(
            check_version("1.5.0-31584d349ace-dirty", "= 1.5.0").unwrap(),
            true
        );
        assert_eq!(
            check_version("1.5.0+1.4.0-31584d349ace-dirty", "= 1.5.0").unwrap(),
            true
        );

        assert_eq!(check_version("v1.5.0", "= 1.5.0").unwrap(), true);
        assert_eq!(check_version("v1.5.0", "= 1.5.0").unwrap(), true);
        assert_eq!(check_version("v1.5.0+1.4.0", "= 1.5.0").unwrap(), true);
        assert_eq!(check_version("v1.5.0-", "= 1.5.0").unwrap(), true);
        assert_eq!(
            check_version("v1.5.0-31584d349ace", "= 1.5.0").unwrap(),
            true
        );
        assert_eq!(
            check_version("v1.5.0-31584d349ace-dirty", "= 1.5.0").unwrap(),
            true
        );
        assert_eq!(
            check_version("v1.5.0+1.4.0-31584d349ace-dirty", "= 1.5.0").unwrap(),
            true
        );

        assert!(check_version("", "= 1.5.0").is_err());
        assert!(check_version("1.5.", "= 1.5.0").is_err());
        assert!(check_version("1.5.", "= 1.5.0").is_err());
        assert!(check_version("1.5.x", "= 1.5.0").is_err());
        assert!(check_version("1.5.0?foo", "= 1.5.0").is_err());
    }
}
