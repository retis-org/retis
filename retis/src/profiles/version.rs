//! # Profile API Versioning.
//!
//! Profile API versioning is identified using X.Y format (e.g: 3.4).
//!
//! ## Version semantics
//! A change in the minor (Y) digit of the version indicates that the new Profile API:
//! 1) Adds some functionality that is nice to have but not absolutely mandatory for the profile to
//!    yield a consistent and working configuration. A retis version that supports version X.Y will
//!    try to load and execute any profile with version X.Y' and a reasonably good result is expected
//!    (i.e: the tool must not fail and events should be captured).
//! 2) Does not break yaml parsing, i.e: a retis version that is able to parse a profile version
//!    X.Y should also be able to parse X.(Y+1)
//!
//! On the other hand, a change in the mayor (X) digit of the version indicates that the change can
//! break parsing or, even if it doesn't, the change in behavior can make the tool fail if not
//! applied by a retis version that supports the new functionality.
//!
//! ## Backwards compatibility
//! Retis only guarantees backwards compatibility within the same major version.

use core::{fmt, str::FromStr};
use std::cmp::Ordering;

use anyhow::{anyhow, bail, Error, Result};
use serde::{de::Error as Derror, Deserialize, Deserializer};

/// A simple two-digit version struct implementing Profile API Version schema and support logic.
/// No VersionReq is implemented. Instead, requirement satisfaction is implemented manually.
#[derive(Debug, PartialEq)]
pub(crate) struct ApiVersion {
    pub(super) major: u32,
    pub(super) minor: u32,
}

/// Possible Version compatibility results.
#[derive(Debug, PartialEq)]
pub(super) enum ApiVersionSupport {
    Full,
    Partial,
    NotSupported,
}

impl ApiVersion {
    /// Create `ApiVersion` by parsing from string representation.
    pub(crate) fn parse(text: &str) -> Result<Self> {
        ApiVersion::from_str(text)
    }

    /// Assuming `self` is retis' supported API version, return whether parsing the ApiVersion
    /// referenced by `profile` is supported.
    pub(super) fn supports(&self, profile: &ApiVersion) -> Result<ApiVersionSupport> {
        if self.major == profile.major {
            if self.minor >= profile.minor {
                Ok(ApiVersionSupport::Full)
            } else {
                Ok(ApiVersionSupport::Partial)
            }
        } else {
            Ok(ApiVersionSupport::NotSupported)
        }
    }
}
impl fmt::Display for ApiVersion {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}.{}", self.major, self.minor)
    }
}

impl FromStr for ApiVersion {
    type Err = Error;

    fn from_str(text: &str) -> Result<Self, Self::Err> {
        if text.is_empty() {
            bail!("Text is empty");
        }

        let parts: Vec<&str> = text.split('.').collect();
        match parts.len().cmp(&2) {
            Ordering::Greater => bail!("Too many numeric values. Only two (X.Y) are supported"),
            Ordering::Less => bail!("Too few numeric values. Two values (X.Y) must be provided"),
            Ordering::Equal => Ok(ApiVersion {
                major: parts
                    .first()
                    .unwrap()
                    .parse::<u32>()
                    .map_err(|e| anyhow!("Failed to parse major version number: {e}"))?,
                minor: parts
                    .get(1)
                    .unwrap()
                    .parse::<u32>()
                    .map_err(|e| anyhow!("Failed to parse minor version number: {e}"))?,
            }),
        }
    }
}

impl<'de> Deserialize<'de> for ApiVersion {
    fn deserialize<D>(deserializer: D) -> Result<ApiVersion, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct VerVisitor;

        impl<'de> serde::de::Visitor<'de> for VerVisitor {
            type Value = ApiVersion;

            fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
                formatter.write_str("api version")
            }

            fn visit_str<E>(self, value: &str) -> Result<Self::Value, E>
            where
                E: Derror,
            {
                match ApiVersion::parse(value) {
                    Ok(v) => Ok(v),
                    Err(_) => Err(Derror::invalid_value(
                        serde::de::Unexpected::Str(value),
                        &self,
                    )),
                }
            }
        }

        deserializer.deserialize_str(VerVisitor)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parsing() {
        assert!(ApiVersion::parse("0.1").is_ok());
        assert!(ApiVersion::parse("999.123123").is_ok());
        assert!(ApiVersion::parse("1.2.3").is_err());
        assert!(ApiVersion::parse("1").is_err());
    }

    #[test]
    fn support() {
        use ApiVersionSupport::*;
        assert_eq!(
            ApiVersion::parse("1.2")
                .expect("retis version")
                .supports(&ApiVersion::parse("1.2").expect("profile version"))
                .expect("supports"),
            Full
        );
        assert_eq!(
            ApiVersion::parse("1.2")
                .expect("retis version")
                .supports(&ApiVersion::parse("1.1").expect("profile version"))
                .expect("supports"),
            Full
        );
        assert_eq!(
            ApiVersion::parse("1.2")
                .expect("retis version")
                .supports(&ApiVersion::parse("1.4").expect("profile version"))
                .expect("supports"),
            Partial
        );
        assert_eq!(
            ApiVersion::parse("1.2")
                .expect("retis version")
                .supports(&ApiVersion::parse("2.1").expect("profile version"))
                .expect("supports"),
            NotSupported
        );
        assert_eq!(
            ApiVersion::parse("1.2")
                .expect("retis version")
                .supports(&ApiVersion::parse("0.9").expect("profile version"))
                .expect("supports"),
            NotSupported
        );
    }
}
