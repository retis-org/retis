use std::{collections::HashMap, path::PathBuf};

use anyhow::{bail, Result};
use btf_rs::{self, Btf, Enum, Type};
use once_cell::sync::OnceCell;

use super::kernel::KernelInspector;

static INSPECTOR: OnceCell<Inspector> = OnceCell::new();

/// Gets a reference on the inspector.
pub(crate) fn inspector() -> Result<&'static Inspector> {
    INSPECTOR.get_or_try_init(|| Inspector::from(None))
}

/// Initialize the inspector with custom parameters, fail is already
/// initialized.
pub(crate) fn init_inspector(kconf: &PathBuf) -> Result<()> {
    let inspector = Inspector::from(Some(kconf))?;
    if INSPECTOR.set(inspector).is_err() {
        bail!("Could not init inspector: was already initialized.");
    }
    Ok(())
}

/// Provides helpers to inspect various information about the system and the
/// kernel. Used as a singleton.
pub(crate) struct Inspector {
    /// Kernel part of the inspector.
    pub(crate) kernel: KernelInspector,
}

impl Inspector {
    fn from(kconf: Option<&PathBuf>) -> Result<Inspector> {
        Ok(Inspector {
            kernel: KernelInspector::from(kconf)?,
        })
    }
}

/// Same as parse_enum but first find the anonymous enum that contains the
/// provided member.
pub(crate) fn parse_anon_enum(variant: &str, trim_start: &[&str]) -> Result<HashMap<u32, String>> {
    if let Some((btf, anon_enum)) = inspector()?
        .kernel
        .btf
        .resolve_types_by_name("")?
        .iter()
        .find_map(|(btf, t)| match t {
            Type::Enum(e) => {
                if e.members
                    .iter()
                    .any(|m| btf.resolve_name(m).is_ok_and(|v| v == variant))
                {
                    Some((btf, e))
                } else {
                    None
                }
            }
            _ => None,
        })
    {
        parse_enum_type(btf, anon_enum, trim_start)
    } else {
        bail!("Failed to find an anonymous enum with variant {}", variant)
    }
}

/// Parses an enum and returns its variant names, trimed if asked to.
pub(crate) fn parse_enum(r#enum: &str, trim_start: &[&str]) -> Result<HashMap<u32, String>> {
    if let Ok(types) = inspector()?.kernel.btf.resolve_types_by_name(r#enum) {
        if let Some((btf, Type::Enum(r#enum))) =
            types.iter().find(|(_, t)| matches!(t, Type::Enum(_)))
        {
            return parse_enum_type(btf, r#enum, trim_start);
        }
    }
    Ok(HashMap::new())
}

fn parse_enum_type(btf: &Btf, r#enum: &Enum, trim_start: &[&str]) -> Result<HashMap<u32, String>> {
    let mut values = HashMap::new();
    for member in r#enum.members.iter() {
        let mut val = btf.resolve_name(member)?;
        trim_start
            .iter()
            .for_each(|p| val = val.trim_start_matches(p).to_string());
        values.insert(member.val(), val.to_string());
    }
    Ok(values)
}

/// Parses a struct and returns its field names.
pub(crate) fn parse_struct(r#struct: &str) -> Result<Vec<String>> {
    let mut fields = Vec::new();

    if let Ok(types) = inspector()?.kernel.btf.resolve_types_by_name(r#struct) {
        if let Some((btf, Type::Struct(r#enum))) =
            types.iter().find(|(_, t)| matches!(t, Type::Struct(_)))
        {
            for member in r#enum.members.iter() {
                fields.push(btf.resolve_name(member)?);
            }
        }
    }

    Ok(fields)
}

#[cfg(test)]
mod tests {
    #[test]
    fn inspector_init() {
        assert!(super::inspector().is_ok());
    }
}
