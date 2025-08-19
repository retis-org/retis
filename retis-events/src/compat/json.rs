//! Providing backward compatibility for events formatted in JSON.

use anyhow::{anyhow, bail, Result};

use super::*;

/// Equivalent of `serde_json::from_str` with an additional and optional
/// compatibility layer.
pub fn from_str<T>(input: &str, version: CompatVersion) -> Result<T>
where
    T: for<'de> serde::Deserialize<'de>,
{
    // In case the version is the latest one, take the fast path (single
    // deserialize).
    if version == CompatVersion::LATEST {
        return Ok(serde_json::from_str(input)?);
    }

    // Otherwise we do a two-step deserialization to allow fixing up fields in
    // between. The first round deserializes the event into a generic
    // serde_json::Value (which has the advantage of not enforcing any field
    // presence or type) and the second one generates our Event from the fixed
    // up serde_json::Value.

    let mut event: serde_json::Value = serde_json::from_str(input)?;
    match event {
        // Plain events.
        serde_json::Value::Object(_) => {
            super::compatibility_fixup(&mut event, CompatStrategy::Backward(version))?
        }
        // Sorted events.
        serde_json::Value::Array(ref mut vec) => vec.iter_mut().try_for_each(|event| {
            super::compatibility_fixup(event, CompatStrategy::Backward(version))
        })?,
        _ => bail!("Unknown event format (not a map nor an array)"),
    }

    serde_json::from_value(event)
        .map_err(|e| anyhow!(format!("Event was fixed up but parsing still failed: {e}")))
}

impl EventCompatibility for serde_json::Value {
    fn remove(&mut self, target: &str) -> Result<()> {
        if let Some(target) = get_mut_ref(self, target)? {
            *target = serde_json::Value::Null;
        }

        Ok(())
    }

    fn add(&mut self, target: &str, value: CompatValue) -> Result<()> {
        let (target, leaf) = match target.rsplit_once('/') {
            Some((target, leaf)) => match get_mut_ref(self, target)? {
                Some(target) => (target, leaf),
                None => return Ok(()),
            },
            None => (self, target),
        };

        let value = match value {
            CompatValue::Null => serde_json::Value::Null,
            CompatValue::Bool(val) => serde_json::Value::Bool(val),
            CompatValue::Int(val) => serde_json::Value::Number(
                serde_json::Number::from_i128(val.into())
                    .ok_or_else(|| anyhow!("Failed to convert {val} to a serde_json Number"))?,
            ),
            CompatValue::Uint(val) => serde_json::Value::Number(
                serde_json::Number::from_u128(val.into())
                    .ok_or_else(|| anyhow!("Failed to convert {val} to a serde_json Number"))?,
            ),
            CompatValue::String(val) => serde_json::Value::String(val),
        };

        match target {
            serde_json::Value::Object(map) => {
                if map.contains_key(leaf) {
                    bail!("Destination field ('{target}') already exists')");
                }
                let _ = map.insert(leaf.to_string(), value);
            }
            _ => bail!("Cannot add field: '{target}' is not a map"),
        }

        Ok(())
    }

    fn r#move(&mut self, from: &str, to: &str) -> Result<()> {
        // Retrieve the old field/section value.
        let val = match get_mut_ref(self, from)? {
            Some(val) => val.clone(),
            None => return Ok(()),
        };

        // Add the new field/section and initialize it to Null.
        self.add(to, CompatValue::Null)?;
        // Set the new field value. Unwrap as we just added the field/section.
        *get_mut_ref(self, to)?.unwrap() = val;
        // Remove the old field/section.
        self.remove(from)
    }
}

/// Get a mutable reference to a `serde_json::Value` which lies in `val` and is
/// pointed by `target`.
///
/// Not finding a field/section is not an error as all fields/sections are
/// optional in an event.
fn get_mut_ref<'a>(
    mut val: &'a mut serde_json::Value,
    target: &str,
) -> Result<Option<&'a mut serde_json::Value>> {
    let mut fields = parse_target(target)?;
    let leaf = fields.len() - 1;

    for (i, field) in fields.drain(..).enumerate() {
        match val {
            serde_json::Value::Object(map) => {
                val = match map.get_mut(field) {
                    Some(val) => val,
                    None => return Ok(None),
                }
            }
            _ => {
                if i != leaf {
                    bail!("Could not reach target ({field})");
                }
                break;
            }
        }
    }

    Ok(Some(val))
}
