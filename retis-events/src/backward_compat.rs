#![allow(dead_code)] // FIXME

use anyhow::{anyhow, bail, Result};
use serde_json::*;

use crate::Event;

pub fn event_from_str(input: &str, latest: bool) -> Result<Event> {
    // In case the version is the latest one, take the fast path (single
    // deserialize).
    if latest {
        return Ok(serde_json::from_str(input)?);
    }

    // Otherwise we do a two-step deserialization to allow fixing up fields in
    // between. The first round deserializes the event into a generic
    // serde_json::Value (which has the advantage of not enforcing any field
    // presence or type) and the second one generates our Event from the fixed
    // up serde_json::Value.

    let mut event: serde_json::Value = serde_json::from_str(input)?;
    fixup(&mut event)?;

    // TODO: map_err to for better UX (mentioning we tried to fixup the event).
    Ok(serde_json::from_value(event)?)
}

// We allow results not to be checked in the fixup function as fields might not
// be found.
#[allow(unused_must_use)]
fn fixup(event: &mut Value) -> Result<()> {
    Ok(())
}

trait ValueFixup {
    /// Get a mutable reference to a field Value using its path, e.g.
    /// 'path/to/leaf'.
    fn get_mut_ref(&mut self, target: &str) -> Result<&mut Value>;
    /// Delete a field (sets to Value::Null).
    fn delete(&mut self, target: &str) -> Result<()>;
    /// Add a field and sets its (default) value.
    fn add(&mut self, target: &str, value: Value) -> Result<()>;
    /// Move (or rename) a field.
    fn r#move(&mut self, from: &str, to: &str) -> Result<()>;
}

impl ValueFixup for Value {
    fn delete(&mut self, target: &str) -> Result<()> {
        *self.get_mut_ref(target)? = Value::Null;
        Ok(())
    }

    fn add(&mut self, target: &str, value: Value) -> Result<()> {
        if self.get_mut_ref(target).is_ok() {
            bail!("Destination field already exists ('{target}')");
        }

        let (target, leaf) = match target.rsplit_once('/') {
            Some((target, leaf)) => (self.get_mut_ref(target)?, leaf),
            None => (self, target),
        };

        match target {
            Value::Object(map) => {
                let _ = map.insert(leaf.to_string(), value);
            }
            _ => bail!("Cannot add field: '{target}' is not a map"),
        }
        Ok(())
    }

    fn r#move(&mut self, from: &str, to: &str) -> Result<()> {
        self.add(to, Value::Null)?;
        *self.get_mut_ref(to)? = self.get_mut_ref(from)?.clone();
        *self.get_mut_ref(from)? = Value::Null;
        Ok(())
    }

    fn get_mut_ref(&mut self, target: &str) -> Result<&mut Value> {
        let leaf = target.chars().filter(|c| *c == '/').count();
        let mut val = self;

        for (n, field) in target.split('/').enumerate() {
            match val {
                Value::Object(map) => {
                    val = map
                        .get_mut(field)
                        .ok_or_else(|| anyhow!("Could not find field '{field}'"))?;
                }
                _ => {
                    if n != leaf {
                        bail!("Field '{field}' is not a leaf");
                    }
                    break;
                }
            }
        }

        Ok(val)
    }
}
