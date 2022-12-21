//! Internal representation of events. Those events can be marshaled/unmarshaled
//! to other formats to be stored or displayed. We currently support: JSON.
//!
//! As an example, a full JSON output should look like:
//!
//! {
//!     "version": "0.1.0",
//!     "hostname": "mymachine",
//!     "kernel": "6.0.8-300.fc37.x86_64",
//!     "events": [
//!         {
//!              "common": {
//!                  "symbol": "kfree_skb_reason",
//!                  "timestamp": "7322460997041"
//!              },
//!              "skb_tracking": {
//!                  "timestamp": "7322460997041",
//!                  "orig_head": "18446623346735780864",
//!                  "skb": "18446623349161350912",
//!                  "drop_reason": "0",
//!              },
//!              "skb": {
//!                  "etype": "34525"
//!              },
//!              "ovs": {
//!                  "ovs": "2.5.90",
//!                  "foo": "bar"
//!              }
//!         },
//!         ...
//!     ]
//! }

#![allow(dead_code)] // FIXME

use std::{any::Any, collections::HashMap};

use anyhow::{bail, Result};
use serde_json::json;

/// Full event. Internal representation. The first key is the collector from
/// which the event sections originate. The second one is the field name of a
/// given (collector) event field.
pub(crate) struct Event(HashMap<String, HashMap<String, EventField>>);

impl Event {
    pub(crate) fn new() -> Event {
        Event(HashMap::new())
    }

    /// Get the event len, aka. its # of fields.
    pub(crate) fn len(&self) -> usize {
        let mut len = 0;
        for fields in self.0.values() {
            len += fields.len();
        }
        len
    }

    /// Get a reference to an event field by its owner and key.
    pub(crate) fn get<T: 'static>(&self, owner: &str, key: &str) -> Result<Option<&T>> {
        if let Some(section) = self.0.get(&owner.to_string()) {
            if let Some(field) = section.get(&key.to_string()) {
                return match field.val.as_any().downcast_ref::<T>() {
                    Some(val) => Ok(Some(val)),
                    None => bail!(
                        "Can't get {}:{}, invalid type {}",
                        owner,
                        key,
                        stringify!(T)
                    ),
                };
            }
        }
        Ok(None)
    }

    /// Insert a new event field into an event.
    pub(crate) fn insert(&mut self, key: &str, val: EventField) {
        let key = key.to_string();

        if !self.0.contains_key(&key) {
            self.0.insert(key.clone(), HashMap::new());
        }

        // Unwrap can't fail as we checked the key exists in the above block.
        let map = self.0.get_mut(&key).unwrap();
        map.insert(val.key.clone(), val);
    }

    pub(crate) fn to_json(&self) -> serde_json::Value {
        self.into()
    }
}

// This allows converting an Event to a serde_json::Value in the
// Event::to_json() helper.
impl From<&Event> for serde_json::Value {
    fn from(f: &Event) -> Self {
        let mut event = serde_json::Map::new();

        for (key, owner) in f.0.iter() {
            let mut section = serde_json::Map::new();

            for (key, field) in owner.iter() {
                section.insert(key.clone(), field.val.to_json());
            }

            event.insert(key.clone(), serde_json::Value::Object(section));
        }

        serde_json::Value::Object(event)
    }
}

/// Event fields are the events building blocks. They hold per-type data.
pub(crate) struct EventField {
    key: String,
    val: Box<dyn EventFieldType>,
}

impl EventField {
    pub(crate) fn new(key: &str, val: Box<dyn EventFieldType>) -> EventField {
        EventField {
            key: key.to_string(),
            val,
        }
    }
}

/// Wrapper to easily create a new event field to insert into an event.
///
/// `event_field!("key", 42);`
#[macro_export]
macro_rules! event_field {
    ($key:expr, $val:expr) => {
        EventField::new($key, Box::new($val))
    };
}

/// Implementation of an event field type, used to hold the actual data and
/// provide helpers to serialize/deserialize it.
pub(crate) trait EventFieldType {
    fn name(&self) -> &'static str;
    fn as_any(&self) -> &dyn Any;
    fn to_json(&self) -> serde_json::Value;
    fn from_json(from: serde_json::Value) -> Result<Self>
    where
        Self: Sized;
}

/// Macro helping to define common event field types not requiring special
/// handling.
macro_rules! event_field_type {
    ($type:ty) => {
        impl EventFieldType for $type {
            fn name(&self) -> &'static str {
                stringify!($type)
            }

            fn as_any(&self) -> &dyn Any {
                self
            }

            fn to_json(&self) -> serde_json::Value {
                json!(*self)
            }

            fn from_json(from: serde_json::Value) -> Result<Self> {
                Ok(serde_json::from_value(from)?)
            }
        }
    };
}

// Common types definition.
event_field_type!(u32);
event_field_type!(u64);
event_field_type!(i32);
event_field_type!(i64);
event_field_type!(String);
