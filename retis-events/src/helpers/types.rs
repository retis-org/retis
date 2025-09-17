//! # Types

use crate::event_type;

/// u128 representation in the events. We can't use the Rust primitive as serde
/// does not handle the type well.
#[event_type]
pub struct U128 {
    hi: u64,
    lo: u64,
}

impl U128 {
    pub fn from_u128(from: u128) -> Self {
        Self {
            hi: (from >> 64) as u64,
            lo: from as u64,
        }
    }

    pub fn bits(&self) -> u128 {
        ((self.hi as u128) << 64) | self.lo as u128
    }
}
