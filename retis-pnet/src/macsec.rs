use pnet_macros::packet;
use pnet_macros_support::types::*;

/// MACsec header.
#[packet]
pub struct Macsec {
    pub tci: u6,
    pub association_number: u2,
    pub reserved0: u2,
    pub short_length: u6,
    pub packet_number: u32be,
    #[length_fn = "sci_len"]
    pub sci: Vec<u8>,
    #[payload]
    pub payload: Vec<u8>,
}

fn sci_len(macsec: &MacsecPacket) -> usize {
    if macsec.get_tci() & MACSEC_TCI_SC != 0 {
        return 8;
    }
    0
}

pub const MACSEC_TCI_V: u6 = 1 << 5;
pub const MACSEC_TCI_ES: u6 = 1 << 4;
pub const MACSEC_TCI_SC: u6 = 1 << 3;
pub const MACSEC_TCI_SCB: u6 = 1 << 2;
pub const MACSEC_TCI_E: u6 = 1 << 1;
pub const MACSEC_TCI_C: u6 = 1 << 0;
