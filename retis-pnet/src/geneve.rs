use pnet_macros::packet;
use pnet_macros_support::types::*;

use crate::ethernet::EtherType;

/// Generic Network Virtualization Encapsulation
///
/// See [RFC 8926](https://datatracker.ietf.org/doc/html/rfc8926)
///
/// Geneve header:
///    0                   1                   2                   3
///    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
///   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
///   |Ver|  Opt Len  |O|C|    Rsvd.  |          Protocol Type        |
///   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
///   |        Virtual Network Identifier (VNI)       |    Reserved   |
///   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
///   |                                                               |
///   ~                    Variable-Length Options                    ~
///   |                                                               |
///   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
#[packet]
pub struct Geneve {
    pub version: u2,
    pub options_len: u6,
    pub control: u1,
    pub critical: u1,
    pub reserved0: u6,
    #[construct_with(u16)]
    pub protocol: EtherType,
    pub vni: u24be,
    pub reserved1: u8,
    #[length_fn = "geneve_option_length"]
    pub options: Vec<u8>,
    #[payload]
    pub payload: Vec<u8>,
}

fn geneve_option_length(geneve: &GenevePacket) -> usize {
    geneve.get_options_len() as usize * 4
}
