use pnet_macros::packet;
use pnet_macros_support::types::*;

use crate::PrimitiveValues;

/// SCTP header
///
/// See [RFC 2960] (<https://datatracker.ietf.org/doc/html/rfc2960>)
///
/// Packet format:
///
///    0                   1                   2                   3
///    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
///   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
///   |                        Common Header                          |
///   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
///   |                          Chunk #1                             |
///   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
///   |                           ...                                 |
///   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
///   |                          Chunk #n                             |
///   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
///
///
/// Common header:
///
///    0                   1                   2                   3
///    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
///   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
///   |     Source Port Number        |     Destination Port Number   |
///   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
///   |                      Verification Tag                         |
///   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
///   |                           Checksum                            |
///   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
#[packet]
pub struct Sctp {
    pub source: u16be,
    pub destination: u16be,
    pub verification_tag: u32be,
    pub checksum: u32be,
    #[payload]
    pub payload: Vec<u8>,
}

/// SCTP chunk types.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct SctpChunkType(pub u8);

impl PrimitiveValues for SctpChunkType {
    type T = (u8,);
    fn to_primitive_values(&self) -> (u8,) {
        (self.0,)
    }
}

#[allow(non_snake_case, non_upper_case_globals)]
pub mod SctpChunkTypes {
    use super::SctpChunkType;

    /// DATA.
    pub const DATA: SctpChunkType = SctpChunkType(0);

    /// INIT.
    pub const INIT: SctpChunkType = SctpChunkType(1);

    /// INIT ACK.
    pub const INIT_ACK: SctpChunkType = SctpChunkType(2);

    /// SACK.
    pub const SACK: SctpChunkType = SctpChunkType(3);

    /// HEARTBEAT.
    pub const HEARTBEAT: SctpChunkType = SctpChunkType(4);

    /// HEARTBEAT ACK.
    pub const HEARTBEAT_ACK: SctpChunkType = SctpChunkType(5);

    /// ABORT.
    pub const ABORT: SctpChunkType = SctpChunkType(6);

    /// SHUTDOWN.
    pub const SHUTDOWN: SctpChunkType = SctpChunkType(7);

    /// SHUTDOWN ACK.
    pub const SHUTDOWN_ACK: SctpChunkType = SctpChunkType(8);

    /// ERROR.
    pub const ERROR: SctpChunkType = SctpChunkType(9);

    /// COOKIE ECHO.
    pub const COOKIE_ECHO: SctpChunkType = SctpChunkType(10);

    /// COOKIE ACK.
    pub const COOKIE_ACK: SctpChunkType = SctpChunkType(11);

    /// ECNE.
    pub const ECNE: SctpChunkType = SctpChunkType(12);

    /// CWR.
    pub const CWR: SctpChunkType = SctpChunkType(13);

    /// SHUTDOWN COMPLETE.
    pub const SHUTDOWN_COMPLETE: SctpChunkType = SctpChunkType(14);
}

/// SCTP chunk header
///
/// See [RFC 2960] (<https://datatracker.ietf.org/doc/html/rfc2960>)
///
///    0                   1                   2                   3
///    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
///   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
///   |   Chunk Type  | Chunk  Flags  |        Chunk Length           |
///   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
///   \                                                               \
///   /                          Chunk Value                          /
///   \                                                               \
///   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
#[packet]
pub struct SctpChunk {
    #[construct_with(u8)]
    pub chunk_type: SctpChunkType,
    pub flags: u8,
    pub length: u16be,
    #[payload]
    #[length_fn = "sctp_chunk_payload_length"]
    pub payload: Vec<u8>,
}

fn sctp_chunk_payload_length(pkt: &SctpChunkPacket) -> usize {
    let len = pkt.get_length() as usize;
    ((len + 3) & !3).saturating_sub(4)
}

impl SctpChunkType {
    pub fn new(val: u8) -> SctpChunkType {
        SctpChunkType(val)
    }
}

impl<'a> SctpChunkIterable<'a> {
    pub fn new(buf: &'a [u8]) -> SctpChunkIterable<'a> {
        SctpChunkIterable { buf }
    }
}
