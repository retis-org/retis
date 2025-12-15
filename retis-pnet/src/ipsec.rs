use pnet_macros::packet;
use pnet_macros_support::types::*;

use crate::ip::IpNextHeaderProtocol;

/// IP Authentication Header
///
/// See [RFC 4302](https://datatracker.ietf.org/doc/html/rfc4302)
///
/// AH header:
///
///    0                   1                   2                   3
///    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
///   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
///   | Next Header   |  Payload Len  |          RESERVED             |
///   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
///   |                 Security Parameters Index (SPI)               |
///   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
///   |                    Sequence Number Field                      |
///   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
///   |                                                               |
///   +                Integrity Check Value-ICV (variable)           |
///   |                                                               |
///   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
#[packet]
pub struct Ah {
    #[construct_with(u8)]
    pub next_header: IpNextHeaderProtocol,
    pub payload_len: u8,
    pub reserved0: u16be,
    pub spi: u32be,
    pub sequence_number: u32be,
    #[length_fn = "ah_icv_len"]
    pub icv: Vec<u8>,
    #[payload]
    pub payload: Vec<u8>,
}

fn ah_icv_len(ah: &AhPacket) -> usize {
    ah.get_payload_len().saturating_sub(1) as usize * 4
}

/// IP Encapsulating Security Payload
///
/// See [RFC 4303](https://datatracker.ietf.org/doc/html/rfc4303)
///
/// ESP header:
///    0                   1                   2                   3
///    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
///   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+ ----
///   |               Security Parameters Index (SPI)                 | ^Int.
///   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+ |Cov-
///   |                      Sequence Number                          | |ered
///   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+ | ----
///   |                    Payload Data* (variable)                   | |   ^
///   ~                                                               ~ |   |
///   |                                                               | |Conf.
///   +               +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+ |Cov-
///   |               |     Padding (0-255 bytes)                     | |ered*
///   +-+-+-+-+-+-+-+-+               +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+ |   |
///   |                               |  Pad Length   | Next Header   | v   v
///   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+ ------
///   |         Integrity Check Value-ICV   (variable)                |
///   ~                                                               ~
///   |                                                               |
///   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
#[packet]
pub struct Esp {
    pub spi: u32be,
    pub sequence_number: u32be,
    #[payload]
    pub payload: Vec<u8>,
}
