use pnet_macros::packet;
use pnet_macros_support::types::*;

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
