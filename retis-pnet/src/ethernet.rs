pub use pnet_packet::ethernet::*;

#[allow(non_snake_case, non_upper_case_globals)]
pub mod EtherTypes {
    use super::EtherType;
    pub use pnet_packet::ethernet::EtherTypes::*;

    /// Trans Ether Bridging.
    pub const Teb: EtherType = EtherType(0x6558);

    /// Point-to-Point Protocol.
    pub const Ppp: EtherType = EtherType(0x880b);

    /// EAPOL.
    pub const Eapol: EtherType = EtherType(0x888e);

    /// MACsec.
    pub const Macsec: EtherType = EtherType(0x88e5);
}
