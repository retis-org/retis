pub use pnet_packet::ip::*;

#[allow(non_snake_case, non_upper_case_globals)]
pub mod IpNextHeaderProtocols {
    use super::IpNextHeaderProtocol;
    pub use pnet_packet::ip::IpNextHeaderProtocols::*;

    /// Ethernet.
    pub const Ethernet: IpNextHeaderProtocol = IpNextHeaderProtocol(143);
}
