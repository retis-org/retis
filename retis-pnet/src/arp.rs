pub use pnet_packet::arp::*;

#[allow(non_snake_case, non_upper_case_globals)]
pub mod ArpOperations {
    use super::ArpOperation;
    pub use pnet_packet::arp::ArpOperations::*;

    /// Reverse ARP request.
    pub const ReverseRequest: ArpOperation = ArpOperation(3);

    /// Reverse ARP reply.
    pub const ReverseReply: ArpOperation = ArpOperation(4);
}
