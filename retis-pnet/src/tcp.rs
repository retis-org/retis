pub use pnet_packet::tcp::*;

#[allow(non_snake_case, non_upper_case_globals)]
pub mod TcpOptionNumbers {
    use super::TcpOptionNumber;
    pub use pnet_packet::tcp::TcpOptionNumbers::*;

    /// Echo.
    pub const ECHO: TcpOptionNumber = TcpOptionNumber(6);

    /// Echo Reply.
    pub const ECHO_REPLY: TcpOptionNumber = TcpOptionNumber(7);

    /// Connexion Count.
    pub const CC: TcpOptionNumber = TcpOptionNumber(11);

    /// Connection Count New.
    pub const CC_NEW: TcpOptionNumber = TcpOptionNumber(12);

    /// Connection Count Echo.
    pub const CC_ECHO: TcpOptionNumber = TcpOptionNumber(13);

    /// Keyed MD5.
    pub const MD5: TcpOptionNumber = TcpOptionNumber(19);

    /// SCPS.
    pub const SCPS: TcpOptionNumber = TcpOptionNumber(20);

    /// User Timeout.
    pub const UTO: TcpOptionNumber = TcpOptionNumber(28);

    /// TCP Authentication Option.
    pub const TCP_AO: TcpOptionNumber = TcpOptionNumber(29);

    /// MPTCP.
    pub const MPTCP: TcpOptionNumber = TcpOptionNumber(30);

    /// TCP Fast Open.
    pub const TFO: TcpOptionNumber = TcpOptionNumber(34);

    /// Experiment 2.
    pub const EXP_2: TcpOptionNumber = TcpOptionNumber(254);
}
