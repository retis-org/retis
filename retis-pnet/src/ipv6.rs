#![allow(non_upper_case_globals)]

pub use pnet_packet::ipv6::*;

use pnet_packet::{ip::*, Packet, PacketSize};
use std::cmp::min;

pub struct ExtensionIterable<'a> {
    buf: &'a [u8],
    protocol: IpNextHeaderProtocol,
}

impl<'a> ExtensionIterable<'a> {
    pub fn from(ipv6: &'a Ipv6Packet) -> ExtensionIterable<'a> {
        Self {
            buf: ipv6.payload(),
            protocol: ipv6.get_next_header(),
        }
    }

    fn is_extension(protocol: IpNextHeaderProtocol) -> bool {
        use IpNextHeaderProtocols::*;
        matches!(
            protocol,
            Hopopt
                | Ipv6Route
                | Ipv6Frag
                | Ah
                | Esp
                | Ipv6Opts
                | MobilityHeader
                | Hip
                | Shim6
                | Test1
                | Test2
        )
    }
}

impl<'a> Iterator for ExtensionIterable<'a> {
    type Item = ExtensionPacket<'a>;

    fn next(&mut self) -> Option<ExtensionPacket<'a>> {
        if !Self::is_extension(self.protocol) {
            return None;
        }

        match ExtensionPacket::new(self.buf) {
            Some(ext) => {
                let start = min(ext.packet_size(), self.buf.len());
                self.buf = &self.buf[start..];
                self.protocol = ext.get_next_header();
                Some(ext)
            }
            _ => None,
        }
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        (0, None)
    }
}
