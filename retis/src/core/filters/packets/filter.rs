//! # FilterPacket
//!
//! Object for packet filtering it implements from_string() and
//! to_bytes(). While the latter is self explainatory, the second
//! takes as input a pcap-filter string that gets converted to a bpf
//! program using libpcap, the resulting output gets then converted to
//! ebpf and returned for being consumed.

use std::mem;

use anyhow::{bail, Result};
use pcap::{Capture, Linktype};

use super::ebpfinsn::{eBpfInsn, MovInfo};

use crate::{
    bindings::packet_filter_uapi,
    core::filters::packets::{
        cbpf::BpfProg,
        ebpf::{eBpfProg, BpfReg},
    },
};

#[derive(Clone)]
pub(crate) struct FilterPacket(eBpfProg);

impl FilterPacket {
    pub(crate) fn from_string_opt(
        fstring: String,
        layer_type: packet_filter_uapi::filter_type,
    ) -> Result<Self> {
        let link_type = match layer_type {
            packet_filter_uapi::L3 => Linktype(12), // DLT_RAW
            packet_filter_uapi::L2 => Linktype::ETHERNET,
            _ => bail!("Unsupported filter type"),
        };

        let bpf_capture = Capture::dead(link_type)?;
        let program = match bpf_capture.compile(fstring.as_str(), true) {
            Ok(program) => program,
            Err(e) => bail!("Could not compile the filter: {e}"),
        };
        let insns = program.get_instructions();
        let filter =
            BpfProg::try_from(unsafe { mem::transmute::<&[pcap::BpfInstruction], &[u8]>(insns) })?;

        let ebpf_filter = eBpfProg::try_from(filter)?;
        if ebpf_filter.len() > packet_filter_uapi::FILTER_MAX_INSNS as usize {
            bail!("Filter exceeds the maximum allowed size.");
        }

        Ok(FilterPacket(ebpf_filter))
    }

    // Generate an empty eBPF filter containing only a single nop
    // instruction.
    pub(crate) fn reject_filter() -> Self {
        let mut ebpf_filter = eBpfProg::new();

        ebpf_filter.add(eBpfInsn::mov32(MovInfo::Imm {
            dst: BpfReg::R0,
            imm: 0_i32,
        }));

        FilterPacket(ebpf_filter)
    }

    pub(crate) fn to_bytes(&self) -> Result<Vec<u8>> {
        Ok(self.0.to_bytes())
    }
}

#[cfg(test)]
mod tests {
    use std::{mem, slice};

    use rbpf;
    use test_case::test_matrix;

    use super::*;

    use crate::{bindings::packet_filter_uapi::*, core::filters::bpf_probe_read_kernel_helper};

    #[test_matrix([packet_filter_uapi::L2, packet_filter_uapi::L3],
                  ["tcp and dst host 10.0.0.254",
                   "tcp and src host 10.0.0.1",
                   "tcp[tcpflags] & (tcp-syn|tcp-ack) == tcp-syn|tcp-ack",
                   "tcp and ip[20:2] == 59781 and ip[22:2] == 80"] => true)]
    #[test_matrix(packet_filter_uapi::L2, ["tcp and len == 54",
                                           "tcp and ether[34:2] == 59781 and ether[36:2] == 80",
                                           "ether src 00:11:11:11:11:11 and ether dst 00:22:22:22:22:22 and ip proto \\tcp"] => true)]
    #[test_matrix([packet_filter_uapi::L2, packet_filter_uapi::L3],
                  ["udp and dst host 10.0.0.254",
                   "icmp and src host 10.0.0.1",
                   "ip6 and tcp",
                   "udp and ip[20:2] == 59781 and ip[22:2] == 80"] => false)]
    #[test_case(packet_filter_uapi::L3, "tcp and len == 40" => true)]
    fn packet_tcp_match(
        filter_type: packet_filter_uapi::filter_type,
        pcap_filter: &'static str,
    ) -> bool {
        // 00:11:11:11:11:11 > 00:22:22:22:22:22, ethertype IPv4 (0x0800), length 54: (tos 0x0, ttl 64, id 1, offset 0,
        // flags [none], proto TCP (6), length 40)
        //    10.0.0.1.59781 > 10.0.0.254.80: Flags [S.], cksum 0x90fe (correct), seq 0, ack 0, win 8192, length 0
        let packet_bytes: [u8; 54] = [
            0x00, 0x22, 0x22, 0x22, 0x22, 0x22, 0x00, 0x11, 0x11, 0x11, 0x11, 0x11, 0x08, 0x00,
            0x45, 0x00, 0x00, 0x28, 0x00, 0x01, 0x00, 0x00, 0x40, 0x06, 0x65, 0xd1, 0x0a, 0x00,
            0x00, 0x01, 0x0a, 0x00, 0x00, 0xfe, 0xe9, 0x85, 0x00, 0x50, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x50, 0x12, 0x20, 0x00, 0x90, 0xfe, 0x00, 0x00,
        ];

        // The L3 flavor simply does not include the MAC header.
        let packet: &[u8] = match filter_type {
            packet_filter_uapi::L2 => &packet_bytes,
            packet_filter_uapi::L3 => &packet_bytes[14..],
            _ => panic!("Wrong packet type"),
        };

        let ctx = retis_packet_filter_ctx::default();

        let pf = FilterPacket::from_string_opt(format!("{pcap_filter}").to_string(), filter_type);
        let pf = pf.unwrap();

        let mbuff = unsafe {
            slice::from_raw_parts(
                (&ctx as *const _) as *const u8,
                mem::size_of::<retis_packet_filter_ctx>(),
            )
        };

        unsafe {
            let data = mbuff
                .as_ptr()
                .offset(memoffset::offset_of!(retis_packet_filter_ctx, data) as isize)
                as *mut u64;
            let len = mbuff
                .as_ptr()
                .offset(memoffset::offset_of!(retis_packet_filter_ctx, len) as isize)
                as *mut u32;
            *data = packet.as_ptr() as u64;
            *len = packet.len() as u32;
        }

        let prog = &pf.to_bytes().unwrap();

        let mut vm = rbpf::EbpfVmMbuff::new(Some(prog)).unwrap();
        vm.register_helper(113, bpf_probe_read_kernel_helper)
            .unwrap();
        vm.execute_program(packet, &mbuff).unwrap() != 0
    }
}
