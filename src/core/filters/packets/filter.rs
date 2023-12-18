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

use crate::core::filters::packets::{
    cbpf::BpfProg,
    ebpf::{eBpfProg, BpfReg},
};

// please keep in sync with FILTER_MAX_INSNS in
// src/core/probe/kernel/bpf/include/common.h
const FILTER_MAX_INSNS: usize = 4096;

#[derive(Clone, Copy)]
#[repr(u32)]
pub(crate) enum FilterPacketType {
    L2 = 0xdeadbeef,
    L3 = 0xdeadc0de,
}

#[derive(Clone)]
pub(crate) struct FilterPacket(eBpfProg);

impl FilterPacket {
    pub(crate) fn from_string_opt(fstring: String, layer_type: FilterPacketType) -> Result<Self> {
        let link_type = match layer_type {
            FilterPacketType::L3 => Linktype(12), // DLT_RAW
            FilterPacketType::L2 => Linktype::ETHERNET,
        };

        let bpf_capture = Capture::dead(link_type)?;
        let program = match bpf_capture.compile(fstring.as_str(), true) {
            Ok(program) => program,
            Err(e) => bail!("Could not compile the filter: {e}"),
        };
        let insns = program.get_instructions();
        let filter = BpfProg::try_from(unsafe { mem::transmute::<_, &[u8]>(insns) })?;

        let ebpf_filter = eBpfProg::try_from(filter)?;
        if ebpf_filter.len() > FILTER_MAX_INSNS {
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
