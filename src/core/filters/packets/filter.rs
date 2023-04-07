//! # FilterPacket
//!
//! Object for packet filtering it implements from_string() and
//! to_bytes(). While the latter is self explainatory, the second
//! takes as input a pcap-filter string that gets converted to a bpf
//! program using libpcap, the resulting output gets then converted to
//! ebpf and returned for being consumed.

use std::mem;

use anyhow::Result;
use pcap::{Capture, Linktype};

use crate::core::filters::{packets::cbpf::BpfProg, packets::ebpf::eBpfProg};

#[derive(Clone)]
pub(crate) struct FilterPacket(eBpfProg);

impl FilterPacket {
    pub(crate) fn from_string(fstring: String) -> Result<Self> {
        let bpf_capture = Capture::dead(Linktype::ETHERNET)?;
        let program = bpf_capture.compile(fstring.as_str(), true)?;
        let insns = program.get_instructions();
        let filter = BpfProg::try_from(unsafe { mem::transmute::<_, &[u8]>(insns) })?;

        Ok(FilterPacket(eBpfProg::try_from(filter)?))
    }

    pub(crate) fn to_bytes(&self) -> Result<Vec<u8>> {
        Ok(self.0.to_bytes())
    }
}
