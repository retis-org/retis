use std::collections::HashMap;
use std::sync::Arc;

use anyhow::Result;

use super::sock_hook;
use crate::{
    bindings::sock_hook_uapi::*,
    collect::{cli::Collect, Collector},
    core::{
        events::*,
        inspect::parse_anon_enum,
        probe::{manager::ProbeBuilderManager, Hook},
    },
    event_section_factory,
    events::*,
};

#[derive(Default)]
pub(crate) struct SockCollector {}

impl Collector for SockCollector {
    fn new() -> Result<Self> {
        Ok(Self::default())
    }

    fn known_kernel_types(&self) -> Option<Vec<&'static str>> {
        Some(vec!["struct sock *", "struct sk_buff *"])
    }

    fn init(
        &mut self,
        _: &Collect,
        probes: &mut ProbeBuilderManager,
        _: Arc<RetisEventsFactory>,
        _: &mut SectionFactories,
    ) -> Result<()> {
        probes.register_kernel_hook(Hook::from(sock_hook::DATA))
    }
}

#[event_section_factory(FactoryId::Sock)]
#[derive(Default)]
pub(crate) struct SockEventFactory {
    // Mapping of socket protocols to names
    socket_protocols: HashMap<u32, String>,
    // TCP socket states
    tcp_states: HashMap<u32, String>,
}

impl RawEventSectionFactory for SockEventFactory {
    fn create(&mut self, raw_sections: Vec<BpfRawSection>, event: &mut Event) -> Result<()> {
        let raw = parse_single_raw_section::<sock_event>(&raw_sections)?;

        /* These should be kept in sync with "enum sock_type" in
         * include/linux/net.h. It hasn't been modified for the last 20 years
         * so chances are this is not very costy to maintain. */
        let r#type = match raw.type_ {
            1 => "SOCK_STREAM",
            2 => "SOCK_DGRAM",
            3 => "SOCK_RAW",
            4 => "SOCK_RDM",
            5 => "SOCK_SEQPACKET",
            6 => "SOCK_DGRAM",
            10 => "SOCK_PACKET",
            _ => "UNKNOWN",
        }
        .to_string();

        let proto = match self.socket_protocols.get(&(raw.proto as u32)) {
            Some(r) => r.clone(),
            None => format!("{}", raw.proto),
        };

        let state = match proto.as_str() {
            "TCP" | "UDP" => match self.tcp_states.get(&(raw.state as u32)) {
                Some(r) => r.clone(),
                None => format!("{}", raw.state),
            },
            _ => format!("{}", raw.state),
        };

        event.sock = Some(SockEvent {
            inode: raw.inode,
            r#type,
            proto,
            state,
        });

        Ok(())
    }
}

impl SockEventFactory {
    pub(crate) fn new() -> Result<Self> {
        Ok(Self {
            socket_protocols: parse_anon_enum("IPPROTO_IP", &["IPPROTO_"])?,
            tcp_states: parse_anon_enum("TCP_ESTABLISHED", &["TCP_"])?,
        })
    }
}

#[cfg(feature = "benchmark")]
pub(crate) mod benchmark {
    use anyhow::Result;

    use super::*;
    use crate::{benchmark::helpers::*, core::events::FactoryId};

    impl RawSectionBuilder for sock_event {
        fn build_raw(out: &mut Vec<u8>) -> Result<()> {
            let data = Self::default();
            build_raw_section(out, FactoryId::Sock as u8, 0, &mut as_u8_vec(&data));
            Ok(())
        }
    }
}
