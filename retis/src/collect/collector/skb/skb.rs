use std::{
    mem,
    os::fd::{AsFd, AsRawFd},
    sync::Arc,
};

use anyhow::{bail, Result};
use clap::{arg, builder::PossibleValuesParser, Parser};
use libbpf_rs::MapCore;
use log::warn;

use super::skb_hook;
use crate::{
    bindings::skb_hook_uapi::*,
    collect::{cli::Collect, Collector},
    core::{
        events::*,
        probe::{Hook, ProbeBuilderManager},
    },
};

#[derive(Parser, Debug, Default)]
pub(crate) struct SkbCollectorArgs {
    #[arg(
        long,
        value_parser=PossibleValuesParser::new([
            "all", "eth", "meta", "dataref", "gso",
            // Below values are deprecated.
            "arp", "ip", "tcp", "udp", "icmp", "packet", "vlan", "dev", "ns",
        ]),
        value_delimiter=',',
        help = "Comma separated list of extra information to collect from skbs.

Supported values:
- meta:    include skb metadata information (len, data_len, hash, etc).
- dataref: include data & refcnt information (cloned, users, data refs, etc).
- gso:     include generic segmentation offload (GSO) information.
- all:     all of the above.

The packet, dev and ns sections, as well as the VLAN offloading metadata are
always retrieved.

The following values are ignored and no event section will be generated as the
corresponding data is part of the raw packet: eth, arp, ip, tcp, udp, icmp."
    )]
    pub(crate) skb_sections: Vec<String>,
}

#[derive(Default)]
pub(crate) struct SkbCollector {
    // Used to keep a reference to our internal config map.
    #[allow(dead_code)]
    config_map: Option<libbpf_rs::MapHandle>,
}

impl Collector for SkbCollector {
    fn new() -> Result<Self> {
        Ok(Self::default())
    }

    fn known_kernel_types(&self) -> Option<Vec<&'static str>> {
        Some(vec!["struct sk_buff *"])
    }

    fn init(
        &mut self,
        args: &Collect,
        probes: &mut ProbeBuilderManager,
        _: Arc<RetisEventsFactory>,
        _: &mut SectionFactories,
    ) -> Result<()> {
        // Default list of sections. We set SECTION_PACKET even though it's not
        // checked in the BPF hook (raw packet is always reported) and
        // SECTION_VLAN (that's the offloaded VLAN data) as when non-offloaded
        // we'll get VLAN info from the packet and that would be inconsistent.
        let mut sections: u64 =
            1 << SECTION_PACKET | 1 << SECTION_VLAN | 1 << SECTION_DEV | 1 << SECTION_NS;

        for category in args.collector_args.skb.skb_sections.iter() {
            match category.as_str() {
                "all" => sections |= !0_u64,
                "meta" => sections |= 1 << SECTION_META,
                "dataref" => sections |= 1 << SECTION_DATA_REF,
                "gso" => sections |= 1 << SECTION_GSO,
                "eth" => (),
                "packet" | "arp" | "ip" | "tcp" | "udp" | "icmp" | "dev" | "ns" => {
                    warn!(
                        "Use of '{}' in --skb-sections is depreacted",
                        category.as_str(),
                    );
                }
                x => bail!("Unknown skb_collect value ({})", x),
            }
        }

        // Then, create the config map.
        let config_map = Self::config_map()?;

        // Set the config.
        let cfg = skb_config { sections };
        let cfg = unsafe { plain::as_bytes(&cfg) };

        let key = 0_u32.to_ne_bytes();
        config_map.update(&key, cfg, libbpf_rs::MapFlags::empty())?;

        // Register our generic skb hook.
        probes.register_kernel_hook(
            Hook::from(skb_hook::DATA)
                .reuse_map("skb_config_map", config_map.as_fd().as_raw_fd())?
                .to_owned(),
        )?;

        self.config_map = Some(config_map);
        Ok(())
    }
}

impl SkbCollector {
    fn config_map() -> Result<libbpf_rs::MapHandle> {
        let opts = libbpf_sys::bpf_map_create_opts {
            sz: mem::size_of::<libbpf_sys::bpf_map_create_opts>() as libbpf_sys::size_t,
            ..Default::default()
        };

        // Please keep in sync with its BPF counterpart in bpf/skb_hook.bpf.c
        libbpf_rs::MapHandle::create(
            libbpf_rs::MapType::Array,
            Some("skb_config_map"),
            mem::size_of::<u32>() as u32,
            mem::size_of::<skb_config>() as u32,
            1,
            &opts,
        )
        .or_else(|e| bail!("Could not create the skb config map: {}", e))
    }
}
