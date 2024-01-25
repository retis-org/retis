use std::{
    mem,
    os::fd::{AsFd, AsRawFd},
};

use anyhow::{bail, Result};
use clap::{arg, builder::PossibleValuesParser, Parser};
use log::warn;

use super::{bpf::*, skb_hook, SkbEventFactory};
use crate::{
    cli::{dynamic::DynamicCommand, CliConfig},
    collect::Collector,
    core::{
        events::EventSectionFactory,
        probe::{Hook, ProbeBuilderManager},
    },
    module::{Module, ModuleId},
};

#[derive(Parser, Default)]
pub(crate) struct SkbCollectorArgs {
    #[arg(
        long,
        value_parser=PossibleValuesParser::new([
            "all", "eth", "dev", "ns", "meta", "dataref", "gso",
            // Below values are deprecated.
            "arp", "ip", "tcp", "udp", "icmp", "packet",
        ]),
        value_delimiter=',',
        default_value="dev",
        help = "Comma separated list of data to collect from skbs"
    )]
    skb_sections: Vec<String>,
}

#[derive(Default)]
pub(crate) struct SkbModule {
    // Used to keep a reference to our internal config map.
    #[allow(dead_code)]
    config_map: Option<libbpf_rs::MapHandle>,
}

impl Collector for SkbModule {
    fn new() -> Result<Self> {
        Ok(Self::default())
    }

    fn known_kernel_types(&self) -> Option<Vec<&'static str>> {
        Some(vec!["struct sk_buff *"])
    }

    fn register_cli(&self, cmd: &mut DynamicCommand) -> Result<()> {
        cmd.register_module::<SkbCollectorArgs>(ModuleId::Skb)
    }

    fn init(&mut self, cli: &CliConfig, probes: &mut ProbeBuilderManager) -> Result<()> {
        // First, get the cli parameters.
        let args = cli.get_section::<SkbCollectorArgs>(ModuleId::Skb)?;

        // Default list of sections.
        let mut sections: u64 = 1 << SECTION_PACKET
            | 1 << SECTION_ARP
            | 1 << SECTION_TCP
            | 1 << SECTION_UDP
            | 1 << SECTION_ICMP;

        for category in args.skb_sections.iter() {
            match category.as_str() {
                "all" => sections |= !0_u64,
                "dev" => sections |= 1 << SECTION_DEV,
                "ns" => sections |= 1 << SECTION_NS,
                "meta" => sections |= 1 << SECTION_META,
                "dataref" => sections |= 1 << SECTION_DATA_REF,
                "gso" => sections |= 1 << SECTION_GSO,
                "packet" | "eth" | "arp" | "ip" | "tcp" | "udp" | "icmp" => {
                    warn!(
                        "Use of '{}' in --skb-sections is depreacted (is now always set)",
                        category.as_str(),
                    );
                }
                x => bail!("Unknown skb_collect value ({})", x),
            }
        }

        // Then, create the config map.
        let config_map = Self::config_map()?;

        // Set the config.
        let cfg = RawConfig { sections };
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

impl Module for SkbModule {
    fn collector(&mut self) -> &mut dyn Collector {
        self
    }
    fn section_factory(&self) -> Result<Box<dyn EventSectionFactory>> {
        Ok(Box::new(SkbEventFactory {}))
    }
}

impl SkbModule {
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
            mem::size_of::<RawConfig>() as u32,
            1,
            &opts,
        )
        .or_else(|e| bail!("Could not create the skb config map: {}", e))
    }
}
