use std::{
    mem,
    os::fd::{AsFd, AsRawFd},
};

use anyhow::{bail, Result};
use clap::{arg, builder::PossibleValuesParser, Parser};
use log::warn;

use super::{bpf::*, skb_hook};
use crate::{
    cli::{dynamic::DynamicCommand, CliConfig},
    collect::Collector,
    core::probe::{Hook, ProbeBuilderManager},
    events::EventSectionFactory,
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
        help = "Comma separated list of extra information to collect from skbs.

Supported values:
- eth:     include Ethernet information (src, dst, etype).
- dev:     include network device information.
- ns:      include network namespace information.
- meta:    include skb metadata information (len, data_len, hash, etc).
- dataref: include data & refcnt information (cloned, users, data refs, etc).
- gso:     include generic segmentation offload (GSO) information.
- all:     all of the above.

The following values are now always retrieved and their use is deprecated:
packet, arp, ip, tcp, udp, icmp."
    )]
    skb_sections: Vec<String>,
}

#[derive(Default)]
pub(crate) struct SkbModule {
    // Used to keep a reference to our internal config map.
    #[allow(dead_code)]
    config_map: Option<libbpf_rs::MapHandle>,
    // Should we report the Ethernet section?
    report_eth: bool,
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

        // Default list of sections. We set SECTION_PACKET even though it's not
        // checked in the BPF hook (raw packet is always reported).
        let mut sections: u64 = 1 << SECTION_PACKET;

        for category in args.skb_sections.iter() {
            match category.as_str() {
                "all" => {
                    sections |= !0_u64;
                    self.report_eth = true;
                }
                "dev" => sections |= 1 << SECTION_DEV,
                "ns" => sections |= 1 << SECTION_NS,
                "meta" => sections |= 1 << SECTION_META,
                "dataref" => sections |= 1 << SECTION_DATA_REF,
                "gso" => sections |= 1 << SECTION_GSO,
                "eth" => self.report_eth = true,
                "packet" | "arp" | "ip" | "tcp" | "udp" | "icmp" => {
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
        Ok(Box::new(SkbEventFactory {
            report_eth: self.report_eth,
        }))
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
