use std::mem;

use anyhow::{bail, Result};
use clap::{arg, builder::PossibleValuesParser, Parser};
use log::{error, info};

use super::{bpf::*, skb_hook};
use crate::{
    cli::{dynamic::DynamicCommand, CliConfig},
    collect::Collector,
    core::{
        kernel::Symbol,
        probe::{Hook, Probe},
        Retis,
    },
    module::ModuleId,
};

#[derive(Parser, Default)]
pub(crate) struct SkbCollectorArgs {
    #[arg(
        long,
        value_parser=PossibleValuesParser::new(["all", "l2", "l3", "tcp", "udp", "icmp", "dev", "ns", "dataref", "drop_reason"]),
        value_delimiter=',',
        default_value="l3,tcp,udp,icmp,drop_reason",
        help = "Comma separated list of data to collect from skbs"
    )]
    skb_sections: Vec<String>,
}

pub(crate) struct SkbCollector {}

impl Collector for SkbCollector {
    fn new() -> Result<SkbCollector> {
        Ok(SkbCollector {})
    }

    fn known_kernel_types(&self) -> Option<Vec<&'static str>> {
        Some(vec!["struct sk_buff *"])
    }

    fn register_cli(&self, cmd: &mut DynamicCommand) -> Result<()> {
        cmd.register_module::<SkbCollectorArgs>(ModuleId::Skb)
    }

    fn init(&mut self, cli: &CliConfig, retis: &mut Retis) -> Result<()> {
        let probes = retis.probes_mut()?;

        // First, get the cli parameters.
        let args = cli.get_section::<SkbCollectorArgs>(ModuleId::Skb)?;

        let mut sections: u64 = 0;
        for category in args.skb_sections.iter() {
            match category.as_str() {
                "all" => sections |= !0_u64,
                "l2" => sections |= 1 << SECTION_L2,
                "l3" => sections |= 1 << SECTION_IPV4 | 1 << SECTION_IPV6,
                "tcp" => sections |= 1 << SECTION_TCP,
                "udp" => sections |= 1 << SECTION_UDP,
                "icmp" => sections |= 1 << SECTION_ICMP,
                "dev" => sections |= 1 << SECTION_DEV,
                "ns" => sections |= 1 << SECTION_NS,
                "dataref" => sections |= 1 << SECTION_DATA_REF,
                "drop_reason" => sections |= 1 << SECTION_DROP_REASON,
                x => bail!("Unknown skb_collect value ({})", x),
            }
        }

        // Then, create the config map.
        let config_map = Self::config_map()?;

        // Set the config.
        let cfg = SkbConfig { sections };
        let cfg = unsafe { plain::as_bytes(&cfg) };

        let key = 0_u32.to_ne_bytes();
        config_map.update(&key, cfg, libbpf_rs::MapFlags::empty())?;

        // Special case the "drop_reason" section retrieval and automatically
        // add a kprobe to the right function as it's the ~only way to get it.
        if sections & 1 << SECTION_DROP_REASON != 0 {
            let symbol = Symbol::from_name("kfree_skb_reason");
            // Did the probe failed because of an error or because it wasn't
            // available? In case we can't know, do not issue an error.
            match symbol.is_ok() {
                true => {
                    // Unwrap as we just checked the value is valid.
                    if let Err(e) = probes.add_probe(Probe::kprobe(symbol.unwrap())?) {
                        error!("Could not attach to kfree_skb_reason: {}", e);
                    }
                }
                false => info!("Skb drop reasons are not retrievable on this kernel"),
            }
        }

        // Register our generic skb hook.
        probes.register_kernel_hook(
            Hook::from(skb_hook::DATA)
                .reuse_map("skb_config_map", config_map.fd())?
                .to_owned(),
        )?;
        Ok(())
    }
}

impl SkbCollector {
    fn config_map() -> Result<libbpf_rs::Map> {
        let opts = libbpf_sys::bpf_map_create_opts {
            sz: mem::size_of::<libbpf_sys::bpf_map_create_opts>() as libbpf_sys::size_t,
            ..Default::default()
        };

        // Please keep in sync with its BPF counterpart in bpf/skb_hook.bpf.c
        libbpf_rs::Map::create(
            libbpf_rs::MapType::Array,
            Some("skb_config_map"),
            mem::size_of::<u32>() as u32,
            mem::size_of::<SkbConfig>() as u32,
            1,
            &opts,
        )
        .or_else(|e| bail!("Could not create the skb config map: {}", e))
    }
}
