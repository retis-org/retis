use std::mem;

use anyhow::{bail, Result};
use clap::{arg, builder::PossibleValuesParser, Parser};

use super::{bpf::*, skb_hook};
use crate::{
    cli::{dynamic::DynamicCommand, CliConfig},
    collect::Collector,
    core::{
        events::bpf::{BpfEventOwner, BpfEvents},
        probe::{Hook, ProbeManager},
    },
};

const SKB_COLLECTOR: &str = "skb";

#[derive(Parser, Default)]
pub(crate) struct SkbCollectorArgs {
    #[arg(
        long,
        value_parser=PossibleValuesParser::new(["all", "l2"]),
        value_delimiter=',',
        default_value="",
        help = "Comma separated list of data to collect from skbs"
    )]
    skb_sections: Vec<String>,
}

pub(crate) struct SkbCollector {}

impl Collector for SkbCollector {
    fn new() -> Result<SkbCollector> {
        Ok(SkbCollector {})
    }

    fn name(&self) -> &'static str {
        SKB_COLLECTOR
    }

    fn known_kernel_types(&self) -> Option<Vec<&'static str>> {
        Some(vec!["struct sk_buff *"])
    }

    fn register_cli(&self, cmd: &mut DynamicCommand) -> Result<()> {
        cmd.register_module::<SkbCollectorArgs>(SKB_COLLECTOR)
    }

    fn init(
        &mut self,
        cli: &CliConfig,
        probes: &mut ProbeManager,
        events: &mut BpfEvents,
    ) -> Result<()> {
        // First, get the cli parameters.
        let args = cli.get_section::<SkbCollectorArgs>(SKB_COLLECTOR)?;

        let mut sections: u64 = 0;
        for category in args.skb_sections.iter() {
            match category.as_str() {
                "all" => sections |= !0_u64,
                "l2" => sections |= 1 << SECTION_L2,
                x => bail!("Unknown skb_collect value ({})", x),
            }
        }

        // Register our event unmarshaler.
        events.register_unmarshaler(
            BpfEventOwner::CollectorSkb,
            Box::new(
                |raw_section, fields, _| match raw_section.header.data_type as u64 {
                    SECTION_L2 => unmarshal_l2(raw_section, fields),
                    _ => bail!("Unknown data type"),
                },
            ),
        )?;

        // Then, create the config map.
        let mut config_map = Self::config_map()?;

        // Set the config.
        let cfg = SkbConfig { sections };
        let cfg = unsafe { plain::as_bytes(&cfg) };

        let key = 0_u32.to_ne_bytes();
        config_map.update(&key, cfg, libbpf_rs::MapFlags::empty())?;

        // Register our generic skb hook.
        probes.register_kernel_hook(
            Hook::from(skb_hook::DATA)
                .reuse_map("skb_config_map", config_map.fd())?
                .to_owned(),
        )?;
        Ok(())
    }

    fn start(&mut self) -> Result<()> {
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
