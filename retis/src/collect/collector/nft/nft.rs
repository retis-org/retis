use std::{
    mem,
    os::fd::{AsFd, AsRawFd},
    process::{Command, Stdio},
    sync::Arc,
};

use anyhow::{anyhow, bail, Result};
use clap::{builder::PossibleValuesParser, Parser};
use libbpf_rs::MapCore;
use log::info;
use serde_json::json;

use super::{bpf::*, nft_hook};
use crate::{
    bindings::nft_hook_uapi::nft_config,
    collect::{cli::Collect, Collector},
    core::{
        events::*,
        inspect,
        kernel::Symbol,
        probe::{Hook, Probe, ProbeBuilderManager},
    },
};

static NFT_BIN: &str = "nft";
const NFT_TRACE_TABLE: &str = "Retis_Table";
const NFT_TRACE_CHAIN: &str = "Retis_Chain";

#[derive(Parser, Debug, Default)]
pub(crate) struct NftCollectorArgs {
    #[arg(
        long,
        value_parser=PossibleValuesParser::new(["all", "continue", "break", "jump", "goto", "return", "drop", "accept", "stolen", "queue", "repeat"]),
        value_delimiter=',',
        default_value="drop,accept",
        help = "Comma separated list of verdicts whose events will be collected. Note that stolen verdicts might not be visible if a filter has been specified using the -f option."
    )]
    nft_verdicts: Vec<String>,
}

#[derive(Default)]
pub(crate) struct NftCollector {
    install_chain: bool,
    // Used to keep a reference to our internal config map.
    #[allow(dead_code)]
    config_map: Option<libbpf_rs::MapHandle>,
}

impl NftCollector {
    fn apply_json(&self, cmd: String) -> Result<()> {
        let status = Command::new(NFT_BIN)
            .arg("-j")
            .arg(cmd)
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()?;

        if !status.success() {
            bail!("Command failed with code: {:?}", status.code());
        }

        Ok(())
    }

    fn create_table(&self) -> Result<()> {
        let json = json!(
        {"nftables":[
            {"add":
             {"table":
              {"family":"inet","name": NFT_TRACE_TABLE}
             }
            },
            {"add":
             {"chain":
              {"family":"inet","table": NFT_TRACE_TABLE,"name":NFT_TRACE_CHAIN}
             }
            },
            {"insert":
             {"rule":
              {"family": "inet", "table": NFT_TRACE_TABLE, "chain": "Retis_Chain",
               "expr": [{"mangle": {"key": {"meta": {"key": "nftrace"}}, "value": 1}}]
              }
             }
            }]});

        self.apply_json(json.to_string())
    }

    fn delete_table(&self, table: String) -> Result<()> {
        let json = json!({"nftables":[
        {"delete":
         {"table":
          {"family":"inet","name":table}
         }
        }]});

        self.apply_json(json.to_string())
            .map_err(|e| anyhow!("Unable to delete {table}: {e}. To remove the table, please run: {NFT_BIN} delete table inet {table}"))
    }

    fn config_map() -> Result<libbpf_rs::MapHandle> {
        let opts = libbpf_sys::bpf_map_create_opts {
            sz: mem::size_of::<libbpf_sys::bpf_map_create_opts>() as libbpf_sys::size_t,
            ..Default::default()
        };

        // Please keep in sync with its BPF counterpart in bpf/nft.bpf.c
        libbpf_rs::MapHandle::create(
            libbpf_rs::MapType::Array,
            Some("nft_config_map"),
            mem::size_of::<u32>() as u32,
            mem::size_of::<nft_config>() as u32,
            1,
            &opts,
        )
        .or_else(|e| bail!("Could not create the nft config map: {}", e))
    }
}

impl Collector for NftCollector {
    fn new() -> Result<Self> {
        Ok(Self::default())
    }

    fn known_kernel_types(&self) -> Option<Vec<&'static str>> {
        Some(vec!["struct nft_traceinfo *"])
    }

    fn can_run(&mut self, cli: &Collect) -> Result<()> {
        let inspector = inspect::inspector()?;

        if let Err(e) = Symbol::from_name("__nft_trace_packet") {
            if let Ok(kconf) = inspector.kernel.get_config_option("CONFIG_NF_TABLES") {
                if kconf != Some("y")
                    && inspector.kernel.is_module_loaded("nf_tables") == Some(false)
                {
                    bail!("Kernel module 'nf_tables' is not loaded");
                }
            }
            bail!("Could not resolve nft kernel symbol: 'nf_tables' kernel module is likely not built-in or loaded ({e})");
        }

        self.install_chain = cli.allow_system_changes;

        if self.install_chain {
            Command::new(NFT_BIN)
                .arg("-v")
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .spawn()
                .map_err(|e| anyhow!("{NFT_BIN} binary not available: {e}"))?;
        } else {
            info!("If an nft trace rule wasn't manually added nft events won't be reported: see help for --allow-system-changes");
        }

        Ok(())
    }

    fn init(
        &mut self,
        args: &Collect,
        probes: &mut ProbeBuilderManager,
        _: Arc<RetisEventsFactory>,
        _: &mut SectionFactories,
    ) -> Result<()> {
        if self.install_chain {
            // Ignore if delete fails here as the table might not exist
            let _ = self.delete_table(NFT_TRACE_TABLE.to_owned());
            self.create_table()?;
        }

        let mut verdicts: u64 = 0;
        for verdict in args.collector_args.nft.nft_verdicts.iter() {
            verdicts |= match verdict.as_str() {
                "all" => (1 << (VERD_MAX + 1)) - 1,
                "continue" => 1 << VERD_CONTINUE,
                "break" => 1 << VERD_BREAK,
                "jump" => 1 << VERD_JUMP,
                "goto" => 1 << VERD_GOTO,
                "return" => 1 << VERD_RETURN,
                "drop" => 1 << VERD_DROP,
                "accept" => 1 << VERD_ACCEPT,
                "stolen" => 1 << VERD_STOLEN,
                "queue" => 1 << VERD_QUEUE,
                "repeat" => 1 << VERD_REPEAT,
                x => bail!("Unknown verdict value ({})", x),
            };
        }

        let config_map = Self::config_map()?;
        let sym = Symbol::from_name("__nft_trace_packet")?;

        let mut cfg = nft_config {
            verdicts,
            ..Default::default()
        };
        if let Some(offset) = sym.parameter_offset("struct nft_chain *")? {
            cfg.offsets.nft_chain = offset as i8;
        }
        if let Some(offset) = sym.parameter_offset("struct nft_rule_dp *")? {
            cfg.offsets.nft_rule = offset as i8;
        }
        if let Some(offset) = sym.parameter_offset("struct nft_verdict *")? {
            cfg.offsets.nft_verdict = offset as i8;
        }
        if let Some(offset) = sym.parameter_offset("enum nft_trace_types")? {
            cfg.offsets.nft_type = offset as i8;
        }

        let cfg = unsafe { plain::as_bytes(&cfg) };

        let key = 0_u32.to_ne_bytes();
        config_map.update(&key, cfg, libbpf_rs::MapFlags::empty())?;

        let mut nft_probe = Probe::kprobe(sym)?;
        nft_probe.add_hook(
            Hook::from(nft_hook::DATA)
                .reuse_map("nft_config_map", config_map.as_fd().as_raw_fd())?
                .to_owned(),
        )?;
        probes.register_probe(nft_probe)?;

        self.config_map = Some(config_map);
        Ok(())
    }

    fn stop(&mut self) -> Result<()> {
        if self.install_chain {
            self.delete_table(NFT_TRACE_TABLE.to_owned())?;
        }
        Ok(())
    }
}
