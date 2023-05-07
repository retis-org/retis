use std::process::{Command, Stdio};

use anyhow::{anyhow, bail, Result};
use serde_json::json;

use super::nft_hook;
use crate::{
    cli::{dynamic::DynamicCommand, CliConfig},
    collect::{cli::Collect, Collector},
    core::{
        kernel::Symbol,
        probe::{Hook, Probe, ProbeManager},
    },
    module::ModuleId,
};

static NFT_BIN: &str = "nft";
const NFT_TRACE_TABLE: &str = "Retis_Table";
const NFT_TRACE_CHAIN: &str = "Retis_Chain";

#[derive(Default)]
pub(crate) struct NftCollector {
    install_chain: bool,
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
}

impl Collector for NftCollector {
    fn new() -> Result<NftCollector> {
        Ok(NftCollector::default())
    }

    fn register_cli(&self, cmd: &mut DynamicCommand) -> Result<()> {
        cmd.register_module_noargs(ModuleId::Nft)
    }

    fn init(&mut self, cli: &CliConfig, probes: &mut ProbeManager) -> Result<()> {
        self.install_chain = cli
            .subcommand
            .as_any()
            .downcast_ref::<Collect>()
            .ok_or_else(|| anyhow!("wrong subcommand"))?
            .args()?
            .allow_system_changes;
        if self.install_chain {
            // Ignore if delete fails here as the table might not exist
            let _ = self.delete_table(NFT_TRACE_TABLE.to_owned());
            self.create_table()?;
        }

        let mut nft_probe = Probe::kprobe(Symbol::from_name("__nft_trace_packet")?)?;
        nft_probe.add_hook(Hook::from(nft_hook::DATA))?;
        probes.register_probe(nft_probe)?;

        Ok(())
    }

    fn stop(&mut self) -> Result<()> {
        if self.install_chain {
            self.delete_table(NFT_TRACE_TABLE.to_owned())?;
        }
        Ok(())
    }
}
