use anyhow::{bail, Result};

use super::{bpf::*, kernel_exec_tp, kernel_upcall_tp};

use crate::{
    cli::{dynamic::DynamicCommand, CliConfig},
    collect::Collector,
    core::{
        events::bpf::{BpfEventOwner, BpfEvents},
        kernel::Symbol,
        probe::{Hook, Probe, ProbeManager},
        user::proc::Process,
    },
};

const OVS_COLLECTOR: &str = "ovs";

pub(crate) struct OvsCollector {}

impl Collector for OvsCollector {
    fn new() -> Result<OvsCollector> {
        Ok(OvsCollector {})
    }

    fn name(&self) -> &'static str {
        OVS_COLLECTOR
    }

    fn known_kernel_types(&self) -> Option<Vec<&'static str>> {
        None
    }

    fn register_cli(&self, cmd: &mut DynamicCommand) -> Result<()> {
        cmd.register_module_noargs(OVS_COLLECTOR)
    }

    fn init(
        &mut self,
        _: &CliConfig,
        probes: &mut ProbeManager,
        events: &mut BpfEvents,
    ) -> Result<()> {
        // Register unmarshaler.
        events.register_unmarshaler(
            BpfEventOwner::CollectorOvs,
            Box::new(|raw_section, fields, _| {
                let event_type = OvsEventType::from_u8(raw_section.header.data_type)?;
                match event_type {
                    OvsEventType::Upcall => unmarshall_upcall(raw_section, fields)?,
                    OvsEventType::ActionExec => unmarshall_exec(raw_section, fields)?,
                    OvsEventType::OutputAction => unmarshall_output(raw_section, fields)?,
                }
                Ok(())
            }),
        )?;

        // Add generic probes that can be probbed by other collectors such as skb.
        self.add_generic_probes(probes)?;

        // Add targetted hooks.
        self.add_kernel_hooks(probes)?;

        // Add USDT hooks.
        self.add_usdt_hooks(probes)?;
        Ok(())
    }

    fn start(&mut self) -> Result<()> {
        Ok(())
    }
}

impl OvsCollector {
    /// Add generic kernel probes.
    fn add_generic_probes(&self, probes: &mut ProbeManager) -> Result<()> {
        probes.add_probe(Probe::raw_tracepoint(Symbol::from_name(
            "openvswitch:ovs_dp_upcall",
        )?)?)?;
        Ok(())
    }

    /// Add kernel hooks.
    fn add_kernel_hooks(&self, probes: &mut ProbeManager) -> Result<()> {
        // Upcall probe.
        probes.register_hook_to(
            Hook::from(kernel_upcall_tp::DATA),
            Probe::raw_tracepoint(Symbol::from_name("openvswitch:ovs_dp_upcall")?)?,
        )?;

        // Action execute probe.
        probes.register_hook_to(
            Hook::from(kernel_exec_tp::DATA),
            Probe::raw_tracepoint(Symbol::from_name("openvswitch:ovs_do_execute_action")?)?,
        )?;
        Ok(())
    }

    /// Add USDT hooks.
    fn add_usdt_hooks(&self, _probes: &mut ProbeManager) -> Result<()> {
        let ovs = Process::from_cmd("ovs-vswitchd")?;
        if !ovs.is_usdt("main::run_start")? {
            bail!(
                "Cannot find USDT probes in ovs-vswitchd. Was it built with --enable-usdt-probes?"
            );
        }
        Ok(())
    }
}
