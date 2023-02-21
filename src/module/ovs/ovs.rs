use anyhow::{bail, Result};

use super::{bpf::*, kernel_exec_tp, kernel_upcall_tp, user_recv_upcall};

use crate::{
    cli::{dynamic::DynamicCommand, CliConfig},
    collect::Collector,
    core::{
        events::{
            bpf::{BpfEventOwner, BpfEvents, BpfRawSection},
            EventField,
        },
        kernel::Symbol,
        probe::{user::UsdtProbe, Hook, Probe, ProbeManager},
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
            Box::new(
                |raw_section: &BpfRawSection, fields: &mut Vec<EventField>| {
                    match OvsEventType::from_u8(raw_section.header.data_type)? {
                        OvsEventType::Upcall => unmarshall_upcall(raw_section, fields)?,
                        OvsEventType::RecvUpcall => unmarshall_recv(raw_section, fields)?,
                        OvsEventType::ActionExec => unmarshall_exec(raw_section, fields)?,
                        OvsEventType::OutputAction => unmarshall_output(raw_section, fields)?,
                    }
                    Ok(())
                },
            ),
        )?;

        // Add targetted hooks.
        self.add_kernel_hooks(probes)?;

        // Add USDT hooks.
        self.add_usdt_hooks(probes)?;
        Ok(())
    }
}

impl OvsCollector {
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
    fn add_usdt_hooks(&self, probes: &mut ProbeManager) -> Result<()> {
        let ovs = Process::from_cmd("ovs-vswitchd")?;
        if !ovs.is_usdt("main::run_start")? {
            bail!(
                "Cannot find USDT probes in ovs-vswitchd. Was it built with --enable-usdt-probes?"
            );
        }

        let recv_upcall = Probe::Usdt(UsdtProbe::new(&ovs, "dpif_recv::recv_upcall")?);
        probes.register_hook_to(Hook::from(user_recv_upcall::DATA), recv_upcall)?;

        Ok(())
    }
}
