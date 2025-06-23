use std::{
    collections::HashMap,
    mem,
    os::fd::{AsFd, AsRawFd},
    sync::Arc,
    time::Duration,
};

use anyhow::{anyhow, bail, Context, Result};
use clap::{arg, Parser};
use libbpf_rs::MapCore;
use log::warn;

use super::{bpf::OvsEventFactory, flow_info::FlowEnricher, hooks};

use crate::{
    bindings::{
        ovs_common_uapi::{execute_actions_ctx, upcall_context},
        ovs_operation_uapi::upcall_batch,
    },
    collect::{cli::Collect, Collector},
    core::{
        events::*,
        inspect,
        kernel::Symbol,
        probe::{user::UsdtProbe, Hook, Probe, ProbeBuilderManager, ProbeOption},
        tracking::gc::TrackingGC,
        user::proc::{Process, ThreadInfo},
    },
    helpers::signals::Running,
};

// GC runs in a thread every OVS_TRACKING_GC_INTERVAL seconds to collect and
// remove old entries.
const OVS_TRACKING_GC_INTERVAL: u64 = 5;

// Time in seconds after entries in the upcall tracking maps are considered outdated
// and should be manually removed. It's a tradeoff between having consistent
// data and not having the map full of old entries. However, this logic
// shouldn't happen much — or it is a bug.
const TRACKING_OLD_LIMIT: u64 = 60;

#[derive(Parser, Debug, Default)]
pub(crate) struct OvsCollectorArgs {
    #[arg(
        long,
        help = "Enable OpenvSwitch upcall tracking. Requires USDT probes being enabled. See https://docs.openvswitch.org/en/latest/topics/usdt-probes/ for instructions."
    )]
    ovs_track: bool,
    #[arg(
        long,
        help = "Enable OpenvSwitch datapath flow enrichment via unixctl command. Requires OpenvSwitch >= 3.4"
    )]
    ovs_enrich_flows: bool,
    #[arg(
        long,
        default_value = "20",
        value_name = "REQUESTS_PER_SEC",
        help = "If '--ovs-enrich-flows' flag is set, rate-limit the number of requests to OpenvSwitch daemon to the specified number of requests per second. Note that increasing the rate might have an impact on the running OpenvSwitch daemon."
    )]
    ovs_enrich_rate: u32,
}

#[derive(Default)]
pub(crate) struct OvsCollector {
    track: bool,
    inflight_upcalls_map: Option<libbpf_rs::MapHandle>,
    inflight_exec_map: Option<libbpf_rs::MapHandle>,

    /* Tracking file descriptors (the maps are owned by the GC) */
    flow_exec_tracking_fd: i32,
    upcall_tracking_fd: i32,
    gc: Option<TrackingGC>,
    running: Running,
    /* Batch tracking maps. */
    upcall_batches: Option<libbpf_rs::MapHandle>,
    pid_to_batch: Option<libbpf_rs::MapHandle>,

    flow_enricher: Option<FlowEnricher>,
}

impl Collector for OvsCollector {
    fn new() -> Result<Self> {
        Ok(Self::default())
    }

    // Check if the OvS collector can run. Some potential errors are silenced,
    // to avoid returning an error if we can't inspect a given area for some
    // reasons.
    fn can_run(&mut self, _: &Collect) -> Result<()> {
        let inspector = inspect::inspector()?;

        // Check if the OvS kernel module is available. We also check for loaded
        // module in case CONFIG_OPENVSWITCH=n because if might be out of tree.
        if let Err(e) = Symbol::from_name("openvswitch:ovs_dp_upcall") {
            if let Ok(kconf) = inspector.kernel.get_config_option("CONFIG_OPENVSWITCH") {
                if kconf != Some("y")
                    && inspector.kernel.is_module_loaded("openvswitch") == Some(false)
                {
                    bail!("Kernel module 'openvswitch' is not loaded");
                }
            }
            bail!("Could not resolve ovs kernel symbol: 'openvswitch' kernel module is likely not built-in or loaded ({e})");
        }

        Ok(())
    }

    fn init(
        &mut self,
        cli: &Collect,
        probes: &mut ProbeBuilderManager,
        retis_factory: Arc<RetisEventsFactory>,
        section_factories: &mut SectionFactories,
    ) -> Result<()> {
        let args = &cli.collector_args.ovs;

        self.track = args.ovs_track;

        if args.ovs_enrich_flows {
            self.init_flow_enricher(retis_factory, section_factories, args.ovs_enrich_rate)?;
        }

        self.inflight_upcalls_map = Some(Self::create_inflight_upcalls_map()?);

        // Create tracking maps and add USDT hooks.
        self.init_tracking_maps()?;
        if self.track {
            self.add_usdt_hooks(probes)?;
        }
        // Add targetted hooks.
        // Upcall related hooks:
        self.add_upcall_hooks(probes)?;
        // Exec related hooks
        self.add_processing_hooks(probes)?;

        Ok(())
    }

    fn start(&mut self) -> Result<()> {
        if let Some(gc) = &mut self.gc {
            gc.start(self.running.clone())?;
        }
        if let Some(enricher) = &mut self.flow_enricher {
            enricher.start(self.running.clone())?;
        }
        Ok(())
    }

    fn stop(&mut self) -> Result<()> {
        #[cfg(not(test))]
        self.running.terminate();

        if let Some(gc) = &mut self.gc {
            gc.join()?;
        }
        if let Some(enricher) = &mut self.flow_enricher {
            enricher.join()?;
        }
        Ok(())
    }
}

impl OvsCollector {
    fn create_flow_exec_tracking_map() -> Result<libbpf_rs::MapHandle> {
        // Please keep in sync with its C counterpart in bpf/ovs_common.h
        let opts = libbpf_sys::bpf_map_create_opts {
            sz: mem::size_of::<libbpf_sys::bpf_map_create_opts>() as libbpf_sys::size_t,
            ..Default::default()
        };

        libbpf_rs::MapHandle::create(
            libbpf_rs::MapType::Hash,
            Some("flow_exec_tracking"),
            mem::size_of::<u32>() as u32,
            mem::size_of::<u64>() as u32,
            8192,
            &opts,
        )
        .or_else(|e| bail!("Could not create the flow_exec_tracking map: {}", e))
    }

    fn create_upcall_tracking_map() -> Result<libbpf_rs::MapHandle> {
        // Please keep in sync with its C counterpart in bpf/ovs_common.h
        let opts = libbpf_sys::bpf_map_create_opts {
            sz: mem::size_of::<libbpf_sys::bpf_map_create_opts>() as libbpf_sys::size_t,
            ..Default::default()
        };

        libbpf_rs::MapHandle::create(
            libbpf_rs::MapType::Hash,
            Some("upcall_tracking"),
            mem::size_of::<u32>() as u32,
            mem::size_of::<u64>() as u32,
            8192,
            &opts,
        )
        .or_else(|e| bail!("Could not create the upcall tracking map: {}", e))
    }

    fn create_inflight_exec_map() -> Result<libbpf_rs::MapHandle> {
        let opts = libbpf_sys::bpf_map_create_opts {
            sz: mem::size_of::<libbpf_sys::bpf_map_create_opts>() as libbpf_sys::size_t,
            ..Default::default()
        };

        libbpf_rs::MapHandle::create(
            libbpf_rs::MapType::Hash,
            Some("inflight_exec"),
            mem::size_of::<u64>() as u32,
            mem::size_of::<execute_actions_ctx>() as u32,
            50,
            &opts,
        )
        .or_else(|e| bail!("Could not create the inflight_exec map: {}", e))
    }

    fn create_inflight_upcalls_map() -> Result<libbpf_rs::MapHandle> {
        let opts = libbpf_sys::bpf_map_create_opts {
            sz: mem::size_of::<libbpf_sys::bpf_map_create_opts>() as libbpf_sys::size_t,
            ..Default::default()
        };

        libbpf_rs::MapHandle::create(
            libbpf_rs::MapType::Hash,
            Some("inflight_upcalls"),
            mem::size_of::<u64>() as u32,
            mem::size_of::<upcall_context>() as u32,
            50,
            &opts,
        )
        .or_else(|e| bail!("Could not create the inflight_upcalls config map: {}", e))
    }

    // Returns the upcall_batches array and the pid_to_batch hash.
    fn create_batch_maps(&mut self, ovs: &Process) -> Result<()> {
        let ovs_threads = ovs.thread_info()?;
        let handlers: Vec<&ThreadInfo> = ovs_threads
            .iter()
            .filter(|t| t.comm.contains("handler"))
            .collect();
        let nhandlers = handlers.len();

        let opts = libbpf_sys::bpf_map_create_opts {
            sz: mem::size_of::<libbpf_sys::bpf_map_create_opts>() as libbpf_sys::size_t,
            ..Default::default()
        };

        self.upcall_batches = Some(
            libbpf_rs::MapHandle::create(
                libbpf_rs::MapType::Array,
                Some("upcall_batches"),
                mem::size_of::<u32>() as u32,
                mem::size_of::<upcall_batch>() as u32,
                nhandlers as u32,
                &opts,
            )
            .or_else(|e| bail!("Could not create the upcall_batches map: {}", e))?,
        );

        let opts = libbpf_sys::bpf_map_create_opts {
            sz: mem::size_of::<libbpf_sys::bpf_map_create_opts>() as libbpf_sys::size_t,
            ..Default::default()
        };

        self.pid_to_batch = Some(
            libbpf_rs::MapHandle::create(
                libbpf_rs::MapType::Hash,
                Some("pid_to_batch"),
                mem::size_of::<u32>() as u32,
                mem::size_of::<u32>() as u32,
                nhandlers as u32,
                &opts,
            )
            .or_else(|e| bail!("Could not create the pid_to_batch map: {}", e))?,
        );

        /* Populate pid_to_batch map. */
        for (batch_idx, handler) in (0_u32..).zip(handlers.iter().as_ref().iter()) {
            self.pid_to_batch.as_mut().unwrap().update(
                &handler.pid.to_ne_bytes(),
                &batch_idx.to_ne_bytes(),
                libbpf_rs::MapFlags::NO_EXIST,
            )?;
        }
        Ok(())
    }

    /// Add upcall hooks.
    fn add_upcall_hooks(&self, probes: &mut ProbeBuilderManager) -> Result<()> {
        let inflight_upcalls_map = self
            .inflight_upcalls_map
            .as_ref()
            .ok_or_else(|| anyhow!("Inflight upcalls map not created"))?
            .as_fd()
            .as_raw_fd();

        // Upcall probe.
        let mut kernel_upcall_tp_hook = Hook::from(hooks::kernel_upcall_tp::DATA);
        kernel_upcall_tp_hook.reuse_map("inflight_upcalls", inflight_upcalls_map)?;
        let mut probe = Probe::raw_tracepoint(Symbol::from_name("openvswitch:ovs_dp_upcall")?)?;
        probe.add_hook(kernel_upcall_tp_hook)?;
        probes.register_probe(probe)?;

        // Upcall return probe.
        let mut kernel_upcall_ret_hook = Hook::from(hooks::kernel_upcall_ret::DATA);
        kernel_upcall_ret_hook.reuse_map("inflight_upcalls", inflight_upcalls_map)?;
        let mut probe = Probe::kretprobe(Symbol::from_name("ovs_dp_upcall")?)?;
        probe.add_hook(kernel_upcall_ret_hook)?;
        probes.register_probe(probe)?;

        if self.track {
            // Upcall enqueue.
            let mut kernel_enqueue_hook = Hook::from(hooks::kernel_enqueue::DATA);
            kernel_enqueue_hook.reuse_map("inflight_upcalls", inflight_upcalls_map)?;
            kernel_enqueue_hook.reuse_map("upcall_tracking", self.upcall_tracking_fd)?;

            let mut probe = Probe::kretprobe(Symbol::from_name("queue_userspace_packet")?)?;
            probe.add_hook(kernel_enqueue_hook)?;
            probes.register_probe(probe)?;
        }

        Ok(())
    }

    /// Add exec hooks.
    fn add_processing_hooks(&mut self, probes: &mut ProbeBuilderManager) -> Result<()> {
        let inflight_exec_map = Self::create_inflight_exec_map()?;

        // ovs_execute_actions kprobe
        let mut exec_actions_hook = Hook::from(hooks::kernel_exec_actions::DATA);
        let ovs_execute_actions_sym = Symbol::from_name("ovs_execute_actions")?;
        exec_actions_hook.reuse_map("inflight_exec", inflight_exec_map.as_fd().as_raw_fd())?;
        exec_actions_hook.reuse_map("flow_exec_tracking", self.flow_exec_tracking_fd)?;
        let mut probe = Probe::kprobe(ovs_execute_actions_sym.clone())?;
        probe.set_option(ProbeOption::NoGenericHook)?;
        probe.add_hook(exec_actions_hook)?;
        probes.register_probe(probe)?;

        // ovs_execute_actions kretprobe
        let mut exec_actions_ret_hook = Hook::from(hooks::kernel_exec_actions_ret::DATA);
        exec_actions_ret_hook.reuse_map("inflight_exec", inflight_exec_map.as_fd().as_raw_fd())?;
        exec_actions_ret_hook.reuse_map("flow_exec_tracking", self.flow_exec_tracking_fd)?;
        let mut probe = Probe::kretprobe(ovs_execute_actions_sym)?;
        probe.set_option(ProbeOption::NoGenericHook)?;
        probe.add_hook(exec_actions_ret_hook)?;
        probes.register_probe(probe)?;

        // ovs_do_execute_action tracepoint
        let mut exec_action_hook = Hook::from(hooks::kernel_exec_tp::DATA);
        exec_action_hook.reuse_map("inflight_exec", inflight_exec_map.as_fd().as_raw_fd())?;
        let mut probe =
            Probe::raw_tracepoint(Symbol::from_name("openvswitch:ovs_do_execute_action")?)?;
        probe.add_hook(exec_action_hook)?;
        probes.register_probe(probe)?;

        // ovs_dp_process_packet kprobe
        let mut ovs_dp_process_packet_hook = Hook::from(hooks::kernel_process_packet::DATA);
        ovs_dp_process_packet_hook
            .reuse_map("inflight_exec", inflight_exec_map.as_fd().as_raw_fd())?;
        let mut probe = Probe::kprobe(Symbol::from_name("ovs_dp_process_packet")?)?;
        probe.set_option(ProbeOption::NoGenericHook)?;
        probe.add_hook(ovs_dp_process_packet_hook)?;
        probes.register_probe(probe)?;

        // ovs_flow_tbl_lookup_stats kprobe
        let mut ovs_flow_tbl_lookup_stats = Hook::from(hooks::kernel_tbl_lookup::DATA);
        ovs_flow_tbl_lookup_stats
            .reuse_map("inflight_exec", inflight_exec_map.as_fd().as_raw_fd())?;
        let mut probe = Probe::kprobe(Symbol::from_name("ovs_flow_tbl_lookup_stats")?)?;
        probe.set_option(ProbeOption::NoGenericHook)?;
        probe.add_hook(ovs_flow_tbl_lookup_stats)?;
        probes.register_probe(probe)?;

        // ovs_flow_tbl_lookup_stats kretprobe
        let mut ovs_flow_tbl_lookup_stats = Hook::from(hooks::kernel_tbl_lookup_ret::DATA);
        ovs_flow_tbl_lookup_stats
            .reuse_map("inflight_exec", inflight_exec_map.as_fd().as_raw_fd())?;
        let mut ovs_flow_tbl_lookup_stats_ctx = Hook::from(hooks::kernel_tbl_lookup_ctx::DATA);
        ovs_flow_tbl_lookup_stats_ctx
            .reuse_map("inflight_exec", inflight_exec_map.as_fd().as_raw_fd())?;
        let mut probe = Probe::kretprobe(Symbol::from_name("ovs_flow_tbl_lookup_stats")?)?;
        probe.add_hook(ovs_flow_tbl_lookup_stats)?;
        probe.set_ctx_hook(ovs_flow_tbl_lookup_stats_ctx)?;
        probes.register_probe(probe)?;

        self.inflight_exec_map = Some(inflight_exec_map);
        Ok(())
    }

    /// Add USDT hooks.
    fn add_usdt_hooks(&mut self, probes: &mut ProbeBuilderManager) -> Result<()> {
        let ovs = Process::from_cmd("ovs-vswitchd")?;
        if !ovs.is_usdt("main::run_start")? {
            bail!(
                "Cannot find USDT probes in ovs-vswitchd. Was it built with --enable-usdt-probes?"
            );
        }
        self.create_batch_maps(&ovs)?;
        let upcall_batches_fd = self
            .upcall_batches
            .as_ref()
            .ok_or_else(|| anyhow!("upcall batches map not created"))?
            .as_fd()
            .as_raw_fd();
        let pid_to_batch_fd = self
            .pid_to_batch
            .as_ref()
            .ok_or_else(|| anyhow!("pid_to_batch map not created"))?
            .as_fd()
            .as_raw_fd();

        let mut user_recv_hook = Hook::from(hooks::user_recv_upcall::DATA);
        user_recv_hook.reuse_map("upcall_tracking", self.upcall_tracking_fd)?;

        let mut user_exec_hook = Hook::from(hooks::user_op_exec::DATA);
        user_exec_hook.reuse_map("flow_exec_tracking", self.flow_exec_tracking_fd)?;
        let mut batch_probes = vec![
            (
                Probe::usdt(UsdtProbe::new(&ovs, "dpif_recv::recv_upcall")?)?,
                user_recv_hook,
            ),
            (
                Probe::usdt(UsdtProbe::new(
                    &ovs,
                    "dpif_netlink_operate__::op_flow_execute",
                )?)?,
                user_exec_hook,
            ),
            (
                Probe::usdt(UsdtProbe::new(&ovs, "dpif_netlink_operate__::op_flow_put")?)?,
                Hook::from(hooks::user_op_put::DATA),
            ),
        ];

        while let Some((mut probe, mut hook)) = batch_probes.pop() {
            hook.reuse_map("upcall_batches", upcall_batches_fd)?
                .reuse_map("pid_to_batch", pid_to_batch_fd)?;
            probe.add_hook(hook)?;
            probes.register_probe(probe)?;
        }
        Ok(())
    }

    fn init_tracking_maps(&mut self) -> Result<()> {
        let upcall_tracking = Self::create_upcall_tracking_map()?;
        let flow_exec_tracking = Self::create_flow_exec_tracking_map()?;
        self.upcall_tracking_fd = upcall_tracking.as_fd().as_raw_fd();
        self.flow_exec_tracking_fd = flow_exec_tracking.as_fd().as_raw_fd();

        let tracking_maps = HashMap::from([
            ("enqueue_tracking", upcall_tracking),
            ("flow_exec_tracking", flow_exec_tracking),
        ]);

        self.gc = Some(
            TrackingGC::new("ovs-tracking-gc", tracking_maps, |v| {
                let insert_time =
                    u64::from_ne_bytes(v[0..8].try_into().map_err(|e| anyhow!("{:?}", e))?);
                Ok(Duration::from_nanos(insert_time))
            })
            .interval(OVS_TRACKING_GC_INTERVAL)
            .limit(TRACKING_OLD_LIMIT),
        );
        Ok(())
    }

    fn init_flow_enricher(
        &mut self,
        retis_factory: Arc<RetisEventsFactory>,
        section_factories: &mut SectionFactories,
        rate: u32,
    ) -> Result<()> {
        let flow_enricher = FlowEnricher::new(retis_factory, rate)
            .context("Failed to connect to OVS via unixctl")?;

        if !flow_enricher.detrace_supported() {
            warn!(
                "Running OpenvSwitch does not support 'ofproto/detrace', only datapath flows will be enriched"
            );
        }

        let ovs_section_factory: &mut OvsEventFactory =
            section_factories.get_mut(&FactoryId::Ovs)?;

        ovs_section_factory.ufid_sender(flow_enricher.sender().clone());

        self.flow_enricher = Some(flow_enricher);

        Ok(())
    }
}
