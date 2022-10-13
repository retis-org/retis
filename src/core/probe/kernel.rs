use anyhow::Result;
use btf_rs::{Btf, Type};

use super::{
    config,
    events::Events,
    r#type::fexit::FexitBuilder,
    r#type::kprobe::KprobeBuilder,
    r#type::raw_tracepoint::RawTracepointBuilder,
    r#type::{ProbeBuilder, ProbeType},
    Group,
};
use crate::core::kernel_symbols;

pub(crate) struct Kernel<'a> {
    group: Group,
    btf: Btf,
    config_map: libbpf_rs::Map,
    events: Events<'a>,
}

impl<'a> Kernel<'a> {
    pub(crate) fn new() -> Result<Kernel<'a>> {
        let mut group = Group::new();

        group.add_builder(ProbeType::Fexit, Box::new(FexitBuilder::new()))?;
        group.add_builder(ProbeType::Kprobe, Box::new(KprobeBuilder::new()))?;
        group.add_builder(ProbeType::RawTracepoint, Box::new(RawTracepointBuilder::new()))?;

        // Filters are either built-in the eBPF program, or,
        //
        // use crate::core::filter::FilterKind;
        // group.add_filter(FilterKind::Skb, crate::core::filter::skb::new())?;
        // group.add_filter(FilterKind::Socket, crate::core::filter::sk::new())?;
        // group.add_filter(FilterKind::Pid, crate::core::filter::pid::new())?;

        let config_map = config::init_config_map()?;
        group.reuse_map("config_map", config_map.fd())?;

        let events = Events::new()?;
        group.reuse_map("event_map", events.fd())?;

        Ok(Kernel {
            group,
            btf: Btf::from_file("/sys/kernel/btf/vmlinux")?,
            config_map,
            events,
        })
    }

    pub(crate) fn add_probe(&mut self, r#type: ProbeType, target: &str) -> Result<()> {
        let ksym = kernel_symbols::get_symbol_addr(target)?.to_ne_bytes();
        self.group.add_probe(r#type, target)?;

        let mut config = config::probe_config {
            capabilities: 0,
            skb_offset: -1,
        };
        if let Some(offset) = self.sk_buff_offset(target)? {
            config.capabilities |= config::PROBE_CAP_SK_BUFF;
            config.skb_offset = offset as i32;
        }

        let config = unsafe { plain::as_bytes(&config) };
        self.config_map
            .update(&ksym, config, libbpf_rs::MapFlags::NO_EXIST)?;

        Ok(())
    }

    pub(crate) fn add_hook(&mut self, hook: &'static [u8]) -> Result<()> {
        self.group.add_hook(hook)
    }

    pub(crate) fn attach(&mut self) -> Result<()> {
        self.group.attach()?;

        // TODO: remove; only for testing. This starts an infinite event loop.
        self.events.events_loop();
        Ok(())
    }

    fn sk_buff_offset(&self, target: &str) -> Result<Option<usize>> {
        let func = match self.btf.resolve_type_by_name(target)? {
            Type::Func(func) => func,
            _ => return Ok(None),
        };

        let proto = match self.btf.resolve_chained_type(&func)? {
            Type::FuncProto(proto) => proto,
            _ => return Ok(None),
        };

        for (offset, param) in proto.parameters.iter().enumerate() {
            if let Type::Ptr(ptr) = self.btf.resolve_chained_type(param)? {
                if let Type::Struct(r#struct) = self.btf.resolve_chained_type(&ptr)? {
                    if self.btf.resolve_name(&r#struct)? == "sk_buff" {
                        return Ok(Some(offset));
                    }
                };
            };
        }

        Ok(None)
    }
}
