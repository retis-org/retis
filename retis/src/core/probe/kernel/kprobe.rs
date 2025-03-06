//! # Kprobe
//!
//! Module to handle attaching programs to kernel probes. The module is split
//! in two parts, the Rust code (here) and the eBPF one (bpf/kprobe.bpf.c and
//! its auto-generated part in bpf/.out/).

use std::os::fd::{AsFd, AsRawFd, RawFd};

use anyhow::{anyhow, bail, Result};
use libbpf_rs::{
    skel::{OpenSkel, Skel},
    KprobeMultiOpts, KprobeOpts,
};

use crate::core::{filters::Filter, inspect, probe::builder::*, probe::*, workaround::*};

mod kprobe_bpf {
    include!("bpf/.out/kprobe.skel.rs");
}
use kprobe_bpf::*;

#[derive(Default)]
pub(crate) struct KprobeBuilder<'a> {
    skel: Option<SkelStorage<KprobeSkel<'a>>>,
    kprobe_multi: bool,
    probes: Vec<Probe>,
    links: Vec<libbpf_rs::Link>,
}

impl<'a> ProbeBuilder for KprobeBuilder<'a> {
    fn new() -> Result<KprobeBuilder<'a>> {
        Ok(Self {
            kprobe_multi: Self::kprobe_multi_support()?,
            ..Default::default()
        })
    }

    fn init(
        &mut self,
        map_fds: Vec<(String, RawFd)>,
        hooks: Vec<Hook>,
        filters: Vec<Filter>,
        ctx_hook: Option<Hook>,
    ) -> Result<()> {
        if self.skel.is_some() {
            bail!("Kprobe builder already initialized");
        }

        let mut skel = OpenSkelStorage::new::<KprobeSkelBuilder>()?;

        skel.maps.rodata_data.nhooks = hooks.len() as u32;
        skel.maps.rodata_data.log_level = log::max_level() as u8;

        filters.iter().for_each(|f| {
            if let Filter::Meta(m) = f {
                skel.maps.rodata_data.nmeta = m.0.len() as u32
            }
        });

        reuse_map_fds(skel.open_object_mut(), &map_fds)?;

        if self.kprobe_multi {
            skel.open_object_mut()
                .progs_mut()
                .find(|p| p.name() == "probe_kprobe")
                .ok_or_else(|| anyhow!("Couldn't get program"))?
                .set_attach_type(libbpf_rs::ProgramAttachType::KprobeMulti);
        }

        let skel = SkelStorage::load(skel)?;
        let fd = skel
            .object()
            .progs()
            .find(|p| p.name() == "probe_kprobe")
            .ok_or_else(|| anyhow!("Couldn't get program"))?
            .as_fd()
            .as_raw_fd();
        let mut links = replace_hooks(fd, &hooks)?;
        self.links.append(&mut links);

        if let Some(ctx_hook) = ctx_hook {
            self.links.push(replace_ctx_hook(fd, &ctx_hook)?);
        }

        self.skel = Some(skel);
        Ok(())
    }

    fn add_probe(&mut self, probe: Probe) -> Result<()> {
        self.probes.push(probe);
        Ok(())
    }

    fn attach(&mut self) -> Result<()> {
        if self.probes.is_empty() {
            return Ok(());
        }

        let tmp = std::mem::take(&mut self.probes);
        match self.kprobe_multi {
            true => self.attach_kprobe_multi(&tmp)?,
            false => self.attach_kprobes(&tmp)?,
        }

        Ok(())
    }

    fn detach(&mut self) -> Result<()> {
        self.links.drain(..);
        Ok(())
    }
}

impl KprobeBuilder<'_> {
    fn kprobe_multi_support() -> Result<bool> {
        Ok(inspect::parse_enum("bpf_attach_type", &[])?
            .values()
            .any(|variant| variant == "BPF_TRACE_KPROBE_MULTI"))
    }

    // Attach a set of kprobes in a single call, speeding up attaching time *a
    // lot*.
    fn attach_kprobe_multi(&mut self, probes: &[Probe]) -> Result<()> {
        let obj = match &mut self.skel {
            Some(skel) => skel.object(),
            _ => bail!("Kprobe builder is uninitialized"),
        };

        let mut targets = Vec::new();
        let mut ksyms = Vec::new();

        for probe in probes {
            let symbol = match probe.r#type() {
                ProbeType::Kprobe(probe) => &probe.symbol,
                _ => bail!("Wrong probe type {}", probe),
            };

            targets.push(symbol.attach_name());
            ksyms.push(symbol.addr()?);
        }

        let opts = KprobeMultiOpts {
            symbols: targets,
            cookies: ksyms,
            ..Default::default()
        };

        self.links.push(
            obj.progs_mut()
                .find(|p| p.name() == "probe_kprobe")
                .ok_or_else(|| anyhow!("Couldn't get program"))?
                .attach_kprobe_multi_with_opts(opts)?,
        );

        Ok(())
    }

    // Legacy way of attaching kprobes; one at a time.
    fn attach_kprobes(&mut self, probes: &[Probe]) -> Result<()> {
        let obj = match &mut self.skel {
            Some(skel) => skel.object(),
            _ => bail!("Kprobe builder is uninitialized"),
        };

        let prog = obj
            .progs_mut()
            .find(|p| p.name() == "probe_kprobe")
            .ok_or_else(|| anyhow!("Couldn't get program"))?;

        for probe in probes {
            let probe = match probe.r#type() {
                ProbeType::Kprobe(probe) => probe,
                _ => bail!("Wrong probe type {}", probe),
            };

            let opts = KprobeOpts {
                cookie: probe.symbol.addr()?,
                ..Default::default()
            };

            self.links.push(prog.attach_kprobe_with_opts(
                false,
                probe.symbol.attach_name(),
                opts,
            )?);
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use serial_test::serial;

    use super::*;

    use crate::core::{
        filters::{fixup_filter_load_fn, register_filter_handler},
        kernel::Symbol,
    };

    #[test]
    #[serial(libbpf)]
    #[cfg_attr(not(feature = "test_cap_bpf"), ignore)]
    fn init_and_attach() {
        let _ = register_filter_handler(
            "kprobe/probe",
            libbpf_rs::ProgramType::Kprobe,
            Some(fixup_filter_load_fn),
        );

        let mut builder = KprobeBuilder::new().unwrap();

        assert!(builder
            .init(Vec::new(), Vec::new(), Vec::new(), None)
            .is_ok());
        assert!(builder
            .add_probe(Probe::kprobe(Symbol::from_name("consume_skb").unwrap()).unwrap())
            .is_ok());
        assert!(builder.attach().is_ok());
    }
}
