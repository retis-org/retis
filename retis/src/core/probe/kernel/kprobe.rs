//! # Kprobe
//!
//! Module to handle attaching programs to kernel probes. The module is split
//! in two parts, the Rust code (here) and the eBPF one (bpf/kprobe.bpf.c and
//! its auto-generated part in bpf/.out/).

use std::os::fd::{AsFd, AsRawFd, RawFd};

use anyhow::{anyhow, bail, Result};
use libbpf_rs::{
    skel::{OpenSkel, Skel},
    KprobeOpts,
};

use crate::core::{filters::Filter, inspect, probe::builder::*, probe::*, workaround::*};

mod kprobe_bpf {
    include!("bpf/.out/kprobe.skel.rs");
}
use kprobe_bpf::*;

enum KprobeVariant {
    Kprobe,
    KprobeNoCookie,
}

impl Default for KprobeVariant {
    fn default() -> Self {
        Self::KprobeNoCookie
    }
}

#[derive(Default)]
pub(crate) struct KprobeBuilder<'a> {
    skel: Option<SkelStorage<KprobeSkel<'a>>>,
    variant: KprobeVariant,
    kretprobe: bool,
    probes: Vec<Probe>,
    links: Vec<libbpf_rs::Link>,
}

impl<'a> ProbeBuilder for KprobeBuilder<'a> {
    fn new() -> Result<KprobeBuilder<'a>> {
        let variant = Self::inspect_variant()?;
        log::debug!(
            "Kprobe builder {} support",
            match variant {
                KprobeVariant::Kprobe => "with cookie",
                KprobeVariant::KprobeNoCookie => "without cookie",
            }
        );

        Ok(Self {
            variant,
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

        skel.maps.rodata_data.kretprobe = self.kretprobe;
        skel.maps.rodata_data.nhooks = hooks.len() as u32;
        skel.maps.rodata_data.log_level = log::max_level() as u8;

        filters.iter().for_each(|f| {
            if let Filter::Meta(m) = f {
                skel.maps.rodata_data.nmeta = m.0.len() as u32
            }
        });

        reuse_map_fds(skel.open_object_mut(), &map_fds)?;

        let skel = SkelStorage::load(skel)?;
        let fd = skel
            .object()
            .progs()
            .find(|p| {
                p.name()
                    == if !self.kretprobe {
                        "probe_kprobe"
                    } else {
                        "probe_kretprobe"
                    }
            })
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
        let tmp = std::mem::take(&mut self.probes);

        use KprobeVariant::*;
        match self.variant {
            Kprobe => self.attach_kprobes(&tmp, true)?,
            KprobeNoCookie => self.attach_kprobes(&tmp, false)?,
        }

        Ok(())
    }

    fn detach(&mut self) -> Result<()> {
        self.links.drain(..);
        Ok(())
    }
}

impl KprobeBuilder<'_> {
    pub(crate) fn kretprobe(mut self) -> Self {
        self.kretprobe = true;
        self
    }

    /// Inspect the kprobe variant supported by the running kernel.
    fn inspect_variant() -> Result<KprobeVariant> {
        use KprobeVariant::*;

        Ok(
            match inspect::parse_struct("bpf_trace_run_ctx")?
                .iter()
                .any(|field| field == "bpf_cookie")
            {
                true => Kprobe,
                false => KprobeNoCookie,
            },
        )
    }

    fn attach_kprobes(&mut self, probes: &[Probe], cookie: bool) -> Result<()> {
        let obj = match &mut self.skel {
            Some(skel) => skel.object(),
            _ => bail!("Kprobe builder is uninitialized"),
        };

        let prog = obj
            .progs_mut()
            .find(|p| p.name() == "probe_kprobe")
            .ok_or_else(|| anyhow!("Couldn't get kprobe program"))?;
        let prog_ret = match self.kretprobe {
            true => Some(
                obj.progs_mut()
                    .find(|p| p.name() == "probe_kretprobe")
                    .ok_or_else(|| anyhow!("Couldn't get kretprobe program"))?,
            ),
            false => None,
        };

        for probe in probes {
            let symbol = match probe.r#type() {
                ProbeType::Kprobe(probe) if !self.kretprobe => &probe.symbol,
                ProbeType::Kretprobe(probe) if self.kretprobe => &probe.symbol,
                _ => bail!("Wrong probe type {}", probe),
            };

            if cookie {
                let opts = KprobeOpts {
                    cookie: symbol.addr()?,
                    ..Default::default()
                };

                self.links
                    .push(prog.attach_kprobe_with_opts(false, symbol.attach_name(), opts)?);
            } else {
                self.links
                    .push(prog.attach_kprobe(false, symbol.attach_name())?);
            }

            if let Some(ref prog_ret) = prog_ret {
                // No need to set the cookie in the kretprobe as the symbol
                // address is retrieved in the kprobe.
                self.links
                    .push(prog_ret.attach_kprobe(true, symbol.attach_name())?);
            }
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
