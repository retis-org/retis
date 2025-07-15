//! # Kprobe
//!
//! Module to handle attaching programs to kernel probes. The module is split
//! in two parts, the Rust code (here) and the eBPF one (bpf/kprobe.bpf.c and
//! its auto-generated part in bpf/.out/).

use std::os::fd::{AsFd, AsRawFd, RawFd};

use anyhow::{anyhow, bail, Result};
use libbpf_rs::{
    skel::{OpenSkel, Skel},
    KprobeMultiOpts,
};

use crate::core::{inspect, probe::builder::*, probe::*, workaround::*};

mod kprobe_bpf {
    include!("bpf/.out/kprobe.skel.rs");
}
use kprobe_bpf::*;

#[derive(Default)]
pub(crate) struct KprobeBuilder<'a> {
    skel: Option<SkelStorage<KprobeSkel<'a>>>,
    // Use the compatibility mode, aka. older APIs, to support older kernels.
    compat: bool,
    kretprobe: bool,
    probes: Vec<Probe>,
    links: Vec<libbpf_rs::Link>,
}

impl<'a> ProbeBuilder for KprobeBuilder<'a> {
    fn new() -> Result<KprobeBuilder<'a>> {
        let compat = Self::check_compat()?;
        if compat {
            log::debug!("Kprobe builder using compat mode");
        }

        Ok(Self {
            compat,
            ..Default::default()
        })
    }

    fn init(
        &mut self,
        map_fds: Vec<(String, RawFd)>,
        hooks: Vec<Hook>,
        ctx_hook: Option<Hook>,
    ) -> Result<()> {
        if self.skel.is_some() {
            bail!("Kprobe builder already initialized");
        }

        let mut skel = OpenSkelStorage::new::<KprobeSkelBuilder>()?;

        let rodata = skel
            .maps
            .rodata_data
            .as_deref_mut()
            .ok_or_else(|| anyhow!("Can't access eBPF rodata: not memory mapped"))?;
        rodata.kretprobe = self.kretprobe;
        rodata.nhooks = hooks.len() as u32;
        rodata.log_level = log::max_level() as u8;

        reuse_map_fds(skel.open_object_mut(), &map_fds)?;

        if !self.compat {
            skel.open_object_mut()
                .progs_mut()
                .find(|p| p.name() == "probe_kprobe")
                .ok_or_else(|| anyhow!("Couldn't get program"))?
                .set_attach_type(libbpf_rs::ProgramAttachType::KprobeMulti);
            skel.open_object_mut()
                .progs_mut()
                .find(|p| p.name() == "probe_kretprobe")
                .ok_or_else(|| anyhow!("Couldn't get program"))?
                .set_attach_type(libbpf_rs::ProgramAttachType::KprobeMulti);
        }

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
        if self.probes.is_empty() {
            return Ok(());
        }

        match self.compat {
            false => self.attach_kprobe_multi(),
            true => self.attach_kprobes_no_cookie(),
        }
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

    /// Inspect the kprobe support in the running kernel, returning true if the
    /// compat' mode should be used.
    fn check_compat() -> Result<bool> {
        let multi = inspect::parse_enum("bpf_attach_type", &[])?
            .values()
            .any(|variant| variant == "BPF_TRACE_KPROBE_MULTI");
        let multi_cookies = inspect::parse_struct("bpf_kprobe_multi_link")?
            .iter()
            .any(|field| field == "cookies");

        Ok(!multi || !multi_cookies)
    }

    // Attach a set of kprobes in a single call, speeding up attaching time *a
    // lot*.
    fn attach_kprobe_multi(&mut self) -> Result<()> {
        let obj = match &mut self.skel {
            Some(skel) => skel.object(),
            _ => bail!("Kprobe builder is uninitialized"),
        };

        let prog = obj
            .progs_mut()
            .find(|p| p.name() == "probe_kprobe")
            .ok_or_else(|| anyhow!("Couldn't get program"))?;
        let prog_ret = match self.kretprobe {
            true => Some(
                obj.progs_mut()
                    .find(|p| p.name() == "probe_kretprobe")
                    .ok_or_else(|| anyhow!("Couldn't get kretprobe program"))?,
            ),
            false => None,
        };

        let mut targets = Vec::new();
        let mut ksyms = Vec::new();
        for probe in self.probes.drain(..) {
            let symbol = match probe.r#type() {
                ProbeType::Kprobe(probe) if !self.kretprobe => &probe.symbol,
                ProbeType::Kretprobe(probe) if self.kretprobe => &probe.symbol,
                _ => bail!("Wrong probe type {}", probe),
            };

            targets.push(symbol.attach_name());
            ksyms.push(symbol.addr()?);
        }

        let opts = KprobeMultiOpts {
            symbols: targets.clone(),
            cookies: ksyms,
            ..Default::default()
        };

        self.links.push(prog.attach_kprobe_multi_with_opts(opts)?);
        if let Some(ref prog_ret) = prog_ret {
            // No need to set the cookie in the kretprobe as the symbol address
            // is retrieved in the kprobe.
            self.links
                .push(prog_ret.attach_kprobe_multi(true, targets)?);
        }

        Ok(())
    }

    // Legacy way of attaching kprobes; one at a time, without cookies.
    fn attach_kprobes_no_cookie(&mut self) -> Result<()> {
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

        for probe in self.probes.drain(..) {
            let symbol = match probe.r#type() {
                ProbeType::Kprobe(probe) if !self.kretprobe => &probe.symbol,
                ProbeType::Kretprobe(probe) if self.kretprobe => &probe.symbol,
                _ => bail!("Wrong probe type {}", probe),
            };

            self.links
                .push(prog.attach_kprobe(false, symbol.attach_name())?);
            if let Some(ref prog_ret) = prog_ret {
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

        assert!(builder.init(Vec::new(), Vec::new(), None).is_ok());
        assert!(builder
            .add_probe(Probe::kprobe(Symbol::from_name("consume_skb").unwrap()).unwrap())
            .is_ok());
        assert!(builder.attach().is_ok());
    }
}
