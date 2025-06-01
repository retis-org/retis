use std::os::fd::{AsFd, AsRawFd, RawFd};

use anyhow::{anyhow, bail, Result};
use libbpf_rs::skel::{OpenSkel, Skel};

use crate::core::{
    probe::{builder::*, Hook, Probe, ProbeType},
    workaround::*,
};

mod usdt_bpf {
    include!("bpf/.out/usdt.skel.rs");
}
use usdt_bpf::*;

#[derive(Default)]
pub(crate) struct UsdtBuilder<'a> {
    links: Vec<libbpf_rs::Link>,
    skel: Option<SkelStorage<UsdtSkel<'a>>>,
    map_fds: Vec<(String, RawFd)>,
    hooks: Vec<Hook>,
}

impl<'a> ProbeBuilder for UsdtBuilder<'a> {
    fn new() -> UsdtBuilder<'a> {
        UsdtBuilder::default()
    }

    fn init(
        &mut self,
        map_fds: Vec<(String, RawFd)>,
        hooks: Vec<Hook>,
        _ctx_hook: Option<Hook>,
    ) -> Result<()> {
        self.map_fds = map_fds;
        if hooks.len() > 1 {
            bail!("USDT Probes only support a single hook");
        }
        self.hooks = hooks;
        Ok(())
    }

    fn attach(&mut self, probe: &Probe) -> Result<()> {
        let probe = match probe.r#type() {
            ProbeType::Usdt(usdt) => usdt,
            _ => bail!("Wrong probe type"),
        };

        let mut skel = OpenSkelStorage::new::<UsdtSkelBuilder>()?;
        skel.maps.rodata_data.log_level = log::max_level() as u8;

        reuse_map_fds(skel.open_object_mut(), &self.map_fds)?;

        let skel = SkelStorage::load(skel)?;
        let prog = skel
            .object()
            .progs_mut()
            .find(|p| p.name() == "probe_usdt")
            .ok_or_else(|| anyhow!("Couldn't get program"))?;
        let mut links = replace_hooks(prog.as_fd().as_raw_fd(), &self.hooks)?;
        self.links.append(&mut links);

        self.links
            .push(prog.attach_usdt(probe.pid, &probe.path, &probe.provider, &probe.name)?);
        self.skel = Some(skel);

        Ok(())
    }

    fn detach(&mut self) -> Result<()> {
        self.links.drain(..);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use crate::core::{probe::user::UsdtProbe, user::proc::Process};

    use ::probe::probe as define_usdt;

    #[test]
    #[cfg_attr(not(feature = "test_cap_bpf"), ignore)]
    fn init_and_attach_usdt() {
        define_usdt!(test_builder, usdt, 1);

        let mut builder = UsdtBuilder::new();

        let p = Process::from_pid(std::process::id() as i32).unwrap();

        // It's for now, the probes below won't do much.
        assert!(builder.init(Vec::new(), Vec::new(), None).is_ok());
        assert!(builder
            .attach(&Probe::usdt(UsdtProbe::new(&p, "test_builder::usdt").unwrap()).unwrap())
            .is_ok());
    }
}
