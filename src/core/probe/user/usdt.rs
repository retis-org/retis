use std::os::fd::{AsFd, AsRawFd, RawFd};

use anyhow::{anyhow, bail, Result};
use libbpf_rs::skel::SkelBuilder;

use crate::core::filters::Filter;
use crate::core::probe::builder::*;
use crate::core::probe::{Hook, Probe, ProbeType};

mod usdt_bpf {
    include!("bpf/.out/usdt.skel.rs");
}
use usdt_bpf::UsdtSkelBuilder;

#[derive(Default)]
pub(crate) struct UsdtBuilder {
    links: Vec<libbpf_rs::Link>,
    obj: Option<libbpf_rs::Object>,
    map_fds: Vec<(String, RawFd)>,
    hooks: Vec<Hook>,
}

impl ProbeBuilder for UsdtBuilder {
    fn new() -> UsdtBuilder {
        UsdtBuilder::default()
    }

    fn init(
        &mut self,
        map_fds: Vec<(String, RawFd)>,
        hooks: Vec<Hook>,
        _filters: Vec<Filter>,
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

        let mut skel = UsdtSkelBuilder::default().open()?;
        skel.rodata_mut().log_level = log::max_level() as u8;
        let open_obj = skel.obj;
        reuse_map_fds(&open_obj, &self.map_fds)?;

        let mut obj = open_obj.load()?;
        let prog = obj
            .prog_mut("probe_usdt")
            .ok_or_else(|| anyhow!("Couldn't get program"))?;
        let mut links = replace_hooks(prog.as_fd().as_raw_fd(), &self.hooks)?;
        self.links.append(&mut links);

        self.links
            .push(prog.attach_usdt(probe.pid, &probe.path, &probe.provider, &probe.name)?);
        self.obj = Some(obj);

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
        assert!(builder.init(Vec::new(), Vec::new(), Vec::new()).is_ok());
        assert!(builder
            .attach(&Probe::usdt(UsdtProbe::new(&p, "test_builder::usdt").unwrap()).unwrap())
            .is_ok());
    }
}
