//! # ProbeBuilder
//!
//! ProbeBuilder defines the ProbeBuider trait and some useful utility functions
//!
use std::{ffi::CString, ptr};

use anyhow::{anyhow, bail, Result};
use btf_rs::{Btf, Type};

use crate::core::{
    bpf_sys,
    filters::{BpfFilter, Filter},
    probe::*,
};

/// Trait representing the interface used to create and handle probes. We use a
/// trait here as we're supporting various attach types.
pub(super) trait ProbeBuilder {
    /// Allocate and return a new instance of the probe builder, with default
    /// values.
    fn new() -> Self
    where
        Self: Sized;
    /// Initialize the probe builder before attaching programs to probes. It
    /// takes an option vector of map fds so that maps can be reused and shared
    /// accross builders.
    fn init(
        &mut self,
        map_fds: Vec<(String, i32)>,
        hooks: Vec<Hook>,
        filters: Vec<Filter>,
    ) -> Result<()>;
    /// Attach a probe to a given target (function, tracepoint, etc).
    fn attach(&mut self, probe: &Probe) -> Result<()>;
}

pub(super) fn reuse_map_fds(
    open_obj: &libbpf_rs::OpenObject,
    map_fds: &[(String, i32)],
) -> Result<()> {
    for map in map_fds.iter() {
        if let Some(open_map) = open_obj.map(map.0.clone()) {
            open_map.reuse_fd(map.1)?;
        } else {
            // This object does not have this particular map.
            continue;
        }
    }
    Ok(())
}

/// Replaces raw bpf programs using both btf-rs and bpf_sys
/// facilities. This is currently needed because libbpf-rs doesn't
/// have loading nor replacing capabilities for non-ELF files.
fn replace_raw_filter(filter: &BpfFilter, target: &str, fd: u32) -> Result<()> {
    let btf_buff = bpf_sys::get_btf_from_fd(fd)?;
    let btf = Btf::from_bytes(&btf_buff)?;
    let tgt_btf_id = btf.resolve_id_by_name(target)?;

    match btf.resolve_type_by_id(tgt_btf_id)? {
        Type::Func(_) => (),
        _ => bail!("Resolved type is not a function"),
    }

    let btf_fd = bpf_sys::load_btf(crate::core::filters::packets::filter_stub::BTF)?;

    let btf = Btf::from_bytes(crate::core::filters::packets::filter_stub::BTF)?;
    let (func_info_rec, rec_size, rec_count) =
        bpf_sys::gen_dummy_func_info_rec(btf.resolve_id_by_name(target)?);

    let mut attrs: bpf_sys::bpf_attr = unsafe { std::mem::zeroed() };
    let load_attrs = unsafe { &mut attrs.__bindgen_anon_3 };

    load_attrs.prog_type = bpf_sys::bpf_prog_type::BPF_PROG_TYPE_EXT as u32;
    let prog_name = CString::new(format!("r_{}", target)).expect("new string for prog name failed");
    unsafe {
        ptr::copy_nonoverlapping(
            prog_name.as_ptr(),
            load_attrs.prog_name.as_mut_ptr(),
            load_attrs.prog_name.len(),
        )
    };

    let prog: &[u8] = &filter.0;
    load_attrs.insn_cnt = (prog.len() / 8) as u32;
    load_attrs.insns = prog.as_ptr() as u64;
    let license = CString::new("GPL").expect("new string for license failed");
    load_attrs.license = license.as_ptr() as u64;
    load_attrs.attach_btf_id = tgt_btf_id;
    load_attrs.__bindgen_anon_1.attach_prog_fd = fd;
    load_attrs.prog_btf_fd = btf_fd;
    load_attrs.func_info = &func_info_rec as *const _ as u64;
    load_attrs.func_info_rec_size = rec_size as u32;
    load_attrs.func_info_cnt = rec_count;

    let load_fd = bpf_sys::bpf(bpf_sys::bpf_cmd::BPF_PROG_LOAD, &attrs)?;
    let mut attrs: bpf_sys::bpf_attr = unsafe { std::mem::zeroed() };
    let link_attr = unsafe { &mut attrs.link_create };
    link_attr.prog_fd = load_fd;

    bpf_sys::bpf(bpf_sys::bpf_cmd::BPF_LINK_CREATE, &attrs)?;

    Ok(())
}

pub(super) fn replace_filters(fd: i32, filters: &[Filter]) -> Result<()> {
    for filter in filters.iter() {
        match filter {
            Filter::Packet(f) => replace_raw_filter(f, "packet_filter", fd as u32)?,
        }
    }

    Ok(())
}

pub(super) fn replace_hooks(fd: i32, hooks: &[Hook]) -> Result<Vec<libbpf_rs::Link>> {
    let mut links = Vec::new();

    for (i, hook) in hooks.iter().enumerate() {
        let target = format!("hook{i}");

        let mut open_obj =
            libbpf_rs::ObjectBuilder::default().open_memory("hook", hook.bpf_prog)?;

        // We have to explicitly use a Vec below to avoid having an unknown size
        // at build time.
        let map_fds: Vec<(String, i32)> = hook.maps.clone().into_iter().collect();
        reuse_map_fds(&open_obj, &map_fds)?;

        let open_prog = open_obj
            .prog_mut("hook")
            .ok_or_else(|| anyhow!("Couldn't get hook program"))?;

        open_prog.set_prog_type(libbpf_rs::ProgramType::Ext);
        open_prog.set_attach_target(fd, Some(target))?;

        let mut obj = open_obj.load()?;
        links.push(
            obj.prog_mut("hook")
                .ok_or_else(|| anyhow!("Couldn't get hook program"))?
                .attach_trace()?,
        );
    }
    Ok(links)
}
