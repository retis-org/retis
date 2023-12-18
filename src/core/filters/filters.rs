/// eBPF filter wrapper containing the sequence of bytes composing the eBPF program
use std::{collections::HashMap, sync::Mutex};

use anyhow::{bail, Result};
use log::{debug, error};
use once_cell::sync::Lazy;

use crate::core::{
    bpf_sys,
    filters::packets::{
        ebpf::{eBpfProg, BpfReg},
        ebpfinsn::{eBpfInsn, MovInfo},
    },
    workaround,
};

use super::{meta::filter::FilterMeta, packets::filter::FilterPacketType};

#[derive(Clone)]
pub(crate) struct BpfFilter(pub(crate) Vec<u8>);

#[derive(Clone)]
pub(crate) enum Filter {
    Packet(FilterPacketType, BpfFilter),
    Meta(FilterMeta),
}

static FM: Lazy<Mutex<HashMap<u32, Filter>>> = Lazy::new(|| Mutex::new(HashMap::new()));

pub(crate) fn register_filter(r#type: u32, filter: &Filter) -> Result<()> {
    if FM.lock().unwrap().insert(r#type, filter.clone()).is_some() {
        bail!("Filter (k: {}) already registered", r#type);
    }
    Ok(())
}

pub(crate) fn get_filter(r#type: u32) -> Option<Filter> {
    FM.lock().unwrap().get(&r#type).cloned()
}

pub(crate) fn register_filter_handler(
    sec: &str,
    prog_type: libbpf_rs::ProgramType,
    func: libbpf_sys::libbpf_prog_prepare_load_fn_t,
) -> Result<()> {
    let opts = workaround::ProgHandlerOpts {
        prepare_load_fn: func,
        ..Default::default()
    };
    workaround::register_prog_handler(
        Some(sec.to_string()),
        prog_type,
        libbpf_rs::ProgramAttachType::CgroupInetIngress,
        opts,
    )?;

    Ok(())
}

pub(crate) unsafe extern "C" fn fixup_filter_load_fn(
    prog: *mut libbpf_sys::bpf_program,
    _opts: *mut libbpf_sys::bpf_prog_load_opts,
    _cookie: ::std::os::raw::c_long,
) -> std::os::raw::c_int {
    for magic in [FilterPacketType::L2 as u32, FilterPacketType::L3 as u32] {
        let filter = get_filter(magic);

        let f = if let Some(f) = filter {
            match f {
                Filter::Packet(_, bf) => bf.0,
                // fail if non packet filter is encountered
                _ => return -1,
            }
        } else {
            let mut default_filter = eBpfProg::new();
            default_filter.add(eBpfInsn::mov32(MovInfo::Imm {
                dst: BpfReg::R0,
                imm: 0x40000_i32,
            }));
            default_filter.to_bytes()
        };

        let filter: &[libbpf_sys::bpf_insn] = unsafe {
            std::slice::from_raw_parts(
                f.as_slice().as_ptr() as *const libbpf_sys::bpf_insn,
                f.len() / std::mem::size_of::<libbpf_sys::bpf_insn>(),
            )
        };

        let (insns, insns_cnt) = unsafe {
            (
                libbpf_sys::bpf_program__insns(prog),
                libbpf_sys::bpf_program__insn_cnt(prog),
            )
        };

        let insns = unsafe { std::slice::from_raw_parts(insns, insns_cnt as usize) };
        let mut prog_ext = insns.to_vec().clone();

        let inject_pos = match prog_ext.iter().enumerate().find_map(|(pos, insn)| {
            (insn.code == (bpf_sys::BPF_JMP | bpf_sys::BPF_CALL) && insn.imm == magic as i32)
                .then_some(pos)
        }) {
            Some(p) => p,
            None => {
                let none;
                let prog_name = unsafe { libbpf_sys::bpf_program__name(prog) };
                let prog_name = if prog_name.is_null() {
                    none = String::from("[none]");
                    &none
                } else {
                    unsafe { std::ffi::CStr::from_ptr(prog_name) }
                        .to_str()
                        .unwrap()
                };

                debug!("No inline position found for {}", prog_name);
                // Always succeed as probes may not require filtering at all.
                return 0;
            }
        };

        prog_ext.splice(inject_pos..inject_pos + filter.len(), filter.to_vec());

        let ret = libbpf_sys::bpf_program__set_insns(
            prog,
            prog_ext.as_mut_slice().as_mut_ptr(),
            prog_ext.len() as u64,
        );

        if ret != 0 {
            error!("unable to inline filter with magic {:#x} ({ret})", magic);
            return ret;
        }
    }

    0
}
