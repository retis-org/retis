/// eBPF filter wrapper containing the sequence of bytes composing the eBPF program
use std::{collections::HashMap, sync::Mutex};

use anyhow::{bail, Result};
use log::{error, warn};
use once_cell::sync::Lazy;

use crate::{
    bindings::packet_filter_uapi,
    core::{
        bpf_sys,
        filters::packets::{
            ebpf::{eBpfProg, BpfReg},
            ebpfinsn::{eBpfInsn, MovInfo},
        },
        workaround,
    },
};

use super::meta::filter::FilterMeta;

#[derive(Clone)]
pub(crate) struct BpfFilter(pub(crate) Vec<u8>);

#[derive(Clone)]
pub(crate) enum Filter {
    Packet(packet_filter_uapi::filter_type, BpfFilter),
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

fn get_default_filter() -> Vec<u8> {
    let mut default_filter = eBpfProg::new();

    default_filter.add(eBpfInsn::mov32(MovInfo::Imm {
        dst: BpfReg::R0,
        imm: 0x40000_i32,
    }));

    default_filter.to_bytes()
}

fn retrieve_filter(code: u32) -> Vec<libbpf_sys::bpf_insn> {
    let f = if let Some(f) = get_filter(code) {
        match f {
            Filter::Packet(_, bf) => bf.0,
            _ => {
                warn!(
                    "Found invalid type while retrieving the filter, defaulting to match all ..."
                );
                get_default_filter()
            }
        }
    } else {
        get_default_filter()
    };

    let filter: &[libbpf_sys::bpf_insn] = unsafe {
        std::slice::from_raw_parts(
            f.as_slice().as_ptr() as *const libbpf_sys::bpf_insn,
            f.len() / std::mem::size_of::<libbpf_sys::bpf_insn>(),
        )
    };

    filter.to_vec()
}

fn copy_ptr_to_vec<T>(ptr: *mut T, count: usize) -> Vec<T> {
    let mut vec = Vec::with_capacity(count);
    unsafe {
        std::ptr::copy(ptr, vec.as_mut_ptr(), count);
        vec.set_len(count);
    }
    vec
}

// Rewrites the instructions, indexes all the pseudo calls, fixes
// them up along with the relevant .BTF.ext.
pub(crate) unsafe extern "C" fn fixup_filter_load_fn(
    prog: *mut libbpf_sys::bpf_program,
    opts: *mut libbpf_sys::bpf_prog_load_opts,
    _cookie: ::std::os::raw::c_long,
) -> std::os::raw::c_int {
    let filter_types = [packet_filter_uapi::L2, packet_filter_uapi::L3];
    let mut pseudo_calls: Vec<usize> = Vec::new();
    let mut placeholder_calls: Vec<(usize, _)> = Vec::new();

    let insns = unsafe {
        std::slice::from_raw_parts(
            libbpf_sys::bpf_program__insns(prog),
            libbpf_sys::bpf_program__insn_cnt(prog) as usize,
        )
    };

    for (pos, insn) in insns.iter().enumerate() {
        let imm = insn.imm as u32;

        // 0xBAD2310 is used to mark the instructions that failed
        // relocation, e.g.:
        // libbpf: prog 'hook': relo #1: no matching targets found
        // libbpf: prog 'hook': relo #1: substituting insn #55 w/ invalid insn
        // this is skipped as this is intended and handled.
        if insn.code != (bpf_sys::BPF_JMP | bpf_sys::BPF_CALL) || imm == 0xBAD2310 {
            continue;
        }

        if insn.src_reg() == bpf_sys::BPF_PSEUDO_CALL {
            pseudo_calls.push(pos);
            continue;
        }

        if filter_types.contains(&imm) {
            placeholder_calls.push((pos, imm));
        }
    }

    let mut prog_ext = insns.to_vec();

    let func_info_rp = (*opts).func_info as *mut libbpf_sys::bpf_func_info;
    let func_info_orig = copy_ptr_to_vec(
        (*opts).func_info as *mut libbpf_sys::bpf_func_info,
        (*opts).func_info_cnt as usize,
    );

    let line_info_rp = (*opts).line_info as *mut libbpf_sys::bpf_line_info;
    let line_info_orig = copy_ptr_to_vec(
        (*opts).line_info as *mut libbpf_sys::bpf_line_info,
        (*opts).line_info_cnt as usize,
    );

    let mut filters = HashMap::new();
    for placeholder in placeholder_calls.iter() {
        let filter = retrieve_filter(placeholder.1);
        let fixup_len = filter.len() as i32 - 1;
        if filters.insert(placeholder.1, filter).is_some() {
            error!(
                "error while fixing up instructions: found duplicate {:#x} at {}",
                placeholder.1, placeholder.0
            );
            return -1;
        }

        // Fixup subprogram calls
        for c in pseudo_calls.iter() {
            if *c < placeholder.0 && *c as i32 + insns[*c].imm > placeholder.0 as i32 {
                prog_ext[*c].imm += fixup_len;
            } else if *c > placeholder.0 && *c as i32 + insns[*c].imm < placeholder.0 as i32 {
                prog_ext[*c].imm -= fixup_len;
            }
        }

        for (pos, func_info) in func_info_orig.iter().enumerate() {
            unsafe {
                if func_info.insn_off > placeholder.0 as u32 {
                    let finfo = func_info_rp.add(pos);
                    (*finfo).insn_off += fixup_len as u32;
                }
            }
        }

        for (pos, line_info) in line_info_orig.iter().enumerate() {
            unsafe {
                if line_info.insn_off > placeholder.0 as u32 {
                    let linfo = line_info_rp.add(pos);
                    (*linfo).insn_off += fixup_len as u32;
                }
            }
        }
    }

    // Finally inject the filters
    // placeholder_calls is sorted, so proceed backward to avoid
    // further adjustment.
    for placeholder in placeholder_calls.iter().rev() {
        let filter = if let Some(f) = filters.remove(&placeholder.1) {
            f
        } else {
            error!("cannot match filter while inject");
            return -1;
        };

        prog_ext.splice(placeholder.0..placeholder.0 + 1, filter);
    }

    let ret = libbpf_sys::bpf_program__set_insns(
        prog,
        prog_ext.as_mut_slice().as_mut_ptr(),
        prog_ext.len() as u64,
    );

    if ret != 0 {
        error!("unable to inline filters ({ret})");
        return ret;
    }

    0
}
