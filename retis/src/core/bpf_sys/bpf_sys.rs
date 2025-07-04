#![allow(dead_code)]

use std::io::{Error, Result};
use std::mem;
use std::os::raw::c_long;

// Embed in a mod to skip the linter
mod bpf_gen {
    #![allow(non_upper_case_globals)]
    #![allow(non_camel_case_types)]
    #![allow(non_snake_case)]
    // Clippy warns for code generated by bindgen,
    // skip it for this module
    #![allow(clippy::all)]
    include!(concat!(env!("OUT_DIR"), "/bpf_gen.rs"));
}

pub(crate) use bpf_gen::*;

fn bpf_sys(cmd: bpf_gen::bpf_cmd, attr: &bpf_gen::bpf_attr, size: u32) -> c_long {
    unsafe { libc::syscall(libc::SYS_bpf, cmd, attr, size) }
}

pub(crate) fn bpf(cmd: bpf_gen::bpf_cmd, attr: &bpf_gen::bpf_attr) -> Result<u32> {
    let r = bpf_sys(cmd, attr, mem::size_of::<bpf_gen::bpf_attr>() as u32);
    if r < 0 {
        return Err(Error::last_os_error());
    }

    Ok(r as u32)
}

pub(crate) fn bpf_unload(fd: u32) -> Result<()> {
    let r = unsafe { libc::close(fd as libc::c_int) };
    if r < 0 {
        return Err(Error::last_os_error());
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use std::ffi::CString;
    use std::{ptr, str};

    use super::*;
    use crate::core::filters::packets::{bpf_common::*, ebpf::*, ebpfinsn::*};

    const LOG_SIZE: usize = 64 * 1024;
    const INSN_SIZE: usize = 8;

    #[test]
    #[cfg_attr(not(feature = "test_cap_bpf"), ignore)]
    fn load_xdp_insns() {
        let log_buff: [u8; LOG_SIZE] = [0; LOG_SIZE];

        // The bytecode below was generated from the following:
        // int xdp_prog(struct xdp_md *ctx)
        // {
        //     if (!ctx)
        //         return XDP_PASS;
        //
        //     if ((__u16 *)ctx->data + 1 > (__u16 *)ctx->data_end)
        //         return XDP_PASS;
        //
        //     __u16 *data = (void *)(long)ctx->data;
        //     if (*data == 0xaaaa) {
        //         *data = 0xffff;
        //     }
        //
        //     return XDP_PASS;
        // }
        let mut ebpf = eBpfProg::new();

        ebpf.add(eBpfInsn::jmp(
            eBpfJmpOpExt::Bpf(BpfJmpOp::Eq),
            JmpInfo::Imm {
                dst: BpfReg::R1,
                off: 9,
                imm: 0,
            },
        ));
        ebpf.add(eBpfInsn::ld(
            LdInfo::Reg {
                src: BpfReg::R1,
                dst: BpfReg::R2,
                off: 4,
            },
            BpfSize::Word,
        ));
        ebpf.add(eBpfInsn::ld(
            LdInfo::Reg {
                src: BpfReg::R1,
                dst: BpfReg::R1,
                off: 0,
            },
            BpfSize::Word,
        ));
        ebpf.add(eBpfInsn::mov(MovInfo::Reg {
            src: BpfReg::R1,
            dst: BpfReg::R3,
        }));
        ebpf.add(eBpfInsn::alu(
            BpfAluOp::Add,
            AluInfo::Imm {
                dst: BpfReg::R3,
                imm: 2,
            },
        ));
        ebpf.add(eBpfInsn::jmp(
            eBpfJmpOpExt::Bpf(BpfJmpOp::Gt),
            JmpInfo::Reg {
                src: BpfReg::R2,
                dst: BpfReg::R3,
                off: 4,
            },
        ));
        ebpf.add(eBpfInsn::ld(
            LdInfo::Reg {
                src: BpfReg::R1,
                dst: BpfReg::R2,
                off: 0,
            },
            BpfSize::Half,
        ));
        ebpf.add(eBpfInsn::jmp(
            eBpfJmpOpExt::eBpf(eBpfJmpOp::Ne),
            JmpInfo::Imm {
                dst: BpfReg::R2,
                off: 2,
                imm: 0xaaaa,
            },
        ));
        ebpf.add(eBpfInsn::mov(MovInfo::Imm {
            dst: BpfReg::R2,
            imm: 0xffff,
        }));
        ebpf.add(eBpfInsn::st(
            StInfo::Reg {
                src: BpfReg::R2,
                dst: BpfReg::R1,
                off: 0,
            },
            BpfSize::Half,
        ));
        ebpf.add(eBpfInsn::mov(MovInfo::Imm {
            dst: BpfReg::R0,
            imm: 2,
        }));
        ebpf.add(eBpfInsn::exit());

        let prog = ebpf.to_bytes();
        let mut attrs: bpf_gen::bpf_attr = unsafe { std::mem::zeroed() };
        let load_attrs = unsafe { &mut attrs.__bindgen_anon_3 };

        load_attrs.prog_type = bpf_gen::bpf_prog_type::BPF_PROG_TYPE_XDP as u32;

        let prog_name = CString::new("xdp_simple").expect("new string for prog name failed");
        unsafe {
            ptr::copy_nonoverlapping(
                prog_name.as_ptr(),
                load_attrs.prog_name.as_mut_ptr(),
                load_attrs.prog_name.len(),
            )
        };
        load_attrs.insns = prog.as_ptr() as u64;
        load_attrs.insn_cnt = (prog.len() / INSN_SIZE) as u32;
        let license = CString::new("GPL").expect("new string for license failed");
        load_attrs.license = license.as_ptr() as u64;
        load_attrs.log_level = 2;
        load_attrs.log_buf = log_buff.as_ptr() as u64;
        load_attrs.log_size = LOG_SIZE as u32;

        let res = bpf(bpf_gen::bpf_cmd::BPF_PROG_LOAD, &attrs);
        println!("{}", str::from_utf8(&log_buff).unwrap());

        assert!(res.is_ok());

        let fd = res.unwrap();
        const DATA_SZ: usize = 2;

        let data_in: [u8; DATA_SZ] = [0xaa, 0xaa];
        let data_out: [u8; DATA_SZ] = [0; 2];

        attrs = unsafe { std::mem::zeroed() };
        let test_attrs = unsafe { &mut attrs.test };

        test_attrs.data_in = data_in.as_ptr() as u64;
        test_attrs.data_size_in = data_in.len() as u32;
        test_attrs.data_out = data_out.as_ptr() as u64;
        test_attrs.data_size_out = data_out.len() as u32;
        test_attrs.prog_fd = fd;

        assert!(bpf(bpf_gen::bpf_cmd::BPF_PROG_TEST_RUN, &attrs).is_ok());
        assert_eq!(u16::from_ne_bytes(data_out), 0xffff);

        bpf_unload(fd).expect("failed to unload bpf program");
    }
}
