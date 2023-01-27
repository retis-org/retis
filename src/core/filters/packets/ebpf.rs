// The cBPF to eBPF conversion functions are inspired and partially
// based on bpf_convert_filter() in the Linux kernel sources:
//
// """
// SPDX-License-Identifier: GPL-2.0-or-later
//
// Linux Socket Filter - Kernel level socket filtering
//
// Based on the design of the Berkeley Packet Filter. The new
// internal format has been designed by PLUMgrid:
//
//	Copyright (c) 2011 - 2014 PLUMgrid, http://plumgrid.com
//
//  Authors:
//
//  Jay Schulist <jschlst@samba.org>
//  Alexei Starovoitov <ast@plumgrid.com>
//  Daniel Borkmann <dborkman@redhat.com>
//
//  Andi Kleen - Fix a few bad bugs and races.
//  Kris Katterjohn - Added many additional checks in bpf_check_classic()
// """

//! # eBpfProg
//!
//! eBpfProg contains multiple instances of eBpfInsn. eBpfProg could
//! be created from BpfProg objects.
//! For details related to the instructions, registers and calling conventions, see:
//! https://www.kernel.org/doc/html/latest/bpf/instruction-set.html#ebpf-instruction-set-specification-v1-0

#![allow(dead_code, non_camel_case_types)]
use std::convert::TryFrom;

use anyhow::{anyhow, bail, Result};
use memoffset::offset_of;
#[cfg(feature = "debug")]
use rbpf::disassembler::disassemble;

use crate::core::{
    bpf_sys,
    filters::packets::{
        bpf_common::*,
        cbpf::{BpfInsn, BpfProg},
        ebpfinsn::*,
    },
};

#[derive(Clone, Copy)]
#[repr(u8)]
pub(crate) enum BpfReg {
    R0 = bpf_sys::BPF_REG_0 as u8, // mapped to reg A
    R1 = bpf_sys::BPF_REG_1 as u8,
    R2 = bpf_sys::BPF_REG_2 as u8,
    R3 = bpf_sys::BPF_REG_3 as u8,
    R4 = bpf_sys::BPF_REG_4 as u8,
    R5 = bpf_sys::BPF_REG_5 as u8,
    R6 = bpf_sys::BPF_REG_6 as u8,   // points to ctx
    R7 = bpf_sys::BPF_REG_7 as u8,   // mapped to reg X
    R8 = bpf_sys::BPF_REG_8 as u8,   // points to ctx->data
    R9 = bpf_sys::BPF_REG_9 as u8,   // used as scratch
    R10 = bpf_sys::BPF_REG_10 as u8, // Frame pointer
}

impl BpfReg {
    pub const A: Self = Self::R0;
    pub const ARG1: Self = Self::R1;
    pub const ARG2: Self = Self::R2;
    pub const ARG3: Self = Self::R3;
    pub const CTX: Self = Self::R6;
    pub const X: Self = Self::R7;
    pub const CTXDATA: Self = Self::R8;
    pub const SCRATCH: Self = Self::R9;
    pub const FP: Self = Self::R10;
}

const STACK_RESERVED: i16 = 8;
// Start of stack memory store
const SCRATCH_MEM_START: i16 = 16 * 4 + STACK_RESERVED;

// This should be kept in sync with struct retis_filter_context in
// src/core/filter/packets/bpf/include/packet-filter.h
#[repr(C, packed)]
struct retis_filter_ctx {
    data: *mut i8,
    len: u32,
    ret: u32,
}

#[derive(Clone, Default)]
pub(crate) struct eBpfProg(Vec<eBpfInsn>);

impl eBpfProg {
    pub(crate) fn add(&mut self, insn: eBpfInsn) {
        self.0.push(insn);
    }

    pub(crate) fn to_bytes(&self) -> Vec<u8> {
        self.0.iter().flat_map(|insn| insn.to_vec()).collect()
    }

    #[cfg(feature = "debug")]
    pub(crate) fn disasm(&self) {
        disassemble(&self.to_bytes());
    }

    fn new() -> Self {
        Default::default()
    }

    // Generates the equivalent of the following pseudo asm:
    //
    // cmp %reg, $val
    // JMP 1f ; JMP = eq ? jne : je
    // mov $0, %r0
    // ret
    // 1:
    // ...
    //
    // Do NOT use if ctx->ret has been previously set.
    // Only intended for early exit.
    fn exit_if_reg_imm(&mut self, reg: BpfReg, val: i32, eq: bool) {
        let j_type = match eq {
            true => eBpfJmpOpExt::Ne,
            false => eBpfJmpOpExt::Bpf(BpfJmpOp::Eq),
        };

        self.add(eBpfInsn::jmp(
            j_type,
            JmpInfo::Imm {
                dst: reg,
                off: 2,
                imm: val,
            },
        ));
        self.add(eBpfInsn::mov(MovInfo::Imm {
            dst: BpfReg::A,
            imm: 0,
        }));
        self.add(eBpfInsn::exit());
    }

    fn exit_retval_eq(&mut self, rval: i32) {
        self.exit_if_reg_imm(BpfReg::A, rval, true);
    }

    fn exit_retval_neq(&mut self, rval: i32) {
        self.exit_if_reg_imm(BpfReg::A, rval, false);
    }

    fn size_to_bytes(size: BpfSize) -> i32 {
        match size {
            BpfSize::Byte => 1,
            BpfSize::Half => 2,
            BpfSize::Word => 4,
            BpfSize::Double => 8,
        }
    }

    /// Loads size bytes data from ctx->data at offset using the helper
    /// probe_read_kernel(). arg1, arg2 and arg3 are set accordingly
    /// in order to follow the eBPF calling convension specified in
    /// the link in the head of this file.
    fn load_data(&mut self, off: i32, size: BpfSize, ir: Option<BpfReg>) -> Result<()> {
        use self::eBpfInsn as Insn;

        // mov %fp, %arg1
        self.add(Insn::mov(MovInfo::Reg {
            src: BpfReg::FP,
            dst: BpfReg::ARG1,
        }));
        // add -8, %arg1
        self.add(Insn::alu(
            BpfAluOp::Add,
            AluInfo::Imm {
                dst: BpfReg::ARG1,
                imm: -STACK_RESERVED as i32,
            },
        ));
        // mov size, %arg2
        self.add(Insn::mov(MovInfo::Imm {
            dst: BpfReg::ARG2,
            imm: Self::size_to_bytes(size),
        }));
        // mov %reg8, %arg3 ; move data pointer to arg3
        self.add(Insn::mov(MovInfo::Reg {
            src: BpfReg::CTXDATA,
            dst: BpfReg::ARG3,
        }));
        // add offset, %arg3
        self.add(Insn::alu(
            BpfAluOp::Add,
            AluInfo::Imm {
                dst: BpfReg::ARG3,
                imm: off,
            },
        ));
        if let Some(reg) = ir {
            // add %X, %r3
            self.add(Insn::alu(
                BpfAluOp::Add,
                AluInfo::Reg {
                    src: reg,
                    dst: BpfReg::ARG3,
                },
            ));
        }
        // call probe_read_kernel
        self.add(Insn::call(
            bpf_sys::bpf_func_id::BPF_FUNC_probe_read_kernel as u32,
        ));
        // je 0, pc+1
        // ret false
        self.exit_retval_neq(0);
        // ldx -STACK_RESERVED(%r10), %r0
        self.add(Insn::ld(
            LdInfo::Reg {
                src: BpfReg::FP,
                dst: BpfReg::A,
                off: -STACK_RESERVED,
            },
            size,
        ));

        // endian %reg_a ; if bpf_size(op) > bpf_sys::BPF_B;
        match size {
            BpfSize::Half => self.add(Insn::endian16(BpfReg::A, EndianType::Be)),
            BpfSize::Word => self.add(Insn::endian32(BpfReg::A, EndianType::Be)),
            _ => (),
        }

        Ok(())
    }

    /// Prepare to return. If reg selector is set, the value of R0 (A
    /// reg) will be stored ctx->ret, otherwise an immediate value
    /// will be set.
    fn prepare_ret(&mut self, insn: &BpfInsn, reg: bool) -> Result<()> {
        // FIXME: This should handle options and return in A for the
        // common case. Tracepoint are the exception, and in such case
        // we return in ctx->ret as, for what it seems to be an issue,
        // the retval of the freplacing function cannot be a value
        // other than 0
        if reg {
            self.add(eBpfInsn::mov(MovInfo::Reg {
                src: BpfReg::A,
                dst: BpfReg::SCRATCH,
            }));
        } else {
            self.add(eBpfInsn::mov(MovInfo::Imm {
                dst: BpfReg::SCRATCH,
                imm: insn.k as i32,
            }));
        }

        self.add(eBpfInsn::st(
            StInfo::Reg {
                src: BpfReg::SCRATCH,
                dst: BpfReg::CTX,
                off: i16::try_from(offset_of!(retis_filter_ctx, ret))?,
            },
            BpfSize::Word,
        ));

        self.add(eBpfInsn::mov(MovInfo::Imm {
            dst: BpfReg::A,
            imm: 0x00000,
        }));
        Ok(())
    }

    fn jmp_jt_jf(
        &mut self,
        bpf_insn: &BpfInsn,
        op: BpfJmpOp,
        reg: bool,
        true_branch: bool,
    ) -> Result<bool> {
        let offset: i16;
        let mut ret = true;

        if true_branch {
            offset = (bpf_insn.jt + 1) as i16;
            if bpf_insn.jt == 0 {
                ret = false;
            }

            let jmp_spec = if reg {
                JmpInfo::Reg {
                    src: BpfReg::X,
                    dst: BpfReg::A,
                    off: offset,
                }
            } else {
                JmpInfo::Imm {
                    dst: BpfReg::A,
                    off: offset,
                    imm: bpf_insn.k as i32,
                }
            };

            self.add(eBpfInsn::jmp32(eBpfJmpOpExt::Bpf(op), jmp_spec));
        } else {
            offset = (bpf_insn.jf + 1) as i16;
            if bpf_insn.jf == 0 {
                return Ok(false);
            }

            self.add(eBpfInsn::jmp_a(offset));
        }

        Ok(ret)
    }
}

impl TryFrom<BpfProg> for eBpfProg {
    type Error = anyhow::Error;

    fn try_from(cbpf: BpfProg) -> Result<Self> {
        use self::eBpfInsn as Insn;

        let mut ebpf = Self::new();
        // maps cbpf pc to ebpf pc. Every cbpf insn corresponds to the
        // first ebpf insn in the converted block
        let mut insns_map: Vec<usize> = Vec::new();
        let mut jmps_map: Vec<(usize, usize)> = Vec::new();

        if cbpf.prog.is_empty() {
            bail!("Failed to convert filter: program is empty")
        }

        // if (!ctx) return 0;
        ebpf.exit_if_reg_imm(BpfReg::ARG1, 0, true);

        // mov ctx in %CTX
        ebpf.add(Insn::mov(MovInfo::Reg {
            src: BpfReg::ARG1,
            dst: BpfReg::CTX,
        }));

        ebpf.add(Insn::ld(
            LdInfo::Reg {
                src: BpfReg::CTX,
                dst: BpfReg::CTXDATA,
                off: i16::try_from(offset_of!(retis_filter_ctx, data))?,
            },
            BpfSize::Double,
        ));

        // if (!ctx->data) return 0;
        ebpf.exit_if_reg_imm(BpfReg::CTXDATA, 0, true);

        for (cbpf_pos, cbpf_insn) in cbpf.prog.iter().enumerate() {
            insns_map.push(ebpf.0.len());

            match cbpf_insn.insn_type()? {
                BpfInsnType::AluK(s) => ebpf.add(Insn::alu(
                    s,
                    AluInfo::Imm {
                        dst: BpfReg::A,
                        imm: cbpf_insn.k as i32,
                    },
                )),
                BpfInsnType::AluX(s) => ebpf.add(Insn::alu(
                    s,
                    AluInfo::Reg {
                        src: BpfReg::X,
                        dst: BpfReg::A,
                    },
                )),
                BpfInsnType::AluNeg(s) => ebpf.add(Insn::alu(
                    s,
                    AluInfo::Reg {
                        src: BpfReg::A,
                        dst: BpfReg::A,
                    },
                )),
                t @ BpfInsnType::LdxMem | t @ BpfInsnType::LdMem => ebpf.add(Insn::ld(
                    LdInfo::Reg {
                        src: BpfReg::FP,
                        dst: if let BpfInsnType::LdMem = t {
                            BpfReg::A
                        } else {
                            BpfReg::X
                        },
                        off: -SCRATCH_MEM_START + cbpf_insn.k as i16,
                    },
                    BpfSize::Word,
                )),
                t @ BpfInsnType::LdxImm | t @ BpfInsnType::LdImm => {
                    ebpf.add(Insn::mov32(MovInfo::Imm {
                        dst: if let BpfInsnType::LdImm = t {
                            BpfReg::A
                        } else {
                            BpfReg::X
                        },
                        imm: cbpf_insn.k as i32,
                    }))
                }
                t @ BpfInsnType::LdAbs(s) | t @ BpfInsnType::LdInd(s) => {
                    let ir = if let BpfInsnType::LdInd(_) = t {
                        Some(BpfReg::X)
                    } else {
                        None
                    };

                    ebpf.load_data(cbpf_insn.k as i32, s, ir)?;
                }
                BpfInsnType::LdxMsh => {
                    ebpf.load_data(cbpf_insn.k as i32, BpfSize::Byte, None)?;
                    ebpf.add(Insn::mov32(MovInfo::Reg {
                        src: BpfReg::A,
                        dst: BpfReg::X,
                    }));
                    ebpf.add(Insn::alu32(
                        BpfAluOp::And,
                        AluInfo::Imm {
                            dst: BpfReg::X,
                            imm: 0x0f,
                        },
                    ));
                    ebpf.add(Insn::alu32(
                        BpfAluOp::Lsh,
                        AluInfo::Imm {
                            dst: BpfReg::X,
                            imm: 2,
                        },
                    ));
                }
                t @ BpfInsnType::LdLen | t @ BpfInsnType::LdxLen => {
                    ebpf.add(Insn::ld(
                        LdInfo::Reg {
                            src: BpfReg::CTX,
                            dst: if let BpfInsnType::LdLen = t {
                                BpfReg::A
                            } else {
                                BpfReg::X
                            },
                            off: i16::try_from(offset_of!(retis_filter_ctx, len))?,
                        },
                        BpfSize::Word,
                    ));
                }
                BpfInsnType::JmpA => {
                    ebpf.add(Insn::jmp_a(cbpf_insn.k as i16));
                    jmps_map.push((cbpf_pos, ebpf.0.len() - 1));
                }
                t @ BpfInsnType::JmpX(s) | t @ BpfInsnType::JmpK(s) => {
                    let reg_jmp = BpfInsnType::JmpX(s) == t;

                    if ebpf.jmp_jt_jf(cbpf_insn, s, reg_jmp, true)? {
                        jmps_map.push((cbpf_pos, ebpf.0.len() - 1));
                    }

                    if ebpf.jmp_jt_jf(cbpf_insn, s, reg_jmp, false)? {
                        jmps_map.push((cbpf_pos, ebpf.0.len() - 1));
                    }
                }
                t @ BpfInsnType::RetA | t @ BpfInsnType::RetK => {
                    ebpf.prepare_ret(cbpf_insn, BpfInsnType::RetA == t)?;
                    ebpf.add(Insn::exit());
                }
                BpfInsnType::Tax => ebpf.add(Insn::mov(MovInfo::Reg {
                    src: BpfReg::A,
                    dst: BpfReg::X,
                })),
                BpfInsnType::Txa => ebpf.add(Insn::mov(MovInfo::Reg {
                    src: BpfReg::X,
                    dst: BpfReg::A,
                })),
                BpfInsnType::St => ebpf.add(Insn::st(
                    StInfo::Reg {
                        src: BpfReg::A,
                        dst: BpfReg::FP,
                        off: -SCRATCH_MEM_START + cbpf_insn.k as i16,
                    },
                    BpfSize::Word,
                )),
                BpfInsnType::Stx => ebpf.add(Insn::st(
                    StInfo::Reg {
                        src: BpfReg::X,
                        dst: BpfReg::FP,
                        off: -SCRATCH_MEM_START + cbpf_insn.k as i16,
                    },
                    BpfSize::Word,
                )),
            }
        }

        for jmp_off in jmps_map.iter() {
            if jmp_off.1 >= ebpf.0.len() {
                bail!(
                    "Error at position {} in ebpf while trying to resolve jump offset",
                    jmp_off.1
                );
            }

            let ebpf_jmp_insn = ebpf
                .0
                .get_mut(jmp_off.1)
                .ok_or_else(|| anyhow!("Error retrieving ebpf jmp instruction"))?;
            let cbpf_jmp_tgt_off = usize::try_from(i16::try_from(jmp_off.0)? + ebpf_jmp_insn.off)?;

            if cbpf_jmp_tgt_off >= insns_map.len() {
                bail!(
                    "Error at position {} ({}) while getting mapped offsets",
                    cbpf_jmp_tgt_off,
                    insns_map.len()
                );
            }

            ebpf_jmp_insn.off = i16::try_from(
                insns_map
                    .get(cbpf_jmp_tgt_off)
                    .ok_or_else(|| anyhow!("Error retrieving cbpf to ebpf jmp mapping"))?
                    - jmp_off.1
                    - 1,
            )?;
        }

        Ok(ebpf)
    }
}
