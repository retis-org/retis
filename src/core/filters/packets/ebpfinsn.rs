#![allow(dead_code, non_camel_case_types)]
use std::vec;

use crate::core::{
    bpf_sys,
    filters::packets::{bpf_common::*, ebpf::BpfReg},
};

#[repr(u8)]
pub(crate) enum eBpfJmpOpExt {
    Bpf(BpfJmpOp),
    Ne, // identifies bpf_sys::BPF_JNE
}

#[repr(u8)]
pub(crate) enum EndianType {
    Le = bpf_sys::BPF_TO_LE,
    Be = bpf_sys::BPF_TO_BE,
}

pub(crate) enum EndianInfo {
    E16 { r#type: EndianType },
    E32 { r#type: EndianType },
    E64 { r#type: EndianType },
}

pub(crate) enum AluInfo {
    Reg { src: BpfReg, dst: BpfReg },
    Imm { dst: BpfReg, imm: i32 },
}

pub(crate) enum MovInfo {
    Reg { src: BpfReg, dst: BpfReg },
    Imm { dst: BpfReg, imm: i32 },
}

pub(crate) enum JmpInfo {
    Reg { src: BpfReg, dst: BpfReg, off: i16 },
    Imm { dst: BpfReg, off: i16, imm: i32 },
}

pub(crate) enum LdInfo {
    Reg { src: BpfReg, dst: BpfReg, off: i16 },
    Imm { src: BpfReg, imm: i32 },
}

pub(crate) enum StInfo {
    Reg { src: BpfReg, dst: BpfReg, off: i16 },
    Imm { dst: BpfReg, off: i16, imm: i32 },
}

#[derive(Clone, Copy)]
pub(crate) struct eBpfInsn {
    pub(super) code: u8, /* opcode */
    pub(super) dst: u8,
    pub(super) src: u8,
    pub(super) off: i16, /* signed offset */
    pub(super) imm: i32, /* signed immediate constant */
}

impl eBpfInsn {
    // Emit instructions functions
    fn __alu(op: u8, r#type: AluInfo, size: u8) -> eBpfInsn {
        let mut immediate = 0;
        let mut src_reg = 0;
        let mut opcode = 0;
        let dst_reg;

        opcode |= op | size;

        match r#type {
            AluInfo::Reg { src, dst } => {
                opcode |= bpf_sys::BPF_X;
                src_reg = src as u8;
                dst_reg = dst as u8;
            }
            AluInfo::Imm { dst, imm } => {
                opcode |= bpf_sys::BPF_K;
                immediate = imm;
                dst_reg = dst as u8;
            }
        }

        Self::insn(opcode, dst_reg, src_reg, 0, immediate)
    }

    pub(crate) fn alu32(alu_op: BpfAluOp, r#type: AluInfo) -> eBpfInsn {
        Self::__alu(alu_op as u8, r#type, bpf_sys::BPF_ALU)
    }

    pub(crate) fn alu(alu_op: BpfAluOp, r#type: AluInfo) -> eBpfInsn {
        Self::__alu(alu_op as u8, r#type, bpf_sys::BPF_ALU64)
    }

    fn __mov(r#type: MovInfo, size: u8) -> eBpfInsn {
        let mut immediate = 0;
        let mut src_reg = 0;
        let mut opcode = 0;
        let dst_reg;

        opcode |= bpf_sys::BPF_MOV;

        match r#type {
            MovInfo::Reg { src, dst } => {
                opcode |= bpf_sys::BPF_X;
                src_reg = src as u8;
                dst_reg = dst as u8;

                opcode |= size;
            }
            MovInfo::Imm { dst, imm } => {
                opcode |= bpf_sys::BPF_K;
                dst_reg = dst as u8;
                immediate = imm;

                opcode |= size;
            }
        }

        Self::insn(opcode, dst_reg, src_reg, 0, immediate)
    }

    pub(crate) fn mov32(r#type: MovInfo) -> eBpfInsn {
        Self::__mov(r#type, bpf_sys::BPF_ALU)
    }

    pub(crate) fn mov(r#type: MovInfo) -> eBpfInsn {
        Self::__mov(r#type, bpf_sys::BPF_ALU64)
    }

    fn __ld(r#type: LdInfo, mem_size: u8) -> eBpfInsn {
        let mut immediate = 0;
        let mut opcode = 0;
        let mut dst_reg = 0;
        let mut offt = 0;
        let src_reg;

        opcode |= mem_size;

        match r#type {
            LdInfo::Imm { src, imm } => {
                opcode |= match src as u8 {
                    0 => bpf_sys::BPF_ABS,
                    _ => bpf_sys::BPF_IND,
                };

                opcode |= bpf_sys::BPF_LD;
                src_reg = src as u8;
                immediate = imm;
            }
            LdInfo::Reg { src, dst, off } => {
                opcode |= bpf_sys::BPF_LDX | bpf_sys::BPF_MEM;
                src_reg = src as u8;
                dst_reg = dst as u8;
                offt = off;
            }
        }

        Self::insn(opcode, dst_reg, src_reg, offt, immediate)
    }

    // mov off(%src), %dst
    pub(crate) fn ld(r#type: LdInfo, size: BpfSize) -> eBpfInsn {
        Self::__ld(r#type, size as u8)
    }

    fn __st(r#type: StInfo, mem_size: u8) -> eBpfInsn {
        let mut immediate = 0;
        let mut src_reg = 0;
        let mut opcode = 0;
        let dst_reg;
        let offt;

        opcode |= mem_size | bpf_sys::BPF_MEM;

        match r#type {
            StInfo::Reg { src, dst, off } => {
                opcode |= bpf_sys::BPF_STX;
                src_reg = src as u8;
                dst_reg = dst as u8;
                offt = off;
            }
            StInfo::Imm { dst, off, imm } => {
                opcode |= bpf_sys::BPF_ST;
                immediate = imm;
                dst_reg = dst as u8;
                offt = off;
            }
        }

        Self::insn(opcode, dst_reg, src_reg, offt, immediate)
    }

    pub(crate) fn st(r#type: StInfo, size: BpfSize) -> eBpfInsn {
        Self::__st(r#type, size as u8)
    }

    pub(crate) fn exit() -> eBpfInsn {
        Self::insn(bpf_sys::BPF_JMP | bpf_sys::BPF_EXIT, 0, 0, 0, 0)
    }

    pub(crate) fn call(func: u32) -> eBpfInsn {
        Self::insn(bpf_sys::BPF_JMP | bpf_sys::BPF_CALL, 0, 0, 0, func as i32)
    }

    pub(crate) fn __jmp(op: u8, r#type: JmpInfo, size: u8) -> eBpfInsn {
        let mut immediate = 0;
        let mut src_reg = 0;
        let mut opcode = 0;
        let dst_reg;
        let offset;

        opcode |= op | size;

        match r#type {
            JmpInfo::Reg { src, dst, off } => {
                opcode |= bpf_sys::BPF_X;
                src_reg = src as u8;
                dst_reg = dst as u8;
                offset = off;
            }
            JmpInfo::Imm { dst, off, imm } => {
                opcode |= bpf_sys::BPF_K;
                dst_reg = dst as u8;
                offset = off;
                immediate = imm;
            }
        }

        Self::insn(opcode, dst_reg, src_reg, offset, immediate)
    }

    pub(crate) fn jmp(op: eBpfJmpOpExt, r#type: JmpInfo) -> eBpfInsn {
        let jop: u8 = match op {
            eBpfJmpOpExt::Bpf(o) => o as u8,
            eBpfJmpOpExt::Ne => bpf_sys::BPF_JNE,
        };

        Self::__jmp(jop, r#type, bpf_sys::BPF_JMP)
    }

    pub(crate) fn jmp32(op: eBpfJmpOpExt, r#type: JmpInfo) -> eBpfInsn {
        let jop = match op {
            eBpfJmpOpExt::Bpf(o) => o as u8,
            eBpfJmpOpExt::Ne => bpf_sys::BPF_JNE,
        };

        Self::__jmp(jop, r#type, bpf_sys::BPF_JMP32)
    }

    pub(crate) fn jmp_a(off: i16) -> eBpfInsn {
        Self::insn(bpf_sys::BPF_JMP | bpf_sys::BPF_JA, 0, 0, off, 0)
    }

    fn endian(dst: u8, order: EndianInfo) -> eBpfInsn {
        let endian_type;
        let imm;

        match order {
            EndianInfo::E16 { r#type } => {
                imm = 16;
                endian_type = r#type;
            }
            EndianInfo::E32 { r#type } => {
                imm = 32;
                endian_type = r#type;
            }
            EndianInfo::E64 { r#type } => {
                imm = 64;
                endian_type = r#type;
            }
        }

        Self::insn(
            bpf_sys::BPF_ALU | bpf_sys::BPF_END | endian_type as u8,
            dst,
            0,
            0,
            imm,
        )
    }

    pub(crate) fn endian16(dst: BpfReg, r#type: EndianType) -> eBpfInsn {
        Self::endian(dst as u8, EndianInfo::E16 { r#type })
    }

    pub(crate) fn endian32(dst: BpfReg, r#type: EndianType) -> eBpfInsn {
        Self::endian(dst as u8, EndianInfo::E32 { r#type })
    }

    pub(crate) fn endian64(dst: BpfReg, r#type: EndianType) -> eBpfInsn {
        Self::endian(dst as u8, EndianInfo::E64 { r#type })
    }

    fn insn(code: u8, dst: u8, src: u8, off: i16, imm: i32) -> eBpfInsn {
        eBpfInsn {
            code,
            dst,
            src,
            off,
            imm,
        }
    }

    pub(crate) fn to_vec(self) -> Vec<u8> {
        let mut byte_insn = vec![self.code, self.src << 4 | self.dst];

        byte_insn.extend(self.off.to_le_bytes());
        byte_insn.extend(self.imm.to_le_bytes());
        byte_insn
    }
}
