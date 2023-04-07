//! # BpfProg
//!
//! BpfProg contains multiple instances of BpfInsn composing a cbpf program

#![allow(dead_code)]
use std::collections::HashMap;
use std::mem;

use anyhow::{bail, Result};
use once_cell::sync::Lazy;

use crate::core::{bpf_sys, filters::packets::bpf_common::*};

#[derive(Default, Clone, Copy)]
#[repr(C)]
pub(super) struct BpfInsn {
    pub opcode: u16,
    pub jt: u8,
    pub jf: u8,
    pub k: u32,
}

#[derive(Default)]
pub(super) struct BpfProg {
    pub prog: Vec<BpfInsn>,
}

impl BpfInsn {
    // Returns the type of the code, checking its correctness.
    // The code definition follows:
    // https://man.freebsd.org/cgi/man.cgi?query=bpf&sektion=4#FILTER_MACHINE
    pub(super) fn insn_type(&self) -> Result<BpfInsnType> {
        static OPCODE_SET: Lazy<HashMap<u8, BpfInsnType>> = Lazy::new(|| {
            HashMap::from([
                (
                    bpf_sys::BPF_LD | bpf_sys::BPF_W | bpf_sys::BPF_ABS,
                    BpfInsnType::LdAbs(BpfSize::Word),
                ),
                (
                    bpf_sys::BPF_LD | bpf_sys::BPF_H | bpf_sys::BPF_ABS,
                    BpfInsnType::LdAbs(BpfSize::Half),
                ),
                (
                    bpf_sys::BPF_LD | bpf_sys::BPF_B | bpf_sys::BPF_ABS,
                    BpfInsnType::LdAbs(BpfSize::Byte),
                ),
                (
                    bpf_sys::BPF_LD | bpf_sys::BPF_W | bpf_sys::BPF_IND,
                    BpfInsnType::LdInd(BpfSize::Word),
                ),
                (
                    bpf_sys::BPF_LD | bpf_sys::BPF_H | bpf_sys::BPF_IND,
                    BpfInsnType::LdInd(BpfSize::Half),
                ),
                (
                    bpf_sys::BPF_LD | bpf_sys::BPF_B | bpf_sys::BPF_IND,
                    BpfInsnType::LdInd(BpfSize::Byte),
                ),
                (
                    bpf_sys::BPF_LD | bpf_sys::BPF_W | bpf_sys::BPF_LEN,
                    BpfInsnType::LdLen,
                ),
                (bpf_sys::BPF_LD | bpf_sys::BPF_IMM, BpfInsnType::LdImm),
                (bpf_sys::BPF_LD | bpf_sys::BPF_MEM, BpfInsnType::LdMem),
                (
                    bpf_sys::BPF_LDX | bpf_sys::BPF_W | bpf_sys::BPF_IMM,
                    BpfInsnType::LdxImm,
                ),
                (
                    bpf_sys::BPF_LDX | bpf_sys::BPF_W | bpf_sys::BPF_MEM,
                    BpfInsnType::LdxMem,
                ),
                (
                    bpf_sys::BPF_LDX | bpf_sys::BPF_W | bpf_sys::BPF_LEN,
                    BpfInsnType::LdxLen,
                ),
                (
                    bpf_sys::BPF_LDX | bpf_sys::BPF_B | bpf_sys::BPF_MSH,
                    BpfInsnType::LdxMsh,
                ),
                (bpf_sys::BPF_ST, BpfInsnType::St),
                (bpf_sys::BPF_STX, BpfInsnType::Stx),
                (
                    bpf_sys::BPF_ALU | bpf_sys::BPF_ADD | bpf_sys::BPF_K,
                    BpfInsnType::AluK(BpfAluOp::Add),
                ),
                (
                    bpf_sys::BPF_ALU | bpf_sys::BPF_SUB | bpf_sys::BPF_K,
                    BpfInsnType::AluK(BpfAluOp::Sub),
                ),
                (
                    bpf_sys::BPF_ALU | bpf_sys::BPF_MUL | bpf_sys::BPF_K,
                    BpfInsnType::AluK(BpfAluOp::Mul),
                ),
                (
                    bpf_sys::BPF_ALU | bpf_sys::BPF_DIV | bpf_sys::BPF_K,
                    BpfInsnType::AluK(BpfAluOp::Div),
                ),
                (
                    bpf_sys::BPF_ALU | bpf_sys::BPF_MOD | bpf_sys::BPF_K,
                    BpfInsnType::AluK(BpfAluOp::Mod),
                ),
                (
                    bpf_sys::BPF_ALU | bpf_sys::BPF_AND | bpf_sys::BPF_K,
                    BpfInsnType::AluK(BpfAluOp::And),
                ),
                (
                    bpf_sys::BPF_ALU | bpf_sys::BPF_OR | bpf_sys::BPF_K,
                    BpfInsnType::AluK(BpfAluOp::Or),
                ),
                (
                    bpf_sys::BPF_ALU | bpf_sys::BPF_XOR | bpf_sys::BPF_K,
                    BpfInsnType::AluK(BpfAluOp::Xor),
                ),
                (
                    bpf_sys::BPF_ALU | bpf_sys::BPF_LSH | bpf_sys::BPF_K,
                    BpfInsnType::AluK(BpfAluOp::Lsh),
                ),
                (
                    bpf_sys::BPF_ALU | bpf_sys::BPF_RSH | bpf_sys::BPF_K,
                    BpfInsnType::AluK(BpfAluOp::Rsh),
                ),
                (
                    bpf_sys::BPF_ALU | bpf_sys::BPF_ADD | bpf_sys::BPF_X,
                    BpfInsnType::AluX(BpfAluOp::Add),
                ),
                (
                    bpf_sys::BPF_ALU | bpf_sys::BPF_SUB | bpf_sys::BPF_X,
                    BpfInsnType::AluX(BpfAluOp::Sub),
                ),
                (
                    bpf_sys::BPF_ALU | bpf_sys::BPF_MUL | bpf_sys::BPF_X,
                    BpfInsnType::AluX(BpfAluOp::Mul),
                ),
                (
                    bpf_sys::BPF_ALU | bpf_sys::BPF_DIV | bpf_sys::BPF_X,
                    BpfInsnType::AluX(BpfAluOp::Div),
                ),
                (
                    bpf_sys::BPF_ALU | bpf_sys::BPF_MOD | bpf_sys::BPF_X,
                    BpfInsnType::AluX(BpfAluOp::Mod),
                ),
                (
                    bpf_sys::BPF_ALU | bpf_sys::BPF_AND | bpf_sys::BPF_X,
                    BpfInsnType::AluX(BpfAluOp::And),
                ),
                (
                    bpf_sys::BPF_ALU | bpf_sys::BPF_OR | bpf_sys::BPF_X,
                    BpfInsnType::AluX(BpfAluOp::Or),
                ),
                (
                    bpf_sys::BPF_ALU | bpf_sys::BPF_XOR | bpf_sys::BPF_X,
                    BpfInsnType::AluX(BpfAluOp::Xor),
                ),
                (
                    bpf_sys::BPF_ALU | bpf_sys::BPF_LSH | bpf_sys::BPF_X,
                    BpfInsnType::AluX(BpfAluOp::Lsh),
                ),
                (
                    bpf_sys::BPF_ALU | bpf_sys::BPF_RSH | bpf_sys::BPF_X,
                    BpfInsnType::AluX(BpfAluOp::Rsh),
                ),
                (
                    bpf_sys::BPF_ALU | bpf_sys::BPF_NEG,
                    BpfInsnType::AluNeg(BpfAluOp::Not),
                ),
                (bpf_sys::BPF_JMP | bpf_sys::BPF_JA, BpfInsnType::JmpA),
                (
                    bpf_sys::BPF_JMP | bpf_sys::BPF_JGT | bpf_sys::BPF_K,
                    BpfInsnType::JmpK(BpfJmpOp::Gt),
                ),
                (
                    bpf_sys::BPF_JMP | bpf_sys::BPF_JGE | bpf_sys::BPF_K,
                    BpfInsnType::JmpK(BpfJmpOp::Ge),
                ),
                (
                    bpf_sys::BPF_JMP | bpf_sys::BPF_JEQ | bpf_sys::BPF_K,
                    BpfInsnType::JmpK(BpfJmpOp::Eq),
                ),
                (
                    bpf_sys::BPF_JMP | bpf_sys::BPF_JSET | bpf_sys::BPF_K,
                    BpfInsnType::JmpK(BpfJmpOp::Set),
                ),
                (
                    bpf_sys::BPF_JMP | bpf_sys::BPF_JGT | bpf_sys::BPF_X,
                    BpfInsnType::JmpX(BpfJmpOp::Gt),
                ),
                (
                    bpf_sys::BPF_JMP | bpf_sys::BPF_JGE | bpf_sys::BPF_X,
                    BpfInsnType::JmpX(BpfJmpOp::Ge),
                ),
                (
                    bpf_sys::BPF_JMP | bpf_sys::BPF_JEQ | bpf_sys::BPF_X,
                    BpfInsnType::JmpX(BpfJmpOp::Eq),
                ),
                (
                    bpf_sys::BPF_JMP | bpf_sys::BPF_JSET | bpf_sys::BPF_X,
                    BpfInsnType::JmpX(BpfJmpOp::Set),
                ),
                (bpf_sys::BPF_RET | bpf_sys::BPF_A, BpfInsnType::RetA),
                (bpf_sys::BPF_RET | bpf_sys::BPF_K, BpfInsnType::RetK),
                (bpf_sys::BPF_MISC | bpf_sys::BPF_TAX, BpfInsnType::Tax),
                (bpf_sys::BPF_MISC | bpf_sys::BPF_TXA, BpfInsnType::Txa),
            ])
        });

        match OPCODE_SET.get(&(self.opcode as u8)) {
            Some(o) => Ok(*o),
            None => bail!("Unknown bpf instruction: {}", self.opcode),
        }
    }
}

impl core::fmt::Debug for BpfInsn {
    fn fmt(&self, f: &mut core::fmt::Formatter) -> Result<(), core::fmt::Error> {
        write!(f, "{} {} {} {}", self.opcode, self.jf, self.jt, self.k)?;

        Ok(())
    }
}

impl BpfProg {
    fn new() -> BpfProg {
        Default::default()
    }
}

impl TryFrom<&[u8]> for BpfProg {
    type Error = anyhow::Error;

    fn try_from(insns: &[u8]) -> Result<Self> {
        let mut bpf = Self::new();
        bpf.prog.extend_from_slice(unsafe { mem::transmute(insns) });

        Ok(bpf)
    }
}

impl core::fmt::Debug for BpfProg {
    fn fmt(&self, f: &mut core::fmt::Formatter) -> Result<(), core::fmt::Error> {
        let mut bpf_dbg = String::new();

        bpf_dbg.push_str(&format!("{},", self.prog.len()));

        for x in self.prog.iter() {
            bpf_dbg.push_str(&format!("{:?},", x));
        }

        write!(f, "{}", bpf_dbg.trim_end_matches(','))?;
        Ok(())
    }
}
