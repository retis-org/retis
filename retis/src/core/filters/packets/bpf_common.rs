#![allow(dead_code)]

use crate::core::bpf_sys;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub(crate) enum BpfAluOp {
    Add = bpf_sys::BPF_ADD,
    Sub = bpf_sys::BPF_SUB,
    And = bpf_sys::BPF_AND,
    Or = bpf_sys::BPF_OR,
    Lsh = bpf_sys::BPF_LSH,
    Rsh = bpf_sys::BPF_RSH,
    Xor = bpf_sys::BPF_XOR,
    Mul = bpf_sys::BPF_MUL,
    Div = bpf_sys::BPF_DIV,
    Mod = bpf_sys::BPF_MOD,
    Not = bpf_sys::BPF_NEG,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub(crate) enum BpfJmpOp {
    Eq = bpf_sys::BPF_JEQ,
    Gt = bpf_sys::BPF_JGT,
    Ge = bpf_sys::BPF_JGE,
    Set = bpf_sys::BPF_JSET,
}

#[derive(Clone, Copy, Eq, PartialEq)]
#[repr(u8)]
pub(crate) enum BpfSize {
    Byte = bpf_sys::BPF_B,
    Half = bpf_sys::BPF_H,
    Word = bpf_sys::BPF_W,
    Double = bpf_sys::BPF_DW,
}

#[derive(Clone, Copy, Eq, PartialEq)]
pub(super) enum BpfInsnType {
    LdAbs(BpfSize),
    LdInd(BpfSize),
    LdLen,
    LdImm,
    LdMem,
    LdxImm,
    LdxMem,
    LdxLen,
    LdxMsh,
    St,
    Stx,
    AluK(BpfAluOp),
    AluX(BpfAluOp),
    AluNeg(BpfAluOp),
    JmpA,
    JmpK(BpfJmpOp),
    JmpX(BpfJmpOp),
    RetA,
    RetK,
    Tax,
    Txa,
}
