//! # FilterMeta
//!
//! Object for metadata filtering. It takes as input a filter string
//! under the form struct_name.member1.member2.[...].leafmember
//! generating a sequence of eBPF instructions implementing the
//! semantic expressed by the filter.

use std::fmt;

use anyhow::{anyhow, bail, ensure, Result};
use btf_rs::*;
use pest::Parser;
use pest_derive::Parser;

use crate::core::{
    bpf_sys,
    filters::packets::{
        bpf_common::*,
        ebpf::{eBpfProg, BpfReg},
        ebpfinsn::*,
    },
    inspect::{inspector, BtfInfo},
};

const PTR_BIT: u8 = 1 << 6;
const SIGN_BIT: u8 = 1 << 7;

#[derive(Clone, Debug, Default)]
struct LhsNode {
    member: String,
    mask: u64,
    cast: Option<String>,
}

type Lhs = Vec<LhsNode>;

#[derive(Copy, Clone, Debug, Default, Eq, PartialEq)]
enum RelOp {
    Eq,
    Gt,
    Lt,
    Ge,
    Le,
    #[default]
    Ne,
}

impl fmt::Display for RelOp {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            RelOp::Eq => write!(f, "=="),
            RelOp::Gt => write!(f, ">"),
            RelOp::Lt => write!(f, "<"),
            RelOp::Ge => write!(f, ">="),
            RelOp::Le => write!(f, "<="),
            RelOp::Ne => write!(f, "!="),
        }
    }
}

enum MetaType {
    Char = 1,
    Short = 2,
    Int = 3,
    Long = 4,
}

const META_TARGET_MAX: usize = 32;

#[derive(Copy, Clone, Default)]
struct TargetCtx {
    md: [u8; META_TARGET_MAX],
    sz: usize,
    cmp: RelOp,
}

#[derive(Copy, Clone, Debug, Default, Eq, PartialEq)]
struct LoadCtx {
    // Type of data we're going to load
    // bit 0-4: [char|short|int|long], bit5: reserved, bit6: is_ptr, bit7: sign
    r#type: u8,
    // Usually zero.
    // nmemb > 0 is valid iff XlateCtx::r#type == MetaType::Char
    nmemb: u8,
    // Byte offset if bf_size is zero. Bit offset otherwise.
    offt: u16,
    // Zero for no bitfield.
    bf_size: u8,
    // Mask to apply. Only numbers are supported.
    mask: u64,
}

impl LoadCtx {
    fn is_num(&self) -> bool {
        self.is_byte() || self.is_short() || self.is_int() || self.is_long()
    }

    fn is_byte(&self) -> bool {
        self.r#type & 0x1f == MetaType::Char as u8
    }

    fn is_short(&self) -> bool {
        self.r#type & 0x1f == MetaType::Short as u8
    }

    fn is_int(&self) -> bool {
        self.r#type & 0x1f == MetaType::Int as u8
    }

    fn is_long(&self) -> bool {
        self.r#type & 0x1f == MetaType::Long as u8
    }

    fn is_ptr(&self) -> bool {
        self.r#type & PTR_BIT > 0
    }

    fn is_signed(&self) -> bool {
        self.r#type & SIGN_BIT > 0
    }

    fn is_arr(&self) -> bool {
        self.nmemb > 0
    }
}

#[repr(C)]
#[derive(Copy, Clone, Default)]
pub(crate) struct XlateCtx {
    load: LoadCtx,
    target: TargetCtx,
}

impl XlateCtx {
    fn new() -> XlateCtx {
        Default::default()
    }

    fn bail_on_arr(&self, tn: &str) -> Result<()> {
        if self.load.is_arr() {
            bail!("array of {tn} are not supported.");
        }

        Ok(())
    }

    fn bail_on_ptr(&self, tn: &str) -> Result<()> {
        if self.load.is_ptr() {
            bail!("pointers to {tn} are not supported.");
        }

        Ok(())
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
enum Rhs {
    Str(String),
    Unsigned(u64),
    Signed(i64),
}

impl Default for Rhs {
    fn default() -> Self {
        Self::Unsigned(0)
    }
}

#[derive(Default)]
struct TFlist {
    true_list: Vec<usize>,
    false_list: Vec<usize>,
}

impl TFlist {
    fn from_true_false(true_list: &[usize], false_list: &[usize]) -> Self {
        let mut list = Self::default();

        list.merge_true(true_list);
        list.merge_false(false_list);

        list
    }

    fn merge_true(&mut self, list: &[usize]) {
        self.true_list.extend_from_slice(list);
    }

    fn merge_false(&mut self, list: &[usize]) {
        self.false_list.extend_from_slice(list);
    }

    fn merge_lists(&mut self, lists: &TFlist) {
        self.merge_true(&lists.true_list);
        self.merge_false(&lists.false_list);
    }

    fn push_true(&mut self, val: usize) {
        self.true_list.push(val);
    }

    fn push_false(&mut self, val: usize) {
        self.false_list.push(val);
    }

    fn fixup(&mut self, pos: usize) {
        self.true_list.iter_mut().for_each(|t| *t += pos);
        self.false_list.iter_mut().for_each(|f| *f += pos);
    }
}

#[derive(Parser)]
#[grammar = "core/filters/meta/meta.pest"]
struct ParserMeta;

macro_rules! parse_unreach {
    ($msg:expr) => {{
        bail!("Unexpected parse error: {} (at file: {}, line: {})", $msg, file!(), line!());
    }};
    ($fmt:expr, $($arg:tt)*) => {{
        bail!(concat!("Unexpected parse error: ", $fmt, " (at file: {}, line: {})"), $($arg)*, file!(), line!());
    }};
}

impl ParserMeta {
    fn parse_mask(pair: pest::iterators::Pair<Rule>) -> Result<u64> {
        let mut not = false;
        let mut mask = 0;

        for inner in pair.into_inner() {
            match inner.as_rule() {
                Rule::not => not = true,
                Rule::hex => {
                    mask = u64::from_str_radix(inner.as_str().trim_start_matches("0x"), 16)?
                }
                Rule::dec => mask = inner.as_str().parse::<u64>()?,
                Rule::bin => {
                    mask = u64::from_str_radix(inner.as_str().trim_start_matches("0b"), 2)?
                }
                e => parse_unreach!("while parsing mask {:#?}", e),
            }
        }

        if not {
            mask = !mask;
        }

        ensure!(mask > 0, "mask must be greater than 0");

        Ok(mask)
    }

    fn parse_ident_modifiers(pair: pest::iterators::Pair<Rule>) -> Result<(u64, Option<String>)> {
        let mut cast = None;
        let mut mask = 0;

        for inner in pair.into_inner() {
            match inner.as_rule() {
                Rule::mask => {
                    mask = Self::parse_mask(inner)?;
                }
                Rule::uident => {
                    cast = Some(inner.as_str().to_owned());
                }
                _ => parse_unreach!("while parsing field modifier"),
            }
        }

        Ok((mask, cast))
    }

    fn parse_ident(pair: pest::iterators::Pair<Rule>) -> Result<LhsNode> {
        let mut member = String::new();
        let mut mask = 0;
        let mut cast = None;

        for inner in pair.into_inner() {
            match inner.as_rule() {
                Rule::uident => {
                    member = inner.as_str().to_owned();
                }
                Rule::ident_modifiers => {
                    (mask, cast) = Self::parse_ident_modifiers(inner)?;
                }
                _ => parse_unreach!("while parsing identifier"),
            }
        }

        Ok(LhsNode { member, mask, cast })
    }

    fn parse_lhs(pair: pest::iterators::Pair<Rule>) -> Result<Lhs> {
        let mut lhs = Vec::new();
        for inner in pair.into_inner() {
            if inner.as_rule() == Rule::ident {
                lhs.push(Self::parse_ident(inner.clone())?);
            }
        }
        Ok(lhs)
    }

    fn parse_rhs(pair: pest::iterators::Pair<Rule>) -> Result<Rhs> {
        let pair = pair
            .into_inner()
            .next()
            .ok_or_else(|| anyhow!("rhs: failed to retrieve inner pairs"))?;

        match pair.as_rule() {
            Rule::num => {
                let text = pair.as_str();
                if let Some(stripped_hex) = text.strip_prefix("0x") {
                    Ok(Rhs::Unsigned(u64::from_str_radix(stripped_hex, 16)?))
                } else if let Some(stripped_bin) = text.strip_prefix("0b") {
                    Ok(Rhs::Unsigned(u64::from_str_radix(stripped_bin, 2)?))
                } else if text.starts_with("-") {
                    Ok(Rhs::Signed(text.parse()?))
                } else {
                    Ok(Rhs::Unsigned(text.parse()?))
                }
            }
            Rule::string => Ok(Rhs::Str(
                pair.as_str()
                    .trim_matches('"')
                    .trim_matches('\'')
                    .to_string(),
            )),
            e => parse_unreach!("unexpected RHS type {:?}", e),
        }
    }

    fn parse_operator(pair: pest::iterators::Pair<Rule>) -> Result<RelOp> {
        match pair.as_str() {
            "==" => Ok(RelOp::Eq),
            "!=" => Ok(RelOp::Ne),
            ">=" => Ok(RelOp::Ge),
            ">" => Ok(RelOp::Gt),
            "<=" => Ok(RelOp::Le),
            "<" => Ok(RelOp::Lt),
            op => parse_unreach!("{} is an invalid operator", op),
        }
    }

    fn parse_infix(pair: pest::iterators::Pair<Rule>) -> Result<BooleanOp> {
        match pair.as_str() {
            "and" | "&&" => Ok(BooleanOp::And),
            "or" | "||" => Ok(BooleanOp::Or),
            _ => parse_unreach!("Unexpected boolean operator"),
        }
    }

    fn parse_term(pair: pest::iterators::Pair<Rule>) -> Result<AstNode> {
        let mut inner_pairs = pair.into_inner();
        let lhs = Self::parse_lhs(
            inner_pairs
                .next()
                .ok_or_else(|| anyhow!("term: failed to retrieve inner pairs"))?,
        )?;

        // If op and rhs are omitted the expression defaults to lhs != 0.
        let mut op = RelOp::default();
        let mut rhs = Rhs::default();
        for inner in inner_pairs {
            match inner.as_rule() {
                Rule::op => {
                    op = Self::parse_operator(inner)?;
                }
                Rule::rhs => {
                    rhs = Self::parse_rhs(inner)?;
                }
                _ => parse_unreach!("unexpected terminal symbol"),
            }
        }

        Ok(AstNode::RelOpExpr { lhs, op, rhs })
    }

    fn parse_primary(pair: pest::iterators::Pair<Rule>) -> Result<AstNode> {
        let inner = pair
            .into_inner()
            .next()
            .ok_or_else(|| anyhow!("primary: failed to retrieve inner pairs"))?;

        match inner.as_rule() {
            Rule::term => Self::parse_term(inner),
            Rule::expr => Ok(Self::parse_expr(inner)?),
            _ => parse_unreach!("invalid expression"),
        }
    }

    fn parse_expr(pair: pest::iterators::Pair<Rule>) -> Result<AstNode> {
        let mut infix = BooleanOp::Or;
        let mut lhs;

        match pair.as_rule() {
            Rule::expr => {
                let mut inner_pair = pair.into_inner();
                let inner_lhs = inner_pair
                    .next()
                    .ok_or_else(|| anyhow!("expr: failed to retrieve inner lhs"))?;
                // lhs is mandatory.
                lhs = Self::parse_primary(inner_lhs)?;

                for inner in inner_pair {
                    match inner.as_rule() {
                        Rule::infix => {
                            infix = Self::parse_infix(inner)?;
                        }
                        Rule::primary => {
                            lhs = AstNode::BooleanExpr {
                                lhs: Box::new(lhs),
                                op: infix.clone(),
                                rhs: Box::new(Self::parse_primary(inner)?),
                            }
                        }
                        _ => parse_unreach!("while parsing the expression"),
                    }
                }
            }
            _ => parse_unreach!("unexpected rule while parsing expression"),
        }

        Ok(lhs)
    }
}

#[derive(Clone, Debug)]
enum BooleanOp {
    And,
    Or,
}

#[derive(Clone, Debug)]
enum AstNode {
    RelOpExpr {
        lhs: Lhs,
        op: RelOp,
        rhs: Rhs,
    },
    BooleanExpr {
        lhs: Box<AstNode>,
        op: BooleanOp,
        rhs: Box<AstNode>,
    },
}

struct MetaExpr<'a> {
    filter: eBpfProg,
    btf_info: &'a BtfInfo,
    btf: &'a Btf,
    btf_type: Type,
    offt: u32,
}

impl<'a> MetaExpr<'a> {
    fn init_filter(store_arg: bool) -> eBpfProg {
        let mut filter = eBpfProg::new();

        if store_arg {
            filter.add(eBpfInsn::mov(MovInfo::Reg {
                src: BpfReg::R1,
                dst: BpfReg::R0,
            }));

            filter.exit_retval_eq(0);

            // Argument address (any walkable type).
            // The assumption is that this remains untouched.
            filter.add(eBpfInsn::mov(MovInfo::Reg {
                src: BpfReg::R1,
                dst: BpfReg::R6,
            }));
        }

        // R7 will be used as new base in each
        // iteration.
        filter.add(eBpfInsn::mov(MovInfo::Reg {
            src: BpfReg::R6,
            dst: BpfReg::R7,
        }));

        filter
    }

    fn new(btf_info: &'a BtfInfo, sym: &str, arg: bool) -> Result<MetaExpr<'a>> {
        let types = btf_info
            .resolve_types_by_name(sym)
            .map_err(|e| anyhow!("unable to resolve {sym} data type ({e})"))?;

        let (btf, r#type) = match types.iter().find(|(_, t)| matches!(t, Type::Struct(_))) {
            Some(r#struct) => r#struct,
            None => bail!("Could not resolve {sym} to a struct"),
        };

        Ok(Self {
            filter: Self::init_filter(arg),
            btf_info,
            btf,
            btf_type: r#type.clone(),
            offt: 0,
        })
    }

    fn finalize_expr(
        &self,
        field: &LhsNode,
        rel_op: RelOp,
        rval: Rhs,
        bfs: Option<u32>,
    ) -> Result<XlateCtx> {
        let mut ctx: XlateCtx = XlateCtx::new();
        let mut t = self.btf_type.clone();
        let mut type_iter = self.btf.type_iter(
            self.btf_type
                .as_btf_type()
                .ok_or_else(|| anyhow!("Unable to retrieve iterable BTF type"))?,
        );

        loop {
            match t {
                Type::Ptr(_) => {
                    ctx.bail_on_ptr(t.name())?;
                    ctx.load.r#type |= PTR_BIT
                }
                Type::Array(ref a) => {
                    // Pointers to array are not supported.
                    ctx.bail_on_ptr(t.name())?;
                    // Retrieve the number of elements
                    ctx.load.nmemb = u8::try_from(a.len())?;
                }
                Type::Enum(ref e) => {
                    // Pointers to enum are not supported.
                    ctx.bail_on_ptr(t.name())?;
                    // Always assume size 4B
                    ctx.load.r#type |= MetaType::Int as u8;
                    if e.is_signed() {
                        ctx.load.r#type |= SIGN_BIT;
                    }
                }
                Type::Enum64(ref e64) => {
                    // Pointers to enum64 are not supported.
                    ctx.bail_on_ptr(t.name())?;
                    // Always assume size 8B
                    ctx.load.r#type |= MetaType::Long as u8;
                    if e64.is_signed() {
                        ctx.load.r#type |= SIGN_BIT;
                    }
                }
                Type::Int(ref i) => {
                    if i.is_signed() {
                        ctx.load.r#type |= SIGN_BIT;
                    }

                    match i.size() {
                        8 => ctx.load.r#type |= MetaType::Long as u8,
                        4 => ctx.load.r#type |= MetaType::Int as u8,
                        2 => ctx.load.r#type |= MetaType::Short as u8,
                        1 => ctx.load.r#type |= MetaType::Char as u8,
                        _ => bail!("unsupported type."),
                    }

                    // Array or Ptr are not supported for types other than
                    // chars
                    if !ctx.load.is_byte() {
                        ctx.bail_on_arr(t.name())?;
                        ctx.bail_on_ptr(t.name())?;
                    }
                }
                Type::Typedef(_)
                | Type::Volatile(_)
                | Type::Const(_)
                | Type::Restrict(_)
                | Type::DeclTag(_)
                | Type::TypeTag(_) => (),
                _ => bail!(
                    "found unsupported type while emitting operation ({}).",
                    t.name()
                ),
            }

            t = match type_iter.next() {
                Some(x) => x,
                None => break,
            };
        }

        if field.mask > 0 {
            if ctx.load.is_ptr() || (ctx.load.is_num() && !ctx.load.is_signed()) {
                ctx.load.mask = field.mask;
            } else {
                bail!("mask is only supported for pointers and unsigned numeric members.");
            }
        }

        ctx.load.offt = u16::try_from(self.offt)?;

        if ctx.load.is_ptr() || ctx.load.nmemb > 0 {
            if rel_op != RelOp::Eq && rel_op != RelOp::Ne {
                bail!(
                    "wrong comparison operator. Only '{}' and '{}' are supported for strings.",
                    RelOp::Eq,
                    RelOp::Ne
                );
            }

            if let Rhs::Str(val) = rval {
                // lenght including '\0'
                let rval_len = val.len() + 1;
                let md = &mut ctx.target.md;

                if rval_len > md.len() {
                    bail!("invalid rval size (max {})", md.len() - 1);
                }

                ctx.target.sz = rval_len;

                md[..val.len()].copy_from_slice(val.as_bytes());
                if ctx.load.nmemb == 0 {
                    ctx.load.nmemb = rval_len as u8;
                }
            } else {
                bail!("invalid target value for array or ptr type. Only strings are supported.");
            }
        } else if ctx.load.is_num() {
            let long = match rval {
                Rhs::Unsigned(u) => u,
                Rhs::Signed(si) => {
                    if si < 0 && !ctx.load.is_signed() {
                        bail!("invalid target value (value is signed while type is unsigned)");
                    }
                    si as u64
                }
                Rhs::Str(s) => {
                    bail!("invalid target ({s}) value (cannot compare string with number)")
                }
            };

            ctx.target.md[..std::mem::size_of_val(&long)].copy_from_slice(&long.to_ne_bytes());

            ctx.target.sz = if ctx.load.is_byte() {
                1
            } else if ctx.load.is_short() {
                2
            } else if ctx.load.is_int() {
                4
            } else if ctx.load.is_long() {
                8
            } else {
                bail!("unexpected numeric type");
            };
        }

        ctx.target.cmp = rel_op;

        if let Some(bfs) = bfs {
            ctx.load.bf_size = u8::try_from(bfs)?;
        }

        Ok(ctx)
    }

    // Handles string comparison.
    // Useful for cases like sk_buff.dev.name == "..."
    fn emit_bytes_expr(&mut self, ctx: XlateCtx) -> Result<TFlist> {
        let mut tf_list = TFlist::default();

        self.filter.add_multi(&[
            // Sets the parameters for the helper call that reads the
            // LHS for later comparison
            eBpfInsn::mov(MovInfo::Reg {
                src: BpfReg::FP,
                dst: BpfReg::ARG1,
            }),
            eBpfInsn::alu(
                BpfAluOp::Add,
                AluInfo::Imm {
                    dst: BpfReg::ARG1,
                    imm: -(std::mem::size_of_val(&ctx.target.md) as i32),
                },
            ),
            eBpfInsn::mov(MovInfo::Reg {
                src: BpfReg::R1,
                dst: BpfReg::R8,
            }),
            eBpfInsn::mov(MovInfo::Imm {
                dst: BpfReg::ARG2,
                imm: ctx.load.nmemb as i32,
            }),
            eBpfInsn::alu(
                BpfAluOp::Add,
                AluInfo::Imm {
                    dst: BpfReg::R7,
                    imm: (ctx.load.offt / 8) as i32,
                },
            ),
            eBpfInsn::mov(MovInfo::Reg {
                src: BpfReg::R7,
                dst: BpfReg::ARG3,
            }),
            eBpfInsn::call(bpf_sys::bpf_func_id::BPF_FUNC_probe_read_kernel_str as u32),
            eBpfInsn::jmp(
                eBpfJmpOpExt::eBpf(eBpfJmpOp::GtS),
                JmpInfo::Imm {
                    dst: BpfReg::R0,
                    imm: 0,
                    off: 2,
                },
            ),
            eBpfInsn::mov(MovInfo::Imm {
                dst: BpfReg::R0,
                imm: 0_i32,
            }),
        ]);

        tf_list.push_false(self.filter.len());

        self.filter.add_multi(&[
            eBpfInsn::jmp_a(0),
            eBpfInsn::mov(MovInfo::Reg {
                src: BpfReg::R8,
                dst: BpfReg::R5,
            }),
            eBpfInsn::mov(MovInfo::Reg {
                src: BpfReg::R0,
                dst: BpfReg::R3,
            }),
            eBpfInsn::mov(MovInfo::Reg {
                src: BpfReg::FP,
                dst: BpfReg::R4,
            }),
        ]);

        let mut idx_sz = 0;
        loop {
            self.filter.add(eBpfInsn::st(
                // Store the target in the stack for later comparison.
                // This can ideally be avoided in favor or unrolled comparison
                // but in such case we can only rely on the size of
                // the RHS for arrays as well.
                StInfo::Imm {
                    dst: BpfReg::R4,
                    off: -((std::mem::size_of_val(&ctx.target.md) as i16 * 2) - idx_sz as i16),
                    imm: ctx.target.md[idx_sz] as i32,
                },
                1.try_into()?,
            ));

            idx_sz += 1;
            // idx_sz >= ctx.target.sz is just enough, but this is
            // needed to make old verifier happy.
            if idx_sz >= std::mem::size_of_val(&ctx.target.md) {
                break;
            }
        }

        self.filter.add(eBpfInsn::alu(
            BpfAluOp::Add,
            AluInfo::Imm {
                dst: BpfReg::R4,
                imm: -(std::mem::size_of_val(&ctx.target.md) as i32 * 2),
            },
        ));

        let ld_size = 1.try_into()?;
        let early_exit = if ctx.target.cmp == RelOp::Eq {
            0x0
        } else {
            !0x0
        };

        self.filter.add(eBpfInsn::mov(MovInfo::Imm {
            dst: BpfReg::R0,
            imm: early_exit,
        }));

        let loopback = self.filter.len() - 1;
        self.filter.add_multi(&[
            eBpfInsn::ld(
                LdInfo::Reg {
                    src: BpfReg::R5,
                    dst: BpfReg::R8,
                    off: 0,
                },
                ld_size,
            ),
            eBpfInsn::ld(
                LdInfo::Reg {
                    src: BpfReg::R4,
                    dst: BpfReg::R9,
                    off: 0,
                },
                ld_size,
            ),
            eBpfInsn::alu(
                BpfAluOp::Add,
                AluInfo::Imm {
                    dst: BpfReg::R5,
                    imm: 1,
                },
            ),
            eBpfInsn::alu(
                BpfAluOp::Add,
                AluInfo::Imm {
                    dst: BpfReg::R4,
                    imm: 1,
                },
            ),
            eBpfInsn::jmp(
                eBpfJmpOpExt::Bpf(BpfJmpOp::Eq),
                JmpInfo::Reg {
                    src: BpfReg::R8,
                    dst: BpfReg::R9,
                    off: 1,
                },
            ),
        ]);

        tf_list.push_false(self.filter.len());

        self.filter.add_multi(&[
            eBpfInsn::jmp_a(0),
            eBpfInsn::jmp(
                eBpfJmpOpExt::eBpf(eBpfJmpOp::Ne),
                JmpInfo::Imm {
                    dst: BpfReg::R8,
                    imm: 0,
                    off: 1,
                },
            ),
            eBpfInsn::jmp_a(4),
            eBpfInsn::jmp(
                eBpfJmpOpExt::eBpf(eBpfJmpOp::Ne),
                JmpInfo::Imm {
                    dst: BpfReg::R9,
                    imm: 0,
                    off: 1,
                },
            ),
            eBpfInsn::jmp_a(2),
            eBpfInsn::alu(
                BpfAluOp::Add,
                AluInfo::Imm {
                    dst: BpfReg::R3,
                    imm: -1,
                },
            ),
        ]);

        // These two blocks cannot be coalesced because the following
        // has a dependency on the filter length based on the previous
        // instructions.
        self.filter.add_multi(&[
            eBpfInsn::jmp(
                eBpfJmpOpExt::Bpf(BpfJmpOp::Gt),
                JmpInfo::Imm {
                    dst: BpfReg::R3,
                    imm: 0,
                    off: -((self.filter.len() - loopback) as i16),
                },
            ),
            eBpfInsn::mov(MovInfo::Imm {
                dst: BpfReg::R0,
                imm: !early_exit,
            }),
        ]);

        tf_list.push_true(self.filter.len());
        self.filter.add(eBpfInsn::jmp_a(0));

        Ok(tf_list)
    }

    // Handles numeric and bitfield comparisons handling the mask
    // modifier
    fn emit_num_expr(&mut self, ctx: XlateCtx) -> Result<TFlist> {
        let bf_lshf;
        let bf_rshf;
        let mut sz;
        let mut tf_list = TFlist::default();

        let offset = ctx.load.offt / 8;

        // Prepare left and right shift for both bitfields and signed
        // for later fixup
        if ctx.load.bf_size > 0 {
            bf_rshf = 64 - ctx.load.bf_size as i32;
            bf_lshf = bf_rshf - (ctx.load.offt % 8) as i32;
            sz = (ctx.load.offt - offset * 8) + ctx.load.bf_size as u16;
            sz = sz.div_ceil(8);
        } else {
            sz = ctx.target.sz as u16;
            bf_rshf = 64 - sz as i32 * 8;
            bf_lshf = bf_rshf;
        }

        sz = sz.min(8);
        if sz == 0 {
            bail!("Invalid field/target size (cannot be zero).");
        }

        self.filter.add_multi(&[
            eBpfInsn::mov(MovInfo::Imm {
                dst: BpfReg::R0,
                imm: 0,
            }),
            eBpfInsn::mov(MovInfo::Reg {
                src: BpfReg::FP,
                dst: BpfReg::ARG1,
            }),
            eBpfInsn::alu(
                BpfAluOp::Add,
                AluInfo::Imm {
                    dst: BpfReg::ARG1,
                    imm: -8,
                },
            ),
            eBpfInsn::mov(MovInfo::Imm {
                dst: BpfReg::ARG2,
                imm: sz as i32,
            }),
            eBpfInsn::alu(
                BpfAluOp::Add,
                AluInfo::Imm {
                    dst: BpfReg::R7,
                    imm: offset as i32,
                },
            ),
            eBpfInsn::mov(MovInfo::Reg {
                src: BpfReg::R7,
                dst: BpfReg::ARG3,
            }),
            eBpfInsn::call(bpf_sys::bpf_func_id::BPF_FUNC_probe_read_kernel as u32),
            eBpfInsn::jmp(
                eBpfJmpOpExt::Bpf(BpfJmpOp::Eq),
                JmpInfo::Imm {
                    dst: BpfReg::R0,
                    off: 2,
                    imm: 0,
                },
            ),
            eBpfInsn::mov(MovInfo::Imm {
                dst: BpfReg::R0,
                imm: 0,
            }),
        ]);

        tf_list.push_false(self.filter.len());

        self.filter.add(eBpfInsn::jmp_a(0));
        self.filter.add(eBpfInsn::ld(
            LdInfo::Reg {
                src: BpfReg::FP,
                dst: BpfReg::R5,
                off: -8,
            },
            (sz as u8).try_into()?,
        ));

        // Here sign for both bitfield and non-bitfield types (smaller
        // than 64 bits) is fixed up.
        // Also bitfields require to discard contiguous bits non
        // belonging to the type, so even the usigned ones follow the
        // shift dance.
        if (ctx.target.sz != 8 && ctx.load.is_signed()) || ctx.load.bf_size > 0 {
            self.filter.add(eBpfInsn::alu(
                BpfAluOp::Lsh,
                AluInfo::Imm {
                    dst: BpfReg::R5,
                    imm: bf_lshf,
                },
            ));

            let shift_type = if ctx.load.is_signed() {
                BpfAluOp::Arsh
            } else {
                BpfAluOp::Rsh
            };

            self.filter.add(eBpfInsn::alu(
                shift_type,
                AluInfo::Imm {
                    dst: BpfReg::R5,
                    imm: bf_rshf,
                },
            ));
        }

        // Apply the mask, if set.
        if ctx.load.mask > 0 {
            self.filter
                .add_multi(&eBpfInsn::ld64_imm(BpfReg::R8, ctx.load.mask as i64));

            self.filter.add(eBpfInsn::alu(
                BpfAluOp::And,
                AluInfo::Reg {
                    src: BpfReg::R8,
                    dst: BpfReg::R5,
                },
            ));
        }

        let target_u64 = u64::from_ne_bytes(ctx.target.md[0..8].try_into()?);

        self.filter
            .add_multi(&eBpfInsn::ld64_imm(BpfReg::R7, target_u64 as i64));

        // Based on the comparison, picks the right jump operation
        let j_type = match ctx.target.cmp {
            RelOp::Eq => eBpfJmpOpExt::Bpf(BpfJmpOp::Eq),
            RelOp::Gt => {
                if ctx.load.is_signed() {
                    eBpfJmpOpExt::eBpf(eBpfJmpOp::GtS)
                } else {
                    eBpfJmpOpExt::Bpf(BpfJmpOp::Gt)
                }
            }
            RelOp::Ge => {
                if ctx.load.is_signed() {
                    eBpfJmpOpExt::eBpf(eBpfJmpOp::GeS)
                } else {
                    eBpfJmpOpExt::Bpf(BpfJmpOp::Ge)
                }
            }
            RelOp::Lt => {
                if ctx.load.is_signed() {
                    eBpfJmpOpExt::eBpf(eBpfJmpOp::LtS)
                } else {
                    eBpfJmpOpExt::eBpf(eBpfJmpOp::Lt)
                }
            }
            RelOp::Le => {
                if ctx.load.is_signed() {
                    eBpfJmpOpExt::eBpf(eBpfJmpOp::LeS)
                } else {
                    eBpfJmpOpExt::eBpf(eBpfJmpOp::Lt)
                }
            }
            RelOp::Ne => eBpfJmpOpExt::eBpf(eBpfJmpOp::Ne),
        };

        self.filter.add(eBpfInsn::jmp(
            j_type,
            JmpInfo::Reg {
                src: BpfReg::R7,
                dst: BpfReg::R5,
                off: 2,
            },
        ));

        self.filter.add(eBpfInsn::mov(MovInfo::Imm {
            dst: BpfReg::R0,
            imm: 0x00,
        }));

        tf_list.push_false(self.filter.len());

        self.filter.add_multi(&[
            eBpfInsn::jmp_a(0),
            eBpfInsn::mov(MovInfo::Imm {
                dst: BpfReg::R0,
                imm: 0x40000,
            }),
        ]);

        tf_list.push_true(self.filter.len());

        self.filter.add(eBpfInsn::jmp_a(0));

        Ok(tf_list)
    }

    fn add_expr(&mut self, field: &LhsNode, relop: RelOp, rval: Rhs) -> Result<TFlist> {
        let sub_node = Self::walk_btf_node(self.btf, &self.btf_type, &field.member, self.offt)?;
        let tf_list;

        match sub_node {
            Some((offset, bfs, snode)) => {
                if let Some(tgt) = &field.cast {
                    bail!("trying to cast a leaf member into {tgt}");
                }

                self.btf_type = snode;
                self.offt = offset;

                let ctx = self.finalize_expr(field, relop, rval, bfs)?;

                if ctx.load.nmemb > 0 {
                    tf_list = self.emit_bytes_expr(ctx)?;
                } else {
                    tf_list = self.emit_num_expr(ctx)?;
                }
            }
            None => bail!(
                "field {} not found in type {}",
                field.member,
                self.btf_type.name()
            ),
        }

        Ok(tf_list)
    }

    fn add_lval_next(&mut self, field: &LhsNode) -> Result<Option<TFlist>> {
        let sub_node = Self::walk_btf_node(self.btf, &self.btf_type, &field.member, self.offt)?;
        let mut tf_list = None;

        match sub_node {
            Some((offset, _bfs, snode)) => {
                // Type::Ptr needs indirect actions (Load *Ptr).
                //   Offset need to be reset
                // Named Structs or Union return (level matched) but are
                //   still part of the parent Struct, so the offset has to
                //   be preserved.
                let (ind, x) = Self::next_walkable(self.btf, snode, field.cast.is_some())?;
                let one = 1;

                match ind.cmp(&one) {
                    std::cmp::Ordering::Equal => {
                        self.offt = 0;
                        // Emit load Ptr
                        tf_list = Some(self.emit_load_ptr(offset / 8, field.mask)?);
                    }
                    std::cmp::Ordering::Greater => {
                        bail!("pointers of pointers are not supported")
                    }
                    _ => {
                        if field.mask != 0 {
                            bail!("intermediate members masking is only supported for pointers and unsigned numbers");
                        }
                        self.offt = offset
                    }
                }

                if let Some(tgt) = &field.cast {
                    let mut types = self
                        .btf_info
                        .resolve_types_by_name(tgt)
                        .map_err(|e| anyhow!("unable to resolve data type: {e}"))?;

                    (self.btf, self.btf_type) = match types.iter_mut().find(|(_, t)| {
                        matches!(t, Type::Union(_))
                            || matches!(t, Type::Struct(_))
                            || matches!(t, Type::Typedef(_))
                    }) {
                        Some((ref btf, r#type)) => {
                            let nw = Self::next_walkable(btf, r#type.clone(), false)?;
                            if nw.0 > 0 {
                                bail!(
                                    "cast type ({tgt}: {}) cannot be an alias to a pointer",
                                    r#type.name()
                                );
                            }
                            (btf, nw.1)
                        }
                        None => bail!("Could not resolve {tgt} to a struct or typedef"),
                    };
                } else {
                    self.btf_type = x.clone();
                }
            }
            None => bail!(
                "field {} not found in type {}",
                field.member,
                self.btf_type.name()
            ),
        }

        Ok(tf_list)
    }

    fn check_one_walkable(t: &Type, ind: &mut u8, casted: bool) -> Result<bool> {
        match t {
            Type::Int(i)
                if i.size() == std::mem::size_of::<*const std::ffi::c_void>() && casted =>
            {
                *ind += 1
            }
            Type::Ptr(_) => *ind += 1,
            Type::Struct(_) | Type::Union(_) => {
                return Ok(true);
            }
            Type::Typedef(_)
            | Type::Volatile(_)
            | Type::Const(_)
            | Type::Restrict(_)
            | Type::DeclTag(_)
            | Type::TypeTag(_) => (),
            _ => bail!(
                "unexpected non-walkable type ({}) while walking struct members",
                t.name()
            ),
        };

        Ok(false)
    }

    // R1 = skb
    // R7 = Base address
    fn emit_load_ptr(&mut self, offt: u32, mask: u64) -> Result<TFlist> {
        let mut tf_list = TFlist::default();

        self.filter.add_multi(&[
            eBpfInsn::mov(MovInfo::Reg {
                src: BpfReg::FP,
                dst: BpfReg::ARG1,
            }),
            eBpfInsn::alu(
                BpfAluOp::Add,
                AluInfo::Imm {
                    dst: BpfReg::ARG1,
                    imm: -8,
                },
            ),
            eBpfInsn::mov(MovInfo::Imm {
                dst: BpfReg::ARG2,
                imm: 8,
            }),
            eBpfInsn::alu(
                BpfAluOp::Add,
                AluInfo::Imm {
                    dst: BpfReg::R7,
                    imm: offt as i32,
                },
            ),
            eBpfInsn::mov(MovInfo::Reg {
                src: BpfReg::R7,
                dst: BpfReg::R3,
            }),
            eBpfInsn::call(bpf_sys::bpf_func_id::BPF_FUNC_probe_read_kernel as u32),
        ]);

        self.filter.add(eBpfInsn::jmp(
            eBpfJmpOpExt::Bpf(BpfJmpOp::Eq),
            JmpInfo::Imm {
                dst: BpfReg::R0,
                off: 2,
                imm: 0,
            },
        ));
        self.filter.add(eBpfInsn::mov(MovInfo::Imm {
            dst: BpfReg::R0,
            imm: 0,
        }));

        tf_list.push_false(self.filter.len());
        self.filter.add_multi(&[
            eBpfInsn::jmp_a(0),
            eBpfInsn::ld(
                LdInfo::Reg {
                    src: BpfReg::FP,
                    dst: BpfReg::R7,
                    off: -8,
                },
                BpfSize::Double,
            ),
        ]);

        if mask > 0 {
            self.filter.add_multi(&[
                eBpfInsn::mov(MovInfo::Imm {
                    dst: BpfReg::R5,
                    imm: (mask >> 32) as i32,
                }),
                eBpfInsn::alu(
                    BpfAluOp::Lsh,
                    AluInfo::Imm {
                        dst: BpfReg::R5,
                        imm: 32,
                    },
                ),
                eBpfInsn::alu(
                    BpfAluOp::Or,
                    AluInfo::Imm {
                        dst: BpfReg::R5,
                        imm: (mask & 0xffffffff) as i32,
                    },
                ),
                eBpfInsn::alu(
                    BpfAluOp::And,
                    AluInfo::Reg {
                        src: BpfReg::R5,
                        dst: BpfReg::R7,
                    },
                ),
            ]);
        }

        Ok(tf_list)
    }

    // Return all comparable and walkable types Ptr, Int, Array, Enum[64],
    // Struct, Union
    fn next_walkable(btf: &Btf, r#type: Type, casted: bool) -> Result<(u8, Type)> {
        let btf_type = r#type.as_btf_type();
        let mut ind = 0;

        // Return early if r#type is already walkable
        if Self::check_one_walkable(&r#type, &mut ind, casted)? {
            return Ok((0, r#type));
        } else if casted {
            return Ok((ind, r#type));
        }

        let btf_type = btf_type.ok_or_else(|| {
            anyhow!("cannot convert to iterable type while retrieving next walkable")
        })?;

        for x in btf.type_iter(btf_type) {
            if Self::check_one_walkable(&x, &mut ind, casted)? {
                return Ok((ind, x));
            }
        }

        bail!("failed to retrieve next walkable object.")
    }

    fn walk_btf_node(
        btf: &Btf,
        r#type: &Type,
        node_name: &str,
        offset: u32,
    ) -> Result<Option<(u32, Option<u32>, Type)>> {
        let r#type = match r#type {
            Type::Struct(r#struct) | Type::Union(r#struct) => r#struct,
            _ => {
                return Ok(None);
            }
        };

        for member in r#type.members.iter() {
            let fname = btf.resolve_name(member)?;
            let ty = btf.resolve_chained_type(member)?;

            if fname.eq(node_name) {
                return Ok(Some((
                    offset + member.bit_offset(),
                    member.bitfield_size(),
                    ty,
                )));
            } else if fname.is_empty() {
                match ty {
                    s @ Type::Struct(_) | s @ Type::Union(_) => {
                        match Self::walk_btf_node(btf, &s, node_name, offset + member.bit_offset())?
                        {
                            Some((offt, bfs, x)) => return Ok(Some((offt, bfs, x))),
                            _ => continue,
                        }
                    }
                    _ => return Ok(None),
                };
            }
        }

        Ok(None)
    }

    fn process_parsed(&mut self, lhs: &Lhs, op: RelOp, rhs: Rhs) -> Result<TFlist> {
        let mut tf_list = TFlist::default();

        for (pos, lhs_member) in lhs.iter().enumerate() {
            if pos == lhs.len() - 1 {
                let tf_expr = self.add_expr(lhs_member, op, rhs)?;
                tf_list.merge_lists(&tf_expr);
                break;
            }

            let tf_walkable = self.add_lval_next(lhs_member)?;
            if let Some(list) = tf_walkable {
                tf_list.merge_lists(&list);
            }
        }

        Ok(tf_list)
    }
}

#[derive(Default)]
pub(crate) struct FilterMeta {
    filter: eBpfProg,
}

impl FilterMeta {
    fn new() -> Self {
        Self {
            ..Default::default()
        }
    }

    pub(crate) fn to_bytes(&self) -> Vec<u8> {
        self.filter.to_bytes()
    }

    fn backpatch(&mut self, list: &[usize], target: usize) -> Result<()> {
        let mut insn;

        for pos in list.iter() {
            if target > *pos {
                insn = self.filter.get_raw_insn_mut(*pos)?;
                insn.set_off_raw(i16::try_from(target - *pos - 1)?);
            }
        }

        Ok(())
    }

    fn generate(&mut self, expr: &AstNode) -> Result<TFlist> {
        let btf_info = &inspector()?.kernel.btf;

        match expr {
            AstNode::BooleanExpr { lhs, op, rhs } => {
                let l_list = self.generate(lhs)?;
                let pos = self.filter.len();
                let r_list = self.generate(rhs)?;

                match op {
                    BooleanOp::And => {
                        self.backpatch(&l_list.true_list, pos)?;

                        let mut tf_list =
                            TFlist::from_true_false(&r_list.true_list, &l_list.false_list);
                        tf_list.merge_false(&r_list.false_list);
                        Ok(tf_list)
                    }
                    BooleanOp::Or => {
                        self.backpatch(&l_list.false_list, pos)?;

                        let mut tf_list =
                            TFlist::from_true_false(&l_list.true_list, &r_list.false_list);
                        tf_list.merge_true(&r_list.true_list);
                        Ok(tf_list)
                    }
                }
            }
            AstNode::RelOpExpr { lhs, op, rhs } => {
                let mut me = MetaExpr::new(btf_info, "sk_buff", self.filter.len() == 0)?;
                let mut tf = me.process_parsed(lhs, *op, rhs.clone())?;
                // For every expression the related codeblock gets
                // emitted and true/false lists have offsets relative
                // to the block itself.
                // Fix them up making them relative the the whole
                // program, instead
                tf.fixup(self.filter.len());
                self.filter.append_prog(&me.filter);
                Ok(tf)
            }
        }
    }

    pub(crate) fn from_string(fs: String) -> Result<FilterMeta> {
        let mut pairs = ParserMeta::parse(Rule::program, &fs)?;
        let ast = ParserMeta::parse_expr(
            pairs
                .next()
                .ok_or_else(|| anyhow!("failed to retrieve inner pairs"))?,
        )?;

        let mut mf = FilterMeta::new();
        let tf_list = mf.generate(&ast)?;

        let exit_label = mf.filter.len() - 1;

        mf.backpatch(&tf_list.true_list, exit_label)?;
        mf.backpatch(&tf_list.false_list, exit_label)?;

        // The self test infrastructure doesn't rely on statically
        // compiled template where the filter gets injected. To avoid
        // verification error an exit instruction is required in order
        // to make it process properly by the vm.
        #[cfg(test)]
        mf.filter.add(eBpfInsn::exit());

        Ok(mf)
    }

    #[cfg(feature = "debug")]
    pub(crate) fn disasm(&self) {
        self.filter.disasm();
    }
}

#[cfg(test)]
mod tests {
    use std::{mem, slice};

    use rbpf;
    use test_case::test_case;

    use super::*;

    mod skb_gen {
        #![allow(warnings)]
        include!(concat!(env!("CARGO_MANIFEST_DIR"), "/test_data/skb_gen.rs"));
    }
    use skb_gen::{net_device, nf_conn, sk_buff};

    use crate::core::filters::{bpf_probe_read_kernel_helper, bpf_probe_read_kernel_str_helper};

    #[test]
    fn meta_negative_generic() {
        // sk_buff is mandatory.
        assert!(FilterMeta::from_string("dev.mark == 0xc0de".to_string()).is_err());
        // unsupported type (struct)
        assert!(FilterMeta::from_string("sk_buff.dev == 0xbad".to_string()).is_err());
        // pointers to int are not supported
        assert!(FilterMeta::from_string("sk_buff.dev.pcpu_refcnt == 0xbad".to_string()).is_err());
    }

    #[test_case("==" ; "op is eq")]
    #[test_case("!=" ; "op is ne")]
    #[test_case("<" ; "op is lt")]
    #[test_case("<=" ; "op is le")]
    #[test_case(">" ; "op is gt")]
    #[test_case(">=" ; "op is ge")]
    fn meta_negative_filter_string(op_str: &'static str) {
        // Target string must be quoted.
        assert!(
            FilterMeta::from_string(format!("sk_buff.dev.name {op_str} dummy0").to_string())
                .is_err()
        );
        // Only RelOp::{Eq,Ne} are allowed for strings.
        if op_str != "==" && op_str != "!=" {
            assert!(FilterMeta::from_string(format!("sk_buff.dev.name {op_str} 'dummy0'")).is_err())
        }
        // Target value must be a string.
        assert!(FilterMeta::from_string("sk_buff.mark {op_str} 'dummy0'".to_string()).is_err());
    }

    #[test_case("==" ; "op is eq")]
    #[test_case("!=" ; "op is ne")]
    fn meta_filter_string(op_str: &'static str) {
        assert!(
            FilterMeta::from_string(format!("sk_buff.dev.name {op_str} 'dummy0'").to_string())
                .is_ok()
        );
        assert!(FilterMeta::from_string(
            format!(r#"sk_buff.dev.name {op_str} "dummy0""#).to_string()
        )
        .is_ok());
    }

    #[test]
    fn meta_negative_filter_u32() {
        assert!(FilterMeta::from_string("sk_buff.mark == -1".to_string()).is_err());
        // u32::MAX + 1 is an allowed value for u32 (user has to specify values inside the range).
        assert!(FilterMeta::from_string("sk_buff.mark == 4294967296".to_string()).is_ok());
    }

    #[test_case("==" ; "op is eq")]
    #[test_case("!=" ; "op is ne")]
    #[test_case("<" ; "op is lt")]
    #[test_case("<=" ; "op is le")]
    #[test_case(">" ; "op is gt")]
    #[test_case(">=" ; "op is ge")]
    fn meta_filter_u32(op_str: &'static str) {
        assert!(
            FilterMeta::from_string(format!("sk_buff.mark {op_str} 0xc0de").to_string()).is_ok()
        );
    }

    #[test_case("==" ; "op is eq")]
    #[test_case("!=" ; "op is ne")]
    #[test_case("<" ; "op is lt")]
    #[test_case("<=" ; "op is le")]
    #[test_case(">" ; "op is gt")]
    #[test_case(">=" ; "op is ge")]
    fn meta_filter_bitfields(op_str: &'static str) {
        assert!(
            FilterMeta::from_string(format!("sk_buff.pkt_type {op_str} 1").to_string()).is_ok()
        );
    }

    // Only validates for what type of targets lhs-only expressions
    // are allowed. The offset extraction is not required as it is
    // already performed by previous tests.
    #[test_case("dev" => matches Err(_); "pointer")]
    #[test_case("dev.name" => matches Err(_); "string failure")]
    #[test_case("headers" => matches Err(_); "named struct failure")]
    #[test_case("mark" => matches Ok(_); "u32")]
    #[test_case("headers.skb_iif" => matches Ok(_); "signed int")]
    #[test_case("cloned" => matches Ok(_); "unsigned bitfield")]
    fn meta_filter_lhs_only(field: &'static str) -> Result<()> {
        let _ = FilterMeta::from_string(format!("sk_buff.{field}").to_string())?;
        Ok(())
    }

    #[test_case("dev.name:~0x00" => matches Err(_); "string failure")]
    #[test_case("dev:~0x00.mtu" => matches Ok(_); "pointer")]
    #[test_case("mark:0xff" => matches Ok(_); "u32")]
    #[test_case("mark:0x0" => matches Err(_); "zero hex mask failure")]
    #[test_case("mark:~0xffffffffffffffff" => matches Err(_); "bitwise not u64 hex mask failure")]
    #[test_case("mark:0b00" => matches Err(_); "zero bin mask failure")]
    #[test_case("mark:0" => matches Err(_); "mask format failure")]
    #[test_case("headers.skb_iif:0xbad" => matches Err(_); "signed int failure")]
    #[test_case("pkt_type:0x2" => matches Ok(_); "unsigned bitfield")]
    #[test_case("pkt_type:0b10" => matches Ok(_); "binary unsigned bitfield")]
    #[test_case("pkt_type:~0b10" => matches Ok(_); "bitwise not binary unsigned bitfield")]
    fn meta_filter_masks(expr: &'static str) -> Result<()> {
        let _ = FilterMeta::from_string(format!("sk_buff.{expr}").to_string())?;

        Ok(())
    }

    #[test]
    fn meta_filter_cast() {
        // Casting a field smaller than a pointer is not allowed
        assert!(FilterMeta::from_string("sk_buff.cloned:~0x0:nf_conn".to_string()).is_err());
        assert!(FilterMeta::from_string("sk_buff.len:~0x0:nf_conn".to_string()).is_err());
        assert!(FilterMeta::from_string("sk_buff.mac_len:~0x0:nf_conn".to_string()).is_err());
        // Arrays cannot be casted
        assert!(FilterMeta::from_string("sk_buff.cb:~0x0:nf_conn".to_string()).is_err());
        // Cast to non-walkable types is not allowed
        assert!(FilterMeta::from_string("sk_buff._nfct:~0x0:u32.mark".to_string()).is_err());
        // Casting a leaf is not allowed
        assert!(FilterMeta::from_string("sk_buff._nfct.mark:~0x0:nf_conn".to_string()).is_err());

        assert!(FilterMeta::from_string("sk_buff._nfct:~0x0:nf_conn.mark".to_string()).is_ok())
    }

    // Only validates for what type of targets lhs-only expressions
    // are allowed. The offset extraction is not required as it is
    // already performed by previous tests.
    #[test_case("sk_buff.dev.name == 'lo' or sk_buff.mark > 0" => matches Ok(_); "simple or")]
    #[test_case("sk_buff.dev.name == 'lo' || sk_buff.mark > 0" => matches Ok(_); "simple or alt syntax")]
    #[test_case("(sk_buff.dev.name == 'lo' or sk_buff.mark > 0)" => matches Ok(_); "simple or with paretheses")]
    #[test_case("sk_buff.dev.name == 'lo' or (sk_buff.mark > 0 and sk_buff._nfct:~0x7:nf_conn.proto.tcp.state == 0x1)" => matches Ok(_); "single or with single and")]
    #[test_case("sk_buff.dev.name == 'lo' || (sk_buff.mark > 0 && sk_buff._nfct:~0x7:nf_conn.proto.tcp.state == 0x1)" => matches Ok(_); "single or with single and alt syntax")]
    #[test_case("(sk_buff.dev.name == 'lo' or sk_buff._nfct:~0x7:nf_conn.status:0xf == 0xa) and (sk_buff.mark > 0 and sk_buff._nfct:~0x7:nf_conn.proto.tcp.state == 0x1)" => matches Ok(_); "double or with double and")]
    #[test_case("(sk_buff.dev.name == 'lo' or sk_buff._nfct:~0x7:nf_conn.status:0xf == 0xa and (sk_buff.mark > 0 and sk_buff._nfct:~0x7:nf_conn.proto.tcp.state == 0x1)" => matches Err(_); "double or with double and paren mismatch")]
    #[test_case("(sk_buff._nfct:~0x7:nf_conn.status:0xf == 0xa and (sk_buff.mark > 0 or sk_buff._nfct:~0x7:nf_conn.proto.tcp.state == 0x1)) or sk_buff.dev.name == 'lo'" => matches Ok(_); "single and with double or")]
    #[test_case("((sk_buff._nfct:~0x7:nf_conn.status:0xf == 0xa and (sk_buff.mark > 0 or sk_buff._nfct:~0x7:nf_conn.proto.tcp.state == 0x1)) or sk_buff.dev == 'lo'" => matches Err(_); "single and with double or with type mismatch")]
    #[test_case("sk_buff.mark > 0 and sk_buff._nfct.proto.tcp.state == 0x1" => matches Err(_); "single and with unknown type")]
    fn meta_filter_boolean_expressions(bool_expr: &'static str) -> Result<()> {
        let _ = FilterMeta::from_string(bool_expr.to_string())?;
        Ok(())
    }

    // Applies generic initializations to the skb.
    // The following describes the fields of sk_buff that are being set
    // in this test. The offsets are based on the architecture for which the
    // bindings were generated.
    //
    // +----------------+-------------+------------+-----------+
    // | Field          | Byte Offset | Bit Offset | Size      |
    // +----------------+-------------+------------+-----------+
    // | len            | 112         | 0          | 4 bytes   |
    // | queue_mapping  | 124         | 0          | 2 bytes   |
    // | cloned         | 126         | 0          | 1 bit     |
    // | pkt_type       | 128         | 0          | 3 bits    |
    // | nf_trace       | 128         | 4          | 1 bit     |
    // | ip_summed      | 128         | 5          | 2 bits    |
    // | vlan_tci       | 154         | 0          | 2 bytes   |
    // +----------------+-------------+------------+-----------+
    // net_device.name is a fixed-size (16) array within struct net_device.
    fn init_sk_buff() -> (sk_buff, Box<net_device>, Box<nf_conn>) {
        let mut skb: sk_buff = Default::default();
        let mut net_dev = Box::new(net_device::default());
        let mut nfct = Box::new(nf_conn::default());
        let name_bytes = "verylongtruncat".as_bytes();

        // The string is 15 characters long. Taking 15 anyways as this
        // has no impact.
        name_bytes
            .iter()
            .take(15)
            .enumerate()
            .for_each(|(i, &b)| net_dev.name[i] = b as ::std::os::raw::c_char);

        nfct.mark = 3;

        let nfct_ptr = &*nfct as *const nf_conn as u64;
        skb._nfct = nfct_ptr | 2;

        skb.len = 2048;
        skb.queue_mapping = 3;

        unsafe {
            skb.set_cloned(1);
            skb.__bindgen_anon_5
                .__bindgen_anon_1
                .as_mut()
                .__bindgen_anon_2
                .__bindgen_anon_1
                .vlan_tci = 1234;
            skb.__bindgen_anon_5
                .__bindgen_anon_1
                .as_mut()
                .set_ip_summed(0b11);
            skb.__bindgen_anon_5
                .__bindgen_anon_1
                .as_mut()
                .set_nf_trace(1);
            skb.__bindgen_anon_5
                .__bindgen_anon_1
                .as_mut()
                .set_pkt_type(0b110);
        }

        // Assign the net_device pointer to skb.dev
        skb.__bindgen_anon_1.__bindgen_anon_1.__bindgen_anon_1.dev = &mut *net_dev;

        (skb, net_dev, nfct)
    }

    #[test_case("sk_buff.cloned == 1" => true; "simple single bit dec")]
    #[test_case("sk_buff.cloned == 0x1" => true; "simple single bit hex")]
    #[test_case("sk_buff.cloned == 0b1" => true; "simple single bit bin")]
    #[test_case("sk_buff.cloned:0b1 == 0b1" => true; "simple single bit mask")]
    #[test_case("sk_buff.cloned == 0x1 and sk_buff.ip_summed == 0b11" => true; "two bitfields (1b, 2b)")]
    #[test_case("sk_buff.ip_summed:0b10 == 0b10 and sk_buff.ip_summed:0b01 == 0b01" => true; "two bitfields mask out (bit0, bit1)")]
    #[test_case("sk_buff.ip_summed:0b10 == 0b10 and sk_buff.pkt_type > 0b001" => true; "two bitfields with ge (true and true)")]
    #[test_case("sk_buff.ip_summed:0b10 == 0b10 or sk_buff.pkt_type == 0b001" => true; "two bitfields with true or false")]
    #[test_case("sk_buff.pkt_type <= 0b001 or sk_buff.ip_summed:0b10 == 0b10" => true; "two bitfields with false or true")]
    #[test_case("sk_buff.pkt_type == 0b110 and sk_buff.nf_trace == 0b01" => true; "two bitfields with true and true on the same unit")]
    #[test_case("sk_buff.vlan_tci == 1 or sk_buff.dev.name == 'verylongtruncatedname'" => false; "negative two fields false or false")]
    #[test_case("sk_buff._nfct:0x7 == 0x2 and sk_buff._nfct:~0x7:nf_conn.mark > 2" => true; "two fields with cast and mask+cast (true and true)")]
    #[test_case("sk_buff._nfct:0x7 == 0x2 and sk_buff._nfct:~0x7:nf_conn.mark != 3" => false; "negative two fields with cast and mask+cast (true and true)")]
    #[test_case("sk_buff.vlan_tci == 1 and sk_buff.dev.name == 'foo' or sk_buff.dev.name == 'verylongtruncat'" => true; "three field default precedence (false and false) or true")]
    #[test_case("sk_buff.vlan_tci == 1 and (sk_buff.dev.name == 'foo' or sk_buff.dev.name == 'verylongtruncat')" => false; "negative three field false and (false or true)")]
    fn meta_filter_runtime(expr: &'static str) -> bool {
        let (skb, _net_dev, _nfct) = init_sk_buff();

        let mf = FilterMeta::from_string(format!("{expr}").to_string());
        let mf = mf.unwrap();

        let mem = Vec::new();

        let mbuff = unsafe {
            slice::from_raw_parts((&skb as *const _) as *const u8, mem::size_of::<sk_buff>())
        };
        let prog = &mf.to_bytes();

        let mut vm = rbpf::EbpfVmMbuff::new(Some(prog)).unwrap();
        vm.register_helper(113, bpf_probe_read_kernel_helper)
            .unwrap();
        vm.register_helper(115, bpf_probe_read_kernel_str_helper)
            .unwrap();
        vm.execute_program(&mem, &mbuff).unwrap() != 0
    }
}
