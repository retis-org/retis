//! # FilterMeta
//!
//! Object for metadata filtering. It takes as input a filter string
//! under the form struct_name.member1.member2.[...].leafmember
//! generating a sequence of actions.

use anyhow::{anyhow, bail, Result};
use btf_rs::*;
use plain::Plain;
use regex::Regex;

use crate::core::inspect::inspector;

const META_OPS_MAX: u32 = 32;
const META_TARGET_MAX: usize = 32;
const MF_RE: &str = r#"([a-zA-Z_][a-zA-Z0-9_]*(?:\.[a-zA-Z_][a-zA-Z0-9_]*){1,})[\s]{1,}(==|!=|>=|<=|<|>)[\s]{1,}(0x[0-9a-fA-F]+|-?[0-9]+|"[ -~]*"|'[ -~]*'|[a-zA-Z_][a-zA-Z0-9_]*){1}"#;

const PTR_BIT: u8 = 1 << 6;
const SIGN_BIT: u8 = 1 << 7;

#[derive(Eq, PartialEq)]
enum MetaCmp {
    Eq = 0,
    Gt = 1,
    Lt = 2,
    Ge = 3,
    Le = 4,
    Ne = 5,
}

impl MetaCmp {
    fn from_str(op: &str) -> Result<MetaCmp> {
        let op = match op {
            "==" => MetaCmp::Eq,
            ">" => MetaCmp::Gt,
            "<" => MetaCmp::Lt,
            ">=" => MetaCmp::Ge,
            "<=" => MetaCmp::Le,
            "!=" => MetaCmp::Ne,
            _ => bail!("unknown comparison operator ({op})."),
        };

        Ok(op)
    }
}

enum MetaType {
    Char = 1,
    Short = 2,
    Int = 3,
    Long = 4,
}

#[repr(C)]
#[derive(Copy, Clone)]
union MetaData {
    bin: [u8; META_TARGET_MAX],
    long: u64,
}

#[repr(C)]
#[derive(Copy, Clone)]
struct MetaTarget {
    u: MetaData,
    sz: u8,
    cmp: u8,
}

#[repr(C)]
#[derive(Copy, Clone, Debug)]
struct MetaLoad {
    // Type of data we're going to load
    // bit 0-4: [char|short|int|long], bit5: reserved, bit6: is_ptr, bit7: sign
    r#type: u8,
    // Usually zero.
    // nmemb > 0 is valid iff MetaOp::r#type == MetaType::Char
    nmemb: u8,
    // Byte offset if bf_size is zero. Bit offset otherwise.
    offt: u16,
    // Zero for no bitfield.
    bf_size: u8,
}

impl MetaLoad {
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
#[derive(Copy, Clone)]
pub(crate) union MetaOp {
    l: MetaLoad,
    t: MetaTarget,
}
unsafe impl Plain for MetaOp {}

impl MetaOp {
    fn bail_on_arr(load: &MetaLoad, tn: &str) -> Result<()> {
        if load.is_arr() {
            bail!("array of {tn} are not supported.");
        }

        Ok(())
    }

    fn bail_on_ptr(load: &MetaLoad, tn: &str) -> Result<()> {
        if load.is_ptr() {
            bail!("pointers to {tn} are not supported.");
        }

        Ok(())
    }

    fn emit_load(btf: &Btf, r#type: &Type, offt: u32, bfs: u32) -> Result<MetaOp> {
        let mut op: MetaOp = unsafe { std::mem::zeroed::<_>() };
        let lop = unsafe { &mut op.l };
        let mut t = r#type.clone();
        let mut type_iter = btf.type_iter(
            r#type
                .as_btf_type()
                .ok_or_else(|| anyhow!("Unable to retrieve iterable BTF type"))?,
        );

        loop {
            match t {
                Type::Ptr(_) => {
                    Self::bail_on_ptr(lop, t.name())?;
                    lop.r#type |= PTR_BIT
                }
                Type::Array(ref a) => {
                    // Pointers to array are not supported.
                    Self::bail_on_ptr(lop, t.name())?;
                    // Retrieve the number of elements
                    lop.nmemb = u8::try_from(a.len())?;
                }
                Type::Enum(ref e) => {
                    // Pointers to enum are not supported.
                    Self::bail_on_ptr(lop, t.name())?;
                    // Always assume size 4B
                    lop.r#type |= MetaType::Int as u8;
                    if e.is_signed() {
                        lop.r#type |= SIGN_BIT;
                    }
                }
                Type::Enum64(ref e64) => {
                    // Pointers to enum64 are not supported.
                    Self::bail_on_ptr(lop, t.name())?;
                    // Always assume size 8B
                    lop.r#type |= MetaType::Long as u8;
                    if e64.is_signed() {
                        lop.r#type |= SIGN_BIT;
                    }
                }
                Type::Int(ref i) => {
                    if i.is_signed() {
                        lop.r#type |= SIGN_BIT;
                    }

                    match i.size() {
                        8 => lop.r#type |= MetaType::Long as u8,
                        4 => lop.r#type |= MetaType::Int as u8,
                        2 => lop.r#type |= MetaType::Short as u8,
                        1 => lop.r#type |= MetaType::Char as u8,
                        _ => bail!("unsupported type."),
                    }

                    // Array or Ptr are not supported for types other than
                    // chars
                    if !lop.is_byte() {
                        Self::bail_on_arr(lop, t.name())?;
                        Self::bail_on_ptr(lop, t.name())?;
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

        lop.bf_size = u8::try_from(bfs)?;
        lop.offt = u16::try_from(offt)?;

        if bfs == 0 {
            lop.offt /= 8;
        }

        Ok(op)
    }

    fn emit_target(lmo: MetaLoad, rval: Rval, cmp_op: MetaCmp) -> Result<MetaOp> {
        let mut op: MetaOp = unsafe { std::mem::zeroed::<_>() };
        let top = unsafe { &mut op.t };

        if lmo.is_ptr() || lmo.nmemb > 0 {
            if cmp_op != MetaCmp::Eq && cmp_op != MetaCmp::Ne {
                bail!("wrong comparison operator. Only '==' and '!=' are supported for strings.");
            }

            if let Rval::Str(val) = rval {
                let rval_len = val.len();
                let bin = unsafe { &mut top.u.bin };
                if rval_len >= bin.len() {
                    bail!("invalid rval size (max {}).", bin.len() - 1);
                }

                bin[..rval_len].copy_from_slice(val.as_bytes());
                top.sz = rval_len as u8;
            } else {
                bail!("invalid target value for array or ptr type. Only strings are supported.");
            }
        } else if lmo.is_num() {
            top.u.long = match rval {
                Rval::Dec(val) => {
                    if val.starts_with('-') {
                        if !lmo.is_signed() {
                            bail!("invalid target value (value is signed while type is unsigned)");
                        }

                        val.parse::<i64>()? as u64
                    } else {
                        val.parse::<u64>()?
                    }
                }
                Rval::Hex(val) => u64::from_str_radix(&val, 16)?,
                _ => bail!("invalid target value (neither decimal nor hex)."),
            };

            top.sz = if lmo.is_byte() {
                1
            } else if lmo.is_short() {
                2
            } else if lmo.is_int() {
                4
            } else if lmo.is_long() {
                8
            } else {
                bail!("unexpected numeric type");
            };
        }

        top.cmp = cmp_op as u8;

        Ok(op)
    }
}

fn walk_btf_node(
    btf: &Btf,
    r#type: &Type,
    node_name: &str,
    offset: u32,
) -> Option<(u32, Option<u32>, Type)> {
    let r#type = match r#type {
        Type::Struct(r#struct) | Type::Union(r#struct) => r#struct,
        _ => {
            return None;
        }
    };

    for member in r#type.members.iter() {
        let fname = btf.resolve_name(member).unwrap();
        if fname.eq(node_name) {
            match btf.resolve_chained_type(member).ok() {
                Some(ty) => {
                    return Some((offset + member.bit_offset(), member.bitfield_size(), ty))
                }
                None => return None,
            }
        } else if fname.is_empty() {
            let s = btf.resolve_chained_type(member).ok();
            let ty = s.as_ref()?;

            match ty {
                s @ Type::Struct(_) | s @ Type::Union(_) => {
                    match walk_btf_node(btf, s, node_name, offset + member.bit_offset()) {
                        Some((offt, bfs, x)) => return Some((offt, bfs, x)),
                        _ => continue,
                    }
                }
                _ => return None,
            };
        }
    }

    None
}

#[derive(Eq, PartialEq)]
enum Rval {
    Dec(String),
    Hex(String),
    Str(String),
    // Btf,
}

impl Rval {
    fn from_str(rval: &str) -> Result<Rval> {
        let detected = if (rval.starts_with('"') && rval.ends_with('"'))
            || (rval.starts_with('\'') && rval.ends_with('\''))
        {
            Rval::Str(rval[1..rval.len() - 1].to_string())
        } else {
            let base = if rval.starts_with("0x") {
                Rval::Hex(rval.trim_start_matches("0x").to_string())
            } else {
                Rval::Dec(rval.to_string())
            };

            base
        };

        Ok(detected)
    }
}

#[derive(Clone)]
pub(crate) struct FilterMeta(pub(crate) Vec<MetaOp>);

impl FilterMeta {
    fn check_one_walkable(t: &Type, ind: &mut u8) -> Result<bool> {
        match t {
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
            _ => bail!("unexpected type ({})", t.name()),
        };

        Ok(false)
    }

    // Return all comparable and walkable types Ptr, Int, Array, Enum[64],
    // Struct, Union
    fn next_walkable(btf: &Btf, r#type: Type) -> Result<(u8, Type)> {
        let btf_type = r#type.as_btf_type();
        let mut ind = 0;

        // Return early if r#type is already walkable
        if Self::check_one_walkable(&r#type, &mut ind)? {
            return Ok((0, r#type));
        }

        let btf_type = btf_type.ok_or_else(|| {
            anyhow!("cannot convert to iterable type while retrieving next walkable")
        })?;

        for x in btf.type_iter(btf_type) {
            if Self::check_one_walkable(&x, &mut ind)? {
                return Ok((ind, x));
            }
        }

        bail!("failed to retrieve next walkable object.")
    }

    pub(crate) fn from_string(fstring: String) -> Result<Self> {
        let btf = &inspector()?.kernel.btf;
        let mut ops: Vec<_> = Vec::new();
        let mut offt: u32 = 0;
        let mut stored_offset: u32 = 0;
        let mut stored_bf_size: u32 = 0;

        // Check the correctness, perform preliminar checks for the
        // operator type against the target (e.g. >= against number).
        //
        // Once the lmo type is known, compare the rval against the
        // lmo type (e.g. INT against LONG, sign)
        let re = Regex::new(MF_RE)?;

        let Some((_, [lval, op, rval])) = re.captures(&fstring).map(|caps| caps.extract()) else {
            bail!("Invalid filter expression.")
        };

        let mut fields: Vec<_> = lval.split('.').collect();

        // The captures ensure at least two elements are present
        let init_sym = fields.remove(0);

        if !init_sym.eq("sk_buff") {
            bail!("unsupported data structure {init_sym}. sk_buff must be used.")
        }

        let mut types = btf
            .resolve_types_by_name(init_sym)
            .map_err(|e| anyhow!("unable to resolve sk_buff data type {e}"))?;

        let (btf, ref mut r#type) =
            match types.iter_mut().find(|(_, t)| matches!(t, Type::Struct(_))) {
                Some(r#struct) => r#struct,
                None => bail!("Could not resolve {init_sym} to a struct"),
            };

        for (pos, field) in fields.iter().enumerate() {
            let sub_node = walk_btf_node(btf, r#type, field, offt);
            match sub_node {
                Some((offset, bfs, snode)) => {
                    if pos < fields.len() - 1 {
                        // Type::Ptr needs indirect actions (Load *Ptr).
                        //   Offset need to be reset
                        // Named Structs or Union return (level matched) but are
                        //   still part of the parent Struct, so the offset has to
                        //   be preserved.
                        let (ind, x) = Self::next_walkable(btf, snode)?;
                        let one = 1;

                        match ind.cmp(&one) {
                            std::cmp::Ordering::Equal => {
                                offt = 0;
                                // Emit load Ptr
                                let mut op: MetaOp = unsafe { std::mem::zeroed::<_>() };
                                op.l.offt = u16::try_from(offset / 8)?;
                                op.l.r#type = PTR_BIT;
                                ops.push(op);
                            }
                            std::cmp::Ordering::Greater => {
                                bail!("pointers of pointers are not supported")
                            }
                            _ => offt = offset,
                        }

                        *r#type = x.clone();
                    } else {
                        *r#type = snode;
                    }

                    stored_offset = offset;
                    if let Some(bfs) = bfs {
                        stored_bf_size = bfs;
                    }
                }
                None => bail!("{field} not found or is a bitfield!"),
            }
        }

        let lmo = MetaOp::emit_load(btf, r#type, stored_offset, stored_bf_size)?;
        ops.push(lmo);

        let op = MetaCmp::from_str(op)?;
        let rval = Rval::from_str(rval)?;

        ops.insert(0, MetaOp::emit_target(unsafe { lmo.l }, rval, op)?);
        Ok(FilterMeta(ops))
    }
}

#[cfg_attr(test, allow(dead_code))]
pub(crate) fn init_meta_map() -> Result<libbpf_rs::MapHandle> {
    let opts = libbpf_sys::bpf_map_create_opts {
        sz: std::mem::size_of::<libbpf_sys::bpf_map_create_opts>() as libbpf_sys::size_t,
        ..Default::default()
    };

    Ok(libbpf_rs::MapHandle::create(
        libbpf_rs::MapType::Array,
        Some("filter_meta_map"),
        std::mem::size_of::<u32>() as u32,
        std::mem::size_of::<MetaOp>() as u32,
        META_OPS_MAX,
        &opts,
    )?)
}

#[cfg(test)]
mod tests {
    use super::*;

    use test_case::test_case;

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
    #[test_case("!=" ; "op is neq")]
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
        // Only MetaCmp::{Eq,Ne} are allowed for strings.
        if op_str != "==" && op_str != "!=" {
            assert!(FilterMeta::from_string(format!("sk_buff.dev.name {op_str} 'dummy0'")).is_err())
        }
        // Target value must be a string.
        assert!(FilterMeta::from_string("sk_buff.mark {op_str} 'dummy0'".to_string()).is_err());
    }

    #[test_case("==", MetaCmp::Eq ; "op is eq")]
    #[test_case("!=", MetaCmp::Ne ; "op is neq")]
    fn meta_filter_string(op_str: &'static str, op: MetaCmp) {
        let filter =
            FilterMeta::from_string(format!("sk_buff.dev.name {op_str} 'dummy0'").to_string())
                .unwrap();
        assert_eq!(filter.0.len(), 3);
        let meta_load = unsafe { &filter.0[1].l };
        assert!(!meta_load.is_num());
        assert!(!meta_load.is_arr());
        assert!(meta_load.is_ptr());
        assert_eq!(meta_load.offt, 16);

        let meta_load = unsafe { &filter.0[2].l };
        assert!(!meta_load.is_ptr());
        assert!(meta_load.is_byte());
        assert_eq!(meta_load.nmemb, 16);
        assert_eq!(meta_load.offt, 0);

        let meta_target = unsafe { &filter.0[0].t };
        assert_eq!(meta_target.cmp, op as u8);
        assert_eq!(meta_target.sz, 6);
        let target_str = std::str::from_utf8(unsafe { &meta_target.u.bin })
            .unwrap()
            .trim_end_matches(char::from(0));
        assert_eq!(target_str, "dummy0");
    }

    #[test]
    fn meta_negative_filter_u32() {
        assert!(FilterMeta::from_string("sk_buff.mark == -1".to_string()).is_err());
        // u32::MAX + 1 is an allowed value for u32 (user has to specify values inside the range).
        assert!(FilterMeta::from_string("sk_buff.mark == 4294967296".to_string()).is_ok());
    }

    #[test_case("==", MetaCmp::Eq ; "op is eq")]
    #[test_case("!=", MetaCmp::Ne ; "op is neq")]
    #[test_case("<", MetaCmp::Lt ; "op is lt")]
    #[test_case("<=", MetaCmp::Le ; "op is le")]
    #[test_case(">", MetaCmp::Gt ; "op is gt")]
    #[test_case(">=", MetaCmp::Ge ; "op is ge")]
    fn meta_filter_u32(op_str: &'static str, op: MetaCmp) {
        let filter =
            FilterMeta::from_string(format!("sk_buff.mark {op_str} 0xc0de").to_string()).unwrap();
        assert_eq!(filter.0.len(), 2);
        let meta_load = unsafe { &filter.0[1].l };
        assert!(!meta_load.is_arr());
        assert!(!meta_load.is_ptr());
        assert!(!meta_load.is_signed());
        assert!(meta_load.is_int());
        assert_eq!(meta_load.offt, 168);

        let meta_target = unsafe { &filter.0[0].t };
        assert_eq!(meta_target.cmp, op as u8);
        assert_eq!(meta_target.sz, 4);
        let target = unsafe { meta_target.u.long };
        assert_eq!(target, 0xc0de);
    }

    #[test_case("==", MetaCmp::Eq ; "op is eq")]
    #[test_case("!=", MetaCmp::Ne ; "op is neq")]
    #[test_case("<", MetaCmp::Lt ; "op is lt")]
    #[test_case("<=", MetaCmp::Le ; "op is le")]
    #[test_case(">", MetaCmp::Gt ; "op is gt")]
    #[test_case(">=", MetaCmp::Ge ; "op is ge")]
    fn meta_filter_bitfields(op_str: &'static str, op: MetaCmp) {
        let filter =
            FilterMeta::from_string(format!("sk_buff.pkt_type {op_str} 1").to_string()).unwrap();
        assert_eq!(filter.0.len(), 2);
        let meta_load = unsafe { &filter.0[1].l };
        assert!(!meta_load.is_arr());
        assert!(!meta_load.is_ptr());
        assert!(!meta_load.is_signed());
        assert!(meta_load.is_byte());
        assert_eq!(meta_load.bf_size, 3);
        // Offset in bits for bitfields
        assert_eq!(meta_load.offt, 1024);

        let meta_target = unsafe { &filter.0[0].t };
        assert_eq!(meta_target.cmp, op as u8);
        assert_eq!(meta_target.sz, 1);
        let target = unsafe { meta_target.u.long };
        assert_eq!(target, 1);
    }
}
