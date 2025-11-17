use anyhow::{bail, Result};
use btf_rs::{
    utils::collection::{BtfCollection, NamedBtf},
    Type,
};

use super::BASE_TEST_DIR;
use crate::core::kernel::Symbol;

/// Btf provides multi-module Btf lookups.
pub(crate) struct BtfInfo(BtfCollection);

impl BtfInfo {
    /// Parse kernel BTF files and create a Btf object.
    pub(super) fn new() -> Result<Self> {
        Ok(Self(BtfCollection::from_dir(
            match cfg!(test) || cfg!(feature = "benchmark") {
                false => "/sys/kernel/btf/".to_owned(),
                true => BASE_TEST_DIR.to_owned() + "/test_data/btf/",
            },
            "vmlinux",
        )?))
    }

    /// Get a function's number of arguments.
    pub(super) fn function_nargs(&self, symbol: &Symbol) -> Result<u32> {
        // Events have a void* pointing to the data as their first argument, which
        // does not end up in their context. We have to skip it. See
        // include/trace/bpf_probe.h in the __DEFINE_EVENT definition.
        let fix = match symbol {
            Symbol::Event(_) => 1,
            _ => 0,
        };

        let (_, proto) = self.find_prototype_btf(symbol)?;

        Ok((proto.parameters.len() - fix) as u32)
    }

    /// Given a function symbol, get all its parameter type names (as String)
    /// and their offsets.
    pub(crate) fn get_parameters(&self, symbol: &Symbol) -> Result<Vec<(u32, String)>> {
        let mut params = Vec::new();

        // Events have a void* pointing to the data as their first argument, which
        // does not end up in their context. We have to skip it. See
        // include/trace/bpf_probe.h in the __DEFINE_EVENT definition.
        let start = match symbol {
            Symbol::Event(_) => 1,
            _ => 0,
        };

        let (btf, mut proto) = self.find_prototype_btf(symbol)?;
        for (offset, param) in proto.parameters.drain(start..).enumerate() {
            params.push((offset as u32, Self::get_param(btf, &param)?));
        }

        Ok(params)
    }

    /// Look for a type based on its name and return both a Vec of Type objects
    /// as well as the NamedBtf object where it was found. Subsequent lookups
    /// based on this type (such as nested types by id) must be done on the
    /// returned NamedBtf object since type ids of different modules overlap.
    pub(crate) fn resolve_types_by_name(&self, name: &str) -> Result<Vec<(&NamedBtf, Type)>> {
        let types = self.0.resolve_types_by_name(name)?;
        if types.is_empty() {
            bail!("No type linked to name {name}");
        }
        Ok(types)
    }

    /// Look for a function symbol and return a Vec of matching Type objects as
    /// well as the NamedBtf object where it was found. Subsequent lookups based
    /// on this type (such as nested types by id) must be done on the returned
    /// Btf object since type ids of different modules overlap.
    pub(crate) fn resolve_types_by_symbol(
        &self,
        symbol: &Symbol,
    ) -> Result<Vec<(&NamedBtf, Type)>> {
        self.resolve_types_by_name(&symbol.typedef_name())
    }

    /// Look for symbol prototype. Return the prototype and the NamedBtf object
    /// that contains it.
    pub(crate) fn find_prototype_btf(
        &self,
        symbol: &Symbol,
    ) -> Result<(&NamedBtf, btf_rs::FuncProto)> {
        for (btf, t) in self.resolve_types_by_symbol(symbol)? {
            if let Ok(proto) = match symbol {
                Symbol::Func(_) => Self::get_function_prototype(btf, &t),
                Symbol::Event(_) => Self::get_event_prototype(btf, &t),
            } {
                return Ok((btf, proto));
            }
        }

        bail!("Failed to resolve prototype for {symbol}");
    }

    /// Translate a BTF function parameter into a type name String representation.
    fn get_param(btf: &NamedBtf, param: &btf_rs::Parameter) -> Result<String> {
        let mut resolved = btf.resolve_chained_type(param)?;
        let mut name = String::new();

        // First, traverse the type definition until we find the actual type.
        // Only support valid resolve_chained_type calls and exclude function
        // pointers, static/global variables and especially typedef as we don't
        // want to traverse its full definition!
        let mut is_pointer = false;
        loop {
            resolved = match resolved {
                Type::Ptr(t) => {
                    is_pointer = true;
                    btf.resolve_chained_type(&t)?
                }
                Type::Volatile(t) => btf.resolve_chained_type(&t)?,
                Type::Const(t) => btf.resolve_chained_type(&t)?,
                // FIXME: arrays are not supported at the moment.
                Type::Array(_) => return Ok(name),
                _ => break,
            }
        }

        // Then resolve the type name.
        let type_name = match resolved {
            Type::Int(t) => btf.resolve_name(&t)?,
            Type::Struct(t) => format!("struct {}", btf.resolve_name(&t)?),
            Type::Union(t) => format!("union {}", btf.resolve_name(&t)?),
            Type::Enum(t) => format!("enum {}", btf.resolve_name(&t)?),
            Type::Typedef(t) => btf.resolve_name(&t)?,
            Type::Float(t) => btf.resolve_name(&t)?,
            Type::Enum64(t) => format!("enum {}", btf.resolve_name(&t)?),
            _ => return Ok(name),
        };
        name.push_str(type_name.as_str());

        // Set the pointer information C style.
        if is_pointer {
            name.push_str(" *");
        }

        Ok(name)
    }

    fn get_function_prototype(btf: &NamedBtf, func: &Type) -> Result<btf_rs::FuncProto> {
        // Functions are using directly the target function definition, no
        // change to make to the target format and the prototype resolution
        // is straightforward: Func -> FuncProto.
        let func = match func {
            Type::Func(func) => func,
            _ => bail!("{:?} is not a function", func),
        };

        match btf.resolve_chained_type(func)? {
            Type::FuncProto(proto) => Ok(proto),
            _ => bail!("Function {:?} does not have a prototype", func),
        }
    }

    fn get_event_prototype(btf: &NamedBtf, func: &Type) -> Result<btf_rs::FuncProto> {
        // The prototype resolution for events is:
        // Typedef -> Ptr -> FuncProto.
        let func = match func {
            Type::Typedef(func) => func,
            _ => bail!("{:?} is not a typedef", func),
        };

        let ptr = match btf.resolve_chained_type(func)? {
            Type::Ptr(ptr) => ptr,
            _ => bail!("{:?} typedef does not point to a ptr", func),
        };

        match btf.resolve_chained_type(&ptr)? {
            Type::FuncProto(proto) => Ok(proto),
            _ => bail!("Function {:?} does not have a prototype", func),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn function_nargs() {
        let btf = BtfInfo::new().unwrap();
        assert!(
            btf.function_nargs(&Symbol::Func("kfree_skb_reason".to_string()))
                .unwrap()
                == 2
        );

        assert!(
            btf.function_nargs(&Symbol::Func("consume_skb".to_string()))
                .unwrap()
                == 1
        );

        assert!(
            btf.function_nargs(&Symbol::Func("ovs_dp_upcall".to_string()))
                .unwrap()
                == 5
        );
    }

    #[test]
    fn parameter_offset() {
        assert!(
            Symbol::Func("kfree_skb_reason".to_string())
                .parameter_offset("struct sk_buff *")
                .unwrap()
                == Some(0)
        );

        assert!(Symbol::Func("kfree_skb_reason".to_string())
            .parameter_offset("struct sk_buff")
            .unwrap()
            .is_none());

        assert!(
            Symbol::Event("skb:kfree_skb".to_string())
                .parameter_offset("struct sk_buff *")
                .unwrap()
                == Some(0)
        );

        assert!(
            Symbol::Event("skb:kfree_skb".to_string())
                .parameter_offset("enum skb_drop_reason")
                .unwrap()
                == Some(2)
        );

        assert!(
            Symbol::Event("openvswitch:ovs_do_execute_action".to_string())
                .parameter_offset("struct sw_flow_key *")
                .unwrap()
                == Some(2)
        );

        assert!(
            Symbol::Event("openvswitch:ovs_do_execute_action".to_string())
                .parameter_offset("struct sw_flow_key")
                .unwrap()
                .is_none()
        );

        assert!(
            Symbol::Func("ovs_dp_upcall".to_string())
                .parameter_offset("struct sk_buff *")
                .unwrap()
                == Some(1)
        );

        assert!(Symbol::Func("ovs_dp_upcall".to_string())
            .parameter_offset("struct sk_buff")
            .unwrap()
            .is_none());
    }
}
