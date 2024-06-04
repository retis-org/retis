use std::fs;

use anyhow::{anyhow, bail, Result};
use btf_rs::{Btf, Type};

use super::BASE_TEST_DIR;
use crate::core::kernel::Symbol;

/// Btf provides multi-module Btf lookups.
pub(crate) struct BtfInfo {
    /// Main Btf object (vmlinux).
    vmlinux: Btf,
    /// Extra Btf objects (modules).
    modules: Vec<Btf>,
}

impl BtfInfo {
    /// Parse kernel BTF files and create a Btf object.
    pub(super) fn new() -> Result<BtfInfo> {
        let vmlinux = match cfg!(test) || cfg!(feature = "benchmark") {
            false => "/sys/kernel/btf/vmlinux".to_owned(),
            true => BASE_TEST_DIR.to_owned() + "/test_data/vmlinux",
        };

        let vmlinux = Btf::from_file(vmlinux.clone())
            .map_err(|e| anyhow!("Could not open {vmlinux}: {e}"))?;

        // Load module btf files if possible.
        let modules = match cfg!(test) || cfg!(feature = "benchmark") {
            false => fs::read_dir("/sys/kernel/btf")?
                .filter(|f| f.is_ok() && f.as_ref().unwrap().file_name().ne("vmlinux"))
                .map(|f| Btf::from_split_file(f.as_ref().unwrap().path(), &vmlinux))
                .collect::<Result<Vec<Btf>>>()?,
            true => vec![Btf::from_split_file(
                BASE_TEST_DIR.to_owned() + "/test_data/openvswitch",
                &vmlinux,
            )?],
        };

        Ok(BtfInfo { vmlinux, modules })
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

    /// Get a parameter offset given a kernel function, if any. Can be used to
    /// check a function has a given parameter by using:
    /// `parameter_offset()?.is_some()`
    pub(super) fn parameter_offset(
        &self,
        symbol: &Symbol,
        parameter_type: &str,
    ) -> Result<Option<u32>> {
        // Events have a void* pointing to the data as their first argument, which
        // does not end up in their context. We have to skip it. See
        // include/trace/bpf_probe.h in the __DEFINE_EVENT definition.
        let fix = match symbol {
            Symbol::Event(_) => 1,
            _ => 0,
        };

        let (btf, proto) = self.find_prototype_btf(symbol)?;
        for (offset, param) in proto.parameters.iter().enumerate() {
            if BtfInfo::is_param_type(btf, param, parameter_type)? {
                if offset < fix {
                    continue;
                }
                return Ok(Some((offset - fix) as u32));
            }
        }
        Ok(None)
    }

    /// Look for a type based on its name and return both a Vec of Type objects as well as
    /// the Btf object where it was found.
    /// Subsequent lookups based on this type (such as nested types by id) must be done on
    /// the returned Btf object since type ids of different modules overlap.
    ///
    /// vmlinux is given priority in the lookups.
    pub(crate) fn resolve_types_by_name(&self, name: &str) -> Result<Vec<(&Btf, Type)>> {
        let mut types = Vec::new();

        let mut base_types = match self.vmlinux.resolve_types_by_name(name) {
            Ok(base_types) => base_types,
            _ => Vec::new(), // Id not found in base.
        };

        for module in self.modules.iter() {
            if let Ok(mut res) = module.resolve_types_by_name(name) {
                // FIXME: We can't filter base types so they'll be reported more
                // than once (we need some changes in btf-rs that are not
                // released yet). Not optimal but should be fine with how we use
                // this function for now.
                res.drain(..).for_each(|t| types.push((module, t)));
            }
        }

        // Now add types found in the base BTF.
        base_types
            .drain(..)
            .for_each(|t| types.push((&self.vmlinux, t)));

        if types.is_empty() {
            bail!("No type linked to name {name}");
        }

        Ok(types)
    }

    /// Look for a function symbol and return a Vec of matching Type objects as well as
    /// the Btf object where it was found.
    ///
    /// Subsequent lookups based on this type (such as nested types by id) must be done on
    /// the returned Btf object since type ids of different modules overlap.
    ///
    /// vmlinux is given priority in the lookups.
    pub(crate) fn resolve_types_by_symbol(&self, symbol: &Symbol) -> Result<Vec<(&Btf, Type)>> {
        self.resolve_types_by_name(&symbol.typedef_name())
    }

    /// Look for symbol prototype. Return the prototype and the Btf object that contains it.
    pub(crate) fn find_prototype_btf(&self, symbol: &Symbol) -> Result<(&Btf, btf_rs::FuncProto)> {
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

    /// Determine if a parameter is from a specific type.
    fn is_param_type(btf: &Btf, param: &btf_rs::Parameter, r#type: &str) -> Result<bool> {
        let mut resolved = btf.resolve_chained_type(param)?;
        let mut full_name = String::new();

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
                Type::Array(_) => return Ok(false),
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
            _ => return Ok(false),
        };
        full_name.push_str(type_name.as_str());

        // Set the pointer information C style.
        if is_pointer {
            full_name.push_str(" *");
        }

        // We do not get the symbol name; useless and not always there (e.g.
        // raw tracepoints).

        Ok(r#type == full_name)
    }

    fn get_function_prototype(btf: &Btf, func: &Type) -> Result<btf_rs::FuncProto> {
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

    fn get_event_prototype(btf: &Btf, func: &Type) -> Result<btf_rs::FuncProto> {
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
        let btf = BtfInfo::new().unwrap();
        assert!(
            btf.parameter_offset(
                &Symbol::Func("kfree_skb_reason".to_string()),
                "struct sk_buff *"
            )
            .unwrap()
                == Some(0)
        );

        assert!(btf
            .parameter_offset(
                &Symbol::Func("kfree_skb_reason".to_string()),
                "struct sk_buff"
            )
            .unwrap()
            .is_none());

        assert!(
            btf.parameter_offset(
                &Symbol::Event("skb:kfree_skb".to_string()),
                "struct sk_buff *"
            )
            .unwrap()
                == Some(0)
        );

        assert!(
            btf.parameter_offset(
                &Symbol::Event("skb:kfree_skb".to_string()),
                "enum skb_drop_reason"
            )
            .unwrap()
                == Some(2)
        );

        assert!(
            btf.parameter_offset(
                &Symbol::Event("openvswitch:ovs_do_execute_action".to_string()),
                "struct sw_flow_key *"
            )
            .unwrap()
                == Some(2)
        );

        assert!(btf
            .parameter_offset(
                &Symbol::Event("openvswitch:ovs_do_execute_action".to_string()),
                "struct sw_flow_key"
            )
            .unwrap()
            .is_none());

        assert!(
            btf.parameter_offset(
                &Symbol::Func("ovs_dp_upcall".to_string()),
                "struct sk_buff *"
            )
            .unwrap()
                == Some(1)
        );

        assert!(btf
            .parameter_offset(&Symbol::Func("ovs_dp_upcall".to_string()), "struct sk_buff")
            .unwrap()
            .is_none());
    }
}
