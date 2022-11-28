#![allow(dead_code)] // FIXME

use anyhow::{bail, Result};
use btf_rs::{Btf, Type};

use super::{config::ProbeConfig, ProbeType};
use crate::core::kernel_symbols;

/// Holds the result of a kernel symbol inspection and describes it.
#[derive(Default)]
pub(super) struct TargetDesc {
    /// Symbol address.
    pub(super) ksym: u64,
    /// Number of arguments the symbol has.
    pub(super) nargs: u32,
    /// Holds the different offsets to known parameters.
    pub(super) probe_cfg: ProbeConfig,
}

/// Provides helpers to inspect probe related information in the kernel.
pub(crate) struct Inspector {
    btf: Btf,
}

impl Inspector {
    pub(crate) fn new() -> Result<Inspector> {
        Ok(Inspector {
            #[cfg(not(test))]
            btf: Btf::from_file("/sys/kernel/btf/vmlinux")?,
            #[cfg(test)]
            btf: Btf::from_file("test_data/vmlinux")?,
        })
    }

    /// Get a parameter offset given its type in a given kernel function, if
    /// any. Can be used to check a function has a given parameter by using
    /// `function_parameter_offset()?.is_some()`
    pub(crate) fn function_parameter_offset(
        &self,
        r#type: ProbeType,
        target: &str,
        parameter_type: &str,
    ) -> Result<Option<u32>> {
        // Raw tracepoints have a void* pointing to the data as their first
        // argument, which does not end up in their context. We have to skip it.
        // See include/trace/bpf_probe.h in the __DEFINE_EVENT definition.
        let fix = match r#type {
            ProbeType::RawTracepoint => 1,
            _ => 0,
        };

        let proto = self.get_function_prototype(&r#type, target)?;
        for (offset, param) in proto.parameters.iter().enumerate() {
            if self.is_param_type(param, parameter_type)? {
                if offset < fix {
                    continue;
                }
                return Ok(Some((offset - fix) as u32));
            }
        }
        Ok(None)
    }

    fn get_function_prototype(
        &self,
        r#type: &ProbeType,
        target: &str,
    ) -> Result<btf_rs::FuncProto> {
        // Some probe types might need to change the target format.
        Ok(match r#type {
            ProbeType::Kprobe => {
                // Kprobes are using directly the target function definition, no
                // change to make to the target format and the prototype
                // resolution is straightforward: Func -> FuncProto.
                let func = match self.btf.resolve_type_by_name(target)? {
                    Type::Func(func) => func,
                    _ => bail!("{} is not a function", target),
                };

                match self.btf.resolve_chained_type(&func)? {
                    Type::FuncProto(proto) => proto,
                    _ => bail!("Function {} does not have a prototype", target),
                }
            }
            ProbeType::RawTracepoint => {
                // Raw tracepoints need to access a symbol derived from
                // TP_PROTO(), which is named "btf_trace_<func>". The prototype
                // resolution is: Typedef -> Ptr -> FuncProto.
                let target = match target.split_once(':') {
                    Some((_, tgt)) => format!("btf_trace_{}", tgt),
                    None => bail!("Invalid tracepoint format for {}", target),
                };

                let func = match self.btf.resolve_type_by_name(target.as_str())? {
                    Type::Typedef(func) => func,
                    _ => bail!("{} is not a typedef", target),
                };

                let ptr = match self.btf.resolve_chained_type(&func)? {
                    Type::Ptr(ptr) => ptr,
                    _ => bail!("{} typedef does not point to a ptr", target),
                };

                match self.btf.resolve_chained_type(&ptr)? {
                    Type::FuncProto(proto) => proto,
                    _ => bail!("Function {} does not have a prototype", target),
                }
            }
            ProbeType::Max => bail!("Invalid probe type"),
        })
    }

    fn is_param_type(&self, param: &btf_rs::Parameter, r#type: &str) -> Result<bool> {
        let mut resolved = self.btf.resolve_chained_type(param)?;
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
                    self.btf.resolve_chained_type(&t)?
                }
                Type::Volatile(t) => {
                    full_name.push_str("volatile ");
                    self.btf.resolve_chained_type(&t)?
                }
                Type::Const(t) => {
                    full_name.push_str("const ");
                    self.btf.resolve_chained_type(&t)?
                }
                Type::Array(_) => bail!("Arrays are not supported at the moment"),
                _ => break,
            }
        }

        // Then resolve the type name.
        let type_name = match resolved {
            Type::Int(t) => self.btf.resolve_name(&t)?,
            Type::Struct(t) => format!("struct {}", self.btf.resolve_name(&t)?),
            Type::Union(t) => format!("union {}", self.btf.resolve_name(&t)?),
            Type::Enum(t) => format!("enum {}", self.btf.resolve_name(&t)?),
            Type::Typedef(t) => self.btf.resolve_name(&t)?,
            Type::Float(t) => self.btf.resolve_name(&t)?,
            Type::Enum64(t) => format!("enum {}", self.btf.resolve_name(&t)?),
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

    /// Get a kernel symbol address given a function name and its type. If the
    /// symbol isn't found or isn't traceable an error is returned.
    pub(crate) fn get_ksym(&self, r#type: &ProbeType, target: &str) -> Result<u64> {
        // Some probe types might need to modify the target format.
        let ksym_target = match r#type {
            ProbeType::Kprobe => target.to_string(),
            ProbeType::RawTracepoint => {
                // Raw tracepoints should have a group:target format.
                match target.split_once(':') {
                    Some((_, tgt)) => format!("__tracepoint_{}", tgt),
                    None => bail!("Invalid tracepoint format for {}", target),
                }
            }
            ProbeType::Max => bail!("Invalid probe type"),
        };

        kernel_symbols::get_symbol_addr(ksym_target.as_str())
    }

    /// Inspect a target using BTF and fill its description.
    pub(super) fn inspect_target(&self, r#type: &ProbeType, target: &str) -> Result<TargetDesc> {
        // First look at the symbol address.
        let mut desc = TargetDesc {
            ksym: self.get_ksym(r#type, target)?,
            ..Default::default()
        };

        // Raw tracepoints have a void* pointing to the data as their first
        // argument, which does not end up in their context. We have to skip it.
        // See include/trace/bpf_probe.h in the __DEFINE_EVENT definition.
        let fix = match r#type {
            &ProbeType::RawTracepoint => 1,
            _ => 0,
        };

        // Get parameter offsets.
        let proto = self.get_function_prototype(r#type, target)?;
        desc.nargs = (proto.parameters.len() - fix) as u32;

        for (offset, param) in proto.parameters.iter().enumerate() {
            if offset < fix {
                continue;
            }
            if self.is_param_type(param, "struct sk_buff *")? {
                desc.probe_cfg.offsets.sk_buff = (offset - fix) as i8;
            } else if self.is_param_type(param, "enum skb_drop_reason")? {
                desc.probe_cfg.offsets.skb_drop_reason = (offset - fix) as i8;
            } else if self.is_param_type(param, "struct net_device *")? {
                desc.probe_cfg.offsets.net_device = (offset - fix) as i8;
            } else if self.is_param_type(param, "struct net *")? {
                desc.probe_cfg.offsets.net = (offset - fix) as i8;
            }
        }

        Ok(desc)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parameter_offset() {
        let inspect = Inspector::new().unwrap();

        assert!(
            inspect
                .function_parameter_offset(
                    ProbeType::Kprobe,
                    "kfree_skb_reason",
                    "struct sk_buff *"
                )
                .unwrap()
                == Some(0)
        );
        assert!(
            inspect
                .function_parameter_offset(ProbeType::Kprobe, "kfree_skb_reason", "struct sk_buff")
                .unwrap()
                == None
        );

        assert!(
            inspect
                .function_parameter_offset(
                    ProbeType::RawTracepoint,
                    "skb:kfree_skb",
                    "struct sk_buff *"
                )
                .unwrap()
                == Some(0)
        );
        assert!(
            inspect
                .function_parameter_offset(
                    ProbeType::RawTracepoint,
                    "skb:kfree_skb",
                    "enum skb_drop_reason"
                )
                .unwrap()
                == Some(2)
        );
    }

    #[test]
    fn inspect_target() {
        let inspect = Inspector::new().unwrap();

        let desc = inspect.inspect_target(&ProbeType::RawTracepoint, "skb:kfree_skb");
        assert!(desc.is_ok());

        let desc = desc.unwrap();
        assert!(desc.ksym == 0xffffffff983c29a0);
        assert!(desc.nargs == 3);
        assert!(desc.probe_cfg.offsets.sk_buff == 0);
        assert!(desc.probe_cfg.offsets.skb_drop_reason == 2);
        assert!(desc.probe_cfg.offsets.net_device == -1);
        assert!(desc.probe_cfg.offsets.net == -1);
    }
}
