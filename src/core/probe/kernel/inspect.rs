#![allow(dead_code)] // FIXME

use anyhow::Result;

use super::config::ProbeConfig;
use crate::core::kernel::Symbol;

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

/// Inspect a target using BTF and fill its description.
pub(super) fn inspect_target(target: &str) -> Result<TargetDesc> {
    let symbol = Symbol::from_name(target)?;

    // First look at the symbol address.
    let mut desc = TargetDesc {
        ksym: symbol.addr()?,
        ..Default::default()
    };

    // Get parameter offsets.
    desc.nargs = symbol.nargs()?;

    // Look for known parameter types.
    if let Some(offset) = symbol.parameter_offset("struct sk_buff *")? {
        desc.probe_cfg.offsets.sk_buff = offset as i8;
    }
    if let Some(offset) = symbol.parameter_offset("enum skb_drop_reason")? {
        desc.probe_cfg.offsets.skb_drop_reason = offset as i8;
    }
    if let Some(offset) = symbol.parameter_offset("struct net_device *")? {
        desc.probe_cfg.offsets.net_device = offset as i8;
    }
    if let Some(offset) = symbol.parameter_offset("struct net *")? {
        desc.probe_cfg.offsets.net = offset as i8;
    }

    Ok(desc)
}

#[cfg(test)]
mod tests {
    #[test]
    fn inspect_target() {
        // Inspect an event.
        let desc = super::inspect_target("skb:kfree_skb");
        assert!(desc.is_ok());

        let desc = desc.unwrap();
        assert!(desc.ksym == 0xffffffff983c29a0);
        assert!(desc.nargs == 3);
        assert!(desc.probe_cfg.offsets.sk_buff == 0);
        assert!(desc.probe_cfg.offsets.skb_drop_reason == 2);
        assert!(desc.probe_cfg.offsets.net_device == -1);
        assert!(desc.probe_cfg.offsets.net == -1);

        // Inspect a function.
        let desc = super::inspect_target("kfree_skb_reason");
        assert!(desc.is_ok());

        let desc = desc.unwrap();
        assert!(desc.ksym == 0xffffffff95612980);
        assert!(desc.nargs == 2);
        assert!(desc.probe_cfg.offsets.sk_buff == 0);
        assert!(desc.probe_cfg.offsets.skb_drop_reason == 1);
        assert!(desc.probe_cfg.offsets.net_device == -1);
        assert!(desc.probe_cfg.offsets.net == -1);

        // Inspect a function with net device and netns arguments.
        let desc = super::inspect_target("inet_dev_addr_type");
        assert!(desc.is_ok());

        let desc = desc.unwrap();
        assert!(desc.ksym == 0xffffffff959754a0);
        assert!(desc.nargs == 3);
        assert!(desc.probe_cfg.offsets.sk_buff == -1);
        assert!(desc.probe_cfg.offsets.skb_drop_reason == -1);
        assert!(desc.probe_cfg.offsets.net_device == 1);
        assert!(desc.probe_cfg.offsets.net == 0);

        // Non-existing symbol.
        assert!(super::inspect_target("kfree_skb").is_err());
    }
}
