use anyhow::Result;

use super::config::ProbeConfig;
use crate::core::kernel::Symbol;

/// Inspect a target using BTF and fill its description.
pub(super) fn inspect_symbol(symbol: &Symbol) -> Result<ProbeConfig> {
    let mut cfg = ProbeConfig::default();

    // Look for known parameter types.
    if let Some(offset) = symbol.parameter_offset("struct sk_buff *")? {
        cfg.offsets.sk_buff = offset as i8;
    }
    if let Some(offset) = symbol.parameter_offset("enum skb_drop_reason")? {
        cfg.offsets.skb_drop_reason = offset as i8;
    }
    if let Some(offset) = symbol.parameter_offset("struct net_device *")? {
        cfg.offsets.net_device = offset as i8;
    }
    if let Some(offset) = symbol.parameter_offset("struct net *")? {
        cfg.offsets.net = offset as i8;
    }

    Ok(cfg)
}

#[cfg(test)]
mod tests {
    use crate::core::kernel::Symbol;

    #[test]
    fn inspect_symbol() {
        // Inspect an event.
        let config = super::inspect_symbol(&Symbol::from_name("skb:kfree_skb").unwrap());
        assert!(config.is_ok());

        let config = config.unwrap();
        assert!(config.offsets.sk_buff == 0);
        assert!(config.offsets.skb_drop_reason == 2);
        assert!(config.offsets.net_device == -1);
        assert!(config.offsets.net == -1);

        // Inspect a function.
        let config = super::inspect_symbol(&Symbol::from_name("kfree_skb_reason").unwrap());
        assert!(config.is_ok());

        let config = config.unwrap();
        assert!(config.offsets.sk_buff == 0);
        assert!(config.offsets.skb_drop_reason == 1);
        assert!(config.offsets.net_device == -1);
        assert!(config.offsets.net == -1);

        // Inspect a function with net device and netns arguments.
        let config = super::inspect_symbol(&Symbol::from_name("inet_dev_addr_type").unwrap());
        assert!(config.is_ok());

        let config = config.unwrap();
        assert!(config.offsets.sk_buff == -1);
        assert!(config.offsets.skb_drop_reason == -1);
        assert!(config.offsets.net_device == 1);
        assert!(config.offsets.net == 0);
    }
}
