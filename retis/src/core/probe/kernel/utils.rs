use anyhow::{bail, Result};

use crate::core::{
    kernel::symbol::{matching_events_to_symbols, matching_functions_to_symbols, Symbol},
    probe::Probe,
};

/// Probe type for probes given through cli arguments.
pub(crate) enum CliProbeType {
    Kprobe,
    Kretprobe,
    RawTracepoint,
    Fentry,
    Fexit,
}

impl CliProbeType {
    pub(crate) fn to_str(&self) -> &'static str {
        use CliProbeType::*;
        match self {
            Kprobe => "kprobe",
            Kretprobe => "kretprobe",
            RawTracepoint => "raw_tracepoint",
            Fentry => "fentry",
            Fexit => "fexit",
        }
    }
}

/// Parses a probe given as a cli argument and returns its type and the probe
/// with the type identifier (if any).
pub(crate) fn parse_cli_probe(input: &str) -> Result<(CliProbeType, &str)> {
    use CliProbeType::*;

    Ok(match input.split_once(':') {
        Some((type_str, target)) => match type_str {
            "kprobe" | "k" => (Kprobe, target),
            "kretprobe" | "kr" => (Kretprobe, target),
            "raw_tracepoint" | "tp" => (RawTracepoint, target),
            "fentry" | "f" => (Fentry, target),
            "fexit" | "fe" => (Fexit, target),
            // If a single ':' was found in the probe name but we didn't match
            // any known type, defaults to trying using it as a raw tracepoint.
            _ if input.chars().filter(|c| *c == ':').count() == 1 => (RawTracepoint, input),
            x => bail!("Invalid TYPE {}. See the help.", x),
        },
        // If no ':' was found, defaults to kprobe.
        None => (Kprobe, input),
    })
}

/// Parse a user defined probe (through cli parameters) and convert it to our
/// probe representation (`Probe`).
pub(crate) fn probe_from_cli<F>(probe: &str, filter: F) -> Result<Vec<Probe>>
where
    F: Fn(&Symbol) -> bool,
{
    use CliProbeType::*;

    let (r#type, target) = parse_cli_probe(probe)?;

    // Convert the target to a list of matching ones for probe types
    // supporting it.
    let mut symbols = match r#type {
        Kprobe | Kretprobe | Fentry | Fexit => matching_functions_to_symbols(target)?,
        RawTracepoint => matching_events_to_symbols(target)?,
    };

    let mut probes = Vec::new();
    for symbol in symbols.drain(..) {
        // Check if the symbol matches the filter.
        if !filter(&symbol) {
            continue;
        }

        probes.push(match r#type {
            Kprobe => Probe::kprobe(symbol)?,
            Kretprobe => Probe::kretprobe(symbol)?,
            RawTracepoint => Probe::raw_tracepoint(symbol)?,
            Fentry => Probe::fentry(symbol)?,
            Fexit => Probe::fexit(symbol)?,
        })
    }

    Ok(probes)
}

#[cfg(test)]
mod tests {
    #[test]
    fn probe_from_cli() {
        let filter = |_: &_| true;

        // Valid probes.
        assert!(super::probe_from_cli("consume_skb", filter).is_ok());
        assert!(super::probe_from_cli("kprobe:kfree_skb_reason", filter).is_ok());
        assert!(super::probe_from_cli("k:kfree_skb_reason", filter).is_ok());
        assert!(super::probe_from_cli("skb:kfree_skb", filter).is_ok());
        assert!(super::probe_from_cli("tp:skb:kfree_skb", filter).is_ok());
        assert!(super::probe_from_cli("tcp_v6_*", filter).is_ok());
        assert!(super::probe_from_cli("kprobe:tcp_v6_*", filter).is_ok());
        assert!(!super::probe_from_cli("kprobe:tcp_v6_*", filter)
            .unwrap()
            .is_empty());
        assert!(super::probe_from_cli("kretprobe:tcp_*", filter).is_ok());
        assert!(super::probe_from_cli("kr:tcp_*", filter).is_ok());
        assert!(super::probe_from_cli("tp:skb:kfree_*", filter).is_ok());
        assert!(super::probe_from_cli("tp:*skb*", filter).is_ok());

        // Invalid probe: symbol does not exist.
        assert!(super::probe_from_cli("foobar", filter).is_err());
        assert!(super::probe_from_cli("kprobe:foobar", filter).is_err());
        assert!(super::probe_from_cli("tp:42:foobar", filter).is_err());
        assert!(super::probe_from_cli("tp:kfree_*", filter).is_err());
        assert!(super::probe_from_cli("*foo*", filter).is_err());

        // Invalid probe: wrong TYPE.
        assert!(super::probe_from_cli("kprobe:skb:kfree_skb", filter).is_err());
        assert!(super::probe_from_cli("foo:kfree_skb", filter).is_err());

        // Invalid probe: empty parts.
        assert!(super::probe_from_cli("", filter).is_err());
        assert!(super::probe_from_cli("kprobe:", filter).is_err());
        assert!(super::probe_from_cli("tp:", filter).is_err());
        assert!(super::probe_from_cli("tp:skb:", filter).is_err());
        assert!(super::probe_from_cli(":kfree_skb_reason", filter).is_err());
    }
}
