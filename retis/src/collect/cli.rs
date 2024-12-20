//! # Collect
//!
//! Collect is a dynamic CLI subcommand that allows collectors to register their arguments.

use std::path::PathBuf;

use anyhow::Result;
use clap::{builder::PossibleValuesParser, Parser};

use super::Collectors;
use crate::{cli::*, collect::collector::*};

/// Collect events.
///
/// The collect sub-command use "collectors" to retrieve data and emit events.
/// Collectors extract data from different places of the kernel or userspace
/// daemons using eBPF. Some install probes automatically. Each collector is
/// specialized in retrieving specific data. The list of enabled collectors can
/// be configured using the --collectors argument.
#[derive(Parser, Debug, Default)]
#[command(name = "collect")]
pub(crate) struct Collect {
    // Some of the options that we want for this arg are not available in clap's derive interface
    // so both the argument definition and the field population will be done manually.
    #[arg(
        short,
        long,
        value_parser=PossibleValuesParser::new([
            "skb-tracking", "skb", "skb-drop", "ovs", "nft", "ct",
        ]),
        value_delimiter=',',
        help = "Comma-separated list of collectors to enable. When not specified default to
auto-mode (all collectors are enabled unless a prerequisite is missing)."
    )]
    pub(super) collectors: Option<Vec<String>>,
    // Use the plural in the struct but singular for the cli parameter as we're
    // dealing with a list here.
    #[arg(
        id = "probe",
        short,
        long,
        help = "Add a probe on the given target. Can be used multiple times. Probes should
follow the [TYPE:]TARGET pattern.

When TYPE is not specified it is set to 'kprobe', except if a single ':' is found in TARGET
in which case 'raw_tracepoint' is set instead. Those default types might evolve over time.

Valid TYPEs:
- kprobe | k: kernel probes.
- kretprobe | kr: kernel return probes.
- raw_tracepoint | tp: kernel tracepoints.

Wildcards (*) can be used, eg. \"kprobe:tcp_*\" or \"tp:skb:*\".

Examples:
  --probe tp:skb:kfree_skb --probe kprobe:consume_skb
  --probe skb:kfree_skb --probe consume_skb"
    )]
    pub(super) probes: Vec<String>,
    #[arg(
        id = "filter-packet",
        short,
        long,
        help = r#"Add a packet filter to all targets. The syntax follows the structure of pcap-filer(7).

Example: --filter-packet "ip dst host 10.0.0.1""#
    )]
    pub(super) packet_filter: Option<String>,
    #[arg(
        id = "filter-meta",
        short = 'm',
        long,
        help = r#"Add a meta filter to all targets. A meta filter compares a field within a kernel structure against a user-provided input.
The syntax follows:
sk_buff.member1.[...].memberN.member_leaf [==|<=|>=|!=] value
With value ::= "string" | number.
"==" is the only operator valid for "string" assuming member_leaf type is a pointer to a char or array of chars.

Examples of meta filters:
--filter-meta 'sk_buff.dev.name == "eth0"'
--filter-meta 'sk_buff.dev.nd_net.net.ns.inum == 4026531840'"#
    )]
    pub(super) meta_filter: Option<String>,
    #[arg(
        short,
        long,
        num_args = 0..=1,
        default_missing_value = "retis.data",
        help = "Write the events to a file rather than to sdout. If the flag is used without a file name,
defaults to \"retis.data\"."
    )]
    pub(super) out: Option<PathBuf>,
    #[arg(
        long,
        help = "Write the events to stdout even if --out is used.",
        default_value = "false"
    )]
    pub(super) print: bool,
    #[arg(
        long,
        default_value = "false",
        help = "Include stack traces in the kernel events. The stack entries are limited and
not released. If exhausted, no stack trace will be included."
    )]
    pub(super) stack: bool,
    #[arg(
        long,
        default_value = "false",
        help = "When set, evaluates where Retis could add additional probes based on functions reported
in the events stack traces (their display is still controlled by --stack). All matching
functions are probed at runtime using kprobes.

Notes:
- Using a filter is required (--filter-packet and/or --filter-meta).
- If no explicit probe is given, tp:skb:kfree_skb and tp:skb:consume_skb are used as a
  starting point.
- Additional probes are added only after events including them in their stack trace are
  reported; this means the first packets hitting a probe won't be reported.
- Packets will only be followed prior to the initial set of probes (as this mode uses
  stack traces). This also means the filter must match packets as they appear in the
  initial set of probes; packet transformation can't be automatically detected."
    )]
    pub(crate) probe_stack: bool,
    #[arg(
        long,
        help = "Execute a command and terminate the collection once done."
    )]
    pub(super) cmd: Option<String>,
    #[arg(
        long,
        default_value = "false",
        help = r#"Allow the tool to setup all the system changes needed to make the tracing
fully operational:

- Mounting debugfs to /sys/kernel/debug if not already mounted. If Retis mounted debugfs it
  will unmount it when stopped.

- In the case the nft module is used, creating a dummy table called "Retis_Table"
  as the following:

    table inet Retis_Table {
        chain Retis_Chain {
            meta nftrace set 1
        }
    }

  The table will be removed once the program gets stopped. Note that the tool tries to remove
  "Retis_Table" before creating it.
"#
    )]
    pub(crate) allow_system_changes: bool,
    #[arg(long, help = "Print the time as UTC")]
    pub(super) utc: bool,
    #[arg(long, help = "Format used when printing an event.")]
    #[clap(value_enum, default_value_t=CliDisplayFormat::MultiLine)]
    pub(super) format: CliDisplayFormat,

    /// Embed below all the per-collector arguments.
    #[command(flatten)]
    pub(crate) collector_args: CollectorsArgs,
}

#[derive(Parser, Debug, Default)]
pub(crate) struct CollectorsArgs {
    #[command(flatten, next_help_heading = "collector 'skb'")]
    pub(crate) skb: skb::SkbCollectorArgs,

    #[command(flatten, next_help_heading = "collector 'ovs'")]
    pub(crate) ovs: ovs::OvsCollectorArgs,

    #[command(flatten, next_help_heading = "collector 'nft'")]
    pub(crate) nft: nft::NftCollectorArgs,
}

impl SubCommandParserRunner for Collect {
    fn run(&mut self) -> Result<()> {
        let mut collectors = Collectors::new()?;

        collectors.check(self)?;
        collectors.init(self)?;

        collectors.start(self)?;

        // Starts a loop.
        collectors.process(self)?;

        Ok(())
    }
}
