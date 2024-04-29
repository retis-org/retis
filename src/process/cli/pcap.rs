use std::{
    borrow::Cow,
    collections::HashMap,
    fs::OpenOptions,
    io::Write,
    path::{Path, PathBuf},
    time::Duration,
};

use anyhow::{anyhow, bail, Result};
use clap::{arg, Parser};
use log::{info, warn};
use pcap_file::{
    pcapng::{
        blocks::{
            enhanced_packet::{EnhancedPacketBlock, EnhancedPacketOption},
            interface_description::{InterfaceDescriptionBlock, InterfaceDescriptionOption},
        },
        PcapNgBlock, PcapNgWriter,
    },
    DataLink,
};

use crate::{
    cli::*,
    core::kernel::Symbol,
    events::{common::CommonEvent, file::FileEventsFactory, kernel::KernelEvent, skb::SkbEvent, *},
    helpers::signals::Running,
    module::{ModuleId, Modules},
};

/// Statistics of the event parser about events (processed, skipped, etc).
#[derive(Default)]
struct EventParserStats {
    /// Events that were processed by the parser. Aka. all events that were
    /// matched by the filter.
    processed: u32,
    /// Events w/o an skb section (skipped).
    missing_skb: u32,
    /// Events w/o a packet section (skipped).
    missing_packet: u32,
    /// Events w/o a dev section (fake one was used instead).
    missing_dev: u32,
    /// Events w/o a netns section (fake one was used instead).
    missing_ns: u32,
}

/// Events parser: handles the logic to convert our events to the PCAP format
/// that is represented by the internal writer.
struct EventParser<'a, W: Write> {
    writer: &'a mut PcapNgWriter<W>,
    /// Known network interfaces and their PCAP id: netns|ifindex -> pcap id.
    ifaces: HashMap<u64, u32>,
    /// Statistics.
    stats: EventParserStats,
}

// Unwrap a Some(_) value or return from the function.
macro_rules! some_or_return {
    ($section: expr, $stat: expr) => {
        match $section {
            Some(val) => val,
            None => {
                $stat += 1;
                return Ok(());
            }
        }
    };
}

impl<'a, W: Write> EventParser<'a, W> {
    /// Creates a new EventParser from a PcapNgWriter<W: Write>.
    fn from(writer: &'a mut PcapNgWriter<W>) -> Self {
        Self {
            writer,
            ifaces: HashMap::new(),
            stats: EventParserStats::default(),
        }
    }

    /// Parse & process a single Retis event.
    fn parse(&mut self, event: &Event) -> Result<()> {
        // Having a common & a kernel section is mandatory for now, seeing a
        // filtered event w/o one of those is bogus.
        let common = event
            .get_section::<CommonEvent>(ModuleId::Common)
            .ok_or_else(|| anyhow!("No common section in event"))?;
        let kernel = event
            .get_section::<KernelEvent>(ModuleId::Kernel)
            .ok_or_else(|| anyhow!("No skb section in event"))?;

        self.stats.processed += 1;

        // The skb & packet sections are mandatory for us to generate PCAP
        // events, but they might not be present in some filtered events. Stats
        // are kept here to inform the user.
        let skb = some_or_return!(
            event.get_section::<SkbEvent>(ModuleId::Skb),
            self.stats.missing_skb
        );
        let packet = some_or_return!(skb.packet.as_ref(), self.stats.missing_packet);

        // The dev & ns sections are best to have but not mandatory to generate
        // an event. If not found, fake them.
        let (ifindex, ifname) = match skb.dev.as_ref() {
            Some(dev) => (dev.ifindex, dev.name.as_str()),
            None => {
                self.stats.missing_dev += 1;
                (0, "?")
            }
        };
        let netns = match skb.ns.as_ref() {
            Some(ns) => ns.netns,
            None => {
                self.stats.missing_ns += 1;
                0
            }
        };

        // If we see this iface for the first time, add a description block.
        let key: u64 = (netns as u64) << 32 | ifindex as u64;
        let id = match self.ifaces.contains_key(&key) {
            // Unwrap if contains is true.
            true => *self.ifaces.get(&key).unwrap(),
            false => {
                self.writer.write_block(
                    &InterfaceDescriptionBlock {
                        linktype: DataLink::ETHERNET,
                        snaplen: 0xffff,
                        options: vec![
                            InterfaceDescriptionOption::IfName(Cow::Owned(format!(
                                "{} ({})",
                                ifname, netns
                            ))),
                            InterfaceDescriptionOption::IfDescription(Cow::Owned(match ifindex {
                                0 => "Fake interface".to_string(),
                                _ => format!("ifindex={}", ifindex),
                            })),
                        ],
                    }
                    .into_block(),
                )?;

                let id = self.ifaces.len() as u32;
                self.ifaces.insert(key, id);
                id
            }
        };

        // Add the packet itself.
        self.writer.write_block(
            &EnhancedPacketBlock {
                interface_id: id,
                timestamp: Duration::from_nanos(common.timestamp),
                original_len: packet.len,
                data: Cow::Borrowed(&packet.packet.0),
                options: vec![EnhancedPacketOption::Comment(Cow::Owned(format!(
                    "probe={}:{}",
                    &kernel.probe_type, &kernel.symbol
                )))],
            }
            .into_block(),
        )?;

        Ok(())
    }

    /// Report parser statistics. Should be called after processing was
    /// completed.
    fn report_stats(&self) {
        info!("{} event(s) were processed", self.stats.processed);

        if self.stats.missing_skb != 0 {
            warn!(
                "{} event(s) were skipped because of missing skb information",
                self.stats.missing_skb
            );
        }
        if self.stats.missing_packet != 0 {
            warn!(
                "{} event(s) were skipped because of missing raw packet",
                self.stats.missing_packet
            );
        }
        if self.stats.missing_dev != 0 {
            warn!(
                "{} event(s) are using a fake net device (no device information was found)",
                self.stats.missing_dev
            );
        }
        if self.stats.missing_ns != 0 {
            warn!(
                "{} event(s) are using a fake netns (no netns information was found)",
                self.stats.missing_ns
            );
        }
    }
}

/// Generate a PCAP file from stored events.
#[derive(Parser, Debug, Default)]
#[command(name = "pcap")]
pub(crate) struct Pcap {
    #[arg(
        short,
        long,
        help = "Filter events from this probe. Probes should follow the [TYPE:]TARGET pattern.
See `retis collect --help` for more details on the probe format."
    )]
    pub(super) probe: String,
    #[arg(
        short,
        long,
        help = "Write the generated PCAP output to a file rather than stdio"
    )]
    pub(super) out: Option<PathBuf>,
    #[arg(default_value = "retis.data", help = "File from which to read events")]
    pub(super) input: PathBuf,
}

impl SubCommandParserRunner for Pcap {
    fn run(&mut self, modules: Modules) -> Result<()> {
        let (probe_type, target) = match self.probe.split_once(':') {
            Some((r#type, target)) => (r#type, target),
            None => ("kprobe", self.probe.as_str()),
        };
        let symbol = Symbol::from_name_no_inspect(target);

        // Convert the user-given probe type to the event ones, so both are
        // supported. This helps users to either use the collect format or what
        // is reported in the event itself.
        //
        // E.g. --probe tp:skb:kfree_skb == --probe raw_tracepoint:skb:kfree_skb
        let probe_type = match probe_type {
            "tp" => "raw_tracepoint",
            x => x,
        };

        // Create a PCAP writer to push our events / metadata.
        let mut writer = PcapNgWriter::new(match &self.out {
            Some(file) => OpenOptions::new()
                .create(true)
                .write(true)
                .truncate(true)
                .open(file)
                .or_else(|_| bail!("Could not create or open '{}'", file.display()))?,
            None => OpenOptions::new()
                .write(true)
                .open("/proc/self/fd/1")
                .or_else(|_| bail!("Could not open stdout"))?,
        })?;

        // Filtering logic.
        let filter = |r#type: &str, name: &str| -> bool {
            if name == symbol.name() && r#type == probe_type {
                return true;
            }
            false
        };

        handle_events(
            self.input.as_path(),
            modules.section_factories()?,
            &filter,
            &mut EventParser::from(&mut writer),
        )
    }
}

/// Internal logic to retrieve our events to feed the parser.
fn handle_events<W>(
    input: &Path,
    factories: SectionFactories,
    filter: &dyn Fn(&str, &str) -> bool,
    parser: &mut EventParser<W>,
) -> Result<()>
where
    W: Write,
{
    // Create running instance that will handle signal termination.
    let run = Running::new();
    run.register_term_signals()?;

    // Start our events factory.
    let mut factory = FileEventsFactory::new(input)?;
    factory.start(factories)?;

    // See if we matched (not processed!) at least one event.
    let mut matched = false;

    use EventResult::*;
    while run.running() {
        match factory.next_event(Some(Duration::from_secs(1)))? {
            Event(event) => {
                if let Some(kernel) = event.get_section::<KernelEvent>(ModuleId::Kernel) {
                    // Check the event is matching the requested symbol.
                    if !filter(&kernel.probe_type, &kernel.symbol) {
                        continue;
                    }
                    matched = true;

                    parser.parse(&event)?;
                }
            }
            Eof => break,
            Timeout => continue,
        }
    }

    if !matched {
        bail!("Probe not found in the events");
    }

    parser.report_stats();
    Ok(())
}
