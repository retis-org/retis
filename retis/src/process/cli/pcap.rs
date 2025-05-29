use std::{
    borrow::Cow,
    collections::{HashMap, HashSet},
    fs::{File, OpenOptions},
    path::{Path, PathBuf},
    time::Duration,
};

use anyhow::{anyhow, bail, Result};
use clap::{arg, Args, Parser};
use log::{info, warn};
use pcap_file::{
    pcapng::{
        blocks::{
            enhanced_packet::{EnhancedPacketBlock, EnhancedPacketOption},
            interface_description::{InterfaceDescriptionBlock, InterfaceDescriptionOption},
            Block,
        },
        PcapNgBlock, PcapNgWriter,
    },
    DataLink,
};

use crate::{
    cli::*,
    core::{kernel::Symbol, probe::kernel::utils::*},
    events::{file::FileEventsFactory, *},
    helpers::signals::Running,
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
struct EventParser {
    /// Known network interfaces and their PCAP id: netns|ifindex -> pcap id.
    ifaces: HashMap<u64, u32>,
    /// Statistics.
    stats: EventParserStats,
    /// Time offset
    ts_off: Option<TimeSpec>,
}

// Unwrap a Some(_) value or return from the function.
macro_rules! some_or_return {
    ($section: expr, $stat: expr) => {
        match $section {
            Some(val) => val,
            None => {
                $stat += 1;
                return Ok(Vec::<Block>::new());
            }
        }
    };
}

impl EventParser {
    /// Creates a new EventParser from a PcapNgWriter<W: Write>.
    fn new() -> Self {
        Self {
            ifaces: HashMap::new(),
            stats: EventParserStats::default(),
            ts_off: None,
        }
    }

    /// Parse & process a single Retis event.
    fn parse(&mut self, event: &Event) -> Result<Vec<Block>> {
        // Having a common & a kernel section is mandatory for now, seeing a
        // filtered event w/o one of those is bogus.
        let common = event
            .common
            .as_ref()
            .ok_or_else(|| anyhow!("No common section in event"))?;
        let kernel = event
            .kernel
            .as_ref()
            .ok_or_else(|| anyhow!("No skb section in event"))?;

        self.stats.processed += 1;

        // The skb & packet sections are mandatory for us to generate PCAP
        // events, but they might not be present in some filtered events. Stats
        // are kept here to inform the user.
        let skb = some_or_return!(&event.skb, self.stats.missing_skb);
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
        let mut v = Vec::new();
        let key: u64 = ((netns as u64) << 32) | ifindex as u64;
        let id = match self.ifaces.contains_key(&key) {
            // Unwrap if contains is true.
            true => *self.ifaces.get(&key).unwrap(),
            false => {
                v.push(
                    InterfaceDescriptionBlock {
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
                            InterfaceDescriptionOption::IfTsResol(9),
                        ],
                    }
                    .into_block(),
                );

                let id = self.ifaces.len() as u32;
                self.ifaces.insert(key, id);
                id
            }
        };

        // Add the packet itself.
        v.push(
            EnhancedPacketBlock {
                interface_id: id,
                timestamp: Duration::from_nanos(i64::from(
                    TimeSpec::new(0, common.timestamp as i64) + self.ts_off.unwrap_or_default(),
                ) as u64),
                original_len: packet.len,
                data: Cow::Borrowed(&packet.packet.0),
                options: vec![EnhancedPacketOption::Comment(Cow::Owned(format!(
                    "probe={}:{}",
                    &kernel.probe_type, &kernel.symbol
                )))],
            }
            .into_owned()
            .into_block(),
        );

        Ok(v)
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
    #[command(flatten)]
    cmd: PcapCmd,
    #[arg(
        short,
        long,
        conflicts_with = "list_probes",
        help = "Write the generated PCAP output to a file rather than stdout"
    )]
    pub(super) out: Option<PathBuf>,
    #[arg(default_value = "retis.data", help = "File from which to read events")]
    pub(super) input: PathBuf,
}
#[derive(Args, Debug, Default)]
#[group(required = true, multiple = false)]
pub(crate) struct PcapCmd {
    #[arg(short, long, help = "List probes that are available in the input file")]
    pub(super) list_probes: bool,
    #[arg(
        short,
        long,
        help = "Filter events from this probe. Probes should follow the [TYPE:]TARGET pattern.
See `retis collect --help` for more details on the probe format"
    )]
    pub(super) probe: Option<String>,
}

impl SubCommandParserRunner for Pcap {
    fn run(&mut self, _: &MainConfig) -> Result<()> {
        if self.cmd.list_probes {
            let probes = list_probes(self.input.as_path())?;
            probes.iter().for_each(|p| println!("{p}"));
            return Ok(());
        }
        // The following unwrap() will never fail as Clap makes sure that either
        // list_probes is true, or probe is Some().
        let probe = self.cmd.probe.as_ref().unwrap();
        let (probe_type, target, _) = parse_cli_probe(probe)?;
        let symbol = Symbol::from_name_no_inspect(target);

        // Filtering logic.
        let filter = |r#type: &str, name: &str| -> bool {
            if name == symbol.name() && r#type == probe_type.to_str() {
                return true;
            }
            false
        };

        let mut writer: Option<PcapNgWriter<File>> = None;
        let write_block = |b: &Block| -> Result<()> {
            if writer.is_none() {
                // Create a PCAP writer to push our events / metadata.
                writer = Some(PcapNgWriter::new(match &self.out {
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
                })?);
            }
            writer.as_mut().unwrap().write_block(b)?;
            Ok(())
        };

        handle_events(
            self.input.as_path(),
            &filter,
            &mut EventParser::new(),
            write_block,
        )?;
        Ok(())
    }
}

/// Internal logic to retrieve our events to feed the parser.
fn handle_events<F>(
    input: &Path,
    filter: &dyn Fn(&str, &str) -> bool,
    parser: &mut EventParser,
    mut writer_callback: F,
) -> Result<()>
where
    F: FnMut(&Block) -> Result<()>,
{
    // Create running instance that will handle signal termination.
    let run = Running::new();
    run.register_term_signals()?;

    // Start our events factory.
    let mut factory = FileEventsFactory::new(input)?;

    // See if we matched (not processed!) at least one event.
    let mut matched = false;
    while run.running() {
        match factory.next_event()? {
            Some(event) => {
                if let Some(kernel) = &event.kernel {
                    // Check the event is matching the requested symbol.
                    if !filter(&kernel.probe_type, &kernel.symbol) {
                        continue;
                    }
                    matched = true;

                    // Parse the event and then write the pcap blocks to the file.
                    let parsed_blocks = parser.parse(&event)?;
                    for b in parsed_blocks {
                        writer_callback(&b)?;
                    }
                } else if let Some(common) = event.startup {
                    parser.ts_off = Some(common.clock_monotonic_offset);
                }
            }
            None => break,
        }
    }

    if !matched {
        bail!("Probe not found in the events");
    }

    parser.report_stats();
    Ok(())
}

/// List the probes that are available in the input. Only add probes from events
/// that pass the sanity check.
fn list_probes(input: &Path) -> Result<Vec<String>> {
    let mut probe_set: HashSet<String> = HashSet::new();

    // Create running instance that will handle signal termination.
    let run = Running::new();
    run.register_term_signals()?;

    // Start our events factory.
    let mut factory = FileEventsFactory::new(input)?;

    while run.running() {
        match factory.next_event()? {
            None => break,
            Some(event) => {
                if let Some(kernel) = event.kernel {
                    let probe_name = format!("{}:{}", kernel.probe_type, kernel.symbol);
                    if probe_set.contains(&probe_name) {
                        continue;
                    }
                    // Having a common section is mandatory for now, seeing a
                    // filtered event w/o one of those is bogus.
                    if event.common.is_none() {
                        continue;
                    }
                    // The skb & packet sections are mandatory for us to generate PCAP
                    // events, but they might not be present in some filtered events.
                    match event.skb {
                        None => {}
                        Some(skb) => {
                            if skb.packet.as_ref().is_some() {
                                probe_set.insert(probe_name);
                            }
                        }
                    }
                }
            }
        }
    }

    if probe_set.is_empty() {
        bail!("Could not find any compatible probe in provided data set");
    }
    let mut probes = probe_set.into_iter().collect::<Vec<String>>();
    probes.sort();
    Ok(probes)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_handle_events() {
        let test_cases = [
            // Valid data.
            (
                "test_data/test_events_packets.json",
                "kretprobe",
                "ovs_dp_upcall",
                Ok(()),
                vec![
                    Block::InterfaceDescription(InterfaceDescriptionBlock {
                        linktype: DataLink::ETHERNET,
                        snaplen: 65535,
                        options: vec![
                            InterfaceDescriptionOption::IfName(Cow::Owned(
                                "veth-ns01-ovs (4026531840)".to_string(),
                            )),
                            InterfaceDescriptionOption::IfDescription(Cow::Owned(
                                "ifindex=10".to_string(),
                            )),
                            InterfaceDescriptionOption::IfTsResol(9),
                        ],
                    }),
                    Block::EnhancedPacket(EnhancedPacketBlock {
                        data: Cow::Borrowed(&[
                            250, 92, 189, 142, 204, 1, 166, 194, 17, 113, 89, 69, 8, 0, 69, 0, 0,
                            84, 163, 249, 64, 0, 64, 1, 27, 73, 192, 168, 125, 10, 192, 168, 125,
                            11, 8, 0, 64, 90, 113, 76, 0, 1, 237, 253, 217, 103, 0, 0, 0, 0, 179,
                            31, 13, 0, 0, 0, 0, 0, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27,
                            28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40, 41, 42, 43, 44, 45,
                            46, 47, 48, 49, 50, 51, 52, 53, 54, 55,
                        ]),
                        interface_id: 0,
                        timestamp: Duration::from_nanos(1742339565860167909),
                        original_len: 98,
                        options: vec![EnhancedPacketOption::Comment(Cow::Owned(
                            "probe=kretprobe:ovs_dp_upcall".to_string(),
                        ))],
                    }),
                    Block::InterfaceDescription(InterfaceDescriptionBlock {
                        linktype: DataLink::ETHERNET,
                        snaplen: 65535,
                        options: vec![
                            InterfaceDescriptionOption::IfName(Cow::Owned(
                                "veth-ns02-ovs (4026531840)".to_string(),
                            )),
                            InterfaceDescriptionOption::IfDescription(Cow::Owned(
                                "ifindex=12".to_string(),
                            )),
                            InterfaceDescriptionOption::IfTsResol(9),
                        ],
                    }),
                    Block::EnhancedPacket(EnhancedPacketBlock {
                        data: Cow::Borrowed(&[
                            166, 194, 17, 113, 89, 69, 250, 92, 189, 142, 204, 1, 8, 0, 69, 0, 0,
                            84, 76, 35, 0, 0, 64, 1, 179, 31, 192, 168, 125, 11, 192, 168, 125, 10,
                            0, 0, 72, 90, 113, 76, 0, 1, 237, 253, 217, 103, 0, 0, 0, 0, 179, 31,
                            13, 0, 0, 0, 0, 0, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28,
                            29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40, 41, 42, 43, 44, 45, 46,
                            47, 48, 49, 50, 51, 52, 53, 54, 55,
                        ]),
                        interface_id: 1,
                        timestamp: Duration::from_nanos(1742339565860414774),
                        original_len: 98,
                        options: vec![EnhancedPacketOption::Comment(Cow::Owned(
                            "probe=kretprobe:ovs_dp_upcall".to_string(),
                        ))],
                    }),
                ],
            ),
            // Partially valid data (outdated ct, missing ct_status field).
            // TODO: Skip invalid lines, but process everything else.
            // Both for list-probes and for generating the actual pcap.
            (
                "test_data/test_events_packets_invalid_ct.json",
                "",
                "",
                Err(anyhow!("missing field `ct_status` at line 1 column 404")),
                Vec::<Block>::new(),
            ),
            // No packet data provided.
            (
                "test_data/test_events_bench.json",
                "",
                "",
                Err(anyhow!("Probe not found in the events")),
                Vec::<Block>::new(),
            ),
            // Completely missing probe section.
            (
                "test_data/test_events_bench_no_probes.json",
                "",
                "",
                Err(anyhow!("Probe not found in the events")),
                Vec::<Block>::new(),
            ),
            // Garbage data.
            (
                "test_data/available_events",
                "",
                "",
                Err(anyhow!(
                    "Failed to parse event file: \
                Error(\"expected value\", line: 1, column: 1)"
                )),
                Vec::<Block>::new(),
            ),
        ];
        for (file_path, filter_probe_type, filter_symbol, expected_res, expected_blocks) in
            test_cases.into_iter()
        {
            // Filtering logic.
            let filter = |r#type: &str, name: &str| -> bool {
                if name == filter_symbol && r#type == filter_probe_type {
                    return true;
                }
                false
            };
            // Write all results into a vector.
            let mut blocks = Vec::<Block>::new();
            let write_blocks = |b: &Block| -> Result<()> {
                blocks.push(b.clone().into_owned());
                Ok(())
            };
            match handle_events(
                Path::new(file_path),
                &filter,
                &mut EventParser::new(),
                write_blocks,
            ) {
                Ok(v) => match expected_res {
                    Ok(expected_v) => {
                        assert_eq!(v, expected_v);
                        assert_eq!(blocks, expected_blocks);
                    }
                    Err(expected_e) => {
                        panic!(
                            "Expected error but got valid result instead\n\
                            expected error: {}\n\
                            result: {:#?}",
                            expected_e, v
                        )
                    }
                },
                Err(e) => match expected_res {
                    Ok(expected_v) => {
                        panic!(
                            "Expected a valid result but got err instead\n\
                            result: {:#?},\n\
                            err: {}",
                            expected_v, e
                        )
                    }
                    Err(expected_e) => assert_eq!(e.to_string(), expected_e.to_string(),),
                },
            }
        }
    }

    #[test]
    fn test_list_probes() {
        let test_cases = [
            // Valid data.
            (
                "test_data/test_events_packets.json",
                Ok(vec![
                    "kretprobe:ovs_dp_upcall".to_string(),
                    "raw_tracepoint:net:net_dev_start_xmit".to_string(),
                    "raw_tracepoint:net:netif_receive_skb".to_string(),
                    "raw_tracepoint:openvswitch:ovs_do_execute_action".to_string(),
                    "raw_tracepoint:openvswitch:ovs_dp_upcall".to_string(),
                    "raw_tracepoint:skb:kfree_skb".to_string(),
                ]),
            ),
            // Partially valid data (outdated ct, missing ct_status field).
            // TODO: Skip invalid lines, but process everything else.
            // Both for list-probes and for generating the actual pcap.
            (
                "test_data/test_events_packets_invalid_ct.json",
                Err(anyhow!("missing field `ct_status` at line 1 column 404")),
            ),
            // Completely missing probe section.
            (
                "test_data/test_events_bench_no_probes.json",
                Err(anyhow!(
                    "Could not find any compatible probe in provided data set"
                )),
            ),
            // Garbage data.
            (
                "test_data/available_events",
                Err(anyhow!(
                    "Failed to parse event file: \
                Error(\"expected value\", line: 1, column: 1)"
                )),
            ),
        ];
        for (file_path, expected_res) in test_cases.into_iter() {
            match list_probes(Path::new(file_path)) {
                Ok(v) => match expected_res {
                    Ok(expected_v) => assert_eq!(v, expected_v),
                    Err(expected_e) => {
                        panic!(
                            "Expected error but got valid result instead\n\
                            expected error: {}\n\
                            result: {:#?}",
                            expected_e, v
                        )
                    }
                },
                Err(e) => match expected_res {
                    Ok(expected_v) => {
                        panic!(
                            "Expected a valid result but got err instead\n\
                            result: {:#?},\n\
                            err: {}",
                            expected_v, e
                        )
                    }
                    Err(expected_e) => assert_eq!(e.to_string(), expected_e.to_string(),),
                },
            }
        }
    }
}
