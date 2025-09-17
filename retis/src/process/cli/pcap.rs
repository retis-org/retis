use std::{
    borrow::Cow,
    collections::{HashMap, HashSet},
    fs::{File, OpenOptions},
    io::Write,
    path::{Path, PathBuf},
    time::Duration,
};

use anyhow::{anyhow, bail, Result};
use clap::Parser;
use log::{info, warn};
use pcap_file::{
    pcapng::{
        blocks::{
            custom::CustomCopiable,
            enhanced_packet::{EnhancedPacketBlock, EnhancedPacketOption},
            interface_description::{InterfaceDescriptionBlock, InterfaceDescriptionOption},
            opt_common::{CommonOption, CustomUtf8Option},
            Block,
        },
        PcapNgBlock, PcapNgWriter,
    },
    DataLink,
};
use schemars::{schema_for, Schema};

use crate::{
    cli::*,
    core::{kernel::Symbol, probe::kernel::utils::*},
    events::{file::FileEventsFactory, helpers::time::TimeSpec, *},
    helpers::signals::Running,
};

/// Statistics of the event parser about events (processed, skipped, etc).
#[derive(Default)]
struct EventParserStats {
    /// Events that were processed by the parser. Aka. all events that were
    /// matched by the filter.
    processed: u32,
    /// Events w/o a packet section (skipped).
    missing_packet: u32,
}

/// Events parser: handles the logic to convert our events to the PCAP format
/// that is represented by the internal writer.
struct EventParser {
    /// Pcapng files contain blocks that describe interfaces where packets were
    /// captured (called InterfaceDescriptionBlock). Once such a block is added
    /// to a pcapng file, packet blocks can refer to it by its id.
    /// This map holds the internal cache of known interface names and their
    /// ids. Note we don't really use actual network interfaces, instead we
    /// create fake interfaces based on probing points ({type}/{name}).
    ifaces: HashMap<String, u32>,
    /// Statistics.
    stats: EventParserStats,
    /// Time offset
    ts_off: Option<TimeSpec>,
    /// Whether the header was written
    wrote_header: bool,
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

// TODO: Register with IANA?
const RETIS_PEN: u32 = 70000;

/// Custom block containing the JSON-Schema of events.
struct SchemaBlock {
    schema: Schema,
}

impl SchemaBlock {
    fn new() -> Result<Self> {
        Ok(SchemaBlock {
            schema: schema_for!(Event),
        })
    }
}

impl CustomCopiable<'_> for SchemaBlock {
    const PEN: u32 = RETIS_PEN;
    type FromSliceError = SchemaBlockError;
    type WriteToError = SchemaBlockError;

    fn write_to<W: Write>(&self, writer: &mut W) -> Result<(), SchemaBlockError> {
        let bytes = serde_json::to_vec(&self.schema)?;
        writer.write_all(&bytes[..])?;
        Ok(())
    }

    fn from_slice(slice: &[u8]) -> Result<Option<Self>, SchemaBlockError> {
        let schema: Schema = serde_json::from_slice(slice)?;
        Ok(Some(SchemaBlock { schema }))
    }
}

// Custom error used for pcap-file API.
#[derive(thiserror::Error, Debug)]
enum SchemaBlockError {
    #[error("json error: {0}")]
    Json(#[from] serde_json::Error),
    #[error("i/o error: {0}")]
    Io(#[from] std::io::Error),
}

impl EventParser {
    /// Creates a new EventParser from a PcapNgWriter<W: Write>.
    fn new() -> Self {
        Self {
            ifaces: HashMap::new(),
            stats: EventParserStats::default(),
            ts_off: None,
            wrote_header: false,
        }
    }

    /// Extract interface information adding any necessary block and updating internal cache
    /// accordingly.
    fn process_interface(&mut self, event: &Event, blocks: &mut Vec<Block<'_>>) -> Result<u32> {
        let iface = if let Some(kernel) = &event.kernel {
            format!("{}/{}", kernel.probe_type, kernel.symbol)
        } else {
            bail!("only events with kernel sections are currently supported");
        };
        let key = iface.clone();
        let desc = format!("Fake interface for probe {iface}");

        // If we see this iface for the first time, add a description block.
        let id = match self.ifaces.contains_key(&key) {
            // Unwrap if contains is true.
            true => *self.ifaces.get(&key).unwrap(),
            false => {
                blocks.push(
                    InterfaceDescriptionBlock {
                        linktype: DataLink::ETHERNET,
                        snaplen: 0xffff,
                        options: vec![
                            InterfaceDescriptionOption::IfName(iface.into()),
                            InterfaceDescriptionOption::IfDescription(desc.into()),
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
        Ok(id)
    }

    /// Parse & process a single Retis event.
    fn parse(&mut self, event: &mut Event) -> Result<Vec<Block<'_>>> {
        // Having a common & a kernel section is mandatory for now, seeing a
        // filtered event w/o one of those is bogus.
        let common = event
            .common
            .as_ref()
            .ok_or_else(|| anyhow!("No common section in event"))?;

        self.stats.processed += 1;

        let comment = format!(
            "{}",
            event.display(&DisplayFormat::new().multiline(true), &FormatterConf::new())
        );

        // The packet section is mandatory for us to generate PCAP events, but
        // it might not be present in some filtered events. Stats are kept to
        // inform the user. Removing the packet from the event to avoid adding it
        // to the pcapng file twice.
        let packet = some_or_return!(event.packet.take(), self.stats.missing_packet);

        let mut v = Vec::new();

        // If we see this iface for the first time, add a description block.
        if !self.wrote_header {
            v.push(SchemaBlock::new()?.into_custom_block()?.into_block());
            self.wrote_header = true;
        }

        let id = self.process_interface(event, &mut v)?;

        // Add the packet itself.
        v.push(
            EnhancedPacketBlock {
                interface_id: id,
                timestamp: Duration::from_nanos(i64::from(
                    TimeSpec::new(0, common.timestamp as i64) + self.ts_off.unwrap_or_default(),
                ) as u64),
                original_len: packet.len,
                data: Cow::Borrowed(&packet.data.0),
                options: vec![
                    EnhancedPacketOption::Common(CommonOption::Comment(Cow::Owned(comment))),
                    EnhancedPacketOption::Common(CommonOption::CustomUtf8Copiable(
                        CustomUtf8Option {
                            pen: RETIS_PEN,
                            value: Cow::Owned(serde_json::to_string(&event)?),
                        },
                    )),
                ],
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

        if self.stats.missing_packet != 0 {
            warn!(
                "{} event(s) were skipped because of missing raw packet",
                self.stats.missing_packet
            );
        }
    }
}

#[derive(Parser, Debug, Default)]
#[command(name = "pcap", about = "Generate a PCAP file from stored events.")]
pub(crate) struct Pcap {
    #[arg(
        short,
        long,
        conflicts_with = "list_probes",
        help = "Write the generated PCAP output to a file rather than stdout"
    )]
    pub(super) out: Option<PathBuf>,
    #[arg(default_value = "retis.data", help = "File from which to read events")]
    pub(super) input: PathBuf,
    #[arg(short, long, help = "List probes that are available in the input file")]
    pub(super) list_probes: bool,
    #[arg(
        short,
        long,
        help = "Filter events from this probe. Probes should follow the [TYPE:]TARGET pattern. See `retis collect --help` for more details on the probe format"
    )]
    pub(super) probe: Option<String>,
}

impl SubCommandParserRunner for Pcap {
    fn run(&mut self, _: &MainConfig) -> Result<()> {
        if self.list_probes {
            let probes = list_probes(self.input.as_path())?;
            probes.iter().for_each(|p| println!("{p}"));
            return Ok(());
        }
        // The following unwrap() will never fail as Clap makes sure that either
        // list_probes is true, or probe is Some().
        let filter: &dyn Fn(&str, &str) -> bool = if let Some(probe) = self.probe.as_ref() {
            let (probe_type, target, _) = parse_cli_probe(probe)?;
            let symbol = Symbol::from_name_no_inspect(target);

            // Filtering logic.
            &move |r#type: &str, name: &str| -> bool {
                if name == symbol.name() && r#type == probe_type.to_str() {
                    return true;
                }
                false
            }
        } else {
            &|_t: &str, _n: &str| -> bool { true }
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
            Some(mut event) => {
                if let Some(kernel) = &event.kernel {
                    // Check the event is matching the requested symbol.
                    if !filter(&kernel.probe_type, &kernel.symbol) {
                        continue;
                    }
                    matched = true;

                    // Parse the event and then write the pcap blocks to the file.
                    let parsed_blocks = parser.parse(&mut event)?;
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
                    // The packet section is mandatory for us to generate PCAP
                    // events, but it might not be present in some filtered
                    // events.
                    if event.packet.is_none() {
                        continue;
                    }

                    probe_set.insert(probe_name);
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
                    SchemaBlock::new()
                        .expect("Failed to create SchemaBlock")
                        .into_custom_block()
                        .expect("Failed to convert SchemaBlock into block")
                        .into_block(),
                    Block::InterfaceDescription(InterfaceDescriptionBlock {
                        linktype: DataLink::ETHERNET,
                        snaplen: 65535,
                        options: vec![
                            InterfaceDescriptionOption::IfName(Cow::Owned(
                                "kretprobe/ovs_dp_upcall".to_string(),
                            )),
                            InterfaceDescriptionOption::IfDescription(Cow::Owned(
                                "Fake interface for probe kretprobe/ovs_dp_upcall".to_string(),
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
                        options: vec![
                            EnhancedPacketOption::Common(CommonOption::Comment(Cow::Owned("30419169125909 (6) [ping] 11330 [kr] ovs_dp_upcall #1baa83c42ba1ffff8e95c3b67c00 (skb ffff8e95d3009100)\n  192.168.125.10 > 192.168.125.11 tos 0x0 ttl 64 id 41977 off 0 [DF] len 84 proto ICMP (1) type 8 code 0\n  ns 0x1/4026531840 if 10 (veth-ns01-ovs) rxif 10\n  skb [csum none hash 0x7e2c5976 len 98 priority 0 users 1 dataref 1]\n  upcall_ret (6/30419169098548) ret 0".to_string()))),
                            EnhancedPacketOption::Common(CommonOption::CustomUtf8Copiable(
                                CustomUtf8Option {
                                pen: RETIS_PEN,
                                value: Cow::Owned(String::from(
                                    r#"{"common":{"timestamp":30419169125909,"smp_id":6,"task":{"pid":11330,"tgid":11330,"comm":"ping"}},"kernel":{"symbol":"ovs_dp_upcall","probe_type":"kretprobe"},"skb-tracking":{"orig_head":18446619372617628672,"timestamp":30419169061793,"skb":18446619372874141952},"skb":{"meta":{"len":98,"data_len":0,"hash":2116835702,"ip_summed":0,"csum":2770033380,"csum_level":0,"priority":0},"data_ref":{"nohdr":false,"cloned":false,"fclone":0,"users":1,"dataref":1}},"netns":{"cookie":1,"inum":4026531840},"dev":{"name":"veth-ns01-ovs","ifindex":10,"rx_ifindex":10},"ovs":{"event_type":"upcall_return","upcall_ts":30419169098548,"upcall_cpu":6,"ret":0}}"#,
                                )),
                            })),
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
                        interface_id: 0,
                        timestamp: Duration::from_nanos(1742339565860414774),
                        original_len: 98,
                        options: vec![
                            EnhancedPacketOption::Common(CommonOption::Comment(Cow::Owned("30419169372774 (6) [handler8] 985/995 [kr] ovs_dp_upcall #1baa83c8a025ffff8e95c3b67c00 (skb ffff8e95d3009200)\n  192.168.125.11 > 192.168.125.10 tos 0x0 ttl 64 id 19491 off 0 len 84 proto ICMP (1) type 0 code 0\n  ns 0x1/4026531840 if 12 (veth-ns02-ovs) rxif 12\n  skb [csum none hash 0x7e2c5976 len 98 priority 0 users 1 dataref 1]\n  upcall_ret (6/30419169364667) ret 0".to_string()
                            ))),
                            EnhancedPacketOption::Common(CommonOption::CustomUtf8Copiable(
                                CustomUtf8Option {
                                pen: RETIS_PEN,
                                value: Cow::Owned(String::from(
                                    r#"{"common":{"timestamp":30419169372774,"smp_id":6,"task":{"pid":985,"tgid":995,"comm":"handler8"}},"kernel":{"symbol":"ovs_dp_upcall","probe_type":"kretprobe"},"skb-tracking":{"orig_head":18446619372617628672,"timestamp":30419169353765,"skb":18446619372874142208},"skb":{"meta":{"len":98,"data_len":0,"hash":2116835702,"ip_summed":0,"csum":2753213483,"csum_level":0,"priority":0},"data_ref":{"nohdr":false,"cloned":false,"fclone":0,"users":1,"dataref":1}},"netns":{"cookie":1,"inum":4026531840},"dev":{"name":"veth-ns02-ovs","ifindex":12,"rx_ifindex":12},"ovs":{"event_type":"upcall_return","upcall_ts":30419169364667,"upcall_cpu":6,"ret":0}}"#,
                                )),
                            })),
                        ],
                    }),
                ],
            ),
            // Valid data with no probe filter
            (
                "test_data/test_events_packets.json",
                "",
                "",
                Ok(()),
                vec![
                    SchemaBlock::new()
                        .expect("Failed to create SchemaBlock")
                        .into_custom_block()
                        .expect("Failed to convert SchemaBlock into block")
                        .into_block(),
                    Block::InterfaceDescription(InterfaceDescriptionBlock {
                        linktype: DataLink::ETHERNET,
                        snaplen: 65535,
                        options: vec![
                            InterfaceDescriptionOption::IfName(Cow::Owned(
                                "raw_tracepoint/net:net_dev_start_xmit".to_string(),
                            )),
                            InterfaceDescriptionOption::IfDescription(Cow::Owned(
                                "Fake interface for probe raw_tracepoint/net:net_dev_start_xmit".to_string(),
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
                        timestamp: Duration::from_nanos(1742339565860103793),
                        original_len: 98,
                        options: vec![
                            EnhancedPacketOption::Common(CommonOption::Comment(Cow::Owned("30419169061793 (6) [ping] 11330 [tp] net:net_dev_start_xmit #1baa83c42ba1ffff8e95c3b67c00 (skb ffff8e95d3009100)\n  192.168.125.10 > 192.168.125.11 tos 0x0 ttl 64 id 41977 off 0 [DF] len 84 proto ICMP (1) type 8 code 0\n  ns 0x3/4026532741 if 11 (veth-ns01)\n  skb [csum none len 98 priority 0 users 1 dataref 1]\n  ct_state NEW status 0x8 icmp orig [192.168.125.10 > 192.168.125.11 type 8 code 0 id 29004] reply [192.168.125.11 > 192.168.125.10 type 0 code 0 id 29004] zone 0 mark 0".to_string()))),
                            EnhancedPacketOption::Common(CommonOption::CustomUtf8Copiable(CustomUtf8Option {
                                pen: RETIS_PEN,
                                value: Cow::Owned(String::from(
                                r#"{"common":{"timestamp":30419169061793,"smp_id":6,"task":{"pid":11330,"tgid":11330,"comm":"ping"}},"kernel":{"symbol":"net:net_dev_start_xmit","probe_type":"raw_tracepoint"},"skb-tracking":{"orig_head":18446619372617628672,"timestamp":30419169061793,"skb":18446619372874141952},"skb":{"meta":{"len":98,"data_len":0,"hash":0,"ip_summed":0,"csum":2770033380,"csum_level":0,"priority":0},"data_ref":{"nohdr":false,"cloned":false,"fclone":0,"users":1,"dataref":1}},"netns":{"cookie":3,"inum":4026532741},"dev":{"name":"veth-ns01","ifindex":11},"ct":{"state":"new","zone_id":0,"zone_dir":"Default","orig":{"ip":{"src":"192.168.125.10","dst":"192.168.125.11","version":"v4"},"proto":{"icmp":{"code":0,"type":8,"id":29004}}},"reply":{"ip":{"src":"192.168.125.11","dst":"192.168.125.10","version":"v4"},"proto":{"icmp":{"code":0,"type":0,"id":29004}}},"mark":0,"ct_status":8}}"#)),
                            })),
                        ],
                    }),
                    Block::InterfaceDescription(InterfaceDescriptionBlock {
                        linktype: DataLink::ETHERNET,
                        snaplen: 65535,
                        options: vec![
                            InterfaceDescriptionOption::IfName(Cow::Owned(
                                "raw_tracepoint/net:netif_receive_skb".to_string(),
                            )),
                            InterfaceDescriptionOption::IfDescription(Cow::Owned(
                                "Fake interface for probe raw_tracepoint/net:netif_receive_skb".to_string(),
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
                        interface_id: 1,
                        timestamp: Duration::from_nanos(1742339565860124348),
                        original_len: 98,
                        options: vec![
                            EnhancedPacketOption::Common(CommonOption::Comment(Cow::Owned("30419169082348 (6) [ping] 11330 [tp] net:netif_receive_skb #1baa83c42ba1ffff8e95c3b67c00 (skb ffff8e95d3009100)\n  192.168.125.10 > 192.168.125.11 tos 0x0 ttl 64 id 41977 off 0 [DF] len 84 proto ICMP (1) type 8 code 0\n  ns 0x1/4026531840 if 10 (veth-ns01-ovs)\n  skb [csum none len 84 priority 0 users 1 dataref 1]".to_string()
                            ))),
                            EnhancedPacketOption::Common(CommonOption::CustomUtf8Copiable(CustomUtf8Option {
                                pen: RETIS_PEN,
                                value: Cow::Owned(String::from(
                                    r#"{"common":{"timestamp":30419169082348,"smp_id":6,"task":{"pid":11330,"tgid":11330,"comm":"ping"}},"kernel":{"symbol":"net:netif_receive_skb","probe_type":"raw_tracepoint"},"skb-tracking":{"orig_head":18446619372617628672,"timestamp":30419169061793,"skb":18446619372874141952},"skb":{"meta":{"len":84,"data_len":0,"hash":0,"ip_summed":0,"csum":2770033380,"csum_level":0,"priority":0},"data_ref":{"nohdr":false,"cloned":false,"fclone":0,"users":1,"dataref":1}},"netns":{"cookie":1,"inum":4026531840},"dev":{"name":"veth-ns01-ovs","ifindex":10}}"#
                                )),
                            })),
                        ],
                    }),
                ],
            ),
            // No packet data provided.
            (
                "test_data/test_events_bench.json",
                "",
                "",
                Ok(()),
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
                if filter_symbol.is_empty()
                    || (name == filter_symbol && r#type == filter_probe_type)
                {
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
                        if filter_symbol.is_empty() {
                            blocks = blocks[0..expected_blocks.len()].into()
                        }
                        assert_eq!(blocks, expected_blocks);
                    }
                    Err(expected_e) => {
                        panic!(
                            "Expected error but got valid result instead\n\
                            expected error: {expected_e}\n\
                            result: {v:#?}"
                        )
                    }
                },
                Err(e) => match expected_res {
                    Ok(expected_v) => {
                        panic!(
                            "Expected a valid result but got err instead\n\
                            result: {expected_v:#?},\n\
                            err: {e}"
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
                            expected error: {expected_e}\n\
                            result: {v:#?}"
                        )
                    }
                },
                Err(e) => match expected_res {
                    Ok(expected_v) => {
                        panic!(
                            "Expected a valid result but got err instead\n\
                            result: {expected_v:#?},\n\
                            err: {e}"
                        )
                    }
                    Err(expected_e) => assert_eq!(e.to_string(), expected_e.to_string(),),
                },
            }
        }
    }
}
