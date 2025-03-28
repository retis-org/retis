use std::fmt;

use base64::{
    display::Base64Display, engine::general_purpose::STANDARD, prelude::BASE64_STANDARD, Engine,
};
use retis_pnet::{ethernet::*, vlan::*, *};

use super::*;

/// Represents a raw packet. Stored internally as a `Vec<u8>`.
/// We don't use #[event_type] as we're implementing serde::Serialize and
/// serde::Deserialize manually.
#[derive(Clone, Debug)]
#[cfg_attr(feature = "python", derive(pyo3::IntoPyObject))]
pub struct RawPacket(pub Vec<u8>);

impl serde::Serialize for RawPacket {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.collect_str(&Base64Display::new(&self.0, &STANDARD))
    }
}

impl<'de> serde::Deserialize<'de> for RawPacket {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        struct RawPacketVisitor;

        impl serde::de::Visitor<'_> for RawPacketVisitor {
            type Value = RawPacket;

            fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
                formatter.write_str("raw packet as base64 string")
            }

            fn visit_str<E>(self, value: &str) -> Result<Self::Value, E>
            where
                E: serde::de::Error,
            {
                match BASE64_STANDARD.decode(value).map(RawPacket) {
                    Ok(v) => Ok(v),
                    Err(_) => Err(serde::de::Error::invalid_value(
                        serde::de::Unexpected::Str(value),
                        &self,
                    )),
                }
            }
        }

        deserializer.deserialize_str(RawPacketVisitor)
    }
}

#[derive(thiserror::Error, Debug)]
enum PacketFmtError {
    #[error("Formatting error")]
    Fmt(#[from] fmt::Error),
    #[error("Payload is truncated or incomplete")]
    Truncated,
    #[error("Protocol not supported ({0})")]
    NotSupported(String),
}

type FmtResult<T> = std::result::Result<T, PacketFmtError>;

impl EventFmt for RawPacket {
    fn event_fmt(&self, f: &mut Formatter, format: &DisplayFormat) -> fmt::Result {
        // Do not propagate errors on parsing: keep things best effort (except
        // for real formatting issues).
        use PacketFmtError::*;
        match self.format_packet(f, format) {
            Err(Truncated) => write!(f, "... (truncated or incomplete packet)"),
            Err(NotSupported(p)) => write!(f, "... ({p} not supported, use 'retis pcap')"),
            Err(Fmt(e)) => Err(e),
            _ => Ok(()),
        }
    }
}

impl RawPacket {
    fn format_packet(&self, f: &mut Formatter, format: &DisplayFormat) -> FmtResult<()> {
        match EthernetPacket::new(&self.0) {
            Some(eth) => self.format_ethernet(f, format, &eth),
            None => Err(PacketFmtError::Truncated),
        }
    }

    fn format_ethernet(
        &self,
        f: &mut Formatter,
        format: &DisplayFormat,
        eth: &EthernetPacket,
    ) -> FmtResult<()> {
        let etype = match helpers::etype_str(eth.get_ethertype().0) {
            Some(etype) => etype,
            // We can report non-Ethernet packets, sanity check they look like
            // one. We could still get invalid ones, if the data at the right
            // offset looks like an Ethernet packet; but what else can we do?
            None => {
                return Err(PacketFmtError::NotSupported(format!(
                    "etype {:#06x}",
                    eth.get_ethertype().0
                )))
            }
        };

        if format.print_ll {
            write!(
                f,
                "{} > {} ethertype {etype} ({:#06x})",
                eth.get_source(),
                eth.get_destination(),
                eth.get_ethertype().0
            )?;
        }

        let (etype, payload) = self.traverse_vlan(f, format, eth.get_ethertype(), eth.payload())?;

        Ok(())
    }

    fn traverse_vlan<'a>(
        &self,
        f: &mut Formatter,
        format: &DisplayFormat,
        etype: EtherType,
        payload: &'a [u8],
    ) -> FmtResult<(EtherType, &'a [u8])> {
        match etype {
            EtherTypes::Vlan | EtherTypes::PBridge | EtherTypes::QinQ => {
                match VlanPacket::new(payload) {
                    Some(vlan) => {
                        if format.print_ll {
                            self.format_vlan(f, &vlan)?;
                        }
                        self.traverse_vlan(
                            f,
                            format,
                            vlan.get_ethertype(),
                            &payload[vlan.packet_size()..],
                        )
                    }
                    None => Err(PacketFmtError::Truncated),
                }
            }
            _ => Ok((etype, payload)),
        }
    }

    fn format_vlan(&self, f: &mut Formatter, vlan: &VlanPacket) -> FmtResult<()> {
        write!(
            f,
            " vlan {} p {}{}",
            vlan.get_vlan_identifier(),
            vlan.get_priority_code_point().0,
            if vlan.get_drop_eligible_indicator() == 1 {
                " DEI"
            } else {
                ""
            },
        )?;

        let ethertype = vlan.get_ethertype();
        match helpers::etype_str(ethertype.0) {
            Some(etype) => write!(f, " ethertype {etype} ({:#06x})", ethertype.0)?,
            None => write!(f, " ethertype ({:#06x})", ethertype.0)?,
        }

        Ok(())
    }
}
