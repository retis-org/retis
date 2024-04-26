use std::fmt;

use anyhow::{anyhow, Result};
use base64::{
    display::Base64Display, engine::general_purpose::STANDARD, prelude::BASE64_STANDARD, Engine,
};

/// Returns a translation of some ethertypes into a readable format.
pub(crate) fn etype_str(etype: u16) -> Option<&'static str> {
    Some(match etype {
        0x0800 => "IPv4",
        0x0806 => "ARP",
        0x8035 => "Reverse ARP",
        0x809b => "Appletalk",
        0x80f3 => "Appletalk ARP",
        0x8100 => "802.1Q",
        0x86dd => "IPv6",
        0x880b => "PPP",
        0x8847 => "MPLS unicast",
        0x8848 => "MPLS multicast",
        0x8863 => "PPPoE D",
        0x8864 => "PPPoE S",
        0x888e => "EAPOL",
        0x88a8 => "802.1Q QinQ",
        0x88e5 => "802.1AE MACsec",
        0x88f7 => "PTP",
        _ => return None,
    })
}

/// Returns a translation of some protocols into a readable format.
pub(crate) fn protocol_str(protocol: u8) -> Option<&'static str> {
    Some(match protocol {
        1 => "ICMP",
        2 => "IGMP",
        4 => "IPIP",
        6 => "TCP",
        17 => "UDP",
        27 => "RDP",
        33 => "DCCP",
        41 => "IPv6",
        47 => "GRE",
        50 => "ESP",
        51 => "AH",
        58 => "ICMPv6",
        89 => "OSPF",
        112 => "VRRP",
        115 => "L2TP",
        132 => "SCTP",
        143 => "Ethernet",
        _ => return None,
    })
}

/// Parses an Ethernet address into a String.
pub(crate) fn parse_eth_addr(raw: &[u8; 6]) -> Result<String> {
    let mut addr = String::with_capacity(17);

    for (i, group) in raw.iter().enumerate() {
        addr.push(
            char::from_digit((group >> 4).into(), 16).ok_or_else(|| anyhow!("invalid eth byte"))?,
        );
        addr.push(
            char::from_digit((group & 0xf).into(), 16)
                .ok_or_else(|| anyhow!("invalid eth byte"))?,
        );
        if i < 5 {
            addr.push(':');
        }
    }

    Ok(addr)
}

/// Parses an IPv4 address into a String.
pub(crate) fn parse_ipv4_addr(raw: u32) -> Result<String> {
    let u8_to_utf8 = |addr: &mut String, mut input: u32| -> Result<()> {
        let mut push = false;

        for ord in [100, 10, 1] {
            let current = input / ord;
            input %= ord;

            // Do not push leading 0s but always push the last number in case
            // all we got was 0s.
            if push || current != 0 || ord == 1 {
                push = true;
                addr.push(
                    char::from_digit(current, 10).ok_or_else(|| anyhow!("invalid IPv4 digit"))?,
                );
            }
        }

        Ok(())
    };

    let mut addr = String::with_capacity(15);
    u8_to_utf8(&mut addr, raw >> 24)?;
    addr.push('.');
    u8_to_utf8(&mut addr, (raw >> 16) & 0xff)?;
    addr.push('.');
    u8_to_utf8(&mut addr, (raw >> 8) & 0xff)?;
    addr.push('.');
    u8_to_utf8(&mut addr, raw & 0xff)?;

    Ok(addr)
}

/// Represents a raw packet. Stored internally as a `Vec<u8>`.
#[derive(Clone, Debug)]
pub(crate) struct RawPacket(pub(crate) Vec<u8>);

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

        impl<'de> serde::de::Visitor<'de> for RawPacketVisitor {
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

#[cfg(test)]
mod tests {
    use std::net::Ipv4Addr;

    #[test]
    fn ethaddr_to_string() {
        assert!(
            &super::parse_eth_addr(&[0xff, 0xff, 0xff, 0xff, 0xff, 0xff]).unwrap()
                == "ff:ff:ff:ff:ff:ff"
        );
        assert!(&super::parse_eth_addr(&[0, 0, 0, 0, 0, 0]).unwrap() == "00:00:00:00:00:00");
        assert!(
            &super::parse_eth_addr(&[0x0a, 0x58, 0x0a, 0xf4, 0x00, 0x01]).unwrap()
                == "0a:58:0a:f4:00:01"
        );
    }

    #[test]
    fn ipv4_to_string() {
        assert!(&super::parse_ipv4_addr(0).unwrap() == "0.0.0.0");
        assert!(&super::parse_ipv4_addr(0xffffffff).unwrap() == "255.255.255.255");
        assert!(
            &super::parse_ipv4_addr(Ipv4Addr::new(100, 10, 1, 0).into()).unwrap() == "100.10.1.0"
        );
        assert!(
            &super::parse_ipv4_addr(Ipv4Addr::new(127, 0, 0, 0).into()).unwrap() == "127.0.0.0"
        );
    }
}
