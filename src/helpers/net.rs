use anyhow::{anyhow, Result};

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
