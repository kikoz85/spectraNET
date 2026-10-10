//! Decoding of BSD `sockaddr_in` / `sockaddr_in6` structures as delivered by the kernel.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

const AF_INET: u8 = 2;
const AF_INET6: u8 = 30;

/// Parses a raw BSD socket address. Returns `None` for other families or truncated input.
///
/// Layout (macOS): `sa_len: u8, sa_family: u8, port: u16 (big-endian)`, then for IPv4 the
/// 4-byte address, for IPv6 `flowinfo: u32` followed by the 16-byte address.
pub fn parse(bytes: &[u8]) -> Option<SocketAddr> {
    let family = *bytes.get(1)?;
    let port = u16::from_be_bytes([*bytes.get(2)?, *bytes.get(3)?]);
    let ip = match family {
        AF_INET => {
            let octets: [u8; 4] = bytes.get(4..8)?.try_into().ok()?;
            IpAddr::V4(Ipv4Addr::from(octets))
        }
        AF_INET6 => {
            let octets: [u8; 16] = bytes.get(8..24)?.try_into().ok()?;
            let v6 = Ipv6Addr::from(octets);
            // Dual-stack sockets report IPv4 peers as ::ffff:a.b.c.d; show them as IPv4.
            v6.to_ipv4_mapped().map_or(IpAddr::V6(v6), IpAddr::V4)
        }
        _ => return None,
    };
    Some(SocketAddr::new(ip, port))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_ipv4() {
        // sockaddr_in for 192.168.1.23:443
        let raw = [
            16, AF_INET, 0x01, 0xbb, 192, 168, 1, 23, 0, 0, 0, 0, 0, 0, 0, 0,
        ];
        assert_eq!(parse(&raw), Some("192.168.1.23:443".parse().unwrap()));
    }

    #[test]
    fn parses_ipv6_and_unmaps_ipv4() {
        let mut raw = [0u8; 28];
        raw[0] = 28;
        raw[1] = AF_INET6;
        raw[2..4].copy_from_slice(&8080u16.to_be_bytes());
        raw[8..24].copy_from_slice(&"2001:db8::1".parse::<Ipv6Addr>().unwrap().octets());
        assert_eq!(parse(&raw), Some("[2001:db8::1]:8080".parse().unwrap()));

        raw[8..24].copy_from_slice(&"::ffff:1.2.3.4".parse::<Ipv6Addr>().unwrap().octets());
        assert_eq!(parse(&raw), Some("1.2.3.4:8080".parse().unwrap()));
    }

    #[test]
    fn unspecified_address_from_kernel_dump() {
        // Real value observed for an unconnected UDP socket: 0x10020000 00000000 ...
        let raw = [0x10, 0x02, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
        let addr = parse(&raw).unwrap();
        assert!(addr.ip().is_unspecified());
        assert_eq!(addr.port(), 0);
    }

    #[test]
    fn rejects_unknown_or_short() {
        assert_eq!(parse(&[]), None);
        assert_eq!(parse(&[16, AF_INET, 0, 80]), None);
        assert_eq!(parse(&[16, 1, 0, 0, 0, 0, 0, 0]), None);
    }
}
