//! Decoding captured link-layer frames down to the transport payload.

use std::net::{IpAddr, SocketAddr};

use etherparse::{NetSlice, SlicedPacket, TransportSlice};

/// Link-layer framing of a capture, from the pcap `DLT_*` / `LINKTYPE_*` value.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Link {
    Ethernet,
    /// BSD loopback / utun: 4-byte address family in host byte order.
    Null,
    /// OpenBSD loopback: 4-byte address family in network byte order.
    Loop,
    /// Bare IPv4 or IPv6 packet.
    Raw,
    /// Linux "cooked" capture (the `any` interface): 16-byte header, protocol at offset 14.
    LinuxSll,
    /// Linux cooked capture v2: 20-byte header, protocol at offset 0.
    LinuxSll2,
}

impl Link {
    pub fn from_dlt(dlt: i32) -> Option<Self> {
        match dlt {
            1 => Some(Self::Ethernet),
            0 => Some(Self::Null),
            108 => Some(Self::Loop),
            12 | 14 | 101 | 228 | 229 => Some(Self::Raw),
            113 => Some(Self::LinuxSll),
            276 => Some(Self::LinuxSll2),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Proto {
    Udp,
    Tcp {
        seq: u32,
        syn: bool,
        fin: bool,
        rst: bool,
    },
}

/// One decoded transport segment.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Segment<'a> {
    pub src: SocketAddr,
    pub dst: SocketAddr,
    pub proto: Proto,
    pub payload: &'a [u8],
}

/// Decodes a frame; `None` for anything that is not unfragmented TCP/UDP over IP.
pub fn decode(link: Link, frame: &[u8]) -> Option<Segment<'_>> {
    let sliced = match link {
        Link::Ethernet => SlicedPacket::from_ethernet(frame).ok()?,
        Link::Null | Link::Loop => SlicedPacket::from_ip(frame.get(4..)?).ok()?,
        Link::Raw => SlicedPacket::from_ip(frame).ok()?,
        Link::LinuxSll | Link::LinuxSll2 => {
            let (header, at) = if link == Link::LinuxSll {
                (16, 14)
            } else {
                (20, 0)
            };
            let protocol = u16::from_be_bytes([*frame.get(at)?, *frame.get(at + 1)?]);
            if protocol != 0x0800 && protocol != 0x86DD {
                return None;
            }
            SlicedPacket::from_ip(frame.get(header..)?).ok()?
        }
    };
    let (src_ip, dst_ip): (IpAddr, IpAddr) = match sliced.net.as_ref()? {
        NetSlice::Ipv4(ip) => {
            if ip.is_payload_fragmented() {
                return None;
            }
            (
                ip.header().source_addr().into(),
                ip.header().destination_addr().into(),
            )
        }
        NetSlice::Ipv6(ip) => {
            if ip.is_payload_fragmented() {
                return None;
            }
            (
                ip.header().source_addr().into(),
                ip.header().destination_addr().into(),
            )
        }
        NetSlice::Arp(_) => return None,
    };
    match sliced.transport? {
        TransportSlice::Udp(udp) => Some(Segment {
            src: SocketAddr::new(src_ip, udp.source_port()),
            dst: SocketAddr::new(dst_ip, udp.destination_port()),
            proto: Proto::Udp,
            payload: udp.payload(),
        }),
        TransportSlice::Tcp(tcp) => Some(Segment {
            src: SocketAddr::new(src_ip, tcp.source_port()),
            dst: SocketAddr::new(dst_ip, tcp.destination_port()),
            proto: Proto::Tcp {
                seq: tcp.sequence_number(),
                syn: tcp.syn(),
                fin: tcp.fin(),
                rst: tcp.rst(),
            },
            payload: tcp.payload(),
        }),
        _ => None,
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use etherparse::PacketBuilder;

    pub(crate) fn udp_frame(src: SocketAddr, dst: SocketAddr, payload: &[u8]) -> Vec<u8> {
        let builder = PacketBuilder::ethernet2([1; 6], [2; 6]);
        let builder = match (src.ip(), dst.ip()) {
            (IpAddr::V4(s), IpAddr::V4(d)) => builder.ipv4(s.octets(), d.octets(), 64),
            (IpAddr::V6(s), IpAddr::V6(d)) => builder.ipv6(s.octets(), d.octets(), 64),
            _ => panic!("mixed families"),
        };
        let builder = builder.udp(src.port(), dst.port());
        let mut out = Vec::with_capacity(builder.size(payload.len()));
        builder.write(&mut out, payload).unwrap();
        out
    }

    pub(crate) fn tcp_frame(src: SocketAddr, dst: SocketAddr, seq: u32, payload: &[u8]) -> Vec<u8> {
        let builder = PacketBuilder::ethernet2([1; 6], [2; 6]);
        let builder = match (src.ip(), dst.ip()) {
            (IpAddr::V4(s), IpAddr::V4(d)) => builder.ipv4(s.octets(), d.octets(), 64),
            (IpAddr::V6(s), IpAddr::V6(d)) => builder.ipv6(s.octets(), d.octets(), 64),
            _ => panic!("mixed families"),
        };
        let builder = builder.tcp(src.port(), dst.port(), seq, 65535).ack(1).psh();
        let mut out = Vec::with_capacity(builder.size(payload.len()));
        builder.write(&mut out, payload).unwrap();
        out
    }

    #[test]
    fn decodes_udp_over_ipv4_ethernet() {
        let src: SocketAddr = "192.168.1.1:53".parse().unwrap();
        let dst: SocketAddr = "192.168.1.36:51000".parse().unwrap();
        let frame = udp_frame(src, dst, b"hello");
        let seg = decode(Link::Ethernet, &frame).unwrap();
        assert_eq!(
            (seg.src, seg.dst, seg.proto, seg.payload),
            (src, dst, Proto::Udp, &b"hello"[..])
        );
    }

    #[test]
    fn decodes_tcp_over_ipv6() {
        let src: SocketAddr = "[2001:db8::1]:50000".parse().unwrap();
        let dst: SocketAddr = "[2001:db8::2]:443".parse().unwrap();
        let frame = tcp_frame(src, dst, 1000, b"data");
        let seg = decode(Link::Ethernet, &frame).unwrap();
        assert_eq!(
            seg.proto,
            Proto::Tcp {
                seq: 1000,
                syn: false,
                fin: false,
                rst: false
            }
        );
        assert_eq!(seg.payload, b"data");
        assert_eq!(seg.dst, dst);
    }

    #[test]
    fn decodes_null_and_raw_framing() {
        let src: SocketAddr = "10.0.0.1:53".parse().unwrap();
        let dst: SocketAddr = "10.0.0.2:4000".parse().unwrap();
        let ether = udp_frame(src, dst, b"x");
        let ip = &ether[14..];
        let mut null = 2u32.to_ne_bytes().to_vec();
        null.extend_from_slice(ip);
        assert_eq!(decode(Link::Null, &null).unwrap().src, src);
        assert_eq!(decode(Link::Raw, ip).unwrap().dst, dst);
        assert_eq!(decode(Link::Null, &null[..3]), None);
    }

    #[test]
    fn decodes_linux_cooked_captures() {
        let src: SocketAddr = "192.168.1.1:53".parse().unwrap();
        let dst: SocketAddr = "192.168.1.50:40000".parse().unwrap();
        let ip = udp_frame(src, dst, b"dns")[14..].to_vec();

        let mut sll = vec![0u8; 16];
        sll[14..16].copy_from_slice(&0x0800u16.to_be_bytes());
        sll.extend_from_slice(&ip);
        assert_eq!(decode(Link::LinuxSll, &sll).unwrap().src, src);

        let mut sll2 = vec![0u8; 20];
        sll2[0..2].copy_from_slice(&0x0800u16.to_be_bytes());
        sll2.extend_from_slice(&ip);
        assert_eq!(decode(Link::LinuxSll2, &sll2).unwrap().dst, dst);

        sll2[0..2].copy_from_slice(&0x0806u16.to_be_bytes()); // ARP
        assert_eq!(decode(Link::LinuxSll2, &sll2), None);
        assert_eq!(decode(Link::LinuxSll, &sll[..15]), None);
        assert_eq!(Link::from_dlt(113), Some(Link::LinuxSll));
        assert_eq!(Link::from_dlt(276), Some(Link::LinuxSll2));
    }

    #[test]
    fn link_types() {
        assert_eq!(Link::from_dlt(1), Some(Link::Ethernet));
        assert_eq!(Link::from_dlt(0), Some(Link::Null));
        assert_eq!(Link::from_dlt(12), Some(Link::Raw));
        assert_eq!(Link::from_dlt(127), None, "802.11 radiotap is not handled");
    }

    #[test]
    fn rejects_garbage_and_truncation() {
        let frame = udp_frame(
            "1.1.1.1:53".parse().unwrap(),
            "2.2.2.2:9".parse().unwrap(),
            b"abc",
        );
        for len in 0..frame.len() - 3 {
            assert_eq!(decode(Link::Ethernet, &frame[..len]), None, "len {len}");
        }
        let mut state = 0x2545_F491_4F6C_DD1Du64;
        for _ in 0..20_000 {
            let mut f = frame.clone();
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            let i = (state as usize) % f.len();
            f[i] = (state >> 32) as u8;
            let _ = decode(Link::Ethernet, &f);
        }
    }
}
