//! Per-connection byte accounting from Kernel-Network ETW events. Pure logic, no Windows API,
//! so it is tested on every platform.
//!
//! Event IDs (Microsoft-Windows-Kernel-Network): TCP 10/26 sent, 11/27 received, 12/28
//! connected, 15/31 accepted, 13/29 disconnected (IPv4/IPv6); UDP 42/58 sent, 43/59
//! received. Event 18/34 ("copied data") repeats bytes already reported by 11/27 and is
//! deliberately ignored.

use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::time::{Duration, Instant};

use spectranet_model::Transport;

/// UDP has no close event: an association silent this long is forgotten.
pub const UDP_IDLE_EXPIRY: Duration = Duration::from_secs(120);

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct FlowKey {
    pub pid: u32,
    pub transport: Transport,
    pub local: SocketAddr,
    pub remote: SocketAddr,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Counters {
    /// Distinguishes successive connections with the same key.
    pub generation: u64,
    pub rx: u64,
    pub tx: u64,
    /// Receive and send events (UDP: datagrams), for packet rates.
    pub rx_msgs: u64,
    pub tx_msgs: u64,
    pub closed: bool,
    pub last_activity: Instant,
}

/// One decoded network event.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NetEvent {
    pub id: u16,
    pub pid: u32,
    pub size: u32,
    pub saddr: IpAddr,
    pub daddr: IpAddr,
    /// Ports exactly as in the event: network byte order.
    pub sport_be: u16,
    pub dport_be: u16,
}

#[derive(Debug, Default)]
pub struct Accounting {
    flows: HashMap<FlowKey, Counters>,
    next_generation: u64,
}

enum Effect {
    Open,
    Tx,
    Rx,
    Close,
}

impl Accounting {
    pub fn apply(&mut self, e: &NetEvent, now: Instant) {
        let (transport, effect) = match e.id {
            10 | 26 => (Transport::Tcp, Effect::Tx),
            11 | 27 => (Transport::Tcp, Effect::Rx),
            12 | 28 | 15 | 31 => (Transport::Tcp, Effect::Open),
            13 | 29 => (Transport::Tcp, Effect::Close),
            42 | 58 => (Transport::Udp, Effect::Tx),
            43 | 59 => (Transport::Udp, Effect::Rx),
            _ => return,
        };
        let sport = u16::from_be(e.sport_be);
        let dport = u16::from_be(e.dport_be);
        // TCP events always describe (local = s, remote = d); UDP receive events describe the
        // datagram (s = sender = remote, d = destination = local).
        let (local, remote) = if transport == Transport::Udp && matches!(effect, Effect::Rx) {
            (
                SocketAddr::new(canonical(e.daddr), dport),
                SocketAddr::new(canonical(e.saddr), sport),
            )
        } else {
            (
                SocketAddr::new(canonical(e.saddr), sport),
                SocketAddr::new(canonical(e.daddr), dport),
            )
        };
        let key = FlowKey {
            pid: e.pid,
            transport,
            local,
            remote,
        };
        let generation = &mut self.next_generation;
        let counters = self.flows.entry(key).or_insert_with(|| {
            *generation += 1;
            Counters {
                generation: *generation,
                rx: 0,
                tx: 0,
                rx_msgs: 0,
                tx_msgs: 0,
                closed: false,
                last_activity: now,
            }
        });
        if counters.closed && !matches!(effect, Effect::Close) {
            // The same 4-tuple reused by a new connection before we reported the old one: keep
            // the old totals (they are final) and continue under a new generation.
            self.next_generation += 1;
            *counters = Counters {
                generation: self.next_generation,
                rx: 0,
                tx: 0,
                rx_msgs: 0,
                tx_msgs: 0,
                closed: false,
                last_activity: now,
            };
        }
        counters.last_activity = now;
        match effect {
            Effect::Open => {}
            Effect::Tx => {
                counters.tx = counters.tx.saturating_add(u64::from(e.size));
                counters.tx_msgs += 1;
            }
            Effect::Rx => {
                counters.rx = counters.rx.saturating_add(u64::from(e.size));
                counters.rx_msgs += 1;
            }
            Effect::Close => counters.closed = true,
        }
    }

    /// Current flows; closed TCP connections are returned one last time and forgotten, idle
    /// UDP associations expire.
    pub fn take(&mut self, now: Instant) -> Vec<(FlowKey, Counters)> {
        let out: Vec<_> = self.flows.iter().map(|(k, c)| (*k, *c)).collect();
        self.flows.retain(|k, c| {
            !c.closed
                && !(k.transport == Transport::Udp
                    && now.duration_since(c.last_activity) > UDP_IDLE_EXPIRY)
        });
        out
    }

    #[cfg(test)]
    pub fn len(&self) -> usize {
        self.flows.len()
    }

    #[cfg(test)]
    pub fn is_empty(&self) -> bool {
        self.flows.is_empty()
    }
}

pub fn canonical(ip: IpAddr) -> IpAddr {
    match ip {
        IpAddr::V6(v6) => v6.to_ipv4_mapped().map_or(ip, IpAddr::V4),
        v4 => v4,
    }
}

/// IPv4 address as Kernel-Network reports it: a 32-bit integer holding the address bytes in
/// memory order (little-endian), e.g. 788637888 = 0x2F01A8C0 = 192.168.1.47.
pub fn ipv4_from_event(value: u32) -> IpAddr {
    IpAddr::V4(Ipv4Addr::from(value.to_le_bytes()))
}

/// DNS-Client `QueryResults`, e.g. `"type: 5 github.com;140.82.121.3;"` or
/// `"::ffff:1.2.3.4;::ffff:5.6.7.8;"`: the addresses, aliases skipped.
pub fn dns_results(text: &str) -> Vec<IpAddr> {
    text.split(';')
        .map(str::trim)
        .filter(|t| !t.is_empty() && !t.starts_with("type:"))
        .filter_map(|t| t.parse::<IpAddr>().ok().map(canonical))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    const LOCAL: &str = "192.168.1.47";
    const REMOTE: &str = "195.68.130.183";

    fn ev(id: u16, size: u32, s: &str, sport: u16, d: &str, dport: u16) -> NetEvent {
        NetEvent {
            id,
            pid: 320,
            size,
            saddr: s.parse().unwrap(),
            daddr: d.parse().unwrap(),
            sport_be: sport.to_be(),
            dport_be: dport.to_be(),
        }
    }

    #[test]
    fn decodes_the_observed_wire_values() {
        assert_eq!(
            ipv4_from_event(788_637_888),
            "192.168.1.47".parse::<IpAddr>().unwrap()
        );
        assert_eq!(u16::from_be(47_873), 443, "port as seen in a real event");
    }

    #[test]
    fn tcp_send_receive_and_close() {
        let mut acc = Accounting::default();
        let t = Instant::now();
        acc.apply(&ev(12, 0, LOCAL, 50_000, REMOTE, 443), t);
        acc.apply(&ev(10, 253, LOCAL, 50_000, REMOTE, 443), t);
        acc.apply(&ev(11, 1000, LOCAL, 50_000, REMOTE, 443), t);
        acc.apply(&ev(18, 1000, LOCAL, 50_000, REMOTE, 443), t); // duplicate of 11: ignored
        acc.apply(&ev(11, 500, LOCAL, 50_000, REMOTE, 443), t);
        acc.apply(&ev(13, 0, LOCAL, 50_000, REMOTE, 443), t);
        let flows = acc.take(t);
        assert_eq!(flows.len(), 1);
        let (key, c) = flows[0];
        assert_eq!(key.local, format!("{LOCAL}:50000").parse().unwrap());
        assert_eq!(key.remote, format!("{REMOTE}:443").parse().unwrap());
        assert_eq!((c.tx, c.rx, c.closed), (253, 1500, true));
        assert!(
            acc.is_empty(),
            "closed connection reported once, then forgotten"
        );
    }

    #[test]
    fn udp_receive_events_are_oriented_correctly() {
        let mut acc = Accounting::default();
        let t = Instant::now();
        // Observed: an mDNS datagram from the Mac (192.168.1.36) to 224.0.0.251.
        acc.apply(&ev(43, 219, "192.168.1.36", 5353, "224.0.0.251", 5353), t);
        acc.apply(&ev(42, 29, LOCAL, 61_000, "192.168.1.1", 53), t);
        let flows = acc.take(t);
        let rx = flows.iter().find(|(k, _)| k.remote.port() == 5353).unwrap();
        assert_eq!(
            rx.0.remote.ip(),
            "192.168.1.36".parse::<IpAddr>().unwrap(),
            "remote is the sender"
        );
        assert_eq!(rx.1.rx, 219);
        let tx = flows.iter().find(|(k, _)| k.remote.port() == 53).unwrap();
        assert_eq!(tx.1.tx, 29);
    }

    #[test]
    fn idle_udp_expires_but_active_udp_stays() {
        let mut acc = Accounting::default();
        let t0 = Instant::now();
        acc.apply(&ev(42, 10, LOCAL, 1000, "8.8.8.8", 53), t0);
        assert_eq!(acc.take(t0 + Duration::from_secs(10)).len(), 1);
        assert_eq!(acc.len(), 1, "still fresh");
        acc.take(t0 + UDP_IDLE_EXPIRY + Duration::from_secs(1));
        assert!(acc.is_empty());
    }

    #[test]
    fn reused_tuple_after_close_starts_a_new_generation() {
        let mut acc = Accounting::default();
        let t = Instant::now();
        acc.apply(&ev(10, 100, LOCAL, 50_000, REMOTE, 443), t);
        acc.apply(&ev(13, 0, LOCAL, 50_000, REMOTE, 443), t);
        let first_gen = acc.take(t)[0].1.generation;
        acc.apply(&ev(12, 0, LOCAL, 50_000, REMOTE, 443), t);
        acc.apply(&ev(10, 7, LOCAL, 50_000, REMOTE, 443), t);
        let (_, c) = acc.take(t)[0];
        assert_ne!(c.generation, first_gen);
        assert_eq!(c.tx, 7);
    }

    #[test]
    fn mapped_and_v6_addresses() {
        let mut acc = Accounting::default();
        let t = Instant::now();
        acc.apply(
            &ev(26, 10, "::ffff:192.168.1.47", 1, "::ffff:1.1.1.1", 443),
            t,
        );
        acc.apply(&ev(58, 29, "fe80::708b:aa8:1461:d647", 2, "fe80::1", 53), t);
        let flows = acc.take(t);
        assert!(
            flows
                .iter()
                .any(|(k, _)| k.remote == "1.1.1.1:443".parse().unwrap()),
            "v4-mapped normalised"
        );
        assert!(
            flows
                .iter()
                .any(|(k, _)| k.remote == "[fe80::1]:53".parse().unwrap())
        );
    }

    #[test]
    fn unknown_events_are_ignored() {
        let mut acc = Accounting::default();
        for id in [14, 16, 17, 18, 30, 32, 34, 49, 9999] {
            acc.apply(&ev(id, 10, LOCAL, 1, REMOTE, 2), Instant::now());
        }
        assert!(acc.is_empty());
    }

    #[test]
    fn dns_result_strings() {
        assert_eq!(
            dns_results("type: 5 github.com;140.82.121.3;"),
            ["140.82.121.3".parse::<IpAddr>().unwrap()]
        );
        assert_eq!(
            dns_results("::ffff:34.225.159.174;::ffff:3.92.129.183;").len(),
            2
        );
        assert_eq!(
            dns_results("::ffff:34.225.159.174;")[0],
            "34.225.159.174".parse::<IpAddr>().unwrap()
        );
        assert!(dns_results("").is_empty());
        assert!(dns_results("0").is_empty());
        assert_eq!(dns_results("2a00:1450::200e; garbage;1.2.3.4").len(), 2);
    }
}
