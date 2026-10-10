//! Hostname discovery from observed traffic.
//!
//! Passive sources feed a [`NameTable`]:
//! - **DNS responses** (UDP/TCP port 53): map every answered address to the queried name;
//! - **TLS ClientHello SNI**, over TCP and over QUIC (HTTP/3): names one connection exactly,
//!   and works even when DNS itself is encrypted;
//! - **mDNS announcements** (Bonjour, port 5353): names of devices on the local network;
//! - **`/etc/hosts`**: names the administrator assigned by hand.
//!
//! Lookups prefer the exact per-connection server name, then `/etc/hosts` (the
//! administrator's explicit choice, as in the system resolver), then the latest name observed
//! for the address.
//! Nothing is ever sent on the network.

pub mod dns;
pub mod hosts;
pub mod lan;
#[cfg(any(target_os = "macos", target_os = "linux"))]
pub mod live;
pub mod packet;
pub mod quic;
pub mod tls;

use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::time::{Duration, Instant};

use packet::{Link, Proto, Segment};
use tls::Sni;

/// Upper bound on remembered names per index, to keep memory flat on busy hosts.
const TABLE_CAPACITY: usize = 50_000;
/// Upper bound on half-received ClientHellos tracked at once.
const MAX_PENDING_HELLOS: usize = 1_024;
/// A ClientHello not completed within this time is abandoned.
const HELLO_TIMEOUT: Duration = Duration::from_secs(10);

#[derive(Debug, Clone)]
struct Entry {
    name: String,
    stamp: u64,
}

/// Hostnames learnt from traffic, indexed by connection and by address.
#[derive(Debug, Default)]
pub struct NameTable {
    by_conn: HashMap<(SocketAddr, SocketAddr), Entry>,
    by_ip: HashMap<IpAddr, Entry>,
    /// Entries from `/etc/hosts`: few, fixed, and authoritative.
    static_hosts: HashMap<IpAddr, String>,
    /// Handshake details per connection (client, server), with the time they were learnt.
    tls: HashMap<(SocketAddr, SocketAddr), (spectranet_model::flowmeta::TlsInfo, u64)>,
    clock: u64,
}

impl NameTable {
    /// Best known name for a connection from `local` to `remote`.
    pub fn lookup(&self, local: SocketAddr, remote: SocketAddr) -> Option<&str> {
        let key = (canonical(local), canonical(remote));
        if let Some(e) = self.by_conn.get(&key) {
            return Some(&e.name);
        }
        if let Some(name) = self.static_hosts.get(&key.1.ip()) {
            return Some(name);
        }
        self.by_ip.get(&key.1.ip()).map(|e| e.name.as_str())
    }

    pub fn learn_dns(&mut self, resolution: dns::Resolution) {
        for addr in resolution.addrs {
            let stamp = self.tick();
            let ip = canonical_ip(addr);
            self.by_ip.insert(
                ip,
                Entry {
                    name: resolution.name.clone(),
                    stamp,
                },
            );
        }
        evict_oldest(&mut self.by_ip);
    }

    /// Records an `/etc/hosts` entry; the first name listed for an address wins.
    pub fn learn_static(&mut self, name: String, ip: IpAddr) {
        self.static_hosts.entry(canonical_ip(ip)).or_insert(name);
    }

    /// Records a name for an address announced on the network (mDNS).
    pub fn learn_host(&mut self, name: String, ip: IpAddr) {
        let stamp = self.tick();
        self.by_ip.insert(canonical_ip(ip), Entry { name, stamp });
        evict_oldest(&mut self.by_ip);
    }

    pub fn learn_sni(&mut self, client: SocketAddr, server: SocketAddr, name: String) {
        let stamp = self.tick();
        let (client, server) = (canonical(client), canonical(server));
        self.by_ip.insert(
            server.ip(),
            Entry {
                name: name.clone(),
                stamp,
            },
        );
        self.by_conn.insert((client, server), Entry { name, stamp });
        evict_oldest(&mut self.by_ip);
        evict_oldest(&mut self.by_conn);
    }

    /// Records what a ClientHello says (ALPN, JA4) for one connection.
    pub fn learn_hello(
        &mut self,
        client: SocketAddr,
        server: SocketAddr,
        details: tls::HelloDetails,
        quic: bool,
    ) {
        let stamp = self.tick();
        let entry = self
            .tls
            .entry((canonical(client), canonical(server)))
            .or_insert_with(|| (Default::default(), stamp));
        entry.0.alpn = details.alpn;
        entry.0.ja4 = Some(details.ja4);
        entry.0.quic = quic;
        if quic {
            // QUIC always runs TLS 1.3; its server answer is encrypted for us.
            entry.0.version = Some("TLS 1.3".into());
        }
        entry.1 = stamp;
        self.trim_tls();
    }

    /// Records the TLS version and cipher suite a server chose.
    pub fn learn_server_hello(
        &mut self,
        client: SocketAddr,
        server: SocketAddr,
        choice: tls::ServerChoice,
    ) {
        let stamp = self.tick();
        let entry = self
            .tls
            .entry((canonical(client), canonical(server)))
            .or_insert_with(|| (Default::default(), stamp));
        entry.0.version = Some(choice.version);
        entry.0.cipher = Some(choice.cipher);
        entry.1 = stamp;
        self.trim_tls();
    }

    /// Handshake details of a connection seen from either end.
    pub fn tls(
        &self,
        local: SocketAddr,
        remote: SocketAddr,
    ) -> Option<spectranet_model::flowmeta::TlsInfo> {
        let (l, r) = (canonical(local), canonical(remote));
        self.tls
            .get(&(l, r))
            .or_else(|| self.tls.get(&(r, l)))
            .map(|(info, _)| info.clone())
    }

    fn trim_tls(&mut self) {
        if self.tls.len() > TABLE_CAPACITY
            && let Some(oldest) = self.tls.iter().min_by_key(|(_, v)| v.1).map(|(k, _)| *k)
        {
            self.tls.remove(&oldest);
        }
    }

    pub fn len(&self) -> usize {
        self.by_ip.len() + self.by_conn.len() + self.static_hosts.len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    fn tick(&mut self) -> u64 {
        self.clock += 1;
        self.clock
    }
}

/// When over capacity, drops the oldest quarter (amortised O(1) per insert).
fn evict_oldest<K: Clone + Eq + std::hash::Hash>(map: &mut HashMap<K, Entry>) {
    if map.len() <= TABLE_CAPACITY {
        return;
    }
    let mut stamps: Vec<u64> = map.values().map(|e| e.stamp).collect();
    let cut = stamps.len() / 4;
    let (_, threshold, _) = stamps.select_nth_unstable(cut);
    let threshold = *threshold;
    map.retain(|_, e| e.stamp > threshold);
}

fn canonical_ip(ip: IpAddr) -> IpAddr {
    match ip {
        IpAddr::V6(v6) => v6.to_ipv4_mapped().map_or(ip, IpAddr::V4),
        v4 => v4,
    }
}

fn canonical(addr: SocketAddr) -> SocketAddr {
    SocketAddr::new(canonical_ip(addr.ip()), addr.port())
}

struct PendingHello {
    next_seq: u32,
    data: Vec<u8>,
    started: Instant,
}

/// Collects the first bytes of TCP client streams until a ClientHello can be parsed.
#[derive(Default)]
pub struct HelloAssembler {
    pending: HashMap<(SocketAddr, SocketAddr), PendingHello>,
}

impl HelloAssembler {
    /// Feeds one TCP segment; returns `(client, server, sni)` once a hello is complete.
    pub fn push(
        &mut self,
        seg: &Segment<'_>,
        seq: u32,
        closing: bool,
    ) -> Option<(SocketAddr, SocketAddr, String)> {
        self.push_details(seg, seq, closing)
            .map(|(client, server, name, _)| (client, server, name))
    }

    /// Like [`Self::push`], with the hello's ALPN and JA4 as well.
    pub fn push_details(
        &mut self,
        seg: &Segment<'_>,
        seq: u32,
        closing: bool,
    ) -> Option<(SocketAddr, SocketAddr, String, Option<tls::HelloDetails>)> {
        let key = (seg.src, seg.dst);
        if closing {
            self.pending.remove(&key);
            return None;
        }
        if seg.payload.is_empty() {
            return None;
        }

        let stream = match self.pending.get_mut(&key) {
            Some(p) if seq == p.next_seq => {
                p.data.extend_from_slice(seg.payload);
                p.next_seq = seq.wrapping_add(seg.payload.len() as u32);
                std::mem::take(&mut p.data)
            }
            // Retransmission of bytes we already have: ignore.
            Some(p) if seq_before(seq, p.next_seq) => return None,
            // A gap: reassembly is no longer possible.
            Some(_) => {
                self.pending.remove(&key);
                return None;
            }
            None if seg.payload[0] == 0x16 => seg.payload.to_vec(),
            None => return None,
        };

        match tls::parse_client_hello(&stream) {
            Sni::Found(name) => {
                self.pending.remove(&key);
                let details = stream
                    .get(5..)
                    .and_then(|message| tls::hello_details(message, false));
                name.map(|n| (seg.src, seg.dst, n, details))
            }
            Sni::NeedBytes(n) if n <= tls::MAX_RECORD + 5 => {
                let next_seq = seq.wrapping_add(seg.payload.len() as u32);
                match self.pending.get_mut(&key) {
                    Some(p) => p.data = stream,
                    None => {
                        self.make_room();
                        self.pending.insert(
                            key,
                            PendingHello {
                                next_seq,
                                data: stream,
                                started: Instant::now(),
                            },
                        );
                    }
                }
                None
            }
            Sni::NeedBytes(_) | Sni::NotClientHello => {
                self.pending.remove(&key);
                None
            }
        }
    }

    /// Drops hellos that never completed.
    pub fn expire(&mut self, now: Instant) {
        self.pending
            .retain(|_, p| now.duration_since(p.started) < HELLO_TIMEOUT);
    }

    pub fn pending(&self) -> usize {
        self.pending.len()
    }

    fn make_room(&mut self) {
        if self.pending.len() < MAX_PENDING_HELLOS {
            return;
        }
        self.expire(Instant::now());
        if self.pending.len() >= MAX_PENDING_HELLOS
            && let Some(oldest) = self
                .pending
                .iter()
                .min_by_key(|(_, p)| p.started)
                .map(|(k, _)| *k)
        {
            self.pending.remove(&oldest);
        }
    }
}

/// `a` comes before `b` in TCP sequence space (RFC 1982 serial arithmetic).
fn seq_before(a: u32, b: u32) -> bool {
    (a.wrapping_sub(b) as i32) < 0
}

/// What a frame taught us, if anything.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Learned {
    Dns(dns::Resolution),
    Hosts(Vec<(String, IpAddr)>),
    Sni {
        client: SocketAddr,
        server: SocketAddr,
        name: String,
        /// ALPN and JA4 of the hello, when it could be parsed.
        details: Option<tls::HelloDetails>,
        quic: bool,
    },
    /// The server's answer: negotiated TLS version and cipher suite.
    ServerHello {
        client: SocketAddr,
        server: SocketAddr,
        choice: tls::ServerChoice,
    },
}

/// Turns captured frames into [`Learned`] facts. One per capture thread.
#[derive(Default)]
pub struct Sniffer {
    hellos: HelloAssembler,
    quic: quic::QuicAssembler,
    frames: u64,
}

impl Sniffer {
    pub fn handle(&mut self, link: Link, frame: &[u8]) -> Option<Learned> {
        self.frames += 1;
        if self.frames.is_multiple_of(4096) {
            self.hellos.expire(Instant::now());
            self.quic.expire(Instant::now());
        }
        let seg = packet::decode(link, frame)?;
        match seg.proto {
            Proto::Udp if seg.src.port() == 53 => {
                dns::parse_response(seg.payload).map(Learned::Dns)
            }
            Proto::Udp if seg.src.port() == 5353 => {
                let hosts = dns::parse_mdns(seg.payload);
                (!hosts.is_empty()).then_some(Learned::Hosts(hosts))
            }
            Proto::Udp if seg.dst.port() == 443 => self
                .quic
                .push_details(seg.src, seg.dst, seg.payload)
                .map(|(name, details)| Learned::Sni {
                    client: seg.src,
                    server: seg.dst,
                    name,
                    details,
                    quic: true,
                }),
            Proto::Tcp { .. } if seg.src.port() == 443 && seg.payload.first() == Some(&0x16) => {
                tls::parse_server_hello(seg.payload).map(|choice| Learned::ServerHello {
                    client: seg.dst,
                    server: seg.src,
                    choice,
                })
            }
            Proto::Tcp { .. } if seg.src.port() == 53 => {
                // DNS over TCP: 2-byte length prefix; only whole messages in one segment.
                let len = usize::from(u16::from_be_bytes([
                    *seg.payload.first()?,
                    *seg.payload.get(1)?,
                ]));
                dns::parse_response(seg.payload.get(2..2 + len)?).map(Learned::Dns)
            }
            Proto::Tcp { seq, syn, fin, rst } => {
                if syn && seg.payload.is_empty() {
                    return None;
                }
                self.hellos.push_details(&seg, seq, fin || rst).map(
                    |(client, server, name, details)| Learned::Sni {
                        client,
                        server,
                        name,
                        details,
                        quic: false,
                    },
                )
            }
            Proto::Udp => None,
        }
    }
}

impl NameTable {
    pub fn apply(&mut self, learned: Learned) {
        match learned {
            Learned::Dns(resolution) => self.learn_dns(resolution),
            Learned::Hosts(hosts) => {
                for (name, ip) in hosts {
                    self.learn_host(name, ip);
                }
            }
            Learned::Sni {
                client,
                server,
                name,
                details,
                quic,
            } => {
                if let Some(details) = details {
                    self.learn_hello(client, server, details, quic);
                }
                self.learn_sni(client, server, name);
            }
            Learned::ServerHello {
                client,
                server,
                choice,
            } => self.learn_server_hello(client, server, choice),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::packet::tests::{tcp_frame, udp_frame};
    use super::*;

    fn addr(s: &str) -> SocketAddr {
        s.parse().unwrap()
    }

    const CLIENT: &str = "192.168.1.36:51000";
    const SERVER: &str = "142.250.180.14:443";

    #[test]
    fn dns_answer_names_the_address() {
        let msg = dns::tests::response(
            "www.youtube.com",
            &[("www.youtube.com", 1, vec![142, 250, 180, 14])],
        );
        let frame = udp_frame(addr("192.168.1.1:53"), addr("192.168.1.36:5000"), &msg);
        let mut sniffer = Sniffer::default();
        let mut table = NameTable::default();
        table.apply(sniffer.handle(Link::Ethernet, &frame).unwrap());
        assert_eq!(
            table.lookup(addr(CLIENT), addr(SERVER)),
            Some("www.youtube.com")
        );
        assert_eq!(table.lookup(addr(CLIENT), addr("8.8.8.8:443")), None);
    }

    #[test]
    fn dns_queries_and_other_ports_are_ignored() {
        let msg = dns::tests::response("a.com", &[("a.com", 1, vec![1, 2, 3, 4])]);
        let mut sniffer = Sniffer::default();
        let to_server = udp_frame(addr("192.168.1.36:5000"), addr("192.168.1.1:53"), &msg);
        assert_eq!(
            sniffer.handle(Link::Ethernet, &to_server),
            None,
            "direction matters"
        );
        let other = udp_frame(addr("192.168.1.1:5355"), addr("224.0.0.252:5355"), &msg);
        assert_eq!(sniffer.handle(Link::Ethernet, &other), None);
    }

    #[test]
    fn dns_over_tcp() {
        let msg = dns::tests::response("a.com", &[("a.com", 1, vec![1, 2, 3, 4])]);
        let mut framed = (msg.len() as u16).to_be_bytes().to_vec();
        framed.extend_from_slice(&msg);
        let frame = tcp_frame(addr("9.9.9.9:53"), addr("192.168.1.36:5000"), 1, &framed);
        let learned = Sniffer::default().handle(Link::Ethernet, &frame).unwrap();
        assert!(matches!(learned, Learned::Dns(r) if r.name == "a.com"));
    }

    #[test]
    fn sni_in_one_segment() {
        let hello = tls::tests::client_hello(Some("www.example.com"), 0);
        let frame = tcp_frame(addr(CLIENT), addr(SERVER), 100, &hello);
        let mut table = NameTable::default();
        table.apply(Sniffer::default().handle(Link::Ethernet, &frame).unwrap());
        assert_eq!(
            table.lookup(addr(CLIENT), addr(SERVER)),
            Some("www.example.com")
        );
    }

    #[test]
    fn handshake_details_follow_the_connection() {
        let hello = tls::tests::client_hello(Some("www.example.com"), 0);
        let mut sniffer = Sniffer::default();
        let mut table = NameTable::default();
        let frame = tcp_frame(addr(CLIENT), addr(SERVER), 100, &hello);
        table.apply(sniffer.handle(Link::Ethernet, &frame).unwrap());
        let info = table.tls(addr(CLIENT), addr(SERVER)).unwrap();
        assert!(info.ja4.as_deref().unwrap().starts_with("t13d"));
        assert!(!info.quic && info.version.is_none());
        // The server answers: version and cipher join the same entry, from either end.
        let mut body = vec![0x03, 0x03];
        body.extend_from_slice(&[0x22; 32]);
        body.extend_from_slice(&[0, 0x13, 0x01, 0, 0, 6, 0x00, 0x2b, 0x00, 0x02, 0x03, 0x04]);
        let mut hs = vec![0x02];
        hs.extend_from_slice(&(body.len() as u32).to_be_bytes()[1..]);
        hs.extend_from_slice(&body);
        let mut rec = vec![0x16, 0x03, 0x03];
        rec.extend_from_slice(&(hs.len() as u16).to_be_bytes());
        rec.extend_from_slice(&hs);
        let answer = tcp_frame(addr(SERVER), addr(CLIENT), 7, &rec);
        table.apply(sniffer.handle(Link::Ethernet, &answer).unwrap());
        let info = table.tls(addr(SERVER), addr(CLIENT)).unwrap();
        assert_eq!(info.version.as_deref(), Some("TLS 1.3"));
        assert_eq!(info.cipher.as_deref(), Some("TLS_AES_128_GCM_SHA256"));
        assert_eq!(
            table.lookup(addr(CLIENT), addr(SERVER)),
            Some("www.example.com")
        );
    }

    /// Splits a large hello into segments and feeds them in the given order.
    fn feed(order: &[usize], seg_size: usize, retransmit: bool) -> Option<Learned> {
        let hello = tls::tests::client_hello(Some("split.example.com"), 2500);
        let chunks: Vec<(u32, &[u8])> = hello
            .chunks(seg_size)
            .enumerate()
            .map(|(i, c)| ((u32::MAX - 500).wrapping_add((i * seg_size) as u32), c)) // crosses seq wrap-around
            .collect();
        let mut sniffer = Sniffer::default();
        let mut result = None;
        for &i in order {
            let (seq, data) = chunks[i];
            let frame = tcp_frame(addr(CLIENT), addr(SERVER), seq, data);
            if let Some(l) = sniffer.handle(Link::Ethernet, &frame) {
                result = Some(l);
            }
            if retransmit {
                let _ = sniffer.handle(Link::Ethernet, &frame);
            }
        }
        result
    }

    #[test]
    fn sni_split_across_segments_with_sequence_wrap() {
        let n = tls::tests::client_hello(Some("split.example.com"), 2500)
            .len()
            .div_ceil(1200);
        assert_eq!(n, 3);
        let learned = feed(&[0, 1, 2], 1200, false).unwrap();
        assert!(matches!(learned, Learned::Sni { name, .. } if name == "split.example.com"));
    }

    #[test]
    fn retransmissions_do_not_corrupt_reassembly() {
        assert!(feed(&[0, 1, 2], 1200, true).is_some());
    }

    #[test]
    fn gaps_and_reordering_abort_cleanly() {
        assert_eq!(feed(&[0, 2], 1200, false), None, "missing middle segment");
        assert_eq!(feed(&[0, 2, 1], 1200, false), None, "out of order");
        assert_eq!(feed(&[1, 2], 1200, false), None, "no start");
    }

    #[test]
    fn non_tls_streams_leave_no_state() {
        let mut sniffer = Sniffer::default();
        for i in 0..100u32 {
            let frame = tcp_frame(
                addr(CLIENT),
                addr(SERVER),
                i * 1000,
                b"GET / HTTP/1.1\r\n\r\n",
            );
            assert_eq!(sniffer.handle(Link::Ethernet, &frame), None);
        }
        let partial = &tls::tests::client_hello(Some("x.com"), 2000)[..500];
        let frame = tcp_frame(addr(CLIENT), addr(SERVER), 7, partial);
        sniffer.handle(Link::Ethernet, &frame);
        assert_eq!(sniffer.hellos.pending(), 1);
        let mut fin = tcp_frame(addr(CLIENT), addr(SERVER), 507, b"");
        // Set FIN on the empty segment (TCP flags byte: Ethernet 14 + IPv4 20 + 13).
        fin[14 + 20 + 13] |= 0x01;
        sniffer.handle(Link::Ethernet, &fin);
        assert_eq!(
            sniffer.hellos.pending(),
            0,
            "FIN discards the partial hello"
        );
    }

    #[test]
    fn pending_hellos_are_bounded() {
        let partial = &tls::tests::client_hello(Some("x.com"), 2000)[..300];
        let mut sniffer = Sniffer::default();
        for port in 0..(MAX_PENDING_HELLOS as u16 + 500) {
            let client = SocketAddr::new("10.0.0.1".parse().unwrap(), 1024 + port);
            let frame = tcp_frame(client, addr(SERVER), 1, partial);
            sniffer.handle(Link::Ethernet, &frame);
        }
        assert!(sniffer.hellos.pending() <= MAX_PENDING_HELLOS);
    }

    #[test]
    fn stale_hellos_expire() {
        let partial = &tls::tests::client_hello(Some("x.com"), 2000)[..300];
        let mut sniffer = Sniffer::default();
        let frame = tcp_frame(addr(CLIENT), addr(SERVER), 1, partial);
        sniffer.handle(Link::Ethernet, &frame);
        sniffer
            .hellos
            .expire(Instant::now() + HELLO_TIMEOUT + Duration::from_secs(1));
        assert_eq!(sniffer.hellos.pending(), 0);
    }

    #[test]
    fn quic_initial_names_the_connection() {
        let hello = quic::tests::hello_message("www.youtube.com", 1800);
        let dcid = [9u8; 8];
        let mut sniffer = Sniffer::default();
        let mut table = NameTable::default();
        for (pn, range) in [(0, 0..1000), (1, 1000..hello.len())] {
            let frames = quic::tests::crypto_frame(range.start as u64, &hello[range]);
            let packet = quic::tests::initial_packet(1, &dcid, pn, &frames);
            let frame = udp_frame(addr(CLIENT), addr(SERVER), &packet);
            if let Some(l) = sniffer.handle(Link::Ethernet, &frame) {
                table.apply(l);
            }
        }
        assert_eq!(
            table.lookup(addr(CLIENT), addr(SERVER)),
            Some("www.youtube.com")
        );
    }

    #[test]
    fn hosts_file_beats_mdns_but_not_exact_sni() {
        let server: IpAddr = "192.168.1.50".parse().unwrap();
        let mut table = NameTable::default();
        table.learn_static("nucserver".into(), server);
        table.learn_static("ignored-second-name".into(), server);
        table.learn_host("n95server.local".into(), server);
        let smb = SocketAddr::new(server, 445);
        assert_eq!(table.lookup(addr(CLIENT), smb), Some("nucserver"));
        table.learn_sni(
            addr(CLIENT),
            SocketAddr::new(server, 443),
            "nas.example.com".into(),
        );
        assert_eq!(
            table.lookup(addr(CLIENT), SocketAddr::new(server, 443)),
            Some("nas.example.com")
        );
        assert_eq!(table.lookup(addr("192.168.1.36:1"), smb), Some("nucserver"));
    }

    #[test]
    fn mdns_names_lan_hosts_without_hosts_entry() {
        let mut table = NameTable::default();
        table.apply(Learned::Hosts(vec![(
            "n95server.local".into(),
            "192.168.1.50".parse().unwrap(),
        )]));
        assert_eq!(
            table.lookup(addr(CLIENT), addr("192.168.1.50:445")),
            Some("n95server.local")
        );
    }

    #[test]
    fn exact_sni_beats_shared_address_dns() {
        let mut table = NameTable::default();
        table.learn_sni(addr(CLIENT), addr(SERVER), "mail.google.com".into());
        table.learn_dns(dns::Resolution {
            name: "www.google.com".into(),
            addrs: vec![addr(SERVER).ip()],
        });
        assert_eq!(
            table.lookup(addr(CLIENT), addr(SERVER)),
            Some("mail.google.com")
        );
        assert_eq!(
            table.lookup(addr("192.168.1.36:52000"), addr(SERVER)),
            Some("www.google.com")
        );
    }

    #[test]
    fn ipv4_mapped_addresses_match_plain_ipv4() {
        let mut table = NameTable::default();
        table.learn_dns(dns::Resolution {
            name: "a.com".into(),
            addrs: vec!["1.2.3.4".parse().unwrap()],
        });
        assert_eq!(
            table.lookup(addr("[::ffff:192.168.1.2]:5"), addr("[::ffff:1.2.3.4]:443")),
            Some("a.com")
        );
    }

    #[test]
    fn table_memory_is_bounded() {
        let mut table = NameTable::default();
        for i in 0..(TABLE_CAPACITY as u32 * 2) {
            table.learn_dns(dns::Resolution {
                name: "x.com".into(),
                addrs: vec![IpAddr::V4(i.into())],
            });
        }
        assert!(table.by_ip.len() <= TABLE_CAPACITY);
        // The most recent entries survive eviction.
        let last = IpAddr::V4((TABLE_CAPACITY as u32 * 2 - 1).into());
        assert!(table.by_ip.contains_key(&last));
    }

    #[test]
    fn sequence_comparison_wraps() {
        assert!(seq_before(1, 2));
        assert!(seq_before(u32::MAX, 0));
        assert!(!seq_before(0, u32::MAX));
        assert!(!seq_before(5, 5));
    }
}
