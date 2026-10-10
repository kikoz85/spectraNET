//! Active reverse lookup (PTR) of **local-network** addresses only.
//!
//! Devices on the LAN rarely appear in public DNS, and connections to them are often older
//! than any traffic we could observe. So for private addresses — and only those — spectraNET
//! asks, in this order:
//! 1. **mDNS** (Bonjour) on 224.0.0.251: multicast is link-local by design and never routed;
//! 2. **the local DNS servers**: the configured resolvers and the default gateway, each only
//!    if it is itself a private address. A public resolver (e.g. 8.8.8.8) is never asked;
//! 3. **NetBIOS node status** sent to the device itself (how Windows PCs name themselves).
//!
//! Lookups run on a background thread with a bounded queue; results land in the shared
//! [`NameTable`]. Failures are cached too, so a silent device is retried rarely.

use std::collections::{HashMap, HashSet};
use std::net::{IpAddr, Ipv4Addr, SocketAddr, UdpSocket};
use std::sync::mpsc::{self, Receiver, SyncSender, TrySendError};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

use super::NameTable;
use super::dns;

const MDNS_GROUP: SocketAddr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(224, 0, 0, 251)), 5353);
const QUERY_TIMEOUT: Duration = Duration::from_millis(700);
const RETRY_AFTER_FAILURE: Duration = Duration::from_secs(600);
const REFRESH_AFTER_SUCCESS: Duration = Duration::from_secs(3600);
const QUEUE: usize = 256;

/// True for addresses that belong to the local network: RFC 1918, IPv4 link-local,
/// IPv6 unique-local (fc00::/7) and link-local (fe80::/10).
pub fn is_lan(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => v4.is_private() || v4.is_link_local(),
        IpAddr::V6(v6) => match v6.to_ipv4_mapped() {
            Some(v4) => is_lan(IpAddr::V4(v4)),
            None => {
                let first = v6.segments()[0];
                (first & 0xFE00) == 0xFC00 || (first & 0xFFC0) == 0xFE80
            }
        },
    }
}

/// Where unicast PTR queries may go: the given candidates that are themselves on the LAN.
pub fn lan_dns_servers(candidates: &[IpAddr]) -> Vec<SocketAddr> {
    let mut seen = HashSet::new();
    candidates
        .iter()
        .copied()
        .filter(|ip| is_lan(*ip) && seen.insert(*ip))
        .map(|ip| SocketAddr::new(ip, 53))
        .collect()
}

/// Nameservers from resolv.conf(5) text.
pub fn parse_resolv_conf(text: &str) -> Vec<IpAddr> {
    text.lines()
        .filter_map(|line| {
            let mut fields = line.split_whitespace();
            (fields.next()? == "nameserver").then_some(())?;
            // Strip a zone index ("fe80::1%en0"): the address part is what we need.
            fields.next()?.split('%').next()?.parse().ok()
        })
        .collect()
}

/// The default gateway, from the kernel routing table (Linux).
#[cfg(target_os = "linux")]
fn default_gateway() -> Option<IpAddr> {
    parse_proc_route(&std::fs::read_to_string("/proc/net/route").ok()?)
}

/// Default route of /proc/net/route: destination 00000000, gateway in little-endian hex.
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
fn parse_proc_route(text: &str) -> Option<IpAddr> {
    text.lines().skip(1).find_map(|line| {
        let fields: Vec<&str> = line.split_whitespace().collect();
        if fields.get(1) != Some(&"00000000") {
            return None;
        }
        let raw = u32::from_str_radix(fields.get(2)?, 16).ok()?;
        (raw != 0).then(|| IpAddr::V4(Ipv4Addr::from(raw.swap_bytes())))
    })
}

/// The default gateway, as reported by route(8). `None` if it cannot be determined.
#[cfg(not(target_os = "linux"))]
fn default_gateway() -> Option<IpAddr> {
    let output = std::process::Command::new("/sbin/route")
        .args(["-n", "get", "default"])
        .output()
        .ok()?;
    parse_route_gateway(&String::from_utf8_lossy(&output.stdout))
}

#[cfg_attr(target_os = "linux", allow(dead_code))]
fn parse_route_gateway(text: &str) -> Option<IpAddr> {
    text.lines()
        .find_map(|line| line.trim().strip_prefix("gateway:")?.trim().parse().ok())
}

/// Sends `query` to `server` and waits for a matching PTR answer.
fn ask(server: SocketAddr, query: &[u8], id: u16, name: &str) -> Option<String> {
    let bind: SocketAddr = match server {
        SocketAddr::V4(_) => "0.0.0.0:0".parse().ok()?,
        SocketAddr::V6(_) => "[::]:0".parse().ok()?,
    };
    let socket = UdpSocket::bind(bind).ok()?;
    if server == MDNS_GROUP {
        socket.set_multicast_ttl_v4(255).ok()?; // RFC 6762 §11
    }
    socket.send_to(query, server).ok()?;
    let deadline = Instant::now() + QUERY_TIMEOUT;
    let mut buf = [0u8; 1500];
    loop {
        let left = deadline.checked_duration_since(Instant::now())?;
        socket
            .set_read_timeout(Some(left.max(Duration::from_millis(1))))
            .ok()?;
        let (n, _) = socket.recv_from(&mut buf).ok()?;
        if let Some(found) = dns::parse_ptr(&buf[..n], id, name)
            && is_meaningful(&found)
        {
            return Some(found);
        }
        // Someone else's answer or noise: keep listening until the deadline.
    }
}

/// Some routers answer a PTR query with the address itself ("192.168.1.1"); that is not a
/// name and must not hide a better answer from the next source.
fn is_meaningful(name: &str) -> bool {
    name.parse::<IpAddr>().is_err() && !name.ends_with(".arpa")
}

/// Looks up one address: mDNS first, then each LAN DNS server.
pub fn reverse_lookup(ip: IpAddr, servers: &[SocketAddr], id: u16) -> Option<String> {
    let name = dns::reverse_name(ip);
    // Legacy-unicast mDNS (RFC 6762 §6.7): sent from an ephemeral port, answered to it.
    if let Some(found) = ask(MDNS_GROUP, &dns::ptr_query(id, &name, false), id, &name) {
        return Some(found);
    }
    if let Some(found) = servers
        .iter()
        .find_map(|server| ask(*server, &dns::ptr_query(id, &name, true), id, &name))
    {
        return Some(found);
    }
    match ip {
        IpAddr::V4(_) => netbios_name(SocketAddr::new(ip, 137), id),
        IpAddr::V6(_) => None,
    }
}

/// NetBIOS node status request for the wildcard name "*" (RFC 1002 §4.2.17).
fn netbios_query(id: u16) -> Vec<u8> {
    let mut msg = Vec::with_capacity(50);
    msg.extend_from_slice(&id.to_be_bytes());
    msg.extend_from_slice(&[0x00, 0x00, 0, 1, 0, 0, 0, 0, 0, 0]);
    msg.push(0x20);
    // "*" followed by 15 NULs, each byte encoded as two letters 'A' + nibble.
    let mut raw = [0u8; 16];
    raw[0] = b'*';
    for byte in raw {
        msg.push(b'A' + (byte >> 4));
        msg.push(b'A' + (byte & 0x0F));
    }
    msg.push(0);
    msg.extend_from_slice(&[0x00, 0x21, 0x00, 0x01]); // NBSTAT, IN
    msg
}

/// The machine name from a node status response: the first unique (non-group) name with
/// suffix 0x00, lowercased. Names that are not valid hostnames are rejected.
fn parse_netbios_status(msg: &[u8], id: u16) -> Option<String> {
    if msg.get(..2)? != id.to_be_bytes() || msg.get(2)? & 0x80 == 0 {
        return None;
    }
    // Header (12) + encoded name (34) + type, class, TTL, rdlength (10).
    let count = usize::from(*msg.get(56)?);
    let entries = msg.get(57..57 + count.checked_mul(18)?)?;
    entries.as_chunks::<18>().0.iter().find_map(|entry| {
        let suffix = entry[15];
        let group = u16::from_be_bytes([entry[16], entry[17]]) & 0x8000 != 0;
        if suffix != 0x00 || group {
            return None;
        }
        let name = std::str::from_utf8(&entry[..15])
            .ok()?
            .trim_end_matches([' ', '\0'])
            .to_ascii_lowercase();
        dns::valid_hostname(&name).then_some(name)
    })
}

fn netbios_name(target: SocketAddr, id: u16) -> Option<String> {
    let socket = UdpSocket::bind("0.0.0.0:0").ok()?;
    socket.send_to(&netbios_query(id), target).ok()?;
    let deadline = Instant::now() + QUERY_TIMEOUT;
    let mut buf = [0u8; 1500];
    loop {
        let left = deadline.checked_duration_since(Instant::now())?;
        socket
            .set_read_timeout(Some(left.max(Duration::from_millis(1))))
            .ok()?;
        let (n, from) = socket.recv_from(&mut buf).ok()?;
        if from.ip() == target.ip()
            && let Some(name) = parse_netbios_status(&buf[..n], id)
        {
            return Some(name);
        }
    }
}

/// Background resolver for LAN addresses.
pub struct LanResolver {
    queue: SyncSender<IpAddr>,
    state: Arc<Mutex<State>>,
}

#[derive(Default)]
struct State {
    /// When each address was last resolved, and whether it worked.
    done: HashMap<IpAddr, (Instant, bool)>,
    queued: HashSet<IpAddr>,
}

impl LanResolver {
    /// Starts the worker. DNS servers are discovered from resolv.conf and the default gateway.
    pub fn start(table: Arc<Mutex<NameTable>>) -> Self {
        let mut candidates = std::fs::read_to_string("/etc/resolv.conf")
            .map(|t| parse_resolv_conf(&t))
            .unwrap_or_default();
        candidates.extend(default_gateway());
        Self::with_servers(table, lan_dns_servers(&candidates))
    }

    /// Starts the worker with explicit unicast servers (used by tests).
    pub fn with_servers(table: Arc<Mutex<NameTable>>, servers: Vec<SocketAddr>) -> Self {
        let (queue, requests) = mpsc::sync_channel(QUEUE);
        let state = Arc::new(Mutex::new(State::default()));
        let worker_state = state.clone();
        let _ = thread::Builder::new()
            .name("snet-lan-resolver".into())
            .spawn(move || worker(requests, servers, table, worker_state));
        Self { queue, state }
    }

    /// Asks for `ip` to be resolved if it is a LAN address not resolved recently.
    /// Never blocks; requests beyond the queue capacity are dropped and retried later.
    pub fn request(&self, ip: IpAddr) {
        if !is_lan(ip) {
            return;
        }
        let Ok(mut state) = self.state.lock() else {
            return;
        };
        let fresh = state.done.get(&ip).is_some_and(|(at, ok)| {
            at.elapsed()
                < if *ok {
                    REFRESH_AFTER_SUCCESS
                } else {
                    RETRY_AFTER_FAILURE
                }
        });
        if fresh || state.queued.contains(&ip) {
            return;
        }
        match self.queue.try_send(ip) {
            Ok(()) => {
                state.queued.insert(ip);
            }
            Err(TrySendError::Full(_) | TrySendError::Disconnected(_)) => {}
        }
    }

    /// Number of addresses resolved or attempted so far.
    pub fn attempted(&self) -> usize {
        self.state.lock().map(|s| s.done.len()).unwrap_or(0)
    }
}

fn worker(
    requests: Receiver<IpAddr>,
    servers: Vec<SocketAddr>,
    table: Arc<Mutex<NameTable>>,
    state: Arc<Mutex<State>>,
) {
    let mut id: u16 = (std::process::id() as u16) ^ 0x5A5A;
    // Ends when the LanResolver (the only sender) is dropped.
    while let Ok(ip) = requests.recv() {
        id = id.wrapping_add(1);
        let found = reverse_lookup(ip, &servers, id);
        if let Some(name) = &found
            && let Ok(mut t) = table.lock()
        {
            t.learn_host(name.clone(), ip);
        }
        if let Ok(mut s) = state.lock() {
            s.queued.remove(&ip);
            s.done.insert(ip, (Instant::now(), found.is_some()));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lan_ranges() {
        for lan in [
            "10.1.2.3",
            "172.16.0.1",
            "172.31.255.255",
            "192.168.1.50",
            "169.254.10.1",
            "fd00::1",
            "fe80::1",
            "::ffff:192.168.1.1",
        ] {
            assert!(is_lan(lan.parse().unwrap()), "{lan}");
        }
        for public in [
            "8.8.8.8",
            "172.32.0.1",
            "100.64.0.1",
            "127.0.0.1",
            "0.0.0.0",
            "224.0.0.251",
            "255.255.255.255",
            "2001:4860::8888",
            "::1",
            "::",
            "ff02::fb",
            "::ffff:8.8.8.8",
        ] {
            assert!(!is_lan(public.parse().unwrap()), "{public}");
        }
    }

    #[test]
    fn public_dns_servers_are_never_used() {
        let candidates: Vec<IpAddr> = [
            "8.8.8.8",
            "192.168.1.1",
            "1.1.1.1",
            "192.168.1.1",
            "fd00::53",
        ]
        .iter()
        .map(|s| s.parse().unwrap())
        .collect();
        assert_eq!(
            lan_dns_servers(&candidates),
            [
                "192.168.1.1:53".parse::<SocketAddr>().unwrap(),
                "[fd00::53]:53".parse().unwrap()
            ]
        );
    }

    #[test]
    fn parses_resolv_conf_and_route_output() {
        let conf = "#\n# macOS Notice\nsearch lan\nnameserver 8.8.8.8\nnameserver fe80::1%en0\nnameserver bogus\n";
        assert_eq!(
            parse_resolv_conf(conf),
            [
                "8.8.8.8".parse::<IpAddr>().unwrap(),
                "fe80::1".parse().unwrap()
            ]
        );
        let route = "   route to: default\ndestination: default\n       mask: default\n    gateway: 192.168.1.1\n  interface: en0\n";
        assert_eq!(
            parse_route_gateway(route),
            Some("192.168.1.1".parse().unwrap())
        );
        assert_eq!(
            parse_route_gateway("route: writing to routing socket: not in table"),
            None
        );
    }

    /// A fake LAN DNS server on loopback, answering one PTR query (after a decoy reply).
    fn fake_server(answer: &'static str) -> SocketAddr {
        let socket = UdpSocket::bind("127.0.0.1:0").unwrap();
        let addr = socket.local_addr().unwrap();
        thread::spawn(move || {
            let mut buf = [0u8; 512];
            let (n, from) = socket.recv_from(&mut buf).unwrap();
            let query = &buf[..n];
            // A reply with the wrong ID first: must be ignored, not believed.
            let mut decoy = dns::tests::ptr_response(query, "decoy.lan");
            decoy[0] ^= 0xFF;
            socket.send_to(&decoy, from).unwrap();
            socket
                .send_to(&dns::tests::ptr_response(query, answer), from)
                .unwrap();
        });
        addr
    }

    #[test]
    fn unicast_lookup_end_to_end() {
        let server = fake_server("printer.lan");
        let ip: IpAddr = "192.168.1.77".parse().unwrap();
        let name = dns::reverse_name(ip);
        let found = ask(server, &dns::ptr_query(42, &name, true), 42, &name);
        assert_eq!(found.as_deref(), Some("printer.lan"));
    }

    /// A node status response as sent by a Windows PC named TREEX-WIN in WORKGROUP.
    fn netbios_response(id: u16) -> Vec<u8> {
        let query = netbios_query(id);
        let mut msg = query[..12].to_vec();
        msg[2] = 0x84;
        msg[5] = 0; // no questions
        msg[7] = 1; // one answer
        msg.extend_from_slice(&query[12..46]);
        msg.extend_from_slice(&[0x00, 0x21, 0x00, 0x01, 0, 0, 0, 0]);
        let names: [(&str, u8, u16); 3] = [
            ("WORKGROUP", 0x00, 0x8400), // group name first: must be skipped
            ("TREEX-WIN", 0x20, 0x0400), // file server service: wrong suffix
            ("TREEX-WIN", 0x00, 0x0400), // workstation: the one we want
        ];
        let mut rdata = vec![names.len() as u8];
        for (name, suffix, flags) in names {
            let mut padded = format!("{name:<15}").into_bytes();
            padded.truncate(15);
            rdata.extend_from_slice(&padded);
            rdata.push(suffix);
            rdata.extend_from_slice(&flags.to_be_bytes());
        }
        rdata.extend_from_slice(&[0u8; 46]); // statistics block
        msg.extend_from_slice(&(rdata.len() as u16).to_be_bytes());
        msg.extend_from_slice(&rdata);
        msg
    }

    #[test]
    fn netbios_query_layout() {
        let q = netbios_query(0x1234);
        assert_eq!(q.len(), 50);
        assert_eq!(&q[13..15], b"CK", "'*' encodes as CK");
        assert_eq!(&q[15..45], "AA".repeat(15).as_bytes());
    }

    #[test]
    fn netbios_status_picks_the_workstation_name() {
        assert_eq!(
            parse_netbios_status(&netbios_response(9), 9),
            Some("treex-win".into())
        );
        assert_eq!(
            parse_netbios_status(&netbios_response(9), 10),
            None,
            "wrong id"
        );
        let full = netbios_response(9);
        for len in 0..57 + 3 * 18 {
            assert_eq!(
                parse_netbios_status(&full[..len], 9),
                None,
                "truncated to {len}"
            );
        }
    }

    #[test]
    fn netbios_end_to_end_over_udp() {
        let server = UdpSocket::bind("127.0.0.1:0").unwrap();
        let addr = server.local_addr().unwrap();
        thread::spawn(move || {
            let mut buf = [0u8; 100];
            let (n, from) = server.recv_from(&mut buf).unwrap();
            let id = u16::from_be_bytes([buf[0], buf[1]]);
            assert_eq!(&buf[..n], netbios_query(id).as_slice());
            server.send_to(&netbios_response(id), from).unwrap();
        });
        assert_eq!(netbios_name(addr, 77), Some("treex-win".into()));
    }

    #[test]
    fn linux_route_table() {
        let text = "Iface\tDestination\tGateway \tFlags\tRefCnt\tUse\tMetric\tMask\t\tMTU\tWindow\tIRTT\n\
                    bond0\t00000000\t0101A8C0\t0003\t0\t0\t0\t00000000\t0\t0\t0\n\
                    bond0\t0001A8C0\t00000000\t0001\t0\t0\t0\t00FFFFFF\t0\t0\t0\n";
        assert_eq!(parse_proc_route(text), Some("192.168.1.1".parse().unwrap()));
        assert_eq!(parse_proc_route("Iface\tDestination\n"), None);
    }

    #[test]
    fn address_shaped_answers_are_not_names() {
        assert!(!is_meaningful("192.168.1.1"));
        assert!(!is_meaningful("fe80::1"));
        assert!(!is_meaningful("1.1.168.192.in-addr.arpa"));
        assert!(is_meaningful("router.lan"));
        assert!(is_meaningful("192-168-1-1.lan"));
    }

    #[test]
    fn silent_server_times_out_promptly() {
        let silent = UdpSocket::bind("127.0.0.1:0").unwrap();
        let server = silent.local_addr().unwrap();
        let begun = Instant::now();
        assert_eq!(ask(server, b"query", 1, "x.in-addr.arpa"), None);
        assert!(begun.elapsed() < QUERY_TIMEOUT + Duration::from_millis(300));
        drop(silent);
    }

    #[test]
    fn resolver_fills_the_table_and_caches() {
        let table = Arc::new(Mutex::new(NameTable::default()));
        let server = fake_server("nas.lan");
        let resolver = LanResolver::with_servers(table.clone(), vec![server]);
        let ip: IpAddr = "10.99.88.77".parse().unwrap();
        resolver.request("8.8.8.8".parse().unwrap()); // public: ignored
        resolver.request(ip);
        resolver.request(ip); // duplicate while queued: ignored
        let deadline = Instant::now() + Duration::from_secs(5);
        let local: SocketAddr = "10.99.88.1:5000".parse().unwrap();
        while table
            .lock()
            .unwrap()
            .lookup(local, SocketAddr::new(ip, 445))
            .is_none()
        {
            assert!(Instant::now() < deadline, "lookup did not complete");
            thread::sleep(Duration::from_millis(20));
        }
        assert_eq!(
            table
                .lock()
                .unwrap()
                .lookup(local, SocketAddr::new(ip, 445)),
            Some("nas.lan")
        );
        assert_eq!(
            resolver.attempted(),
            1,
            "only the LAN address was looked up"
        );
        resolver.request(ip);
        thread::sleep(Duration::from_millis(100));
        assert_eq!(resolver.attempted(), 1, "cached: not asked again");
    }

    /// Real network, real devices: must finish in bounded time whatever the LAN looks like.
    #[test]
    fn real_lan_lookup_is_bounded() {
        let begun = Instant::now();
        let mut candidates =
            parse_resolv_conf(&std::fs::read_to_string("/etc/resolv.conf").unwrap_or_default());
        candidates.extend(default_gateway());
        let servers = lan_dns_servers(&candidates);
        let mut targets: Vec<IpAddr> = default_gateway().into_iter().collect();
        if let Ok(extra) = std::env::var("SNET_LAN_PROBE") {
            targets.extend(extra.split(',').filter_map(|s| s.parse::<IpAddr>().ok()));
        }
        for target in &targets {
            let found = reverse_lookup(*target, &servers, 777);
            eprintln!("{target} -> {found:?} via mDNS + {servers:?}");
            if let Some(name) = found {
                assert!(dns::valid_hostname(&name) && is_meaningful(&name));
            }
        }
        let per_target = QUERY_TIMEOUT * (servers.len() as u32 + 1);
        assert!(
            begun.elapsed() < per_target * targets.len().max(1) as u32 + Duration::from_secs(1)
        );
    }
}
