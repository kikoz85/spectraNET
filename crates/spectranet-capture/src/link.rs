//! Reconciliation with the network interfaces: what the interfaces carried, next to the part
//! of it the applications' connections account for.
//!
//! Every backend measures sockets, which is what tells applications apart. The interfaces'
//! own counters (`sysctl` on macOS, `/proc/net/dev` on Linux, `GetIfTable2` on Windows) say
//! how much went through the network adapters, headers included. Comparing the two each
//! second shows how complete the picture is, and makes any blind spot visible instead of
//! silent: traffic of other devices shared through this computer, the system's own protocols,
//! or a capture fault.
//!
//! Loopback, tunnels (a VPN's inner traffic also crosses the physical adapter, encrypted) and
//! other virtual interfaces are left out, so nothing is counted twice.

use std::collections::{HashMap, HashSet};
use std::net::IpAddr;
use std::time::Instant;

use spectranet_model::{LinkTraffic, Snapshot, Transport};

use crate::{CaptureError, TrafficSource};

/// Byte counters of one interface, since it came up.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Counters {
    pub name: String,
    pub rx_bytes: u64,
    pub tx_bytes: u64,
}

/// Interfaces whose traffic is not physical, or is also counted on a physical one.
pub fn is_virtual(name: &str) -> bool {
    const PREFIXES: [&str; 22] = [
        "lo",
        "utun",
        "tun",
        "tap",
        "ipsec",
        "ppp",
        "gif",
        "stf",
        "awdl",
        "llw",
        "bridge",
        "anpi",
        "vmenet",
        "feth",
        "wg",
        "docker",
        "veth",
        "virbr",
        "br-",
        "vnet",
        "zt",
        "tailscale",
    ];
    let lower = name.to_ascii_lowercase();
    PREFIXES.iter().any(|p| lower.starts_with(p))
}

/// Packet headers the interfaces count and sockets don't (Ethernet, IP, TCP with timestamps
/// or UDP), per packet.
fn header_bytes(transport: Transport, ipv6: bool) -> u64 {
    match (transport, ipv6) {
        (Transport::Tcp, false) => 14 + 20 + 32,
        (Transport::Tcp, true) => 14 + 40 + 32,
        (Transport::Udp, false) => 14 + 20 + 8,
        (Transport::Udp, true) => 14 + 40 + 8,
    }
}

/// Fills `snapshot.link` from the interface counters (each sample of the wrapped source).
pub struct WithLink {
    inner: Box<dyn TrafficSource>,
    previous: Option<(Instant, HashMap<String, Counters>)>,
}

impl WithLink {
    pub fn new(inner: Box<dyn TrafficSource>) -> Self {
        // A first reading now, so that even the first sample can be reconciled.
        let previous = counted().ok().map(|(c, _)| (Instant::now(), c));
        Self { inner, previous }
    }
}

impl TrafficSource for WithLink {
    fn name(&self) -> &'static str {
        self.inner.name()
    }

    fn sample(&mut self) -> Result<Snapshot, CaptureError> {
        let mut snapshot = self.inner.sample()?;
        let now = Instant::now();
        let Ok((counters, addresses)) = counted() else {
            return Ok(snapshot);
        };
        if let Some((then, before)) = self.previous.replace((now, counters.clone())) {
            snapshot.link = Some(reconcile(
                &snapshot,
                &before,
                &counters,
                now.duration_since(then).as_secs_f64(),
                &addresses,
            ));
        }
        Ok(snapshot)
    }

    fn notices(&self) -> Vec<String> {
        self.inner.notices()
    }

    fn first_sample_has_rates(&self) -> bool {
        self.inner.first_sample_has_rates()
    }
}

/// The interfaces to count, with their addresses: physical ones that carry an address. A
/// member of a bond, bridge or VLAN has none — the interface built on it does — so its
/// packets are counted once. (Windows already reports hardware interfaces only.)
fn counted() -> std::io::Result<(HashMap<String, Counters>, HashSet<IpAddr>)> {
    let counters = read()?;
    let named = if_addrs::get_if_addrs().unwrap_or_default();
    let with_address: HashSet<&str> = named.iter().map(|i| i.name.as_str()).collect();
    let keep = |name: &str| {
        !is_virtual(name)
            && (cfg!(windows) || with_address.is_empty() || with_address.contains(name))
    };
    let counters: HashMap<String, Counters> = counters
        .into_iter()
        .filter(|c| keep(&c.name))
        .map(|c| (c.name.clone(), c))
        .collect();
    let addresses = named
        .iter()
        .filter(|i| counters.contains_key(&i.name) || cfg!(windows) && !is_virtual(&i.name))
        .map(|i| i.ip())
        .filter(|ip| !ip.is_loopback())
        .collect();
    Ok((counters, addresses))
}

/// The interfaces' rates over `seconds`, next to what the snapshot's connections account for.
pub fn reconcile(
    snapshot: &Snapshot,
    before: &HashMap<String, Counters>,
    after: &HashMap<String, Counters>,
    seconds: f64,
    addresses: &HashSet<IpAddr>,
) -> LinkTraffic {
    let seconds = seconds.max(0.001);
    let (mut rx, mut tx) = (0u64, 0u64);
    let mut interfaces: Vec<String> = Vec::new();
    for (name, now) in after {
        let Some(then) = before.get(name) else {
            continue;
        };
        // A counter that went backwards was reset (interface restarted): skip it once.
        let (d_rx, d_tx) = (
            now.rx_bytes.checked_sub(then.rx_bytes),
            now.tx_bytes.checked_sub(then.tx_bytes),
        );
        let (Some(d_rx), Some(d_tx)) = (d_rx, d_tx) else {
            continue;
        };
        if d_rx + d_tx > 0 || addresses.is_empty() {
            interfaces.push(name.clone());
        }
        rx += d_rx;
        tx += d_tx;
    }
    interfaces.sort();
    let (mut attributed_rx, mut attributed_tx) = (0u64, 0u64);
    for f in snapshot.processes.iter().flat_map(|p| &p.flows) {
        let local = f.local.ip();
        let remote = f.remote.ip();
        if remote.is_loopback() || local.is_loopback() {
            continue;
        }
        // Connections bound to a tunnel or other uncounted interface go through it, not
        // through the adapters counted here. Unbound sockets (local 0.0.0.0) are counted.
        if !local.is_unspecified() && !addresses.is_empty() && !addresses.contains(&local) {
            continue;
        }
        let headers = header_bytes(f.transport, remote.is_ipv6());
        attributed_rx += f.rx_rate + u64::from(f.meta.rx_pps.unwrap_or(0)) * headers;
        attributed_tx += f.tx_rate + u64::from(f.meta.tx_pps.unwrap_or(0)) * headers;
    }
    LinkTraffic {
        rx_rate: (rx as f64 / seconds).round() as u64,
        tx_rate: (tx as f64 / seconds).round() as u64,
        attributed_rx,
        attributed_tx,
        interfaces,
    }
}

/// Reads every interface's byte counters.
#[cfg(target_os = "linux")]
pub fn read() -> std::io::Result<Vec<Counters>> {
    Ok(parse_proc_net_dev(&std::fs::read_to_string(
        "/proc/net/dev",
    )?))
}

/// Parses `/proc/net/dev`: `name: rx_bytes packets … (8 fields) tx_bytes …`.
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
fn parse_proc_net_dev(text: &str) -> Vec<Counters> {
    text.lines()
        .filter_map(|line| {
            let (name, rest) = line.split_once(':')?;
            let fields: Vec<u64> = rest
                .split_whitespace()
                .map(|f| f.parse().ok())
                .collect::<Option<_>>()?;
            Some(Counters {
                name: name.trim().to_string(),
                rx_bytes: *fields.first()?,
                tx_bytes: *fields.get(8)?,
            })
        })
        .collect()
}

/// Reads every interface's byte counters (64-bit, from the routing sysctl).
#[cfg(target_os = "macos")]
#[allow(unsafe_code)]
pub fn read() -> std::io::Result<Vec<Counters>> {
    let mut mib = [libc::CTL_NET, libc::PF_ROUTE, 0, 0, libc::NET_RT_IFLIST2, 0];
    let mut len: libc::size_t = 0;
    // SAFETY: a size query: null buffer, valid length pointer.
    if unsafe {
        libc::sysctl(
            mib.as_mut_ptr(),
            mib.len() as u32,
            std::ptr::null_mut(),
            &mut len,
            std::ptr::null_mut(),
            0,
        )
    } != 0
    {
        return Err(std::io::Error::last_os_error());
    }
    let mut buf = vec![0u8; len + 4096];
    let mut len = buf.len();
    // SAFETY: the buffer is `len` bytes long and the kernel writes at most that.
    if unsafe {
        libc::sysctl(
            mib.as_mut_ptr(),
            mib.len() as u32,
            buf.as_mut_ptr().cast(),
            &mut len,
            std::ptr::null_mut(),
            0,
        )
    } != 0
    {
        return Err(std::io::Error::last_os_error());
    }
    let mut out = Vec::new();
    let mut offset = 0;
    let header = std::mem::size_of::<libc::if_msghdr2>();
    while offset + 4 <= len {
        let msglen = u16::from_ne_bytes([buf[offset], buf[offset + 1]]) as usize;
        if msglen == 0 || offset + msglen > len {
            break;
        }
        let kind = buf[offset + 3];
        if i32::from(kind) == libc::RTM_IFINFO2 && msglen >= header {
            // SAFETY: at least `header` bytes of a kernel-written if_msghdr2 at `offset`;
            // read unaligned, as the buffer has no alignment guarantee.
            let msg: libc::if_msghdr2 =
                unsafe { std::ptr::read_unaligned(buf.as_ptr().add(offset).cast()) };
            let mut name = [0 as libc::c_char; libc::IF_NAMESIZE];
            // SAFETY: the buffer is IF_NAMESIZE long, as if_indextoname requires.
            let named =
                unsafe { libc::if_indextoname(u32::from(msg.ifm_index), name.as_mut_ptr()) };
            if !named.is_null() {
                // SAFETY: if_indextoname wrote a NUL-terminated name into `name`.
                let name = unsafe { std::ffi::CStr::from_ptr(name.as_ptr()) }
                    .to_string_lossy()
                    .into_owned();
                let data = msg.ifm_data;
                out.push(Counters {
                    name,
                    rx_bytes: data.ifi_ibytes,
                    tx_bytes: data.ifi_obytes,
                });
            }
        }
        offset += msglen;
    }
    Ok(out)
}

/// Reads every physical interface's byte counters (filter and virtual layers left out, so a
/// packet is counted once).
#[cfg(windows)]
#[allow(unsafe_code)]
pub fn read() -> std::io::Result<Vec<Counters>> {
    use windows_sys::Win32::NetworkManagement::IpHelper::{
        FreeMibTable, GetIfTable2, MIB_IF_TABLE2,
    };
    const IF_OPER_STATUS_UP: i32 = 1;
    const IF_TYPE_SOFTWARE_LOOPBACK: u32 = 24;
    let mut table: *mut MIB_IF_TABLE2 = std::ptr::null_mut();
    // SAFETY: GetIfTable2 allocates the table and stores its address in `table`.
    let status = unsafe { GetIfTable2(&mut table) };
    if status != 0 || table.is_null() {
        return Err(std::io::Error::from_raw_os_error(status as i32));
    }
    let mut out = Vec::new();
    // SAFETY: `table` is valid until FreeMibTable; NumEntries rows follow the header.
    unsafe {
        let rows =
            std::slice::from_raw_parts((*table).Table.as_ptr(), (*table).NumEntries as usize);
        for row in rows {
            let flags = row.InterfaceAndOperStatusFlags._bitfield;
            let hardware = flags & 0x01 != 0;
            let filter = flags & 0x02 != 0;
            if !hardware
                || filter
                || row.Type == IF_TYPE_SOFTWARE_LOOPBACK
                || row.OperStatus != IF_OPER_STATUS_UP
            {
                continue;
            }
            let end = row
                .Alias
                .iter()
                .position(|c| *c == 0)
                .unwrap_or(row.Alias.len());
            out.push(Counters {
                name: String::from_utf16_lossy(&row.Alias[..end]),
                rx_bytes: row.InOctets,
                tx_bytes: row.OutOctets,
            });
        }
        FreeMibTable(table.cast());
    }
    Ok(out)
}

#[cfg(not(any(target_os = "linux", target_os = "macos", windows)))]
pub fn read() -> std::io::Result<Vec<Counters>> {
    Err(std::io::Error::other("not supported"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use spectranet_model::{Flow, Process, ProcessTraffic, Verdict};

    fn flow(local: &str, remote: &str, rx: u64, rx_pps: u32) -> Flow {
        let mut f = Flow {
            transport: Transport::Tcp,
            local: local.parse().unwrap(),
            remote: remote.parse().unwrap(),
            remote_host: None,
            rx_rate: rx,
            tx_rate: 0,
            rx_bytes: 0,
            tx_bytes: 0,
            verdict: Verdict::Ok,
            note: None,
            meta: Default::default(),
        };
        f.meta.rx_pps = Some(rx_pps);
        f.meta.tx_pps = Some(0);
        f
    }

    fn snapshot(flows: Vec<Flow>) -> Snapshot {
        Snapshot {
            source: "test".into(),
            timestamp_ms: 0,
            interval_ms: 1000,
            processes: vec![ProcessTraffic {
                process: Process {
                    pid: 1,
                    name: "curl".into(),
                    path: None,
                    app: None,
                },
                rx_rate: 0,
                tx_rate: 0,
                rx_bytes: 0,
                tx_bytes: 0,
                verdict: Verdict::Ok,
                flows,
                resources: None,
            }],
            link: None,
        }
    }

    fn counters(name: &str, rx: u64, tx: u64) -> (String, Counters) {
        (
            name.to_string(),
            Counters {
                name: name.into(),
                rx_bytes: rx,
                tx_bytes: tx,
            },
        )
    }

    #[test]
    fn a_download_is_fully_accounted_for_headers_included() {
        // 1000 full packets of 1448 bytes of payload: 1514 bytes each on the wire.
        let snap = snapshot(vec![
            flow("192.168.1.36:50000", "93.184.216.34:443", 1_448_000, 1000),
            // Loopback and tunnel traffic never crosses the adapter.
            flow("127.0.0.1:50001", "127.0.0.1:8080", 9_999_999, 10),
            flow("10.8.0.2:50002", "10.8.0.1:53", 5_000, 10),
        ]);
        let before = HashMap::from([counters("en0", 0, 0)]);
        let after = HashMap::from([counters("en0", 1_514_000, 40_000)]);
        let addresses = HashSet::from(["192.168.1.36".parse().unwrap()]);
        let link = reconcile(&snap, &before, &after, 1.0, &addresses);
        assert_eq!(link.rx_rate, 1_514_000);
        assert_eq!(link.attributed_rx, 1_448_000 + 1000 * 66);
        assert_eq!(link.interfaces, vec!["en0".to_string()]);
        let coverage = link.coverage().unwrap();
        assert!(coverage > 0.95, "{coverage}");
        assert_eq!(link.unattributed().1, 40_000);
    }

    #[test]
    fn reset_counters_and_quiet_links_are_not_misread() {
        let snap = snapshot(Vec::new());
        let before = HashMap::from([counters("eth0", 5_000_000, 5_000_000)]);
        let after = HashMap::from([counters("eth0", 100, 100)]);
        let link = reconcile(&snap, &before, &after, 1.0, &HashSet::new());
        assert_eq!((link.rx_rate, link.tx_rate), (0, 0));
        assert_eq!(link.coverage(), None, "too little traffic to judge");
    }

    #[test]
    fn virtual_interfaces_are_left_out() {
        for name in [
            "lo0",
            "lo",
            "utun3",
            "wg0",
            "docker0",
            "veth12ab",
            "awdl0",
            "bridge100",
        ] {
            assert!(is_virtual(name), "{name}");
        }
        for name in [
            "en0", "en7", "eth0", "wlp2s0", "enp3s0", "Wi-Fi", "Ethernet",
        ] {
            assert!(!is_virtual(name), "{name}");
        }
    }

    #[test]
    fn proc_net_dev_is_parsed() {
        let text = "Inter-|   Receive                                                |  Transmit
 face |bytes    packets errs drop fifo frame compressed multicast|bytes    packets errs drop fifo colls carrier compressed
    lo: 1000 10 0 0 0 0 0 0 1000 10 0 0 0 0 0 0
  eth0: 123456789 1000 0 0 0 0 0 0 987654321 900 0 0 0 0 0 0
";
        let c = parse_proc_net_dev(text);
        assert_eq!(c.len(), 2);
        assert_eq!(c[1].name, "eth0");
        assert_eq!((c[1].rx_bytes, c[1].tx_bytes), (123_456_789, 987_654_321));
    }

    #[test]
    fn this_computer_has_readable_interface_counters() {
        let counters = read().unwrap();
        assert!(!counters.is_empty());
    }
}
