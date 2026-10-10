//! Live capture on Linux, from an eBPF probe that counts bytes per socket in the kernel
//! (see `probe` and ebpf/spectranet.bpf.c). Needs root to load the probe.
//!
//! Counters start when the probe is attached; rates are differences between samples. A
//! socket is identified by its kernel address *and* the time it was first seen, so a new
//! socket reusing a closed one's memory never inherits its counters.

pub(crate) mod destroy;
mod diag;
#[allow(unsafe_code)]
mod probe;

use std::collections::{BTreeMap, HashMap};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use spectranet_model::{App, Flow, Process, ProcessTraffic, Snapshot, Transport, Verdict};

use crate::names::NameTable;
use crate::names::lan::LanResolver;
use crate::names::live::{LiveNames, StartError};
use crate::{CaptureError, SourceOptions, TrafficSource};
use probe::{Probe, ProbeError, SockInfo};

const AF_INET: u16 = 2;
const AF_INET6: u16 = 10;
const PROTO_TCP: u8 = 6;

pub struct LinuxSource {
    probe: Probe,
    previous: HashMap<(u64, u64), (u64, u64, u32, u32)>,
    last_sample: Option<Instant>,
    processes: HashMap<u32, (String, Option<String>, Option<App>)>,
    owners: diag::InodeOwners,
    names: Arc<Mutex<NameTable>>,
    lan: Option<LanResolver>,
    /// Keeps DNS/TLS/QUIC name capture running; `None` with `-n`.
    _live_names: Option<LiveNames>,
    notices: Vec<String>,
}

impl LinuxSource {
    pub fn open(options: SourceOptions) -> Result<Self, CaptureError> {
        let probe = Probe::start().map_err(|e| match e {
            ProbeError::PermissionDenied => CaptureError::PermissionDenied(
                "loading the eBPF probe needs root: run with sudo, or install snetd".into(),
            ),
            ProbeError::Failed(m) => CaptureError::Backend(format!("eBPF probe: {m}")),
        })?;
        let mut table = NameTable::default();
        if options.resolve_names {
            for (name, ip) in crate::names::hosts::load_system() {
                table.learn_static(name, ip);
            }
        }
        let names = Arc::new(Mutex::new(table));
        let lan = options
            .resolve_names
            .then(|| LanResolver::start(names.clone()));
        let mut notices = Vec::new();
        let live_names = if options.resolve_names {
            match LiveNames::start(names.clone()) {
                Ok(live) => Some(live),
                Err(StartError::PermissionDenied) => {
                    notices.push(
                        "hostnames from traffic unavailable: packet capture needs root".into(),
                    );
                    None
                }
                Err(StartError::Failed(reason)) => {
                    notices.push(format!("hostnames from traffic unavailable: {reason}"));
                    None
                }
            }
        } else {
            None
        };
        Ok(Self {
            probe,
            previous: HashMap::new(),
            last_sample: None,
            processes: HashMap::new(),
            owners: diag::InodeOwners::new(Duration::from_secs(2)),
            names,
            lan,
            _live_names: live_names,
            notices,
        })
    }

    fn describe(&mut self, pid: u32, comm: &[u8; 16]) -> Process {
        let fallback =
            String::from_utf8_lossy(comm.split(|b| *b == 0).next().unwrap_or(&[])).into_owned();
        let (name, path, app) = self
            .processes
            .entry(pid)
            .or_insert_with(|| {
                let name = std::fs::read_to_string(format!("/proc/{pid}/comm"))
                    .map(|s| s.trim_end().to_string())
                    .unwrap_or(fallback);
                let path = std::fs::read_link(format!("/proc/{pid}/exe"))
                    .ok()
                    .map(|p| p.to_string_lossy().into_owned());
                let app = std::fs::read_to_string(format!("/proc/{pid}/cgroup"))
                    .ok()
                    .and_then(|text| service_of(&text));
                (name, path, app)
            })
            .clone();
        Process {
            pid,
            name,
            path,
            app,
        }
    }
}

/// The systemd service a process runs in, from /proc/<pid>/cgroup (cgroup v2: `0::/path`).
/// Processes of the same service form one application, named after it.
pub(crate) fn service_of(cgroup: &str) -> Option<App> {
    let path = cgroup.lines().find_map(|l| l.strip_prefix("0::"))?;
    let unit = path.rsplit('/').find(|c| c.ends_with(".service"))?;
    let name = unit.trim_end_matches(".service");
    // User sessions ("user@1000.service") hold everything a user runs: not one application.
    if name.is_empty() || name.starts_with("user@") || name == "init.scope" {
        return None;
    }
    Some(App {
        name: name.to_string(),
        path: format!("systemd:{unit}"),
        main: false,
    })
}

/// Socket address from the probe's raw fields.
pub(crate) fn address(family: u16, raw: &[u8; 16], port: u16) -> Option<SocketAddr> {
    let ip = match family {
        AF_INET => IpAddr::V4(Ipv4Addr::new(raw[0], raw[1], raw[2], raw[3])),
        AF_INET6 => {
            let v6 = Ipv6Addr::from(*raw);
            v6.to_ipv4_mapped().map_or(IpAddr::V6(v6), IpAddr::V4)
        }
        _ => return None,
    };
    Some(SocketAddr::new(ip, port))
}

impl TrafficSource for LinuxSource {
    fn name(&self) -> &'static str {
        "linux"
    }

    fn notices(&self) -> Vec<String> {
        self.notices.clone()
    }

    fn sample(&mut self) -> Result<Snapshot, CaptureError> {
        // Live first, then closed: a socket closed in between appears in both, and its final
        // counters (from the close event) must win.
        let mut sockets: BTreeMap<(u64, u64), (SockInfo, bool)> = BTreeMap::new();
        for (sk, info) in self.probe.live() {
            sockets.insert((sk, info.born_ns), (info, false));
        }
        for (sk, info) in self.probe.drain_closed() {
            sockets.insert((sk, info.born_ns), (info, true));
        }
        let now = Instant::now();
        let first = self.last_sample.is_none();
        let elapsed = self.last_sample.map_or(Duration::ZERO, |t| now - t);
        self.last_sample = Some(now);

        let names = self
            .names
            .lock()
            .map_err(|_| CaptureError::Backend("hostname table lock poisoned".into()))?;
        let mut previous = HashMap::with_capacity(sockets.len());
        let mut by_pid: BTreeMap<u32, ([u8; 16], Vec<Flow>)> = BTreeMap::new();
        for (id, (info, closed)) in sockets {
            // Counters begin when the probe attached, so an unseen socket's bytes are all new,
            // except on the very first sample, which only sets the baseline.
            let baseline = self.previous.get(&id).copied().unwrap_or(if first {
                (info.rx, info.tx, info.rx_msgs, info.tx_msgs)
            } else {
                (0, 0, 0, 0)
            });
            if !closed {
                previous.insert(id, (info.rx, info.tx, info.rx_msgs, info.tx_msgs));
            }
            let (Some(local), Some(remote)) = (
                address(info.family, &info.saddr, info.sport),
                address(info.family, &info.daddr, info.dport),
            ) else {
                continue;
            };
            let transport = if info.proto == PROTO_TCP {
                Transport::Tcp
            } else {
                Transport::Udp
            };
            let remote_host = names.lookup(local, remote).map(str::to_owned);
            if remote_host.is_none()
                && let Some(lan) = &self.lan
            {
                lan.request(remote.ip());
            }
            let flow = Flow {
                transport,
                local,
                remote,
                remote_host,
                rx_rate: per_second(info.rx.saturating_sub(baseline.0), elapsed),
                tx_rate: per_second(info.tx.saturating_sub(baseline.1), elapsed),
                rx_bytes: info.rx,
                tx_bytes: info.tx,
                verdict: Verdict::Ok,
                note: None,
                meta: spectranet_model::flowmeta::FlowMeta {
                    rx_pps: (!first).then(|| {
                        per_second(u64::from(info.rx_msgs.wrapping_sub(baseline.2)), elapsed) as u32
                    }),
                    tx_pps: (!first).then(|| {
                        per_second(u64::from(info.tx_msgs.wrapping_sub(baseline.3)), elapsed) as u32
                    }),
                    tls: names.tls(local, remote),
                    ..Default::default()
                },
            };
            by_pid
                .entry(info.tgid)
                .or_insert_with(|| (info.comm, Vec::new()))
                .1
                .push(flow);
        }
        drop(names);

        // Lifetime counters and idle connections from the kernel's TCP table.
        if let Ok(conns) = diag::tcp_connections() {
            let mut seen = std::collections::HashSet::new();
            for (_, flows) in by_pid.values_mut() {
                for flow in flows.iter_mut().filter(|f| f.transport == Transport::Tcp) {
                    seen.insert((flow.local, flow.remote));
                    if let Some(c) = conns
                        .iter()
                        .find(|c| c.local == flow.local && c.remote == flow.remote)
                    {
                        flow.rx_bytes = flow.rx_bytes.max(c.bytes_received);
                        flow.tx_bytes = flow.tx_bytes.max(c.bytes_acked);
                    }
                }
            }
            for c in conns {
                // TIME_WAIT (6) and CLOSE (7) belong to no process any more.
                if matches!(c.state, 6 | 7)
                    || c.remote.ip().is_unspecified()
                    || seen.contains(&(c.local, c.remote))
                {
                    continue;
                }
                let Some(pid) = self.owners.owner(c.inode) else {
                    continue;
                };
                let names = self
                    .names
                    .lock()
                    .map_err(|_| CaptureError::Backend("hostname table lock poisoned".into()))?;
                let flow = Flow {
                    transport: Transport::Tcp,
                    local: c.local,
                    remote: c.remote,
                    remote_host: names.lookup(c.local, c.remote).map(str::to_owned),
                    rx_rate: 0,
                    tx_rate: 0,
                    rx_bytes: c.bytes_received,
                    tx_bytes: c.bytes_acked,
                    verdict: Verdict::Ok,
                    note: None,
                    meta: spectranet_model::flowmeta::FlowMeta {
                        tls: names.tls(c.local, c.remote),
                        ..Default::default()
                    },
                };
                by_pid
                    .entry(pid)
                    .or_insert_with(|| ([0; 16], Vec::new()))
                    .1
                    .push(flow);
            }
        }
        self.previous = previous;
        self.processes.retain(|pid, _| by_pid.contains_key(pid));

        let processes = by_pid
            .into_iter()
            .map(|(pid, (comm, flows))| ProcessTraffic::new(self.describe(pid, &comm), flows))
            .collect();
        Ok(Snapshot {
            source: self.name().to_string(),
            timestamp_ms: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map_or(0, |d| d.as_millis() as u64),
            interval_ms: elapsed.as_millis() as u64,
            processes,
            link: None,
        })
    }
}

fn per_second(bytes: u64, elapsed: Duration) -> u64 {
    let secs = elapsed.as_secs_f64();
    if secs <= 0.0 {
        0
    } else {
        (bytes as f64 / secs).round() as u64
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn addresses_from_probe_fields() {
        let mut raw = [0u8; 16];
        raw[..4].copy_from_slice(&[192, 168, 1, 50]);
        assert_eq!(
            address(AF_INET, &raw, 445),
            Some("192.168.1.50:445".parse().unwrap())
        );
        let v6: Ipv6Addr = "2001:db8::1".parse().unwrap();
        assert_eq!(
            address(AF_INET6, &v6.octets(), 443),
            Some("[2001:db8::1]:443".parse().unwrap())
        );
        let mapped: Ipv6Addr = "::ffff:1.2.3.4".parse().unwrap();
        assert_eq!(
            address(AF_INET6, &mapped.octets(), 80),
            Some("1.2.3.4:80".parse().unwrap())
        );
        assert_eq!(address(1, &raw, 0), None, "AF_UNIX and others are ignored");
    }

    #[test]
    fn services_from_cgroups() {
        let jellyfin = service_of("0::/system.slice/jellyfin.service\n").unwrap();
        assert_eq!(
            (jellyfin.name.as_str(), jellyfin.path.as_str()),
            ("jellyfin", "systemd:jellyfin.service")
        );
        let user_service = service_of(
            "0::/user.slice/user-1000.slice/user@1000.service/app.slice/syncthing.service\n",
        )
        .unwrap();
        assert_eq!(user_service.name, "syncthing");
        assert_eq!(
            service_of("0::/user.slice/user-1000.slice/session-3.scope\n"),
            None,
            "interactive session"
        );
        assert_eq!(
            service_of("0::/user.slice/user-1000.slice/user@1000.service/init.scope\n"),
            None
        );
        assert_eq!(service_of("0::/\n"), None);
        assert_eq!(
            service_of("12:cpu:/foo\n"),
            None,
            "cgroup v1 lines are ignored"
        );
    }

    /// Live (needs root for the probe): an idle connection opened before sampling started is
    /// listed, with its lifetime bytes, though it moves nothing now.
    #[test]
    fn idle_connections_are_listed_with_lifetime_bytes() {
        use std::io::{Read, Write};
        use std::net::{TcpListener, TcpStream};

        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let mut client = TcpStream::connect(addr).unwrap();
        let (mut server, _) = listener.accept().unwrap();
        client.write_all(&[3u8; 50_000]).unwrap();
        let mut sink = vec![0u8; 50_000];
        server.read_exact(&mut sink).unwrap();

        let mut source = match LinuxSource::open(SourceOptions {
            resolve_names: false,
            service: false,
        }) {
            Ok(s) => s,
            Err(CaptureError::PermissionDenied(_)) if !root() => return,
            Err(e) => panic!("{e}"),
        };
        source.sample().unwrap();
        std::thread::sleep(Duration::from_millis(100));
        let snapshot = source.sample().unwrap();
        let flow = snapshot
            .processes
            .iter()
            .filter(|p| p.process.pid == std::process::id())
            .flat_map(|p| &p.flows)
            .find(|f| f.local == client.local_addr().unwrap())
            .expect("idle connection listed");
        assert_eq!((flow.tx_bytes, flow.tx_rate), (50_000, 0));
    }

    fn root() -> bool {
        // SAFETY: no preconditions.
        #[allow(unsafe_code)]
        unsafe {
            libc::geteuid() == 0
        }
    }

    /// Live: move known bytes over TCP and UDP loopback and find them attributed to us.
    #[test]
    fn live_counters_attribute_traffic_to_this_process() {
        use std::io::{Read, Write};
        use std::net::{TcpListener, TcpStream, UdpSocket};

        let mut source = match LinuxSource::open(SourceOptions {
            resolve_names: false,
            service: false,
        }) {
            Ok(s) => s,
            Err(CaptureError::PermissionDenied(_)) if !root() => {
                eprintln!("not root: skipping live eBPF test");
                return;
            }
            Err(e) => panic!("{e}"),
        };
        source.sample().unwrap();

        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let mut client = TcpStream::connect(addr).unwrap();
        let (mut server, _) = listener.accept().unwrap();
        client.write_all(&[1u8; 300_000]).unwrap();
        let mut sink = vec![0u8; 300_000];
        server.read_exact(&mut sink).unwrap();

        let udp_a = UdpSocket::bind("127.0.0.1:0").unwrap();
        let udp_b = UdpSocket::bind("127.0.0.1:0").unwrap();
        for _ in 0..10 {
            udp_a
                .send_to(&[2u8; 1000], udp_b.local_addr().unwrap())
                .unwrap();
            let mut buf = [0u8; 1500];
            udp_b.recv_from(&mut buf).unwrap();
        }
        std::thread::sleep(Duration::from_millis(200));
        let snapshot = source.sample().unwrap();
        let me = snapshot
            .processes
            .iter()
            .find(|p| p.process.pid == std::process::id())
            .expect("this process is listed");
        let tcp = me
            .flows
            .iter()
            .find(|f| f.transport == Transport::Tcp && f.remote == addr)
            .expect("TCP client flow");
        assert!(tcp.tx_bytes >= 300_000 && tcp.tx_rate > 0, "{tcp:?}");
        let server_side = me
            .flows
            .iter()
            .find(|f| f.transport == Transport::Tcp && f.local == addr)
            .expect("TCP server flow");
        assert!(server_side.rx_bytes >= 300_000, "{server_side:?}");
        let udp = me
            .flows
            .iter()
            .find(|f| f.transport == Transport::Udp && f.local == udp_a.local_addr().unwrap())
            .expect("UDP sender flow");
        assert_eq!(udp.tx_bytes, 10_000, "{udp:?}");
        assert_eq!(
            udp.remote,
            udp_b.local_addr().unwrap(),
            "destination taken from sendto()"
        );
    }

    /// Live: a connection that opens, transfers and closes between two samples is reported once.
    #[test]
    fn short_lived_connections_are_not_missed() {
        use std::io::{Read, Write};
        use std::net::{TcpListener, TcpStream};

        let mut source = match LinuxSource::open(SourceOptions {
            resolve_names: false,
            service: false,
        }) {
            Ok(s) => s,
            Err(CaptureError::PermissionDenied(_)) if !root() => return,
            Err(e) => panic!("{e}"),
        };
        source.sample().unwrap();
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let server = std::thread::spawn(move || {
            let (mut c, _) = listener.accept().unwrap();
            let mut b = vec![0u8; 20_000];
            c.read_exact(&mut b).unwrap();
        });
        let local = {
            let mut c = TcpStream::connect(addr).unwrap();
            c.write_all(&[9u8; 20_000]).unwrap();
            server.join().unwrap();
            c.local_addr().unwrap()
        };
        std::thread::sleep(Duration::from_millis(100));
        let snapshot = source.sample().unwrap();
        let flow = snapshot
            .processes
            .iter()
            .flat_map(|p| &p.flows)
            .find(|f| f.local == local && f.remote == addr)
            .expect("closed connection reported");
        assert_eq!(flow.tx_bytes, 20_000);
        assert!(flow.tx_rate > 0);
        let next = source.sample().unwrap();
        assert!(
            !next
                .processes
                .iter()
                .flat_map(|p| &p.flows)
                .any(|f| f.local == local),
            "then forgotten"
        );
    }
}
