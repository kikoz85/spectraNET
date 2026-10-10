//! Live capture on macOS, from the kernel's per-socket counters (see [`nstat`]).
//!
//! The kernel reports cumulative bytes per socket; rates are the difference between two
//! consecutive samples divided by the time between them.

mod apps;
#[allow(unsafe_code)]
mod nstat;
mod sockaddr;

use std::collections::{BTreeMap, HashMap};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use spectranet_model::{App, Flow, Process, ProcessTraffic, Snapshot, Transport, Verdict};

use crate::names::NameTable;
use crate::names::lan::LanResolver;
use crate::names::live::{LiveNames, StartError};
use crate::{CaptureError, SourceOptions, TrafficSource};
use apps::AppResolver;
use nstat::{NStat, RawFlow};

const QUERY_TIMEOUT: Duration = Duration::from_secs(5);

pub struct MacosSource {
    nstat: NStat,
    /// Byte counters per socket at the previous sample.
    previous: HashMap<u64, (u64, u64, u64, u64)>,
    /// When the previous sample was taken, as wall-clock and kernel (mach) time.
    last_sample: Option<(Instant, u64)>,
    /// Kernel time when the source was opened.
    opened_at: u64,
    processes: HashMap<u32, ProcessInfo>,
    apps: AppResolver,
    names: Arc<Mutex<NameTable>>,
    /// Keeps the packet capture threads alive; `None` when names are disabled or unavailable.
    _live_names: Option<LiveNames>,
    /// Active reverse lookups for LAN peers; `None` with `-n`.
    lan: Option<LanResolver>,
    notices: Vec<String>,
}

/// Cached facts about a process, keyed by PID and invalidated when its name changes
/// (which indicates the PID was reused).
struct ProcessInfo {
    name: String,
    path: Option<String>,
    app: Option<App>,
}

impl MacosSource {
    pub fn open(options: SourceOptions) -> Result<Self, CaptureError> {
        let nstat = NStat::open().map_err(|e| {
            CaptureError::Backend(format!("cannot open macOS network statistics: {e}"))
        })?;
        // The kernel announces existing sockets asynchronously; one round trip lets them
        // arrive so the caller's first sample already sees every connection.
        nstat
            .refresh(QUERY_TIMEOUT)
            .map_err(CaptureError::Backend)?;
        let mut table = NameTable::default();
        if options.resolve_names {
            for (name, ip) in crate::names::hosts::load_system() {
                table.learn_static(name, ip);
            }
        }
        let names = Arc::new(Mutex::new(table));
        let mut notices = Vec::new();
        let live_names = if options.resolve_names {
            match LiveNames::start(names.clone()) {
                Ok(live) => Some(live),
                Err(StartError::PermissionDenied) => {
                    notices.push(
                        "only /etc/hosts names are shown: discovering hostnames from traffic needs root \
                         (run with sudo, or pass -n to show addresses only)"
                            .into(),
                    );
                    None
                }
                Err(StartError::Failed(reason)) => {
                    notices.push(format!("hostnames unavailable: {reason}"));
                    None
                }
            }
        } else {
            None
        };
        let lan = options
            .resolve_names
            .then(|| LanResolver::start(names.clone()));
        Ok(Self {
            nstat,
            previous: HashMap::new(),
            last_sample: None,
            opened_at: mach_time(),
            processes: HashMap::new(),
            apps: AppResolver::default(),
            names,
            _live_names: live_names,
            lan,
            notices,
        })
    }

    fn describe(&mut self, pid: u32, name: String) -> Process {
        let stale = self
            .processes
            .get(&pid)
            .is_none_or(|info| info.name != name);
        if stale {
            let path = process_path(pid);
            let app = path.as_deref().and_then(|p| self.apps.resolve(pid, p));
            self.processes.insert(
                pid,
                ProcessInfo {
                    name: name.clone(),
                    path,
                    app,
                },
            );
        }
        let info = &self.processes[&pid];
        Process {
            pid,
            name,
            path: info.path.clone(),
            app: info.app.clone(),
        }
    }
}

impl TrafficSource for MacosSource {
    fn name(&self) -> &'static str {
        "macos"
    }

    fn notices(&self) -> Vec<String> {
        self.notices.clone()
    }

    fn sample(&mut self) -> Result<Snapshot, CaptureError> {
        let sockets = self
            .nstat
            .refresh(QUERY_TIMEOUT)
            .map_err(CaptureError::Backend)?;
        let now = Instant::now();
        let now_mach = mach_time();
        let (elapsed, since) = match self.last_sample {
            Some((at, mach)) => (now - at, mach),
            None => (Duration::ZERO, self.opened_at),
        };
        self.last_sample = Some((now, now_mach));

        let names = self
            .names
            .lock()
            .map_err(|_| CaptureError::Backend("hostname table lock poisoned".into()))?;
        let mut previous = HashMap::with_capacity(sockets.len());
        let mut by_pid: BTreeMap<u32, (String, Vec<Flow>)> = BTreeMap::new();
        for (id, raw, removed) in sockets {
            let baseline = match self.previous.get(&id) {
                Some(&counts) => counts,
                // Opened during the interval: every byte it carried belongs to this interval.
                None if raw.start_time >= since => (0, 0, 0, 0),
                // Pre-existing socket seen for the first time: no history to attribute.
                None => (raw.rx_bytes, raw.tx_bytes, raw.rx_packets, raw.tx_packets),
            };
            if !removed {
                previous.insert(
                    id,
                    (raw.rx_bytes, raw.tx_bytes, raw.rx_packets, raw.tx_packets),
                );
            }
            if !is_interesting(&raw) {
                continue;
            }
            let rx_delta = raw.rx_bytes.saturating_sub(baseline.0);
            let tx_delta = raw.tx_bytes.saturating_sub(baseline.1);
            let flow = Flow {
                meta: spectranet_model::flowmeta::FlowMeta {
                    rx_pps: (!elapsed.is_zero()).then(|| {
                        per_second(raw.rx_packets.saturating_sub(baseline.2), elapsed) as u32
                    }),
                    tx_pps: (!elapsed.is_zero()).then(|| {
                        per_second(raw.tx_packets.saturating_sub(baseline.3), elapsed) as u32
                    }),
                    tls: names.tls(raw.local, raw.remote),
                    ..Default::default()
                },
                transport: raw.transport,
                local: raw.local,
                remote: raw.remote,
                remote_host: match names.lookup(raw.local, raw.remote) {
                    Some(name) => Some(name.to_owned()),
                    None => {
                        if let Some(lan) = &self.lan {
                            lan.request(raw.remote.ip());
                        }
                        None
                    }
                },
                rx_rate: per_second(rx_delta, elapsed),
                tx_rate: per_second(tx_delta, elapsed),
                rx_bytes: raw.rx_bytes,
                tx_bytes: raw.tx_bytes,
                verdict: Verdict::Ok,
                note: None,
            };
            by_pid
                .entry(raw.pid)
                .or_insert_with(|| (raw.process_name.clone(), Vec::new()))
                .1
                .push(flow);
        }
        drop(names);
        self.previous = previous;
        self.processes.retain(|pid, _| by_pid.contains_key(pid));

        let processes = by_pid
            .into_iter()
            .map(|(pid, (name, flows))| ProcessTraffic::new(self.describe(pid, name), flows))
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

/// Hides sockets that carry no traffic and never will: listeners and idle unconnected UDP.
fn is_interesting(raw: &RawFlow) -> bool {
    if raw.tcp_state.as_deref() == Some("Listen") {
        return false;
    }
    let has_traffic = raw.rx_bytes + raw.tx_bytes > 0;
    match raw.transport {
        Transport::Tcp => has_traffic || !raw.remote.ip().is_unspecified(),
        Transport::Udp => has_traffic,
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

#[allow(unsafe_code)]
fn mach_time() -> u64 {
    // SAFETY: no preconditions; reads a monotonic kernel clock.
    unsafe { mach_absolute_time() }
}

#[allow(unsafe_code)]
unsafe extern "C" {
    fn mach_absolute_time() -> u64;
}

#[allow(unsafe_code)]
fn process_path(pid: u32) -> Option<String> {
    let mut buf = vec![0u8; libc::PROC_PIDPATHINFO_MAXSIZE as usize];
    // SAFETY: the buffer is writable and its exact size is passed.
    let len = unsafe { libc::proc_pidpath(pid as i32, buf.as_mut_ptr().cast(), buf.len() as u32) };
    if len <= 0 {
        return None;
    }
    buf.truncate(len as usize);
    String::from_utf8(buf).ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn raw(transport: Transport, remote: &str, state: Option<&str>, bytes: u64) -> RawFlow {
        RawFlow {
            pid: 1,
            process_name: "test".into(),
            transport,
            local: "192.168.1.2:50000".parse().unwrap(),
            remote: remote.parse().unwrap(),
            tcp_state: state.map(str::to_string),
            rx_packets: 0,
            tx_packets: 0,
            rx_bytes: bytes,
            tx_bytes: 0,
            start_time: 0,
        }
    }

    #[test]
    fn filters_idle_sockets() {
        assert!(!is_interesting(&raw(
            Transport::Tcp,
            "0.0.0.0:0",
            Some("Listen"),
            0
        )));
        assert!(!is_interesting(&raw(Transport::Udp, "0.0.0.0:0", None, 0)));
        assert!(is_interesting(&raw(Transport::Udp, "0.0.0.0:0", None, 10)));
        assert!(is_interesting(&raw(
            Transport::Tcp,
            "1.1.1.1:443",
            Some("Established"),
            0
        )));
    }

    #[test]
    fn rates_are_per_second() {
        assert_eq!(per_second(1000, Duration::from_millis(500)), 2000);
        assert_eq!(per_second(1000, Duration::ZERO), 0);
    }

    #[test]
    fn own_process_path_is_known() {
        let path = process_path(std::process::id()).unwrap();
        assert!(path.starts_with('/'));
    }

    /// A connection opened and closed between two samples (like a quick HTTP request) must
    /// still be reported, with its full byte count, in the next sample.
    #[test]
    fn short_lived_connections_are_not_missed() {
        use std::io::{Read, Write};
        use std::net::{TcpListener, TcpStream};

        let mut source = MacosSource::open(SourceOptions {
            resolve_names: false,
            service: false,
        })
        .unwrap();
        source.sample().unwrap();

        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let server = std::thread::spawn(move || {
            let (mut conn, _) = listener.accept().unwrap();
            let mut buf = vec![0u8; 20_000];
            conn.read_exact(&mut buf).unwrap();
        });
        let local = {
            let mut client = TcpStream::connect(addr).unwrap();
            client.write_all(&[9u8; 20_000]).unwrap();
            let local = client.local_addr().unwrap();
            server.join().unwrap();
            local
        }; // closed here, well before the next sample
        std::thread::sleep(Duration::from_millis(300));

        let snapshot = source.sample().unwrap();
        let flow = snapshot
            .processes
            .iter()
            .flat_map(|p| &p.flows)
            .find(|f| f.local == local && f.remote == addr)
            .expect("the closed connection is reported once");
        assert!(flow.tx_bytes >= 20_000, "tx_bytes = {}", flow.tx_bytes);
        assert!(flow.tx_rate > 0, "its bytes count towards this interval");

        let next = source.sample().unwrap();
        assert!(
            !next
                .processes
                .iter()
                .flat_map(|p| &p.flows)
                .any(|f| f.local == local),
            "and then forgotten"
        );
    }

    /// Exercises the real kernel interface: open a TCP connection to ourselves, move a known
    /// number of bytes, and check the counters attribute them to this process.
    #[test]
    fn live_counters_attribute_traffic_to_this_process() {
        use std::io::{Read, Write};
        use std::net::{TcpListener, TcpStream};

        let mut source = MacosSource::open(SourceOptions {
            resolve_names: false,
            service: false,
        })
        .expect("NetworkStatistics available");
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let mut client = TcpStream::connect(addr).unwrap();
        let (mut server, _) = listener.accept().unwrap();
        source.sample().unwrap();

        let payload = vec![7u8; 256 * 1024];
        client.write_all(&payload).unwrap();
        let mut received = vec![0u8; payload.len()];
        server.read_exact(&mut received).unwrap();
        std::thread::sleep(Duration::from_millis(200));

        let snapshot = source.sample().unwrap();
        let me = snapshot
            .processes
            .iter()
            .find(|p| p.process.pid == std::process::id())
            .expect("this test process appears in the snapshot");
        let client_flow = me
            .flows
            .iter()
            .find(|f| f.remote == addr)
            .expect("client side of the connection is reported");
        assert!(
            client_flow.tx_bytes >= payload.len() as u64,
            "tx_bytes = {}",
            client_flow.tx_bytes
        );
        assert!(client_flow.tx_rate > 0);
    }
}
