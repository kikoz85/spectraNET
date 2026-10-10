//! Live capture on Windows from ETW (Event Tracing for Windows): the Kernel-Network provider
//! reports every TCP/UDP send and receive with the owning process, so even connections
//! shorter than a sample are counted exactly; the DNS-Client provider names the addresses
//! applications resolved. Needs Administrator rights to start the trace session.

#[allow(unsafe_code)]
mod system;

use std::collections::{BTreeMap, HashMap, HashSet};
use std::net::{IpAddr, SocketAddr};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use ferrisetw::EventRecord;
use ferrisetw::parser::Parser;
use ferrisetw::provider::Provider;
use ferrisetw::schema_locator::SchemaLocator;
use ferrisetw::trace::{UserTrace, stop_trace_by_name};
use spectranet_model::{App, Flow, Process, ProcessTraffic, Snapshot, Transport, Verdict};

use crate::names::NameTable;
use crate::names::dns::{Resolution, valid_hostname};
use crate::names::lan::LanResolver;
use crate::windows_accounting::{Accounting, FlowKey, NetEvent, dns_results, ipv4_from_event};
use crate::{CaptureError, SourceOptions, TrafficSource};

/// The service's trace session. Other clients use `spectraNET-<pid>`.
const SERVICE_SESSION: &str = "spectraNET";
/// How often the service checks that its session is still running.
const WATCHDOG: Duration = Duration::from_secs(10);
const KERNEL_NETWORK: &str = "7dd42a49-5329-4832-8dfd-43d979153a88";
const DNS_CLIENT: &str = "1c95126e-7eea-49a9-a3fe-a378b03ddb4d";
/// KERNEL_NETWORK_KEYWORD_IPV4 | KERNEL_NETWORK_KEYWORD_IPV6.
const IPV4_IPV6: u64 = 0x30;

/// Executable paths, captured when a process is first seen on the network: a short-lived
/// process may be gone by the next sample, too late to ask for its name.
type PathCache = Arc<Mutex<HashMap<u32, Option<String>>>>;

pub struct WindowsSource {
    accounting: Arc<Mutex<Accounting>>,
    paths: PathCache,
    /// Dropped (stopping the session) before a replacement is started.
    trace: Option<UserTrace>,
    session: String,
    resolve_names: bool,
    last_check: Instant,
    restarts: u32,
    previous: HashMap<(FlowKey, u64), (u64, u64, u64, u64)>,
    last_sample: Option<Instant>,
    processes: HashMap<u32, (String, Option<String>, Option<App>)>,
    names: Arc<Mutex<NameTable>>,
    lan: Option<LanResolver>,
}

/// Reads an address field: IPv6 fields parse as addresses, IPv4 ones as 32-bit integers.
fn address(parser: &Parser<'_, '_>, name: &str) -> Option<IpAddr> {
    parser
        .try_parse::<IpAddr>(name)
        .ok()
        .or_else(|| parser.try_parse::<u32>(name).ok().map(ipv4_from_event))
}

fn network_event(record: &EventRecord, locator: &SchemaLocator) -> Option<NetEvent> {
    let id = record.event_id();
    if !matches!(id, 10..=13 | 15 | 26..=29 | 31 | 42 | 43 | 58 | 59) {
        return None;
    }
    let schema = locator.event_schema(record).ok()?;
    let parser = Parser::create(record, &schema);
    Some(NetEvent {
        id,
        pid: parser.try_parse("PID").ok()?,
        size: parser.try_parse("size").unwrap_or(0),
        saddr: address(&parser, "saddr")?,
        daddr: address(&parser, "daddr")?,
        sport_be: parser.try_parse("sport").ok()?,
        dport_be: parser.try_parse("dport").ok()?,
    })
}

/// Event 3008 (query completed, `QueryStatus`) and 3020 (response, `Status`).
fn dns_event(record: &EventRecord, locator: &SchemaLocator) -> Option<Resolution> {
    let id = record.event_id();
    if id != 3008 && id != 3020 {
        return None;
    }
    let schema = locator.event_schema(record).ok()?;
    let parser = Parser::create(record, &schema);
    let status: u32 = parser
        .try_parse(if id == 3008 { "QueryStatus" } else { "Status" })
        .ok()?;
    if status != 0 {
        return None;
    }
    let name = parser
        .try_parse::<String>("QueryName")
        .ok()?
        .trim_end_matches('.')
        .to_ascii_lowercase();
    let addrs = dns_results(&parser.try_parse::<String>("QueryResults").ok()?);
    (valid_hostname(&name) && !addrs.is_empty()).then_some(Resolution { name, addrs })
}

impl WindowsSource {
    pub fn open(options: SourceOptions) -> Result<Self, CaptureError> {
        let session = if options.service {
            SERVICE_SESSION.to_string()
        } else {
            // Several sources may live in one process (the app, tests): each gets its own.
            static NEXT: std::sync::atomic::AtomicU32 = std::sync::atomic::AtomicU32::new(0);
            let n = NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            format!("{SERVICE_SESSION}-{}-{n}", std::process::id())
        };
        // A session left behind by a previous run of the same owner that did not exit
        // cleanly would block ours. Never another owner's: that would blind the service.
        let _ = stop_trace_by_name(&session);
        stop_orphaned_sessions();

        let accounting = Arc::new(Mutex::new(Accounting::default()));
        let paths: PathCache = Arc::new(Mutex::new(HashMap::new()));
        let mut table = NameTable::default();
        if options.resolve_names {
            for (name, ip) in crate::names::hosts::load_system() {
                table.learn_static(name, ip);
            }
        }
        let names = Arc::new(Mutex::new(table));
        let trace = start_trace(&session, options.resolve_names, &accounting, &paths, &names)?;
        let lan = options
            .resolve_names
            .then(|| LanResolver::start(names.clone()));
        Ok(Self {
            accounting,
            paths,
            trace: Some(trace),
            session,
            resolve_names: options.resolve_names,
            last_check: Instant::now(),
            restarts: 0,
            previous: HashMap::new(),
            last_sample: None,
            processes: HashMap::new(),
            names,
            lan,
        })
    }

    /// Restarts the trace session if something stopped it (another tool, `logman stop`,
    /// the system under memory pressure). Counters carry on; only the gap is lost.
    fn watchdog(&mut self) {
        if self.last_check.elapsed() < WATCHDOG {
            return;
        }
        self.last_check = Instant::now();
        stop_orphaned_sessions();
        if system::trace_session_exists(&self.session) {
            return;
        }
        // Drop the dead session first: its handle may be reused by the new one.
        drop(self.trace.take());
        let _ = stop_trace_by_name(&self.session);
        if let Ok(trace) = start_trace(
            &self.session,
            self.resolve_names,
            &self.accounting,
            &self.paths,
            &self.names,
        ) {
            self.trace = Some(trace);
            self.restarts += 1;
        }
    }

    fn describe(&mut self, pid: u32) -> Process {
        let captured = self
            .paths
            .lock()
            .ok()
            .and_then(|p| p.get(&pid).cloned())
            .flatten();
        let (name, path, app) = self
            .processes
            .entry(pid)
            .or_insert_with(|| {
                let path = captured.or_else(|| system::process_path(pid));
                let name = match (pid, &path) {
                    (0, _) => "Idle".to_string(),
                    (4, _) => "System".to_string(),
                    (_, Some(p)) => file_name(p),
                    (_, None) => format!("pid {pid}"),
                };
                let app = path.as_deref().and_then(app_for);
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

/// The client process a session name belongs to (`spectraNET-1234-0` → 1234; the older
/// `spectraNET-1234` form too).
fn session_owner(name: &str) -> Option<u32> {
    let rest = name.strip_prefix(SERVICE_SESSION)?.strip_prefix('-')?;
    rest.split('-').next()?.parse().ok()
}

/// Stops client sessions whose process is gone. A process killed before it could stop its
/// session leaves it running without a consumer, and such a session starves every other
/// session of Kernel-Network events, the service's included.
fn stop_orphaned_sessions() {
    for name in system::trace_sessions() {
        if let Some(pid) = session_owner(&name)
            && pid != std::process::id()
            && !system::process_alive(pid)
        {
            let _ = stop_trace_by_name(&name);
        }
    }
}

/// Starts a trace session feeding `accounting`, `paths` and (optionally) `names`.
fn start_trace(
    session: &str,
    resolve_names: bool,
    accounting: &Arc<Mutex<Accounting>>,
    paths: &PathCache,
    names: &Arc<Mutex<NameTable>>,
) -> Result<UserTrace, CaptureError> {
    let network = {
        let accounting = accounting.clone();
        let paths = paths.clone();
        Provider::by_guid(KERNEL_NETWORK)
            .any(IPV4_IPV6)
            .add_callback(move |record: &EventRecord, locator: &SchemaLocator| {
                let Some(event) = network_event(record, locator) else {
                    return;
                };
                if let Ok(mut paths) = paths.lock()
                    && !paths.contains_key(&event.pid)
                {
                    paths.insert(event.pid, system::process_path(event.pid));
                }
                if let Ok(mut acc) = accounting.lock() {
                    acc.apply(&event, Instant::now());
                }
            })
            .build()
    };
    let mut builder = UserTrace::new().named(session.to_string()).enable(network);
    if resolve_names {
        let names = names.clone();
        let dns = Provider::by_guid(DNS_CLIENT)
            .add_callback(move |record: &EventRecord, locator: &SchemaLocator| {
                if let Some(resolution) = dns_event(record, locator)
                    && let Ok(mut table) = names.lock()
                {
                    table.learn_dns(resolution);
                }
            })
            .build();
        builder = builder.enable(dns);
    }
    builder.start_and_process().map_err(|e| {
        let text = format!("{e:?}");
        if text.contains("AccessDenied")
            || text.contains("0x80070005")
            || text.contains("(5)")
            || text.contains("ACCESS_DENIED")
        {
            CaptureError::PermissionDenied(
                "ETW tracing needs an Administrator command prompt".into(),
            )
        } else {
            CaptureError::Backend(format!("starting the ETW session: {text}"))
        }
    })
}

fn file_name(path: &str) -> String {
    path.rsplit(['\\', '/']).next().unwrap_or(path).to_string()
}

/// Installed applications (under Program Files or the user's AppData) are identified by their
/// executable: Chrome's many chrome.exe processes form one application. System executables
/// (svchost.exe hosts unrelated services) stay separate.
pub(crate) fn app_for(path: &str) -> Option<App> {
    let lower = path.to_ascii_lowercase();
    let installed = lower.contains("\\program files") || lower.contains("\\appdata\\");
    if !installed {
        return None;
    }
    let file = file_name(path);
    let stem = file
        .strip_suffix(".exe")
        .or_else(|| file.strip_suffix(".EXE"))
        .unwrap_or(&file);
    Some(App {
        name: stem.to_string(),
        path: path.to_string(),
        main: false,
    })
}

impl TrafficSource for WindowsSource {
    fn name(&self) -> &'static str {
        "windows"
    }

    fn notices(&self) -> Vec<String> {
        let mut notices = Vec::new();
        if self.trace.is_none() {
            notices.push("the ETW trace session stopped and could not be restarted".into());
        } else if self.restarts > 0 {
            notices.push(format!(
                "the ETW trace session was stopped by another program and restarted ({} time{})",
                self.restarts,
                if self.restarts == 1 { "" } else { "s" }
            ));
        }
        notices
    }

    fn sample(&mut self) -> Result<Snapshot, CaptureError> {
        self.watchdog();
        let now = Instant::now();
        let flows = self
            .accounting
            .lock()
            .map_err(|_| CaptureError::Backend("accounting lock poisoned".into()))?
            .take(now);
        let first = self.last_sample.is_none();
        let elapsed = self.last_sample.map_or(Duration::ZERO, |t| now - t);
        self.last_sample = Some(now);

        let names = self
            .names
            .lock()
            .map_err(|_| CaptureError::Backend("hostname table lock poisoned".into()))?;
        let mut previous = HashMap::with_capacity(flows.len());
        let mut by_pid: BTreeMap<u32, Vec<Flow>> = BTreeMap::new();
        let mut seen = HashSet::new();
        for (key, c) in flows {
            let id = (key, c.generation);
            let baseline = self.previous.get(&id).copied().unwrap_or(if first {
                (c.rx, c.tx, c.rx_msgs, c.tx_msgs)
            } else {
                (0, 0, 0, 0)
            });
            if !c.closed {
                previous.insert(id, (c.rx, c.tx, c.rx_msgs, c.tx_msgs));
            }
            seen.insert((key.local, key.remote));
            let remote_host = names.lookup(key.local, key.remote).map(str::to_owned);
            if remote_host.is_none()
                && let Some(lan) = &self.lan
            {
                lan.request(key.remote.ip());
            }
            by_pid.entry(key.pid).or_default().push(Flow {
                transport: key.transport,
                local: key.local,
                remote: key.remote,
                remote_host,
                rx_rate: per_second(c.rx.saturating_sub(baseline.0), elapsed),
                tx_rate: per_second(c.tx.saturating_sub(baseline.1), elapsed),
                rx_bytes: c.rx,
                tx_bytes: c.tx,
                verdict: Verdict::Ok,
                note: None,
                meta: spectranet_model::flowmeta::FlowMeta {
                    rx_pps: (!first)
                        .then(|| per_second(c.rx_msgs.saturating_sub(baseline.2), elapsed) as u32),
                    tx_pps: (!first)
                        .then(|| per_second(c.tx_msgs.saturating_sub(baseline.3), elapsed) as u32),
                    ..Default::default()
                },
            });
        }
        // Idle TCP connections, which produce no events, from the system's TCP table.
        for conn in system::tcp_connections() {
            // TIME_WAIT connections (state 11) are reported as owned by PID 0: no process holds
            // them any more.
            if conn.pid == 0
                || conn.state == 11
                || seen.contains(&(conn.local, conn.remote))
                || conn.remote.ip().is_unspecified()
            {
                continue;
            }
            by_pid.entry(conn.pid).or_default().push(Flow {
                transport: Transport::Tcp,
                local: conn.local,
                remote: conn.remote,
                remote_host: names.lookup(conn.local, conn.remote).map(str::to_owned),
                rx_rate: 0,
                tx_rate: 0,
                rx_bytes: 0,
                tx_bytes: 0,
                verdict: Verdict::Ok,
                note: None,
                meta: Default::default(),
            });
        }
        drop(names);
        self.previous = previous;
        self.processes.retain(|pid, _| by_pid.contains_key(pid));
        if let Ok(mut paths) = self.paths.lock() {
            paths.retain(|pid, _| by_pid.contains_key(pid));
        }

        let processes = by_pid
            .into_iter()
            .map(|(pid, flows)| ProcessTraffic::new(self.describe(pid), flows))
            .collect();
        Ok(Snapshot {
            source: self.name().to_string(),
            timestamp_ms: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map_or(0, |d| d.as_millis() as u64),
            interval_ms: elapsed.as_millis() as u64,
            processes,
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

/// A TCP connection from the system table.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TcpConn {
    pub local: SocketAddr,
    pub remote: SocketAddr,
    pub state: u32,
    pub pid: u32,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn session_names_identify_their_owner() {
        assert_eq!(session_owner("spectraNET-1234"), Some(1234));
        assert_eq!(session_owner("spectraNET-1234-7"), Some(1234));
        assert_eq!(
            session_owner("spectraNET"),
            None,
            "the service's session has no owner"
        );
        assert_eq!(session_owner("spectraNET-x"), None);
        assert_eq!(session_owner("Other-12"), None);
    }

    #[test]
    fn lists_running_sessions_and_live_processes() {
        // EventLog sessions always run, but listing them may need rights: just no panic.
        let _ = system::trace_sessions();
        assert!(system::process_alive(std::process::id()));
        assert!(!system::process_alive(0xFFFF_FFF0));
    }

    /// Live: a session orphaned by a dead process is cleaned up by the next client.
    #[test]
    fn orphaned_client_sessions_are_stopped() {
        let _live = live();
        if !admin() {
            eprintln!("not an Administrator: skipping live ETW test");
            return;
        }
        // Simulate a crashed client: a session named after a PID that does not exist.
        let fake = format!("{SERVICE_SESSION}-{}", 0xFFFF_FFF0u32);
        let orphan = UserTrace::new()
            .named(fake.clone())
            .enable(Provider::by_guid(KERNEL_NETWORK).any(IPV4_IPV6).build())
            .start()
            .unwrap();
        std::mem::forget(orphan); // as if the process had died
        assert!(system::trace_sessions().contains(&fake));
        stop_orphaned_sessions();
        assert!(!system::trace_session_exists(&fake), "orphan stopped");
    }

    #[test]
    fn apps_for_installed_programs_only() {
        let chrome = app_for(r"C:\Program Files\Google\Chrome\Application\chrome.exe").unwrap();
        assert_eq!(chrome.name, "chrome");
        assert!(app_for(r"C:\Users\me\AppData\Local\Discord\app-1.0\Discord.exe").is_some());
        assert_eq!(app_for(r"C:\Windows\System32\svchost.exe"), None);
        assert_eq!(file_name(r"C:\Windows\System32\svchost.exe"), "svchost.exe");
    }

    /// Live ETW tests run one at a time: one of them deliberately leaves an orphaned
    /// session behind for a moment, which would starve the others.
    static LIVE: std::sync::Mutex<()> = std::sync::Mutex::new(());

    fn live() -> std::sync::MutexGuard<'static, ()> {
        LIVE.lock().unwrap_or_else(|e| e.into_inner())
    }

    fn admin() -> bool {
        WindowsSource::open(SourceOptions {
            resolve_names: false,
            service: false,
        })
        .is_ok()
    }

    /// Live: known TCP and UDP traffic over loopback is attributed to this process.
    #[test]
    fn live_counters_attribute_traffic_to_this_process() {
        let _live = live();
        use std::io::{Read, Write};
        use std::net::{TcpListener, TcpStream, UdpSocket};
        if !admin() {
            eprintln!("not an Administrator: skipping live ETW test");
            return;
        }
        let mut source = WindowsSource::open(SourceOptions {
            resolve_names: false,
            service: false,
        })
        .unwrap();
        std::thread::sleep(Duration::from_millis(500)); // let the session start delivering
        source.sample().unwrap();

        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let mut client = TcpStream::connect(addr).unwrap();
        let (mut server, _) = listener.accept().unwrap();
        client.write_all(&[1u8; 300_000]).unwrap();
        let mut sink = vec![0u8; 300_000];
        server.read_exact(&mut sink).unwrap();
        let a = UdpSocket::bind("127.0.0.1:0").unwrap();
        let b = UdpSocket::bind("127.0.0.1:0").unwrap();
        for _ in 0..10 {
            a.send_to(&[2u8; 1000], b.local_addr().unwrap()).unwrap();
            let mut buf = [0u8; 1500];
            b.recv_from(&mut buf).unwrap();
        }
        std::thread::sleep(Duration::from_millis(1500)); // ETW delivers with a little latency
        let snapshot = source.sample().unwrap();
        let me: Vec<_> = snapshot
            .processes
            .iter()
            .filter(|p| p.process.pid == std::process::id())
            .flat_map(|p| &p.flows)
            .collect();
        let tcp = me
            .iter()
            .find(|f| f.transport == Transport::Tcp && f.remote == addr)
            .expect("TCP client flow");
        assert_eq!(tcp.tx_bytes, 300_000, "{tcp:?}");
        let udp = me
            .iter()
            .find(|f| f.transport == Transport::Udp && f.local == a.local_addr().unwrap())
            .expect("UDP flow");
        assert_eq!(udp.tx_bytes, 10_000, "{udp:?}");
    }

    /// Live: a client never stops someone else's session, and a stopped session comes back.
    #[test]
    fn sessions_are_private_and_restarted_when_stopped() {
        let _live = live();
        if !admin() {
            eprintln!("not an Administrator: skipping live ETW test");
            return;
        }
        let mut source = WindowsSource::open(SourceOptions {
            resolve_names: false,
            service: false,
        })
        .unwrap();
        assert_ne!(source.session, SERVICE_SESSION);
        assert!(system::trace_session_exists(&source.session));
        assert!(!system::trace_session_exists("spectraNET-no-such-session"));
        stop_trace_by_name(&source.session).unwrap();
        assert!(!system::trace_session_exists(&source.session));
        source.last_check = Instant::now() - WATCHDOG;
        source.sample().unwrap();
        assert!(system::trace_session_exists(&source.session), "restarted");
        assert_eq!(source.restarts, 1);
        assert_eq!(source.notices().len(), 1);
    }

    #[test]
    fn tcp_table_lists_our_connection() {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let client = std::net::TcpStream::connect(addr).unwrap();
        let conns = system::tcp_connections();
        let mine = conns
            .iter()
            .find(|c| c.local == client.local_addr().unwrap())
            .expect("listed");
        assert_eq!((mine.remote, mine.pid), (addr, std::process::id()));
        assert!(
            system::process_path(std::process::id())
                .unwrap()
                .to_ascii_lowercase()
                .ends_with(".exe")
        );
    }
}
