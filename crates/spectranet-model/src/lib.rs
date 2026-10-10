//! Core data types shared by every spectraNET component (capture backends, CLI, daemon, GUI).
//!
//! A [`Snapshot`] is the unit of exchange: the per-process traffic observed during one
//! sampling interval, plus running totals since the source started.

pub mod flowmeta;
pub mod record;

use std::net::SocketAddr;

use serde::{Deserialize, Serialize};

/// Transport protocol of a flow.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Transport {
    Tcp,
    Udp,
}

/// Security assessment of a flow or process. Ordered by severity, so `max()` yields the worst.
#[derive(
    Debug, Clone, Copy, Default, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize,
)]
#[serde(rename_all = "lowercase")]
pub enum Verdict {
    #[default]
    Ok,
    Warn,
    Alert,
}

/// What a process costs the system, sampled alongside its traffic.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Resources {
    /// Parent process, if still known.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ppid: Option<u32>,
    /// CPU use in tenths of a percent of one core (1000 = one core fully busy; several
    /// busy cores add up, as in `top`).
    pub cpu_tenths: u32,
    /// Resident memory, bytes.
    pub memory: u64,
    /// Account the process runs as.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub user: Option<String>,
}

impl Resources {
    /// CPU use as a percentage of one core.
    pub fn cpu_percent(&self) -> f32 {
        self.cpu_tenths as f32 / 10.0
    }
}

/// An operating-system process that owns network sockets.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Process {
    pub pid: u32,
    pub name: String,
    /// Full path of the executable, when the platform exposes it.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub path: Option<String>,
    /// The user-facing application this process belongs to, when it is part of one
    /// (e.g. a browser's helper processes all belong to the browser).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub app: Option<App>,
}

/// A user-facing application, possibly made of several processes.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct App {
    /// Display name, e.g. `Google Chrome`.
    pub name: String,
    /// Location identifying the application, e.g. its bundle `/Applications/Google Chrome.app`.
    /// Processes with the same `path` belong to the same application.
    pub path: String,
    /// Whether this process is the application's main executable (rather than a helper).
    #[serde(default)]
    pub main: bool,
}

/// One connection (or UDP association) between a local and a remote endpoint.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Flow {
    pub transport: Transport,
    pub local: SocketAddr,
    pub remote: SocketAddr,
    /// Hostname the remote address was resolved from (DNS answer or TLS SNI), if known.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub remote_host: Option<String>,
    /// Bytes per second received during the last interval.
    pub rx_rate: u64,
    /// Bytes per second sent during the last interval.
    pub tx_rate: u64,
    /// Bytes received over the connection's lifetime.
    pub rx_bytes: u64,
    /// Bytes sent over the connection's lifetime.
    pub tx_bytes: u64,
    pub verdict: Verdict,
    /// Human-readable reason for a non-`Ok` verdict.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub note: Option<String>,
    /// Packet rates, handshake details and what kind of traffic it is, when known.
    #[serde(default, skip_serializing_if = "flowmeta::FlowMeta::is_empty")]
    pub meta: flowmeta::FlowMeta,
}

impl Flow {
    /// Ordering key for "busiest first": current rate, then lifetime volume.
    pub fn activity(&self) -> (u64, u64) {
        (self.rx_rate + self.tx_rate, self.rx_bytes + self.tx_bytes)
    }

    /// Remote hostname if known, otherwise the remote IP address.
    pub fn remote_label(&self) -> String {
        match &self.remote_host {
            Some(host) => host.clone(),
            None => self.remote.ip().to_string(),
        }
    }
}

/// All traffic attributed to one process, with aggregates precomputed from its flows.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ProcessTraffic {
    pub process: Process,
    /// CPU, memory and parentage during the interval, when the source measured them.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub resources: Option<Resources>,
    pub rx_rate: u64,
    pub tx_rate: u64,
    pub rx_bytes: u64,
    pub tx_bytes: u64,
    pub verdict: Verdict,
    pub flows: Vec<Flow>,
}

impl ProcessTraffic {
    pub fn new(process: Process, flows: Vec<Flow>) -> Self {
        Self {
            process,
            resources: None,
            rx_rate: flows.iter().map(|f| f.rx_rate).sum(),
            tx_rate: flows.iter().map(|f| f.tx_rate).sum(),
            rx_bytes: flows.iter().map(|f| f.rx_bytes).sum(),
            tx_bytes: flows.iter().map(|f| f.tx_bytes).sum(),
            verdict: flows.iter().map(|f| f.verdict).max().unwrap_or_default(),
            flows,
        }
    }

    /// Combined download + upload rate in bytes per second.
    pub fn total_rate(&self) -> u64 {
        self.rx_rate + self.tx_rate
    }

    /// The flow currently moving the most data, used as the process's headline destination.
    pub fn busiest_flow(&self) -> Option<&Flow> {
        self.flows.iter().max_by_key(|f| f.activity())
    }
}

/// Traffic of one application: either a group of processes sharing an [`App`], or a single
/// standalone process.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct AppTraffic {
    pub name: String,
    /// The application's location, or the executable path of a standalone process.
    pub path: Option<String>,
    /// Representative process ID: the main executable if present, otherwise the lowest PID.
    pub pid: u32,
    pub rx_rate: u64,
    pub tx_rate: u64,
    pub rx_bytes: u64,
    pub tx_bytes: u64,
    pub verdict: Verdict,
    /// CPU of all member processes, tenths of a percent of one core (0 if not measured).
    #[serde(default)]
    pub cpu_tenths: u32,
    /// Resident memory of all member processes, bytes (0 if not measured).
    #[serde(default)]
    pub memory: u64,
    /// Member processes, in ascending PID order.
    pub processes: Vec<ProcessTraffic>,
}

impl AppTraffic {
    /// Builds the aggregate for a non-empty set of processes.
    ///
    /// # Panics
    /// If `processes` is empty.
    pub fn new(mut processes: Vec<ProcessTraffic>) -> Self {
        assert!(
            !processes.is_empty(),
            "an application has at least one process"
        );
        processes.sort_by_key(|p| p.process.pid);
        let representative = processes
            .iter()
            .find(|p| p.process.app.as_ref().is_some_and(|a| a.main))
            .unwrap_or(&processes[0]);
        let (name, path) = match &representative.process.app {
            Some(app) => (app.name.clone(), Some(app.path.clone())),
            None => (
                representative.process.name.clone(),
                representative.process.path.clone(),
            ),
        };
        Self {
            name,
            path,
            pid: representative.process.pid,
            rx_rate: processes.iter().map(|p| p.rx_rate).sum(),
            tx_rate: processes.iter().map(|p| p.tx_rate).sum(),
            rx_bytes: processes.iter().map(|p| p.rx_bytes).sum(),
            tx_bytes: processes.iter().map(|p| p.tx_bytes).sum(),
            verdict: processes
                .iter()
                .map(|p| p.verdict)
                .max()
                .unwrap_or_default(),
            cpu_tenths: processes
                .iter()
                .filter_map(|p| p.resources.as_ref())
                .map(|r| r.cpu_tenths)
                .sum(),
            memory: processes
                .iter()
                .filter_map(|p| p.resources.as_ref())
                .map(|r| r.memory)
                .sum(),
            processes,
        }
    }

    /// Combined download + upload rate in bytes per second.
    pub fn total_rate(&self) -> u64 {
        self.rx_rate + self.tx_rate
    }

    pub fn flow_count(&self) -> usize {
        self.processes.iter().map(|p| p.flows.len()).sum()
    }

    /// The flow currently moving the most data across all member processes.
    pub fn busiest_flow(&self) -> Option<&Flow> {
        self.processes
            .iter()
            .flat_map(|p| &p.flows)
            .max_by_key(|f| f.activity())
    }

    pub fn contains_pid(&self, pid: u32) -> bool {
        self.processes.iter().any(|p| p.process.pid == pid)
    }
}

/// Groups processes by application. Processes without an [`App`] stay on their own.
/// Groups are returned in order of their first member's appearance in `processes`.
pub fn group_by_app(processes: Vec<ProcessTraffic>) -> Vec<AppTraffic> {
    let mut order: Vec<String> = Vec::new();
    let mut groups: std::collections::HashMap<String, Vec<ProcessTraffic>> =
        std::collections::HashMap::new();
    for p in processes {
        let key = match &p.process.app {
            Some(app) => format!("app:{}", app.path),
            None => format!("pid:{}", p.process.pid),
        };
        if !groups.contains_key(&key) {
            order.push(key.clone());
        }
        groups.entry(key).or_default().push(p);
    }
    order
        .into_iter()
        .filter_map(|key| groups.remove(&key))
        .map(AppTraffic::new)
        .collect()
}

/// Wraps each process as its own [`AppTraffic`], ignoring application membership.
pub fn one_per_process(processes: Vec<ProcessTraffic>) -> Vec<AppTraffic> {
    processes
        .into_iter()
        .map(|p| AppTraffic::new(vec![p]))
        .collect()
}

/// Per-process traffic observed over one sampling interval.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Snapshot {
    /// Name of the capture backend that produced this snapshot (e.g. `mock`, `macos`).
    pub source: String,
    /// Wall-clock time at the end of the interval, in milliseconds since the Unix epoch.
    pub timestamp_ms: u64,
    /// Length of the interval the rates were measured over.
    pub interval_ms: u64,
    pub processes: Vec<ProcessTraffic>,
    /// What the network interfaces themselves carried, to check how much of it the
    /// applications account for (absent from sources that can't read interface counters).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub link: Option<LinkTraffic>,
}

/// Traffic on the computer's network interfaces (loopback, tunnels and other virtual
/// interfaces left out), next to the part of it attributed to applications.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct LinkTraffic {
    /// Bytes per second received and sent by the interfaces, headers included.
    pub rx_rate: u64,
    pub tx_rate: u64,
    /// The part of it carried by applications' connections: their payload plus an estimate
    /// of the packet headers (the interfaces count those, sockets don't).
    pub attributed_rx: u64,
    pub attributed_tx: u64,
    /// The interfaces counted.
    pub interfaces: Vec<String>,
}

impl LinkTraffic {
    /// Below this (both directions, per second) there is too little traffic to judge.
    pub const MIN_RATE: u64 = 4_096;

    /// Share of the interfaces' traffic attributed to applications, 0–1; `None` when there is
    /// too little traffic to judge.
    pub fn coverage(&self) -> Option<f64> {
        coverage(
            self.rx_rate + self.tx_rate,
            self.attributed_rx + self.attributed_tx,
            Self::MIN_RATE,
        )
    }

    /// Traffic no application accounts for (other devices bridged or shared through this
    /// computer, the system's own protocols, header estimates that fall short).
    pub fn unattributed(&self) -> (u64, u64) {
        (
            self.rx_rate.saturating_sub(self.attributed_rx),
            self.tx_rate.saturating_sub(self.attributed_tx),
        )
    }
}

/// `attributed / total` capped at 1, or `None` when `total` is below `min`.
pub fn coverage(total: u64, attributed: u64, min: u64) -> Option<f64> {
    (total >= min.max(1)).then(|| (attributed as f64 / total as f64).min(1.0))
}

impl Snapshot {
    pub fn rx_rate(&self) -> u64 {
        self.processes.iter().map(|p| p.rx_rate).sum()
    }

    pub fn tx_rate(&self) -> u64 {
        self.processes.iter().map(|p| p.tx_rate).sum()
    }

    pub fn flow_count(&self) -> usize {
        self.processes.iter().map(|p| p.flows.len()).sum()
    }

    /// Number of processes whose verdict is at least `Warn`.
    pub fn flagged_count(&self) -> usize {
        self.processes
            .iter()
            .filter(|p| p.verdict >= Verdict::Warn)
            .count()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn flow(rx_rate: u64, tx_rate: u64, verdict: Verdict) -> Flow {
        Flow {
            meta: Default::default(),
            transport: Transport::Tcp,
            local: "192.168.1.10:50000".parse().unwrap(),
            remote: "1.1.1.1:443".parse().unwrap(),
            remote_host: None,
            rx_rate,
            tx_rate,
            rx_bytes: rx_rate * 10,
            tx_bytes: tx_rate * 10,
            verdict,
            note: None,
        }
    }

    fn traffic(pid: u32, name: &str, app: Option<(&str, &str, bool)>, rx: u64) -> ProcessTraffic {
        let process = Process {
            pid,
            name: name.into(),
            path: Some(format!("/bin/{name}")),
            app: app.map(|(name, path, main)| App {
                name: name.into(),
                path: path.into(),
                main,
            }),
        };
        ProcessTraffic::new(process, vec![flow(rx, 0, Verdict::Ok)])
    }

    #[test]
    fn groups_helpers_under_their_app() {
        let chrome = Some(("Google Chrome", "/Applications/Google Chrome.app", false));
        let chrome_main = Some(("Google Chrome", "/Applications/Google Chrome.app", true));
        let apps = group_by_app(vec![
            traffic(300, "Google Chrome Helper", chrome, 100),
            traffic(50, "curl", None, 7),
            traffic(200, "Google Chrome", chrome_main, 10),
            traffic(400, "Google Chrome Helper (GPU)", chrome, 1),
            traffic(60, "curl", None, 3),
        ]);
        assert_eq!(apps.len(), 3, "chrome + two separate curl processes");

        let chrome = &apps[0];
        assert_eq!(chrome.name, "Google Chrome");
        assert_eq!(chrome.pid, 200, "main executable is the representative");
        assert_eq!(chrome.rx_rate, 111);
        assert_eq!(chrome.flow_count(), 3);
        let pids: Vec<_> = chrome.processes.iter().map(|p| p.process.pid).collect();
        assert_eq!(pids, [200, 300, 400]);
        assert!(chrome.contains_pid(400) && !chrome.contains_pid(50));
        assert_eq!(chrome.busiest_flow().unwrap().rx_rate, 100);

        assert_eq!((apps[1].name.as_str(), apps[1].pid), ("curl", 50));
        assert_eq!((apps[2].name.as_str(), apps[2].pid), ("curl", 60));
        assert_eq!(apps[1].path.as_deref(), Some("/bin/curl"));
    }

    #[test]
    fn group_without_main_uses_lowest_pid() {
        let helper = Some(("Signal", "/Applications/Signal.app", false));
        let apps = group_by_app(vec![
            traffic(9, "Signal Helper", helper, 1),
            traffic(5, "Signal Helper", helper, 1),
        ]);
        assert_eq!(apps.len(), 1);
        assert_eq!(apps[0].pid, 5);
        assert_eq!(apps[0].name, "Signal");
    }

    #[test]
    fn one_per_process_never_merges() {
        let app = Some(("X", "/X.app", false));
        let apps = one_per_process(vec![traffic(1, "a", app, 1), traffic(2, "b", app, 1)]);
        assert_eq!(apps.len(), 2);
        assert_eq!(
            apps[0].name, "X",
            "a member of an app still shows the app name"
        );
    }

    #[test]
    fn grouping_preserves_totals() {
        let app = Some(("X", "/X.app", false));
        let processes: Vec<_> = (1..=20)
            .map(|i| {
                traffic(
                    i,
                    "p",
                    if i % 3 == 0 { app } else { None },
                    u64::from(i) * 7,
                )
            })
            .collect();
        let total: u64 = processes.iter().map(|p| p.rx_rate).sum();
        let apps = group_by_app(processes);
        assert_eq!(apps.iter().map(|a| a.rx_rate).sum::<u64>(), total);
        assert_eq!(apps.iter().map(|a| a.processes.len()).sum::<usize>(), 20);
    }

    #[test]
    fn process_aggregates_its_flows() {
        let process = Process {
            pid: 1,
            name: "app".into(),
            path: None,
            app: None,
        };
        let traffic = ProcessTraffic::new(
            process,
            vec![flow(100, 10, Verdict::Ok), flow(50, 5, Verdict::Warn)],
        );
        assert_eq!(traffic.rx_rate, 150);
        assert_eq!(traffic.tx_rate, 15);
        assert_eq!(traffic.rx_bytes, 1500);
        assert_eq!(traffic.verdict, Verdict::Warn);
        assert_eq!(traffic.busiest_flow().unwrap().rx_rate, 100);
    }

    #[test]
    fn process_without_flows_is_ok_and_idle() {
        let process = Process {
            pid: 1,
            name: "idle".into(),
            path: None,
            app: None,
        };
        let traffic = ProcessTraffic::new(process, vec![]);
        assert_eq!(traffic.total_rate(), 0);
        assert_eq!(traffic.verdict, Verdict::Ok);
        assert!(traffic.busiest_flow().is_none());
    }

    #[test]
    fn busiest_flow_breaks_rate_ties_by_volume() {
        let mut idle_big = flow(0, 0, Verdict::Ok);
        idle_big.rx_bytes = 5_000;
        let mut idle_small = flow(0, 0, Verdict::Ok);
        idle_small.rx_bytes = 10;
        let process = Process {
            pid: 1,
            name: "p".into(),
            path: None,
            app: None,
        };
        for order in [
            vec![idle_small.clone(), idle_big.clone()],
            vec![idle_big.clone(), idle_small.clone()],
        ] {
            let traffic = ProcessTraffic::new(process.clone(), order);
            assert_eq!(traffic.busiest_flow().unwrap().rx_bytes, 5_000);
            let app = AppTraffic::new(vec![traffic]);
            assert_eq!(app.busiest_flow().unwrap().rx_bytes, 5_000);
        }
        let active = flow(1, 0, Verdict::Ok);
        let traffic = ProcessTraffic::new(process, vec![idle_big, active]);
        assert_eq!(
            traffic.busiest_flow().unwrap().rx_rate,
            1,
            "any current traffic beats history"
        );
    }

    #[test]
    fn remote_label_prefers_hostname() {
        let mut f = flow(0, 0, Verdict::Ok);
        assert_eq!(f.remote_label(), "1.1.1.1");
        f.remote_host = Some("one.one.one.one".into());
        assert_eq!(f.remote_label(), "one.one.one.one");
    }
}
