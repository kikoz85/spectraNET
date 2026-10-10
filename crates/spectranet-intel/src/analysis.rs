//! Analysis of a Flight Recorder session: where an application talked, how much, how often,
//! and what looks suspicious.

use std::collections::{BTreeMap, HashMap, HashSet};
use std::io::BufRead;
use std::net::SocketAddr;

use serde::{Deserialize, Serialize};
use spectranet_model::record::{FORMAT, Header, RecordLine};
use spectranet_model::{Snapshot, Transport, Verdict, group_by_app};

use crate::Intel;

/// Fewer contacts than this are never called periodic.
const BEACON_MIN_EVENTS: usize = 4;
/// Contacts closer together than this are ordinary chatter, not beacons.
const BEACON_MIN_PERIOD_MS: f64 = 2_000.0;
/// Maximum coefficient of variation of the intervals for a pattern to count as regular.
const BEACON_MAX_CV: f64 = 0.2;
/// Uploading more than this, and more than twice what was downloaded, is reported.
const UPLOAD_THRESHOLD: u64 = 1024 * 1024;

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Report {
    pub header: Option<Header>,
    pub started_ms: u64,
    pub ended_ms: u64,
    pub samples: u64,
    /// The recording has no footer (it was interrupted).
    pub truncated: bool,
    /// Lines that could not be read.
    pub corrupt_lines: usize,
    pub rx: u64,
    pub tx: u64,
    pub apps: Vec<AppSummary>,
    pub destinations: Vec<Destination>,
    pub findings: Vec<ReportFinding>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AppSummary {
    pub name: String,
    pub pids: Vec<u32>,
    pub rx: u64,
    pub tx: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Destination {
    /// Hostname if it was ever known during the recording, otherwise the address.
    pub label: String,
    pub address: SocketAddr,
    pub transport: String,
    /// Distinct connections opened to it.
    pub connections: usize,
    pub rx: u64,
    pub tx: u64,
    pub first_ms: u64,
    pub last_ms: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReportFinding {
    pub verdict: Verdict,
    pub rule: String,
    /// The application concerned, when one is.
    pub app: Option<String>,
    pub destination: Option<String>,
    pub message: String,
}

#[derive(Default)]
struct DestState {
    host: Option<String>,
    transport: Option<Transport>,
    connections: HashSet<SocketAddr>,
    rx: u64,
    tx: u64,
    first_ms: u64,
    last_ms: u64,
    /// Times at which contact (re)started: a new connection, or traffic after a quiet sample.
    contacts: Vec<u64>,
    active_last_sample: bool,
    /// Applications that talked to this destination.
    apps: std::collections::BTreeSet<String>,
}

/// Reads a recording and analyses it. Unreadable lines are counted, not fatal; an I/O error
/// while reading is.
pub fn analyze<R: BufRead>(reader: R, intel: &Intel) -> std::io::Result<Report> {
    let mut header = None;
    let mut footer_seen = false;
    let mut corrupt = 0;
    let mut snapshots = Vec::new();
    for line in reader.lines() {
        let line = line?;
        if line.trim().is_empty() {
            continue;
        }
        match serde_json::from_str::<RecordLine>(&line) {
            Ok(RecordLine::Header(h)) if h.format == FORMAT => header = Some(h),
            Ok(RecordLine::Header(_)) => corrupt += 1,
            Ok(RecordLine::Sample { snapshot }) => snapshots.push(snapshot),
            Ok(RecordLine::Footer(_)) => footer_seen = true,
            Err(_) => corrupt += 1,
        }
    }
    Ok(analyze_snapshots(
        header,
        &snapshots,
        !footer_seen,
        corrupt,
        intel,
    ))
}

pub fn analyze_snapshots(
    header: Option<Header>,
    snapshots: &[Snapshot],
    truncated: bool,
    corrupt_lines: usize,
    intel: &Intel,
) -> Report {
    let mut dests: HashMap<(SocketAddr, Transport), DestState> = HashMap::new();
    let mut apps: BTreeMap<String, AppSummary> = BTreeMap::new();
    let mut findings: Vec<ReportFinding> = Vec::new();
    // The same observation can arrive twice: flagged live by the service while recording, and
    // found again by the rules here. One finding per application, destination and message.
    let mut reported: HashSet<(Option<String>, Option<String>, String)> = HashSet::new();
    let mut add_finding = |f: ReportFinding| {
        if reported.insert((f.app.clone(), f.destination.clone(), f.message.clone())) {
            findings.push(f);
        }
    };
    let (mut rx_total, mut tx_total) = (0u64, 0u64);

    for (index, snapshot) in snapshots.iter().enumerate() {
        let t = snapshot.timestamp_ms;
        let interval = snapshot.interval_ms;
        let mut active_now: HashSet<(SocketAddr, Transport)> = HashSet::new();
        for app in group_by_app(snapshot.processes.clone()) {
            let summary = apps.entry(app.name.clone()).or_insert_with(|| AppSummary {
                name: app.name.clone(),
                pids: Vec::new(),
                rx: 0,
                tx: 0,
            });
            for p in &app.processes {
                if !summary.pids.contains(&p.process.pid) {
                    summary.pids.push(p.process.pid);
                }
                for flow in &p.flows {
                    if flow.remote.ip().is_unspecified() {
                        continue;
                    }
                    let rx = bytes_in(flow.rx_rate, interval);
                    let tx = bytes_in(flow.tx_rate, interval);
                    summary.rx += rx;
                    summary.tx += tx;
                    rx_total += rx;
                    tx_total += tx;

                    let key = (flow.remote, flow.transport);
                    let dest = dests.entry(key).or_insert_with(|| DestState {
                        first_ms: t,
                        ..Default::default()
                    });
                    dest.transport = Some(flow.transport);
                    dest.apps.insert(app.name.clone());
                    if flow.remote_host.is_some() {
                        dest.host.clone_from(&flow.remote_host);
                    }
                    dest.last_ms = t;
                    dest.rx += rx;
                    dest.tx += tx;
                    // A connection already open when recording began was not "opened" then.
                    let opened = dest.connections.insert(flow.local) && index > 0;
                    let active = rx + tx > 0;
                    if opened || (active && !dest.active_last_sample) {
                        dest.contacts.push(t);
                    }
                    if active {
                        active_now.insert(key);
                    }

                    let label = flow.remote_host.clone().map_or_else(
                        || flow.remote.to_string(),
                        |h| format!("{h}:{}", flow.remote.port()),
                    );
                    if flow.verdict > Verdict::Ok {
                        add_finding(ReportFinding {
                            verdict: flow.verdict,
                            rule: "recorded".into(),
                            app: Some(app.name.clone()),
                            destination: Some(label.clone()),
                            message: flow
                                .note
                                .clone()
                                .unwrap_or_else(|| "flagged during recording".into()),
                        });
                    }
                    for (rule, verdict, message) in intel.assess(flow) {
                        add_finding(ReportFinding {
                            verdict,
                            rule,
                            app: Some(app.name.clone()),
                            destination: Some(label.clone()),
                            message,
                        });
                    }
                }
            }
        }
        for (key, dest) in &mut dests {
            dest.active_last_sample = active_now.contains(key);
        }
    }

    let mut destinations: Vec<Destination> = dests
        .iter()
        .map(|((address, transport), d)| Destination {
            label: d.host.clone().unwrap_or_else(|| address.ip().to_string()),
            address: *address,
            transport: transport_name(*transport).into(),
            connections: d.connections.len(),
            rx: d.rx,
            tx: d.tx,
            first_ms: d.first_ms,
            last_ms: d.last_ms,
        })
        .collect();
    destinations.sort_by(|a, b| {
        (b.rx + b.tx)
            .cmp(&(a.rx + a.tx))
            .then(a.label.cmp(&b.label))
    });

    for ((address, _), d) in &dests {
        if let Some((period, count, spread)) = periodicity(&d.contacts) {
            let label = d.host.clone().unwrap_or_else(|| address.ip().to_string());
            findings.push(ReportFinding {
                verdict: Verdict::Warn,
                rule: "beaconing".into(),
                app: Some(d.apps.iter().cloned().collect::<Vec<_>>().join(", ")).filter(|a| !a.is_empty()),
                destination: Some(format!("{label}:{}", address.port())),
                message: format!(
                    "contacted every {} ({count} times, ±{:.0}%): regular check-ins are typical of update checks and telemetry, and of malware calling home",
                    human_period(period),
                    spread * 100.0
                ),
            });
        }
    }
    for app in apps.values() {
        if app.tx > UPLOAD_THRESHOLD && app.tx > app.rx.saturating_mul(2) {
            findings.push(ReportFinding {
                verdict: Verdict::Warn,
                rule: "upload-heavy".into(),
                app: Some(app.name.clone()),
                destination: None,
                message: format!(
                    "sent {} but received only {}: it mostly uploads",
                    fmt_bytes(app.tx),
                    fmt_bytes(app.rx)
                ),
            });
        }
    }
    findings.sort_by(|a, b| {
        b.verdict
            .cmp(&a.verdict)
            .then(a.rule.cmp(&b.rule))
            .then(a.destination.cmp(&b.destination))
    });

    let started_ms = header
        .as_ref()
        .map(|h| h.started_ms)
        .or_else(|| snapshots.first().map(|s| s.timestamp_ms))
        .unwrap_or(0);
    let ended_ms = snapshots
        .last()
        .map_or(started_ms, |s| s.timestamp_ms)
        .max(started_ms);
    let mut apps: Vec<AppSummary> = apps.into_values().collect();
    apps.sort_by_key(|a| std::cmp::Reverse(a.rx + a.tx));
    Report {
        header,
        started_ms,
        ended_ms,
        samples: snapshots.len() as u64,
        truncated,
        corrupt_lines,
        rx: rx_total,
        tx: tx_total,
        apps,
        destinations,
        findings,
    }
}

/// `(mean period ms, number of contacts, coefficient of variation)` when contacts are regular.
pub fn periodicity(times: &[u64]) -> Option<(f64, usize, f64)> {
    if times.len() < BEACON_MIN_EVENTS {
        return None;
    }
    let gaps: Vec<f64> = times
        .windows(2)
        .map(|w| w[1].saturating_sub(w[0]) as f64)
        .collect();
    let mean = gaps.iter().sum::<f64>() / gaps.len() as f64;
    if mean < BEACON_MIN_PERIOD_MS {
        return None;
    }
    let variance = gaps.iter().map(|g| (g - mean).powi(2)).sum::<f64>() / gaps.len() as f64;
    let cv = variance.sqrt() / mean;
    (cv <= BEACON_MAX_CV).then_some((mean, times.len(), cv))
}

fn bytes_in(rate: u64, interval_ms: u64) -> u64 {
    u64::try_from(u128::from(rate) * u128::from(interval_ms) / 1000).unwrap_or(u64::MAX)
}

fn transport_name(t: Transport) -> &'static str {
    match t {
        Transport::Tcp => "tcp",
        Transport::Udp => "udp",
    }
}

fn human_period(ms: f64) -> String {
    let s = ms / 1000.0;
    if s < 90.0 {
        format!("{s:.0} s")
    } else if s < 5400.0 {
        format!("{:.1} min", s / 60.0)
    } else {
        format!("{:.1} h", s / 3600.0)
    }
}

fn fmt_bytes(n: u64) -> String {
    const UNITS: [&str; 5] = ["B", "KiB", "MiB", "GiB", "TiB"];
    let mut v = n as f64;
    let mut u = 0;
    while v >= 1024.0 && u < UNITS.len() - 1 {
        v /= 1024.0;
        u += 1;
    }
    if u == 0 {
        format!("{n} B")
    } else {
        format!("{v:.1} {}", UNITS[u])
    }
}

#[cfg(test)]
mod tests {
    use spectranet_model::{Flow, Process, ProcessTraffic};

    use super::*;

    const T0: u64 = 1_760_000_000_000;

    fn flow(local_port: u16, remote: &str, host: Option<&str>, rx_rate: u64, tx_rate: u64) -> Flow {
        Flow {
            meta: Default::default(),
            transport: Transport::Tcp,
            local: SocketAddr::new("192.168.1.36".parse().unwrap(), local_port),
            remote: remote.parse().unwrap(),
            remote_host: host.map(str::to_string),
            rx_rate,
            tx_rate,
            rx_bytes: rx_rate,
            tx_bytes: tx_rate,
            verdict: Verdict::Ok,
            note: None,
        }
    }

    fn sample(t_s: u64, flows: Vec<Flow>) -> Snapshot {
        let process = Process {
            pid: 42,
            name: "agent".into(),
            path: Some("/opt/agent".into()),
            app: None,
        };
        Snapshot {
            source: "test".into(),
            timestamp_ms: T0 + t_s * 1000,
            interval_ms: 1000,
            processes: vec![ProcessTraffic::new(process, flows)],
            link: None,
        }
    }

    #[test]
    fn regular_new_connections_are_beacons() {
        // A fresh connection to the same server every 30 s, 6 times, each lasting one sample.
        let mut samples = Vec::new();
        for i in 0..180u64 {
            let flows = if i % 30 == 0 {
                vec![flow(
                    50_000 + i as u16,
                    "203.0.113.9:443",
                    Some("c2.example.net"),
                    200,
                    300,
                )]
            } else {
                vec![]
            };
            samples.push(sample(i, flows));
        }
        let report = analyze_snapshots(None, &samples, false, 0, &Intel::default());
        let beacon = report
            .findings
            .iter()
            .find(|f| f.rule == "beaconing")
            .expect("beacon found");
        assert_eq!(beacon.destination.as_deref(), Some("c2.example.net:443"));
        assert_eq!(beacon.app.as_deref(), Some("agent"));
        assert!(
            beacon.message.starts_with("contacted every 30 s (6 times"),
            "{}",
            beacon.message
        );
        let dest = &report.destinations[0];
        assert_eq!(
            (dest.label.as_str(), dest.connections, dest.rx, dest.tx),
            ("c2.example.net", 6, 1200, 1800)
        );
    }

    #[test]
    fn bursts_on_a_long_lived_connection_are_beacons_too() {
        let samples: Vec<_> = (0..100u64)
            .map(|i| {
                sample(
                    i,
                    vec![flow(
                        50_000,
                        "198.51.100.7:8443",
                        None,
                        0,
                        if i % 20 == 5 { 64 } else { 0 },
                    )],
                )
            })
            .collect();
        let report = analyze_snapshots(None, &samples, false, 0, &Intel::default());
        let beacon = report
            .findings
            .iter()
            .find(|f| f.rule == "beaconing")
            .expect("beacon found");
        assert!(beacon.message.contains("every 20 s"), "{}", beacon.message);
        assert_eq!(report.destinations[0].connections, 1);
    }

    #[test]
    fn irregular_or_rapid_traffic_is_not_a_beacon() {
        let gaps = [3u64, 17, 4, 40, 9, 25, 2, 31];
        let mut t = 0;
        let mut samples = Vec::new();
        for (n, gap) in gaps.iter().enumerate() {
            t += gap;
            samples.push(sample(
                t,
                vec![flow(40_000 + n as u16, "203.0.113.9:443", None, 10, 10)],
            ));
            samples.push(sample(t + 1, vec![]));
        }
        assert!(
            analyze_snapshots(None, &samples, false, 0, &Intel::default())
                .findings
                .iter()
                .all(|f| f.rule != "beaconing")
        );

        // Every second: chatty but not a "check-in" pattern.
        let rapid: Vec<_> = (0..60u64)
            .map(|i| {
                sample(
                    i,
                    vec![flow(41_000 + i as u16, "203.0.113.9:443", None, 1, 1)],
                )
            })
            .collect();
        assert!(
            analyze_snapshots(None, &rapid, false, 0, &Intel::default())
                .findings
                .iter()
                .all(|f| f.rule != "beaconing")
        );
    }

    #[test]
    fn upload_heavy_and_cleartext_are_reported() {
        let samples: Vec<_> = (0..10u64)
            .map(|i| {
                sample(
                    i,
                    vec![flow(50_000, "93.184.216.34:80", None, 1_000, 500_000)],
                )
            })
            .collect();
        let report = analyze_snapshots(None, &samples, false, 0, &Intel::default());
        let rules: Vec<_> = report.findings.iter().map(|f| f.rule.as_str()).collect();
        assert!(rules.contains(&"upload-heavy"), "{rules:?}");
        assert!(rules.contains(&"cleartext:http"));
        assert_eq!(
            report
                .findings
                .iter()
                .filter(|f| f.rule == "cleartext:http")
                .count(),
            1,
            "deduplicated"
        );
        assert_eq!(report.tx, 5_000_000);
        assert_eq!(report.apps[0].name, "agent");
    }

    #[test]
    fn a_live_verdict_and_the_same_rule_are_reported_once() {
        let mut f = flow(50_000, "93.184.216.34:80", None, 10, 10);
        let intel = Intel::default();
        let (rule, verdict, message) = intel.assess(&f).remove(0);
        f.verdict = verdict;
        f.note = Some(message);
        let report = analyze_snapshots(None, &[sample(0, vec![f])], false, 0, &intel);
        assert_eq!(report.findings.len(), 1, "{:?}", report.findings);
        assert!(report.findings[0].rule == "recorded" || report.findings[0].rule == rule);
    }

    #[test]
    fn verdicts_recorded_live_are_kept() {
        let mut f = flow(50_000, "185.220.101.5:443", None, 10, 10);
        f.verdict = Verdict::Alert;
        f.note = Some("known botnet command-and-control server".into());
        let report = analyze_snapshots(None, &[sample(0, vec![f])], false, 0, &Intel::default());
        assert_eq!(report.findings[0].verdict, Verdict::Alert);
        assert!(report.findings[0].message.contains("botnet"));
    }

    #[test]
    fn reads_files_with_damage() {
        let header = RecordLine::Header(Header::new(
            T0,
            "mac".into(),
            1000,
            "macos".into(),
            vec!["agent".into()],
            vec![],
        ));
        let mut text = serde_json::to_string(&header).unwrap() + "\n";
        for i in 0..5 {
            text += &serde_json::to_string(&RecordLine::Sample {
                snapshot: sample(i, vec![flow(50_000, "203.0.113.9:443", None, 100, 0)]),
            })
            .unwrap();
            text += "\n";
        }
        text += "{\"type\":\"sample\",\"snapshot\":{\"broken\n\nnot json at all\n";
        let report = analyze(std::io::Cursor::new(text), &Intel::default()).unwrap();
        assert_eq!(report.samples, 5);
        assert_eq!(report.corrupt_lines, 2);
        assert!(report.truncated, "no footer");
        assert_eq!(report.header.unwrap().names, ["agent"]);
        assert_eq!(report.rx, 500);
        assert_eq!(report.ended_ms - report.started_ms, 4000);
    }

    #[test]
    fn empty_recording() {
        let report = analyze(std::io::Cursor::new(""), &Intel::default()).unwrap();
        assert_eq!(report.samples, 0);
        assert!(report.findings.is_empty() && report.destinations.is_empty());
    }

    #[test]
    fn periodicity_math() {
        assert_eq!(periodicity(&[0, 10_000, 20_000]), None, "too few");
        let (period, n, cv) = periodicity(&[0, 10_000, 20_000, 30_000, 40_000]).unwrap();
        assert_eq!((period, n), (10_000.0, 5));
        assert!(cv < 1e-9);
        assert!(
            periodicity(&[0, 10_000, 11_000, 30_000, 31_000]).is_none(),
            "irregular"
        );
        assert!(
            periodicity(&[0, 1_000, 2_000, 3_000, 4_000]).is_none(),
            "too rapid"
        );
        assert!(periodicity(&[5, 5, 5, 5]).is_none(), "zero period");
    }
}
