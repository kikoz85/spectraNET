//! Using the snetd service: as a traffic source, and for `status` and `history`.

use std::collections::HashMap;
use std::fmt::Write as _;
use std::path::Path;
use std::time::Duration;

use anstyle::Style;
use spectranet_capture::{CaptureError, TrafficSource};
use spectranet_model::Snapshot;
use spectranet_proto::{AlertEvent, Client, ClientError, Command, Reply, Status, UsageRow};

use crate::units::{bytes, truncate};

const TIMEOUT: Duration = Duration::from_secs(5);
#[cfg(windows)]
const INSTALL_HINT: &str = "snetd install (from an Administrator prompt)";
#[cfg(not(windows))]
const INSTALL_HINT: &str = "sudo snetd install";
const HEADER: Style = Style::new().bold();
const DIM: Style = Style::new().dimmed();

/// Why a command that needs snetd cannot run; maps to exit status 69.
#[derive(Debug, thiserror::Error)]
#[error("{0}")]
pub struct Unavailable(pub String);

pub fn connect(socket: &Path) -> Result<Client, ClientError> {
    Client::connect(socket, TIMEOUT)
}

fn unavailable(socket: &Path, error: &ClientError) -> Unavailable {
    match error {
        ClientError::NotRunning => Unavailable(format!(
            "snetd is not running (no service on {}); install it with: {INSTALL_HINT}",
            socket.display()
        )),
        ClientError::PermissionDenied => Unavailable(format!(
            "snetd is running but {} is reserved to administrators",
            socket.display()
        )),
        ClientError::Io(e) => Unavailable(format!("cannot reach snetd: {e}")),
        ClientError::Unsupported => {
            Unavailable("snetd is not available on this platform yet".into())
        }
        other => Unavailable(other.to_string()),
    }
}

/// Snapshots served by snetd, which samples continuously.
pub struct DaemonSource {
    client: Client,
    notices: Vec<String>,
}

impl DaemonSource {
    pub fn new(mut client: Client) -> Result<Self, ClientError> {
        let notices = match client.call(Command::Status)? {
            Reply::Status(status) => status.notices,
            _ => Vec::new(),
        };
        Ok(Self { client, notices })
    }
}

impl TrafficSource for DaemonSource {
    fn name(&self) -> &'static str {
        "snetd"
    }

    fn sample(&mut self) -> Result<Snapshot, CaptureError> {
        match self.client.call(Command::Snapshot) {
            Ok(Reply::Snapshot(snapshot)) => Ok(snapshot),
            Ok(_) => Err(CaptureError::Backend(
                "snetd sent an unexpected reply".into(),
            )),
            Err(e) => Err(CaptureError::Backend(e.to_string())),
        }
    }

    fn notices(&self) -> Vec<String> {
        self.notices.iter().map(|n| format!("snetd: {n}")).collect()
    }

    fn first_sample_has_rates(&self) -> bool {
        true
    }
}

pub fn status(socket: &Path) -> anyhow::Result<String> {
    let reply = connect(socket)
        .and_then(|mut c| c.call(Command::Status))
        .map_err(|e| unavailable(socket, &e))?;
    let Reply::Status(status) = reply else {
        anyhow::bail!("snetd sent an unexpected reply");
    };
    Ok(render_status(&status, socket))
}

fn render_status(s: &Status, socket: &Path) -> String {
    let mut out = String::new();
    let _ = writeln!(
        out,
        "{HEADER}snetd {}{HEADER:#} is running (pid {}, up {})",
        s.version,
        s.pid,
        uptime(s.uptime_s)
    );
    let _ = writeln!(
        out,
        "source:   {}, sampling every {} ms",
        s.source, s.interval_ms
    );
    let _ = writeln!(out, "socket:   {}", socket.display());
    if s.notices.is_empty() {
        let _ = writeln!(out, "notices:  none");
    }
    for notice in &s.notices {
        let _ = writeln!(out, "notice:   {notice}");
    }
    let _ = writeln!(
        out,
        "alerts:   {} in the last 24 hours (snet alerts)",
        s.alerts_24h
    );
    if let Some(c) = &s.coverage {
        let interfaces = if c.interfaces.is_empty() {
            "the network interfaces".to_string()
        } else {
            c.interfaces.join(", ")
        };
        let line = match c.ratio() {
            Some(r) => format!(
                "{} of the traffic on {interfaces} attributed to applications over the last {} s",
                crate::view::coverage_percent(r),
                c.seconds
            ),
            None => format!(
                "too little traffic on {interfaces} in the last {} s to judge",
                c.seconds
            ),
        };
        let _ = writeln!(out, "coverage: {line}");
    }
    if !s.feeds.is_empty() {
        let _ = writeln!(out, "reputation lists:");
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |d| d.as_secs());
        for feed in &s.feeds {
            let age = match feed.updated {
                Some(t) => format!("updated {} ago", uptime(now.saturating_sub(t))),
                None => "not downloaded yet".to_string(),
            };
            let _ = writeln!(
                out,
                "  {:<24} {:>6} ranges  {DIM}{age}{DIM:#}",
                feed.name, feed.ranges
            );
        }
    }
    out
}

pub fn alerts(socket: &Path, since: Duration, limit: u32) -> anyhow::Result<Vec<AlertEvent>> {
    let reply = connect(socket)
        .and_then(|mut c| {
            c.call(Command::Alerts {
                since_s: since.as_secs(),
                limit,
            })
        })
        .map_err(|e| unavailable(socket, &e))?;
    match reply {
        Reply::Alerts { events } => Ok(events),
        _ => anyhow::bail!("snetd sent an unexpected reply"),
    }
}

/// Local wall-clock `YYYY-MM-DD HH:MM:SS` for a Unix timestamp.
fn local_time(ts: u64) -> String {
    i64::try_from(ts)
        .ok()
        .and_then(|t| jiff::Timestamp::from_second(t).ok())
        .map(|t| {
            t.to_zoned(jiff::tz::TimeZone::system())
                .strftime("%Y-%m-%d %H:%M:%S")
                .to_string()
        })
        .unwrap_or_else(|| ts.to_string())
}

pub fn render_alerts(events: &[AlertEvent], since: Duration) -> String {
    use anstyle::AnsiColor;
    let mut out = String::new();
    let window = uptime(since.as_secs());
    if events.is_empty() {
        let _ = writeln!(out, "No alerts in the last {window}.");
        return out;
    }
    let _ = writeln!(
        out,
        "{HEADER}{:<19}  {:<6}  {:<24}  {:<36}  WHAT{HEADER:#}",
        "WHEN", "LEVEL", "APPLICATION", "DESTINATION"
    );
    for e in events {
        let style = match e.severity.as_str() {
            "alert" => AnsiColor::Red.on_default().bold(),
            "warn" => AnsiColor::Yellow.on_default(),
            _ => AnsiColor::Cyan.on_default(),
        };
        let destination = match (&e.host, &e.remote) {
            (Some(host), Some(remote)) => {
                let port = remote.rsplit(':').next().unwrap_or("");
                format!("{host}:{port}")
            }
            (None, Some(remote)) => remote.clone(),
            _ => "-".into(),
        };
        let _ = writeln!(
            out,
            "{:<19}  {style}{:<6}{style:#}  {:<24}  {:<36}  {}",
            local_time(e.ts),
            e.severity.to_uppercase(),
            truncate(&e.app, 24),
            crate::units::truncate_left(&destination, 36),
            e.message
        );
    }
    let noun = if events.len() == 1 { "alert" } else { "alerts" };
    let _ = writeln!(out, "\n{} {noun} in the last {window}", events.len());
    out
}

fn uptime(secs: u64) -> String {
    let (d, h, m, s) = (secs / 86_400, secs / 3_600 % 24, secs / 60 % 60, secs % 60);
    match (d, h, m) {
        (0, 0, 0) => format!("{s}s"),
        (0, 0, _) => format!("{m}m {s}s"),
        (0, _, _) => format!("{h}h {m}m"),
        _ => format!("{d}d {h}h"),
    }
}

pub fn history_rows(socket: &Path, days: u32) -> anyhow::Result<Vec<UsageRow>> {
    let reply = connect(socket)
        .and_then(|mut c| c.call(Command::History { days }))
        .map_err(|e| unavailable(socket, &e))?;
    match reply {
        Reply::History { rows } => Ok(rows),
        _ => anyhow::bail!("snetd sent an unexpected reply"),
    }
}

/// One application's totals over the whole window.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Total {
    pub app: String,
    pub rx: u64,
    pub tx: u64,
}

/// Sums per-day rows per application, busiest first.
pub fn totals(rows: &[UsageRow]) -> Vec<Total> {
    let mut by_key: HashMap<&str, Total> = HashMap::new();
    let mut latest_day: HashMap<&str, &str> = HashMap::new();
    for row in rows {
        let total = by_key.entry(&row.key).or_insert_with(|| Total {
            app: row.app.clone(),
            rx: 0,
            tx: 0,
        });
        total.rx = total.rx.saturating_add(row.rx);
        total.tx = total.tx.saturating_add(row.tx);
        // Show the most recent display name.
        if latest_day
            .get(row.key.as_str())
            .is_none_or(|d| *d <= row.day.as_str())
        {
            total.app.clone_from(&row.app);
            latest_day.insert(&row.key, &row.day);
        }
    }
    let mut totals: Vec<Total> = by_key.into_values().collect();
    totals.sort_by(|a, b| (b.rx + b.tx).cmp(&(a.rx + a.tx)).then(a.app.cmp(&b.app)));
    totals
}

pub fn render_history(rows: &[UsageRow], days: u32, limit: Option<usize>) -> String {
    let mut totals = totals(rows);
    let all = totals.len();
    if let Some(limit) = limit {
        totals.truncate(limit);
    }
    let first = rows.iter().map(|r| r.day.as_str()).min();
    let last = rows.iter().map(|r| r.day.as_str()).max();
    let mut out = String::new();
    let span = match (first, last) {
        (Some(f), Some(l)) if f == l => f.to_string(),
        (Some(f), Some(l)) => format!("{f} → {l}"),
        _ => "no data yet".to_string(),
    };
    let period = if days == 1 {
        "today".to_string()
    } else {
        format!("last {days} days")
    };
    let _ = writeln!(
        out,
        "{HEADER}Data usage, {period}{HEADER:#} {DIM}({span}){DIM:#}\n"
    );
    let _ = writeln!(
        out,
        "{HEADER}{:<32} {:>11} {:>11} {:>11}{HEADER:#}",
        "APPLICATION", "▼ RECEIVED", "▲ SENT", "TOTAL"
    );
    if totals.is_empty() {
        let _ = writeln!(out, "{DIM}no usage recorded in this period{DIM:#}");
    }
    for t in &totals {
        let _ = writeln!(
            out,
            "{:<32} {:>11} {:>11} {:>11}",
            truncate(&t.app, 32),
            bytes(t.rx),
            bytes(t.tx),
            bytes(t.rx + t.tx)
        );
    }
    let (rx, tx) = rows.iter().fold((0u64, 0u64), |(a, b), r| {
        (a.saturating_add(r.rx), b.saturating_add(r.tx))
    });
    let shown = if totals.len() < all {
        format!("{} of {all}", totals.len())
    } else {
        all.to_string()
    };
    let _ = writeln!(
        out,
        "\n{shown} applications · ▼ {} ▲ {} · total {}",
        bytes(rx),
        bytes(tx),
        bytes(rx + tx)
    );
    out
}

/// Asks snetd to carry out an action. A refusal is an ordinary error (exit 1); no service
/// is "unavailable" (exit 69).
pub fn act(socket: &Path, action: spectranet_proto::Action) -> anyhow::Result<String> {
    let mut client = connect(socket).map_err(|e| unavailable(socket, &e))?;
    match client.call(Command::Act { action }) {
        Ok(Reply::Done { message }) => Ok(message),
        Ok(_) => anyhow::bail!("snetd sent an unexpected reply"),
        Err(ClientError::Protocol(message)) => anyhow::bail!("{message}"),
        Err(e) => Err(unavailable(socket, &e).into()),
    }
}

/// What `snet block TARGET` means: an address, or the application of a PID, a name or a
/// path, looked up in snetd's latest sample.
pub fn block_target(socket: &Path, target: &str) -> anyhow::Result<spectranet_proto::BlockTarget> {
    use spectranet_proto::BlockTarget;
    if let Ok(ip) = target.parse::<std::net::IpAddr>() {
        return Ok(BlockTarget::Remote { ip });
    }
    let reply = connect(socket)
        .and_then(|mut c| c.call(Command::Snapshot))
        .map_err(|e| unavailable(socket, &e))?;
    let Reply::Snapshot(snapshot) = reply else {
        anyhow::bail!("snetd sent an unexpected reply");
    };
    resolve_app(&snapshot, target)
}

/// Finds the application meant by a PID, an exact path or a name (exact, or the only one
/// containing it).
pub fn resolve_app(
    snapshot: &spectranet_model::Snapshot,
    target: &str,
) -> anyhow::Result<spectranet_proto::BlockTarget> {
    let apps = spectranet_model::group_by_app(snapshot.processes.clone());
    let wanted = target.to_lowercase();
    let pid: Option<u32> = target.parse().ok();
    let exact: Vec<_> = apps
        .iter()
        .filter(|a| {
            pid.is_some_and(|pid| a.processes.iter().any(|p| p.process.pid == pid))
                || a.path.as_deref() == Some(target)
                || a.name.to_lowercase() == wanted
        })
        .collect();
    let candidates = if exact.is_empty() {
        apps.iter()
            .filter(|a| pid.is_none() && a.name.to_lowercase().contains(&wanted))
            .collect()
    } else {
        exact
    };
    // Several standalone processes of one program (e.g. three curl) are one application.
    let mut paths: Vec<(&str, &str)> = candidates
        .iter()
        .filter_map(|a| a.path.as_deref().map(|p| (p, a.name.as_str())))
        .collect();
    paths.sort_unstable();
    paths.dedup_by_key(|p| p.0);
    match paths.as_slice() {
        [(path, name)] => Ok(spectranet_proto::BlockTarget::App {
            path: (*path).to_string(),
            name: (*name).to_string(),
        }),
        [] if candidates.is_empty() => anyhow::bail!(
            "no application with network activity matches '{target}' (see 'snet list'; an address must be a plain IP)"
        ),
        [] => anyhow::bail!("the program file of '{target}' is unknown, so it can't be blocked"),
        many => anyhow::bail!(
            "'{target}' matches several applications: {}; be more specific or use the PID",
            many.iter().map(|(_, n)| *n).collect::<Vec<_>>().join(", ")
        ),
    }
}

pub fn blocks(socket: &Path) -> anyhow::Result<Vec<spectranet_proto::BlockInfo>> {
    let reply = connect(socket)
        .and_then(|mut c| c.call(Command::Blocks))
        .map_err(|e| unavailable(socket, &e))?;
    match reply {
        Reply::Blocks { blocks } => Ok(blocks),
        _ => anyhow::bail!("snetd sent an unexpected reply"),
    }
}

pub fn now_s() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

pub fn render_blocks(blocks: &[spectranet_proto::BlockInfo], now: u64) -> String {
    use std::fmt::Write as _;
    if blocks.is_empty() {
        return "no blocks in force\n".into();
    }
    let mut out = String::new();
    for b in blocks {
        let what = match &b.target {
            spectranet_proto::BlockTarget::App { name, path } => format!("{name}  ({path})"),
            spectranet_proto::BlockTarget::Remote { ip } => ip.to_string(),
        };
        let left = if b.expires == 0 {
            "until lifted".to_string()
        } else {
            format!("{} left", uptime(b.expires.saturating_sub(now)))
        };
        let _ = writeln!(
            out,
            "{:>3}  {:<14} {}  — by {}, {}",
            b.id, left, what, b.by, b.method
        );
    }
    out
}

pub fn audit(
    socket: &Path,
    since: Duration,
    limit: u32,
) -> anyhow::Result<Vec<spectranet_proto::AuditEvent>> {
    let reply = connect(socket)
        .and_then(|mut c| {
            c.call(Command::Audit {
                since_s: since.as_secs(),
                limit,
            })
        })
        .map_err(|e| unavailable(socket, &e))?;
    match reply {
        Reply::Audit { events } => Ok(events),
        _ => anyhow::bail!("snetd sent an unexpected reply"),
    }
}

pub fn render_audit(events: &[spectranet_proto::AuditEvent], since: Duration) -> String {
    use std::fmt::Write as _;
    if events.is_empty() {
        return format!("no actions in the last {}\n", uptime(since.as_secs()));
    }
    let mut out = String::new();
    for e in events {
        let verb = match &e.action {
            spectranet_proto::Action::Kill { force: true, .. } => "kill -9",
            spectranet_proto::Action::Kill { .. } => "kill",
            spectranet_proto::Action::Pause { .. } => "pause",
            spectranet_proto::Action::Resume { .. } => "resume",
            spectranet_proto::Action::DropFlow { .. } => "drop",
            spectranet_proto::Action::Block { .. } => "block",
            spectranet_proto::Action::Unblock { .. } => "unblock",
        };
        let outcome = if e.ok { "done" } else { "refused" };
        let _ = writeln!(
            out,
            "{}  {:<10} {:<8} {:<8} {}  — {}",
            local_time(e.ts),
            e.by,
            verb,
            outcome,
            e.target,
            e.message
        );
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn snapshot_of(procs: &[(u32, &str, Option<&str>)]) -> Snapshot {
        Snapshot {
            source: "test".into(),
            timestamp_ms: 0,
            interval_ms: 1000,
            processes: procs
                .iter()
                .map(|(pid, name, path)| {
                    spectranet_model::ProcessTraffic::new(
                        spectranet_model::Process {
                            pid: *pid,
                            name: (*name).into(),
                            path: path.map(Into::into),
                            app: None,
                        },
                        Vec::new(),
                    )
                })
                .collect(),
            link: None,
        }
    }

    #[test]
    fn block_targets_by_pid_name_or_path() {
        use spectranet_proto::BlockTarget;
        let s = snapshot_of(&[
            (10, "curl", Some("/usr/bin/curl")),
            (11, "curl", Some("/usr/bin/curl")),
            (20, "svc_update", Some("/tmp/svc_update")),
            (30, "firefox", Some("/usr/lib/firefox/firefox")),
            (31, "firefox-bin", Some("/opt/firefox-bin")),
            (40, "mystery", None),
        ]);
        let curl = BlockTarget::App {
            path: "/usr/bin/curl".into(),
            name: "curl".into(),
        };
        assert_eq!(resolve_app(&s, "11").unwrap(), curl, "by PID");
        assert_eq!(
            resolve_app(&s, "CURL").unwrap(),
            curl,
            "by name, two processes"
        );
        assert_eq!(resolve_app(&s, "/usr/bin/curl").unwrap(), curl, "by path");
        assert!(
            matches!(resolve_app(&s, "svc").unwrap(), BlockTarget::App { name, .. } if name == "svc_update")
        );
        assert_eq!(
            resolve_app(&s, "firefox").unwrap(),
            BlockTarget::App {
                path: "/usr/lib/firefox/firefox".into(),
                name: "firefox".into()
            },
            "an exact name wins over partial matches"
        );
        assert!(
            resolve_app(&s, "fire")
                .unwrap_err()
                .to_string()
                .contains("several")
        );
        assert!(
            resolve_app(&s, "mystery")
                .unwrap_err()
                .to_string()
                .contains("unknown")
        );
        assert!(resolve_app(&s, "nothing").is_err());
        assert!(resolve_app(&s, "99").is_err());
    }

    #[test]
    fn block_list() {
        let blocks = vec![spectranet_proto::BlockInfo {
            id: 3,
            target: spectranet_proto::BlockTarget::Remote {
                ip: "185.220.101.34".parse().unwrap(),
            },
            created: 0,
            expires: 1000 + 900,
            by: "alice".into(),
            method: "eBPF (cgroup)".into(),
        }];
        let text = render_blocks(&blocks, 1000);
        assert!(
            text.contains("185.220.101.34") && text.contains("left"),
            "{text}"
        );
        assert_eq!(render_blocks(&[], 0), "no blocks in force\n");
    }

    fn row(day: &str, key: &str, app: &str, rx: u64, tx: u64) -> UsageRow {
        UsageRow {
            day: day.into(),
            key: key.into(),
            app: app.into(),
            rx,
            tx,
        }
    }

    #[test]
    fn totals_sum_days_and_keep_latest_name() {
        let rows = [
            row("2026-10-08", "/A.app", "Old Name", 100, 0),
            row("2026-10-09", "/A.app", "New Name", 50, 10),
            row("2026-10-09", "/usr/bin/curl", "curl", 500, 1),
        ];
        assert_eq!(
            totals(&rows),
            [
                Total {
                    app: "curl".into(),
                    rx: 500,
                    tx: 1
                },
                Total {
                    app: "New Name".into(),
                    rx: 150,
                    tx: 10
                }
            ]
        );
    }

    #[test]
    fn history_table() {
        let rows = [
            row("2026-10-09", "/A.app", "Alpha", 2048, 1024),
            row("2026-10-10", "/B.app", "Beta", 1, 1),
        ];
        let text = render_history(&rows, 7, None);
        assert!(text.contains("Data usage, last 7 days"));
        assert!(text.contains("2026-10-09 → 2026-10-10"));
        assert!(text.contains("Alpha") && text.contains("3.0 KiB"));
        assert!(text.contains("2 applications · ▼ 2.0 KiB ▲ 1.0 KiB · total 3.0 KiB"));
        let limited = render_history(&rows, 7, Some(1));
        assert!(limited.contains("1 of 2 applications"));
        assert!(!limited.contains("Beta"));
        assert!(render_history(&[], 1, None).contains("no usage recorded"));
    }

    #[test]
    fn alerts_table() {
        let events = [
            AlertEvent {
                ts: 1_760_000_000,
                severity: "alert".into(),
                rule: "reputation:feodo".into(),
                app: "svc_update".into(),
                remote: Some("185.220.101.5:80".into()),
                host: None,
                message: "known botnet command-and-control server".into(),
            },
            AlertEvent {
                ts: 1_760_000_100,
                severity: "info".into(),
                rule: "first-connection".into(),
                app: "newtool".into(),
                remote: Some("[2606:4700::1111]:443".into()),
                host: Some("one.one.one.one".into()),
                message: "first time on the network".into(),
            },
        ];
        let text = render_alerts(&events, Duration::from_secs(86_400));
        assert!(
            text.contains("ALERT") && text.contains("185.220.101.5:80") && text.contains("botnet")
        );
        assert!(text.contains("one.one.one.one:443"), "{text}");
        assert!(text.contains("2 alerts in the last 1d 0h"));
        assert!(
            render_alerts(&[], Duration::from_secs(3600)).contains("No alerts in the last 1h 0m")
        );
    }

    #[test]
    fn uptime_formatting() {
        assert_eq!(uptime(5), "5s");
        assert_eq!(uptime(65), "1m 5s");
        assert_eq!(uptime(3_700), "1h 1m");
        assert_eq!(uptime(90_000), "1d 1h");
    }
}
