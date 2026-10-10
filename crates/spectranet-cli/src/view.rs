//! Selecting, ordering and rendering the applications of a snapshot.

use std::fmt::Write as _;

use anstyle::{AnsiColor, Style};
use spectranet_model::{
    AppTraffic, Flow, Process, Snapshot, Transport, Verdict, group_by_app, one_per_process,
};

use crate::cli::{SortKey, ViewArgs};
use crate::units::{bytes, rate, truncate, truncate_left};

const HEADER: Style = Style::new().bold();
const DIM: Style = Style::new().dimmed();
const ACCENT: Style = AnsiColor::Cyan.on_default();
const DOWN: Style = AnsiColor::Green.on_default();
const UP: Style = AnsiColor::Blue.on_default();

const NAME_WIDTH: usize = 24;
/// With a single `-c`, connections shown per application (beyond the active ones).
const CONNECTIONS_SHOWN: usize = 10;

/// A snapshot reduced to the applications the user asked to see, in display order.
#[derive(Debug, Clone)]
pub struct View {
    pub source: String,
    pub timestamp_ms: u64,
    pub interval_ms: u64,
    pub apps: Vec<AppTraffic>,
}

impl View {
    /// The selected processes as a snapshot, in display order (used for JSON output).
    pub fn into_snapshot(self) -> Snapshot {
        Snapshot {
            source: self.source,
            timestamp_ms: self.timestamp_ms,
            interval_ms: self.interval_ms,
            processes: self.apps.into_iter().flat_map(|a| a.processes).collect(),
        }
    }
}

/// Applies the filters, grouping, sort order and limit from `args`.
///
/// Filters apply to individual processes; `--name` matches either the process name or the
/// name of the application it belongs to. `--limit` counts applications.
/// Whether a process belongs to a domain (`--domain`).
pub fn in_domain(p: &spectranet_model::ProcessTraffic, domain: crate::cli::Domain) -> bool {
    match domain {
        crate::cli::Domain::Radio => {
            spectranet_intel::radio::program(&p.process.name).is_some()
                || p.process
                    .path
                    .as_deref()
                    .is_some_and(|path| spectranet_intel::radio::program(path).is_some())
                || p.flows
                    .iter()
                    .any(|f| f.meta.class.as_ref().is_some_and(|c| c.kind.is_radio()))
        }
    }
}

pub fn select(snapshot: Snapshot, args: &ViewArgs) -> View {
    let needle = args.name.as_deref().map(str::to_lowercase);
    let processes = snapshot
        .processes
        .into_iter()
        .filter(|p| {
            (args.pids.is_empty() || args.pids.contains(&p.process.pid))
                && needle.as_deref().is_none_or(|n| {
                    name_matches(&p.process, n) || p.flows.iter().any(|f| destination_matches(f, n))
                })
                && (!args.flagged || p.verdict >= Verdict::Warn)
                && args.domain.is_none_or(|d| in_domain(p, d))
        })
        .collect();
    let mut apps = if args.by_process {
        one_per_process(processes)
    } else {
        group_by_app(processes)
    };
    sort(&mut apps, args.sort);
    if let Some(limit) = args.limit {
        apps.truncate(limit);
    }
    View {
        source: snapshot.source,
        timestamp_ms: snapshot.timestamp_ms,
        interval_ms: snapshot.interval_ms,
        apps,
    }
}

/// Name search: a substring, or the needle's letters in order ("gch" → Google Chrome).
fn name_matches(process: &Process, needle: &str) -> bool {
    let matches = |name: &str| {
        let name = name.to_lowercase();
        name.contains(needle) || fuzzy(&name, needle)
    };
    matches(&process.name) || process.app.as_ref().is_some_and(|a| matches(&a.name))
}

/// Every character of `needle` appears in `text`, in order. Needles shorter than three
/// characters must be substrings: "go" would otherwise match almost everything.
pub fn fuzzy(text: &str, needle: &str) -> bool {
    if needle.chars().count() < 3 {
        return false;
    }
    let mut chars = text.chars();
    needle.chars().all(|n| chars.any(|c| c == n))
}

/// Destination search: hostname or address substring (`googlevideo`, `142.250.`).
fn destination_matches(flow: &spectranet_model::Flow, needle: &str) -> bool {
    flow.remote_host
        .as_deref()
        .is_some_and(|h| h.to_lowercase().contains(needle))
        || flow.remote.ip().to_string().contains(needle)
}

fn sort(apps: &mut [AppTraffic], key: SortKey) {
    apps.sort_by(|a, b| {
        let primary = match key {
            SortKey::Rate => b.total_rate().cmp(&a.total_rate()),
            SortKey::Down => b.rx_rate.cmp(&a.rx_rate),
            SortKey::Up => b.tx_rate.cmp(&a.tx_rate),
            SortKey::Total => (b.rx_bytes + b.tx_bytes).cmp(&(a.rx_bytes + a.tx_bytes)),
            SortKey::Pid => a.pid.cmp(&b.pid),
            SortKey::Name => a.name.to_lowercase().cmp(&b.name.to_lowercase()),
            SortKey::Cpu => b.cpu_tenths.cmp(&a.cpu_tenths),
            SortKey::Mem => b.memory.cmp(&a.memory),
            SortKey::Alerts => b
                .verdict
                .cmp(&a.verdict)
                .then(b.total_rate().cmp(&a.total_rate())),
        };
        primary.then(a.pid.cmp(&b.pid))
    });
}

/// One-line overview of the view.
pub fn summary(view: &View) -> String {
    let processes: usize = view.apps.iter().map(|a| a.processes.len()).sum();
    let connections: usize = view.apps.iter().map(AppTraffic::flow_count).sum();
    let flagged = view
        .apps
        .iter()
        .filter(|a| a.verdict >= Verdict::Warn)
        .count();
    let flagged = if flagged == 0 {
        format!("{DOWN}no alerts{DOWN:#}")
    } else {
        let style = verdict_style(Verdict::Alert);
        format!("{style}{flagged} flagged{style:#}")
    };
    let apps = match view.apps.len() {
        1 => "1 application".to_string(),
        n => format!("{n} applications"),
    };
    let processes = if processes == view.apps.len() {
        String::new()
    } else {
        format!(" ({processes} processes)")
    };
    format!(
        "{apps}{processes} · {connections} connections · {DOWN}▼ {}{DOWN:#} {UP}▲ {}{UP:#} · {flagged}",
        rate(view.apps.iter().map(|a| a.rx_rate).sum()),
        rate(view.apps.iter().map(|a| a.tx_rate).sum()),
    )
}

/// Renders the application table. `connections` is how many times `-c` was given:
/// 0 = none, 1 = active ones and up to [`CONNECTIONS_SHOWN`], 2+ = all.
pub fn table(view: &View, connections: u8) -> String {
    let mut out = String::new();
    let _ = writeln!(
        out,
        "{HEADER}{:>7}  {:<NAME_WIDTH$} {:>11} {:>11} {:>9} {:>9} {:>4}  {:<32} STATUS{HEADER:#}",
        "PID", "APPLICATION", "▼ DOWN", "▲ UP", "RECEIVED", "SENT", "CONN", "TOP DESTINATION"
    );
    if view.apps.is_empty() {
        let _ = writeln!(out, "{DIM}{:>7}  no matching applications{DIM:#}", "");
    }
    for app in &view.apps {
        let destination = app.busiest_flow().map(endpoint).unwrap_or_default();
        let _ = writeln!(
            out,
            "{:>7}  {ACCENT}{:<NAME_WIDTH$}{ACCENT:#} {DOWN}{:>11}{DOWN:#} {UP}{:>11}{UP:#} {:>9} {:>9} {:>4}  {:<32} {}",
            app.pid,
            app_label(app),
            rate(app.rx_rate),
            rate(app.tx_rate),
            bytes(app.rx_bytes),
            bytes(app.tx_bytes),
            app.flow_count(),
            truncate_left(&destination, 32),
            verdict_label(app.verdict),
        );
        if connections > 0 {
            let grouped = app.processes.len() > 1;
            let rows = connection_rows(app);
            let shown = if connections >= 2 {
                rows.len()
            } else {
                let active = rows
                    .iter()
                    .filter(|r| r.flow.rx_rate + r.flow.tx_rate > 0)
                    .count();
                active.max(CONNECTIONS_SHOWN).min(rows.len())
            };
            for row in &rows[..shown] {
                out.push_str(&connection_line(row, grouped));
            }
            let hidden = rows.len() - shown;
            if hidden > 0 {
                let noun = if hidden == 1 {
                    "connection"
                } else {
                    "connections"
                };
                let _ = writeln!(
                    out,
                    "{DIM}{:>7}  └ … {hidden} more idle {noun} (-cc lists all){DIM:#}",
                    ""
                );
            }
        }
    }
    out
}

/// The application name, with the number of processes when there is more than one.
pub(crate) fn app_label(app: &AppTraffic) -> String {
    match app.processes.len() {
        1 => truncate(&app.name, NAME_WIDTH),
        n => {
            let suffix = format!(" ({n})");
            let room = NAME_WIDTH.saturating_sub(suffix.chars().count());
            format!("{}{suffix}", truncate(&app.name, room))
        }
    }
}

/// A line of the connection list: one connection, or several identical unconnected sockets
/// (e.g. a browser's many mDNS listeners) merged into one.
pub(crate) struct ConnectionRow<'a> {
    pub(crate) flow: Flow,
    pub(crate) local: String,
    pub(crate) count: usize,
    pub(crate) owner: &'a Process,
}

/// Builds the connection list of an application, busiest first. Unconnected sockets of the
/// same process, protocol and local port are merged, summing their traffic.
pub(crate) fn connection_rows(app: &AppTraffic) -> Vec<ConnectionRow<'_>> {
    let mut rows: Vec<ConnectionRow<'_>> = Vec::new();
    for p in &app.processes {
        for f in &p.flows {
            let unconnected = f.remote.ip().is_unspecified();
            let same = rows.iter_mut().find(|r| {
                unconnected
                    && r.flow.remote.ip().is_unspecified()
                    && r.owner.pid == p.process.pid
                    && r.flow.transport == f.transport
                    && r.flow.local.port() == f.local.port()
            });
            match same {
                Some(row) => {
                    row.count += 1;
                    row.local = format!("*:{}", f.local.port());
                    row.flow.rx_rate += f.rx_rate;
                    row.flow.tx_rate += f.tx_rate;
                    row.flow.rx_bytes += f.rx_bytes;
                    row.flow.tx_bytes += f.tx_bytes;
                    if f.verdict > row.flow.verdict {
                        row.flow.verdict = f.verdict;
                        row.flow.note.clone_from(&f.note);
                    }
                }
                None => rows.push(ConnectionRow {
                    flow: f.clone(),
                    local: f.local.to_string(),
                    count: 1,
                    owner: &p.process,
                }),
            }
        }
    }
    rows.sort_by_key(|r| std::cmp::Reverse(r.flow.activity()));
    rows
}

/// One line of the connection list; the owning process is shown when the application has
/// several.
fn connection_line(row: &ConnectionRow<'_>, show_owner: bool) -> String {
    let f = &row.flow;
    let transport = match f.transport {
        Transport::Tcp => "tcp",
        Transport::Udp => "udp",
    };
    let note = match &f.note {
        Some(note) => {
            let style = verdict_style(f.verdict);
            format!("  {style}{note}{style:#}")
        }
        None => String::new(),
    };
    let owner = if show_owner {
        format!("  {DIM}{} {}{DIM:#}", row.owner.pid, row.owner.name)
    } else {
        String::new()
    };
    let destination = match row.count {
        1 => truncate_left(&endpoint(f), 40),
        n => format!("* ({n} sockets)"),
    };
    let kind = match &f.meta.class {
        Some(c) => {
            let (_, tag, (r, g, b)) = crate::flowtext::kind_style(c.kind);
            let style = Style::new().fg_color(Some(anstyle::RgbColor(r, g, b).into()));
            format!("  {style}[{tag}]{style:#}")
        }
        None => String::new(),
    };
    format!(
        "{DIM}{:>7}  └ {transport} {:<21} → {DIM:#}{:<40} {DOWN}▼ {:>10}{DOWN:#} {UP}▲ {:>10}{UP:#}{kind}{owner}{note}\n",
        "",
        truncate_left(&row.local, 21),
        destination,
        rate(f.rx_rate),
        rate(f.tx_rate),
    )
}

/// `host:port`, falling back to the IP address when the hostname is unknown,
/// or `*` for a socket not connected to any particular peer (e.g. unconnected UDP).
pub(crate) fn endpoint(f: &Flow) -> String {
    if f.remote.ip().is_unspecified() {
        return "*".into();
    }
    match &f.remote_host {
        Some(host) => format!("{host}:{}", f.remote.port()),
        None => f.remote.to_string(),
    }
}

fn verdict_style(verdict: Verdict) -> Style {
    match verdict {
        Verdict::Ok => AnsiColor::Green.on_default(),
        Verdict::Warn => AnsiColor::Yellow.on_default(),
        Verdict::Alert => AnsiColor::Red.on_default().bold(),
    }
}

fn verdict_label(verdict: Verdict) -> String {
    let style = verdict_style(verdict);
    let text = match verdict {
        Verdict::Ok => "ok",
        Verdict::Warn => "warn",
        Verdict::Alert => "ALERT",
    };
    format!("{style}{text}{style:#}")
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use spectranet_capture::mock::MockSource;

    #[test]
    fn radio_domain_by_program_or_kind() {
        use spectranet_model::flowmeta::{Certainty, Class, Kind};
        use spectranet_model::{Flow, Process, ProcessTraffic, Transport, Verdict};
        let process = |name: &str, kind: Option<Kind>| {
            let mut flow = Flow {
                transport: Transport::Tcp,
                local: "192.168.1.2:50000".parse().unwrap(),
                remote: "1.2.3.4:443".parse().unwrap(),
                remote_host: None,
                rx_rate: 1,
                tx_rate: 1,
                rx_bytes: 0,
                tx_bytes: 0,
                verdict: Verdict::Ok,
                note: None,
                meta: Default::default(),
            };
            flow.meta.class = kind.map(|kind| Class {
                kind,
                certainty: Certainty::Likely,
                reasons: Vec::new(),
            });
            ProcessTraffic::new(
                Process {
                    pid: 1,
                    name: name.into(),
                    path: None,
                    app: None,
                },
                vec![flow],
            )
        };
        let radio = crate::cli::Domain::Radio;
        assert!(in_domain(&process("satdump", None), radio));
        assert!(
            in_domain(&process("chrome", Some(Kind::WebSdr)), radio),
            "a KiwiSDR tab"
        );
        assert!(!in_domain(&process("chrome", Some(Kind::Video)), radio));
    }

    use super::*;
    use crate::cli::{Cli, Command};
    use clap::Parser;

    fn view_args(args: &[&str]) -> ViewArgs {
        let argv = ["snet", "list"].iter().chain(args).copied();
        match Cli::parse_from(argv).command {
            Command::List(list) => list.view,
            _ => unreachable!(),
        }
    }

    fn snapshot() -> Snapshot {
        MockSource::new(3).advance(Duration::from_secs(1))
    }

    fn names(view: &View) -> Vec<&str> {
        view.apps.iter().map(|a| a.name.as_str()).collect()
    }

    #[test]
    fn search_covers_fuzzy_names_hosts_and_addresses() {
        let all = select(snapshot(), &view_args(&[])).apps.len();
        assert!(
            names(&select(snapshot(), &view_args(&["--name", "gch"]))).contains(&"Google Chrome")
        );
        assert!(
            names(&select(snapshot(), &view_args(&["--name", "googlevideo"])))
                .contains(&"Google Chrome")
        );
        let by_ip = select(snapshot(), &view_args(&["--name", "185.220."]));
        assert!(
            names(&by_ip).iter().any(|n| n.contains("svc_update")),
            "{:?}",
            names(&by_ip)
        );
        assert!(
            select(snapshot(), &view_args(&["--name", "zzzz"]))
                .apps
                .is_empty()
        );
        assert!(
            select(snapshot(), &view_args(&["--name", "go"])).apps.len() < all,
            "short needles are substrings only"
        );
        assert!(
            fuzzy("google chrome", "gch") && !fuzzy("google chrome", "chg") && !fuzzy("abc", "ab")
        );
    }

    #[test]
    fn sorts_by_cpu_memory_and_alerts() {
        let cpu = select(snapshot(), &view_args(&["--sort", "cpu"]));
        assert!(
            cpu.apps
                .windows(2)
                .all(|w| w[0].cpu_tenths >= w[1].cpu_tenths)
        );
        let mem = select(snapshot(), &view_args(&["--sort", "mem"]));
        assert!(mem.apps.windows(2).all(|w| w[0].memory >= w[1].memory));
        assert!(mem.apps[0].memory > 0, "the simulator reports memory");
        let alerts = select(snapshot(), &view_args(&["--sort", "alerts"]));
        assert_eq!(alerts.apps[0].verdict, Verdict::Alert);
    }

    #[test]
    fn default_sort_is_busiest_first() {
        let view = select(snapshot(), &view_args(&[]));
        let rates: Vec<_> = view.apps.iter().map(AppTraffic::total_rate).collect();
        assert!(rates.windows(2).all(|w| w[0] >= w[1]));
    }

    #[test]
    fn every_sort_key_orders_consistently() {
        for key in ["rate", "down", "up", "total", "pid", "name"] {
            let view = select(snapshot(), &view_args(&["--sort", key]));
            assert_eq!(view.apps.len(), 6, "sort {key} must not drop applications");
        }
        let view = select(snapshot(), &view_args(&["--sort", "pid"]));
        let pids: Vec<_> = view.apps.iter().map(|a| a.pid).collect();
        assert!(pids.windows(2).all(|w| w[0] < w[1]));
    }

    #[test]
    fn helpers_are_grouped_by_default() {
        let view = select(snapshot(), &view_args(&[]));
        assert_eq!(view.apps.len(), 6, "7 processes, Chrome's two merged");
        let chrome = view
            .apps
            .iter()
            .find(|a| a.name == "Google Chrome")
            .unwrap();
        assert_eq!(chrome.pid, 4892, "main process represents the app");
        assert_eq!(chrome.processes.len(), 2);
        assert_eq!(chrome.flow_count(), 3);
    }

    #[test]
    fn by_process_keeps_every_process_separate() {
        let view = select(snapshot(), &view_args(&["--by-process"]));
        assert_eq!(view.apps.len(), 7);
        assert!(view.apps.iter().all(|a| a.processes.len() == 1));
    }

    #[test]
    fn grouping_never_changes_the_totals() {
        let grouped = select(snapshot(), &view_args(&[]));
        let flat = select(snapshot(), &view_args(&["-P"]));
        let total = |v: &View| {
            v.apps
                .iter()
                .map(|a| (a.rx_rate, a.tx_rate, a.flow_count()))
                .fold((0, 0, 0), |acc, x| (acc.0 + x.0, acc.1 + x.1, acc.2 + x.2))
        };
        assert_eq!(total(&grouped), total(&flat));
    }

    #[test]
    fn name_filter_matches_process_or_application() {
        let view = select(snapshot(), &view_args(&["--name", "CHROME"]));
        assert_eq!(names(&view), ["Google Chrome"]);
        assert_eq!(view.apps[0].processes.len(), 2);

        let view = select(snapshot(), &view_args(&["--name", "helper"]));
        assert_eq!(
            names(&view),
            ["Google Chrome"],
            "helper matched by process name"
        );
        assert_eq!(view.apps[0].pid, 4901);
    }

    #[test]
    fn pid_filter_selects_single_processes() {
        let view = select(snapshot(), &view_args(&["--pid", "4901"]));
        assert_eq!(view.apps.len(), 1);
        assert_eq!(
            (view.apps[0].name.as_str(), view.apps[0].pid),
            ("Google Chrome", 4901)
        );

        let view = select(
            snapshot(),
            &view_args(&["-p", "112", "-p", "9912", "--sort", "pid"]),
        );
        let pids: Vec<_> = view.apps.iter().map(|a| a.pid).collect();
        assert_eq!(pids, [112, 9912]);

        let view = select(snapshot(), &view_args(&["--pid", "999999"]));
        assert!(view.apps.is_empty());
        assert!(table(&view, 1).contains("no matching applications"));
    }

    #[test]
    fn flagged_filter_keeps_only_suspicious() {
        let view = select(snapshot(), &view_args(&["--flagged"]));
        assert!(view.apps.iter().all(|a| a.verdict >= Verdict::Warn));
        assert_eq!(view.apps.len(), 2);
    }

    #[test]
    fn limit_counts_applications_after_sorting() {
        let view = select(snapshot(), &view_args(&["--sort", "name", "--limit", "2"]));
        assert_eq!(names(&view), ["Discord", "Google Chrome"]);
        let json = view.into_snapshot();
        assert_eq!(
            json.processes.len(),
            3,
            "Chrome contributes both its processes"
        );

        let view = select(snapshot(), &view_args(&["--limit", "0"]));
        assert!(view.apps.is_empty());
    }

    #[test]
    fn json_snapshot_follows_display_order() {
        let view = select(snapshot(), &view_args(&["--sort", "pid"]));
        let order: Vec<_> = view
            .apps
            .iter()
            .flat_map(|a| a.processes.iter().map(|p| p.process.pid))
            .collect();
        let pids: Vec<_> = view
            .into_snapshot()
            .processes
            .iter()
            .map(|p| p.process.pid)
            .collect();
        assert_eq!(order, pids);
    }

    #[test]
    fn table_shows_process_count_and_owners() {
        let view = select(snapshot(), &view_args(&["--name", "chrome"]));
        let plain = table(&view, 0);
        assert!(plain.contains("Google Chrome (2)"));
        assert!(!plain.contains("└"));
        let detailed = table(&view, 1);
        assert!(detailed.contains("4901 Google Chrome Helper"));
        assert_eq!(detailed.matches("└").count(), 3);

        let single = select(snapshot(), &view_args(&["--name", "discord"]));
        let detailed = table(&single, 1);
        assert!(detailed.contains("└ udp"));
        assert!(
            !detailed.contains("10440 Discord"),
            "no owner suffix for single-process apps"
        );
    }

    #[test]
    fn connections_are_listed_busiest_first() {
        let view = select(snapshot(), &view_args(&["--name", "chrome"]));
        let detailed = table(&view, 1);
        let video = detailed.find("googlevideo").unwrap();
        let youtube = detailed.find("www.youtube.com").unwrap();
        let search = detailed.find("www.google.com").unwrap();
        assert!(
            video < search && video < youtube,
            "880 KiB/s flow comes first"
        );
    }

    #[test]
    fn identical_unconnected_sockets_are_merged() {
        let mut snap = snapshot();
        let chrome = snap
            .processes
            .iter_mut()
            .find(|p| p.process.pid == 4901)
            .unwrap();
        let mut mdns = chrome.flows[0].clone();
        mdns.transport = Transport::Udp;
        mdns.remote = "0.0.0.0:0".parse().unwrap();
        for (i, local) in ["0.0.0.0:5353", "[::]:5353", "[::]:5353", "[::]:5353"]
            .iter()
            .enumerate()
        {
            let mut f = mdns.clone();
            f.local = local.parse().unwrap();
            f.rx_rate = 100 * (i as u64 + 1);
            f.tx_rate = 0;
            chrome.flows.push(f);
        }
        // A different port stays separate.
        let mut other = mdns.clone();
        other.local = "0.0.0.0:6000".parse().unwrap();
        chrome.flows.push(other);

        let view = select(snap, &view_args(&["--name", "chrome"]));
        let rows = connection_rows(&view.apps[0]);
        let merged: Vec<_> = rows.iter().filter(|r| r.count > 1).collect();
        assert_eq!(merged.len(), 1);
        assert_eq!(merged[0].count, 4);
        assert_eq!(merged[0].local, "*:5353");
        assert_eq!(merged[0].flow.rx_rate, 1000, "rates are summed");
        assert_eq!(
            rows.len(),
            3 + 1 + 1,
            "3 real connections, 1 merged, 1 other port"
        );

        let text = table(&view, 1);
        assert!(text.contains("* (4 sockets)"));
        assert_eq!(text.matches("5353").count(), 1);
    }

    /// Chrome with 30 extra idle connections and 12 active ones.
    fn busy_browser() -> View {
        let mut snap = snapshot();
        let helper = snap
            .processes
            .iter_mut()
            .find(|p| p.process.pid == 4901)
            .unwrap();
        let template = helper.flows[0].clone();
        for i in 0..42u16 {
            let mut f = template.clone();
            f.local.set_port(40_000 + i);
            f.rx_rate = if i < 12 { 1 + u64::from(i) } else { 0 };
            f.tx_rate = 0;
            helper.flows.push(f);
        }
        select(snap, &view_args(&["--name", "chrome"]))
    }

    #[test]
    fn single_c_shows_active_and_summarises_idle() {
        let view = busy_browser();
        let total = connection_rows(&view.apps[0]).len();
        assert_eq!(total, 45);
        let text = table(&view, 1);
        let listed = text.matches("└ tcp").count() + text.matches("└ udp").count();
        // 3 original active + 12 new active = 15 active, all shown even beyond 10.
        assert_eq!(listed, 15);
        assert!(text.contains(&format!(
            "… {} more idle connections (-cc lists all)",
            total - 15
        )));
    }

    #[test]
    fn single_c_fills_up_to_ten_and_double_c_shows_all() {
        let view = select(snapshot(), &view_args(&["--name", "chrome"]));
        let text = table(&view, 1);
        assert!(!text.contains("more idle"), "3 connections: nothing hidden");

        let view = busy_browser();
        let all = table(&view, 2);
        assert_eq!(
            all.matches("└ tcp").count() + all.matches("└ udp").count(),
            45
        );
        assert!(!all.contains("more idle"));
    }

    #[test]
    fn one_hidden_connection_uses_singular() {
        let mut snap = snapshot();
        let helper = snap
            .processes
            .iter_mut()
            .find(|p| p.process.pid == 4901)
            .unwrap();
        let template = helper.flows[0].clone();
        for i in 0..8u16 {
            let mut f = template.clone();
            f.local.set_port(41_000 + i);
            f.rx_rate = 0;
            f.tx_rate = 0;
            helper.flows.push(f);
        }
        let view = select(snap, &view_args(&["--name", "chrome"]));
        assert_eq!(connection_rows(&view.apps[0]).len(), 11);
        assert!(table(&view, 1).contains("… 1 more idle connection (-cc"));
    }

    #[test]
    fn connected_flows_are_never_merged() {
        let view = select(snapshot(), &view_args(&["--name", "discord"]));
        assert!(connection_rows(&view.apps[0]).iter().all(|r| r.count == 1));
    }

    #[test]
    fn long_names_keep_their_process_count() {
        let mut view = select(snapshot(), &view_args(&["--name", "chrome"]));
        view.apps[0].name = "An Extraordinarily Long Application Name".into();
        let label = app_label(&view.apps[0]);
        assert!(label.ends_with("… (2)"), "{label}");
        assert_eq!(label.chars().count(), NAME_WIDTH);
    }

    #[test]
    fn summary_counts_apps_processes_and_alerts() {
        let view = select(snapshot(), &view_args(&[]));
        let line = summary(&view);
        assert!(
            line.starts_with("6 applications (7 processes) · 9 connections"),
            "{line}"
        );
        assert!(line.contains("2 flagged"));

        let view = select(snapshot(), &view_args(&["--name", "spotify"]));
        assert!(summary(&view).starts_with("1 application · 1 connections"));
        assert!(summary(&view).contains("no alerts"));
    }
}
