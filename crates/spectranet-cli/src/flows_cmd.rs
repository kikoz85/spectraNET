//! `snet stream` and `snet inspect`: what kind of traffic connections carry, for scripts and
//! quick looks.

use std::collections::HashMap;
use std::io::Write;
use std::net::SocketAddr;
use std::thread;

use anstyle::{RgbColor, Style};
use serde::Serialize;
use spectranet_capture::TrafficSource;
use spectranet_model::flowmeta::{Certainty, Kind, Reason, TlsInfo};
use spectranet_model::{Flow, Snapshot, Transport};

use crate::cli::{InspectArgs, StreamArgs};
use crate::flowtext::{certainty_word, kind_style, kind_word, protocol, reason_text};
use crate::units::{rate, truncate_left};
use crate::view::{self, endpoint};

const DIM: Style = Style::new().dimmed();
const BOLD: Style = Style::new().bold();

/// One line of `snet stream --json`.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct StreamEvent {
    pub ts_ms: u64,
    pub pid: u32,
    pub process: String,
    pub transport: Transport,
    pub local: SocketAddr,
    pub remote: SocketAddr,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub host: Option<String>,
    pub kind: Kind,
    pub certainty: Certainty,
    pub reasons: Vec<Reason>,
    pub rx_rate: u64,
    pub tx_rate: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tls: Option<TlsInfo>,
}

type Key = (u32, Transport, SocketAddr, SocketAddr);

/// Classification changes between two snapshots: connections newly classified, or whose
/// kind or certainty changed.
pub fn changes(
    last: &mut HashMap<Key, (Kind, Certainty)>,
    snapshot: &Snapshot,
) -> Vec<StreamEvent> {
    let mut events = Vec::new();
    let mut seen = HashMap::new();
    for p in &snapshot.processes {
        for f in &p.flows {
            let Some(class) = &f.meta.class else {
                continue;
            };
            let key = (p.process.pid, f.transport, f.local, f.remote);
            let now = (class.kind, class.certainty);
            seen.insert(key, now);
            if last.get(&key) == Some(&now) {
                continue;
            }
            events.push(StreamEvent {
                ts_ms: snapshot.timestamp_ms,
                pid: p.process.pid,
                process: p.process.name.clone(),
                transport: f.transport,
                local: f.local,
                remote: f.remote,
                host: f.remote_host.clone(),
                kind: class.kind,
                certainty: class.certainty,
                reasons: class.reasons.clone(),
                rx_rate: f.rx_rate,
                tx_rate: f.tx_rate,
                tls: f.meta.tls.clone(),
            });
        }
    }
    *last = seen;
    events
}

fn clock(ts_ms: u64) -> String {
    i64::try_from(ts_ms / 1000)
        .ok()
        .and_then(|t| jiff::Timestamp::from_second(t).ok())
        .map(|t| {
            t.to_zoned(jiff::tz::TimeZone::system())
                .strftime("%H:%M:%S")
                .to_string()
        })
        .unwrap_or_default()
}

fn kind_tag(kind: Kind) -> String {
    let (symbol, tag, (r, g, b)) = kind_style(kind);
    let style = Style::new().fg_color(Some(RgbColor(r, g, b).into())).bold();
    format!("{style}{symbol} {tag}{style:#}")
}

/// `09:41:02 [PID 4102 chrome] → video.googlevideo.com:443 | 2.1 MB/s | 🎥 VIDEO (known service) — reason`
pub fn stream_line(e: &StreamEvent) -> String {
    let destination = match &e.host {
        Some(h) => format!("{h}:{}", e.remote.port()),
        None => e.remote.to_string(),
    };
    let first_reason = e.reasons.first().map(reason_text).unwrap_or_default();
    format!(
        "{DIM}{}{DIM:#} [PID {} {}] → {:<40} | {:>10} | {} {DIM}({}){DIM:#} {first_reason}",
        clock(e.ts_ms),
        e.pid,
        e.process,
        truncate_left(&destination, 40),
        rate(e.rx_rate + e.tx_rate),
        kind_tag(e.kind),
        certainty_word(e.certainty),
    )
}

pub fn stream(source: &mut dyn TrafficSource, args: &StreamArgs) -> anyhow::Result<()> {
    if !source.first_sample_has_rates() {
        source.sample()?;
        thread::sleep(args.view.interval);
    }
    let mut last = HashMap::new();
    let mut printed = 0u64;
    let mut out = anstream::stdout();
    loop {
        let snapshot = view::select(source.sample()?, &args.view).into_snapshot();
        for event in changes(&mut last, &snapshot) {
            if args.view.json {
                serde_json::to_writer(&mut out, &event)?;
                writeln!(out)?;
            } else {
                writeln!(out, "{}", stream_line(&event))?;
            }
            printed += 1;
            if args.count.is_some_and(|c| printed >= c) {
                return Ok(());
            }
        }
        out.flush()?;
        thread::sleep(args.view.interval);
    }
}

/// One connection in `snet inspect` (text).
fn inspect_flow(out: &mut String, f: &Flow) {
    use std::fmt::Write as _;
    let proto = match protocol(f) {
        p if p.is_empty() => match f.transport {
            Transport::Tcp => "tcp".to_string(),
            Transport::Udp => "udp".to_string(),
        },
        p => p,
    };
    // Padded by visible width (the symbols are two columns wide).
    let kind = match &f.meta.class {
        Some(c) => {
            let (_, tag, _) = kind_style(c.kind);
            format!(
                "{}{}",
                kind_tag(c.kind),
                " ".repeat(11usize.saturating_sub(tag.len()))
            )
        }
        None => format!("{DIM}·{DIM:#}{}", " ".repeat(13)),
    };
    let pps = match (f.meta.rx_pps, f.meta.tx_pps) {
        (Some(r), Some(t)) => format!("{r}/{t} pkt/s"),
        _ => String::new(),
    };
    let _ = writeln!(
        out,
        "  {kind} {:<44} {DIM}{proto:<16}{DIM:#} ▼ {:>10} ▲ {:>10} {DIM}{pps}{DIM:#}",
        truncate_left(&endpoint(f), 44),
        rate(f.rx_rate),
        rate(f.tx_rate),
    );
    if let Some(c) = &f.meta.class {
        let _ = writeln!(
            out,
            "      {BOLD}probably {}{BOLD:#} — {}",
            kind_word(c.kind),
            certainty_word(c.certainty)
        );
        for r in &c.reasons {
            let _ = writeln!(out, "      {DIM}• {}{DIM:#}", reason_text(r));
        }
    }
    if let Some(tls) = &f.meta.tls {
        let mut parts = Vec::new();
        if let Some(v) = &tls.version {
            parts.push(v.clone());
        }
        if let Some(c) = &tls.cipher {
            parts.push(c.clone());
        }
        if let Some(j) = &tls.ja4 {
            parts.push(format!("JA4 {j}"));
        }
        if !parts.is_empty() {
            let _ = writeln!(out, "      {DIM}🔒 {}{DIM:#}", parts.join(" · "));
        }
    }
}

pub fn render_inspect(view: &view::View) -> String {
    use std::fmt::Write as _;
    let mut out = String::new();
    if view.apps.is_empty() {
        return "no matching process with network activity\n".into();
    }
    for app in &view.apps {
        let pids: Vec<String> = app
            .processes
            .iter()
            .map(|p| p.process.pid.to_string())
            .collect();
        let _ = writeln!(
            out,
            "{BOLD}{}{BOLD:#} {DIM}(pid {}) · {} connections · ▼ {} ▲ {}{DIM:#}",
            app.name,
            pids.join(", "),
            app.flow_count(),
            rate(app.rx_rate),
            rate(app.tx_rate)
        );
        let mut kinds: HashMap<Kind, u64> = HashMap::new();
        for f in app.processes.iter().flat_map(|p| &p.flows) {
            if let Some(c) = &f.meta.class {
                *kinds.entry(c.kind).or_default() += f.rx_rate + f.tx_rate;
            }
        }
        if !kinds.is_empty() {
            let mut kinds: Vec<_> = kinds.into_iter().collect();
            kinds.sort_by_key(|(_, r)| std::cmp::Reverse(*r));
            let summary: Vec<String> = kinds
                .iter()
                .map(|(k, r)| format!("{} {}", kind_tag(*k), rate(*r)))
                .collect();
            let _ = writeln!(out, "  {}", summary.join("   "));
        }
        let mut flows: Vec<&Flow> = app.processes.iter().flat_map(|p| &p.flows).collect();
        flows.sort_by_key(|f| std::cmp::Reverse(f.activity()));
        for f in flows
            .into_iter()
            .filter(|f| !f.remote.ip().is_unspecified())
        {
            inspect_flow(&mut out, f);
        }
        out.push('\n');
    }
    out
}

pub fn inspect(source: &mut dyn TrafficSource, args: &InspectArgs) -> anyhow::Result<()> {
    // Patterns need a few seconds of traffic: sample for the requested time.
    let samples = (args.wait.as_secs_f64() / args.view.interval.as_secs_f64())
        .ceil()
        .max(1.0) as u32;
    if !source.first_sample_has_rates() {
        source.sample()?;
    }
    let mut snapshot = None;
    for _ in 0..samples {
        thread::sleep(args.view.interval);
        snapshot = Some(source.sample()?);
    }
    let Some(snapshot) = snapshot else {
        return Ok(());
    };
    let view = view::select(snapshot, &args.view);
    let mut out = anstream::stdout().lock();
    if args.view.json {
        serde_json::to_writer(&mut out, &view.into_snapshot())?;
        writeln!(out)?;
    } else {
        write!(out, "{}", render_inspect(&view))?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use spectranet_model::flowmeta::Class;
    use spectranet_model::{Process, ProcessTraffic, Verdict};

    fn snapshot(kind: Option<Kind>, certainty: Certainty) -> Snapshot {
        let mut flow = Flow {
            transport: Transport::Tcp,
            local: "192.168.1.2:50000".parse().unwrap(),
            remote: "142.250.180.14:443".parse().unwrap(),
            remote_host: Some("rr1.googlevideo.com".into()),
            rx_rate: 2_000_000,
            tx_rate: 1_000,
            rx_bytes: 0,
            tx_bytes: 0,
            verdict: Verdict::Ok,
            note: None,
            meta: Default::default(),
        };
        flow.meta.class = kind.map(|kind| Class {
            kind,
            certainty,
            reasons: vec![Reason::KnownHost {
                domain: "googlevideo.com".into(),
            }],
        });
        Snapshot {
            source: "t".into(),
            timestamp_ms: 1_760_000_000_000,
            interval_ms: 1000,
            processes: vec![ProcessTraffic::new(
                Process {
                    pid: 4102,
                    name: "chrome".into(),
                    path: None,
                    app: None,
                },
                vec![flow],
            )],
        }
    }

    #[test]
    fn stream_reports_only_changes() {
        let mut last = HashMap::new();
        assert!(changes(&mut last, &snapshot(None, Certainty::Likely)).is_empty());
        let first = changes(&mut last, &snapshot(Some(Kind::Video), Certainty::Likely));
        assert_eq!(first.len(), 1);
        assert!(changes(&mut last, &snapshot(Some(Kind::Video), Certainty::Likely)).is_empty());
        let upgraded = changes(&mut last, &snapshot(Some(Kind::Video), Certainty::Declared));
        assert_eq!(upgraded[0].certainty, Certainty::Declared);
        let line = stream_line(&upgraded[0]);
        assert!(line.contains("[PID 4102 chrome]") && line.contains("rr1.googlevideo.com:443"));
        let json = serde_json::to_string(&upgraded[0]).unwrap();
        assert!(json.contains("\"kind\":\"video\"") && json.contains("\"certainty\":\"declared\""));
    }

    #[test]
    fn inspect_explains_each_connection() {
        let view = view::View {
            source: "t".into(),
            timestamp_ms: 0,
            interval_ms: 1000,
            apps: spectranet_model::group_by_app(
                snapshot(Some(Kind::Video), Certainty::Declared).processes,
            ),
        };
        let text = render_inspect(&view);
        assert!(text.contains("probably video streaming"), "{text}");
        assert!(text.contains("googlevideo.com is a known service"));
    }
}
