//! `snet record` and `snet analyze`: the Flight Recorder.

use std::fmt::Write as _;
use std::fs::OpenOptions;
use std::io::{BufReader, BufWriter, IsTerminal, Write};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

use anstyle::{AnsiColor, Style};
use anyhow::{Context, Result};
use spectranet_capture::TrafficSource;
use spectranet_intel::analysis::{self, Report};
use spectranet_model::record::{Footer, Header, RecordLine};
use spectranet_model::{Process, Snapshot, Verdict};
use spectranet_proto::Subscription;

use crate::cli::{AnalyzeArgs, RecordArgs};
use crate::units::{bytes, truncate, truncate_left};

const HEADER: Style = Style::new().bold();
const DIM: Style = Style::new().dimmed();

/// Where snapshots come from while recording.
pub enum Feed {
    /// Every sample snetd takes, exactly once.
    Service(Subscription),
    /// Sampling here, at `interval`.
    Direct {
        source: Box<dyn TrafficSource>,
        interval: Duration,
        primed: bool,
    },
}

impl Feed {
    fn next(&mut self, stop: &AtomicBool) -> Option<Result<Snapshot>> {
        match self {
            Self::Service(stream) => stream.next().map(|r| r.map_err(Into::into)),
            Self::Direct {
                source,
                interval,
                primed,
            } => {
                if !*primed
                    && !source.first_sample_has_rates()
                    && let Err(e) = source.sample()
                {
                    return Some(Err(e.into()));
                }
                *primed = true;
                let deadline = Instant::now() + *interval;
                while Instant::now() < deadline {
                    if stop.load(Ordering::Relaxed) {
                        return None;
                    }
                    std::thread::sleep(Duration::from_millis(20).min(*interval));
                }
                Some(source.sample().map_err(Into::into))
            }
        }
    }

    fn source_name(&self) -> String {
        match self {
            Self::Service(_) => "snetd".into(),
            Self::Direct { source, .. } => source.name().into(),
        }
    }
}

/// Keeps only the processes the recording is about. No filter means everything.
pub fn keep(process: &Process, names: &[String], pids: &[u32]) -> bool {
    if names.is_empty() && pids.is_empty() {
        return true;
    }
    if pids.contains(&process.pid) {
        return true;
    }
    let own = process.name.to_lowercase();
    let app = process.app.as_ref().map(|a| a.name.to_lowercase());
    names
        .iter()
        .map(|n| n.to_lowercase())
        .any(|n| own.contains(&n) || app.as_ref().is_some_and(|a| a.contains(&n)))
}

fn default_path() -> PathBuf {
    let now = jiff::Zoned::now();
    PathBuf::from(format!(
        "snet-record-{}.jsonl",
        now.strftime("%Y%m%d-%H%M%S")
    ))
}

pub fn record(mut feed: Feed, args: &RecordArgs) -> Result<()> {
    let path = args.output.clone().unwrap_or_else(default_path);
    let file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&path)
        .with_context(|| {
            format!(
                "creating {} (existing files are never overwritten)",
                path.display()
            )
        })?;
    let mut out = BufWriter::new(file);

    let stop = Arc::new(AtomicBool::new(false));
    for signal in [signal_hook::consts::SIGINT, signal_hook::consts::SIGTERM] {
        signal_hook::flag::register(signal, stop.clone())?;
    }

    let started = Instant::now();
    let hostname = std::process::Command::new("hostname")
        .output()
        .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string())
        .unwrap_or_default();
    let interval_ms = match &feed {
        Feed::Direct { interval, .. } => interval.as_millis() as u64,
        Feed::Service(_) => 0,
    };
    let header = Header::new(
        now_ms(),
        hostname,
        interval_ms,
        feed.source_name(),
        args.names.clone(),
        args.pids.clone(),
    );
    write_line(&mut out, &RecordLine::Header(header))?;

    let what = if args.names.is_empty() && args.pids.is_empty() {
        "all applications".to_string()
    } else {
        let mut parts: Vec<String> = args.names.iter().map(|n| format!("'{n}'")).collect();
        parts.extend(args.pids.iter().map(|p| format!("pid {p}")));
        parts.join(", ")
    };
    let progress = std::io::stderr().is_terminal();
    eprintln!(
        "snet: recording {what} to {} (Ctrl-C to stop)",
        path.display()
    );

    let (mut samples, mut rx, mut tx) = (0u64, 0u64, 0u64);
    let mut destinations = std::collections::HashSet::new();
    let mut problem = None;
    while !stop.load(Ordering::Relaxed) && args.duration.is_none_or(|d| started.elapsed() < d) {
        let Some(next) = feed.next(&stop) else { break };
        let mut snapshot = match next {
            Ok(s) => s,
            Err(e) => {
                // A transient hiccup (e.g. the service skipped a sample) is noted, not fatal.
                eprintln!("\nsnet: {e:#}");
                problem = Some(e);
                continue;
            }
        };
        snapshot
            .processes
            .retain(|p| keep(&p.process, &args.names, &args.pids));
        for p in &snapshot.processes {
            rx += u64::try_from(u128::from(p.rx_rate) * u128::from(snapshot.interval_ms) / 1000)
                .unwrap_or(0);
            tx += u64::try_from(u128::from(p.tx_rate) * u128::from(snapshot.interval_ms) / 1000)
                .unwrap_or(0);
            destinations.extend(
                p.flows
                    .iter()
                    .filter(|f| !f.remote.ip().is_unspecified())
                    .map(|f| f.remote),
            );
        }
        write_line(&mut out, &RecordLine::Sample { snapshot })?;
        samples += 1;
        if progress {
            let secs = started.elapsed().as_secs();
            eprint!(
                "\r\x1b[2K● {:02}:{:02}:{:02} · {samples} samples · {} destinations · ▼ {} ▲ {}",
                secs / 3600,
                secs / 60 % 60,
                secs % 60,
                destinations.len(),
                bytes(rx),
                bytes(tx)
            );
        }
    }
    write_line(
        &mut out,
        &RecordLine::Footer(Footer {
            ended_ms: now_ms(),
            samples,
        }),
    )?;
    out.flush()?;
    if progress {
        eprintln!();
    }
    eprintln!("snet: saved {samples} samples to {}", path.display());
    eprintln!("snet: analyse it with: snet analyze {}", shell_quote(&path));
    if samples == 0
        && let Some(e) = problem
    {
        return Err(e);
    }
    Ok(())
}

fn write_line(out: &mut impl Write, line: &RecordLine) -> Result<()> {
    serde_json::to_writer(&mut *out, line)?;
    out.write_all(b"\n")?;
    // Every sample reaches the disk immediately: an abrupt stop loses at most the current one.
    out.flush()?;
    Ok(())
}

fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_millis() as u64)
}

fn shell_quote(path: &Path) -> String {
    let text = path.display().to_string();
    if text
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || "-_./".contains(c))
    {
        text
    } else {
        format!("'{}'", text.replace('\'', "'\\''"))
    }
}

pub fn analyze(args: &AnalyzeArgs) -> Result<()> {
    let file = std::fs::File::open(&args.file)
        .with_context(|| format!("opening {}", args.file.display()))?;
    let feeds = Path::new(spectranet_proto::DEFAULT_DATA_DIR).join(spectranet_proto::FEEDS_SUBDIR);
    let report = analysis::analyze(BufReader::new(file), &spectranet_intel::Intel::load(&feeds))
        .with_context(|| format!("reading {}", args.file.display()))?;
    let mut out = anstream::stdout().lock();
    if args.json {
        serde_json::to_writer(&mut out, &report)?;
        writeln!(out)?;
    } else {
        write!(out, "{}", render(&report, &args.file, args.limit))?;
    }
    Ok(())
}

fn clock(ms: u64) -> String {
    i64::try_from(ms / 1000)
        .ok()
        .and_then(|s| jiff::Timestamp::from_second(s).ok())
        .map(|t| {
            t.to_zoned(jiff::tz::TimeZone::system())
                .strftime("%Y-%m-%d %H:%M:%S")
                .to_string()
        })
        .unwrap_or_else(|| "?".into())
}

fn offset(ms: u64) -> String {
    let s = ms / 1000;
    format!("{:02}:{:02}:{:02}", s / 3600, s / 60 % 60, s % 60)
}

pub fn render(report: &Report, file: &Path, limit: usize) -> String {
    let mut out = String::new();
    let _ = writeln!(
        out,
        "{HEADER}Flight Recorder{HEADER:#} {DIM}· {}{DIM:#}",
        file.display()
    );
    if let Some(h) = &report.header {
        let filter = if h.names.is_empty() && h.pids.is_empty() {
            "all applications".to_string()
        } else {
            let mut parts = h.names.clone();
            parts.extend(h.pids.iter().map(|p| format!("pid {p}")));
            parts.join(", ")
        };
        let _ = writeln!(
            out,
            "host {} · recorded {filter} · source {}",
            h.hostname, h.source
        );
    }
    let _ = writeln!(
        out,
        "{} → {} · {} · {} samples · ▼ {} ▲ {}",
        clock(report.started_ms),
        clock(report.ended_ms),
        offset(report.ended_ms.saturating_sub(report.started_ms)),
        report.samples,
        bytes(report.rx),
        bytes(report.tx)
    );
    let warn = AnsiColor::Yellow.on_default();
    if report.truncated {
        let _ = writeln!(
            out,
            "{warn}⚠ the recording was interrupted (no end marker); analysed up to where it stops{warn:#}"
        );
    }
    if report.corrupt_lines > 0 {
        let _ = writeln!(
            out,
            "{warn}⚠ {} unreadable lines were skipped{warn:#}",
            report.corrupt_lines
        );
    }

    let _ = writeln!(out, "\n{HEADER}FINDINGS{HEADER:#}");
    if report.findings.is_empty() {
        let _ = writeln!(out, "  nothing suspicious in this recording");
    }
    for f in &report.findings {
        let style = match f.verdict {
            Verdict::Alert => AnsiColor::Red.on_default().bold(),
            Verdict::Warn => AnsiColor::Yellow.on_default(),
            Verdict::Ok => AnsiColor::Cyan.on_default(),
        };
        let level = match f.verdict {
            Verdict::Alert => "ALERT",
            Verdict::Warn => "WARN",
            Verdict::Ok => "INFO",
        };
        let subject = match (&f.app, &f.destination) {
            (Some(app), Some(dest)) => format!("{app} → {dest}"),
            (Some(app), None) => app.clone(),
            (None, Some(dest)) => format!("→ {dest}"),
            (None, None) => String::new(),
        };
        let _ = writeln!(
            out,
            "  {style}{level:<5}{style:#}  {subject}\n         {DIM}{}{DIM:#}",
            f.message
        );
    }

    let _ = writeln!(
        out,
        "\n{HEADER}{:<32} {:>16} {:>11} {:>11}{HEADER:#}",
        "APPLICATION", "PIDS", "▼ RECEIVED", "▲ SENT"
    );
    for app in &report.apps {
        let pids: Vec<String> = app.pids.iter().map(u32::to_string).collect();
        let _ = writeln!(
            out,
            "{:<32} {:>16} {:>11} {:>11}",
            truncate(&app.name, 32),
            truncate(&pids.join(","), 16),
            bytes(app.rx),
            bytes(app.tx)
        );
    }

    let shown = report.destinations.len().min(limit);
    let _ = writeln!(
        out,
        "\n{HEADER}{:<44} {:>5} {:>5} {:>11} {:>11} {:>9} {:>9}{HEADER:#}",
        format!("DESTINATIONS ({shown} of {})", report.destinations.len()),
        "PROTO",
        "CONN",
        "▼ RECEIVED",
        "▲ SENT",
        "FIRST",
        "LAST"
    );
    for d in report.destinations.iter().take(limit) {
        let label = format!("{}:{}", d.label, d.address.port());
        let _ = writeln!(
            out,
            "{:<44} {:>5} {:>5} {:>11} {:>11} {:>9} {:>9}",
            truncate_left(&label, 44),
            d.transport,
            d.connections,
            bytes(d.rx),
            bytes(d.tx),
            offset(d.first_ms.saturating_sub(report.started_ms)),
            offset(d.last_ms.saturating_sub(report.started_ms))
        );
    }
    out
}

#[cfg(test)]
mod tests {
    use spectranet_model::App;

    use super::*;

    fn process(pid: u32, name: &str, app: Option<&str>) -> Process {
        Process {
            pid,
            name: name.into(),
            path: None,
            app: app.map(|a| App {
                name: a.into(),
                path: format!("/Applications/{a}.app"),
                main: false,
            }),
        }
    }

    #[test]
    fn filter_by_name_app_or_pid() {
        let helper = process(10, "Google Chrome Helper", Some("Google Chrome"));
        let curl = process(20, "curl", None);
        let names = vec!["CHROME".to_string()];
        assert!(keep(&helper, &names, &[]));
        assert!(!keep(&curl, &names, &[]));
        assert!(keep(&curl, &names, &[20]));
        assert!(keep(&curl, &[], &[]), "no filter records everything");
        assert!(
            keep(&helper, &["google chrome".to_string()], &[]),
            "matches the app name"
        );
    }

    #[test]
    fn quoting_for_the_hint() {
        assert_eq!(
            shell_quote(Path::new("snet-record-1.jsonl")),
            "snet-record-1.jsonl"
        );
        assert_eq!(
            shell_quote(Path::new("my file's.jsonl")),
            "'my file'\\''s.jsonl'"
        );
    }
}
