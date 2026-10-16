//! `snet check` — "Is my network slow?": router, internet and DNS measured in about ten
//! seconds, next to what the applications are doing, and a plain verdict.
//!
//! With snetd running the service runs the check (it knows the usual latency and the recent
//! traffic peak, and keeps the result in its history); otherwise it runs here.

use std::fmt::Write as _;
use std::io::{IsTerminal, Write};
use std::path::Path;
use std::time::Duration;

use spectranet_capture::{SourceOptions, TrafficSource, system_source};
use spectranet_probe::{Apps, Dns, Hop, Latency, Method, Probe, Report, Verdict};
use spectranet_proto::{Client, ClientError, Command, Reply};

use anstyle::{AnsiColor, Style};

use crate::cli::{CheckArgs, Cli};
use crate::units;

const HEADER: Style = Style::new().bold();
const DIM: Style = Style::new().dimmed();
const GOOD: Style = AnsiColor::Green.on_default();
const WARN: Style = AnsiColor::Yellow.on_default();
const BAD: Style = AnsiColor::Red.on_default().bold();

fn verdict_color(v: &Verdict) -> Style {
    match v {
        Verdict::AllGood => GOOD.bold(),
        Verdict::Unmeasured => DIM,
        Verdict::App { .. } | Verdict::DnsSlow => WARN.bold(),
        _ => BAD,
    }
}

/// Exit codes of `snet check`.
pub const OK: i32 = 0;
pub const PROBLEM: i32 = 1;
pub const ERROR: i32 = 2;

/// How long the service may take to answer (a check with the path takes up to a minute).
const SERVICE_TIMEOUT: Duration = Duration::from_secs(120);

pub fn run(cli: &Cli, args: &CheckArgs) -> i32 {
    match run_inner(cli, args) {
        Ok(code) => code,
        Err(e) => {
            anstream::eprintln!("snet: {e:#}");
            ERROR
        }
    }
}

fn run_inner(cli: &Cli, args: &CheckArgs) -> anyhow::Result<i32> {
    if let Some(limit) = args.history {
        return history(&cli.socket, limit, args.json);
    }
    let interactive = !args.json && std::io::stderr().is_terminal();
    if interactive {
        anstream::eprintln!(
            "Checking the router, the internet and DNS… (about 5 seconds{})",
            if args.path { ", then the path" } else { "" }
        );
    }
    let report = match (!cli.no_daemon && !cli.mock)
        .then(|| via_service(&cli.socket, args))
        .flatten()
    {
        Some(report) => report,
        None => locally(cli, args),
    };
    let mut out = anstream::stdout().lock();
    if args.json {
        serde_json::to_writer(&mut out, &report)?;
        writeln!(out)?;
    } else {
        write!(out, "{}", render(&report))?;
    }
    Ok(exit_code(&report.verdict))
}

pub fn exit_code(verdict: &Verdict) -> i32 {
    match verdict {
        Verdict::Unmeasured => ERROR,
        v if v.is_problem() => PROBLEM,
        _ => OK,
    }
}

/// The check run by snetd, or `None` when it isn't running or can't (an older version).
fn via_service(socket: &Path, args: &CheckArgs) -> Option<Report> {
    let mut client = match crate::daemon::connect(socket) {
        Ok(c) => c,
        Err(ClientError::NotRunning | ClientError::Unsupported) => return None,
        Err(e) => {
            anstream::eprintln!("snet: not using snetd ({e}); checking from here");
            return None;
        }
    };
    let call = |client: &mut Client| {
        client.set_timeout(SERVICE_TIMEOUT)?;
        client.call(Command::Check {
            targets: args.targets.clone(),
            path: args.path,
        })
    };
    match call(&mut client) {
        Ok(Reply::Check(report)) => Some(*report),
        Ok(_) | Err(ClientError::Protocol(_)) => {
            anstream::eprintln!(
                "snet: this snetd can't run network checks (update it); checking from here"
            );
            None
        }
        Err(e) => {
            anstream::eprintln!("snet: snetd did not answer ({e}); checking from here");
            None
        }
    }
}

/// The check run in this process, the applications sampled directly.
fn locally(cli: &Cli, args: &CheckArgs) -> Report {
    let config = spectranet_probe::check::Config {
        targets: args.targets.clone(),
        path: args.path,
        ..Default::default()
    };
    let source: Option<Box<dyn TrafficSource>> = if cli.mock {
        Some(Box::new(spectranet_capture::mock::MockSource::default()))
    } else {
        system_source(SourceOptions {
            resolve_names: false,
            service: false,
        })
        .ok()
    };
    spectranet_probe::check::run(
        &config,
        |window| match source {
            Some(source) => sample_apps(source, window),
            None => Apps::default(),
        },
        None,
        |_| {},
    )
}

/// Samples the applications once a second for `window`.
fn sample_apps(mut source: Box<dyn TrafficSource>, window: Duration) -> Apps {
    let started = std::time::Instant::now();
    if !source.first_sample_has_rates() {
        let _ = source.sample();
    }
    let mut snapshots = Vec::new();
    while started.elapsed() < window {
        std::thread::sleep(Duration::from_secs(1));
        if let Ok(s) = source.sample() {
            snapshots.push(s);
        }
    }
    spectranet_probe::apps::from_snapshots(&snapshots, None)
}

/// The latest checks kept by snetd.
fn history(socket: &Path, limit: u32, json: bool) -> anyhow::Result<i32> {
    let reply = crate::daemon::connect(socket)
        .and_then(|mut c| c.call(Command::Checks { limit }))
        .map_err(|e| anyhow::anyhow!("the history of checks needs snetd 1.3.0 or later ({e})"))?;
    let Reply::Checks { reports } = reply else {
        anyhow::bail!("snetd sent an unexpected reply");
    };
    let mut out = anstream::stdout().lock();
    if json {
        serde_json::to_writer(&mut out, &reports)?;
        writeln!(out)?;
    } else {
        write!(out, "{}", render_history(&reports))?;
    }
    Ok(OK)
}

pub fn render_history(reports: &[Report]) -> String {
    if reports.is_empty() {
        return "No network checks recorded yet (run: snet check)\n".into();
    }
    let mut out = String::new();
    for r in reports {
        let when = jiff::Timestamp::from_millisecond(r.started_ms as i64)
            .map(|t| {
                t.to_zoned(jiff::tz::TimeZone::system())
                    .strftime("%Y-%m-%d %H:%M")
                    .to_string()
            })
            .unwrap_or_default();
        let internet = r
            .internet
            .iter()
            .filter_map(Probe::measured)
            .filter(|l| l.received > 0)
            .map(|l| l.avg_ms)
            .min_by(f64::total_cmp)
            .map_or("–".into(), |ms| format!("{ms:.0} ms"));
        let _ = writeln!(
            out,
            "{when}  {style}{} {:<44}{style:#} internet {internet}",
            mark(&r.verdict),
            headline(&r.verdict),
            style = verdict_color(&r.verdict)
        );
    }
    out
}

fn mark(verdict: &Verdict) -> &'static str {
    match verdict {
        Verdict::AllGood => "✔",
        Verdict::Unmeasured => "?",
        Verdict::App { .. } | Verdict::DnsSlow => "⚠",
        _ => "✖",
    }
}

/// The verdict in a few words.
pub fn headline(verdict: &Verdict) -> String {
    match verdict {
        Verdict::AllGood => "All good: the network is not slow".into(),
        Verdict::LocalLink => "It's the link to the router (Wi-Fi or cable)".into(),
        Verdict::Provider => "It's the line, past the router (line or provider)".into(),
        Verdict::Line => "It's the line (the router can't be measured)".into(),
        Verdict::DnsSlow => "DNS is slow".into(),
        Verdict::App { name } => format!("It's {name}: it is filling the connection"),
        Verdict::Unmeasured => "Nothing could be measured".into(),
    }
}

/// One sentence with the numbers behind the verdict.
fn because(r: &Report) -> String {
    let best = r
        .internet
        .iter()
        .filter_map(Probe::measured)
        .filter(|l| l.received > 0)
        .min_by(|a, b| a.avg_ms.total_cmp(&b.avg_ms));
    let usual = r
        .baseline_ms
        .map_or(String::new(), |u| format!(" (usually {u:.0} ms)"));
    match &r.verdict {
        Verdict::AllGood => match best {
            Some(l) => format!(
                "Router, internet ({:.0} ms{}) and DNS answer normally.",
                l.avg_ms,
                r.baseline_ms
                    .map_or(String::new(), |u| format!(", usually {u:.0}"))
            ),
            None => "Router and DNS answer normally.".into(),
        },
        Verdict::LocalLink => match r.gateway.measured() {
            Some(g) if g.received == 0 => {
                "The router stopped answering: check the Wi-Fi signal or the cable.".into()
            }
            Some(g) => format!(
                "The router answers in {:.0} ms with {:.0}% loss (should be under 30 ms, no loss): \
                 move closer to the Wi-Fi, or try a cable.",
                g.avg_ms,
                g.loss_percent()
            ),
            None => String::new(),
        },
        Verdict::Provider | Verdict::Line => {
            let start = if matches!(r.verdict, Verdict::Provider) {
                "The router is fine, but the internet"
            } else {
                "The internet"
            };
            match best {
                Some(l) => format!(
                    "{start} answers in {:.0} ms{usual} with {:.0}% loss: \
                     restart the modem, or ask the provider.",
                    l.avg_ms,
                    l.loss_percent()
                ),
                None => format!("{start} does not answer: restart the modem, or ask the provider."),
            }
        }
        Verdict::DnsSlow => match r.dns.measured() {
            Some(d) if !d.resolves => {
                "The network works, but names don't resolve: the DNS server is not answering."
                    .into()
            }
            Some(d) => format!(
                "The network works, but a name takes {:.0} ms to resolve (should be under 300 ms): \
                 try another DNS server.",
                d.median_ms
            ),
            None => String::new(),
        },
        Verdict::App { name } => {
            let share = r.apps.top.first().map_or(0.0, |a| a.share * 100.0).round();
            format!(
                "The network is fine, but {name} uses {share:.0}% of the traffic \
                 (↓ {} ↑ {}): pause it to get the bandwidth back.",
                units::rate(r.apps.total_rx),
                units::rate(r.apps.total_tx)
            )
        }
        Verdict::Unmeasured => "No router, internet target or DNS server could be reached: \
                                is this computer connected?"
            .into(),
    }
}

/// How a latency was measured, as shown beside it.
pub fn method(m: Method) -> String {
    match m {
        Method::Icmp => "ICMP".into(),
        Method::Tcp { port } => format!("TCP:{port}"),
    }
}

fn latency_line(out: &mut String, label: &str, p: &Probe<Latency>) {
    match p {
        Probe::Measured(l) if l.received == 0 => {
            let _ = writeln!(
                out,
                "  {HEADER}{label:<9}{HEADER:#} {:<18} {BAD}no answer (100% loss){BAD:#}",
                l.address.to_string()
            );
        }
        Probe::Measured(l) => {
            // A name with its address when both fit, else just the name.
            let host = format!("{} ({})", l.target, l.address);
            let host = if l.target == l.address.to_string() || host.chars().count() > 18 {
                l.target.clone()
            } else {
                host
            };
            let style = match l.method {
                Method::Icmp => GOOD,
                Method::Tcp { .. } => WARN,
            };
            let loss = l.loss_percent();
            let loss_style = if loss > 0.0 { WARN } else { Style::new() };
            let _ = writeln!(
                out,
                "  {HEADER}{label:<9}{HEADER:#} {:<18} {style}{:<7}{style:#} avg {:>5.1} ms  min {:.1}  max {:.1}  jitter {:.1}  {loss_style}loss {:.0}%{loss_style:#}",
                units::truncate(&host, 18),
                method(l.method),
                l.avg_ms,
                l.min_ms,
                l.max_ms,
                l.jitter_ms,
                loss
            );
        }
        Probe::Unmeasurable { why } => {
            let _ = writeln!(
                out,
                "  {HEADER}{label:<9}{HEADER:#} {DIM}not measurable: {why}{DIM:#}"
            );
        }
    }
}

fn dns_line(out: &mut String, p: &Probe<Dns>) {
    match p {
        Probe::Measured(d) => {
            let each: Vec<String> = d.lookups_ms.iter().map(|ms| format!("{ms:.0}")).collect();
            let _ = writeln!(
                out,
                "  {HEADER}DNS{HEADER:#}       system resolver    median {:.0} ms ({} ms){}",
                d.median_ms,
                each.join(", "),
                if d.resolves {
                    ""
                } else {
                    " · known names don't resolve"
                }
            );
        }
        Probe::Unmeasurable { why } => {
            let _ = writeln!(
                out,
                "  {HEADER}DNS{HEADER:#}       {DIM}not measurable: {why}{DIM:#}"
            );
        }
    }
}

fn apps_lines(out: &mut String, apps: &Apps) {
    let _ = writeln!(
        out,
        "  {HEADER}Apps{HEADER:#}      ↓ {} ↑ {}{}",
        units::rate(apps.total_rx),
        units::rate(apps.total_tx),
        apps.recent_peak.map_or(String::new(), |p| format!(
            " (recent peak {})",
            units::rate(p)
        ))
    );
    for a in apps
        .top
        .iter()
        .take(5)
        .filter(|a| a.rx_rate + a.tx_rate > 0)
    {
        let _ = writeln!(
            out,
            "            {:<22} ↓ {:>11} ↑ {:>11}  {:>3.0}%",
            units::truncate(&a.name, 22),
            units::rate(a.rx_rate),
            units::rate(a.tx_rate),
            a.share * 100.0
        );
    }
}

fn path_lines(out: &mut String, p: &Probe<Vec<Hop>>) {
    match p {
        Probe::Measured(hops) => {
            let _ = writeln!(out, "\n{HEADER}Path{HEADER:#} (ICMP, hop by hop)");
            for h in hops {
                let addr = h.address.map_or("*".into(), |a| a.to_string());
                let rtt = h.avg_ms.map_or("–".into(), |ms| format!("{ms:.1} ms"));
                let loss = f64::from(h.sent - h.received) * 100.0 / f64::from(h.sent.max(1));
                let _ = writeln!(out, "  {:>2}  {addr:<39} {rtt:>9}  loss {loss:.0}%", h.ttl);
            }
        }
        Probe::Unmeasurable { why } => {
            let _ = writeln!(out, "\nPath      not measurable: {why}");
        }
    }
}

/// The report for a terminal: the verdict first, then the details.
pub fn render(r: &Report) -> String {
    let mut out = String::new();
    let style = verdict_color(&r.verdict);
    let _ = writeln!(
        out,
        "{style}{} {}{style:#}",
        mark(&r.verdict),
        headline(&r.verdict)
    );
    let reason = because(r);
    if !reason.is_empty() {
        let _ = writeln!(out, "  {reason}");
    }
    let _ = writeln!(out);
    latency_line(&mut out, "Router", &r.gateway);
    for (i, p) in r.internet.iter().enumerate() {
        latency_line(&mut out, if i == 0 { "Internet" } else { "" }, p);
    }
    if let Some(u) = r.baseline_ms {
        let _ = writeln!(out, "  {:<9} usual internet latency {u:.0} ms", "");
    }
    dns_line(&mut out, &r.dns);
    apps_lines(&mut out, &r.apps);
    if let Some(p) = &r.path {
        path_lines(&mut out, p);
    }
    let _ = writeln!(
        out,
        "\n{DIM}Checked in {:.1} s. TCP:port means ICMP was not available and the time to open a \
         connection was measured instead (a little higher than a ping).{DIM:#}",
        r.duration_ms as f64 / 1000.0
    );
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use spectranet_probe::AppLoad;

    fn render(r: &Report) -> String {
        anstream::adapter::strip_str(&super::render(r)).to_string()
    }

    fn lat(target: &str, method: Method, avg: f64, received: u32) -> Probe<Latency> {
        let samples: Vec<Option<f64>> = (0..20).map(|i| (i < received).then_some(avg)).collect();
        Probe::Measured(Latency::from_samples(
            target,
            target.parse().unwrap(),
            method,
            &samples,
        ))
    }

    fn report(verdict: Verdict) -> Report {
        Report {
            started_ms: 1_700_000_000_000,
            duration_ms: 5200,
            gateway: lat("192.168.1.1", Method::Icmp, 2.0, 20),
            internet: vec![
                lat("1.1.1.1", Method::Icmp, 14.0, 20),
                lat("9.9.9.9", Method::Tcp { port: 443 }, 18.0, 20),
            ],
            dns: Probe::Measured(Dns {
                lookups_ms: vec![20.0, 25.0, 31.0],
                median_ms: 25.0,
                resolves: true,
            }),
            apps: Apps {
                total_rx: 3 << 20,
                total_tx: 1 << 10,
                recent_peak: None,
                top: vec![AppLoad {
                    name: "Steam".into(),
                    rx_rate: 3 << 20,
                    tx_rate: 1 << 10,
                    share: 0.95,
                }],
            },
            path: None,
            baseline_ms: Some(15.0),
            verdict,
        }
    }

    #[test]
    fn the_verdict_comes_first_and_tcp_is_marked() {
        let text = render(&report(Verdict::AllGood));
        assert!(text.starts_with("✔ All good"), "{text}");
        assert!(text.contains("ICMP"));
        assert!(text.contains("TCP:443"), "a TCP measurement is labelled");
        let order: Vec<usize> = ["Router", "Internet", "DNS", "Apps"]
            .iter()
            .map(|w| text.find(&format!("  {w} ")).unwrap())
            .collect();
        assert!(order.windows(2).all(|w| w[0] < w[1]), "{text}");
    }

    #[test]
    fn an_application_is_named() {
        let text = render(&report(Verdict::App {
            name: "Steam".into(),
        }));
        assert!(text.starts_with("⚠ It's Steam"), "{text}");
        assert!(text.contains("95%"));
    }

    #[test]
    fn unmeasurable_is_not_an_error() {
        let mut r = report(Verdict::AllGood);
        r.gateway = Probe::Unmeasurable {
            why: "no default route".into(),
        };
        let text = render(&r);
        assert!(text.contains("not measurable: no default route"), "{text}");
    }

    #[test]
    fn exit_codes() {
        assert_eq!(exit_code(&Verdict::AllGood), OK);
        assert_eq!(exit_code(&Verdict::DnsSlow), PROBLEM);
        assert_eq!(exit_code(&Verdict::LocalLink), PROBLEM);
        assert_eq!(exit_code(&Verdict::Unmeasured), ERROR);
    }

    #[test]
    fn the_path_shows_silent_hops() {
        let mut r = report(Verdict::AllGood);
        r.path = Some(Probe::Measured(vec![
            Hop {
                ttl: 1,
                address: Some("192.168.1.1".parse().unwrap()),
                sent: 3,
                received: 3,
                avg_ms: Some(1.5),
            },
            Hop {
                ttl: 2,
                address: None,
                sent: 3,
                received: 0,
                avg_ms: None,
            },
        ]));
        let text = render(&r);
        assert!(text.contains("Path (ICMP, hop by hop)"));
        assert!(text.contains("   2  *"), "{text}");
    }
}
