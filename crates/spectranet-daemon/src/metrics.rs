//! Prometheus metrics, opt-in: `snetd run --metrics 127.0.0.1:9790` or `metrics = "..."` in
//! snetd.conf. Off by default; nothing is ever served on the network unless asked for.
//!
//! `GET /metrics` answers in the Prometheus text format (version 0.0.4): per-application
//! traffic (rates and byte counters), connections, CPU and memory, plus the service's own
//! state (samples, clients, alerts, blocks). Applications are labelled by name; byte
//! counters grow for as long as snetd runs, as Prometheus counters should.

use std::collections::HashMap;
use std::fmt::Write as _;
use std::io::{BufRead, BufReader, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::time::{Duration, Instant};

use spectranet_model::{Snapshot, group_by_app};

/// Applications whose counters are kept; the least recently seen go first beyond this.
const MAX_APPS: usize = 1000;

/// Running totals, updated on every sample.
#[derive(Debug, Default)]
pub struct Metrics {
    samples: u64,
    /// Bytes received / sent per application since snetd started, and when it was last seen.
    totals: HashMap<String, (f64, f64, Instant)>,
    /// The latest per-application gauges.
    apps: Vec<AppGauges>,
}

#[derive(Debug, Clone, PartialEq)]
struct AppGauges {
    name: String,
    rx_rate: u64,
    tx_rate: u64,
    connections: usize,
    processes: usize,
    cpu: f64,
    memory: u64,
}

/// What the service knows besides traffic, at the time of a scrape.
#[derive(Debug, Default, Clone)]
pub struct ServiceState {
    pub version: &'static str,
    pub uptime_s: u64,
    pub clients: usize,
    pub alerts_24h: u64,
    pub blocks: usize,
}

impl Metrics {
    /// Adds one sample.
    pub fn observe(&mut self, snapshot: &Snapshot) {
        self.samples += 1;
        let seconds = snapshot.interval_ms as f64 / 1000.0;
        let now = Instant::now();
        let mut apps: HashMap<String, AppGauges> = HashMap::new();
        for app in group_by_app(snapshot.processes.clone()) {
            let g = apps.entry(app.name.clone()).or_insert_with(|| AppGauges {
                name: app.name.clone(),
                rx_rate: 0,
                tx_rate: 0,
                connections: 0,
                processes: 0,
                cpu: 0.0,
                memory: 0,
            });
            g.rx_rate += app.rx_rate;
            g.tx_rate += app.tx_rate;
            g.connections += app.flow_count();
            g.processes += app.processes.len();
            g.cpu += f64::from(app.cpu_tenths) / 10.0;
            g.memory += app.memory;
        }
        for g in apps.values() {
            let t = self.totals.entry(g.name.clone()).or_insert((0.0, 0.0, now));
            t.0 += g.rx_rate as f64 * seconds;
            t.1 += g.tx_rate as f64 * seconds;
            t.2 = now;
        }
        if self.totals.len() > MAX_APPS {
            let mut by_age: Vec<(String, Instant)> =
                self.totals.iter().map(|(k, v)| (k.clone(), v.2)).collect();
            by_age.sort_by_key(|(_, seen)| *seen);
            for (name, _) in by_age.into_iter().take(self.totals.len() - MAX_APPS) {
                self.totals.remove(&name);
            }
        }
        let mut list: Vec<AppGauges> = apps.into_values().collect();
        list.sort_by(|a, b| a.name.cmp(&b.name));
        self.apps = list;
    }

    /// The text exposition format.
    pub fn render(&self, state: &ServiceState) -> String {
        let mut out = String::new();
        family(
            &mut out,
            "spectranet_build_info",
            "gauge",
            "spectraNET version.",
        );
        let _ = writeln!(
            out,
            "spectranet_build_info{{version=\"{}\"}} 1",
            state.version
        );
        family(
            &mut out,
            "spectranet_uptime_seconds",
            "gauge",
            "Seconds since snetd started.",
        );
        let _ = writeln!(out, "spectranet_uptime_seconds {}", state.uptime_s);
        family(
            &mut out,
            "spectranet_samples_total",
            "counter",
            "Traffic samples taken.",
        );
        let _ = writeln!(out, "spectranet_samples_total {}", self.samples);
        family(
            &mut out,
            "spectranet_clients",
            "gauge",
            "Clients connected to snetd.",
        );
        let _ = writeln!(out, "spectranet_clients {}", state.clients);
        family(
            &mut out,
            "spectranet_alerts_last_24h",
            "gauge",
            "Security alerts raised in the last 24 hours.",
        );
        let _ = writeln!(out, "spectranet_alerts_last_24h {}", state.alerts_24h);
        family(&mut out, "spectranet_blocks", "gauge", "Blocks in force.");
        let _ = writeln!(out, "spectranet_blocks {}", state.blocks);

        type Get = fn(&AppGauges) -> String;
        let gauges: [(&str, &str, Get); 6] = [
            (
                "spectranet_app_receive_bytes_per_second",
                "Download rate of the application.",
                |g| g.rx_rate.to_string(),
            ),
            (
                "spectranet_app_transmit_bytes_per_second",
                "Upload rate of the application.",
                |g| g.tx_rate.to_string(),
            ),
            (
                "spectranet_app_connections",
                "Open connections of the application.",
                |g| g.connections.to_string(),
            ),
            (
                "spectranet_app_processes",
                "Processes of the application with network activity.",
                |g| g.processes.to_string(),
            ),
            (
                "spectranet_app_cpu_percent",
                "Processor use of the application (100 = one core).",
                |g| format!("{:.1}", g.cpu),
            ),
            (
                "spectranet_app_memory_bytes",
                "Resident memory of the application.",
                |g| g.memory.to_string(),
            ),
        ];
        for (name, help, get) in gauges {
            family(&mut out, name, "gauge", help);
            for g in &self.apps {
                let _ = writeln!(out, "{name}{{app=\"{}\"}} {}", escape(&g.name), get(g));
            }
        }
        let mut names: Vec<&String> = self.totals.keys().collect();
        names.sort();
        for (name, help, rx) in [
            (
                "spectranet_app_receive_bytes_total",
                "Bytes received by the application since snetd started.",
                true,
            ),
            (
                "spectranet_app_transmit_bytes_total",
                "Bytes sent by the application since snetd started.",
                false,
            ),
        ] {
            family(&mut out, name, "counter", help);
            for app in &names {
                let t = &self.totals[*app];
                let value = if rx { t.0 } else { t.1 };
                let _ = writeln!(out, "{name}{{app=\"{}\"}} {}", escape(app), value.round());
            }
        }
        out
    }
}

/// The HELP and TYPE lines of a metric family.
fn family(out: &mut String, name: &str, kind: &str, help: &str) {
    let _ = writeln!(out, "# HELP {name} {help}");
    let _ = writeln!(out, "# TYPE {name} {kind}");
}

/// Label values escape backslash, double quote and newline.
fn escape(value: &str) -> String {
    value
        .replace('\\', "\\\\")
        .replace('"', "\\\"")
        .replace('\n', "\\n")
}

/// Serves `/metrics` until the process ends. `render` builds the page for each request.
pub fn serve(
    addr: SocketAddr,
    render: impl Fn() -> String + Send + 'static,
) -> std::io::Result<SocketAddr> {
    let listener = TcpListener::bind(addr)?;
    let bound = listener.local_addr()?;
    if !bound.ip().is_loopback() {
        crate::service::log(&format!(
            "metrics are served on {bound}, reachable from the network as configured"
        ));
    }
    std::thread::Builder::new()
        .name("snetd-metrics".into())
        .spawn(move || {
            for stream in listener.incoming().flatten() {
                // One at a time: scrapes are rare and small, and a slow client is cut off.
                let _ = answer(stream, &render);
            }
        })?;
    Ok(bound)
}

fn answer(mut stream: TcpStream, render: &dyn Fn() -> String) -> std::io::Result<()> {
    stream.set_read_timeout(Some(Duration::from_secs(2)))?;
    stream.set_write_timeout(Some(Duration::from_secs(5)))?;
    let mut reader = BufReader::new(stream.try_clone()?);
    let mut request = String::new();
    reader.read_line(&mut request)?;
    // Skip the headers (bounded).
    for _ in 0..100 {
        let mut line = String::new();
        if reader.read_line(&mut line)? == 0 || line == "\r\n" || line == "\n" {
            break;
        }
    }
    let mut parts = request.split_whitespace();
    let (method, path) = (parts.next().unwrap_or(""), parts.next().unwrap_or(""));
    let path = path.split('?').next().unwrap_or("");
    let (status, kind, body) = match (method, path) {
        ("GET" | "HEAD", "/metrics") => (
            "200 OK",
            "text/plain; version=0.0.4; charset=utf-8",
            render(),
        ),
        ("GET" | "HEAD", "/") => (
            "200 OK",
            "text/html; charset=utf-8",
            "<html><body><h1>spectraNET</h1><p><a href=\"/metrics\">metrics</a></p></body></html>\n"
                .to_string(),
        ),
        ("GET" | "HEAD", _) => ("404 Not Found", "text/plain", "not found\n".to_string()),
        _ => (
            "405 Method Not Allowed",
            "text/plain",
            "only GET\n".to_string(),
        ),
    };
    let head = format!(
        "HTTP/1.1 {status}\r\nContent-Type: {kind}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        body.len()
    );
    stream.write_all(head.as_bytes())?;
    if method != "HEAD" {
        stream.write_all(body.as_bytes())?;
    }
    stream.flush()
}

#[cfg(test)]
mod tests {
    use super::*;
    use spectranet_capture::TrafficSource;
    use spectranet_capture::mock::MockSource;

    fn state() -> ServiceState {
        ServiceState {
            version: "0.3.0",
            uptime_s: 12,
            clients: 1,
            alerts_24h: 2,
            blocks: 1,
        }
    }

    #[test]
    fn counters_grow_and_gauges_follow_the_latest_sample() {
        let mut source = MockSource::new(5);
        let mut m = Metrics::default();
        let first = source.sample().unwrap();
        m.observe(&first);
        let second = source.sample().unwrap();
        m.observe(&second);
        let text = m.render(&state());
        assert!(text.contains("spectranet_samples_total 2"));
        assert!(text.contains("# TYPE spectranet_app_receive_bytes_total counter"));
        assert!(text.contains("spectranet_blocks 1"));
        // Every sample line is `name{labels} value` or `name value`, values are numbers.
        for line in text.lines().filter(|l| !l.starts_with('#')) {
            let value = line.rsplit(' ').next().unwrap();
            assert!(value.parse::<f64>().is_ok(), "{line}");
        }
        let total = |text: &str| -> f64 {
            text.lines()
                .filter(|l| l.starts_with("spectranet_app_receive_bytes_total{"))
                .map(|l| l.rsplit(' ').next().unwrap().parse::<f64>().unwrap())
                .sum()
        };
        let before = total(&text);
        m.observe(&source.sample().unwrap());
        assert!(
            total(&m.render(&state())) >= before,
            "counters never go back"
        );
    }

    #[test]
    fn labels_are_escaped() {
        assert_eq!(escape("a\"b\\c\nd"), "a\\\"b\\\\c\\nd");
    }

    #[test]
    fn serves_metrics_over_http() {
        use std::io::Read;
        let addr = serve("127.0.0.1:0".parse().unwrap(), || {
            "spectranet_up 1\n".to_string()
        })
        .unwrap();
        let get = |path: &str| {
            let mut s = TcpStream::connect(addr).unwrap();
            write!(s, "GET {path} HTTP/1.1\r\nHost: x\r\n\r\n").unwrap();
            let mut reply = String::new();
            s.read_to_string(&mut reply).unwrap();
            reply
        };
        let ok = get("/metrics");
        assert!(ok.starts_with("HTTP/1.1 200 OK"), "{ok}");
        assert!(ok.contains("version=0.0.4") && ok.ends_with("spectranet_up 1\n"));
        assert!(get("/nope").starts_with("HTTP/1.1 404"));
    }
}
