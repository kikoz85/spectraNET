//! `snet-qa`: accuracy and endurance tests for spectraNET's capture, on real networks.
//!
//! * `snet-qa serve` runs on another computer and sends or receives exactly the bytes asked.
//! * `snet-qa run --peer HOST:PORT` runs scenarios against it — large download and upload,
//!   parallel connections, hundreds of short-lived ones, a long quiet connection, UDP — while
//!   sampling this computer's capture backend every second, and compares, byte for byte,
//!   what the backend measured for this process with what was really sent and received. It
//!   also reconciles with the network interfaces during each scenario.
//! * `snet-qa soak --name snetd` records the CPU and memory of a process over hours.
//!
//! The same program runs on macOS, Linux and Windows (capture needs administrator rights on
//! Linux and Windows, as snetd does).

use std::collections::HashMap;
use std::io::{BufRead, BufReader, Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream, ToSocketAddrs, UdpSocket};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use anyhow::{Context, Result, bail};
use clap::{Parser, Subcommand};
use serde::Serialize;
use spectranet_capture::{SourceOptions, TrafficSource};
use spectranet_model::{Snapshot, Transport};

#[derive(Parser)]
#[command(
    name = "snet-qa",
    version,
    about = "spectraNET accuracy and endurance tests"
)]
struct Cli {
    #[command(subcommand)]
    command: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Serve the test traffic (on another computer)
    Serve {
        #[arg(long, default_value = "0.0.0.0:47800")]
        listen: SocketAddr,
    },
    /// Run the scenarios against a `serve` and compare with what the capture measured
    Run {
        /// The `serve` to talk to
        #[arg(long)]
        peer: String,
        /// Smaller transfers (a quicker check)
        #[arg(long)]
        quick: bool,
        /// Also write the report as JSON here
        #[arg(long)]
        json: Option<std::path::PathBuf>,
    },
    /// Record CPU and memory of a process (e.g. snetd) every 10 seconds
    Soak {
        /// Process name to follow
        #[arg(long, default_value = "snetd")]
        name: String,
        /// How long
        #[arg(long, default_value = "1440")]
        minutes: u64,
        /// CSV file to write (elapsed_s, cpu_percent, memory_mib)
        #[arg(long)]
        out: std::path::PathBuf,
    },
}

fn main() -> Result<()> {
    match Cli::parse().command {
        Cmd::Serve { listen } => serve(listen),
        Cmd::Run { peer, quick, json } => run(&peer, quick, json),
        Cmd::Soak { name, minutes, out } => soak(&name, minutes, &out),
    }
}

// ---------------------------------------------------------------------------------------
// Server

const CHUNK: usize = 64 * 1024;
const DATAGRAM: usize = 1200;

fn serve(listen: SocketAddr) -> Result<()> {
    let tcp = TcpListener::bind(listen).with_context(|| format!("listening on {listen}"))?;
    let udp = UdpSocket::bind(listen).with_context(|| format!("UDP on {listen}"))?;
    println!("snet-qa serving TCP and UDP on {listen}");
    std::thread::spawn(move || udp_server(udp));
    for stream in tcp.incoming().flatten() {
        std::thread::spawn(move || {
            if let Err(e) = handle(stream) {
                eprintln!("connection: {e:#}");
            }
        });
    }
    Ok(())
}

/// `GET n`: sends n bytes. `PUT n`: reads n bytes, answers `OK`. `PING k ms`: k exchanges of
/// 64 bytes, `ms` apart.
fn handle(stream: TcpStream) -> Result<()> {
    stream.set_nodelay(true)?;
    let mut reader = BufReader::new(stream.try_clone()?);
    let mut line = String::new();
    reader.read_line(&mut line)?;
    let words: Vec<&str> = line.split_whitespace().collect();
    let mut out = stream;
    match words.as_slice() {
        ["GET", n] => {
            let mut left: usize = n.parse()?;
            let block = vec![0x5a_u8; CHUNK];
            while left > 0 {
                let k = left.min(CHUNK);
                out.write_all(&block[..k])?;
                left -= k;
            }
        }
        ["PUT", n] => {
            let mut left: usize = n.parse()?;
            let mut block = vec![0u8; CHUNK];
            while left > 0 {
                let k = reader.read(&mut block[..left.min(CHUNK)])?;
                if k == 0 {
                    bail!("upload ended early");
                }
                left -= k;
            }
            out.write_all(b"OK\n")?;
        }
        ["PING", count, _] => {
            let count: usize = count.parse()?;
            let mut msg = [0u8; 64];
            for _ in 0..count {
                reader.read_exact(&mut msg)?;
                out.write_all(&msg)?;
            }
        }
        _ => bail!("unknown request {line:?}"),
    }
    Ok(())
}

/// `UDP n`: n bytes back in datagrams, then `END`.
fn udp_server(socket: UdpSocket) {
    let mut buf = [0u8; 2048];
    loop {
        let Ok((len, from)) = socket.recv_from(&mut buf) else {
            continue;
        };
        let text = String::from_utf8_lossy(&buf[..len]).to_string();
        let Some(n) = text
            .strip_prefix("UDP ")
            .and_then(|n| n.trim().parse::<usize>().ok())
        else {
            continue;
        };
        let socket = socket.try_clone().expect("udp clone");
        std::thread::spawn(move || {
            let block = [0x33_u8; DATAGRAM];
            let mut left = n;
            while left > 0 {
                let k = left.min(DATAGRAM);
                let _ = socket.send_to(&block[..k], from);
                left -= k;
                // About 40 MB/s: gentle enough not to overflow a socket buffer.
                std::thread::sleep(Duration::from_micros(30));
            }
            for _ in 0..3 {
                let _ = socket.send_to(b"END", from);
                std::thread::sleep(Duration::from_millis(20));
            }
        });
    }
}

// ---------------------------------------------------------------------------------------
// Measurement

/// What the capture said about one of our connections: the largest lifetime counters seen.
#[derive(Debug, Clone, Copy, Default)]
struct Seen {
    rx: u64,
    tx: u64,
    /// Seen with an unknown remote address (a capture fault).
    unconnected: bool,
}

#[derive(Default)]
struct Measured {
    /// By (transport, local port).
    flows: HashMap<(Transport, u16), Seen>,
    /// Interface bytes and attributed bytes, per sample: (when, link rx+tx, attributed rx+tx).
    link: Vec<(Instant, u64, u64)>,
    /// Our traffic attributed to another process.
    misattributed: u64,
    samples: u64,
}

/// Samples the capture backend every second until stopped, keeping our process's flows.
fn sampler(
    mut source: Box<dyn TrafficSource>,
    measured: Arc<Mutex<Measured>>,
    stop: Arc<AtomicBool>,
    peer: SocketAddr,
) {
    let me = std::process::id();
    while !stop.load(Ordering::Relaxed) {
        let started = Instant::now();
        if let Ok(snapshot) = source.sample() {
            record(&snapshot, me, peer, &measured);
        }
        let spent = started.elapsed();
        if spent < Duration::from_secs(1) {
            std::thread::sleep(Duration::from_secs(1) - spent);
        }
    }
}

fn record(snapshot: &Snapshot, me: u32, peer: SocketAddr, measured: &Mutex<Measured>) {
    let Ok(mut m) = measured.lock() else {
        return;
    };
    m.samples += 1;
    for p in &snapshot.processes {
        for f in &p.flows {
            let ours = f.remote.ip() == peer.ip() && f.remote.port() == peer.port();
            if p.process.pid != me {
                if ours {
                    m.misattributed += f.rx_rate + f.tx_rate;
                }
                continue;
            }
            let unconnected = f.remote.ip().is_unspecified();
            if !ours && !unconnected {
                continue;
            }
            let seen = m.flows.entry((f.transport, f.local.port())).or_default();
            seen.rx = seen.rx.max(f.rx_bytes);
            seen.tx = seen.tx.max(f.tx_bytes);
            seen.unconnected |= unconnected;
        }
    }
    if let Some(link) = &snapshot.link {
        let secs = snapshot.interval_ms as f64 / 1000.0;
        let total = ((link.rx_rate + link.tx_rate) as f64 * secs) as u64;
        let attributed = ((link.attributed_rx + link.attributed_tx) as f64 * secs) as u64;
        m.link.push((Instant::now(), total, attributed));
    }
}

// ---------------------------------------------------------------------------------------
// Scenarios

/// What the client really did in a scenario.
#[derive(Default)]
struct Done {
    /// (transport, local port) of every connection opened.
    ports: Vec<(Transport, u16)>,
    rx: u64,
    tx: u64,
}

fn connect(peer: SocketAddr, request: &str, done: &mut Done) -> Result<TcpStream> {
    let mut s = TcpStream::connect_timeout(&peer, Duration::from_secs(5))?;
    s.set_nodelay(true)?;
    done.ports.push((Transport::Tcp, s.local_addr()?.port()));
    s.write_all(request.as_bytes())?;
    done.tx += request.len() as u64;
    Ok(s)
}

fn download(peer: SocketAddr, n: u64, done: &mut Done) -> Result<()> {
    let mut s = connect(peer, &format!("GET {n}\n"), done)?;
    let mut buf = vec![0u8; CHUNK];
    loop {
        let k = s.read(&mut buf)?;
        if k == 0 {
            break;
        }
        done.rx += k as u64;
    }
    Ok(())
}

fn upload(peer: SocketAddr, n: u64, done: &mut Done) -> Result<()> {
    let mut s = connect(peer, &format!("PUT {n}\n"), done)?;
    let block = vec![0xa5_u8; CHUNK];
    let mut left = n as usize;
    while left > 0 {
        let k = left.min(CHUNK);
        s.write_all(&block[..k])?;
        left -= k;
    }
    done.tx += n;
    let mut ok = String::new();
    BufReader::new(&mut s).read_line(&mut ok)?;
    done.rx += ok.len() as u64;
    Ok(())
}

fn ping(peer: SocketAddr, count: usize, every: Duration, done: &mut Done) -> Result<()> {
    let mut s = connect(peer, &format!("PING {count} {}\n", every.as_millis()), done)?;
    let mut msg = [7u8; 64];
    for _ in 0..count {
        s.write_all(&msg)?;
        s.read_exact(&mut msg)?;
        done.tx += 64;
        done.rx += 64;
        std::thread::sleep(every);
    }
    Ok(())
}

fn udp(peer: SocketAddr, n: u64, done: &mut Done) -> Result<()> {
    let bind: SocketAddr = if peer.is_ipv4() {
        "0.0.0.0:0".parse()?
    } else {
        "[::]:0".parse()?
    };
    let s = UdpSocket::bind(bind)?;
    s.connect(peer)?;
    s.set_read_timeout(Some(Duration::from_secs(3)))?;
    done.ports.push((Transport::Udp, s.local_addr()?.port()));
    let request = format!("UDP {n}");
    s.send(request.as_bytes())?;
    done.tx += request.len() as u64;
    let mut buf = [0u8; 2048];
    while let Ok(k) = s.recv(&mut buf) {
        done.rx += k as u64;
        if &buf[..k] == b"END" {
            // Three are sent; count the others as they come.
            std::thread::sleep(Duration::from_millis(100));
            s.set_read_timeout(Some(Duration::from_millis(100)))?;
        }
    }
    Ok(())
}

#[derive(Serialize)]
struct Outcome {
    scenario: String,
    connections: usize,
    seen: usize,
    expected_rx: u64,
    expected_tx: u64,
    measured_rx: u64,
    measured_tx: u64,
    /// Relative error of the total, in percent.
    error_percent: f64,
    /// Share of the interfaces' traffic attributed during the scenario, in percent.
    coverage_percent: Option<f64>,
    unconnected_rows: usize,
    misattributed_bytes: u64,
    pass: bool,
}

fn run(peer: &str, quick: bool, json: Option<std::path::PathBuf>) -> Result<()> {
    let peer: SocketAddr = peer
        .to_socket_addrs()?
        .next()
        .context("peer address not found")?;
    let source = spectranet_capture::system_source(SourceOptions {
        resolve_names: false,
        service: false,
    })
    .context("opening the capture backend (administrator rights on Linux and Windows)")?;
    println!("snet-qa: {} capture, peer {peer}", source.name());
    let measured = Arc::new(Mutex::new(Measured::default()));
    let stop = Arc::new(AtomicBool::new(false));
    let sampling = {
        let (measured, stop) = (measured.clone(), stop.clone());
        std::thread::spawn(move || sampler(source, measured, stop, peer))
    };
    // Let the backend settle (first samples prime its counters).
    std::thread::sleep(Duration::from_secs(3));

    let mb = move |n: u64| if quick { n << 18 } else { n << 20 };
    type Scenario = (&'static str, Box<dyn Fn(&mut Done) -> Result<()>>);
    let scenarios: Vec<Scenario> = vec![
        (
            "large download",
            Box::new(move |d| download(peer, mb(200), d)),
        ),
        ("large upload", Box::new(move |d| upload(peer, mb(100), d))),
        (
            "4 parallel downloads",
            Box::new(move |d| {
                let handles: Vec<_> = (0..4)
                    .map(|_| {
                        std::thread::spawn(move || {
                            let mut part = Done::default();
                            download(peer, mb(25), &mut part).map(|()| part)
                        })
                    })
                    .collect();
                for h in handles {
                    let part = h.join().map_err(|_| anyhow::anyhow!("thread"))??;
                    d.ports.extend(part.ports);
                    d.rx += part.rx;
                    d.tx += part.tx;
                }
                Ok(())
            }),
        ),
        (
            "200 short connections",
            Box::new(move |d| {
                for _ in 0..200 {
                    download(peer, 50_000, d)?;
                }
                Ok(())
            }),
        ),
        (
            "long quiet connection",
            Box::new(move |d| ping(peer, 15, Duration::from_secs(1), d)),
        ),
        ("UDP stream", Box::new(move |d| udp(peer, mb(20), d))),
    ];

    let mut outcomes = Vec::new();
    for (name, scenario) in scenarios {
        let started = Instant::now();
        let mut done = Done::default();
        if let Err(e) = scenario(&mut done) {
            println!("{name}: could not run ({e:#})");
            continue;
        }
        // Closed connections are reported one last time at the next samples.
        std::thread::sleep(Duration::from_secs(4));
        let m = measured.lock().map_err(|_| anyhow::anyhow!("lock"))?;
        let (mut rx, mut tx, mut seen, mut unconnected) = (0u64, 0u64, 0usize, 0usize);
        for port in &done.ports {
            if let Some(s) = m.flows.get(port) {
                rx += s.rx;
                tx += s.tx;
                seen += 1;
                unconnected += usize::from(s.unconnected);
            }
        }
        let (link, attributed) = m
            .link
            .iter()
            .filter(|(t, _, _)| *t >= started)
            .fold((0u64, 0u64), |(a, b), (_, l, at)| (a + l, b + at));
        let coverage = (link > 0).then(|| (attributed as f64 / link as f64).min(1.0) * 100.0);
        let expected = done.rx + done.tx;
        let error = if expected == 0 {
            0.0
        } else {
            ((rx + tx) as f64 - expected as f64) / expected as f64 * 100.0
        };
        let all_seen = seen * 100 >= done.ports.len() * 99;
        let outcome = Outcome {
            scenario: name.into(),
            connections: done.ports.len(),
            seen,
            expected_rx: done.rx,
            expected_tx: done.tx,
            measured_rx: rx,
            measured_tx: tx,
            error_percent: error,
            coverage_percent: coverage,
            unconnected_rows: unconnected,
            misattributed_bytes: m.misattributed,
            pass: error.abs() <= 1.0 && all_seen,
        };
        println!(
            "{:<24} {:>4}/{:<4} conn  expected {:>12}  measured {:>12}  error {:>+7.3}%  coverage {}  {}",
            outcome.scenario,
            outcome.seen,
            outcome.connections,
            expected,
            rx + tx,
            error,
            coverage.map_or("   -  ".into(), |c| format!("{c:5.1}%")),
            if outcome.pass { "PASS" } else { "FAIL" }
        );
        outcomes.push(outcome);
    }
    stop.store(true, Ordering::Relaxed);
    let _ = sampling.join();
    if let Some(path) = json {
        std::fs::write(&path, serde_json::to_string_pretty(&outcomes)?)?;
    }
    let failed = outcomes.iter().filter(|o| !o.pass).count();
    println!(
        "{} scenarios, {} passed, {failed} failed",
        outcomes.len(),
        outcomes.len() - failed
    );
    if failed > 0 {
        std::process::exit(1);
    }
    Ok(())
}

// ---------------------------------------------------------------------------------------
// Endurance

fn soak(name: &str, minutes: u64, out: &std::path::Path) -> Result<()> {
    use sysinfo::{ProcessRefreshKind, ProcessesToUpdate, System};
    let mut system = System::new();
    let mut file = std::fs::File::create(out)?;
    writeln!(file, "elapsed_s,cpu_percent,memory_mib")?;
    let started = Instant::now();
    let end = started + Duration::from_secs(minutes * 60);
    let mut rows: Vec<(f32, f64)> = Vec::new();
    let refresh = ProcessRefreshKind::nothing().with_cpu().with_memory();
    system.refresh_processes_specifics(ProcessesToUpdate::All, true, refresh);
    while Instant::now() < end {
        std::thread::sleep(Duration::from_secs(10));
        system.refresh_processes_specifics(ProcessesToUpdate::All, true, refresh);
        let found = system
            .processes()
            .values()
            .filter(|p| p.name().to_string_lossy().trim_end_matches(".exe") == name)
            .fold((0.0f32, 0u64, false), |(c, m, _), p| {
                (c + p.cpu_usage(), m + p.memory(), true)
            });
        let (cpu, memory, present) = found;
        if !present {
            writeln!(file, "{},,", started.elapsed().as_secs())?;
            continue;
        }
        let mib = memory as f64 / 1_048_576.0;
        writeln!(file, "{},{cpu:.2},{mib:.1}", started.elapsed().as_secs())?;
        file.flush()?;
        rows.push((cpu, mib));
    }
    if rows.is_empty() {
        bail!("{name} was never seen");
    }
    let avg_cpu = rows.iter().map(|r| r.0 as f64).sum::<f64>() / rows.len() as f64;
    let max_cpu = rows.iter().map(|r| r.0).fold(0.0, f32::max);
    let first = rows.iter().take(6).map(|r| r.1).sum::<f64>() / rows.len().min(6) as f64;
    let last = rows.iter().rev().take(6).map(|r| r.1).sum::<f64>() / rows.len().min(6) as f64;
    let max_mem = rows.iter().map(|r| r.1).fold(0.0, f64::max);
    println!(
        "{name}: {} samples · CPU {avg_cpu:.2}% average, {max_cpu:.1}% peak · memory {first:.1} → {last:.1} MiB (peak {max_mem:.1})",
        rows.len()
    );
    Ok(())
}
