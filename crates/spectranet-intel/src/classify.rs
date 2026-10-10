//! What kind of traffic a connection carries, without looking at its content.
//!
//! Signals, all visible without decrypting anything:
//! - the **host** (DNS, TLS SNI): a list of known services by kind ([`Domains`]);
//! - the **pattern** over the last half minute: periodic download bursts (a player filling
//!   its buffer), a sustained transfer, many small packets at a steady pace (calls, games),
//!   short exchanges separated by pauses (web, APIs);
//! - **well-known ports** of call services, and the protocols offered in the TLS handshake.
//!
//! Every classification carries its reasons, and a certainty that says which signals agree:
//! no percentages, no guessed codecs or resolutions.

use std::collections::{HashMap, VecDeque};
use std::net::SocketAddr;
use std::path::Path;
use std::time::Duration;

use spectranet_model::flowmeta::{Certainty, Class, Kind, Reason};
use spectranet_model::{Flow, Snapshot, Transport};

/// The built-in list of known services (the project's `data/categories.txt`).
pub const BUILTIN: &str = include_str!("../../../data/categories.txt");
/// File name of a downloaded or hand-made list in the feeds directory.
pub const FILE_NAME: &str = "categories.txt";
/// Where snetd refreshes the list from.
pub const URL: &str =
    "https://raw.githubusercontent.com/kikoz85/spectraNET/main/data/categories.txt";

/// Seconds of history kept per connection.
const WINDOW: usize = 30;
/// Samples needed before a pattern counts.
const MIN_SAMPLES: usize = 5;
/// Connections not seen for this many samples are forgotten.
const FORGET_AFTER: u64 = 10;

/// Known services: domain suffix → kind.
#[derive(Debug, Clone, Default)]
pub struct Domains {
    map: HashMap<String, Kind>,
}

impl Domains {
    /// Parses the list format: `kind domain` per line, `#` comments.
    pub fn parse(text: &str) -> (Self, usize) {
        let mut map = HashMap::new();
        let mut rejected = 0;
        for line in text.lines() {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            let mut parts = line.split_whitespace();
            match (
                parts.next().and_then(Kind::parse),
                parts.next(),
                parts.next(),
            ) {
                (Some(kind), Some(domain), None)
                    if domain.contains('.')
                        && domain
                            .chars()
                            .all(|c| c.is_ascii_alphanumeric() || c == '.' || c == '-') =>
                {
                    map.insert(domain.to_ascii_lowercase(), kind);
                }
                _ => rejected += 1,
            }
        }
        (Self { map }, rejected)
    }

    pub fn builtin() -> Self {
        Self::parse(BUILTIN).0
    }

    /// The list in `dir` if there is a good one, else the built-in list.
    pub fn load(dir: &Path) -> Self {
        std::fs::read_to_string(dir.join(FILE_NAME))
            .ok()
            .map(|text| Self::parse(&text))
            .filter(|(d, rejected)| d.len() >= 20 && *rejected < d.len())
            .map_or_else(Self::builtin, |(d, _)| d)
    }

    pub fn len(&self) -> usize {
        self.map.len()
    }

    pub fn is_empty(&self) -> bool {
        self.map.is_empty()
    }

    /// The kind of a host and the listed domain it matched (the most specific one).
    pub fn lookup(&self, host: &str) -> Option<(Kind, &str)> {
        let host = host.trim_end_matches('.').to_ascii_lowercase();
        let mut rest = host.as_str();
        loop {
            if let Some((domain, kind)) = self.map.get_key_value(rest) {
                return Some((*kind, domain.as_str()));
            }
            rest = rest.split_once('.')?.1;
        }
    }
}

/// Downloads the list into `dir`, replacing the stored one only with a plausible list.
pub fn update(dir: &Path) -> Result<usize, String> {
    let agent: ureq::Agent = ureq::Agent::config_builder()
        .timeout_global(Some(Duration::from_secs(60)))
        .user_agent(concat!("spectraNET/", env!("CARGO_PKG_VERSION")))
        .build()
        .into();
    let mut response = agent.get(URL).call().map_err(|e| e.to_string())?;
    let body = response
        .body_mut()
        .with_config()
        .limit(1 << 20)
        .read_to_string()
        .map_err(|e| e.to_string())?;
    let (domains, rejected) = Domains::parse(&body);
    if domains.len() < 20 || rejected > domains.len() {
        return Err("download does not look like a list of services".into());
    }
    std::fs::create_dir_all(dir).map_err(|e| e.to_string())?;
    let path = dir.join(FILE_NAME);
    let tmp = path.with_extension("txt.tmp");
    std::fs::write(&tmp, &body).map_err(|e| e.to_string())?;
    std::fs::rename(&tmp, &path).map_err(|e| e.to_string())?;
    Ok(domains.len())
}

/// One second of a connection's life.
#[derive(Debug, Clone, Copy, Default, PartialEq)]
struct Sample {
    rx: u64,
    tx: u64,
    rx_pps: Option<u32>,
    tx_pps: Option<u32>,
}

#[derive(Debug, Default)]
struct History {
    samples: VecDeque<Sample>,
    last_seen: u64,
}

type FlowId = (u32, Transport, SocketAddr, SocketAddr);

/// Keeps a short history per connection and classifies it on every sample.
#[derive(Debug, Default)]
pub struct Classifier {
    domains: Domains,
    history: HashMap<FlowId, History>,
    tick: u64,
}

impl Classifier {
    pub fn new(domains: Domains) -> Self {
        Self {
            domains,
            ..Default::default()
        }
    }

    pub fn set_domains(&mut self, domains: Domains) {
        self.domains = domains;
    }

    /// Records the sample and sets `meta.class` on every flow that can be classified.
    pub fn annotate(&mut self, snapshot: &mut Snapshot) {
        self.tick += 1;
        for p in &mut snapshot.processes {
            let pid = p.process.pid;
            // Radio programs are recognised by name, or by file when the name is generic.
            // Named as the user sees it (SDR++, not sdr++).
            let program = crate::radio::program(&p.process.name)
                .or_else(|| p.process.path.as_deref().and_then(crate::radio::program))
                .map(|(_, kind)| (p.process.name.clone(), kind));
            for flow in &mut p.flows {
                let id = (pid, flow.transport, flow.local, flow.remote);
                let h = self.history.entry(id).or_default();
                h.last_seen = self.tick;
                // Rates and packet rates are per second already: one entry per sample.
                h.samples.push_back(Sample {
                    rx: flow.rx_rate,
                    tx: flow.tx_rate,
                    rx_pps: flow.meta.rx_pps,
                    tx_pps: flow.meta.tx_pps,
                });
                while h.samples.len() > WINDOW {
                    h.samples.pop_front();
                }
                flow.meta.class = classify(flow, &h.samples, &self.domains, program.as_ref());
            }
        }
        let tick = self.tick;
        self.history
            .retain(|_, h| tick.saturating_sub(h.last_seen) < FORGET_AFTER);
    }
}

/// Ports of call and conferencing services (media over UDP).
fn call_port(port: u16) -> bool {
    matches!(port, 3478..=3481 | 8801..=8810 | 19302..=19309 | 50000..=50059)
}

/// The service a well-known port belongs to, for the reasons shown to the user.
pub fn port_service(port: u16) -> Option<&'static str> {
    Some(match port {
        20 | 21 => "FTP",
        22 => "SSH · SFTP · SCP",
        989 | 990 => "FTPS",
        445 => "SMB",
        548 => "AFP",
        873 => "rsync",
        2049 => "NFS",
        8096 | 8920 => "Jellyfin · Emby",
        32400 => "Plex",
        5900..=5909 => "VNC",
        3389 => "RDP",
        3478..=3481 => "STUN · TURN",
        8801..=8810 => "Zoom",
        19302..=19309 => "Google Meet",
        50000..=50059 => "WebRTC",
        _ => return None,
    })
}

/// Ports of remote desktops: VNC (5900–5909, macOS Screen Sharing) and RDP (3389).
fn remote_desktop_port(port: u16) -> bool {
    matches!(port, 5900..=5909 | 3389)
}

/// A remote screen is a video of a desktop: named so once it moves (50 kB in the window).
fn remote_desktop(flow: &Flow, samples: &VecDeque<Sample>) -> Option<Option<Class>> {
    let port = [flow.remote.port(), flow.local.port()]
        .into_iter()
        .find(|p| remote_desktop_port(*p))?;
    if flow.transport != Transport::Tcp {
        return None;
    }
    let moved: u64 = samples.iter().map(|s| s.rx + s.tx).sum();
    Some((moved >= 50_000).then(|| Class {
        kind: Kind::Video,
        certainty: Certainty::VeryLikely,
        reasons: vec![Reason::WellKnownPort { port }],
    }))
}

/// Ports of file-transfer protocols: FTP (20, 21), SSH with SFTP and SCP (22), FTPS (989,
/// 990), SMB (445), AFP (548), rsync (873), NFS (2049).
pub fn file_transfer_port(port: u16) -> bool {
    matches!(port, 20 | 21 | 22 | 445 | 548 | 873 | 989 | 990 | 2049)
}

/// Moved over the window before a file-transfer connection counts as a transfer (below, it is
/// a session: commands, a remote shell, browsing folders).
const TRANSFER_MIN_BYTES: u64 = 1 << 20;

/// File-transfer protocols carry files, whatever their rhythm looks like (a fast SFTP copy
/// comes in bursts, like a video player): a download or an upload by direction, or nothing.
fn file_transfer(flow: &Flow, samples: &VecDeque<Sample>) -> Option<Option<Class>> {
    let port = if file_transfer_port(flow.remote.port()) {
        flow.remote.port()
    } else if file_transfer_port(flow.local.port()) {
        flow.local.port()
    } else {
        return None;
    };
    if flow.transport != Transport::Tcp {
        return None;
    }
    let rx: u64 = samples.iter().map(|s| s.rx).sum();
    let tx: u64 = samples.iter().map(|s| s.tx).sum();
    if rx.max(tx) < TRANSFER_MIN_BYTES {
        return Some(None);
    }
    let download = rx >= tx;
    let rate = rx.max(tx) / samples.len().max(1) as u64;
    Some(Some(Class {
        kind: if download {
            Kind::Download
        } else {
            Kind::Upload
        },
        certainty: Certainty::VeryLikely,
        reasons: vec![
            Reason::WellKnownPort { port },
            Reason::Sustained { download, rate },
        ],
    }))
}

/// Ports of home media servers: Jellyfin and Emby (8096, 8920), Plex (32400).
fn media_server_port(port: u16) -> bool {
    matches!(port, 8096 | 8920 | 32400)
}

/// Received at least this much from a media server before the port counts as evidence: the
/// same port also carries the server's web pages and API.
const MEDIA_SERVER_MIN_BYTES: u64 = 4 << 20;

/// What the pattern alone says.
fn pattern(flow: &Flow, samples: &VecDeque<Sample>) -> Option<(Kind, Vec<Reason>)> {
    if samples.len() < MIN_SAMPLES {
        return None;
    }
    // Listening and unconnected sockets have no conversation to describe.
    if flow.remote.ip().is_unspecified() || flow.remote.port() == 0 {
        return None;
    }
    let n = samples.len() as f64;
    let rx: Vec<u64> = samples.iter().map(|s| s.rx).collect();
    let tx: Vec<u64> = samples.iter().map(|s| s.tx).collect();
    let total_rx: u64 = rx.iter().sum();
    let total_tx: u64 = tx.iter().sum();
    if total_rx + total_tx == 0 {
        return None;
    }
    let peak_rx = *rx.iter().max().unwrap_or(&0);
    let peak_tx = *tx.iter().max().unwrap_or(&0);
    let avg_rx = total_rx as f64 / n;
    let avg_tx = total_tx as f64 / n;

    // Steady small packets both ways: calls and games. QUIC (UDP 443) is web traffic
    // (HTTP/3) and follows the TCP rules below.
    let quic = flow.remote.port() == 443 || flow.local.port() == 443;
    if flow.transport == Transport::Udp && !quic {
        let pps: Vec<(u32, u32)> = samples
            .iter()
            .filter_map(|s| Some((s.rx_pps?, s.tx_pps?)))
            .collect();
        if pps.len() >= MIN_SAMPLES {
            let both_ways = pps.iter().filter(|(r, t)| *r >= 10 && *t >= 10).count();
            // Calls and games keep a steady pace; file transfers over UDP (BitTorrent's uTP)
            // swing widely.
            let steady = |values: Vec<f64>| {
                let mean = values.iter().sum::<f64>() / values.len() as f64;
                let var =
                    values.iter().map(|v| (v - mean).powi(2)).sum::<f64>() / values.len() as f64;
                mean > 0.0 && var.sqrt() / mean <= 0.5
            };
            let rx_steady = steady(pps.iter().map(|(r, _)| f64::from(*r)).collect());
            let tx_steady = steady(pps.iter().map(|(_, t)| f64::from(*t)).collect());
            if both_ways as f64 >= 0.7 * pps.len() as f64 && rx_steady && tx_steady {
                let total_pps: u64 = pps.iter().map(|(r, t)| u64::from(r + t)).sum();
                let avg_pps = (total_pps / pps.len() as u64) as u32;
                let size = ((total_rx + total_tx) / total_pps.max(1)) as u32;
                let reason = Reason::SmallSteadyPackets { pps: avg_pps, size };
                // Games send tiny state updates; calls carry voice and video frames.
                let kind = if size < 120 && avg_rx + avg_tx < 60_000.0 {
                    Kind::Game
                } else {
                    Kind::Call
                };
                return Some((kind, vec![reason]));
            }
        }
    }

    let download = total_rx >= total_tx * 4;
    let upload = total_tx >= total_rx * 4;

    // Periodic bursts: a player filling its buffer every few seconds.
    if download && peak_rx >= 64_000 {
        let threshold = peak_rx / 3;
        let quiet = peak_rx / 10;
        let mut starts = Vec::new();
        let mut in_burst = false;
        let mut quiet_seen = false;
        for (i, r) in rx.iter().enumerate() {
            if *r >= threshold {
                if !in_burst && (quiet_seen || starts.is_empty()) {
                    starts.push(i);
                }
                in_burst = true;
                quiet_seen = false;
            } else if *r <= quiet {
                in_burst = false;
                quiet_seen = true;
            }
        }
        let active = rx.iter().filter(|r| **r >= threshold).count();
        if starts.len() >= 3 && (active as f64) < 0.6 * n {
            let gaps: Vec<usize> = starts.windows(2).map(|w| w[1] - w[0]).collect();
            let mean = gaps.iter().sum::<usize>() as f64 / gaps.len() as f64;
            let regular = gaps
                .iter()
                .all(|g| (*g as f64 - mean).abs() <= mean * 0.5 + 1.0);
            if regular && mean >= 2.0 {
                let kind = if peak_rx >= 250_000 {
                    Kind::Video
                } else {
                    Kind::Audio
                };
                return Some((
                    kind,
                    vec![Reason::PeriodicBursts {
                        every_s: mean.round() as u32,
                        peak: peak_rx,
                    }],
                ));
            }
        }
    }

    // A sustained transfer in one direction.
    let busy = |v: &[u64], floor: u64| v.iter().filter(|x| **x >= floor).count() as f64 >= 0.8 * n;
    if download && busy(&rx, 100_000) {
        return Some((
            Kind::Download,
            vec![Reason::Sustained {
                download: true,
                rate: avg_rx as u64,
            }],
        ));
    }
    if upload && busy(&tx, 50_000) {
        return Some((
            Kind::Upload,
            vec![Reason::Sustained {
                download: false,
                rate: avg_tx as u64,
            }],
        ));
    }

    // Short exchanges separated by pauses: web pages, APIs, messaging — on web ports or
    // with a web protocol offered in the handshake (SSH, mail… are not "web").
    let web = matches!(flow.remote.port(), 80 | 443 | 8080 | 8443)
        || flow.meta.tls.as_ref().is_some_and(|t| {
            t.alpn
                .iter()
                .any(|a| matches!(a.as_str(), "h2" | "h3" | "http/1.1"))
        });
    let active = samples.iter().filter(|s| s.rx + s.tx > 0).count();
    if web && (active as f64) <= 0.4 * n && peak_rx.max(peak_tx) < 5_000_000 {
        return Some((Kind::Web, vec![Reason::ShortExchanges]));
    }
    None
}

/// Combines host, port, protocol and pattern into a classification.
/// A stream whose total rate stays even: (mean rate) when active in most samples.
fn steady_rate(samples: &VecDeque<Sample>) -> Option<u64> {
    if samples.len() < MIN_SAMPLES {
        return None;
    }
    let rates: Vec<f64> = samples.iter().map(|s| (s.rx + s.tx) as f64).collect();
    let active = rates.iter().filter(|r| **r > 0.0).count();
    if (active as f64) < 0.8 * rates.len() as f64 {
        return None;
    }
    let mean = rates.iter().sum::<f64>() / rates.len() as f64;
    let var = rates.iter().map(|r| (r - mean).powi(2)).sum::<f64>() / rates.len() as f64;
    (mean > 0.0 && var.sqrt() / mean <= 0.35).then_some(mean as u64)
}

/// Software-defined radio and satellite reception: by program, by port, by pattern.
fn radio(
    flow: &Flow,
    samples: &VecDeque<Sample>,
    program: Option<&(String, Kind)>,
) -> Option<Class> {
    use crate::radio::PortTrust;
    let port = crate::radio::port(flow.transport, flow.local.port(), flow.remote.port());
    if program.is_none() && port.is_none() {
        return None;
    }
    let steady = steady_rate(samples);
    let mut reasons = Vec::new();
    if let Some((name, _)) = program {
        reasons.push(Reason::RadioProgram {
            program: name.clone(),
        });
    }
    let (kind, certainty) = match (program, port) {
        (_, Some((p, kind, service, trust))) => {
            // A shared port needs a radio program, or a radio-like stream, to count.
            let confirmed = program.is_some()
                || match kind {
                    Kind::RawIq => steady.is_some_and(|r| r >= 100_000),
                    _ => steady.is_some(),
                };
            if trust == PortTrust::WithEvidence && !confirmed {
                return None;
            }
            reasons.push(Reason::RadioPort {
                port: p,
                service: service.to_string(),
            });
            let certainty = if program.is_some() || (trust == PortTrust::WithEvidence && confirmed)
            {
                Certainty::VeryLikely
            } else {
                Certainty::Likely
            };
            (kind, certainty)
        }
        (Some((_, usual)), None) => match *usual {
            // Receivers: samples at high rates, demodulated audio at modest ones; anything
            // else they do (updates, band plans) is ordinary traffic.
            Kind::RawIq | Kind::RadioAudio => match steady {
                Some(r) if r >= 150_000 => (Kind::RawIq, Certainty::VeryLikely),
                Some(_) => (Kind::RadioAudio, Certainty::VeryLikely),
                None => return None,
            },
            other => (other, Certainty::Likely),
        },
        (None, None) => return None,
    };
    if let Some(rate) = steady
        && matches!(kind, Kind::RawIq | Kind::RadioAudio)
    {
        reasons.push(Reason::ConstantRate { rate });
    }
    Some(Class {
        kind,
        certainty,
        reasons,
    })
}

fn classify(
    flow: &Flow,
    samples: &VecDeque<Sample>,
    domains: &Domains,
    program: Option<&(String, Kind)>,
) -> Option<Class> {
    let host = flow
        .remote_host
        .as_deref()
        .and_then(|h| domains.lookup(h).map(|(k, d)| (k, d.to_string())));
    // A known host speaks for itself (radio services are in the list too); otherwise radio
    // programs and ports come before the general patterns.
    if host.is_none()
        && let Some(class) = radio(flow, samples, program)
    {
        return Some(class);
    }
    if let Some(class) = file_transfer(flow, samples) {
        return class;
    }
    if let Some(class) = remote_desktop(flow, samples) {
        return class;
    }
    let port = flow.remote.port();
    // A player on a fast local network downloads minutes of film in a second, then waits:
    // the bursts are too far apart for the pattern, so a media server's port, with a large
    // download, speaks for it.
    let media_server = flow.transport == Transport::Tcp
        && media_server_port(port)
        && flow.rx_bytes >= MEDIA_SERVER_MIN_BYTES
        && flow.rx_bytes > flow.tx_bytes.saturating_mul(10);
    let by_port = if flow.transport == Transport::Udp && call_port(port) {
        Some(Kind::Call)
    } else if media_server {
        Some(Kind::Video)
    } else {
        None
    };
    let seen = pattern(flow, samples);
    let alpn = flow.meta.tls.as_ref().and_then(|t| t.alpn.first().cloned());

    if let Some((kind, domain)) = host {
        let mut reasons = vec![Reason::KnownHost { domain }];
        if let Some((k, r)) = &seen
            && *k == kind
        {
            reasons.extend(r.iter().cloned());
        }
        return Some(Class {
            kind,
            certainty: Certainty::Declared,
            reasons,
        });
    }
    if let Some(kind) = by_port {
        let mut reasons = vec![Reason::WellKnownPort { port }];
        let certainty = match &seen {
            Some((k, r)) if *k == kind => {
                reasons.extend(r.iter().cloned());
                Certainty::VeryLikely
            }
            _ => Certainty::Likely,
        };
        return Some(Class {
            kind,
            certainty,
            reasons,
        });
    }
    let (kind, mut reasons) = seen?;
    // The protocol offered in the handshake supports web and media classifications.
    let mut certainty = Certainty::Likely;
    if let Some(alpn) = alpn {
        let fits = match kind {
            Kind::Web | Kind::Video | Kind::Audio | Kind::Download | Kind::Upload => {
                matches!(alpn.as_str(), "h2" | "h3" | "http/1.1")
            }
            Kind::Call | Kind::Game => false,
            Kind::RawIq
            | Kind::RadioAudio
            | Kind::DigitalModes
            | Kind::Telemetry
            | Kind::WebSdr => false,
        };
        if fits {
            reasons.push(Reason::Protocol { alpn });
            certainty = Certainty::VeryLikely;
        }
    }
    Some(Class {
        kind,
        certainty,
        reasons,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use spectranet_model::{Process, ProcessTraffic, Verdict};

    #[test]
    fn remote_desktops_are_named_by_port() {
        let vnc = flow(Transport::Tcp, "192.168.1.20:5900", Some("notebook"));
        let screen: VecDeque<Sample> = (0..WINDOW)
            .map(|i| Sample {
                rx: if i % 15 == 0 { 1 << 20 } else { 2_000 },
                tx: 100,
                ..Default::default()
            })
            .collect();
        let class = classify(&vnc, &screen, &Domains::builtin(), None).unwrap();
        assert_eq!(class.kind, Kind::Video);
        assert_eq!(class.reasons, vec![Reason::WellKnownPort { port: 5900 }]);
        assert_eq!(port_service(5900), Some("VNC"));
        assert_eq!(port_service(22), Some("SSH · SFTP · SCP"));
        assert_eq!(port_service(443), None);
    }

    #[test]
    fn file_transfers_are_never_called_video() {
        // A fast SFTP copy arrives in bursts, like a video player filling its buffer.
        let mut sftp = flow(Transport::Tcp, "82.85.208.204:22", None);
        sftp.rx_bytes = 900 << 20;
        let bursts: VecDeque<Sample> = (0..WINDOW)
            .map(|i| Sample {
                rx: if i % 4 == 0 { 40 << 20 } else { 1 << 20 },
                tx: 60 << 10,
                ..Default::default()
            })
            .collect();
        let class = classify(&sftp, &bursts, &Domains::builtin(), None).unwrap();
        assert_eq!(class.kind, Kind::Download);
        assert!(class.reasons.contains(&Reason::WellKnownPort { port: 22 }));
        // Sending files over SMB is an upload.
        let smb = flow(Transport::Tcp, "192.168.1.50:445", Some("nucserver"));
        let up: VecDeque<Sample> = (0..WINDOW)
            .map(|_| Sample {
                rx: 20 << 10,
                tx: 30 << 20,
                ..Default::default()
            })
            .collect();
        assert_eq!(
            classify(&smb, &up, &Domains::builtin(), None).unwrap().kind,
            Kind::Upload
        );
        // A remote shell is not a transfer, nor a call or a game.
        let quiet: VecDeque<Sample> = (0..WINDOW)
            .map(|_| Sample {
                rx: 300,
                tx: 200,
                rx_pps: Some(20),
                tx_pps: Some(20),
            })
            .collect();
        assert!(classify(&sftp, &quiet, &Domains::builtin(), None).is_none());
    }

    #[test]
    fn a_film_from_a_home_media_server_is_video_even_between_bursts() {
        let mut film = flow(Transport::Tcp, "192.168.1.50:8096", Some("nucserver"));
        film.rx_bytes = 120 << 20;
        film.tx_bytes = 300 << 10;
        // Idle between two bursts: nothing in the window.
        let quiet: VecDeque<Sample> = (0..WINDOW).map(|_| Sample::default()).collect();
        let class = classify(&film, &quiet, &Domains::builtin(), None).unwrap();
        assert_eq!(class.kind, Kind::Video);
        assert!(
            class
                .reasons
                .contains(&Reason::WellKnownPort { port: 8096 })
        );
        // The server's pages and API on the same port are not called video.
        let mut api = flow(Transport::Tcp, "192.168.1.50:8096", Some("nucserver"));
        api.rx_bytes = 31 << 10;
        assert!(classify(&api, &quiet, &Domains::builtin(), None).is_none());
    }

    fn flow(transport: Transport, remote: &str, host: Option<&str>) -> Flow {
        Flow {
            transport,
            local: "192.168.1.36:50000".parse().unwrap(),
            remote: remote.parse().unwrap(),
            remote_host: host.map(Into::into),
            rx_rate: 0,
            tx_rate: 0,
            rx_bytes: 0,
            tx_bytes: 0,
            verdict: Verdict::Ok,
            note: None,
            meta: Default::default(),
        }
    }

    /// Feeds `rates` (rx, tx, rx_pps, tx_pps) one per second and returns the last class.
    fn run(mut f: Flow, rates: &[(u64, u64, u32, u32)], domains: &Domains) -> Option<Class> {
        let mut c = Classifier::new(domains.clone());
        let mut last = None;
        for (rx, tx, rp, tp) in rates {
            f.rx_rate = *rx;
            f.tx_rate = *tx;
            f.meta.rx_pps = Some(*rp);
            f.meta.tx_pps = Some(*tp);
            let mut s = Snapshot {
                source: "test".into(),
                timestamp_ms: 0,
                interval_ms: 1000,
                processes: vec![ProcessTraffic::new(
                    Process {
                        pid: 7,
                        name: "app".into(),
                        path: None,
                        app: None,
                    },
                    vec![f.clone()],
                )],
                link: None,
            };
            c.annotate(&mut s);
            last = s.processes[0].flows[0].meta.class.clone();
        }
        last
    }

    #[test]
    fn the_builtin_list_is_valid_and_specific_domains_win() {
        let (d, rejected) = Domains::parse(BUILTIN);
        assert_eq!(rejected, 0);
        assert!(d.len() > 100);
        assert_eq!(
            d.lookup("rr3---sn-hpa7zn7s.googlevideo.com"),
            Some((Kind::Video, "googlevideo.com"))
        );
        assert_eq!(
            d.lookup("audio-ak-spotify-com.akamaized.net").map(|x| x.0),
            Some(Kind::Audio)
        );
        assert_eq!(d.lookup("example.com"), None);
        assert_eq!(d.lookup("googlevideo.com.evil.example"), None);
        let (_, bad) =
            Domains::parse("video\nnope example.com\nvideo bad domain extra\nvideo x_y.com");
        assert_eq!(bad, 4);
    }

    #[test]
    fn known_hosts_are_declared() {
        let f = flow(
            Transport::Tcp,
            "142.250.180.14:443",
            Some("rr1.googlevideo.com"),
        );
        let c = run(f, &[(0, 0, 0, 0)], &Domains::builtin()).unwrap();
        assert_eq!(c.kind, Kind::Video);
        assert_eq!(c.certainty, Certainty::Declared);
    }

    #[test]
    fn periodic_bursts_are_video() {
        let mut rates = Vec::new();
        for i in 0..30 {
            let rx = if i % 5 == 0 { 2_000_000 } else { 1_000 };
            rates.push((rx, 2_000, 100, 20));
        }
        let c = run(
            flow(Transport::Tcp, "1.2.3.4:443", None),
            &rates,
            &Domains::default(),
        )
        .unwrap();
        assert_eq!(c.kind, Kind::Video);
        assert!(matches!(
            c.reasons[0],
            Reason::PeriodicBursts { every_s: 5, .. }
        ));
        assert_eq!(c.certainty, Certainty::Likely);
    }

    #[test]
    fn steady_small_udp_is_a_call_or_a_game() {
        let call: Vec<_> = (0..20).map(|_| (12_000, 11_000, 50, 50)).collect();
        let c = run(
            flow(Transport::Udp, "1.2.3.4:40000", None),
            &call,
            &Domains::default(),
        )
        .unwrap();
        assert_eq!(c.kind, Kind::Call);
        let game: Vec<_> = (0..20).map(|_| (3_000, 2_000, 60, 60)).collect();
        let c = run(
            flow(Transport::Udp, "1.2.3.4:27015", None),
            &game,
            &Domains::default(),
        )
        .unwrap();
        assert_eq!(c.kind, Kind::Game);
        // QUIC looks like many UDP packets but is web traffic.
        let c = run(
            flow(Transport::Udp, "1.2.3.4:443", None),
            &call,
            &Domains::default(),
        );
        assert_ne!(c.map(|c| c.kind), Some(Kind::Call));
        // On a call service port, pattern and port agree.
        let c = run(
            flow(Transport::Udp, "1.2.3.4:3478", None),
            &call,
            &Domains::default(),
        )
        .unwrap();
        assert_eq!((c.kind, c.certainty), (Kind::Call, Certainty::VeryLikely));
    }

    #[test]
    fn sustained_transfers_and_short_exchanges() {
        let dl: Vec<_> = (0..10).map(|_| (5_000_000, 50_000, 3000, 1500)).collect();
        let c = run(
            flow(Transport::Tcp, "1.2.3.4:443", None),
            &dl,
            &Domains::default(),
        )
        .unwrap();
        assert_eq!(c.kind, Kind::Download);
        let up: Vec<_> = (0..10).map(|_| (20_000, 900_000, 300, 700)).collect();
        let c = run(
            flow(Transport::Tcp, "1.2.3.4:443", None),
            &up,
            &Domains::default(),
        )
        .unwrap();
        assert_eq!(c.kind, Kind::Upload);
        let web: Vec<_> = (0..10)
            .map(|i| {
                if i == 3 {
                    (40_000, 3_000, 40, 20)
                } else {
                    (0, 0, 0, 0)
                }
            })
            .collect();
        let c = run(
            flow(Transport::Tcp, "1.2.3.4:443", None),
            &web,
            &Domains::default(),
        )
        .unwrap();
        assert_eq!(c.kind, Kind::Web);
    }

    #[test]
    fn bursty_udp_transfers_are_not_calls() {
        // BitTorrent-like: many packets both ways, but swinging.
        let torrent: Vec<_> = (0..20)
            .map(|i| {
                if i % 3 == 0 {
                    (900_000, 40_000, 700, 60)
                } else {
                    (50_000, 5_000, 40, 12)
                }
            })
            .collect();
        let c = run(
            flow(Transport::Udp, "79.54.65.218:17130", None),
            &torrent,
            &Domains::default(),
        );
        assert_ne!(c.map(|c| c.kind), Some(Kind::Call));
    }

    #[test]
    fn non_web_ports_and_listeners_get_no_web_label() {
        let web: Vec<_> = (0..10)
            .map(|i| {
                if i == 3 {
                    (4_000, 3_000, 10, 10)
                } else {
                    (0, 0, 0, 0)
                }
            })
            .collect();
        assert!(
            run(
                flow(Transport::Tcp, "1.2.3.4:22", None),
                &web,
                &Domains::default()
            )
            .is_none()
        );
        assert!(
            run(
                flow(Transport::Udp, "0.0.0.0:0", None),
                &web,
                &Domains::default()
            )
            .is_none()
        );
    }

    /// Like `run`, for a process with the given name.
    fn run_as(name: &str, mut f: Flow, rates: &[(u64, u64, u32, u32)]) -> Option<Class> {
        let mut c = Classifier::new(Domains::builtin());
        let mut last = None;
        for (rx, tx, rp, tp) in rates {
            f.rx_rate = *rx;
            f.tx_rate = *tx;
            f.meta.rx_pps = Some(*rp);
            f.meta.tx_pps = Some(*tp);
            let mut s = Snapshot {
                source: "test".into(),
                timestamp_ms: 0,
                interval_ms: 1000,
                processes: vec![ProcessTraffic::new(
                    Process {
                        pid: 9,
                        name: name.into(),
                        path: None,
                        app: None,
                    },
                    vec![f.clone()],
                )],
                link: None,
            };
            c.annotate(&mut s);
            last = s.processes[0].flows[0].meta.class.clone();
        }
        last
    }

    #[test]
    fn radio_streams_by_program_port_and_pattern() {
        let iq: Vec<_> = (0..10).map(|_| (2_400_000, 0, 1800, 2)).collect();
        // rtl_tcp samples into SDR++: program, port and a constant rate agree.
        let c = run_as(
            "sdrpp",
            flow(Transport::Tcp, "192.168.1.60:1234", None),
            &iq,
        )
        .unwrap();
        assert_eq!((c.kind, c.certainty), (Kind::RawIq, Certainty::VeryLikely));
        assert!(
            c.reasons
                .iter()
                .any(|r| matches!(r, Reason::ConstantRate { .. }))
        );
        // The same port from an unknown program counts only with an IQ-like stream…
        let c = run_as(
            "mystery",
            flow(Transport::Tcp, "192.168.1.60:1234", None),
            &iq,
        )
        .unwrap();
        assert_eq!(c.kind, Kind::RawIq);
        let web: Vec<_> = (0..10)
            .map(|i| {
                if i == 2 {
                    (5_000, 1_000, 5, 3)
                } else {
                    (0, 0, 0, 0)
                }
            })
            .collect();
        assert!(
            run_as("mystery", flow(Transport::Tcp, "10.0.0.5:5555", None), &web).is_none(),
            "ADB shares 5555"
        );
        // …while WSJT-X's UDP port speaks for itself.
        let c = run_as(
            "gridtracker",
            flow(Transport::Udp, "127.0.0.1:2237", None),
            &web,
        )
        .unwrap();
        assert_eq!(c.kind, Kind::DigitalModes);
        // A receiver's modest steady stream is demodulated audio.
        let audio: Vec<_> = (0..10).map(|_| (48_000, 0, 50, 1)).collect();
        let c = run_as("gqrx", flow(Transport::Udp, "127.0.0.1:7355", None), &audio).unwrap();
        assert_eq!(c.kind, Kind::RadioAudio);
        // A decoder uploading: telemetry, and the satellite service is known.
        let up: Vec<_> = (0..10)
            .map(|i| {
                if i % 4 == 0 {
                    (2_000, 90_000, 5, 70)
                } else {
                    (0, 0, 0, 0)
                }
            })
            .collect();
        let c = run_as("satdump", flow(Transport::Tcp, "1.2.3.4:443", None), &up).unwrap();
        assert_eq!(c.kind, Kind::Telemetry);
        let c = run_as(
            "satdump",
            flow(Transport::Tcp, "1.2.3.4:443", Some("db.satnogs.org")),
            &up,
        )
        .unwrap();
        assert_eq!(
            (c.kind, c.certainty),
            (Kind::Telemetry, Certainty::Declared)
        );
        // A receiver's ordinary web traffic stays ordinary.
        let c = run_as("sdrpp", flow(Transport::Tcp, "1.2.3.4:443", None), &web);
        assert_ne!(c.map(|c| c.kind), Some(Kind::RawIq));
    }

    #[test]
    fn idle_or_new_connections_are_left_alone() {
        assert!(
            run(
                flow(Transport::Tcp, "1.2.3.4:443", None),
                &[(1, 1, 1, 1); 3],
                &Domains::default()
            )
            .is_none()
        );
        assert!(
            run(
                flow(Transport::Tcp, "1.2.3.4:443", None),
                &[(0, 0, 0, 0); 10],
                &Domains::default()
            )
            .is_none()
        );
    }

    #[test]
    fn forgotten_connections_free_their_history() {
        let mut c = Classifier::default();
        let mut s = Snapshot {
            source: "t".into(),
            timestamp_ms: 0,
            interval_ms: 1000,
            processes: vec![ProcessTraffic::new(
                Process {
                    pid: 1,
                    name: "a".into(),
                    path: None,
                    app: None,
                },
                vec![flow(Transport::Tcp, "1.2.3.4:443", None)],
            )],
            link: None,
        };
        c.annotate(&mut s);
        assert_eq!(c.history.len(), 1);
        s.processes.clear();
        for _ in 0..FORGET_AFTER {
            c.annotate(&mut s);
        }
        assert!(c.history.is_empty());
    }
}
