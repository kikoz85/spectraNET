//! Simulated traffic source modelled on the GUI prototype's scenario.
//!
//! Useful for demos, tests and developing clients without capture privileges.
//! Rates fluctuate around fixed baselines with a deterministic pseudo-random walk.

use std::net::SocketAddr;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use spectranet_model::{App, Flow, Process, ProcessTraffic, Snapshot, Transport, Verdict};

use crate::{CaptureError, TrafficSource};

const LOCAL_IP: &str = "192.168.1.23";

struct MockFlow {
    flow: Flow,
    base_rx: f64,
    base_tx: f64,
}

struct MockProcess {
    process: Process,
    flows: Vec<MockFlow>,
}

/// A [`TrafficSource`] that fabricates a plausible, reproducible workload.
pub struct MockSource {
    processes: Vec<MockProcess>,
    rng: XorShift,
    last_sample: Option<Instant>,
}

impl MockSource {
    pub fn new(seed: u64) -> Self {
        Self {
            processes: scenario(),
            rng: XorShift::new(seed),
            last_sample: None,
        }
    }

    /// Advances the simulation by `dt` and returns the resulting snapshot.
    pub fn advance(&mut self, dt: Duration) -> Snapshot {
        let secs = dt.as_secs_f64();
        for proc in &mut self.processes {
            for mf in &mut proc.flows {
                mf.flow.rx_rate = jitter(&mut self.rng, mf.base_rx);
                mf.flow.tx_rate = jitter(&mut self.rng, mf.base_tx);
                mf.flow.rx_bytes += (mf.flow.rx_rate as f64 * secs) as u64;
                mf.flow.tx_bytes += (mf.flow.tx_rate as f64 * secs) as u64;
                // Plausible packet rates: full-size TCP segments, medium UDP datagrams.
                let size = match mf.flow.transport {
                    Transport::Tcp => 1_200,
                    Transport::Udp => 400,
                };
                let pps = |rate: u64| (rate.div_ceil(size)) as u32;
                mf.flow.meta.rx_pps = Some(pps(mf.flow.rx_rate));
                mf.flow.meta.tx_pps = Some(pps(mf.flow.tx_rate));
            }
        }

        let processes = self
            .processes
            .iter()
            .enumerate()
            .map(|(i, p)| {
                let mut traffic = ProcessTraffic::new(
                    p.process.clone(),
                    p.flows.iter().map(|mf| mf.flow.clone()).collect(),
                );
                // Deterministic, plausible CPU and memory to go with the traffic.
                let busy = ((traffic.rx_rate + traffic.tx_rate) as f64 + 1.0).log10();
                traffic.resources = Some(spectranet_model::Resources {
                    ppid: Some(1),
                    cpu_tenths: (busy * 25.0) as u32 + i as u32 * 7,
                    memory: 60_000_000 + i as u64 * 83_000_000,
                    user: Some("demo".into()),
                });
                traffic
            })
            .collect();

        Snapshot {
            source: self.name().to_string(),
            timestamp_ms: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map_or(0, |d| d.as_millis() as u64),
            interval_ms: dt.as_millis() as u64,
            processes,
            link: None,
        }
    }
}

impl Default for MockSource {
    fn default() -> Self {
        Self::new(0x5EC7_4A2E)
    }
}

impl TrafficSource for MockSource {
    fn name(&self) -> &'static str {
        "mock"
    }

    fn sample(&mut self) -> Result<Snapshot, CaptureError> {
        let now = Instant::now();
        let dt = self
            .last_sample
            .map_or(Duration::from_secs(1), |prev| now - prev);
        self.last_sample = Some(now);
        Ok(self.advance(dt))
    }
}

/// Returns `base` varied by up to ±25%.
fn jitter(rng: &mut XorShift, base: f64) -> u64 {
    let factor = 0.75 + rng.next_f64() * 0.5;
    (base * factor).round() as u64
}

/// Minimal xorshift64* generator: deterministic and dependency-free.
struct XorShift(u64);

impl XorShift {
    fn new(seed: u64) -> Self {
        Self(seed.max(1))
    }

    fn next_f64(&mut self) -> f64 {
        self.0 ^= self.0 >> 12;
        self.0 ^= self.0 << 25;
        self.0 ^= self.0 >> 27;
        let v = self.0.wrapping_mul(0x2545_F491_4F6C_DD1D);
        (v >> 11) as f64 / (1u64 << 53) as f64
    }
}

struct FlowSpec {
    transport: Transport,
    local_port: u16,
    remote: &'static str,
    host: Option<&'static str>,
    kib_rx: f64,
    kib_tx: f64,
    verdict: Verdict,
    note: Option<&'static str>,
}

fn tcp(
    local_port: u16,
    remote: &'static str,
    host: &'static str,
    kib_rx: f64,
    kib_tx: f64,
) -> FlowSpec {
    FlowSpec {
        transport: Transport::Tcp,
        local_port,
        remote,
        host: Some(host),
        kib_rx,
        kib_tx,
        verdict: Verdict::Ok,
        note: None,
    }
}

fn process(pid: u32, name: &str, path: &str, flows: Vec<FlowSpec>) -> MockProcess {
    let flows = flows
        .into_iter()
        .map(|spec| MockFlow {
            flow: Flow {
                meta: Default::default(),
                transport: spec.transport,
                local: SocketAddr::new(LOCAL_IP.parse().unwrap(), spec.local_port),
                remote: spec.remote.parse().unwrap(),
                remote_host: spec.host.map(str::to_string),
                rx_rate: 0,
                tx_rate: 0,
                rx_bytes: 0,
                tx_bytes: 0,
                verdict: spec.verdict,
                note: spec.note.map(str::to_string),
            },
            base_rx: spec.kib_rx * 1024.0,
            base_tx: spec.kib_tx * 1024.0,
        })
        .collect();
    MockProcess {
        process: Process {
            pid,
            name: name.to_string(),
            path: Some(path.to_string()),
            app: app_of(path),
        },
        flows,
    }
}

/// Simplified macOS bundle rule: the outermost `*.app` directory owns the executable.
fn app_of(path: &str) -> Option<App> {
    let end = path.find(".app/")? + ".app".len();
    let bundle = &path[..end];
    let name = bundle.rsplit('/').next()?.trim_end_matches(".app");
    let rest = &path[end..];
    Some(App {
        name: name.to_string(),
        path: bundle.to_string(),
        main: rest.starts_with("/Contents/MacOS/") && rest.matches('/').count() == 3,
    })
}

fn scenario() -> Vec<MockProcess> {
    vec![
        process(
            4892,
            "Google Chrome",
            "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome",
            vec![tcp(
                52114,
                "142.250.180.206:443",
                "www.google.com",
                142.5,
                18.2,
            )],
        ),
        process(
            4901,
            "Google Chrome Helper",
            "/Applications/Google Chrome.app/Contents/Frameworks/Google Chrome Framework.framework/Versions/154.0.8037.98/Helpers/Google Chrome Helper.app/Contents/MacOS/Google Chrome Helper",
            vec![
                tcp(
                    52120,
                    "173.194.182.9:443",
                    "rr3---sn-hpa7zn7s.googlevideo.com",
                    880.0,
                    6.0,
                ),
                FlowSpec {
                    transport: Transport::Udp,
                    local_port: 50527,
                    remote: "142.251.127.84:443",
                    host: Some("www.youtube.com"),
                    kib_rx: 64.0,
                    kib_tx: 9.0,
                    verdict: Verdict::Ok,
                    note: None,
                },
            ],
        ),
        process(
            8120,
            "Spotify",
            "/Applications/Spotify.app/Contents/MacOS/Spotify",
            vec![tcp(
                52201,
                "104.199.65.124:443",
                "audio-ak.spotify.com",
                320.0,
                4.1,
            )],
        ),
        process(
            10440,
            "Discord",
            "/Applications/Discord.app/Contents/MacOS/Discord",
            vec![
                tcp(
                    52305,
                    "162.159.135.232:443",
                    "gateway.discord.gg",
                    12.0,
                    3.0,
                ),
                FlowSpec {
                    transport: Transport::Udp,
                    local_port: 61022,
                    remote: "66.22.196.18:50004",
                    host: Some("rotterdam1234.discord.media"),
                    kib_rx: 45.2,
                    kib_tx: 38.0,
                    verdict: Verdict::Ok,
                    note: None,
                },
            ],
        ),
        process(
            3110,
            "steam_osx",
            "/Users/demo/Library/Application Support/Steam/Steam.AppBundle/Steam/Contents/MacOS/steam_osx",
            vec![FlowSpec {
                verdict: Verdict::Warn,
                note: Some("sustained high-bandwidth download"),
                ..tcp(
                    52410,
                    "155.133.246.50:443",
                    "cdn.steampowered.com",
                    1240.0,
                    12.0,
                )
            }],
        ),
        process(
            9912,
            "svc_update",
            "/Users/Shared/.svc/svc_update",
            vec![FlowSpec {
                transport: Transport::Tcp,
                local_port: 52777,
                remote: "185.220.101.5:80",
                host: None,
                kib_rx: 12.0,
                kib_tx: 480.5,
                verdict: Verdict::Alert,
                note: Some("unencrypted HTTP upload to a known Tor exit node"),
            }],
        ),
        process(
            112,
            "mDNSResponder",
            "/usr/sbin/mDNSResponder",
            vec![FlowSpec {
                transport: Transport::Udp,
                local_port: 5353,
                remote: "192.168.1.1:53",
                host: None,
                kib_rx: 2.1,
                kib_tx: 0.8,
                verdict: Verdict::Ok,
                note: None,
            }],
        ),
    ]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn app_of_matches_bundle_rules() {
        let main = app_of("/Applications/Google Chrome.app/Contents/MacOS/Google Chrome").unwrap();
        assert_eq!((main.name.as_str(), main.main), ("Google Chrome", true));
        let helper =
            app_of("/Applications/Google Chrome.app/Contents/Frameworks/X.framework/Helpers/H.app/Contents/MacOS/H")
                .unwrap();
        assert_eq!(helper.path, "/Applications/Google Chrome.app");
        assert!(!helper.main);
        assert_eq!(app_of("/usr/sbin/mDNSResponder"), None);
        assert_eq!(app_of("/Users/Shared/.svc/svc_update"), None);
    }

    #[test]
    fn same_seed_gives_same_snapshots() {
        let mut a = MockSource::new(42);
        let mut b = MockSource::new(42);
        for _ in 0..5 {
            let (sa, sb) = (
                a.advance(Duration::from_secs(1)),
                b.advance(Duration::from_secs(1)),
            );
            assert_eq!(sa.processes, sb.processes);
        }
    }

    #[test]
    fn rates_stay_within_jitter_bounds() {
        let mut source = MockSource::new(7);
        for _ in 0..50 {
            let snap = source.advance(Duration::from_millis(500));
            let chrome = snap
                .processes
                .iter()
                .find(|p| p.process.pid == 4892)
                .unwrap();
            let base = 142.5 * 1024.0;
            let rx = chrome.flows[0].rx_rate as f64;
            assert!(
                rx >= base * 0.75 - 1.0 && rx <= base * 1.25 + 1.0,
                "rx {rx} out of bounds"
            );
        }
    }

    #[test]
    fn byte_totals_accumulate() {
        let mut source = MockSource::new(1);
        let first = source.advance(Duration::from_secs(1));
        let second = source.advance(Duration::from_secs(1));
        let total = |s: &Snapshot| s.processes.iter().map(|p| p.rx_bytes).sum::<u64>();
        assert!(total(&second) > total(&first));
    }

    #[test]
    fn scenario_contains_one_alert() {
        let snap = MockSource::default().advance(Duration::from_secs(1));
        assert_eq!(snap.processes.len(), 7);
        let alerts: Vec<_> = snap
            .processes
            .iter()
            .filter(|p| p.verdict == Verdict::Alert)
            .collect();
        assert_eq!(alerts.len(), 1);
        assert_eq!(alerts[0].process.name, "svc_update");
    }
}
