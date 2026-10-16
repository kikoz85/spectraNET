//! "Is my network slow?": a ten-second check of the router, the internet and DNS, next to
//! what the applications are doing, and a plain verdict.
//!
//! Everything is measured from this computer, with no privilege beyond what spectraNET
//! already has: unprivileged ICMP echo where the system allows it (macOS, Linux with
//! `ping_group_range`, Windows' ICMP API), otherwise the time to open a TCP connection. A
//! measurement that can't be made is reported as such, never as an error. Only the router,
//! the chosen internet targets and the system's DNS are contacted, and only during a check.
//!
//! The verdict comes from [`diagnose`], whose thresholds all live in [`Thresholds`].

use std::net::IpAddr;

use serde::{Deserialize, Serialize};

pub mod apps;
pub mod check;
pub mod dns;
pub mod gateway;
pub mod path;
pub mod ping;

/// The internet targets used when none are configured.
pub const DEFAULT_TARGETS: [&str; 2] = ["1.1.1.1", "9.9.9.9"];

/// How a latency was measured.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum Method {
    /// ICMP echo (ping).
    Icmp,
    /// Time to open a TCP connection to this port: a little longer than a ping, as it
    /// includes the handshake.
    Tcp { port: u16 },
}

/// A measurement, or why it could not be made.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "status", rename_all = "snake_case")]
pub enum Probe<T> {
    Measured(T),
    Unmeasurable { why: String },
}

impl<T> Probe<T> {
    pub fn measured(&self) -> Option<&T> {
        match self {
            Probe::Measured(t) => Some(t),
            Probe::Unmeasurable { .. } => None,
        }
    }
}

/// Round trips to one host.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Latency {
    /// As given (a name or an address).
    pub target: String,
    pub address: IpAddr,
    pub method: Method,
    pub sent: u32,
    pub received: u32,
    pub min_ms: f64,
    pub avg_ms: f64,
    pub max_ms: f64,
    /// Mean difference between consecutive round trips (RFC 3550 style, without smoothing).
    pub jitter_ms: f64,
}

impl Latency {
    /// From round-trip times (`None` for a lost probe).
    pub fn from_samples(
        target: &str,
        address: IpAddr,
        method: Method,
        samples: &[Option<f64>],
    ) -> Self {
        let rtts: Vec<f64> = samples.iter().flatten().copied().collect();
        let n = rtts.len().max(1) as f64;
        let jitter = if rtts.len() > 1 {
            rtts.windows(2).map(|w| (w[1] - w[0]).abs()).sum::<f64>() / (rtts.len() - 1) as f64
        } else {
            0.0
        };
        Self {
            target: target.to_string(),
            address,
            method,
            sent: samples.len() as u32,
            received: rtts.len() as u32,
            min_ms: if rtts.is_empty() {
                0.0
            } else {
                rtts.iter().copied().fold(f64::INFINITY, f64::min)
            },
            avg_ms: rtts.iter().sum::<f64>() / n,
            max_ms: rtts.iter().copied().fold(0.0, f64::max),
            jitter_ms: jitter,
        }
    }

    /// Share of probes lost, in percent.
    pub fn loss_percent(&self) -> f64 {
        if self.sent == 0 {
            return 100.0;
        }
        f64::from(self.sent - self.received) * 100.0 / f64::from(self.sent)
    }
}

/// Name resolution with the system's resolver.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Dns {
    /// Each lookup of a name no cache can know, in milliseconds.
    pub lookups_ms: Vec<f64>,
    pub median_ms: f64,
    /// A well-known name resolved (false: the resolver gives no answers at all).
    pub resolves: bool,
}

/// One application's traffic during the check.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct AppLoad {
    pub name: String,
    /// Bytes per second, averaged over the check.
    pub rx_rate: u64,
    pub tx_rate: u64,
    /// Share of all the computer's traffic, 0–1.
    pub share: f64,
}

/// What the applications did during the check.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct Apps {
    /// Bytes per second, all applications.
    pub total_rx: u64,
    pub total_tx: u64,
    /// The highest total seen recently (the service keeps it), to tell "busy" from "active".
    pub recent_peak: Option<u64>,
    /// Busiest first.
    pub top: Vec<AppLoad>,
}

/// One hop of the path to an internet target.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Hop {
    pub ttl: u8,
    /// `None`: no answer at this hop.
    pub address: Option<IpAddr>,
    pub sent: u32,
    pub received: u32,
    pub avg_ms: Option<f64>,
}

/// The outcome, in a few words.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "verdict", rename_all = "snake_case")]
pub enum Verdict {
    /// Router, internet and DNS fine; no application saturating the line.
    AllGood,
    /// Between this computer and the router: Wi-Fi or cable.
    LocalLink,
    /// After the router: the line or the provider.
    Provider,
    /// The internet is slow but the router could not be measured: where can't be told.
    Line,
    /// Everything answers, names take long.
    DnsSlow,
    /// The network is fine; one application fills it.
    App { name: String },
    /// Nothing could be measured.
    Unmeasured,
}

impl Verdict {
    /// Whether a problem was found (`snet check` exits with 1).
    pub fn is_problem(&self) -> bool {
        !matches!(self, Verdict::AllGood | Verdict::Unmeasured)
    }
}

/// The complete result of a check.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Report {
    /// Milliseconds since the Unix epoch.
    pub started_ms: u64,
    pub duration_ms: u64,
    pub gateway: Probe<Latency>,
    pub internet: Vec<Probe<Latency>>,
    pub dns: Probe<Dns>,
    pub apps: Apps,
    /// Hop by hop, when asked for.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub path: Option<Probe<Vec<Hop>>>,
    /// The usual internet latency (median of recent checks), when the service knows it.
    pub baseline_ms: Option<f64>,
    pub verdict: Verdict,
}

/// Every threshold of the diagnosis, in one place.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct Thresholds {
    /// Router: more loss than this (percent) is a local link problem…
    pub gateway_loss_percent: f64,
    /// …and so is a slower average round trip (ms).
    pub gateway_latency_ms: f64,
    /// Internet: more loss than this (percent) is a line problem…
    pub internet_loss_percent: f64,
    /// …and so is a latency this many times the usual one…
    pub internet_factor: f64,
    /// …and at least this much above it (ms)…
    pub internet_margin_ms: f64,
    /// …or, with no usual latency known, above this (ms)…
    pub internet_latency_ms: f64,
    /// …or with more jitter than this (ms).
    pub internet_jitter_ms: f64,
    /// DNS: a lookup slower than this (ms, median) is slow DNS.
    pub dns_ms: f64,
    /// An application with this share of the traffic (0–1)…
    pub app_share: f64,
    /// …while the traffic is at least this share of the recent peak…
    pub app_peak_share: f64,
    /// …or, with no peak known, at least this many bytes per second.
    pub app_busy_rate: u64,
}

impl Default for Thresholds {
    fn default() -> Self {
        Self {
            gateway_loss_percent: 2.0,
            gateway_latency_ms: 30.0,
            internet_loss_percent: 2.0,
            internet_factor: 2.0,
            internet_margin_ms: 40.0,
            internet_latency_ms: 150.0,
            internet_jitter_ms: 30.0,
            dns_ms: 300.0,
            app_share: 0.8,
            app_peak_share: 0.7,
            app_busy_rate: 1 << 20,
        }
    }
}

impl Thresholds {
    fn gateway_bad(&self, g: &Latency) -> bool {
        g.received == 0
            || g.loss_percent() > self.gateway_loss_percent
            || g.avg_ms > self.gateway_latency_ms
    }

    fn internet_bad(&self, i: &Latency, baseline: Option<f64>) -> bool {
        if i.received == 0 || i.loss_percent() > self.internet_loss_percent {
            return true;
        }
        match baseline {
            Some(usual) => {
                i.avg_ms > usual * self.internet_factor
                    && i.avg_ms > usual + self.internet_margin_ms
            }
            None => i.avg_ms > self.internet_latency_ms || i.jitter_ms > self.internet_jitter_ms,
        }
    }

    /// The application filling the line, if one does.
    fn saturating_app<'a>(&self, apps: &'a Apps) -> Option<&'a AppLoad> {
        let top = apps.top.first()?;
        let total = apps.total_rx + apps.total_tx;
        let busy = match apps.recent_peak {
            Some(peak) if peak > 0 => total as f64 >= peak as f64 * self.app_peak_share,
            _ => total >= self.app_busy_rate,
        };
        (busy && top.share >= self.app_share).then_some(top)
    }
}

/// The verdict for a set of measurements.
///
/// In order: the router (Wi-Fi or cable), the internet past the router (line or provider; all
/// measured targets must agree, so one unreachable target is not a line problem), DNS, then
/// an application filling a line that is otherwise fine.
pub fn diagnose(
    gateway: &Probe<Latency>,
    internet: &[Probe<Latency>],
    dns: &Probe<Dns>,
    apps: &Apps,
    baseline_ms: Option<f64>,
    t: &Thresholds,
) -> Verdict {
    let measured: Vec<&Latency> = internet.iter().filter_map(Probe::measured).collect();
    let gateway = gateway.measured();
    if gateway.is_none() && measured.is_empty() && dns.measured().is_none() {
        return Verdict::Unmeasured;
    }
    if gateway.is_some_and(|g| t.gateway_bad(g)) {
        return Verdict::LocalLink;
    }
    let internet_bad =
        !measured.is_empty() && measured.iter().all(|i| t.internet_bad(i, baseline_ms));
    if internet_bad {
        // A line full of one application's traffic is slow because of it.
        if let Some(app) = t.saturating_app(apps) {
            return Verdict::App {
                name: app.name.clone(),
            };
        }
        return if gateway.is_some() {
            Verdict::Provider
        } else {
            Verdict::Line
        };
    }
    if let Some(d) = dns.measured()
        && (!d.resolves || d.median_ms > t.dns_ms)
    {
        return Verdict::DnsSlow;
    }
    if let Some(app) = t.saturating_app(apps) {
        return Verdict::App {
            name: app.name.clone(),
        };
    }
    Verdict::AllGood
}

#[cfg(test)]
mod tests {
    use super::*;

    fn lat(avg: f64, sent: u32, received: u32, jitter: f64) -> Probe<Latency> {
        Probe::Measured(Latency {
            target: "t".into(),
            address: "192.0.2.1".parse().unwrap(),
            method: Method::Icmp,
            sent,
            received,
            min_ms: avg,
            avg_ms: avg,
            max_ms: avg,
            jitter_ms: jitter,
        })
    }

    fn ok_gateway() -> Probe<Latency> {
        lat(3.0, 20, 20, 0.5)
    }

    fn ok_internet() -> Vec<Probe<Latency>> {
        vec![lat(20.0, 20, 20, 2.0), lat(25.0, 20, 20, 2.0)]
    }

    fn dns(ms: f64) -> Probe<Dns> {
        Probe::Measured(Dns {
            lookups_ms: vec![ms; 3],
            median_ms: ms,
            resolves: true,
        })
    }

    fn quiet() -> Apps {
        Apps::default()
    }

    fn busy(share: f64, total: u64, peak: Option<u64>) -> Apps {
        Apps {
            total_rx: total,
            total_tx: 0,
            recent_peak: peak,
            top: vec![AppLoad {
                name: "qbittorrent".into(),
                rx_rate: (total as f64 * share) as u64,
                tx_rate: 0,
                share,
            }],
        }
    }

    fn unmeasurable<T>() -> Probe<T> {
        Probe::Unmeasurable {
            why: "not allowed".into(),
        }
    }

    const T: Thresholds = Thresholds {
        gateway_loss_percent: 2.0,
        gateway_latency_ms: 30.0,
        internet_loss_percent: 2.0,
        internet_factor: 2.0,
        internet_margin_ms: 40.0,
        internet_latency_ms: 150.0,
        internet_jitter_ms: 30.0,
        dns_ms: 300.0,
        app_share: 0.8,
        app_peak_share: 0.7,
        app_busy_rate: 1 << 20,
    };

    #[test]
    fn the_constant_in_the_tests_is_the_default() {
        assert_eq!(T, Thresholds::default());
    }

    #[test]
    fn all_good() {
        let v = diagnose(
            &ok_gateway(),
            &ok_internet(),
            &dns(40.0),
            &quiet(),
            Some(22.0),
            &T,
        );
        assert_eq!(v, Verdict::AllGood);
        assert!(!v.is_problem());
    }

    #[test]
    fn router_loss_or_latency_is_the_local_link() {
        // 1 lost in 20 = 5% > 2%.
        let lossy = lat(3.0, 20, 19, 0.5);
        assert_eq!(
            diagnose(&lossy, &ok_internet(), &dns(40.0), &quiet(), None, &T),
            Verdict::LocalLink
        );
        // Exactly at the limit is still fine; just above is not.
        assert_eq!(
            diagnose(
                &lat(30.0, 20, 20, 1.0),
                &ok_internet(),
                &dns(40.0),
                &quiet(),
                None,
                &T
            ),
            Verdict::AllGood
        );
        assert_eq!(
            diagnose(
                &lat(30.1, 20, 20, 1.0),
                &ok_internet(),
                &dns(40.0),
                &quiet(),
                None,
                &T
            ),
            Verdict::LocalLink
        );
        // A router that never answered counts as bad when it was measurable.
        assert_eq!(
            diagnose(
                &lat(0.0, 20, 0, 0.0),
                &ok_internet(),
                &dns(40.0),
                &quiet(),
                None,
                &T
            ),
            Verdict::LocalLink
        );
    }

    #[test]
    fn internet_trouble_past_a_good_router_is_the_provider() {
        let lossy = vec![lat(20.0, 20, 18, 2.0), lat(25.0, 20, 17, 2.0)];
        assert_eq!(
            diagnose(&ok_gateway(), &lossy, &dns(40.0), &quiet(), None, &T),
            Verdict::Provider
        );
        // Far above the usual latency: 2× and +40 ms.
        let slow = vec![lat(90.0, 20, 20, 2.0), lat(95.0, 20, 20, 2.0)];
        assert_eq!(
            diagnose(&ok_gateway(), &slow, &dns(40.0), &quiet(), Some(20.0), &T),
            Verdict::Provider
        );
        // Twice the usual but only +30 ms: not "far above".
        let bit_slow = vec![lat(50.0, 20, 20, 2.0), lat(50.0, 20, 20, 2.0)];
        assert_eq!(
            diagnose(
                &ok_gateway(),
                &bit_slow,
                &dns(40.0),
                &quiet(),
                Some(20.0),
                &T
            ),
            Verdict::AllGood
        );
        // No usual latency known: absolute limits, latency or jitter.
        let jittery = vec![lat(60.0, 20, 20, 45.0), lat(60.0, 20, 20, 50.0)];
        assert_eq!(
            diagnose(&ok_gateway(), &jittery, &dns(40.0), &quiet(), None, &T),
            Verdict::Provider
        );
    }

    #[test]
    fn one_bad_target_is_not_the_line() {
        let mixed = vec![lat(20.0, 20, 0, 0.0), lat(25.0, 20, 20, 2.0)];
        assert_eq!(
            diagnose(&ok_gateway(), &mixed, &dns(40.0), &quiet(), None, &T),
            Verdict::AllGood
        );
    }

    #[test]
    fn without_the_router_a_slow_internet_is_just_the_line() {
        let slow = vec![lat(400.0, 20, 20, 2.0), lat(380.0, 20, 20, 2.0)];
        assert_eq!(
            diagnose(&unmeasurable(), &slow, &dns(40.0), &quiet(), None, &T),
            Verdict::Line
        );
    }

    #[test]
    fn slow_names_with_a_good_network_are_dns() {
        assert_eq!(
            diagnose(
                &ok_gateway(),
                &ok_internet(),
                &dns(301.0),
                &quiet(),
                None,
                &T
            ),
            Verdict::DnsSlow
        );
        assert_eq!(
            diagnose(
                &ok_gateway(),
                &ok_internet(),
                &dns(300.0),
                &quiet(),
                None,
                &T
            ),
            Verdict::AllGood
        );
        let silent = Probe::Measured(Dns {
            lookups_ms: vec![2000.0],
            median_ms: 2000.0,
            resolves: false,
        });
        assert_eq!(
            diagnose(&ok_gateway(), &ok_internet(), &silent, &quiet(), None, &T),
            Verdict::DnsSlow
        );
        // Slow DNS on a broken line: the line is the problem.
        let slow = vec![lat(400.0, 20, 20, 2.0), lat(380.0, 20, 20, 2.0)];
        assert_eq!(
            diagnose(&ok_gateway(), &slow, &dns(900.0), &quiet(), None, &T),
            Verdict::Provider
        );
    }

    #[test]
    fn an_app_filling_the_line_is_named() {
        let app = Verdict::App {
            name: "qbittorrent".into(),
        };
        // 85% of a busy line (80% of the recent peak).
        assert_eq!(
            diagnose(
                &ok_gateway(),
                &ok_internet(),
                &dns(40.0),
                &busy(0.85, 8_000_000, Some(10_000_000)),
                None,
                &T
            ),
            app
        );
        // It also explains a slow internet while it lasts.
        let slow = vec![lat(400.0, 20, 20, 2.0), lat(380.0, 20, 20, 2.0)];
        assert_eq!(
            diagnose(
                &ok_gateway(),
                &slow,
                &dns(40.0),
                &busy(0.9, 9_000_000, Some(10_000_000)),
                None,
                &T
            ),
            app
        );
        // 85% of an idle line is not filling anything.
        assert_eq!(
            diagnose(
                &ok_gateway(),
                &ok_internet(),
                &dns(40.0),
                &busy(0.85, 20_000, Some(10_000_000)),
                None,
                &T
            ),
            Verdict::AllGood
        );
        // Just below the share.
        assert_eq!(
            diagnose(
                &ok_gateway(),
                &ok_internet(),
                &dns(40.0),
                &busy(0.79, 9_000_000, Some(10_000_000)),
                None,
                &T
            ),
            Verdict::AllGood
        );
        // No peak known: an absolute rate.
        assert_eq!(
            diagnose(
                &ok_gateway(),
                &ok_internet(),
                &dns(40.0),
                &busy(0.9, 2 << 20, None),
                None,
                &T
            ),
            app
        );
    }

    #[test]
    fn nothing_measurable_is_said_so() {
        let v = diagnose(
            &unmeasurable(),
            &[unmeasurable()],
            &unmeasurable(),
            &quiet(),
            None,
            &T,
        );
        assert_eq!(v, Verdict::Unmeasured);
        assert!(!v.is_problem());
    }

    #[test]
    fn statistics_from_samples() {
        let l = Latency::from_samples(
            "1.1.1.1",
            "1.1.1.1".parse().unwrap(),
            Method::Tcp { port: 443 },
            &[Some(10.0), None, Some(14.0), Some(12.0)],
        );
        assert_eq!((l.sent, l.received), (4, 3));
        assert_eq!(l.loss_percent(), 25.0);
        assert_eq!((l.min_ms, l.max_ms, l.avg_ms), (10.0, 14.0, 12.0));
        assert_eq!(l.jitter_ms, 3.0);
        let none = Latency::from_samples(
            "x",
            "192.0.2.9".parse().unwrap(),
            Method::Icmp,
            &[None, None],
        );
        assert_eq!((none.received, none.min_ms, none.avg_ms), (0, 0.0, 0.0));
        assert_eq!(none.loss_percent(), 100.0);
    }

    #[test]
    fn reports_round_trip_through_json() {
        let r = Report {
            started_ms: 1,
            duration_ms: 10_000,
            gateway: ok_gateway(),
            internet: ok_internet(),
            dns: dns(40.0),
            apps: busy(0.5, 1000, None),
            path: None,
            baseline_ms: None,
            verdict: Verdict::AllGood,
        };
        let text = serde_json::to_string(&r).unwrap();
        assert!(text.contains("\"method\":{\"kind\":\"icmp\"}"));
        assert_eq!(serde_json::from_str::<Report>(&text).unwrap(), r);
    }
}
