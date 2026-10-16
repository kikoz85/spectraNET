//! A whole check: router, internet targets and DNS measured in parallel while the
//! applications' traffic is observed, then the verdict; the path on request.

use std::net::{IpAddr, ToSocketAddrs};
use std::time::{Duration, Instant};

use crate::{Apps, Probe, Report, Thresholds, diagnose, dns, gateway, path, ping};

/// What to check.
#[derive(Debug, Clone, Default)]
pub struct Config {
    /// Internet targets (names or addresses); [`crate::DEFAULT_TARGETS`] when empty.
    pub targets: Vec<String>,
    /// Also trace the path to the first target.
    pub path: bool,
    pub ping: ping::Options,
    pub thresholds: Thresholds,
}

/// Where a check is.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Phase {
    /// Router, internet, DNS and applications, all at once.
    Measuring,
    Path,
    Done,
}

/// How long the applications are watched (the probes take about as long).
pub const APPS_WINDOW: Duration = Duration::from_secs(4);

/// Resolves a target to one address (IPv4 preferred: the path is traced over IPv4).
pub fn resolve_target(target: &str) -> Option<IpAddr> {
    if let Ok(ip) = target.parse::<IpAddr>() {
        return Some(ip);
    }
    let addrs: Vec<IpAddr> = (target, 443)
        .to_socket_addrs()
        .ok()?
        .map(|a| a.ip())
        .collect();
    addrs
        .iter()
        .find(|a| a.is_ipv4())
        .or(addrs.first())
        .copied()
}

/// Runs a check. `apps` watches the applications for the given time and returns their
/// traffic; `baseline_ms` is the usual internet latency when known; `progress` hears about
/// each phase.
pub fn run(
    config: &Config,
    apps: impl FnOnce(Duration) -> Apps,
    baseline_ms: Option<f64>,
    progress: impl Fn(Phase),
) -> Report {
    let started = Instant::now();
    let started_ms = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_millis() as u64);
    progress(Phase::Measuring);
    let targets: Vec<String> = if config.targets.is_empty() {
        crate::DEFAULT_TARGETS
            .iter()
            .map(|t| t.to_string())
            .collect()
    } else {
        config.targets.clone()
    };
    let options = config.ping;
    let router = std::thread::spawn(move || match gateway::default_gateway() {
        Some(ip) => ping::probe(&ip.to_string(), ip, options, &[80, 443, 53], false),
        None => Probe::Unmeasurable {
            why: "no default route".into(),
        },
    });
    let internet: Vec<_> = targets
        .iter()
        .cloned()
        .map(|target| {
            std::thread::spawn(move || match resolve_target(&target) {
                Some(ip) => ping::probe(&target, ip, options, &ping::TCP_PORTS, true),
                None => Probe::Unmeasurable {
                    why: format!("{target}: name not found"),
                },
            })
        })
        .collect();
    let names = std::thread::spawn(dns::measure);
    let apps = apps(APPS_WINDOW);
    fn unmeasurable<T>() -> Probe<T> {
        Probe::Unmeasurable {
            why: "the measurement stopped unexpectedly".into(),
        }
    }
    let gateway = router.join().unwrap_or_else(|_| unmeasurable());
    let internet: Vec<_> = internet
        .into_iter()
        .map(|t| t.join().unwrap_or_else(|_| unmeasurable()))
        .collect();
    let dns = names.join().unwrap_or_else(|_| unmeasurable());
    let verdict = diagnose(
        &gateway,
        &internet,
        &dns,
        &apps,
        baseline_ms,
        &config.thresholds,
    );
    let path = config.path.then(|| {
        progress(Phase::Path);
        match internet
            .iter()
            .filter_map(Probe::measured)
            .map(|l| l.address)
            .next()
            .or_else(|| targets.first().and_then(|t| resolve_target(t)))
        {
            Some(ip) => path::trace(ip),
            None => Probe::Unmeasurable {
                why: "no target to trace".into(),
            },
        }
    });
    progress(Phase::Done);
    Report {
        started_ms,
        duration_ms: started.elapsed().as_millis() as u64,
        gateway,
        internet,
        dns,
        apps,
        path,
        baseline_ms,
        verdict,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn addresses_and_names_resolve() {
        assert_eq!(
            resolve_target("192.0.2.7"),
            Some("192.0.2.7".parse().unwrap())
        );
        assert_eq!(resolve_target("::1"), Some("::1".parse().unwrap()));
        assert!(resolve_target("localhost").is_some());
    }
}
