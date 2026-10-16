//! The applications' traffic during a check, from the snapshots spectraNET already takes.

use std::collections::HashMap;

use spectranet_model::{Snapshot, group_by_app};

use crate::{AppLoad, Apps};

/// The applications' traffic, averaged over snapshots, busiest first.
pub fn from_snapshots(snapshots: &[Snapshot], peak: Option<u64>) -> Apps {
    if snapshots.is_empty() {
        return Apps {
            recent_peak: peak,
            ..Apps::default()
        };
    }
    let n = snapshots.len() as u64;
    let mut sums: HashMap<String, (u64, u64)> = HashMap::new();
    for s in snapshots {
        for app in group_by_app(s.processes.clone()) {
            let e = sums.entry(app.name.clone()).or_default();
            e.0 += app.rx_rate;
            e.1 += app.tx_rate;
        }
    }
    let total_rx = sums.values().map(|v| v.0).sum::<u64>() / n;
    let total_tx = sums.values().map(|v| v.1).sum::<u64>() / n;
    let total = (total_rx + total_tx).max(1);
    let mut top: Vec<AppLoad> = sums
        .into_iter()
        .map(|(name, (rx, tx))| AppLoad {
            name,
            rx_rate: rx / n,
            tx_rate: tx / n,
            share: ((rx + tx) / n) as f64 / total as f64,
        })
        .filter(|a| a.rx_rate + a.tx_rate > 0)
        .collect();
    top.sort_by_key(|a| std::cmp::Reverse(a.rx_rate + a.tx_rate));
    top.truncate(5);
    Apps {
        total_rx,
        total_tx,
        recent_peak: peak,
        top,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use spectranet_model::{Process, ProcessTraffic};

    fn snapshot(apps: &[(&str, u64)]) -> Snapshot {
        Snapshot {
            source: "t".into(),
            timestamp_ms: 0,
            interval_ms: 1000,
            processes: apps
                .iter()
                .enumerate()
                .map(|(i, (name, rx))| {
                    let mut p = ProcessTraffic::new(
                        Process {
                            pid: i as u32 + 1,
                            name: (*name).into(),
                            path: None,
                            app: None,
                        },
                        Vec::new(),
                    );
                    p.rx_rate = *rx;
                    p
                })
                .collect(),
            link: None,
        }
    }

    #[test]
    fn apps_are_averaged_and_shared() {
        let snaps = [
            snapshot(&[("qbittorrent", 9_000_000), ("Safari", 1_000_000)]),
            snapshot(&[("qbittorrent", 7_000_000), ("Safari", 1_000_000)]),
        ];
        let apps = from_snapshots(&snaps, Some(10_000_000));
        assert_eq!(apps.total_rx, 9_000_000);
        assert_eq!(apps.top[0].name, "qbittorrent");
        assert_eq!(apps.top[0].rx_rate, 8_000_000);
        assert!((apps.top[0].share - 8.0 / 9.0).abs() < 1e-9);
        assert_eq!(apps.recent_peak, Some(10_000_000));
        assert_eq!(from_snapshots(&[], None).top.len(), 0);
    }
}
