//! "Is my network slow?" in the service: checks run here (with what snetd knows besides —
//! the applications' traffic, the usual latency, the recent peak), are recorded, and an
//! optional watch alerts when the internet latency stays high.

use std::collections::VecDeque;
use std::sync::Mutex;
use std::time::{Duration, Instant};

use anyhow::Result;
use rusqlite::params;
use spectranet_model::Snapshot;
use spectranet_probe::{Probe, Report};
use spectranet_proto::AlertEvent;

use crate::usage::Store;

/// Checks kept in the history (the oldest go first).
const KEPT: i64 = 500;
/// Samples of internet latency behind "the usual latency" (24 hours).
const BASELINE_WINDOW: Duration = Duration::from_secs(24 * 3600);
/// Fewer samples than this and there is no usual latency yet.
const BASELINE_MIN: usize = 3;

const SCHEMA: &str = "
    CREATE TABLE IF NOT EXISTS checks (
        ts      INTEGER NOT NULL,
        verdict TEXT NOT NULL,
        report  TEXT NOT NULL
    );
    CREATE INDEX IF NOT EXISTS checks_ts ON checks (ts);
";

impl Store {
    pub fn prepare_checks(&self) -> Result<()> {
        self.conn.execute_batch(SCHEMA)?;
        Ok(())
    }

    /// Records a check, keeping the latest [`KEPT`].
    pub fn record_check(&self, report: &Report) -> Result<()> {
        let verdict = serde_json::to_value(&report.verdict)?
            .get("verdict")
            .and_then(|v| v.as_str())
            .unwrap_or("unknown")
            .to_string();
        self.conn.execute(
            "INSERT INTO checks (ts, verdict, report) VALUES (?1, ?2, ?3)",
            params![
                (report.started_ms / 1000) as i64,
                verdict,
                serde_json::to_string(report)?
            ],
        )?;
        self.conn.execute(
            "DELETE FROM checks WHERE rowid NOT IN (SELECT rowid FROM checks ORDER BY ts DESC LIMIT ?1)",
            [KEPT],
        )?;
        Ok(())
    }

    /// The latest checks, newest first.
    pub fn checks(&self, limit: u32) -> Result<Vec<Report>> {
        let mut stmt = self
            .conn
            .prepare_cached("SELECT report FROM checks ORDER BY ts DESC LIMIT ?1")?;
        let rows = stmt.query_map([i64::from(limit)], |r| r.get::<_, String>(0))?;
        Ok(rows
            .filter_map(|r| r.ok())
            .filter_map(|text| serde_json::from_str(&text).ok())
            .collect())
    }

    /// Records one alert raised outside the traffic watchdog.
    pub fn record_alert(&self, event: &AlertEvent) -> Result<()> {
        self.conn.execute(
            "INSERT INTO alerts (ts, severity, rule, app, remote, host, message) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
            params![
                event.ts as i64,
                event.severity,
                event.rule,
                event.app,
                event.remote,
                event.host,
                event.message
            ],
        )?;
        Ok(())
    }
}

/// The best internet latency of a check (the fastest target that answered), in ms.
pub fn internet_ms(report: &Report) -> Option<f64> {
    report
        .internet
        .iter()
        .filter_map(Probe::measured)
        .filter(|l| l.received > 0)
        .map(|l| l.avg_ms)
        .min_by(f64::total_cmp)
}

/// What the service remembers between checks.
#[derive(Default)]
pub struct Memory {
    /// (when, internet latency in ms) from checks and the watch.
    latency: VecDeque<(Instant, f64)>,
    /// Highest total traffic (bytes per second) per minute, for the last 24 hours.
    peaks: VecDeque<(Instant, u64)>,
    /// Consecutive watch minutes with a high latency, and whether that was alerted.
    high_minutes: u32,
    alerted: bool,
}

impl Memory {
    pub fn add_latency(&mut self, ms: f64) {
        let now = Instant::now();
        self.latency.push_back((now, ms));
        while self
            .latency
            .front()
            .is_some_and(|(t, _)| now.duration_since(*t) > BASELINE_WINDOW)
        {
            self.latency.pop_front();
        }
    }

    /// The usual internet latency: the median of the last day, when there is enough of it.
    pub fn baseline(&self) -> Option<f64> {
        if self.latency.len() < BASELINE_MIN {
            return None;
        }
        let mut v: Vec<f64> = self.latency.iter().map(|(_, ms)| *ms).collect();
        v.sort_by(f64::total_cmp);
        Some(v[v.len() / 2])
    }

    /// Notes the total traffic of a sample.
    pub fn add_traffic(&mut self, total: u64) {
        let now = Instant::now();
        match self.peaks.back_mut() {
            Some((started, max)) if now.duration_since(*started) < Duration::from_secs(60) => {
                *max = (*max).max(total);
            }
            _ => self.peaks.push_back((now, total)),
        }
        while self
            .peaks
            .front()
            .is_some_and(|(t, _)| now.duration_since(*t) > BASELINE_WINDOW)
        {
            self.peaks.pop_front();
        }
    }

    /// The highest total traffic of the last day.
    pub fn peak(&self) -> Option<u64> {
        self.peaks.iter().map(|(_, m)| *m).max().filter(|m| *m > 0)
    }

    /// One watch minute: whether the latency was high. Returns true once, when it has been
    /// high for `minutes` in a row.
    pub fn watch_minute(&mut self, high: bool, minutes: u32) -> bool {
        if !high {
            self.high_minutes = 0;
            self.alerted = false;
            return false;
        }
        self.high_minutes += 1;
        if self.high_minutes >= minutes && !self.alerted {
            self.alerted = true;
            return true;
        }
        false
    }
}

/// Snapshots published during `window`, by polling the latest one (`latest` returns its
/// sequence number and the snapshot).
pub fn collect(window: Duration, latest: impl Fn() -> Option<(u64, Snapshot)>) -> Vec<Snapshot> {
    let started = Instant::now();
    let mut seen = None;
    let mut out = Vec::new();
    while started.elapsed() < window {
        if let Some((seq, snapshot)) = latest()
            && seen != Some(seq)
        {
            seen = Some(seq);
            out.push(snapshot);
        }
        std::thread::sleep(Duration::from_millis(250));
    }
    out
}

/// The watch's message when the latency has stayed high.
pub fn latency_alert(now: u64, minutes: u32, ms: f64, usual: Option<f64>) -> AlertEvent {
    let usual = usual.map_or(String::new(), |u| format!(" (usually {u:.0} ms)"));
    AlertEvent {
        ts: now,
        severity: "warn".into(),
        rule: "latency:high".into(),
        app: "network".into(),
        remote: None,
        host: None,
        message: format!(
            "internet latency has been high for {minutes} minutes: {ms:.0} ms{usual}; run snet check"
        ),
    }
}

/// The watch: every minute, a few pings to the targets; `on_minute` gets the best latency
/// (or `None` when nothing answered).
pub fn watch_once(targets: &[String]) -> Option<f64> {
    let options = spectranet_probe::ping::Options {
        count: 3,
        interval: Duration::from_millis(200),
        timeout: Duration::from_secs(1),
    };
    let targets: Vec<String> = if targets.is_empty() {
        spectranet_probe::DEFAULT_TARGETS
            .iter()
            .map(|t| t.to_string())
            .collect()
    } else {
        targets.to_vec()
    };
    targets
        .iter()
        .filter_map(|t| {
            let ip = spectranet_probe::check::resolve_target(t)?;
            spectranet_probe::ping::latency(t, ip, options, &spectranet_probe::ping::TCP_PORTS)
        })
        .filter(|l| l.received > 0)
        .map(|l| l.avg_ms)
        .min_by(f64::total_cmp)
}

/// Shared between the service's threads.
pub type SharedMemory = Mutex<Memory>;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_usual_latency_needs_a_few_samples() {
        let mut m = Memory::default();
        m.add_latency(20.0);
        m.add_latency(30.0);
        assert_eq!(m.baseline(), None);
        m.add_latency(25.0);
        assert_eq!(m.baseline(), Some(25.0));
    }

    #[test]
    fn the_peak_is_the_highest_minute() {
        let mut m = Memory::default();
        assert_eq!(m.peak(), None);
        m.add_traffic(100);
        m.add_traffic(900);
        m.add_traffic(300);
        assert_eq!(m.peak(), Some(900));
    }

    #[test]
    fn the_watch_alerts_once_after_n_minutes() {
        let mut m = Memory::default();
        assert!(!m.watch_minute(true, 3));
        assert!(!m.watch_minute(true, 3));
        assert!(m.watch_minute(true, 3), "third high minute");
        assert!(!m.watch_minute(true, 3), "only once while it lasts");
        assert!(!m.watch_minute(false, 3));
        assert!(!m.watch_minute(true, 3), "counting starts again");
    }

    #[test]
    fn checks_are_recorded_and_read_back() {
        let dir = tempfile::tempdir().unwrap();
        let store = Store::open(&dir.path().join("u.sqlite")).unwrap();
        store.prepare_checks().unwrap();
        let report = Report {
            started_ms: 1_700_000_000_000,
            duration_ms: 9000,
            gateway: Probe::Unmeasurable { why: "x".into() },
            internet: Vec::new(),
            dns: Probe::Unmeasurable { why: "x".into() },
            apps: spectranet_probe::Apps::default(),
            path: None,
            baseline_ms: None,
            verdict: spectranet_probe::Verdict::AllGood,
        };
        store.record_check(&report).unwrap();
        let back = store.checks(10).unwrap();
        assert_eq!(back, vec![report]);
    }
}
