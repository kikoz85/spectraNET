//! Security alerts: what the rules found, plus applications reaching the network for the
//! first time, de-duplicated and kept in the service database.

use std::collections::{HashMap, HashSet};

use anyhow::Result;
use rusqlite::params;
use spectranet_intel::Finding;
use spectranet_model::{Snapshot, Verdict, group_by_app};
use spectranet_proto::AlertEvent;

use crate::usage::{Store, app_key};

/// The same rule for the same application and remote address is reported at most this often.
const REPEAT_AFTER_S: u64 = 3600;
/// Alerts older than this are deleted.
const RETENTION_S: u64 = 90 * 86_400;
/// After the very first start, applications seen during this period form the baseline and do
/// not raise "first connection" alerts (otherwise every app would on day one).
pub const BASELINE_S: u64 = 600;
/// For a day after an application's first TLS connection, its TLS clients (JA4 fingerprints)
/// are learnt silently: browsers and their updaters use several.
pub const FINGERPRINT_LEARNING_S: u64 = 86_400;

const SCHEMA: &str = "
    CREATE TABLE IF NOT EXISTS alerts (
        ts INTEGER NOT NULL,
        severity TEXT NOT NULL,
        rule TEXT NOT NULL,
        app TEXT NOT NULL,
        remote TEXT,
        host TEXT,
        message TEXT NOT NULL
    );
    CREATE INDEX IF NOT EXISTS alerts_ts ON alerts (ts);
    CREATE TABLE IF NOT EXISTS apps_seen (
        key TEXT PRIMARY KEY,
        app TEXT NOT NULL,
        first_seen INTEGER NOT NULL
    ) WITHOUT ROWID;
    CREATE TABLE IF NOT EXISTS meta (k TEXT PRIMARY KEY, v TEXT NOT NULL) WITHOUT ROWID;
    CREATE TABLE IF NOT EXISTS fingerprints (
        key TEXT NOT NULL,
        ja4 TEXT NOT NULL,
        first_seen INTEGER NOT NULL,
        PRIMARY KEY (key, ja4)
    ) WITHOUT ROWID;
";

/// TLS client fingerprints per application: when its first one was seen, and all of them.
pub type Fingerprints = HashMap<String, (u64, HashSet<String>)>;

fn severity(verdict: Verdict) -> &'static str {
    match verdict {
        Verdict::Ok => "info",
        Verdict::Warn => "warn",
        Verdict::Alert => "alert",
    }
}

impl Store {
    /// Creates the alert tables and applies retention. Returns when the baseline period ends.
    pub fn prepare_alerts(&mut self, now: u64) -> Result<u64> {
        self.conn.execute_batch(SCHEMA)?;
        self.conn.execute(
            "DELETE FROM alerts WHERE ts < ?1",
            [now.saturating_sub(RETENTION_S) as i64],
        )?;
        let existing: Option<String> = self
            .conn
            .query_row("SELECT v FROM meta WHERE k = 'baseline_until'", [], |r| {
                r.get(0)
            })
            .ok();
        match existing.and_then(|v| v.parse().ok()) {
            Some(until) => Ok(until),
            None => {
                let until = now + BASELINE_S;
                self.conn.execute(
                    "INSERT INTO meta (k, v) VALUES ('baseline_until', ?1)",
                    [until.to_string()],
                )?;
                Ok(until)
            }
        }
    }

    pub fn seen_apps(&self) -> Result<HashSet<String>> {
        let mut stmt = self.conn.prepare("SELECT key FROM apps_seen")?;
        let keys = stmt.query_map([], |r| r.get(0))?;
        keys.collect::<Result<_, _>>().map_err(Into::into)
    }

    /// Known TLS client fingerprints per application.
    pub fn fingerprints(&self) -> Result<Fingerprints> {
        let mut stmt = self
            .conn
            .prepare("SELECT key, ja4, first_seen FROM fingerprints")?;
        let rows = stmt.query_map([], |r| {
            Ok((
                r.get::<_, String>(0)?,
                r.get::<_, String>(1)?,
                r.get::<_, i64>(2)?,
            ))
        })?;
        let mut out: Fingerprints = HashMap::new();
        for row in rows {
            let (key, ja4, first) = row?;
            let entry = out
                .entry(key)
                .or_insert_with(|| (first as u64, HashSet::new()));
            entry.0 = entry.0.min(first as u64);
            entry.1.insert(ja4);
        }
        Ok(out)
    }

    fn save(
        &mut self,
        events: &[AlertEvent],
        new_apps: &[(String, String)],
        new_fingerprints: &[(String, String)],
        now: u64,
    ) -> Result<()> {
        let tx = self.conn.transaction()?;
        {
            let mut insert = tx.prepare_cached(
                "INSERT INTO alerts (ts, severity, rule, app, remote, host, message) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
            )?;
            for e in events {
                insert.execute(params![
                    e.ts as i64,
                    e.severity,
                    e.rule,
                    e.app,
                    e.remote,
                    e.host,
                    e.message
                ])?;
            }
            let mut seen = tx.prepare_cached(
                "INSERT OR IGNORE INTO apps_seen (key, app, first_seen) VALUES (?1, ?2, ?3)",
            )?;
            for (key, app) in new_apps {
                seen.execute(params![key, app, now as i64])?;
            }
            let mut fp = tx.prepare_cached(
                "INSERT OR IGNORE INTO fingerprints (key, ja4, first_seen) VALUES (?1, ?2, ?3)",
            )?;
            for (key, ja4) in new_fingerprints {
                fp.execute(params![key, ja4, now as i64])?;
            }
        }
        tx.commit()?;
        Ok(())
    }

    /// Alerts since `since` (Unix seconds), newest first.
    pub fn alerts_since(&self, since: u64, limit: u32) -> Result<Vec<AlertEvent>> {
        let mut stmt = self.conn.prepare_cached(
            "SELECT ts, severity, rule, app, remote, host, message FROM alerts
             WHERE ts >= ?1 ORDER BY ts DESC, rowid DESC LIMIT ?2",
        )?;
        let rows = stmt.query_map(params![since as i64, i64::from(limit)], |r| {
            Ok(AlertEvent {
                ts: r.get::<_, i64>(0)?.max(0) as u64,
                severity: r.get(1)?,
                rule: r.get(2)?,
                app: r.get(3)?,
                remote: r.get(4)?,
                host: r.get(5)?,
                message: r.get(6)?,
            })
        })?;
        rows.collect::<Result<_, _>>().map_err(Into::into)
    }

    pub fn count_alerts_since(&self, since: u64) -> Result<u64> {
        let n: i64 = self.conn.query_row(
            "SELECT count(*) FROM alerts WHERE ts >= ?1",
            [since as i64],
            |r| r.get(0),
        )?;
        Ok(n.max(0) as u64)
    }
}

/// Turns findings and new applications into alerts, without repeating itself.
pub struct Watchdog {
    seen: HashSet<String>,
    baseline_until: u64,
    last_reported: HashMap<(String, String, String), u64>,
    fingerprints: Fingerprints,
}

impl Watchdog {
    pub fn new(seen: HashSet<String>, baseline_until: u64) -> Self {
        Self {
            seen,
            baseline_until,
            last_reported: HashMap::new(),
            fingerprints: HashMap::new(),
        }
    }

    /// Starts from the TLS client fingerprints already learnt.
    pub fn with_fingerprints(mut self, fingerprints: Fingerprints) -> Self {
        self.fingerprints = fingerprints;
        self
    }

    /// Records what `snapshot` (already annotated) and its `findings` warrant. Returns the
    /// alerts raised, already saved.
    pub fn observe(
        &mut self,
        store: &mut Store,
        snapshot: &Snapshot,
        findings: &[Finding],
        now: u64,
    ) -> Result<Vec<AlertEvent>> {
        let mut events = Vec::new();
        let mut new_apps = Vec::new();
        let mut new_fingerprints = Vec::new();
        let apps = group_by_app(snapshot.processes.clone());

        // An application connecting with a TLS client it never used before, once its usual
        // ones are known: an update, or another program using its name.
        for app in &apps {
            let key = app_key(app);
            for flow in app.processes.iter().flat_map(|p| &p.flows) {
                let Some(ja4) = flow.meta.tls.as_ref().and_then(|t| t.ja4.clone()) else {
                    continue;
                };
                let known = self
                    .fingerprints
                    .entry(key.clone())
                    .or_insert_with(|| (now, HashSet::new()));
                if known.1.contains(&ja4) {
                    continue;
                }
                let learning =
                    now.saturating_sub(known.0) < FINGERPRINT_LEARNING_S || known.1.is_empty();
                known.1.insert(ja4.clone());
                new_fingerprints.push((key.clone(), ja4.clone()));
                if learning {
                    continue;
                }
                events.push(AlertEvent {
                    ts: now,
                    severity: "warn".into(),
                    rule: "new-tls-client".into(),
                    app: app.name.clone(),
                    remote: Some(flow.remote.to_string()),
                    host: flow.remote_host.clone(),
                    message: format!(
                        "connected with a TLS client never seen for this application (JA4 {ja4}); \
                         this happens after an update, otherwise another program may be using its name"
                    ),
                });
            }
        }

        for app in &apps {
            let active = app.rx_bytes + app.tx_bytes > 0;
            let key = app_key(app);
            if !active || self.seen.contains(&key) {
                continue;
            }
            self.seen.insert(key.clone());
            new_apps.push((key.clone(), app.name.clone()));
            if now >= self.baseline_until {
                let destination = app.busiest_flow().map(|f| {
                    f.remote_host
                        .clone()
                        .unwrap_or_else(|| f.remote.ip().to_string())
                });
                events.push(AlertEvent {
                    ts: now,
                    severity: "info".into(),
                    rule: "first-connection".into(),
                    app: app.name.clone(),
                    remote: app.busiest_flow().map(|f| f.remote.to_string()),
                    host: app.busiest_flow().and_then(|f| f.remote_host.clone()),
                    message: format!(
                        "first time on the network{}",
                        destination
                            .map(|d| format!(", talking to {d}"))
                            .unwrap_or_default()
                    ),
                });
            }
        }

        for finding in findings {
            // Report under the application name the user sees.
            let app = apps
                .iter()
                .find(|a| a.contains_pid(finding.pid))
                .map_or_else(|| finding.process.clone(), |a| a.name.clone());
            let dedup = (
                app.clone(),
                finding.rule.clone(),
                finding.remote.ip().to_string(),
            );
            if self
                .last_reported
                .get(&dedup)
                .is_some_and(|t| now.saturating_sub(*t) < REPEAT_AFTER_S)
            {
                continue;
            }
            self.last_reported.insert(dedup, now);
            events.push(AlertEvent {
                ts: now,
                severity: severity(finding.verdict).into(),
                rule: finding.rule.clone(),
                app,
                remote: Some(finding.remote.to_string()),
                host: finding.host.clone(),
                message: finding.message.clone(),
            });
        }

        if !events.is_empty() || !new_apps.is_empty() || !new_fingerprints.is_empty() {
            store.save(&events, &new_apps, &new_fingerprints, now)?;
        }
        if self.last_reported.len() > 100_000 {
            self.last_reported
                .retain(|_, t| now.saturating_sub(*t) < REPEAT_AFTER_S);
        }
        Ok(events)
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use spectranet_capture::mock::MockSource;
    use spectranet_intel::Intel;

    use super::*;

    const T0: u64 = 1_760_000_000;

    fn setup() -> (Store, tempfile::TempDir) {
        let dir = tempfile::tempdir().unwrap();
        let store = Store::open(&dir.path().join("db.sqlite")).unwrap();
        (store, dir)
    }

    fn annotated() -> (Snapshot, Vec<Finding>) {
        let mut snap = MockSource::new(3).advance(Duration::from_secs(1));
        // svc_update talks HTTP to a public address: the cleartext rule fires.
        let findings = Intel::default().annotate(&mut snap);
        (snap, findings)
    }

    #[test]
    fn baseline_then_first_connections() {
        let (mut store, _dir) = setup();
        let until = store.prepare_alerts(T0).unwrap();
        assert_eq!(until, T0 + BASELINE_S);
        assert_eq!(
            store.prepare_alerts(T0 + 5).unwrap(),
            until,
            "baseline fixed at first start"
        );

        let (snap, _) = annotated();
        let mut dog = Watchdog::new(store.seen_apps().unwrap(), until);
        let during = dog.observe(&mut store, &snap, &[], T0 + 10).unwrap();
        assert!(during.is_empty(), "baseline apps are learnt silently");
        assert_eq!(store.seen_apps().unwrap().len(), 6);

        // After the baseline a brand-new program appears.
        let mut later = snap.clone();
        let mut newcomer = later.processes[0].clone();
        newcomer.process.pid = 4242;
        newcomer.process.name = "newtool".into();
        newcomer.process.path = Some("/usr/local/bin/newtool".into());
        newcomer.process.app = None;
        later.processes.push(newcomer);
        let events = dog.observe(&mut store, &later, &[], until + 1).unwrap();
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].rule, "first-connection");
        assert_eq!(events[0].app, "newtool");
        assert!(events[0].message.starts_with("first time on the network"));
        assert!(
            dog.observe(&mut store, &later, &[], until + 2)
                .unwrap()
                .is_empty(),
            "only once"
        );
    }

    #[test]
    fn findings_become_deduplicated_alerts() {
        let (mut store, _dir) = setup();
        store.prepare_alerts(T0).unwrap();
        let (snap, findings) = annotated();
        assert!(!findings.is_empty(), "mock traffic includes cleartext HTTP");
        let mut dog = Watchdog::new(store.seen_apps().unwrap(), T0 + BASELINE_S);
        let first = dog.observe(&mut store, &snap, &findings, T0 + 1).unwrap();
        assert_eq!(first.len(), findings.len());
        assert!(
            first.iter().any(|e| e.rule == "cleartext:http"
                && e.app == "svc_update"
                && e.severity == "warn")
        );
        assert!(
            dog.observe(&mut store, &snap, &findings, T0 + 60)
                .unwrap()
                .is_empty(),
            "no repeats within the hour"
        );
        assert_eq!(
            dog.observe(&mut store, &snap, &findings, T0 + 1 + REPEAT_AFTER_S)
                .unwrap()
                .len(),
            findings.len()
        );

        let stored = store.alerts_since(T0, 100).unwrap();
        assert_eq!(stored.len(), 2 * findings.len());
        assert!(stored[0].ts >= stored[stored.len() - 1].ts, "newest first");
        assert_eq!(
            store.count_alerts_since(T0 + 2).unwrap(),
            findings.len() as u64
        );
        assert_eq!(
            store.alerts_since(T0, 1).unwrap().len(),
            1,
            "limit respected"
        );
    }

    #[test]
    fn helper_findings_are_reported_under_the_app_name() {
        let (mut store, _dir) = setup();
        store.prepare_alerts(T0).unwrap();
        let (snap, _) = annotated();
        let helper = snap
            .processes
            .iter()
            .find(|p| p.process.name == "Google Chrome Helper")
            .unwrap();
        let finding = Finding {
            pid: helper.process.pid,
            process: helper.process.name.clone(),
            remote: "93.184.216.34:80".parse().unwrap(),
            host: Some("example.com".into()),
            rule: "cleartext:http".into(),
            verdict: Verdict::Warn,
            message: "unencrypted HTTP".into(),
        };
        let mut dog = Watchdog::new(HashSet::new(), u64::MAX);
        let events = dog.observe(&mut store, &snap, &[finding], T0).unwrap();
        assert_eq!(events[0].app, "Google Chrome");
    }

    #[test]
    fn new_tls_clients_after_learning_are_reported_once() {
        let (mut store, _dir) = setup();
        store.prepare_alerts(T0).unwrap();
        let mut dog = Watchdog::new(HashSet::new(), 0);
        let with_ja4 = |ja4: &str| {
            let (mut s, _) = annotated();
            for p in &mut s.processes {
                for f in &mut p.flows {
                    f.meta.tls = Some(spectranet_model::flowmeta::TlsInfo {
                        ja4: Some(ja4.into()),
                        ..Default::default()
                    });
                }
            }
            s
        };
        let rule =
            |events: &[AlertEvent]| events.iter().filter(|e| e.rule == "new-tls-client").count();
        // Learning: two fingerprints on day one, silently.
        assert_eq!(
            rule(
                &dog.observe(&mut store, &with_ja4("t13d1516h2_a_b"), &[], T0)
                    .unwrap()
            ),
            0
        );
        assert_eq!(
            rule(
                &dog.observe(&mut store, &with_ja4("t13d0909h1_c_d"), &[], T0 + 60)
                    .unwrap()
            ),
            0
        );
        // A day later: known ones are fine, a new one is reported once per application.
        let later = T0 + FINGERPRINT_LEARNING_S + 1;
        assert_eq!(
            rule(
                &dog.observe(&mut store, &with_ja4("t13d1516h2_a_b"), &[], later)
                    .unwrap()
            ),
            0
        );
        let alerts = dog
            .observe(&mut store, &with_ja4("t12i0405h1_e_f"), &[], later)
            .unwrap();
        assert!(rule(&alerts) >= 1);
        assert_eq!(
            rule(
                &dog.observe(&mut store, &with_ja4("t12i0405h1_e_f"), &[], later + 5)
                    .unwrap()
            ),
            0
        );
        // What was learnt survives a restart.
        let known = store.fingerprints().unwrap();
        assert!(
            known
                .values()
                .all(|(_, set)| set.contains("t12i0405h1_e_f"))
        );
    }

    #[test]
    fn retention_removes_old_alerts() {
        let (mut store, _dir) = setup();
        store.prepare_alerts(T0).unwrap();
        let (snap, findings) = annotated();
        let mut dog = Watchdog::new(HashSet::new(), u64::MAX);
        dog.observe(&mut store, &snap, &findings, T0).unwrap();
        assert!(!store.alerts_since(0, 10).unwrap().is_empty());
        store.prepare_alerts(T0 + RETENTION_S + 1).unwrap();
        assert!(store.alerts_since(0, 10).unwrap().is_empty());
    }
}
