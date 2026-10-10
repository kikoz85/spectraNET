//! Data usage history: per application, per local calendar day.
//!
//! Every sample's per-application rates are converted to bytes and accumulated in memory;
//! the accumulator is flushed to SQLite periodically and at shutdown, so the database sees
//! one small transaction per flush rather than one write per second.

use std::collections::HashMap;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use rusqlite::{Connection, params};
use spectranet_model::{AppTraffic, Snapshot, group_by_app};
use spectranet_proto::UsageRow;

/// Stable identity of an application across restarts: its bundle or executable path.
pub fn app_key(app: &AppTraffic) -> String {
    match &app.path {
        Some(path) => path.clone(),
        None => format!("name:{}", app.name),
    }
}

/// Bytes moved at `rate` bytes/s during `interval_ms`.
fn bytes_in(rate: u64, interval_ms: u64) -> u64 {
    u64::try_from(u128::from(rate) * u128::from(interval_ms) / 1000).unwrap_or(u64::MAX)
}

/// Usage not yet written to the database.
#[derive(Debug, Default)]
pub struct Accumulator {
    pending: HashMap<(String, String), (String, u64, u64)>,
    /// Executable path last seen for each standalone program name. A short-lived process can
    /// exit before its path is read; it is then filed under the path its namesakes have, so
    /// one `ssh` does not split into two history rows.
    known_paths: HashMap<String, String>,
}

impl Accumulator {
    /// Adds one snapshot's traffic to `day`.
    pub fn record(&mut self, day: &str, snapshot: &Snapshot) {
        for mut app in group_by_app(snapshot.processes.clone()) {
            match &app.path {
                Some(path) => {
                    self.known_paths.insert(app.name.clone(), path.clone());
                }
                None => app.path = self.known_paths.get(&app.name).cloned(),
            }
            let rx = bytes_in(app.rx_rate, snapshot.interval_ms);
            let tx = bytes_in(app.tx_rate, snapshot.interval_ms);
            if rx == 0 && tx == 0 {
                continue;
            }
            let entry = self
                .pending
                .entry((day.to_string(), app_key(&app)))
                .or_insert_with(|| (app.name.clone(), 0, 0));
            entry.0.clone_from(&app.name);
            entry.1 = entry.1.saturating_add(rx);
            entry.2 = entry.2.saturating_add(tx);
        }
    }

    /// Pending usage, without clearing it.
    pub fn rows(&self) -> Vec<UsageRow> {
        self.pending
            .iter()
            .map(|((day, key), (app, rx, tx))| UsageRow {
                day: day.clone(),
                app: app.clone(),
                key: key.clone(),
                rx: *rx,
                tx: *tx,
            })
            .collect()
    }

    pub fn clear(&mut self) {
        self.pending.clear();
    }

    pub fn is_empty(&self) -> bool {
        self.pending.is_empty()
    }
}

/// Sums rows with the same day and application; keeps the latest display name.
pub fn merge(rows: impl IntoIterator<Item = UsageRow>) -> Vec<UsageRow> {
    let mut merged: HashMap<(String, String), UsageRow> = HashMap::new();
    for row in rows {
        match merged.get_mut(&(row.day.clone(), row.key.clone())) {
            Some(existing) => {
                existing.rx = existing.rx.saturating_add(row.rx);
                existing.tx = existing.tx.saturating_add(row.tx);
                existing.app = row.app;
            }
            None => {
                merged.insert((row.day.clone(), row.key.clone()), row);
            }
        }
    }
    let mut rows: Vec<_> = merged.into_values().collect();
    rows.sort_by(|a, b| a.day.cmp(&b.day).then(a.key.cmp(&b.key)));
    rows
}

/// The SQLite usage database.
pub struct Store {
    pub(crate) conn: Connection,
}

const SCHEMA: &str = "
    CREATE TABLE IF NOT EXISTS usage (
        day TEXT NOT NULL,
        key TEXT NOT NULL,
        app TEXT NOT NULL,
        rx  INTEGER NOT NULL CHECK (rx >= 0),
        tx  INTEGER NOT NULL CHECK (tx >= 0),
        PRIMARY KEY (day, key)
    ) WITHOUT ROWID;
";

impl Store {
    /// Opens (creating if needed) the database. A corrupt file is moved aside and replaced,
    /// so a damaged history never stops the service from running.
    pub fn open(path: &Path) -> Result<Self> {
        if let Some(dir) = path.parent() {
            std::fs::create_dir_all(dir).with_context(|| format!("creating {}", dir.display()))?;
        }
        match Self::open_unchecked(path) {
            Ok(store) => Ok(store),
            Err(first) => {
                let aside = corrupt_name(path);
                std::fs::rename(path, &aside).with_context(|| {
                    format!("{first:#}; and moving the damaged database aside failed")
                })?;
                eprintln!(
                    "snetd: usage database was unreadable ({first:#}); moved to {}",
                    aside.display()
                );
                Self::open_unchecked(path)
            }
        }
    }

    fn open_unchecked(path: &Path) -> Result<Self> {
        let conn = Connection::open(path).with_context(|| format!("opening {}", path.display()))?;
        conn.busy_timeout(std::time::Duration::from_secs(5))?;
        conn.pragma_update(None, "journal_mode", "WAL")?;
        conn.pragma_update(None, "synchronous", "NORMAL")?;
        let check: String = conn.query_row("PRAGMA quick_check", [], |r| r.get(0))?;
        anyhow::ensure!(check == "ok", "integrity check failed: {check}");
        conn.execute_batch(SCHEMA)?;
        Ok(Self { conn })
    }

    /// Removes the days before `first_day` (`YYYY-MM-DD`); returns the rows removed.
    pub fn prune_before(&self, first_day: &str) -> Result<usize> {
        Ok(self
            .conn
            .execute("DELETE FROM usage WHERE day < ?1", [first_day])?)
    }

    /// Adds `rows` to the stored totals in one transaction.
    pub fn add(&mut self, rows: &[UsageRow]) -> Result<()> {
        let tx = self.conn.transaction()?;
        {
            let mut stmt = tx.prepare_cached(
                "INSERT INTO usage (day, key, app, rx, tx) VALUES (?1, ?2, ?3, ?4, ?5)
                 ON CONFLICT (day, key) DO UPDATE SET
                     app = excluded.app,
                     rx = min(usage.rx + excluded.rx, 9223372036854775807),
                     tx = min(usage.tx + excluded.tx, 9223372036854775807)",
            )?;
            for row in rows {
                stmt.execute(params![
                    row.day,
                    row.key,
                    row.app,
                    clamp(row.rx),
                    clamp(row.tx)
                ])?;
            }
        }
        tx.commit()?;
        Ok(())
    }

    /// All rows from `first_day` (inclusive) onwards.
    pub fn since(&self, first_day: &str) -> Result<Vec<UsageRow>> {
        let mut stmt = self.conn.prepare_cached(
            "SELECT day, key, app, rx, tx FROM usage WHERE day >= ?1 ORDER BY day, key",
        )?;
        let rows = stmt.query_map([first_day], |r| {
            Ok(UsageRow {
                day: r.get(0)?,
                key: r.get(1)?,
                app: r.get(2)?,
                rx: r.get::<_, i64>(3)?.max(0) as u64,
                tx: r.get::<_, i64>(4)?.max(0) as u64,
            })
        })?;
        rows.collect::<Result<_, _>>().map_err(Into::into)
    }
}

fn clamp(v: u64) -> i64 {
    i64::try_from(v).unwrap_or(i64::MAX)
}

fn corrupt_name(path: &Path) -> PathBuf {
    let stamp = jiff::Timestamp::now().as_second();
    let mut name = path.file_name().unwrap_or_default().to_os_string();
    name.push(format!(".corrupt-{stamp}"));
    path.with_file_name(name)
}

/// Today's local date as `YYYY-MM-DD`.
pub fn today() -> String {
    jiff::Zoned::now().date().to_string()
}

/// The first day of a `days`-day window ending today (`days` ≥ 1).
pub fn first_day(days: u32) -> String {
    let days = i64::from(days.max(1) - 1);
    let today = jiff::Zoned::now().date();
    today
        .checked_sub(jiff::Span::new().days(days))
        .unwrap_or(today)
        .to_string()
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use spectranet_capture::mock::MockSource;

    use super::*;

    fn row(day: &str, key: &str, rx: u64, tx: u64) -> UsageRow {
        UsageRow {
            day: day.into(),
            app: key.trim_start_matches('/').into(),
            key: key.into(),
            rx,
            tx,
        }
    }

    #[test]
    fn rates_become_bytes() {
        assert_eq!(bytes_in(1000, 1000), 1000);
        assert_eq!(bytes_in(1000, 500), 500);
        assert_eq!(
            bytes_in(u64::MAX, u64::MAX),
            u64::MAX,
            "saturates instead of overflowing"
        );
    }

    #[test]
    fn accumulator_groups_by_app_and_day() {
        let mut source = MockSource::new(5);
        let snap = source.advance(Duration::from_secs(1));
        let chrome: u64 = snap
            .processes
            .iter()
            .filter(|p| {
                p.process
                    .app
                    .as_ref()
                    .is_some_and(|a| a.name == "Google Chrome")
            })
            .map(|p| p.rx_rate)
            .sum();
        let mut acc = Accumulator::default();
        acc.record("2026-10-10", &snap);
        acc.record("2026-10-10", &snap);
        acc.record("2026-10-11", &snap);
        let rows = merge(acc.rows());
        let chrome_rows: Vec<_> = rows
            .iter()
            .filter(|r| r.key == "/Applications/Google Chrome.app")
            .collect();
        assert_eq!(chrome_rows.len(), 2, "one row per day");
        assert_eq!(chrome_rows[0].rx, 2 * chrome, "both helpers, both samples");
        assert_eq!(chrome_rows[1].rx, chrome);
        assert_eq!(
            rows.iter().filter(|r| r.day == "2026-10-10").count(),
            6,
            "six applications"
        );
        acc.clear();
        assert!(acc.is_empty());
    }

    #[test]
    fn short_lived_process_without_path_joins_its_namesake() {
        let mut snap = MockSource::new(2).advance(Duration::from_secs(1));
        let mut acc = Accumulator::default();
        acc.record("2026-10-10", &snap);
        // Same program, but this time the path could not be read (process already gone).
        for p in &mut snap.processes {
            if p.process.name == "svc_update" {
                p.process.path = None;
            }
        }
        acc.record("2026-10-10", &snap);
        let rows: Vec<_> = merge(acc.rows())
            .into_iter()
            .filter(|r| r.app == "svc_update")
            .collect();
        assert_eq!(rows.len(), 1, "{rows:?}");
        assert_eq!(rows[0].key, "/Users/Shared/.svc/svc_update");

        // A program never seen with a path keeps a name-based key.
        let mut fresh = Accumulator::default();
        fresh.record("2026-10-10", &snap);
        assert!(fresh.rows().iter().any(|r| r.key == "name:svc_update"));
    }

    #[test]
    fn idle_apps_are_not_recorded() {
        let mut snap = MockSource::new(1).advance(Duration::from_secs(1));
        for p in &mut snap.processes {
            p.rx_rate = 0;
            p.tx_rate = 0;
        }
        let mut acc = Accumulator::default();
        acc.record("2026-10-10", &snap);
        assert!(acc.is_empty());
    }

    #[test]
    fn store_adds_up_and_persists() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("nested/usage.sqlite");
        {
            let mut store = Store::open(&path).unwrap();
            store
                .add(&[
                    row("2026-10-09", "/a", 10, 1),
                    row("2026-10-10", "/a", 5, 5),
                ])
                .unwrap();
            store
                .add(&[row("2026-10-10", "/a", 5, 0), row("2026-10-10", "/b", 1, 1)])
                .unwrap();
        }
        let store = Store::open(&path).unwrap();
        assert_eq!(
            store.since("2026-10-10").unwrap(),
            [
                row("2026-10-10", "/a", 10, 5),
                row("2026-10-10", "/b", 1, 1)
            ]
        );
        assert_eq!(store.since("2000-01-01").unwrap().len(), 3);
    }

    #[test]
    fn store_saturates_huge_values() {
        let dir = tempfile::tempdir().unwrap();
        let mut store = Store::open(&dir.path().join("u.sqlite")).unwrap();
        store.add(&[row("2026-10-10", "/a", u64::MAX, 0)]).unwrap();
        store.add(&[row("2026-10-10", "/a", u64::MAX, 0)]).unwrap();
        assert_eq!(store.since("2026-10-10").unwrap()[0].rx, i64::MAX as u64);
    }

    #[test]
    fn corrupt_database_is_moved_aside() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("usage.sqlite");
        std::fs::write(
            &path,
            b"this is definitely not a sqlite database, just junk bytes....",
        )
        .unwrap();
        let mut store = Store::open(&path).unwrap();
        store.add(&[row("2026-10-10", "/a", 1, 1)]).unwrap();
        let aside: Vec<_> = std::fs::read_dir(dir.path())
            .unwrap()
            .filter_map(|e| e.ok())
            .filter(|e| e.file_name().to_string_lossy().contains(".corrupt-"))
            .collect();
        assert_eq!(aside.len(), 1, "the damaged file is kept for inspection");
    }

    #[test]
    fn merge_sums_and_orders() {
        let merged = merge([
            row("2026-10-10", "/b", 1, 1),
            row("2026-10-09", "/a", 1, 0),
            row("2026-10-10", "/b", 2, 3),
        ]);
        assert_eq!(
            merged,
            [row("2026-10-09", "/a", 1, 0), row("2026-10-10", "/b", 3, 4)]
        );
    }

    #[test]
    fn day_window() {
        assert_eq!(first_day(1), today());
        assert_eq!(first_day(0), today(), "zero is treated as one day");
        assert!(first_day(7) < today());
        assert_eq!(first_day(7).len(), 10);
    }
}
