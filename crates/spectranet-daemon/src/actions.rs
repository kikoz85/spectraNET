//! Acting on the user's behalf: ending, pausing and resuming processes, closing connections,
//! blocking applications and addresses.
//!
//! Every request goes through the same gate: the policy (`actions = "elevated-only"`), the
//! protected list (processes whose loss would break the system or cut the user off), a check
//! that the target is something snetd actually sees, and the audit log, which records every
//! attempt, successful or not.

use std::collections::HashSet;

use anyhow::Result;
use rusqlite::params;
use spectranet_capture::control;
use spectranet_model::{Snapshot, group_by_app};
use spectranet_proto::{Action, AuditEvent, BlockInfo, BlockTarget, capability};

use crate::blocks::Blocks;
use crate::transport::Peer;
use crate::usage::Store;

/// Longest timed block, seconds (30 days); 0 asks for a block until lifted.
pub const MAX_BLOCK_S: u64 = 30 * 86_400;
/// Audit entries older than this are deleted.
const AUDIT_RETENTION_S: u64 = 365 * 86_400;

const SCHEMA: &str = "
    CREATE TABLE IF NOT EXISTS audit (
        ts INTEGER NOT NULL,
        by_user TEXT NOT NULL,
        action TEXT NOT NULL,
        target TEXT NOT NULL,
        ok INTEGER NOT NULL,
        message TEXT NOT NULL
    );
    CREATE INDEX IF NOT EXISTS audit_ts ON audit (ts);
    CREATE TABLE IF NOT EXISTS block_exes (
        id INTEGER NOT NULL,
        path TEXT NOT NULL
    );
    CREATE TABLE IF NOT EXISTS blocks (
        id INTEGER PRIMARY KEY,
        target TEXT NOT NULL,
        created INTEGER NOT NULL,
        expires INTEGER NOT NULL,
        by_user TEXT NOT NULL,
        method TEXT NOT NULL
    );
";

/// Processes never ended, paused or blocked, whatever the client asks: losing them breaks
/// the system, name resolution, the display or remote access. Compared without case and
/// without `.exe`.
const PROTECTED: &[&str] = &[
    // macOS
    "launchd",
    "kernel_task",
    "windowserver",
    "loginwindow",
    "mdnsresponder",
    "configd",
    "opendirectoryd",
    "securityd",
    "trustd",
    "logd",
    "syslogd",
    "networkd",
    "nehelper",
    // Linux
    "init",
    "systemd",
    "systemd-resolved",
    "systemd-networkd",
    "systemd-logind",
    "networkmanager",
    "dbus-daemon",
    "dbus-broker",
    "wpa_supplicant",
    "dhclient",
    "dhcpcd",
    // Windows
    "system",
    "registry",
    "smss",
    "csrss",
    "wininit",
    "winlogon",
    "services",
    "lsass",
    "svchost",
    "dwm",
    "fontdrvhost",
    "lsaiso",
    "memory compression",
    // Remote access and spectraNET itself
    "sshd-session",
    "sshd-auth",
    "sshd",
    "snetd",
    "winvnc",
    "vncserver",
    "xtigervnc",
];

pub fn is_protected_name(name: &str) -> bool {
    let n = name.to_lowercase();
    let n = n.strip_suffix(".exe").unwrap_or(&n);
    PROTECTED.contains(&n)
}

/// Who may act.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Policy {
    /// Only root / elevated administrators (config `actions = "elevated-only"`).
    pub elevated_only: bool,
}

/// What this system supports, for [`spectranet_proto::Status::capabilities`].
pub fn capabilities() -> Vec<String> {
    let mut caps = vec![capability::KILL.to_string(), capability::PAUSE.to_string()];
    match control::drop_support() {
        control::DropSupport::Native => caps.push(capability::DROP.into()),
        control::DropSupport::Experimental => caps.push(capability::DROP_EXPERIMENTAL.into()),
        control::DropSupport::None => {}
    }
    match spectranet_capture::block::support() {
        Some(spectranet_capture::block::AppBlocking::Full) => {
            caps.push(capability::BLOCK_APP.into());
            caps.push(capability::BLOCK_IP.into());
        }
        Some(spectranet_capture::block::AppBlocking::Following) => {
            caps.push(capability::BLOCK_APP_PARTIAL.into());
            caps.push(capability::BLOCK_IP.into());
        }
        None => {}
    }
    caps
}

/// A duration in words: `15 min`, `2 h`, `3 days`.
pub fn duration(s: u64) -> String {
    match s {
        0..=119 => format!("{s} s"),
        120..=7199 => format!("{} min", s / 60),
        7200..=172_799 => format!("{} h", s / 3600),
        _ => format!("{} days", s / 86_400),
    }
}

impl Store {
    pub fn prepare_actions(&mut self, now: u64) -> Result<()> {
        self.conn.execute_batch(SCHEMA)?;
        self.conn.execute(
            "DELETE FROM audit WHERE ts < ?1",
            [now.saturating_sub(AUDIT_RETENTION_S) as i64],
        )?;
        Ok(())
    }

    pub fn record_action(
        &self,
        ts: u64,
        by: &str,
        action: &Action,
        target: &str,
        ok: bool,
        message: &str,
    ) -> Result<()> {
        self.conn.execute(
            "INSERT INTO audit (ts, by_user, action, target, ok, message) VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
            params![ts as i64, by, serde_json::to_string(action)?, target, ok, message],
        )?;
        Ok(())
    }

    pub fn audit_since(&self, since: u64, limit: u32) -> Result<Vec<AuditEvent>> {
        let mut stmt = self.conn.prepare_cached(
            "SELECT ts, by_user, action, target, ok, message FROM audit WHERE ts >= ?1 ORDER BY ts DESC, rowid DESC LIMIT ?2",
        )?;
        let rows = stmt.query_map(params![since as i64, limit], |r| {
            Ok((
                r.get::<_, i64>(0)?,
                r.get::<_, String>(1)?,
                r.get::<_, String>(2)?,
                r.get::<_, String>(3)?,
                r.get::<_, bool>(4)?,
                r.get::<_, String>(5)?,
            ))
        })?;
        let mut out = Vec::new();
        for row in rows {
            let (ts, by, action, target, ok, message) = row?;
            // An entry written by a newer snetd may hold an action this one doesn't know.
            let Ok(action) = serde_json::from_str(&action) else {
                continue;
            };
            out.push(AuditEvent {
                ts: ts as u64,
                by,
                action,
                target,
                ok,
                message,
            });
        }
        Ok(out)
    }

    pub fn save_block(&self, block: &BlockInfo) -> Result<()> {
        self.conn.execute(
            "INSERT OR REPLACE INTO blocks (id, target, created, expires, by_user, method) VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
            params![block.id as i64, serde_json::to_string(&block.target)?, block.created as i64, block.expires as i64, block.by, block.method],
        )?;
        Ok(())
    }

    pub fn delete_block(&self, id: u64) -> Result<()> {
        self.conn
            .execute("DELETE FROM blocks WHERE id = ?1", [id as i64])?;
        self.conn
            .execute("DELETE FROM block_exes WHERE id = ?1", [id as i64])?;
        Ok(())
    }

    pub fn save_block_executables(&self, id: u64, paths: &[std::path::PathBuf]) -> Result<()> {
        for path in paths {
            self.conn.execute(
                "INSERT INTO block_exes (id, path) VALUES (?1, ?2)",
                params![id as i64, path.to_string_lossy()],
            )?;
        }
        Ok(())
    }

    pub fn block_executables(&self, id: u64) -> Result<Vec<std::path::PathBuf>> {
        let mut stmt = self
            .conn
            .prepare_cached("SELECT path FROM block_exes WHERE id = ?1 ORDER BY rowid")?;
        let rows = stmt.query_map([id as i64], |r| r.get::<_, String>(0))?;
        Ok(rows.filter_map(Result::ok).map(Into::into).collect())
    }

    pub fn load_blocks(&self) -> Result<Vec<BlockInfo>> {
        let mut stmt = self.conn.prepare(
            "SELECT id, target, created, expires, by_user, method FROM blocks ORDER BY id",
        )?;
        let rows = stmt.query_map([], |r| {
            Ok((
                r.get::<_, i64>(0)?,
                r.get::<_, String>(1)?,
                r.get::<_, i64>(2)?,
                r.get::<_, i64>(3)?,
                r.get::<_, String>(4)?,
                r.get::<_, String>(5)?,
            ))
        })?;
        let mut out = Vec::new();
        for row in rows {
            let (id, target, created, expires, by, method) = row?;
            let Ok(target) = serde_json::from_str(&target) else {
                continue;
            };
            out.push(BlockInfo {
                id: id as u64,
                target,
                created: created as u64,
                expires: expires as u64,
                by,
                method,
            });
        }
        Ok(out)
    }
}

/// The process behind a PID in the latest snapshot: (display name, executable name).
fn describe_pid(snapshot: Option<&Snapshot>, pid: u32) -> Option<(String, String)> {
    let snapshot = snapshot?;
    let p = snapshot.processes.iter().find(|p| p.process.pid == pid)?;
    let display = match &p.process.app {
        Some(app) if app.name != p.process.name => {
            format!("{} ({}, pid {pid})", app.name, p.process.name)
        }
        _ => format!("{} (pid {pid})", p.process.name),
    };
    let exe = p
        .process
        .path
        .as_deref()
        .and_then(|path| path.rsplit(['/', '\\']).next())
        .unwrap_or(&p.process.name)
        .to_string();
    Some((display, exe))
}

/// Checks a request against the policy, the protected list and what snetd sees; carries it
/// out; records it. Returns the message for the client, or why it was refused or failed.
#[allow(clippy::too_many_arguments)]
pub fn act(
    action: &Action,
    peer: &Peer,
    policy: Policy,
    snapshot: Option<&Snapshot>,
    paused: &mut HashSet<u32>,
    blocks: &mut Blocks,
    store: Option<&Store>,
    now: u64,
) -> Result<String, String> {
    let (target, outcome) = evaluate(action, peer, policy, snapshot, paused, blocks, store, now);
    let ok = outcome.is_ok();
    let message = match &outcome {
        Ok(m) | Err(m) => m.clone(),
    };
    if let Some(store) = store
        && let Err(e) = store.record_action(now, &peer.user, action, &target, ok, &message)
    {
        crate::service::log(&format!("audit: could not record an action: {e:#}"));
    }
    crate::service::log(&format!(
        "action by {}: {} → {}",
        peer.user, target, message
    ));
    outcome
}

#[allow(clippy::too_many_arguments)]
fn evaluate(
    action: &Action,
    peer: &Peer,
    policy: Policy,
    snapshot: Option<&Snapshot>,
    paused: &mut HashSet<u32>,
    blocks: &mut Blocks,
    store: Option<&Store>,
    now: u64,
) -> (String, Result<String, String>) {
    if policy.elevated_only && !peer.elevated {
        return ("-".into(), Err("actions are limited to administrators (actions = \"elevated-only\" in the snetd configuration)".into()));
    }
    let own_pid = std::process::id();
    let pid_target = |pid: u32| -> Result<(String, String), String> {
        if pid <= 1 || pid == 4 || pid == own_pid {
            return Err(format!("pid {pid} is protected"));
        }
        describe_pid(snapshot, pid).ok_or_else(|| {
            format!("pid {pid} is not a process with network activity seen by snetd")
        })
    };
    match action {
        Action::Kill { pid, force } => {
            let (name, exe) = match pid_target(*pid) {
                Ok(t) => t,
                Err(e) => return (format!("pid {pid}"), Err(e)),
            };
            if is_protected_name(&exe) {
                return (
                    name,
                    Err(format!(
                        "{exe} is protected: ending it could break the system or cut off remote access"
                    )),
                );
            }
            let result = control::terminate(*pid, *force)
                .map(|()| {
                    if *force {
                        format!("ended {name}")
                    } else {
                        format!("asked {name} to quit")
                    }
                })
                .map_err(|e| format!("could not end {name}: {e}"));
            paused.remove(pid);
            (name, result)
        }
        Action::Pause { pid } => {
            let (name, exe) = match pid_target(*pid) {
                Ok(t) => t,
                Err(e) => return (format!("pid {pid}"), Err(e)),
            };
            if is_protected_name(&exe) {
                return (
                    name,
                    Err(format!(
                        "{exe} is protected: pausing it could freeze the system or cut off remote access"
                    )),
                );
            }
            let result = control::pause(*pid).map(|()| {
                paused.insert(*pid);
                format!("paused {name}: it uses no CPU and no network until resumed")
            });
            let result = result.map_err(|e| format!("could not pause {name}: {e}"));
            (name, result)
        }
        Action::Resume { pid } => {
            // A paused process may have dropped out of the snapshot (no traffic): resuming
            // is always allowed for processes we paused.
            let name = describe_pid(snapshot, *pid).map_or(format!("pid {pid}"), |d| d.0);
            if !paused.contains(pid) && describe_pid(snapshot, *pid).is_none() {
                return (name, Err(format!("pid {pid} was not paused by snetd")));
            }
            let result = control::resume(*pid).map(|()| {
                paused.remove(pid);
                format!("resumed {name}")
            });
            let result = result.map_err(|e| format!("could not resume {name}: {e}"));
            (name, result)
        }
        Action::DropFlow {
            pid,
            transport,
            local,
            remote,
        } => {
            let target = format!("{local} → {remote}");
            let (name, exe) = match pid_target(*pid) {
                Ok(t) => t,
                Err(e) => return (target, Err(e)),
            };
            let target = format!("{name}: {target}");
            if is_protected_name(&exe) {
                return (target, Err(format!("{exe} is protected")));
            }
            let exists = snapshot.is_some_and(|s| {
                s.processes
                    .iter()
                    .filter(|p| p.process.pid == *pid)
                    .flat_map(|p| &p.flows)
                    .any(|f| f.transport == *transport && f.local == *local && f.remote == *remote)
            });
            if !exists {
                return (
                    target,
                    Err("no such connection in the latest sample (it may have just closed)".into()),
                );
            }
            let result = control::drop_flow(*transport, *local, *remote)
                .map(|()| format!("closed the connection to {remote}"))
                .map_err(|e| format!("could not close the connection: {e}"));
            (target, result)
        }
        Action::Block { target, ttl_s } => {
            let what = match target {
                BlockTarget::App { name, .. } => name.clone(),
                BlockTarget::Remote { ip } => ip.to_string(),
            };
            if let Err(e) = check_block_target(target, snapshot) {
                return (what, Err(e));
            }
            if *ttl_s > MAX_BLOCK_S {
                return (
                    what,
                    Err(format!(
                        "a timed block lasts at most {}; ask for 0 to block until lifted",
                        duration(MAX_BLOCK_S)
                    )),
                );
            }
            let outcome = blocks.add(target.clone(), *ttl_s, &peer.user, snapshot, store, now);
            (what, outcome)
        }
        Action::Unblock { id } => (
            id.map_or("all blocks".into(), |i| format!("block {i}")),
            blocks.lift(*id, store),
        ),
    }
}

/// Blocks never apply to protected programs, nor to addresses that would break the machine.
pub fn check_block_target(target: &BlockTarget, snapshot: Option<&Snapshot>) -> Result<(), String> {
    match target {
        BlockTarget::App { path, name } => {
            let exe = path.rsplit(['/', '\\']).next().unwrap_or(path);
            if is_protected_name(exe) || is_protected_name(name) {
                return Err(format!(
                    "{name} is protected: blocking it could break the system or cut off remote access"
                ));
            }
            let seen = snapshot.is_some_and(|s| {
                group_by_app(s.processes.clone())
                    .iter()
                    .any(|a| a.path.as_deref() == Some(path.as_str()))
            });
            if !seen {
                return Err(format!(
                    "{name} is not an application with network activity seen by snetd"
                ));
            }
            Ok(())
        }
        BlockTarget::Remote { ip } => {
            crate::blocks::blockable(*ip, &crate::blocks::protected_addresses(snapshot))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use spectranet_model::{Flow, Process, ProcessTraffic, Transport, Verdict};

    fn snapshot(pid: u32, name: &str) -> Snapshot {
        let flow = Flow {
            meta: Default::default(),
            transport: Transport::Tcp,
            local: "192.168.1.2:50000".parse().unwrap(),
            remote: "1.2.3.4:443".parse().unwrap(),
            remote_host: None,
            rx_rate: 10,
            tx_rate: 10,
            rx_bytes: 0,
            tx_bytes: 0,
            verdict: Verdict::Ok,
            note: None,
        };
        let process = Process {
            pid,
            name: name.into(),
            path: Some(format!("/usr/bin/{name}")),
            app: None,
        };
        Snapshot {
            source: "test".into(),
            timestamp_ms: 0,
            interval_ms: 1000,
            processes: vec![ProcessTraffic::new(process, vec![flow])],
        }
    }

    fn peer(elevated: bool) -> Peer {
        Peer {
            pid: Some(1),
            user: "tester".into(),
            elevated,
            resolved: true,
        }
    }

    #[test]
    fn protected_names() {
        for n in [
            "sshd-session",
            "launchd",
            "svchost.exe",
            "LSASS.EXE",
            "sshd",
            "systemd",
            "snetd",
            "mDNSResponder",
        ] {
            assert!(is_protected_name(n), "{n}");
        }
        for n in ["chrome", "Google Chrome Helper", "svc_update"] {
            assert!(!is_protected_name(n), "{n}");
        }
    }

    #[test]
    fn refuses_what_it_must() {
        let mut paused = HashSet::new();
        let s = snapshot(4242, "sshd");
        let (_, r) = evaluate(
            &Action::Kill {
                pid: 4242,
                force: true,
            },
            &peer(true),
            Policy::default(),
            Some(&s),
            &mut paused,
            &mut Blocks::default(),
            None,
            0,
        );
        assert!(r.unwrap_err().contains("protected"));
        let (_, r) = evaluate(
            &Action::Kill {
                pid: 1,
                force: true,
            },
            &peer(true),
            Policy::default(),
            Some(&s),
            &mut paused,
            &mut Blocks::default(),
            None,
            0,
        );
        assert!(r.unwrap_err().contains("protected"));
        let (_, r) = evaluate(
            &Action::Kill {
                pid: std::process::id(),
                force: true,
            },
            &peer(true),
            Policy::default(),
            Some(&s),
            &mut paused,
            &mut Blocks::default(),
            None,
            0,
        );
        assert!(r.is_err(), "never ourselves");
        let (_, r) = evaluate(
            &Action::Kill {
                pid: 9999,
                force: true,
            },
            &peer(true),
            Policy::default(),
            Some(&s),
            &mut paused,
            &mut Blocks::default(),
            None,
            0,
        );
        assert!(
            r.unwrap_err()
                .contains("not a process with network activity")
        );
        let strict = Policy {
            elevated_only: true,
        };
        let (_, r) = evaluate(
            &Action::Pause { pid: 4242 },
            &peer(false),
            strict,
            Some(&s),
            &mut paused,
            &mut Blocks::default(),
            None,
            0,
        );
        assert!(r.unwrap_err().contains("elevated-only"));
        let (_, r) = evaluate(
            &Action::DropFlow {
                pid: 4242,
                transport: Transport::Tcp,
                local: "1.1.1.1:1".parse().unwrap(),
                remote: "2.2.2.2:2".parse().unwrap(),
            },
            &peer(true),
            Policy::default(),
            Some(&snapshot(4243, "curl")),
            &mut paused,
            &mut Blocks::default(),
            None,
            0,
        );
        assert!(r.is_err());
    }

    #[test]
    fn pauses_resumes_and_ends_a_real_process() {
        let mut child = if cfg!(windows) {
            std::process::Command::new("cmd")
                .args(["/c", "ping -n 30 127.0.0.1 >nul"])
                .spawn()
                .unwrap()
        } else {
            std::process::Command::new("sleep")
                .arg("30")
                .spawn()
                .unwrap()
        };
        let pid = child.id();
        let s = snapshot(pid, "sleep");
        let mut paused = HashSet::new();
        let (_, r) = evaluate(
            &Action::Pause { pid },
            &peer(false),
            Policy::default(),
            Some(&s),
            &mut paused,
            &mut Blocks::default(),
            None,
            0,
        );
        assert!(r.unwrap().starts_with("paused"));
        assert!(paused.contains(&pid));
        let (_, r) = evaluate(
            &Action::Resume { pid },
            &peer(false),
            Policy::default(),
            None,
            &mut paused,
            &mut Blocks::default(),
            None,
            0,
        );
        assert!(
            r.unwrap().starts_with("resumed"),
            "resuming works even without a snapshot"
        );
        let (_, r) = evaluate(
            &Action::Kill { pid, force: true },
            &peer(false),
            Policy::default(),
            Some(&s),
            &mut paused,
            &mut Blocks::default(),
            None,
            0,
        );
        assert!(r.unwrap().starts_with("ended"));
        child.wait().unwrap();
    }

    #[test]
    fn block_targets() {
        assert!(
            check_block_target(
                &BlockTarget::Remote {
                    ip: "127.0.0.1".parse().unwrap()
                },
                None
            )
            .is_err()
        );
        assert!(
            check_block_target(
                &BlockTarget::Remote {
                    ip: "224.0.0.251".parse().unwrap()
                },
                None
            )
            .is_err()
        );
        assert!(
            check_block_target(
                &BlockTarget::Remote {
                    ip: "185.220.101.34".parse().unwrap()
                },
                None
            )
            .is_ok()
        );
        let s = snapshot(77, "sshd");
        assert!(
            check_block_target(
                &BlockTarget::App {
                    path: "/usr/bin/sshd".into(),
                    name: "sshd".into()
                },
                Some(&s)
            )
            .is_err()
        );
        let s = snapshot(78, "curl");
        assert!(
            check_block_target(
                &BlockTarget::App {
                    path: "/usr/bin/curl".into(),
                    name: "curl".into()
                },
                Some(&s)
            )
            .is_ok()
        );
        assert!(
            check_block_target(
                &BlockTarget::App {
                    path: "/usr/bin/wget".into(),
                    name: "wget".into()
                },
                Some(&s)
            )
            .is_err(),
            "not seen"
        );
    }

    #[test]
    fn audit_and_blocks_persist() {
        let dir = tempfile::tempdir().unwrap();
        let mut store = Store::open(&dir.path().join("t.sqlite")).unwrap();
        store.prepare_actions(1000).unwrap();
        store
            .record_action(
                1000,
                "alice",
                &Action::Kill {
                    pid: 5,
                    force: false,
                },
                "x (pid 5)",
                false,
                "nope",
            )
            .unwrap();
        store
            .record_action(
                1001,
                "alice",
                &Action::Pause { pid: 6 },
                "y (pid 6)",
                true,
                "paused",
            )
            .unwrap();
        let events = store.audit_since(0, 10).unwrap();
        assert_eq!(events.len(), 2);
        assert_eq!(events[0].action, Action::Pause { pid: 6 }, "newest first");
        assert!(!events[1].ok);
        let block = BlockInfo {
            id: 3,
            target: BlockTarget::Remote {
                ip: "1.2.3.4".parse().unwrap(),
            },
            created: 10,
            expires: 20,
            by: "alice".into(),
            method: "test".into(),
        };
        store.save_block(&block).unwrap();
        assert_eq!(store.load_blocks().unwrap(), vec![block]);
        store.delete_block(3).unwrap();
        assert!(store.load_blocks().unwrap().is_empty());
    }
}
