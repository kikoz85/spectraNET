//! Blocks in force: what is blocked, until when, and keeping the system in line with it.
//!
//! The enforcement mechanism ([`spectranet_capture::block`]) is started on the first block
//! and lives as long as snetd: blocks are saved in the database and put back in force when
//! snetd starts. On every sample, expired blocks are lifted, connections that a block should
//! have ended are closed, and (on macOS) the addresses of blocked applications are followed.

use std::collections::HashSet;
use std::net::IpAddr;
use std::path::PathBuf;

use spectranet_capture::block::{self, AppBlocking, Enforcer};
use spectranet_capture::control;
use spectranet_model::{ProcessTraffic, Snapshot};
use spectranet_proto::{BlockInfo, BlockTarget};

use crate::usage::Store;

/// Ports of remote-access services: the address of whoever is connected to them is never
/// blocked, so a remote administrator can't cut themselves off.
const REMOTE_ACCESS_PORTS: [u16; 4] = [22, 3389, 5900, 5938];
const REMOTE_ACCESS_NAMES: [&str; 8] = [
    "sshd",
    "sshd-session",
    "winvnc",
    "vncserver",
    "xtigervnc",
    "teamviewer",
    "anydesk",
    "rustdesk",
];

#[derive(Default)]
pub struct Blocks {
    list: Vec<BlockInfo>,
    enforcer: Option<Box<dyn Enforcer>>,
    /// Executables blocked for each application block (Linux, Windows).
    executables: std::collections::HashMap<u64, Vec<PathBuf>>,
}

/// Processes belonging to the application at `path` (as in `AppTraffic::path`).
fn members<'a>(snapshot: &'a Snapshot, path: &'a str) -> impl Iterator<Item = &'a ProcessTraffic> {
    snapshot
        .processes
        .iter()
        .filter(move |p| match &p.process.app {
            Some(app) => app.path == path,
            None => p.process.path.as_deref() == Some(path),
        })
}

/// The executables of an application: each member process's file, and the application's
/// path itself when it is a file (not a macOS bundle directory).
pub fn executables(snapshot: Option<&Snapshot>, path: &str) -> Vec<PathBuf> {
    let mut out: Vec<PathBuf> = Vec::new();
    if let Some(s) = snapshot {
        for p in members(s, path) {
            if let Some(exe) = &p.process.path {
                let exe = PathBuf::from(exe);
                if !out.contains(&exe) {
                    out.push(exe);
                }
            }
        }
    }
    let own = PathBuf::from(path);
    if own.is_file() && !out.contains(&own) {
        out.push(own);
    }
    out
}

/// Addresses that must never be blocked: loopback and unspecified, the default gateway, the
/// DNS servers, and the remote ends of remote-access sessions.
pub fn protected_addresses(snapshot: Option<&Snapshot>) -> HashSet<IpAddr> {
    let mut out = HashSet::new();
    if let Ok(iface) = netdev::get_default_interface() {
        if let Some(gw) = &iface.gateway {
            out.extend(gw.ipv4.iter().map(|ip| IpAddr::V4(*ip)));
            out.extend(gw.ipv6.iter().map(|ip| IpAddr::V6(*ip)));
        }
        out.extend(iface.dns_servers.iter().copied());
    }
    if let Some(s) = snapshot {
        for p in &s.processes {
            let name = p.process.name.to_lowercase();
            let name = name.strip_suffix(".exe").unwrap_or(&name);
            let remote_access = REMOTE_ACCESS_NAMES.contains(&name);
            for f in &p.flows {
                if remote_access || REMOTE_ACCESS_PORTS.contains(&f.local.port()) {
                    out.insert(f.remote.ip());
                }
            }
        }
    }
    out
}

/// Whether `ip` may be blocked: never the machine's own plumbing.
pub fn blockable(ip: IpAddr, protected: &HashSet<IpAddr>) -> Result<(), String> {
    let canonical = match ip {
        IpAddr::V6(v6) => v6.to_ipv4_mapped().map_or(ip, IpAddr::V4),
        v4 => v4,
    };
    let system = canonical.is_loopback()
        || canonical.is_unspecified()
        || canonical.is_multicast()
        || matches!(canonical, IpAddr::V4(v4) if v4.is_broadcast() || v4.is_link_local());
    if system {
        return Err(format!("{ip} can't be blocked: the system needs it"));
    }
    if protected.contains(&canonical) {
        return Err(format!(
            "{ip} can't be blocked: it is this network's gateway or DNS server, or a remote-access session"
        ));
    }
    Ok(())
}

impl Blocks {
    /// Puts the saved blocks back in force (dropping the expired ones).
    pub fn restore(store: &Store, now: u64) -> Self {
        let mut blocks = Self::default();
        let saved = store.load_blocks().unwrap_or_default();
        for b in saved {
            if expired(&b, now) {
                let _ = store.delete_block(b.id);
                continue;
            }
            let executables = store.block_executables(b.id).unwrap_or_default();
            match blocks.enforce(&b, &executables) {
                Ok(()) => {
                    blocks.executables.insert(b.id, executables);
                    blocks.list.push(b);
                }
                Err(e) => {
                    crate::service::log(&format!("block {} could not be restored: {e}", b.id))
                }
            }
        }
        if !blocks.list.is_empty() {
            crate::service::log(&format!("{} block(s) back in force", blocks.list.len()));
        }
        blocks
    }

    pub fn list(&self) -> Vec<BlockInfo> {
        self.list.clone()
    }

    pub fn len(&self) -> usize {
        self.list.len()
    }

    pub fn is_empty(&self) -> bool {
        self.list.is_empty()
    }

    fn enforcer(&mut self) -> Result<&mut Box<dyn Enforcer>, String> {
        if self.enforcer.is_none() {
            self.enforcer =
                Some(block::start().map_err(|e| format!("blocking is not available: {e}"))?);
        }
        Ok(self.enforcer.as_mut().expect("just set"))
    }

    fn enforce(&mut self, b: &BlockInfo, executables: &[PathBuf]) -> Result<(), String> {
        let enforcer = self.enforcer()?;
        match &b.target {
            BlockTarget::Remote { ip } => enforcer.block_ip(b.id, *ip).map_err(|e| e.to_string()),
            BlockTarget::App { .. } => match enforcer.app_blocking() {
                AppBlocking::Full => enforcer
                    .block_app(b.id, executables)
                    .map_err(|e| e.to_string()),
                // Its addresses are added as they are seen.
                AppBlocking::Following => Ok(()),
            },
        }
    }

    /// Puts a new block in force. `ttl_s` 0 means until lifted.
    #[allow(clippy::too_many_arguments)]
    pub fn add(
        &mut self,
        target: BlockTarget,
        ttl_s: u64,
        by: &str,
        snapshot: Option<&Snapshot>,
        store: Option<&Store>,
        now: u64,
    ) -> Result<String, String> {
        if let Some(existing) = self.list.iter().find(|b| b.target == target) {
            return Err(format!(
                "already blocked (block {}); lift it first to change it",
                existing.id
            ));
        }
        let executables = match &target {
            BlockTarget::App { path, name } => {
                let exes = executables(snapshot, path);
                if exes.is_empty() && block::support() == Some(AppBlocking::Full) {
                    return Err(format!("the program file of {name} could not be found"));
                }
                exes
            }
            BlockTarget::Remote { .. } => Vec::new(),
        };
        let id = self.list.iter().map(|b| b.id).max().unwrap_or(0).max(
            store
                .and_then(|s| s.load_blocks().ok())
                .and_then(|l| l.iter().map(|b| b.id).max())
                .unwrap_or(0),
        ) + 1;
        let method = self
            .enforcer()
            .map(|e| e.method().to_string())
            .unwrap_or_default();
        let info = BlockInfo {
            id,
            target,
            created: now,
            expires: if ttl_s == 0 { 0 } else { now + ttl_s },
            by: by.to_string(),
            method,
        };
        self.enforce(&info, &executables)?;
        if let Some(store) = store {
            let saved = store
                .save_block(&info)
                .and_then(|()| store.save_block_executables(id, &executables));
            if let Err(e) = saved {
                crate::service::log(&format!("block {id} not saved: {e:#}"));
            }
        }
        self.executables.insert(id, executables);
        self.list.push(info.clone());
        // Connections already open end now, not when they next reconnect.
        if let Some(s) = snapshot {
            self.sweep(s);
        }
        let until = if info.expires == 0 {
            "until lifted".to_string()
        } else {
            format!("for {}", crate::actions::duration(ttl_s))
        };
        let what = match &info.target {
            BlockTarget::App { name, .. } => name.clone(),
            BlockTarget::Remote { ip } => ip.to_string(),
        };
        Ok(format!(
            "blocked {what} {until} (block {id}, {})",
            info.method
        ))
    }

    /// Lifts one block, or all of them.
    pub fn lift(&mut self, id: Option<u64>, store: Option<&Store>) -> Result<String, String> {
        let ids: Vec<u64> = match id {
            Some(id) if self.list.iter().any(|b| b.id == id) => vec![id],
            Some(id) => return Err(format!("there is no block {id}")),
            None if self.list.is_empty() => return Err("there are no blocks to lift".into()),
            None => self.list.iter().map(|b| b.id).collect(),
        };
        for id in &ids {
            self.remove(*id, store);
        }
        Ok(match id {
            Some(id) => format!("lifted block {id}"),
            None => format!("lifted {} block(s)", ids.len()),
        })
    }

    fn remove(&mut self, id: u64, store: Option<&Store>) {
        if let Some(e) = self.enforcer.as_mut()
            && let Err(err) = e.lift(id)
        {
            crate::service::log(&format!("lifting block {id}: {err}"));
        }
        self.list.retain(|b| b.id != id);
        self.executables.remove(&id);
        if let Some(store) = store {
            let _ = store.delete_block(id);
        }
        if self.list.is_empty() {
            // Nothing left: release the mechanism entirely (detach, close the session).
            self.enforcer = None;
        }
    }

    /// Lifts expired blocks; returns what was lifted, for the audit log.
    pub fn expire(&mut self, store: Option<&Store>, now: u64) -> Vec<BlockInfo> {
        let gone: Vec<BlockInfo> = self
            .list
            .iter()
            .filter(|b| expired(b, now))
            .cloned()
            .collect();
        for b in &gone {
            self.remove(b.id, store);
        }
        gone
    }

    /// Keeps the system in line with the blocks after a new sample: follows the addresses of
    /// blocked applications where needed, and closes connections that are still open.
    pub fn on_snapshot(&mut self, snapshot: &Snapshot) {
        if self.list.is_empty() {
            return;
        }
        let following = self
            .enforcer
            .as_ref()
            .is_some_and(|e| e.app_blocking() == AppBlocking::Following);
        if following {
            let protected = protected_addresses(Some(snapshot));
            let apps: Vec<(u64, String)> = self
                .list
                .iter()
                .filter_map(|b| match &b.target {
                    BlockTarget::App { path, .. } => Some((b.id, path.clone())),
                    BlockTarget::Remote { .. } => None,
                })
                .collect();
            for (id, path) in apps {
                let remotes: HashSet<IpAddr> = members(snapshot, &path)
                    .flat_map(|p| &p.flows)
                    .map(|f| f.remote.ip())
                    .filter(|ip| blockable(*ip, &protected).is_ok())
                    .collect();
                if let Some(e) = self.enforcer.as_mut() {
                    for ip in remotes {
                        if let Err(err) = e.block_ip(id, ip) {
                            crate::service::log(&format!("block {id}: {ip}: {err}"));
                        }
                    }
                }
            }
        }
        self.sweep(snapshot);
    }

    /// Closes the connections a block covers that are still open.
    fn sweep(&self, snapshot: &Snapshot) {
        if control::drop_support() == control::DropSupport::None {
            return;
        }
        for b in &self.list {
            let flows: Vec<_> = match &b.target {
                BlockTarget::App { path, .. } => members(snapshot, path)
                    .flat_map(|p| p.flows.iter())
                    .collect(),
                BlockTarget::Remote { ip } => snapshot
                    .processes
                    .iter()
                    .flat_map(|p| &p.flows)
                    .filter(|f| f.remote.ip() == *ip)
                    .collect(),
            };
            for f in flows {
                // Listening and unconnected sockets have no remote end to close.
                if f.remote.ip().is_unspecified() || f.remote.port() == 0 {
                    continue;
                }
                let _ = control::drop_flow(f.transport, f.local, f.remote);
            }
        }
    }
}

fn expired(b: &BlockInfo, now: u64) -> bool {
    b.expires != 0 && b.expires <= now
}

#[cfg(test)]
mod tests {
    use super::*;
    use spectranet_model::{Flow, Process, Transport, Verdict};

    fn snapshot() -> Snapshot {
        let flow = |local: &str, remote: &str| Flow {
            meta: Default::default(),
            transport: Transport::Tcp,
            local: local.parse().unwrap(),
            remote: remote.parse().unwrap(),
            remote_host: None,
            rx_rate: 1,
            tx_rate: 1,
            rx_bytes: 0,
            tx_bytes: 0,
            verdict: Verdict::Ok,
            note: None,
        };
        let process = |pid, name: &str, path: &str, flows| {
            ProcessTraffic::new(
                Process {
                    pid,
                    name: name.into(),
                    path: Some(path.into()),
                    app: None,
                },
                flows,
            )
        };
        Snapshot {
            source: "test".into(),
            timestamp_ms: 0,
            interval_ms: 1000,
            processes: vec![
                process(
                    10,
                    "sshd-session",
                    "/usr/sbin/sshd",
                    vec![flow("10.0.0.2:22", "203.0.113.9:51000")],
                ),
                process(
                    11,
                    "curl",
                    "/usr/bin/curl",
                    vec![flow("10.0.0.2:50000", "198.51.100.7:443")],
                ),
                process(
                    12,
                    "curl",
                    "/usr/bin/curl",
                    vec![flow("10.0.0.2:50001", "198.51.100.8:443")],
                ),
            ],
        }
    }

    #[test]
    fn remote_admins_are_never_cut_off() {
        let s = snapshot();
        let protected = protected_addresses(Some(&s));
        let admin: IpAddr = "203.0.113.9".parse().unwrap();
        assert!(protected.contains(&admin));
        assert!(blockable(admin, &protected).is_err());
        assert!(blockable("198.51.100.7".parse().unwrap(), &protected).is_ok());
        for system in [
            "127.0.0.1",
            "::1",
            "0.0.0.0",
            "224.0.0.251",
            "169.254.1.1",
            "::ffff:127.0.0.1",
        ] {
            assert!(
                blockable(system.parse().unwrap(), &protected).is_err(),
                "{system}"
            );
        }
    }

    #[test]
    fn an_app_is_all_of_its_processes() {
        let s = snapshot();
        assert_eq!(members(&s, "/usr/bin/curl").count(), 2);
        let exes = executables(Some(&s), "/usr/bin/curl");
        assert_eq!(exes[0], PathBuf::from("/usr/bin/curl"));
        assert_eq!(exes.len(), 1, "one file, however many processes");
    }

    #[test]
    fn expiry() {
        let b = BlockInfo {
            id: 1,
            target: BlockTarget::Remote {
                ip: "198.51.100.7".parse().unwrap(),
            },
            created: 100,
            expires: 200,
            by: "t".into(),
            method: "test".into(),
        };
        assert!(!expired(&b, 199));
        assert!(expired(&b, 200));
        let forever = BlockInfo { expires: 0, ..b };
        assert!(!expired(&forever, u64::MAX));
    }
}
