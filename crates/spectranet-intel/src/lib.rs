//! Security assessment of connections: turns raw traffic into verdicts a person can act on.
//!
//! Rules (all evaluated locally):
//! - **reputation**: the remote address is on a public blocklist (botnet C2, criminal
//!   networks, Tor exits) — see [`feeds`];
//! - **cleartext**: data exchanged with a public server over a protocol that is not
//!   encrypted (HTTP, FTP, Telnet, POP3, IMAP), readable by anyone on the path.
//!
//! The verdict of a flow is the most severe of its findings; a process takes the most severe
//! verdict of its flows.

pub mod analysis;
pub mod classify;
pub mod conversation;
pub mod feeds;
pub mod ipset;
pub mod radio;

use std::net::{IpAddr, SocketAddr};
use std::path::Path;

use spectranet_model::{Flow, Snapshot, Transport, Verdict};

pub use feeds::{FEEDS, Feed, FeedStatus, Feeds};

/// Unencrypted protocols, by server port.
const CLEARTEXT: [(u16, &str); 6] = [
    (80, "HTTP"),
    (8080, "HTTP"),
    (21, "FTP"),
    (23, "Telnet"),
    (110, "POP3"),
    (143, "IMAP"),
];

/// One reason a connection deserves attention.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Finding {
    pub pid: u32,
    pub process: String,
    pub remote: SocketAddr,
    pub host: Option<String>,
    /// Stable rule identifier, e.g. `reputation:feodo`, `cleartext:http`.
    pub rule: String,
    pub verdict: Verdict,
    pub message: String,
}

/// The rule engine.
#[derive(Debug, Default)]
pub struct Intel {
    feeds: Feeds,
}

impl Intel {
    pub fn new(feeds: Feeds) -> Self {
        Self { feeds }
    }

    /// Loads the reputation lists stored in `dir` (missing lists are skipped).
    pub fn load(dir: &Path) -> Self {
        Self::new(Feeds::load(dir))
    }

    pub fn feeds(&self) -> &Feeds {
        &self.feeds
    }

    /// Assesses one flow.
    pub fn assess(&self, flow: &Flow) -> Vec<(String, Verdict, String)> {
        let mut found = Vec::new();
        let ip = flow.remote.ip();
        if !is_public(ip) {
            return found;
        }
        if let Some(feed) = self.feeds.lookup(ip) {
            found.push((
                format!("reputation:{}", feed.id),
                feed.verdict,
                feed.reason.to_string(),
            ));
        }
        if flow.transport == Transport::Tcp
            && flow.rx_bytes + flow.tx_bytes > 0
            && let Some((_, protocol)) = CLEARTEXT
                .iter()
                .find(|(port, _)| *port == flow.remote.port())
        {
            found.push((
                format!("cleartext:{}", protocol.to_ascii_lowercase()),
                Verdict::Warn,
                format!("unencrypted {protocol}: anyone on the network path can read this traffic"),
            ));
        }
        found
    }

    /// Applies the rules to every flow of `snapshot`, raising verdicts and setting notes, and
    /// returns what was found. Existing verdicts are never lowered.
    pub fn annotate(&self, snapshot: &mut Snapshot) -> Vec<Finding> {
        let mut findings = Vec::new();
        for process in &mut snapshot.processes {
            for flow in &mut process.flows {
                let mut found = self.assess(flow);
                found.sort_by_key(|(_, verdict, _)| std::cmp::Reverse(*verdict));
                if let Some((_, verdict, message)) = found.first()
                    && *verdict > flow.verdict
                {
                    flow.verdict = *verdict;
                    flow.note = Some(message.clone());
                }
                findings.extend(found.into_iter().map(|(rule, verdict, message)| Finding {
                    pid: process.process.pid,
                    process: process.process.name.clone(),
                    remote: flow.remote,
                    host: flow.remote_host.clone(),
                    rule,
                    verdict,
                    message,
                }));
            }
            process.verdict = process
                .flows
                .iter()
                .map(|f| f.verdict)
                .max()
                .unwrap_or_default();
        }
        findings
    }
}

/// Addresses on the public Internet: not private, loopback, link-local, multicast, carrier-NAT,
/// documentation or unspecified.
pub fn is_public(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => {
            let [a, b, ..] = v4.octets();
            !(v4.is_private()
                || v4.is_loopback()
                || v4.is_link_local()
                || v4.is_multicast()
                || v4.is_broadcast()
                || v4.is_unspecified()
                || v4.is_documentation()
                || (a == 100 && (64..128).contains(&b)))
        }
        IpAddr::V6(v6) => match v6.to_ipv4_mapped() {
            Some(v4) => is_public(IpAddr::V4(v4)),
            None => {
                let first = v6.segments()[0];
                !(v6.is_loopback()
                    || v6.is_unspecified()
                    || v6.is_multicast()
                    || (first & 0xFE00) == 0xFC00
                    || (first & 0xFFC0) == 0xFE80
                    || first == 0x2001 && v6.segments()[1] == 0x0db8)
            }
        },
    }
}

#[cfg(test)]
mod tests {
    use spectranet_model::{Process, ProcessTraffic};

    use super::*;

    fn flow(remote: &str, transport: Transport, bytes: u64) -> Flow {
        Flow {
            meta: Default::default(),
            transport,
            local: "192.168.1.36:50000".parse().unwrap(),
            remote: remote.parse().unwrap(),
            remote_host: None,
            rx_rate: 0,
            tx_rate: 0,
            rx_bytes: bytes,
            tx_bytes: 0,
            verdict: Verdict::Ok,
            note: None,
        }
    }

    fn intel_with(lists: &[(usize, &str)]) -> (Intel, tempfile::TempDir) {
        let dir = tempfile::tempdir().unwrap();
        for (index, body) in lists {
            feeds::install(dir.path(), &FEEDS[*index], body).unwrap();
        }
        (Intel::load(dir.path()), dir)
    }

    fn snapshot(flows: Vec<Flow>) -> Snapshot {
        let process = Process {
            pid: 7,
            name: "app".into(),
            path: None,
            app: None,
        };
        Snapshot {
            source: "test".into(),
            timestamp_ms: 0,
            interval_ms: 1000,
            processes: vec![ProcessTraffic::new(process, flows)],
        }
    }

    #[test]
    fn cleartext_to_public_servers_only() {
        let intel = Intel::default();
        let warn = |remote: &str, transport, bytes| intel.assess(&flow(remote, transport, bytes));
        assert_eq!(
            warn("93.184.216.34:80", Transport::Tcp, 10)[0].0,
            "cleartext:http"
        );
        assert_eq!(
            warn("93.184.216.34:21", Transport::Tcp, 10)[0].0,
            "cleartext:ftp"
        );
        assert!(
            warn("93.184.216.34:443", Transport::Tcp, 10).is_empty(),
            "HTTPS is fine"
        );
        assert!(
            warn("192.168.1.1:80", Transport::Tcp, 10).is_empty(),
            "router admin page on the LAN"
        );
        assert!(
            warn("93.184.216.34:80", Transport::Tcp, 0).is_empty(),
            "nothing exchanged yet"
        );
        assert!(warn("93.184.216.34:80", Transport::Udp, 10).is_empty());
    }

    #[test]
    fn reputation_matches_and_most_severe_wins() {
        let (intel, _dir) = intel_with(&[
            (0, "185.220.101.5\n"),
            (3, "185.220.101.5\n171.25.193.25\n"),
        ]);
        let found = intel.assess(&flow("185.220.101.5:80", Transport::Tcp, 100));
        let rules: Vec<_> = found.iter().map(|(r, _, _)| r.as_str()).collect();
        assert_eq!(rules, ["reputation:feodo", "cleartext:http"]);

        let mut snap = snapshot(vec![
            flow("185.220.101.5:80", Transport::Tcp, 100),
            flow("171.25.193.25:443", Transport::Tcp, 100),
            flow("8.8.8.8:443", Transport::Udp, 100),
        ]);
        let findings = intel.annotate(&mut snap);
        assert_eq!(findings.len(), 3);
        let flows = &snap.processes[0].flows;
        assert_eq!(flows[0].verdict, Verdict::Alert);
        assert!(flows[0].note.as_deref().unwrap().contains("botnet"));
        assert_eq!(flows[1].verdict, Verdict::Warn);
        assert!(flows[1].note.as_deref().unwrap().contains("Tor"));
        assert_eq!(flows[2].verdict, Verdict::Ok);
        assert_eq!(
            snap.processes[0].verdict,
            Verdict::Alert,
            "process takes the worst verdict"
        );
    }

    #[test]
    fn existing_verdicts_are_never_lowered() {
        let intel = Intel::default();
        let mut f = flow("8.8.8.8:443", Transport::Tcp, 1);
        f.verdict = Verdict::Alert;
        f.note = Some("set elsewhere".into());
        let mut snap = snapshot(vec![f]);
        intel.annotate(&mut snap);
        assert_eq!(
            snap.processes[0].flows[0].note.as_deref(),
            Some("set elsewhere")
        );
        assert_eq!(snap.processes[0].verdict, Verdict::Alert);
    }

    #[test]
    fn public_address_classification() {
        for public in [
            "8.8.8.8",
            "93.184.216.34",
            "2606:4700::1111",
            "::ffff:1.1.1.1",
        ] {
            assert!(is_public(public.parse().unwrap()), "{public}");
        }
        for private in [
            "10.0.0.1",
            "192.168.1.50",
            "172.16.0.1",
            "127.0.0.1",
            "169.254.1.1",
            "100.64.0.1",
            "224.0.0.251",
            "0.0.0.0",
            "192.0.2.1",
            "::1",
            "fe80::1",
            "fd00::1",
            "ff02::fb",
            "2001:db8::1",
            "::",
        ] {
            assert!(!is_public(private.parse().unwrap()), "{private}");
        }
    }

    #[test]
    fn many_flows_are_cheap() {
        let lines: String = (0..50_000u32)
            .map(|i| format!("{}\n", std::net::Ipv4Addr::from(0x0A00_0000 + i * 7)))
            .collect();
        let (intel, _dir) = intel_with(&[(1, &lines)]);
        let flows: Vec<_> = (0..5_000)
            .map(|i| {
                flow(
                    &format!("93.{}.{}.1:443", i % 250, i / 250),
                    Transport::Tcp,
                    1,
                )
            })
            .collect();
        let mut snap = snapshot(flows);
        let begun = std::time::Instant::now();
        intel.annotate(&mut snap);
        assert!(
            begun.elapsed() < std::time::Duration::from_millis(200),
            "{:?}",
            begun.elapsed()
        );
    }
}
