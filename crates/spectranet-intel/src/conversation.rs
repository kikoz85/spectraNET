//! What an application exchanges with one host, all its connections together.
//!
//! Applications rarely use one connection per conversation: browsers open several per site,
//! FTP one per file next to its control connection, video players two or three, SMB and SFTP
//! reuse or add sockets. Inspectors follow the conversation, so the picture stays right while
//! connections come and go.

use spectranet_model::Flow;
use spectranet_model::flowmeta::{Kind, Reason};

use crate::classify::file_transfer_port;

/// The conversation as one flow: the busiest connection's identity, the kind said by the
/// connection that carries the most, and the rates and totals of all of them. `None` when
/// there is no connection.
pub fn combine<'a>(flows: impl IntoIterator<Item = &'a Flow>) -> Option<Flow> {
    let flows: Vec<&Flow> = flows.into_iter().collect();
    let busiest = flows.iter().copied().max_by_key(|f| {
        (
            f.rx_rate + f.tx_rate,
            f.meta.class.is_some(),
            f.rx_bytes + f.tx_bytes,
        )
    })?;
    let mut flow = busiest.clone();
    if let Some(class) = flows
        .iter()
        .filter(|f| f.meta.class.is_some())
        .max_by_key(|f| (f.rx_rate + f.tx_rate, f.rx_bytes + f.tx_bytes))
        .and_then(|f| f.meta.class.clone())
    {
        flow.meta.class = Some(class);
    }
    // With a file-transfer protocol in the conversation (FTP's control connection, SFTP,
    // SMB) it carries files, also on connections whose own port says nothing (FTP data).
    let files = flows.iter().find_map(|f| {
        [f.remote.port(), f.local.port()]
            .into_iter()
            .find(|p| file_transfer_port(*p))
    });
    let rx: u64 = flows.iter().map(|f| f.rx_rate).sum();
    let tx: u64 = flows.iter().map(|f| f.tx_rate).sum();
    if let (Some(port), Some(class)) = (files, flow.meta.class.as_mut())
        && !matches!(class.kind, Kind::Download | Kind::Upload)
    {
        class.kind = if tx > rx {
            Kind::Upload
        } else {
            Kind::Download
        };
        class.reasons = vec![Reason::WellKnownPort { port }];
    }
    if flow.meta.tls.is_none() {
        flow.meta.tls = flows.iter().find_map(|f| f.meta.tls.clone());
    }
    if flow.remote_host.is_none() {
        flow.remote_host = flows.iter().find_map(|f| f.remote_host.clone());
    }
    if let Some(worst) = flows.iter().max_by_key(|f| f.verdict)
        && worst.verdict > flow.verdict
    {
        flow.verdict = worst.verdict;
        flow.note.clone_from(&worst.note);
    }
    flow.rx_rate = rx;
    flow.tx_rate = tx;
    flow.rx_bytes = flows.iter().map(|f| f.rx_bytes).sum();
    flow.tx_bytes = flows.iter().map(|f| f.tx_bytes).sum();
    let pps = |get: fn(&Flow) -> Option<u32>| {
        let v: Vec<u32> = flows.iter().filter_map(|f| get(f)).collect();
        (!v.is_empty()).then(|| v.iter().sum())
    };
    flow.meta.rx_pps = pps(|f| f.meta.rx_pps);
    flow.meta.tx_pps = pps(|f| f.meta.tx_pps);
    Some(flow)
}

/// Recent traffic that makes a host "busy now" (64 kB over the last minutes).
pub const BUSY_NOW: u64 = 64 << 10;

/// Sort key of a host in an inspector's list, most interesting first when sorted in reverse:
/// hosts busy right now by recent traffic, then the others by everything they exchanged (a
/// music player that downloaded the song and now plays it from memory still points to the
/// music server, not to the small exchanges of the moment).
pub fn interest(recent: u64, total: u64) -> (bool, u64) {
    if recent >= BUSY_NOW {
        (true, recent)
    } else {
        (false, total)
    }
}

/// The remote ports of a conversation, short: `:8096`, ` (21, 50012)`, ` (21, 50012…)`.
pub fn ports_label<'a>(flows: impl IntoIterator<Item = &'a Flow>) -> String {
    let mut ports: Vec<u16> = flows.into_iter().map(|f| f.remote.port()).collect();
    ports.sort_unstable();
    ports.dedup();
    match ports.as_slice() {
        [one] => format!(":{one}"),
        [a, b] => format!(" ({a}, {b})"),
        [a, b, ..] => format!(" ({a}, {b}…)"),
        [] => String::new(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use spectranet_model::flowmeta::{Certainty, Class};
    use spectranet_model::{Transport, Verdict};

    fn flow(remote: &str, rx_rate: u64, rx_bytes: u64, kind: Option<Kind>) -> Flow {
        let mut f = Flow {
            transport: Transport::Tcp,
            local: "192.168.1.36:50000".parse().unwrap(),
            remote: remote.parse().unwrap(),
            remote_host: None,
            rx_rate,
            tx_rate: 100,
            rx_bytes,
            tx_bytes: 1_000,
            verdict: Verdict::Ok,
            note: None,
            meta: Default::default(),
        };
        f.meta.class = kind.map(|kind| Class {
            kind,
            certainty: Certainty::Likely,
            reasons: Vec::new(),
        });
        f
    }

    #[test]
    fn connections_to_one_host_add_up() {
        let film = flow("192.168.1.50:8096", 0, 120 << 20, Some(Kind::Video));
        let second = flow("192.168.1.50:8096", 5 << 20, 60 << 20, None);
        let api = flow("192.168.1.50:8096", 300, 30 << 10, None);
        let all = [film, second, api];
        let c = combine(&all).unwrap();
        assert_eq!(c.rx_rate, (5 << 20) + 300);
        assert_eq!(c.rx_bytes, (180 << 20) + (30 << 10));
        assert_eq!(c.meta.class.unwrap().kind, Kind::Video);
        assert_eq!(ports_label(&all), ":8096");
        assert!(combine(std::iter::empty()).is_none());
    }

    #[test]
    fn ftp_data_on_any_port_is_a_transfer() {
        let control = flow("82.85.208.204:21", 200, 4_000, None);
        let data = flow(
            "82.85.208.204:50012",
            30 << 20,
            900 << 20,
            Some(Kind::Video),
        );
        let all = [control, data];
        let c = combine(&all).unwrap();
        let class = c.meta.class.unwrap();
        assert_eq!(class.kind, Kind::Download);
        assert_eq!(class.reasons, vec![Reason::WellKnownPort { port: 21 }]);
        assert_eq!(ports_label(&all), " (21, 50012)");
    }
}
