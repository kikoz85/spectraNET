//! Name resolution time with the system's resolver (whatever it is configured to use: the
//! router, the provider's servers, a DoH proxy…).
//!
//! Names no cache can know are looked up (a random label under example.com, which answers
//! "no such name" after a real trip to its servers), so the time is the resolver's, not a
//! cache's. A well-known name is resolved too, to tell "slow" from "not answering at all".

use std::net::ToSocketAddrs;
use std::sync::mpsc;
use std::time::{Duration, Instant};

use crate::{Dns, Probe};

/// How many uncached lookups, and how long one may take.
pub const LOOKUPS: usize = 3;
pub const TIMEOUT: Duration = Duration::from_secs(3);

/// A name that must resolve on any working connection.
pub const WELL_KNOWN: &str = "www.wikipedia.org";

/// Resolves `name` with the system resolver; the time taken in ms, and whether it gave
/// addresses. A lookup that outlives `timeout` counts as `timeout` and no answer (the thread
/// is left to finish on its own: getaddrinfo can't be cancelled).
pub fn resolve(name: &str, timeout: Duration) -> (f64, bool) {
    let (tx, rx) = mpsc::channel();
    let target = format!("{name}:443");
    let started = Instant::now();
    std::thread::spawn(move || {
        let ok = target
            .to_socket_addrs()
            .is_ok_and(|mut addrs| addrs.next().is_some());
        let _ = tx.send(ok);
    });
    match rx.recv_timeout(timeout) {
        Ok(ok) => (started.elapsed().as_secs_f64() * 1000.0, ok),
        Err(_) => (timeout.as_secs_f64() * 1000.0, false),
    }
}

/// A label nobody has asked for before.
fn fresh_name(i: usize) -> String {
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_nanos());
    format!(
        "snet-{:x}-{i}.example.com",
        nanos ^ u128::from(std::process::id())
    )
}

/// Measures the system resolver.
pub fn measure() -> Probe<Dns> {
    // All lookups in parallel: about three seconds at worst.
    let known = std::thread::spawn(|| resolve(WELL_KNOWN, TIMEOUT));
    let fresh: Vec<_> = (0..LOOKUPS)
        .map(|i| {
            let name = fresh_name(i);
            std::thread::spawn(move || resolve(&name, TIMEOUT).0)
        })
        .collect();
    let mut lookups_ms: Vec<f64> = fresh
        .into_iter()
        .map(|t| t.join().unwrap_or(TIMEOUT.as_secs_f64() * 1000.0))
        .collect();
    let (_, resolves) = known.join().unwrap_or((0.0, false));
    let mut sorted = lookups_ms.clone();
    sorted.sort_by(f64::total_cmp);
    let median_ms = sorted[sorted.len() / 2];
    lookups_ms.shrink_to_fit();
    Probe::Measured(Dns {
        lookups_ms,
        median_ms,
        resolves,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn localhost_resolves_quickly() {
        let (ms, ok) = resolve("localhost", TIMEOUT);
        assert!(ok);
        assert!(ms < TIMEOUT.as_secs_f64() * 1000.0);
    }

    #[test]
    fn fresh_names_differ() {
        assert_ne!(fresh_name(0), fresh_name(1));
        assert!(fresh_name(0).ends_with(".example.com"));
    }
}
