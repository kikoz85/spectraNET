//! Live packet capture (libpcap) feeding the [`NameTable`]. Requires root.
//!
//! One thread per active interface, plus a supervisor that picks up interfaces appearing
//! later (VPN tunnels, a newly joined network). Only DNS responses and TLS client traffic
//! pass the kernel filter, so the cost stays proportional to new connections, not bandwidth.

use std::collections::HashSet;
use std::path::Path;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::thread::{self, JoinHandle};
use std::time::Duration;

use pcap::{Activated, Capture, Device};

use super::packet::Link;
use super::{NameTable, Sniffer};

/// Kernel-side filter: DNS answers, mDNS, client-to-server TLS over TCP (where the
/// ClientHello travels), server segments that start with a TLS handshake record (the
/// ServerHello: version and cipher suite) and QUIC long-header packets (Initial handshakes)
/// — but not QUIC's short-header data packets nor the servers' data, which carry the bulk
/// of the traffic.
///
/// libpcap cannot index `udp[]` over IPv6, so the QUIC first byte is addressed through the
/// IPv6 header instead (40-byte fixed header + 8-byte UDP header).
const FILTER: &str = "udp src port 53 or tcp src port 53 or udp port 5353 or tcp dst port 443 \
                      or (ip and udp dst port 443 and udp[8] & 0xc0 = 0xc0) \
                      or (ip6 and udp dst port 443 and ip6[48] & 0xc0 = 0xc0) \
                      or (ip and tcp src port 443 and tcp[((tcp[12] & 0xf0) >> 2)] = 0x16) \
                      or (ip6 and tcp src port 443 and ip6[40 + ((ip6[52] & 0xf0) >> 2)] = 0x16)";
const READ_TIMEOUT_MS: i32 = 250;
const RESCAN_EVERY: Duration = Duration::from_secs(5);

/// Why live capture could not start.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StartError {
    /// Opening capture devices needs root (or read access to /dev/bpf*).
    PermissionDenied,
    /// No interface could be opened for another reason.
    Failed(String),
}

/// Running capture threads. Dropping it stops them.
pub struct LiveNames {
    stop: Arc<AtomicBool>,
    supervisor: Option<JoinHandle<()>>,
}

impl LiveNames {
    pub fn start(table: Arc<Mutex<NameTable>>) -> Result<Self, StartError> {
        let stop = Arc::new(AtomicBool::new(false));
        let running = Arc::new(Mutex::new(HashSet::new()));
        let mut workers = Vec::new();
        let opened = open_new_devices(&table, &stop, &running, &mut workers)?;
        if opened == 0 {
            return Err(StartError::Failed("no usable network interface".into()));
        }
        let supervisor = {
            let stop = stop.clone();
            thread::Builder::new()
                .name("snet-capture-supervisor".into())
                .spawn(move || {
                    while !sleep_unless_stopped(&stop, RESCAN_EVERY) {
                        let _ = open_new_devices(&table, &stop, &running, &mut workers);
                        workers.retain(|w| !w.is_finished());
                    }
                    for worker in workers {
                        let _ = worker.join();
                    }
                })
                .map_err(|e| StartError::Failed(e.to_string()))?
        };
        Ok(Self {
            stop,
            supervisor: Some(supervisor),
        })
    }
}

impl Drop for LiveNames {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Relaxed);
        if let Some(supervisor) = self.supervisor.take() {
            let _ = supervisor.join();
        }
    }
}

/// Opens every usable interface not already captured. Returns how many are now running.
fn open_new_devices(
    table: &Arc<Mutex<NameTable>>,
    stop: &Arc<AtomicBool>,
    running: &Arc<Mutex<HashSet<String>>>,
    workers: &mut Vec<JoinHandle<()>>,
) -> Result<usize, StartError> {
    let devices = Device::list().map_err(|e| StartError::Failed(e.to_string()))?;
    let mut denied = 0;
    let mut candidates = 0;
    for device in devices.into_iter().filter(usable) {
        let name = device.name.clone();
        if running.lock().map(|r| r.contains(&name)).unwrap_or(true) {
            continue;
        }
        candidates += 1;
        match open(device) {
            Ok((capture, link)) => {
                if let Ok(mut r) = running.lock() {
                    r.insert(name.clone());
                }
                let (table, stop, running) = (table.clone(), stop.clone(), running.clone());
                let spawned = thread::Builder::new()
                    .name(format!("snet-capture-{name}"))
                    .spawn(move || {
                        let mut capture = capture;
                        pump(&mut capture, link, &table, &stop);
                        if let Ok(mut r) = running.lock() {
                            r.remove(&name);
                        }
                    });
                if let Ok(handle) = spawned {
                    workers.push(handle);
                }
            }
            Err(e) if is_permission_error(&e) => denied += 1,
            Err(_) => {}
        }
    }
    if candidates > 0 && denied == candidates && workers.is_empty() {
        return Err(StartError::PermissionDenied);
    }
    Ok(running.lock().map(|r| r.len()).unwrap_or(0))
}

/// On Linux the pseudo-interface `any` sees every interface, including ones that appear
/// later, through a single handle. Elsewhere, each active interface is opened.
#[cfg(target_os = "linux")]
fn usable(device: &Device) -> bool {
    device.name == "any"
}

#[cfg(not(target_os = "linux"))]
fn usable(device: &Device) -> bool {
    device.flags.is_up() && device.flags.is_running() && !device.addresses.is_empty()
}

fn open(device: Device) -> Result<(Capture<pcap::Active>, Link), pcap::Error> {
    let mut capture = Capture::from_device(device)?
        .immediate_mode(true)
        .snaplen(65_535)
        .timeout(READ_TIMEOUT_MS)
        .open()?;
    capture.filter(FILTER, true)?;
    let link = Link::from_dlt(capture.get_datalink().0)
        .ok_or_else(|| pcap::Error::PcapError("unsupported link type".into()))?;
    Ok((capture, link))
}

fn is_permission_error(e: &pcap::Error) -> bool {
    let text = e.to_string().to_lowercase();
    text.contains("permission denied") || text.contains("operation not permitted")
}

/// Reads frames until stopped, end of file, or a fatal error.
pub fn pump<T: Activated + ?Sized>(
    capture: &mut Capture<T>,
    link: Link,
    table: &Mutex<NameTable>,
    stop: &AtomicBool,
) {
    let mut sniffer = Sniffer::default();
    while !stop.load(Ordering::Relaxed) {
        match capture.next_packet() {
            Ok(packet) => {
                if let Some(learned) = sniffer.handle(link, packet.data)
                    && let Ok(mut t) = table.lock()
                {
                    t.apply(learned);
                }
            }
            Err(pcap::Error::TimeoutExpired) => {}
            Err(_) => break, // NoMorePackets (file) or interface gone
        }
    }
}

/// Replays a capture file through the same pipeline as live capture.
pub fn replay(path: &Path, table: &Mutex<NameTable>) -> Result<(), pcap::Error> {
    let mut capture = Capture::from_file(path)?;
    let link = Link::from_dlt(capture.get_datalink().0)
        .ok_or_else(|| pcap::Error::PcapError("unsupported link type".into()))?;
    pump(&mut capture, link, table, &AtomicBool::new(false));
    Ok(())
}

/// Sleeps in short steps; returns true as soon as `stop` is set.
fn sleep_unless_stopped(stop: &AtomicBool, total: Duration) -> bool {
    let step = Duration::from_millis(100);
    let mut slept = Duration::ZERO;
    while slept < total {
        if stop.load(Ordering::Relaxed) {
            return true;
        }
        thread::sleep(step);
        slept += step;
    }
    stop.load(Ordering::Relaxed)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::names::{dns, packet::tests::*, tls};
    use pcap::{Linktype, Packet, PacketHeader};

    fn write_pcap(path: &Path, frames: &[Vec<u8>]) {
        let dead = Capture::dead(Linktype::ETHERNET).unwrap();
        let mut file = dead.savefile(path).unwrap();
        for (i, frame) in frames.iter().enumerate() {
            let header = PacketHeader {
                ts: libc::timeval {
                    tv_sec: 1_760_000_000 + i as libc::time_t,
                    tv_usec: 0,
                },
                caplen: frame.len() as u32,
                len: frame.len() as u32,
            };
            file.write(&Packet::new(&header, frame));
        }
        file.flush().unwrap();
    }

    /// End-to-end through libpcap: a capture file with a realistic browsing session.
    #[test]
    fn replayed_session_yields_names() {
        let dns_reply = dns::tests::response(
            "www.youtube.com",
            &[("www.youtube.com", 1, vec![142, 250, 180, 14])],
        );
        let hello = tls::tests::client_hello(Some("i.ytimg.com"), 2200);
        let client: std::net::SocketAddr = "192.168.1.36:52000".parse().unwrap();
        let server: std::net::SocketAddr = "142.250.180.78:443".parse().unwrap();
        let mut frames = vec![udp_frame(
            "192.168.1.1:53".parse().unwrap(),
            "192.168.1.36:61000".parse().unwrap(),
            &dns_reply,
        )];
        for (i, chunk) in hello.chunks(1448).enumerate() {
            frames.push(tcp_frame(client, server, 1 + (i * 1448) as u32, chunk));
        }
        // Unrelated noise that must be ignored.
        frames.push(tcp_frame(
            client,
            server,
            99_999,
            &[0x17, 0x03, 0x03, 0, 4, 1, 2, 3, 4],
        ));
        frames.push(vec![0xFF; 60]);

        let path = std::env::temp_dir().join(format!("snet-replay-{}.pcap", std::process::id()));
        write_pcap(&path, &frames);
        let table = Mutex::new(NameTable::default());
        replay(&path, &table).unwrap();
        std::fs::remove_file(&path).unwrap();

        let table = table.into_inner().unwrap();
        let elsewhere: std::net::SocketAddr = "192.168.1.36:1".parse().unwrap();
        assert_eq!(
            table.lookup(elsewhere, "142.250.180.14:443".parse().unwrap()),
            Some("www.youtube.com")
        );
        assert_eq!(table.lookup(client, server), Some("i.ytimg.com"));
    }

    /// The kernel filter, compiled by libpcap, must pass exactly the traffic we decode,
    /// over IPv4 and IPv6 alike.
    #[test]
    fn kernel_filter_selects_the_right_packets() {
        let program = Capture::dead(Linktype::ETHERNET)
            .unwrap()
            .compile(FILTER, true)
            .unwrap();
        let v4 = ("192.168.1.36", "142.250.180.14");
        let v6 = ("2001:db8::36", "2001:db8::14");
        for (client, server) in [v4, v6] {
            let a = |ip: &str, port: u16| -> std::net::SocketAddr {
                std::net::SocketAddr::new(ip.parse().unwrap(), port)
            };
            let long_header = [0xC3, 0, 0, 0, 1, 8];
            let short_header = [0x43, 1, 2, 3, 4, 5];
            let cases = [
                (
                    udp_frame(a(server, 53), a(client, 5000), b"dns"),
                    true,
                    "DNS answer",
                ),
                (
                    udp_frame(a(client, 5000), a(server, 53), b"dns"),
                    false,
                    "DNS query",
                ),
                (
                    tcp_frame(a(server, 53), a(client, 5000), 1, b"dns"),
                    true,
                    "DNS over TCP",
                ),
                (
                    udp_frame(a(server, 5353), a(client, 5353), b"mdns"),
                    true,
                    "mDNS",
                ),
                (
                    tcp_frame(a(client, 5000), a(server, 443), 1, b"hello"),
                    true,
                    "TLS to server",
                ),
                (
                    tcp_frame(
                        a(server, 443),
                        a(client, 5000),
                        1,
                        &[0x17, 3, 3, 0, 4, 1, 2, 3, 4],
                    ),
                    false,
                    "TLS data from server",
                ),
                (
                    tcp_frame(
                        a(server, 443),
                        a(client, 5000),
                        1,
                        &[0x16, 3, 3, 0, 4, 2, 0, 0, 0],
                    ),
                    true,
                    "ServerHello",
                ),
                (
                    udp_frame(a(client, 5000), a(server, 443), &long_header),
                    true,
                    "QUIC Initial",
                ),
                (
                    udp_frame(a(client, 5000), a(server, 443), &short_header),
                    false,
                    "QUIC data",
                ),
                (
                    udp_frame(a(server, 443), a(client, 5000), &long_header),
                    false,
                    "QUIC from server",
                ),
                (
                    tcp_frame(a(client, 5000), a(server, 80), 1, b"GET"),
                    false,
                    "plain HTTP",
                ),
            ];
            for (frame, expected, what) in cases {
                assert_eq!(program.filter(&frame), expected, "{what} over {client}");
            }
        }
    }

    #[test]
    fn missing_capture_file_is_an_error() {
        let table = Mutex::new(NameTable::default());
        assert!(replay(Path::new("/nonexistent/snet.pcap"), &table).is_err());
    }

    /// Without root, starting must fail cleanly with PermissionDenied (never hang or panic).
    /// With root, it must start and stop promptly.
    #[test]
    fn start_and_stop() {
        let table = Arc::new(Mutex::new(NameTable::default()));
        let begun = std::time::Instant::now();
        match LiveNames::start(table) {
            Ok(live) => {
                drop(live);
                assert!(begun.elapsed() < Duration::from_secs(3), "stop is prompt");
            }
            Err(StartError::PermissionDenied) => {
                assert!(unsafe_euid() != 0, "root must not be denied");
            }
            Err(StartError::Failed(e)) => panic!("unexpected failure: {e}"),
        }
    }

    #[allow(unsafe_code)]
    fn unsafe_euid() -> u32 {
        // SAFETY: no preconditions.
        unsafe { libc::geteuid() }
    }
}
