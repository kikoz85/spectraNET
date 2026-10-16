//! Round trips to a host: ICMP echo without privileges where the system allows it, otherwise
//! the time to open a TCP connection (a refusal is an answer too: it took one round trip).

use std::net::{IpAddr, SocketAddr, TcpStream};
use std::time::{Duration, Instant};

use crate::{Latency, Method, Probe};

/// How a host is probed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Options {
    pub count: u32,
    pub interval: Duration,
    pub timeout: Duration,
}

impl Default for Options {
    fn default() -> Self {
        Self {
            count: 20,
            interval: Duration::from_millis(200),
            timeout: Duration::from_secs(1),
        }
    }
}

/// Ports tried, in order, when ICMP is not available.
pub const TCP_PORTS: [u16; 3] = [443, 53, 80];

/// Measures `address`: ICMP if possible, else TCP on the first of `ports` that answers.
/// `None` when the host answered nothing at all.
pub fn latency(target: &str, address: IpAddr, options: Options, ports: &[u16]) -> Option<Latency> {
    // ICMP first; a host that ignores pings may still answer TCP.
    if let Ok(mut pinger) = Pinger::open(address) {
        let samples = run(options, |seq| pinger.ping(seq, options.timeout));
        if samples.iter().any(Option::is_some) {
            return Some(Latency::from_samples(
                target,
                address,
                Method::Icmp,
                &samples,
            ));
        }
    }
    let port = ports
        .iter()
        .copied()
        .find(|p| tcp_rtt(SocketAddr::new(address, *p), options.timeout).is_some())?;
    let samples = run(options, |_| {
        tcp_rtt(SocketAddr::new(address, port), options.timeout)
    });
    Some(Latency::from_samples(
        target,
        address,
        Method::Tcp { port },
        &samples,
    ))
}

/// [`latency`] as a [`Probe`]: no answer at all is "not measurable" for a router (some never
/// answer) but a 100 % loss for an internet target, which must answer.
pub fn probe(
    target: &str,
    address: IpAddr,
    options: Options,
    ports: &[u16],
    must_answer: bool,
) -> Probe<Latency> {
    match latency(target, address, options, ports) {
        Some(l) => Probe::Measured(l),
        None if must_answer => Probe::Measured(Latency::from_samples(
            target,
            address,
            Method::Icmp,
            &vec![None; options.count as usize],
        )),
        None => Probe::Unmeasurable {
            why: "no answer to ping or TCP".into(),
        },
    }
}

/// Runs `count` probes, `interval` apart (or right after a slow one).
fn run(options: Options, mut probe: impl FnMut(u16) -> Option<f64>) -> Vec<Option<f64>> {
    (0..options.count)
        .map(|i| {
            let started = Instant::now();
            let rtt = probe(i as u16);
            if i + 1 < options.count
                && let Some(left) = options.interval.checked_sub(started.elapsed())
            {
                std::thread::sleep(left);
            }
            rtt
        })
        .collect()
}

/// Time to get an answer to a TCP connection attempt, in ms: accepted, or refused where a
/// refusal comes back at once (Windows retries a refused connection for about a second, so
/// there only accepted connections are timed).
pub fn tcp_rtt(address: SocketAddr, timeout: Duration) -> Option<f64> {
    let started = Instant::now();
    match TcpStream::connect_timeout(&address, timeout) {
        Ok(stream) => {
            let rtt = ms(started.elapsed());
            drop(stream);
            Some(rtt)
        }
        Err(e) if !cfg!(windows) && e.kind() == std::io::ErrorKind::ConnectionRefused => {
            Some(ms(started.elapsed()))
        }
        Err(_) => None,
    }
}

fn ms(d: Duration) -> f64 {
    d.as_secs_f64() * 1000.0
}

/// The ICMP echo request: type, code, checksum, identifier, sequence, then `payload`.
pub fn echo_request(v6: bool, id: u16, seq: u16, payload: &[u8]) -> Vec<u8> {
    let mut packet = vec![if v6 { 128 } else { 8 }, 0, 0, 0];
    packet.extend_from_slice(&id.to_be_bytes());
    packet.extend_from_slice(&seq.to_be_bytes());
    packet.extend_from_slice(payload);
    if !v6 {
        // ICMPv6's checksum covers a pseudo-header: the kernel fills it in.
        let sum = checksum(&packet);
        packet[2..4].copy_from_slice(&sum.to_be_bytes());
    }
    packet
}

/// The Internet checksum (RFC 1071).
pub fn checksum(data: &[u8]) -> u16 {
    let mut sum: u32 = data
        .chunks(2)
        .map(|c| u32::from(u16::from_be_bytes([c[0], *c.get(1).unwrap_or(&0)])))
        .sum();
    while sum > 0xffff {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    !(sum as u16)
}

/// Whether `packet` is the echo reply to `seq` carrying `payload`. macOS hands datagram ICMP
/// sockets the IPv4 header too; Linux doesn't (and rewrites the identifier), so the sequence
/// and the payload are what identify our reply.
pub fn is_reply(packet: &[u8], v6: bool, seq: u16, payload: &[u8]) -> bool {
    let icmp = if !v6 && packet.first().is_some_and(|b| b >> 4 == 4) {
        let header = usize::from(packet[0] & 0x0f) * 4;
        match packet.get(header..) {
            Some(rest) => rest,
            None => return false,
        }
    } else {
        packet
    };
    icmp.len() >= 8 + payload.len()
        && icmp[0] == if v6 { 129 } else { 0 }
        && icmp[6..8] == seq.to_be_bytes()
        && &icmp[8..8 + payload.len()] == payload
}

/// Unprivileged ICMP echo.
pub struct Pinger {
    #[cfg(unix)]
    fd: libc::c_int,
    #[cfg(windows)]
    handle: windows_sys::Win32::Foundation::HANDLE,
    address: IpAddr,
    /// Distinguishes our replies from other programs' (random per pinger).
    token: [u8; 8],
}

fn token() -> [u8; 8] {
    // The clock alone is not enough: pingers opened at once in parallel threads may read the
    // same microsecond (macOS), and then take each other's replies.
    static OPENED: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
    let n = OPENED.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_nanos() as u64);
    (nanos ^ (u64::from(std::process::id()) << 32) ^ n.rotate_right(16)).to_be_bytes()
}

#[cfg(unix)]
#[allow(unsafe_code)]
impl Pinger {
    /// A datagram ICMP socket (macOS always; Linux when `net.ipv4.ping_group_range` lets this
    /// user in, as systemd sets it by default).
    pub fn open(address: IpAddr) -> std::io::Result<Self> {
        let (family, protocol) = match address {
            IpAddr::V4(_) => (libc::AF_INET, libc::IPPROTO_ICMP),
            IpAddr::V6(_) => (libc::AF_INET6, libc::IPPROTO_ICMPV6),
        };
        // SAFETY: plain socket creation; the descriptor is closed in Drop.
        let fd = unsafe { libc::socket(family, libc::SOCK_DGRAM, protocol) };
        if fd < 0 {
            return Err(std::io::Error::last_os_error());
        }
        Ok(Self {
            fd,
            address,
            token: token(),
        })
    }

    /// One echo; the round trip in ms, `None` when no reply came within `timeout`.
    pub fn ping(&mut self, seq: u16, timeout: Duration) -> Option<f64> {
        let v6 = self.address.is_ipv6();
        let packet = echo_request(v6, std::process::id() as u16, seq, &self.token);
        let started = Instant::now();
        self.send(&packet).ok()?;
        let mut buf = [0u8; 1500];
        loop {
            let left = timeout.checked_sub(started.elapsed())?;
            let (n, from) = self.recv(&mut buf, left)?;
            if from.is_none_or(|f| f == self.address) && is_reply(&buf[..n], v6, seq, &self.token) {
                return Some(ms(started.elapsed()));
            }
        }
    }

    fn send(&self, packet: &[u8]) -> std::io::Result<()> {
        let sent = match self.address {
            IpAddr::V4(ip) => {
                let mut sa: libc::sockaddr_in = unsafe { std::mem::zeroed() };
                sa.sin_family = libc::AF_INET as libc::sa_family_t;
                sa.sin_addr.s_addr = u32::from_ne_bytes(ip.octets());
                #[cfg(target_os = "macos")]
                {
                    sa.sin_len = std::mem::size_of::<libc::sockaddr_in>() as u8;
                }
                // SAFETY: valid buffer and address for the duration of the call.
                unsafe {
                    libc::sendto(
                        self.fd,
                        packet.as_ptr().cast(),
                        packet.len(),
                        0,
                        (&sa as *const libc::sockaddr_in).cast(),
                        std::mem::size_of::<libc::sockaddr_in>() as libc::socklen_t,
                    )
                }
            }
            IpAddr::V6(ip) => {
                let mut sa: libc::sockaddr_in6 = unsafe { std::mem::zeroed() };
                sa.sin6_family = libc::AF_INET6 as libc::sa_family_t;
                sa.sin6_addr.s6_addr = ip.octets();
                #[cfg(target_os = "macos")]
                {
                    sa.sin6_len = std::mem::size_of::<libc::sockaddr_in6>() as u8;
                }
                // SAFETY: valid buffer and address for the duration of the call.
                unsafe {
                    libc::sendto(
                        self.fd,
                        packet.as_ptr().cast(),
                        packet.len(),
                        0,
                        (&sa as *const libc::sockaddr_in6).cast(),
                        std::mem::size_of::<libc::sockaddr_in6>() as libc::socklen_t,
                    )
                }
            }
        };
        if sent < 0 {
            Err(std::io::Error::last_os_error())
        } else {
            Ok(())
        }
    }

    /// One datagram and who sent it (when the system says).
    fn recv(&self, buf: &mut [u8], timeout: Duration) -> Option<(usize, Option<IpAddr>)> {
        let tv = libc::timeval {
            tv_sec: timeout.as_secs() as libc::time_t,
            tv_usec: timeout.subsec_micros().max(1000) as libc::suseconds_t,
        };
        // SAFETY: valid option value for SO_RCVTIMEO.
        unsafe {
            libc::setsockopt(
                self.fd,
                libc::SOL_SOCKET,
                libc::SO_RCVTIMEO,
                (&tv as *const libc::timeval).cast(),
                std::mem::size_of::<libc::timeval>() as libc::socklen_t,
            );
        }
        let mut from: libc::sockaddr_storage = unsafe { std::mem::zeroed() };
        let mut len = std::mem::size_of::<libc::sockaddr_storage>() as libc::socklen_t;
        // SAFETY: the buffer and the address storage are valid for their lengths.
        let n = unsafe {
            libc::recvfrom(
                self.fd,
                buf.as_mut_ptr().cast(),
                buf.len(),
                0,
                (&mut from as *mut libc::sockaddr_storage).cast(),
                &mut len,
            )
        };
        if n <= 0 {
            return None;
        }
        let sender = match i32::from(from.ss_family) {
            libc::AF_INET => {
                // SAFETY: the kernel wrote an AF_INET address.
                let sa = unsafe {
                    *(&from as *const libc::sockaddr_storage).cast::<libc::sockaddr_in>()
                };
                Some(IpAddr::V4(std::net::Ipv4Addr::from(
                    sa.sin_addr.s_addr.to_ne_bytes(),
                )))
            }
            libc::AF_INET6 => {
                // SAFETY: the kernel wrote an AF_INET6 address.
                let sa = unsafe {
                    *(&from as *const libc::sockaddr_storage).cast::<libc::sockaddr_in6>()
                };
                Some(IpAddr::V6(std::net::Ipv6Addr::from(sa.sin6_addr.s6_addr)))
            }
            _ => None,
        };
        Some((n as usize, sender))
    }

    /// The raw descriptor (for the path probe, which sets the TTL).
    pub(crate) fn fd(&self) -> libc::c_int {
        self.fd
    }

    pub(crate) fn token(&self) -> [u8; 8] {
        self.token
    }
}

#[cfg(unix)]
#[allow(unsafe_code)]
impl Drop for Pinger {
    fn drop(&mut self) {
        // SAFETY: the descriptor is ours and closed once.
        unsafe {
            libc::close(self.fd);
        }
    }
}

#[cfg(windows)]
#[allow(unsafe_code)]
impl Pinger {
    /// The system's ICMP API (no privilege needed); IPv4 only.
    pub fn open(address: IpAddr) -> std::io::Result<Self> {
        use windows_sys::Win32::Foundation::INVALID_HANDLE_VALUE;
        use windows_sys::Win32::NetworkManagement::IpHelper::IcmpCreateFile;
        if address.is_ipv6() {
            return Err(std::io::Error::other("IPv6 echo is not used on Windows"));
        }
        // SAFETY: no arguments; the handle is closed in Drop.
        let handle = unsafe { IcmpCreateFile() };
        if handle == INVALID_HANDLE_VALUE || handle.is_null() {
            return Err(std::io::Error::last_os_error());
        }
        Ok(Self {
            handle,
            address,
            token: token(),
        })
    }

    /// One echo; the round trip in ms, `None` when no reply came within `timeout`.
    pub fn ping(&mut self, _seq: u16, timeout: Duration) -> Option<f64> {
        self.echo(None, timeout)
            .and_then(|(rtt, _, done)| done.then_some(rtt))
    }

    /// One echo with an optional TTL: (round trip in ms, the address that answered, whether
    /// it was the destination itself rather than a router on the way).
    pub(crate) fn echo(
        &mut self,
        ttl: Option<u8>,
        timeout: Duration,
    ) -> Option<(f64, IpAddr, bool)> {
        use windows_sys::Win32::NetworkManagement::IpHelper::{
            ICMP_ECHO_REPLY, IP_OPTION_INFORMATION, IP_SUCCESS, IP_TTL_EXPIRED_TRANSIT,
            IcmpSendEcho,
        };
        let IpAddr::V4(dest) = self.address else {
            return None;
        };
        let mut reply = vec![0u8; std::mem::size_of::<ICMP_ECHO_REPLY>() + self.token.len() + 64];
        let options = IP_OPTION_INFORMATION {
            Ttl: ttl.unwrap_or(128),
            ..Default::default()
        };
        let started = Instant::now();
        // SAFETY: valid handle, buffers and options for the duration of the call.
        let count = unsafe {
            IcmpSendEcho(
                self.handle,
                u32::from_ne_bytes(dest.octets()),
                self.token.as_ptr().cast(),
                self.token.len() as u16,
                &options,
                reply.as_mut_ptr().cast(),
                reply.len() as u32,
                timeout.as_millis().max(1) as u32,
            )
        };
        let rtt = ms(started.elapsed());
        if count == 0 {
            return None;
        }
        // SAFETY: the buffer starts with an ICMP_ECHO_REPLY written by the call.
        let r: ICMP_ECHO_REPLY = unsafe { std::ptr::read_unaligned(reply.as_ptr().cast()) };
        let from = IpAddr::V4(std::net::Ipv4Addr::from(r.Address.to_ne_bytes()));
        match r.Status {
            IP_SUCCESS => Some((rtt, from, true)),
            IP_TTL_EXPIRED_TRANSIT => Some((rtt, from, false)),
            _ => None,
        }
    }
}

#[cfg(windows)]
#[allow(unsafe_code)]
impl Drop for Pinger {
    fn drop(&mut self) {
        // SAFETY: the handle is ours and closed once.
        unsafe {
            windows_sys::Win32::NetworkManagement::IpHelper::IcmpCloseHandle(self.handle);
        }
    }
}

// SAFETY: the socket or handle is owned by the pinger and used from one thread at a time.
#[allow(unsafe_code)]
unsafe impl Send for Pinger {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn checksum_of_a_known_echo() {
        // Echo request, id 0x1234, seq 1, no payload: checksum 0xe5ca.
        let p = echo_request(false, 0x1234, 1, &[]);
        assert_eq!(&p[2..4], &0xe5ca_u16.to_be_bytes());
        assert_eq!(checksum(&p), 0, "a correct packet sums to zero");
    }

    #[test]
    fn replies_are_recognised_with_or_without_the_ip_header() {
        let payload = *b"spectran";
        let mut reply = echo_request(false, 7, 42, &payload);
        reply[0] = 0; // echo reply
        assert!(is_reply(&reply, false, 42, &payload));
        assert!(!is_reply(&reply, false, 43, &payload), "another sequence");
        assert!(!is_reply(&reply, false, 42, b"otherpay"), "another program");
        // macOS: a 20-byte IPv4 header first.
        let mut with_ip = vec![
            0x45, 0, 0, 0, 0, 0, 0, 0, 64, 1, 0, 0, 1, 1, 1, 1, 10, 0, 0, 2,
        ];
        with_ip.extend_from_slice(&reply);
        assert!(is_reply(&with_ip, false, 42, &payload));
        // A request is not a reply.
        assert!(!is_reply(
            &echo_request(false, 7, 42, &payload),
            false,
            42,
            &payload
        ));
        let mut v6 = echo_request(true, 7, 5, &payload);
        v6[0] = 129;
        assert!(is_reply(&v6, true, 5, &payload));
    }

    #[test]
    fn tcp_round_trips_to_a_local_listener() {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let rtt = tcp_rtt(addr, Duration::from_secs(1)).unwrap();
        assert!(rtt < 500.0);
        // A closed port refuses: an answer too, except on Windows (see tcp_rtt).
        drop(listener);
        assert_eq!(
            tcp_rtt(addr, Duration::from_millis(500)).is_some(),
            !cfg!(windows)
        );
    }

    #[test]
    fn loopback_answers_and_says_how() {
        let options = Options {
            count: 5,
            interval: Duration::from_millis(10),
            timeout: Duration::from_millis(500),
        };
        let l = latency(
            "localhost",
            "127.0.0.1".parse().unwrap(),
            options,
            &TCP_PORTS,
        )
        .unwrap();
        assert_eq!(l.sent, 5);
        assert!(l.received >= 4, "{l:?}");
        // ICMP where the system allows it, TCP otherwise: either way it is said.
        assert!(matches!(l.method, Method::Icmp | Method::Tcp { .. }));
    }
}
