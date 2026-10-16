//! The path to an internet target, hop by hop (in the style of mtr): echo requests with a
//! growing TTL; each router on the way answers "time exceeded" when the TTL runs out there.
//!
//! No privilege is needed: Windows' ICMP API reports the router that answered; on Linux the
//! unprivileged ICMP socket queues the "time exceeded" in its error queue (IP_RECVERR); on
//! macOS it is delivered to the same socket. Hops that don't answer (many don't) are shown as
//! such; only IPv4 targets are traced.

use std::net::IpAddr;
use std::time::Duration;
#[cfg(unix)]
use std::time::Instant;

use crate::{Hop, Probe};

/// Hops tried at most, probes per hop, and how long to wait for each.
pub const MAX_HOPS: u8 = 20;
pub const PER_HOP: u32 = 3;
pub const TIMEOUT: Duration = Duration::from_millis(800);

/// What one probe with a TTL got back.
#[derive(Debug, Clone, Copy, PartialEq)]
pub(crate) enum Echo {
    /// A router on the way: time exceeded.
    Hop {
        from: IpAddr,
        rtt_ms: f64,
    },
    /// The target itself answered.
    Reached {
        rtt_ms: f64,
    },
    Silent,
}

/// Traces the path to `target`.
pub fn trace(target: IpAddr) -> Probe<Vec<Hop>> {
    if target.is_ipv6() {
        return Probe::Unmeasurable {
            why: "only IPv4 paths are traced".into(),
        };
    }
    let mut prober = match Prober::open(target) {
        Ok(p) => p,
        Err(e) => {
            return Probe::Unmeasurable {
                why: format!("no unprivileged ICMP here ({e})"),
            };
        }
    };
    let mut hops = Vec::new();
    let mut seq: u16 = 1000;
    for ttl in 1..=MAX_HOPS {
        let mut address = None;
        let mut rtts = Vec::new();
        let mut reached = false;
        for _ in 0..PER_HOP {
            seq = seq.wrapping_add(1);
            match prober.probe(ttl, seq, TIMEOUT) {
                Echo::Hop { from, rtt_ms } => {
                    address.get_or_insert(from);
                    rtts.push(rtt_ms);
                }
                Echo::Reached { rtt_ms } => {
                    address.get_or_insert(target);
                    rtts.push(rtt_ms);
                    reached = true;
                }
                Echo::Silent => {}
            }
        }
        hops.push(Hop {
            ttl,
            address,
            sent: PER_HOP,
            received: rtts.len() as u32,
            avg_ms: (!rtts.is_empty()).then(|| rtts.iter().sum::<f64>() / rtts.len() as f64),
        });
        if reached {
            return Probe::Measured(hops);
        }
    }
    if hops.iter().all(|h| h.received == 0) {
        return Probe::Unmeasurable {
            why: "no router on the way answered".into(),
        };
    }
    Probe::Measured(hops)
}

#[cfg_attr(windows, allow(dead_code))]
/// Finds which of our probes a "time exceeded" quotes: the original IPv4 header and the first
/// eight bytes of our echo (type, code, checksum, id, sequence) follow the ICMP header.
pub(crate) fn quoted_sequence(icmp_error: &[u8]) -> Option<u16> {
    let inner = icmp_error.get(8..)?;
    let ihl = usize::from(inner.first()? & 0x0f) * 4;
    let echo = inner.get(ihl..ihl + 8)?;
    (echo[0] == 8).then(|| u16::from_be_bytes([echo[6], echo[7]]))
}

#[cfg(windows)]
struct Prober(crate::ping::Pinger);

#[cfg(windows)]
impl Prober {
    fn open(target: IpAddr) -> std::io::Result<Self> {
        crate::ping::Pinger::open(target).map(Self)
    }

    fn probe(&mut self, ttl: u8, _seq: u16, timeout: Duration) -> Echo {
        match self.0.echo(Some(ttl), timeout) {
            Some((rtt_ms, _, true)) => Echo::Reached { rtt_ms },
            Some((rtt_ms, from, false)) => Echo::Hop { from, rtt_ms },
            None => Echo::Silent,
        }
    }
}

#[cfg(unix)]
struct Prober {
    pinger: crate::ping::Pinger,
    target: IpAddr,
}

#[cfg(unix)]
#[allow(unsafe_code)]
impl Prober {
    fn open(target: IpAddr) -> std::io::Result<Self> {
        let pinger = crate::ping::Pinger::open(target)?;
        #[cfg(target_os = "linux")]
        {
            let on: libc::c_int = 1;
            // SAFETY: valid option value; errors are reported through the error queue.
            unsafe {
                libc::setsockopt(
                    pinger.fd(),
                    libc::IPPROTO_IP,
                    libc::IP_RECVERR,
                    (&on as *const libc::c_int).cast(),
                    std::mem::size_of::<libc::c_int>() as libc::socklen_t,
                );
            }
        }
        Ok(Self { pinger, target })
    }

    fn probe(&mut self, ttl: u8, seq: u16, timeout: Duration) -> Echo {
        let fd = self.pinger.fd();
        let value: libc::c_int = libc::c_int::from(ttl);
        // SAFETY: valid option value.
        unsafe {
            libc::setsockopt(
                fd,
                libc::IPPROTO_IP,
                libc::IP_TTL,
                (&value as *const libc::c_int).cast(),
                std::mem::size_of::<libc::c_int>() as libc::socklen_t,
            );
        }
        let token = self.pinger.token();
        let packet = crate::ping::echo_request(false, std::process::id() as u16, seq, &token);
        let IpAddr::V4(ip) = self.target else {
            return Echo::Silent;
        };
        let mut sa: libc::sockaddr_in = unsafe { std::mem::zeroed() };
        sa.sin_family = libc::AF_INET as libc::sa_family_t;
        sa.sin_addr.s_addr = u32::from_ne_bytes(ip.octets());
        #[cfg(target_os = "macos")]
        {
            sa.sin_len = std::mem::size_of::<libc::sockaddr_in>() as u8;
        }
        let started = Instant::now();
        // SAFETY: valid buffer and address.
        let sent = unsafe {
            libc::sendto(
                fd,
                packet.as_ptr().cast(),
                packet.len(),
                0,
                (&sa as *const libc::sockaddr_in).cast(),
                std::mem::size_of::<libc::sockaddr_in>() as libc::socklen_t,
            )
        };
        if sent < 0 {
            return Echo::Silent;
        }
        let mut buf = [0u8; 1500];
        loop {
            let Some(left) = timeout.checked_sub(started.elapsed()) else {
                return Echo::Silent;
            };
            let mut pfd = libc::pollfd {
                fd,
                events: libc::POLLIN,
                revents: 0,
            };
            // SAFETY: one valid pollfd.
            let ready = unsafe { libc::poll(&mut pfd, 1, left.as_millis().max(1) as libc::c_int) };
            if ready <= 0 {
                return Echo::Silent;
            }
            let rtt_ms = started.elapsed().as_secs_f64() * 1000.0;
            #[cfg(target_os = "linux")]
            if pfd.revents & libc::POLLERR != 0 {
                if let Some((from, quoted)) = linux_error(fd, &mut buf)
                    && quoted == seq
                {
                    return Echo::Hop { from, rtt_ms };
                }
                continue;
            }
            // SAFETY: the buffer is valid for its length.
            let n =
                unsafe { libc::recv(fd, buf.as_mut_ptr().cast(), buf.len(), libc::MSG_DONTWAIT) };
            if n <= 0 {
                continue;
            }
            let packet = &buf[..n as usize];
            if crate::ping::is_reply(packet, false, seq, &token) {
                return Echo::Reached { rtt_ms };
            }
            // macOS: the IPv4 header, then a time exceeded quoting our echo.
            if packet.first().is_some_and(|b| b >> 4 == 4) {
                let ihl = usize::from(packet[0] & 0x0f) * 4;
                if let Some(icmp) = packet.get(ihl..)
                    && icmp.first() == Some(&11)
                    && quoted_sequence(icmp) == Some(seq)
                    && packet.len() >= 20
                {
                    let from = IpAddr::V4(std::net::Ipv4Addr::new(
                        packet[12], packet[13], packet[14], packet[15],
                    ));
                    return Echo::Hop { from, rtt_ms };
                }
            }
        }
    }
}

/// Reads one entry of the socket's error queue: the router that sent "time exceeded", and the
/// sequence of the echo it refers to.
#[cfg(target_os = "linux")]
#[allow(unsafe_code)]
fn linux_error(fd: libc::c_int, buf: &mut [u8]) -> Option<(IpAddr, u16)> {
    let mut control = [0u8; 512];
    let mut iov = libc::iovec {
        iov_base: buf.as_mut_ptr().cast(),
        iov_len: buf.len(),
    };
    let mut msg: libc::msghdr = unsafe { std::mem::zeroed() };
    msg.msg_iov = &mut iov;
    msg.msg_iovlen = 1;
    msg.msg_control = control.as_mut_ptr().cast();
    msg.msg_controllen = control.len();
    // SAFETY: msg points to valid buffers for the duration of the call.
    let n = unsafe { libc::recvmsg(fd, &mut msg, libc::MSG_ERRQUEUE | libc::MSG_DONTWAIT) };
    if n < 0 {
        return None;
    }
    // The queued payload is our own echo: its sequence tells which probe this was.
    let payload = &buf[..n as usize];
    let seq = u16::from_be_bytes([*payload.get(6)?, *payload.get(7)?]);
    // SAFETY: walking the control messages the kernel wrote into `control`.
    unsafe {
        let mut cmsg = libc::CMSG_FIRSTHDR(&msg);
        while !cmsg.is_null() {
            if (*cmsg).cmsg_level == libc::IPPROTO_IP && (*cmsg).cmsg_type == libc::IP_RECVERR {
                let err = libc::CMSG_DATA(cmsg) as *const libc::sock_extended_err;
                let e = std::ptr::read_unaligned(err);
                if e.ee_origin == libc::SO_EE_ORIGIN_ICMP && e.ee_type == 11 {
                    let offender = libc::SO_EE_OFFENDER(err) as *const libc::sockaddr_in;
                    let o = std::ptr::read_unaligned(offender);
                    let ip = std::net::Ipv4Addr::from(o.sin_addr.s_addr.to_ne_bytes());
                    return Some((IpAddr::V4(ip), seq));
                }
            }
            cmsg = libc::CMSG_NXTHDR(&msg, cmsg);
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_quoted_echo_is_found_in_a_time_exceeded() {
        // ICMP time exceeded header, then the original IPv4 header, then our echo (seq 1234).
        let mut msg = vec![11, 0, 0, 0, 0, 0, 0, 0];
        msg.extend_from_slice(&[
            0x45, 0, 0, 36, 0, 0, 0, 0, 1, 1, 0, 0, 10, 0, 0, 2, 1, 1, 1, 1,
        ]);
        msg.extend_from_slice(&crate::ping::echo_request(false, 9, 1234, &[])[..8]);
        assert_eq!(quoted_sequence(&msg), Some(1234));
        assert_eq!(quoted_sequence(&msg[..20]), None, "cut short");
    }
}
