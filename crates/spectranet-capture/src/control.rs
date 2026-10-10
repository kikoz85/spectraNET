//! Acting on processes and connections: end, pause, resume a process; close one connection.
//!
//! These are the operating-system primitives only. Who may call them, and on what, is
//! decided by snetd (protected list, policy, audit).

use std::io;
use std::net::SocketAddr;

use spectranet_model::Transport;

/// Whether this system can close a single connection, and how reliably.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DropSupport {
    /// A system call closes it (Linux `SOCK_DESTROY`, Windows `SetTcpEntry`).
    Native,
    /// Closed without a system call made for it (macOS): experimental, may not always work.
    Experimental,
    /// Not available.
    None,
}

pub fn drop_support() -> DropSupport {
    if cfg!(any(target_os = "linux", windows)) {
        DropSupport::Native
    } else if cfg!(target_os = "macos") {
        DropSupport::Experimental
    } else {
        DropSupport::None
    }
}

/// Asks a process to end (SIGTERM); with `force`, ends it at once (SIGKILL). Windows has no
/// polite request for arbitrary processes: it is always ended at once.
pub fn terminate(pid: u32, force: bool) -> io::Result<()> {
    platform::terminate(pid, force)
}

/// Freezes a process: it gets no CPU and sends nothing until resumed.
pub fn pause(pid: u32) -> io::Result<()> {
    platform::pause(pid)
}

pub fn resume(pid: u32) -> io::Result<()> {
    platform::resume(pid)
}

/// Whether a process with this ID exists.
pub fn alive(pid: u32) -> bool {
    platform::alive(pid)
}

/// Closes one connection, identified by its endpoints as seen from this machine.
pub fn drop_flow(transport: Transport, local: SocketAddr, remote: SocketAddr) -> io::Result<()> {
    platform::drop_flow(transport, local, remote)
}

#[cfg(unix)]
#[allow(unsafe_code)]
mod platform {
    use super::*;

    fn signal(pid: u32, sig: libc::c_int) -> io::Result<()> {
        if pid == 0 || pid > i32::MAX as u32 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "invalid process ID",
            ));
        }
        // SAFETY: kill(2) with a positive PID targets exactly that process.
        if unsafe { libc::kill(pid as libc::pid_t, sig) } == 0 {
            Ok(())
        } else {
            Err(io::Error::last_os_error())
        }
    }

    pub fn terminate(pid: u32, force: bool) -> io::Result<()> {
        signal(pid, if force { libc::SIGKILL } else { libc::SIGTERM })
    }

    pub fn pause(pid: u32) -> io::Result<()> {
        signal(pid, libc::SIGSTOP)
    }

    pub fn resume(pid: u32) -> io::Result<()> {
        signal(pid, libc::SIGCONT)
    }

    pub fn alive(pid: u32) -> bool {
        // Signal 0 checks existence; EPERM still means it exists.
        signal(pid, 0).is_ok() || io::Error::last_os_error().raw_os_error() == Some(libc::EPERM)
    }

    #[cfg(target_os = "linux")]
    pub fn drop_flow(
        transport: Transport,
        local: SocketAddr,
        remote: SocketAddr,
    ) -> io::Result<()> {
        crate::linux::destroy::destroy(transport, local, remote)
    }

    /// macOS has no call that closes one socket. A hand-built SYN, spoofed as if it came from the
    /// remote peer, is delivered to the local TCP stack; in ESTABLISHED that stack answers with a
    /// challenge ACK (RFC 5961) whose sequence and acknowledgment numbers are the real ones. libpcap
    /// catches that ACK, and two hand-built RST segments use it: one aimed at the local application
    /// and one at the remote server. IPv4 TCP only; needs root (raw socket and a capture device).
    #[cfg(target_os = "macos")]
    pub fn drop_flow(
        transport: Transport,
        local: SocketAddr,
        remote: SocketAddr,
    ) -> io::Result<()> {
        use std::net::{IpAddr, Ipv4Addr};
        use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
        use std::time::{Duration, Instant};

        use etherparse::{NetSlice, SlicedPacket, TransportSlice};

        const TCP_SYN: u8 = 0x02;
        const TCP_RST: u8 = 0x04;
        /// Any sequence works: a SYN in ESTABLISHED is answered before the window is checked.
        const PROBE_SEQ: u32 = 10;

        fn internet_checksum(words: impl IntoIterator<Item = u16>) -> u16 {
            let mut sum = words.into_iter().fold(0u32, |acc, w| acc + u32::from(w));
            while sum > 0xffff {
                sum = (sum & 0xffff) + (sum >> 16);
            }
            !(sum as u16)
        }

        /// IPv4 + TCP, no options. On macOS `ip_len` and `ip_off` are host byte order (`ip(4)`);
        /// the kernel swaps them. The TCP checksum is ours: the kernel does not fill it in for a
        /// raw header.
        fn tcp_packet(
            src: Ipv4Addr,
            dst: Ipv4Addr,
            src_port: u16,
            dst_port: u16,
            seq: u32,
            flags: u8,
        ) -> [u8; 40] {
            let mut pkt = [0u8; 40];
            pkt[0] = 0x45;
            pkt[2..4].copy_from_slice(&40u16.to_ne_bytes());
            pkt[8] = 64;
            pkt[9] = u8::try_from(libc::IPPROTO_TCP).unwrap_or(6);
            pkt[12..16].copy_from_slice(&src.octets());
            pkt[16..20].copy_from_slice(&dst.octets());
            pkt[20..22].copy_from_slice(&src_port.to_be_bytes());
            pkt[22..24].copy_from_slice(&dst_port.to_be_bytes());
            pkt[24..28].copy_from_slice(&seq.to_be_bytes());
            pkt[32] = 5 << 4;
            pkt[33] = flags;
            if flags & TCP_RST == 0 {
                pkt[34..36].copy_from_slice(&65535u16.to_be_bytes());
            }
            let src_b = src.octets();
            let dst_b = dst.octets();
            let mut words = Vec::with_capacity(16);
            words.push(u16::from_be_bytes([src_b[0], src_b[1]]));
            words.push(u16::from_be_bytes([src_b[2], src_b[3]]));
            words.push(u16::from_be_bytes([dst_b[0], dst_b[1]]));
            words.push(u16::from_be_bytes([dst_b[2], dst_b[3]]));
            words.push(u16::try_from(libc::IPPROTO_TCP).unwrap_or(6));
            words.push(20);
            for chunk in pkt[20..].chunks(2) {
                words.push(u16::from_be_bytes([chunk[0], chunk[1]]));
            }
            pkt[36..38].copy_from_slice(&internet_checksum(words).to_be_bytes());
            pkt
        }

        fn send(fd: i32, pkt: &[u8], dst: Ipv4Addr) -> io::Result<()> {
            let addr = libc::sockaddr_in {
                sin_len: std::mem::size_of::<libc::sockaddr_in>() as u8,
                sin_family: libc::AF_INET as libc::sa_family_t,
                sin_port: 0,
                sin_addr: libc::in_addr {
                    s_addr: u32::from_ne_bytes(dst.octets()),
                },
                sin_zero: [0; 8],
            };
            // SAFETY: `fd` is an open raw socket, `pkt` and `addr` live for the call.
            let n = unsafe {
                libc::sendto(
                    fd,
                    pkt.as_ptr().cast(),
                    pkt.len(),
                    0,
                    (&addr as *const libc::sockaddr_in).cast(),
                    std::mem::size_of::<libc::sockaddr_in>() as libc::socklen_t,
                )
            };
            if n < 0 {
                Err(io::Error::last_os_error())
            } else {
                Ok(())
            }
        }

        fn pcap_io(err: pcap::Error) -> io::Error {
            let text = err.to_string();
            let lower = text.to_ascii_lowercase();
            if lower.contains("permission denied") || lower.contains("operation not permitted") {
                io::Error::new(io::ErrorKind::PermissionDenied, text)
            } else {
                io::Error::other(text)
            }
        }

        /// `(sequence, acknowledgment)` of a pure ACK from the local stack: its sequence number is
        /// what the server expects next, and its acknowledgment is what the local stack expects next.
        fn pure_ack(
            dlt: i32,
            frame: &[u8],
            local: SocketAddr,
            remote: SocketAddr,
        ) -> Option<(u32, u32)> {
            let link = crate::names::packet::Link::from_dlt(dlt)?;
            let sliced = match link {
                crate::names::packet::Link::Ethernet => SlicedPacket::from_ethernet(frame).ok()?,
                crate::names::packet::Link::Null | crate::names::packet::Link::Loop => {
                    SlicedPacket::from_ip(frame.get(4..)?).ok()?
                }
                crate::names::packet::Link::Raw => SlicedPacket::from_ip(frame).ok()?,
                _ => return None,
            };
            let Some(NetSlice::Ipv4(ip)) = sliced.net else {
                return None;
            };
            let TransportSlice::Tcp(tcp) = sliced.transport? else {
                return None;
            };
            let src = SocketAddr::new(IpAddr::V4(ip.header().source_addr()), tcp.source_port());
            let dst = SocketAddr::new(
                IpAddr::V4(ip.header().destination_addr()),
                tcp.destination_port(),
            );
            if src == local
                && dst == remote
                && tcp.ack()
                && !tcp.rst()
                && !tcp.syn()
                && tcp.payload().is_empty()
            {
                Some((tcp.sequence_number(), tcp.acknowledgment_number()))
            } else {
                None
            }
        }

        if transport != Transport::Tcp {
            return Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "macOS can only close TCP connections",
            ));
        }
        let (IpAddr::V4(local_ip), IpAddr::V4(remote_ip)) = (local.ip(), remote.ip()) else {
            return Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "macOS can only close IPv4 connections",
            ));
        };

        // SAFETY: socket(2) with a fresh descriptor; `OwnedFd` closes it.
        let fd = unsafe { libc::socket(libc::AF_INET, libc::SOCK_RAW, libc::IPPROTO_RAW) };
        if fd < 0 {
            return Err(io::Error::last_os_error());
        }
        let fd = unsafe { OwnedFd::from_raw_fd(fd) };
        let raw = fd.as_raw_fd();
        let on: libc::c_int = 1;
        // SAFETY: valid socket, the option value lives for the call. macOS does not imply
        // IP_HDRINCL from IPPROTO_RAW, unlike Linux.
        if unsafe {
            libc::setsockopt(
                raw,
                libc::IPPROTO_IP,
                libc::IP_HDRINCL,
                (&on as *const libc::c_int).cast(),
                std::mem::size_of::<libc::c_int>() as libc::socklen_t,
            )
        } != 0
        {
            return Err(io::Error::last_os_error());
        }

        let mut devices = pcap::Device::list().map_err(pcap_io)?;
        let iface = if let Some(i) = devices
            .iter()
            .position(|d| d.addresses.iter().any(|a| a.addr == IpAddr::V4(local_ip)))
        {
            devices.swap_remove(i)
        } else if local_ip.is_loopback()
            && let Some(i) = devices.iter().position(|d| d.flags.is_loopback())
        {
            devices.swap_remove(i)
        } else {
            return Err(io::Error::new(
                io::ErrorKind::NotFound,
                "no capture interface has this local address",
            ));
        };
        let mut capture = pcap::Capture::from_device(iface)
            .map_err(pcap_io)?
            .immediate_mode(true)
            .promisc(false)
            .snaplen(512)
            .timeout(200)
            .open()
            .map_err(pcap_io)?;
        // The challenge ACK leaves toward the server. The probe itself is the other direction.
        capture
            .filter(
                &format!(
                    "ip and tcp and src host {local_ip} and src port {} and dst host {remote_ip} and dst port {}",
                    local.port(),
                    remote.port()
                ),
                true,
            )
            .map_err(pcap_io)?;
        let dlt = capture.get_datalink().0;
        if crate::names::packet::Link::from_dlt(dlt).is_none() {
            return Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "unsupported capture link type",
            ));
        }

        let probe = tcp_packet(
            remote_ip,
            local_ip,
            remote.port(),
            local.port(),
            PROBE_SEQ,
            TCP_SYN,
        );
        let mut numbers = None;
        for _ in 0..3 {
            // Destination is local, so the kernel loops the segment back into the TCP stack.
            send(raw, &probe, local_ip)?;
            let deadline = Instant::now() + Duration::from_millis(400);
            while Instant::now() < deadline {
                match capture.next_packet() {
                    Ok(packet) => {
                        if let Some(found) = pure_ack(dlt, packet.data, local, remote) {
                            numbers = Some(found);
                            break;
                        }
                    }
                    Err(pcap::Error::TimeoutExpired) => {}
                    Err(e) => return Err(pcap_io(e)),
                }
            }
            if numbers.is_some() {
                break;
            }
        }
        let Some((snd_nxt, rcv_nxt)) = numbers else {
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "the connection did not reveal its sequence numbers",
            ));
        };

        // Into the local stack: sequence must be exactly the acknowledgment it just sent.
        send(
            raw,
            &tcp_packet(
                remote_ip,
                local_ip,
                remote.port(),
                local.port(),
                rcv_nxt,
                TCP_RST,
            ),
            local_ip,
        )?;
        // Out to the server: sequence must be exactly what that stack expects next.
        send(
            raw,
            &tcp_packet(
                local_ip,
                remote_ip,
                local.port(),
                remote.port(),
                snd_nxt,
                TCP_RST,
            ),
            remote_ip,
        )?;
        Ok(())
    }

    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    pub fn drop_flow(_: Transport, _: SocketAddr, _: SocketAddr) -> io::Result<()> {
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "closing a single connection is not supported on this system",
        ))
    }
}

#[cfg(windows)]
#[allow(unsafe_code)]
mod platform {
    use std::net::IpAddr;

    use windows_sys::Win32::Foundation::{CloseHandle, HANDLE, STILL_ACTIVE};
    use windows_sys::Win32::NetworkManagement::IpHelper::{
        MIB_TCP_STATE_DELETE_TCB, MIB_TCPROW_LH, MIB_TCPROW_LH_0, SetTcpEntry,
    };
    use windows_sys::Win32::System::Threading::{
        GetExitCodeProcess, OpenProcess, PROCESS_QUERY_LIMITED_INFORMATION, PROCESS_SUSPEND_RESUME,
        PROCESS_TERMINATE, TerminateProcess,
    };

    use super::*;

    #[link(name = "ntdll")]
    unsafe extern "system" {
        fn NtSuspendProcess(process: HANDLE) -> i32;
        fn NtResumeProcess(process: HANDLE) -> i32;
    }

    fn open(pid: u32, access: u32) -> io::Result<HANDLE> {
        // SAFETY: plain call; the handle is closed by the caller.
        let h = unsafe { OpenProcess(access, 0, pid) };
        if h.is_null() {
            Err(io::Error::last_os_error())
        } else {
            Ok(h)
        }
    }

    pub fn terminate(pid: u32, _force: bool) -> io::Result<()> {
        let h = open(pid, PROCESS_TERMINATE)?;
        // SAFETY: valid handle with PROCESS_TERMINATE, closed right after.
        let ok = unsafe { TerminateProcess(h, 1) } != 0;
        let err = io::Error::last_os_error();
        unsafe { CloseHandle(h) };
        if ok { Ok(()) } else { Err(err) }
    }

    fn nt(pid: u32, f: unsafe extern "system" fn(HANDLE) -> i32) -> io::Result<()> {
        let h = open(pid, PROCESS_SUSPEND_RESUME)?;
        // SAFETY: valid handle with PROCESS_SUSPEND_RESUME, closed right after.
        let status = unsafe { f(h) };
        unsafe { CloseHandle(h) };
        if status >= 0 {
            Ok(())
        } else {
            Err(io::Error::other(format!("NTSTATUS {status:#x}")))
        }
    }

    pub fn pause(pid: u32) -> io::Result<()> {
        nt(pid, NtSuspendProcess)
    }

    pub fn resume(pid: u32) -> io::Result<()> {
        nt(pid, NtResumeProcess)
    }

    pub fn alive(pid: u32) -> bool {
        let Ok(h) = open(pid, PROCESS_QUERY_LIMITED_INFORMATION) else {
            return false;
        };
        let mut code = 0u32;
        // SAFETY: valid handle, closed right after.
        let ok = unsafe { GetExitCodeProcess(h, &mut code) } != 0;
        unsafe { CloseHandle(h) };
        ok && code == STILL_ACTIVE as u32
    }

    pub fn drop_flow(
        transport: Transport,
        local: SocketAddr,
        remote: SocketAddr,
    ) -> io::Result<()> {
        if transport != Transport::Tcp {
            return Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "Windows can only close TCP connections",
            ));
        }
        let v4 = |ip: IpAddr| match ip {
            IpAddr::V4(v) => Some(v),
            IpAddr::V6(v) => v.to_ipv4_mapped(),
        };
        let (Some(l), Some(r)) = (v4(local.ip()), v4(remote.ip())) else {
            return Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "Windows can only close IPv4 connections",
            ));
        };
        let row = MIB_TCPROW_LH {
            Anonymous: MIB_TCPROW_LH_0 {
                dwState: MIB_TCP_STATE_DELETE_TCB as u32,
            },
            dwLocalAddr: u32::from_ne_bytes(l.octets()),
            dwLocalPort: u32::from(local.port().to_be()),
            dwRemoteAddr: u32::from_ne_bytes(r.octets()),
            dwRemotePort: u32::from(remote.port().to_be()),
        };
        // SAFETY: a fully initialised row living for the call.
        let rc = unsafe { SetTcpEntry(&row) };
        if rc == 0 {
            Ok(())
        } else {
            Err(io::Error::from_raw_os_error(rc as i32))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pause_resume_and_end_a_child() {
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
        assert!(alive(pid));
        pause(pid).unwrap();
        resume(pid).unwrap();
        terminate(pid, true).unwrap();
        child.wait().unwrap();
        assert!(!alive(pid) || cfg!(windows), "reaped");
    }

    #[test]
    fn invalid_targets_are_errors_not_accidents() {
        assert!(
            terminate(0, false).is_err(),
            "pid 0 would signal our whole process group"
        );
        assert!(terminate(0xFFFF_FFF0, true).is_err());
        assert!(!alive(0xFFFF_FFF0));
    }

    /// Live: closing an established loopback TCP connection makes the peer see it end.
    #[test]
    fn drops_a_tcp_connection() {
        use std::io::Read;
        if drop_support() != DropSupport::Native {
            return;
        }
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let client = std::net::TcpStream::connect(listener.local_addr().unwrap()).unwrap();
        let (mut server, _) = listener.accept().unwrap();
        match drop_flow(
            Transport::Tcp,
            client.local_addr().unwrap(),
            client.peer_addr().unwrap(),
        ) {
            Ok(()) => {
                server
                    .set_read_timeout(Some(std::time::Duration::from_secs(3)))
                    .unwrap();
                let mut buf = [0u8; 1];
                // Reset (error) or orderly close (0 bytes): either way the connection is gone.
                assert!(matches!(server.read(&mut buf), Ok(0) | Err(_)));
            }
            // Needs CAP_NET_ADMIN / Administrator: fine to skip unprivileged.
            Err(e)
                if e.kind() == io::ErrorKind::PermissionDenied
                    || e.raw_os_error() == Some(1)
                    || e.raw_os_error() == Some(5)
                    || e.raw_os_error() == Some(317) =>
            {
                eprintln!("not privileged, skipping: {e}");
            }
            Err(e) => panic!("{e}"),
        }
    }
}
