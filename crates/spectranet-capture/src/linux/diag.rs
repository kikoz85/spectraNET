//! TCP connection table from the kernel via netlink `sock_diag` (what ss(8) uses), with
//! lifetime byte counters from `tcp_info`, and the owning process of each socket.
//!
//! The eBPF probe only knows sockets that moved data since it was attached; this table adds
//! idle connections and gives every TCP connection its total since it was opened.

use std::collections::HashMap;
use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::time::{Duration, Instant};

const NETLINK_SOCK_DIAG: i32 = 4;
const SOCK_DIAG_BY_FAMILY: u16 = 20;
const NLM_F_REQUEST: u16 = 0x1;
const NLM_F_DUMP: u16 = 0x300;
const NLMSG_DONE: u16 = 3;
const NLMSG_ERROR: u16 = 2;
const INET_DIAG_INFO: u16 = 2;
const IPPROTO_TCP: u8 = 6;
const TCP_LISTEN: u8 = 10;
/// Offsets in `struct tcp_info` (include/uapi/linux/tcp.h, stable ABI).
const TCPI_BYTES_ACKED: usize = 120;
const TCPI_BYTES_RECEIVED: usize = 128;

/// One TCP connection as the kernel reports it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TcpConn {
    pub local: SocketAddr,
    pub remote: SocketAddr,
    pub state: u8,
    pub inode: u32,
    /// Bytes sent and acknowledged since the connection opened (data only).
    pub bytes_acked: u64,
    /// Bytes received since the connection opened.
    pub bytes_received: u64,
}

/// Every TCP socket except listeners, IPv4 and IPv6.
pub fn tcp_connections() -> io::Result<Vec<TcpConn>> {
    let mut all = dump(libc::AF_INET as u8)?;
    all.extend(dump(libc::AF_INET6 as u8)?);
    Ok(all)
}

#[allow(unsafe_code)]
fn dump(family: u8) -> io::Result<Vec<TcpConn>> {
    // SAFETY: plain socket creation; the fd is closed by OwnedFd.
    let fd = unsafe {
        libc::socket(
            libc::AF_NETLINK,
            libc::SOCK_DGRAM | libc::SOCK_CLOEXEC,
            NETLINK_SOCK_DIAG,
        )
    };
    if fd < 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: fd is a fresh, valid descriptor we own.
    let fd = unsafe { <std::os::fd::OwnedFd as std::os::fd::FromRawFd>::from_raw_fd(fd) };
    let raw = std::os::fd::AsRawFd::as_raw_fd(&fd);
    let timeout = libc::timeval {
        tv_sec: 2,
        tv_usec: 0,
    };
    // SAFETY: valid fd and a correctly sized option value.
    unsafe {
        libc::setsockopt(
            raw,
            libc::SOL_SOCKET,
            libc::SO_RCVTIMEO,
            (&timeout as *const libc::timeval).cast(),
            std::mem::size_of::<libc::timeval>() as u32,
        );
    }

    let request = build_request(family);
    // SAFETY: the buffer is valid for its length; the kernel is the implicit destination.
    if unsafe { libc::send(raw, request.as_ptr().cast(), request.len(), 0) } < 0 {
        return Err(io::Error::last_os_error());
    }
    let mut out = Vec::new();
    let mut buf = vec![0u8; 64 * 1024];
    loop {
        // SAFETY: the buffer is valid and writable for its length.
        let n = unsafe { libc::recv(raw, buf.as_mut_ptr().cast(), buf.len(), 0) };
        if n < 0 {
            return Err(io::Error::last_os_error());
        }
        if n == 0 {
            return Ok(out);
        }
        match parse_messages(&buf[..n as usize], &mut out) {
            Parsed::More => continue,
            Parsed::Done => return Ok(out),
            Parsed::Error(code) => return Err(io::Error::from_raw_os_error(code)),
        }
    }
}

fn build_request(family: u8) -> Vec<u8> {
    // nlmsghdr (16) + inet_diag_req_v2 (56)
    let len: u32 = 16 + 56;
    let mut msg = Vec::with_capacity(len as usize);
    msg.extend_from_slice(&len.to_ne_bytes());
    msg.extend_from_slice(&SOCK_DIAG_BY_FAMILY.to_ne_bytes());
    msg.extend_from_slice(&(NLM_F_REQUEST | NLM_F_DUMP).to_ne_bytes());
    msg.extend_from_slice(&1u32.to_ne_bytes()); // seq
    msg.extend_from_slice(&0u32.to_ne_bytes()); // pid
    msg.push(family);
    msg.push(IPPROTO_TCP);
    msg.push(1 << (INET_DIAG_INFO - 1)); // ext: ask for tcp_info
    msg.push(0); // pad
    let states: u32 = !(1 << TCP_LISTEN);
    msg.extend_from_slice(&states.to_ne_bytes());
    msg.extend_from_slice(&[0u8; 48]); // inet_diag_sockid: wildcard
    msg
}

enum Parsed {
    More,
    Done,
    Error(i32),
}

/// Parses a datagram of netlink messages, appending connections to `out`.
fn parse_messages(mut buf: &[u8], out: &mut Vec<TcpConn>) -> Parsed {
    while buf.len() >= 16 {
        let len = u32::from_ne_bytes(buf[0..4].try_into().unwrap()) as usize;
        let kind = u16::from_ne_bytes(buf[4..6].try_into().unwrap());
        if len < 16 || len > buf.len() {
            return Parsed::Done; // malformed: stop rather than misread
        }
        let body = &buf[16..len];
        match kind {
            NLMSG_DONE => return Parsed::Done,
            NLMSG_ERROR => {
                let code = body
                    .get(0..4)
                    .map_or(0, |b| i32::from_ne_bytes(b.try_into().unwrap()));
                return if code == 0 {
                    Parsed::Done
                } else {
                    Parsed::Error(-code)
                };
            }
            SOCK_DIAG_BY_FAMILY => {
                if let Some(conn) = parse_diag_msg(body) {
                    out.push(conn);
                }
            }
            _ => {}
        }
        buf = &buf[align4(len).min(buf.len())..];
    }
    Parsed::More
}

fn align4(n: usize) -> usize {
    (n + 3) & !3
}

/// `struct inet_diag_msg` (72 bytes) followed by attributes.
fn parse_diag_msg(body: &[u8]) -> Option<TcpConn> {
    let family = *body.first()?;
    let state = *body.get(1)?;
    let sport = u16::from_be_bytes([*body.get(4)?, *body.get(5)?]);
    let dport = u16::from_be_bytes([*body.get(6)?, *body.get(7)?]);
    let src: [u8; 16] = body.get(8..24)?.try_into().ok()?;
    let dst: [u8; 16] = body.get(24..40)?.try_into().ok()?;
    let inode = u32::from_ne_bytes(body.get(68..72)?.try_into().ok()?);
    let ip = |raw: [u8; 16]| -> Option<IpAddr> {
        match i32::from(family) {
            libc::AF_INET => Some(IpAddr::V4(Ipv4Addr::new(raw[0], raw[1], raw[2], raw[3]))),
            libc::AF_INET6 => {
                let v6 = Ipv6Addr::from(raw);
                Some(v6.to_ipv4_mapped().map_or(IpAddr::V6(v6), IpAddr::V4))
            }
            _ => None,
        }
    };
    let (mut acked, mut received) = (0, 0);
    let mut attrs = body.get(72..).unwrap_or(&[]);
    while attrs.len() >= 4 {
        let len = usize::from(u16::from_ne_bytes([attrs[0], attrs[1]]));
        let kind = u16::from_ne_bytes([attrs[2], attrs[3]]);
        if len < 4 || len > attrs.len() {
            break;
        }
        if kind == INET_DIAG_INFO {
            let info = &attrs[4..len];
            let field = |at: usize| {
                info.get(at..at + 8)
                    .map_or(0, |b| u64::from_ne_bytes(b.try_into().unwrap()))
            };
            // The kernel counts the SYN as one acknowledged byte; report data only.
            acked = field(TCPI_BYTES_ACKED).saturating_sub(1);
            received = field(TCPI_BYTES_RECEIVED);
        }
        attrs = &attrs[align4(len).min(attrs.len())..];
    }
    Some(TcpConn {
        local: SocketAddr::new(ip(src)?, sport),
        remote: SocketAddr::new(ip(dst)?, dport),
        state,
        inode,
        bytes_acked: acked,
        bytes_received: received,
    })
}

/// Maps socket inodes to the process holding them, by scanning /proc/<pid>/fd. Rescanned
/// at most every `min_interval`, and only when an unknown inode is asked for.
pub struct InodeOwners {
    owners: HashMap<u32, u32>,
    scanned: Option<Instant>,
    min_interval: Duration,
}

impl InodeOwners {
    pub fn new(min_interval: Duration) -> Self {
        Self {
            owners: HashMap::new(),
            scanned: None,
            min_interval,
        }
    }

    pub fn owner(&mut self, inode: u32) -> Option<u32> {
        if inode == 0 {
            return None;
        }
        if !self.owners.contains_key(&inode)
            && self
                .scanned
                .is_none_or(|t| t.elapsed() >= self.min_interval)
        {
            self.owners = scan();
            self.scanned = Some(Instant::now());
        }
        self.owners.get(&inode).copied()
    }
}

fn scan() -> HashMap<u32, u32> {
    let mut owners = HashMap::new();
    let Ok(procs) = std::fs::read_dir("/proc") else {
        return owners;
    };
    for entry in procs.flatten() {
        let Some(pid) = entry
            .file_name()
            .to_str()
            .and_then(|n| n.parse::<u32>().ok())
        else {
            continue;
        };
        let Ok(fds) = std::fs::read_dir(entry.path().join("fd")) else {
            continue;
        };
        for fd in fds.flatten() {
            if let Some(inode) = std::fs::read_link(fd.path()).ok().and_then(|target| {
                target
                    .to_str()?
                    .strip_prefix("socket:[")?
                    .strip_suffix(']')?
                    .parse()
                    .ok()
            }) {
                owners.entry(inode).or_insert(pid);
            }
        }
    }
    owners
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{Read, Write};
    use std::net::{TcpListener, TcpStream};

    #[test]
    fn request_layout() {
        let req = build_request(libc::AF_INET as u8);
        assert_eq!(req.len(), 72);
        assert_eq!(u32::from_ne_bytes(req[0..4].try_into().unwrap()), 72);
        assert_eq!(req[16], libc::AF_INET as u8);
        assert_eq!(req[17], IPPROTO_TCP);
    }

    #[test]
    fn malformed_messages_do_not_panic() {
        let mut out = Vec::new();
        for junk in [
            &[][..],
            &[0xFF; 15],
            &[0xFF; 40],
            &[16, 0, 0, 0, 20, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
        ] {
            let _ = parse_messages(junk, &mut out);
        }
        assert!(parse_diag_msg(&[2, 1, 0, 0]).is_none());
    }

    /// Real kernel: our own connection is listed with the bytes we moved, and owned by us.
    #[test]
    fn lists_own_connection_with_lifetime_counters() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let mut client = TcpStream::connect(addr).unwrap();
        let (mut server, _) = listener.accept().unwrap();
        client.write_all(&[5u8; 123_456]).unwrap();
        let mut sink = vec![0u8; 123_456];
        server.read_exact(&mut sink).unwrap();
        std::thread::sleep(Duration::from_millis(50));

        let conns = tcp_connections().unwrap();
        let mine = conns
            .iter()
            .find(|c| c.remote == addr && c.local == client.local_addr().unwrap())
            .expect("client listed");
        assert_eq!(mine.bytes_acked, 123_456, "{mine:?}");
        let other = conns
            .iter()
            .find(|c| c.local == addr)
            .expect("server side listed");
        assert_eq!(other.bytes_received, 123_456, "{other:?}");
        assert!(
            conns.iter().all(|c| c.state != TCP_LISTEN),
            "listeners excluded"
        );

        let mut owners = InodeOwners::new(Duration::ZERO);
        assert_eq!(owners.owner(mine.inode), Some(std::process::id()));
        assert_eq!(owners.owner(0), None);
    }
}
