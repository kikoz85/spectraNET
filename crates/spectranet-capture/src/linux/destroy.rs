//! Closing one socket with netlink `SOCK_DESTROY` (what `ss -K` does). Needs
//! CAP_NET_ADMIN and a kernel built with CONFIG_INET_DIAG_DESTROY (every major distribution).

use std::io;
use std::net::{IpAddr, SocketAddr};

use spectranet_model::Transport;

const NETLINK_SOCK_DIAG: i32 = 4;
const SOCK_DESTROY: u16 = 21;
const NLM_F_REQUEST: u16 = 0x1;
const NLM_F_ACK: u16 = 0x4;
const NLMSG_ERROR: u16 = 2;

/// The `SOCK_DESTROY` request for one socket: nlmsghdr + inet_diag_req_v2 with an exact id.
pub(crate) fn build_request(
    transport: Transport,
    local: SocketAddr,
    remote: SocketAddr,
) -> Vec<u8> {
    let (family, src, dst) = match (local.ip(), remote.ip()) {
        (IpAddr::V4(l), IpAddr::V4(r)) => {
            let mut s = [0u8; 16];
            let mut d = [0u8; 16];
            s[..4].copy_from_slice(&l.octets());
            d[..4].copy_from_slice(&r.octets());
            (libc::AF_INET as u8, s, d)
        }
        (l, r) => {
            let six = |ip: IpAddr| match ip {
                IpAddr::V6(v) => v.octets(),
                IpAddr::V4(v) => v.to_ipv6_mapped().octets(),
            };
            (libc::AF_INET6 as u8, six(l), six(r))
        }
    };
    let protocol: u8 = match transport {
        Transport::Tcp => libc::IPPROTO_TCP as u8,
        Transport::Udp => libc::IPPROTO_UDP as u8,
    };
    let len: u32 = 16 + 56;
    let mut msg = Vec::with_capacity(len as usize);
    msg.extend_from_slice(&len.to_ne_bytes());
    msg.extend_from_slice(&SOCK_DESTROY.to_ne_bytes());
    msg.extend_from_slice(&(NLM_F_REQUEST | NLM_F_ACK).to_ne_bytes());
    msg.extend_from_slice(&1u32.to_ne_bytes()); // seq
    msg.extend_from_slice(&0u32.to_ne_bytes()); // pid
    msg.push(family);
    msg.push(protocol);
    msg.push(0); // ext
    msg.push(0); // pad
    msg.extend_from_slice(&u32::MAX.to_ne_bytes()); // any state
    msg.extend_from_slice(&local.port().to_be_bytes());
    msg.extend_from_slice(&remote.port().to_be_bytes());
    msg.extend_from_slice(&src);
    msg.extend_from_slice(&dst);
    msg.extend_from_slice(&0u32.to_ne_bytes()); // any interface
    msg.extend_from_slice(&u32::MAX.to_ne_bytes()); // INET_DIAG_NOCOOKIE
    msg.extend_from_slice(&u32::MAX.to_ne_bytes());
    msg
}

#[allow(unsafe_code)]
pub(crate) fn destroy(
    transport: Transport,
    local: SocketAddr,
    remote: SocketAddr,
) -> io::Result<()> {
    // SAFETY: plain socket creation; closed by OwnedFd.
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
    // SAFETY: fresh descriptor we own.
    let fd = unsafe { <std::os::fd::OwnedFd as std::os::fd::FromRawFd>::from_raw_fd(fd) };
    let raw = std::os::fd::AsRawFd::as_raw_fd(&fd);
    let timeout = libc::timeval {
        tv_sec: 2,
        tv_usec: 0,
    };
    // SAFETY: valid fd, correctly sized option.
    unsafe {
        libc::setsockopt(
            raw,
            libc::SOL_SOCKET,
            libc::SO_RCVTIMEO,
            (&timeout as *const libc::timeval).cast(),
            std::mem::size_of::<libc::timeval>() as u32,
        );
    }
    let request = build_request(transport, local, remote);
    // SAFETY: buffer valid for its length.
    if unsafe { libc::send(raw, request.as_ptr().cast(), request.len(), 0) } < 0 {
        return Err(io::Error::last_os_error());
    }
    let mut buf = [0u8; 4096];
    // SAFETY: writable buffer of its length.
    let n = unsafe { libc::recv(raw, buf.as_mut_ptr().cast(), buf.len(), 0) };
    if n < 0 {
        return Err(io::Error::last_os_error());
    }
    let n = n as usize;
    if n >= 20 && u16::from_ne_bytes([buf[4], buf[5]]) == NLMSG_ERROR {
        let code = i32::from_ne_bytes(buf[16..20].try_into().unwrap());
        return match code {
            0 => Ok(()),
            // ENOENT: no such socket (already closed, or a typo in the endpoints).
            c => Err(io::Error::from_raw_os_error(-c)),
        };
    }
    Err(io::Error::other("unexpected netlink reply"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn request_layout_matches_the_kernel_abi() {
        let msg = build_request(
            Transport::Tcp,
            "10.0.0.2:50000".parse().unwrap(),
            "1.2.3.4:443".parse().unwrap(),
        );
        assert_eq!(msg.len(), 72);
        assert_eq!(u16::from_ne_bytes([msg[4], msg[5]]), SOCK_DESTROY);
        assert_eq!(msg[16], libc::AF_INET as u8);
        assert_eq!(msg[17], libc::IPPROTO_TCP as u8);
        assert_eq!(
            &msg[24..26],
            &50000u16.to_be_bytes(),
            "source port, network order"
        );
        assert_eq!(&msg[26..28], &443u16.to_be_bytes());
        assert_eq!(&msg[28..32], &[10, 0, 0, 2]);
        assert_eq!(&msg[44..48], &[1, 2, 3, 4]);
        let v6 = build_request(
            Transport::Udp,
            "[::1]:1".parse().unwrap(),
            "[::1]:2".parse().unwrap(),
        );
        assert_eq!(v6[16], libc::AF_INET6 as u8);
        assert_eq!(v6[17], libc::IPPROTO_UDP as u8);
    }
}
