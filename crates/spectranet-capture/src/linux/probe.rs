//! Loading the eBPF probe and reading its maps (see ebpf/spectranet.bpf.c).

use aya::maps::{HashMap, MapData, RingBuf};
use aya::programs::{FEntry, FExit};
use aya::{Btf, Ebpf, EbpfLoader};

/// Mirror of `struct sock_info` in the probe. Layout checked by a test.
#[repr(C)]
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct SockInfo {
    pub born_ns: u64,
    pub tx: u64,
    pub rx: u64,
    pub tgid: u32,
    pub family: u16,
    pub sport: u16,
    pub dport: u16,
    pub proto: u8,
    pub pad: [u8; 5],
    pub saddr: [u8; 16],
    pub daddr: [u8; 16],
    pub comm: [u8; 16],
    /// Send and receive calls (UDP: datagrams).
    pub tx_msgs: u32,
    pub rx_msgs: u32,
}

// SAFETY: plain-old-data with explicit padding, no pointers; any bit pattern is valid.
unsafe impl aya::Pod for SockInfo {}

/// Mirror of `struct close_event`.
#[repr(C)]
#[derive(Debug, Clone, Copy)]
struct CloseEvent {
    sk: u64,
    info: SockInfo,
}

const OBJECT: &[u8] = aya::include_bytes_aligned!(concat!(env!("OUT_DIR"), "/spectranet.bpf.o"));

/// Hooks: (program name in the object, kernel function, exit hook?).
const HOOKS: [(&str, &str, bool); 7] = [
    ("tcp_sendmsg_exit", "tcp_sendmsg", true),
    ("tcp_cleanup_rbuf_entry", "tcp_cleanup_rbuf", false),
    ("udp_sendmsg_exit", "udp_sendmsg", true),
    ("udpv6_sendmsg_exit", "udpv6_sendmsg", true),
    ("udp_recvmsg_exit", "udp_recvmsg", true),
    ("udpv6_recvmsg_exit", "udpv6_recvmsg", true),
    ("inet_release_entry", "inet_release", false),
];

/// Why the probe could not be started.
#[derive(Debug)]
pub enum ProbeError {
    PermissionDenied,
    Failed(String),
}

/// The loaded and attached probe. Dropping it detaches everything.
pub struct Probe {
    socks: HashMap<MapData, u64, SockInfo>,
    closed: RingBuf<MapData>,
    // Owns the programs and their attachments; must outlive the maps' usefulness.
    _ebpf: Ebpf,
}

impl Probe {
    pub fn start() -> Result<Self, ProbeError> {
        let btf = Btf::from_sys_fs()
            .map_err(|e| ProbeError::Failed(format!("kernel BTF unavailable: {e}")))?;
        let mut ebpf = EbpfLoader::new()
            .btf(Some(&btf))
            .load(OBJECT)
            .map_err(classify)?;
        for (program, function, exit) in HOOKS {
            let prog = ebpf.program_mut(program).ok_or_else(|| {
                ProbeError::Failed(format!("program {program} missing from probe"))
            })?;
            let result = if exit {
                let p: &mut FExit = prog.try_into().map_err(classify)?;
                p.load(function, &btf).and_then(|()| p.attach().map(drop))
            } else {
                let p: &mut FEntry = prog.try_into().map_err(classify)?;
                p.load(function, &btf).and_then(|()| p.attach().map(drop))
            };
            result.map_err(|e| match classify(e) {
                ProbeError::Failed(m) => {
                    ProbeError::Failed(format!("attaching to {function}: {m}"))
                }
                denied => denied,
            })?;
        }
        let socks = HashMap::try_from(
            ebpf.take_map("socks")
                .ok_or_else(|| ProbeError::Failed("map socks missing".into()))?,
        )
        .map_err(classify)?;
        let closed = RingBuf::try_from(
            ebpf.take_map("closed")
                .ok_or_else(|| ProbeError::Failed("map closed missing".into()))?,
        )
        .map_err(classify)?;
        Ok(Self {
            socks,
            closed,
            _ebpf: ebpf,
        })
    }

    /// Every socket currently tracked.
    pub fn live(&self) -> Vec<(u64, SockInfo)> {
        self.socks.iter().filter_map(Result::ok).collect()
    }

    /// Sockets closed since the last call, with their final counters.
    pub fn drain_closed(&mut self) -> Vec<(u64, SockInfo)> {
        let mut events = Vec::new();
        while let Some(item) = self.closed.next() {
            if item.len() >= std::mem::size_of::<CloseEvent>() {
                // SAFETY: the kernel wrote a `struct close_event` of at least this size;
                // read_unaligned copes with any alignment of the ring buffer slot.
                #[allow(unsafe_code)]
                let event = unsafe { std::ptr::read_unaligned(item.as_ptr().cast::<CloseEvent>()) };
                events.push((event.sk, event.info));
            }
        }
        events
    }
}

fn classify(error: impl std::error::Error) -> ProbeError {
    let mut text = error.to_string();
    let mut source = error.source();
    while let Some(s) = source {
        text.push_str(": ");
        text.push_str(&s.to_string());
        source = s.source();
    }
    if text.contains("Operation not permitted")
        || text.contains("Permission denied")
        || text.contains("EPERM")
    {
        ProbeError::PermissionDenied
    } else {
        ProbeError::Failed(text)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Must match `struct sock_info` / `struct close_event` in the C probe.
    #[test]
    fn layout_matches_the_probe() {
        assert_eq!(std::mem::size_of::<SockInfo>(), 96);
        assert_eq!(std::mem::offset_of!(SockInfo, tx_msgs), 88);
        assert_eq!(std::mem::offset_of!(SockInfo, tgid), 24);
        assert_eq!(std::mem::offset_of!(SockInfo, proto), 34);
        assert_eq!(std::mem::offset_of!(SockInfo, saddr), 40);
        assert_eq!(std::mem::offset_of!(SockInfo, daddr), 56);
        assert_eq!(std::mem::offset_of!(SockInfo, comm), 72);
        assert_eq!(std::mem::size_of::<CloseEvent>(), 104);
    }

    #[test]
    fn object_is_embedded() {
        assert!(OBJECT.starts_with(b"\x7fELF"));
    }
}
