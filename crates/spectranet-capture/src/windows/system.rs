//! Windows API calls: the TCP connection table and process image paths.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

use windows_sys::Win32::Foundation::{CloseHandle, ERROR_INSUFFICIENT_BUFFER, NO_ERROR};
use windows_sys::Win32::NetworkManagement::IpHelper::{
    GetExtendedTcpTable, MIB_TCP6ROW_OWNER_PID, MIB_TCPROW_OWNER_PID, TCP_TABLE_OWNER_PID_ALL,
};
use windows_sys::Win32::Networking::WinSock::{AF_INET, AF_INET6};
use windows_sys::Win32::System::Threading::{
    OpenProcess, PROCESS_NAME_WIN32, PROCESS_QUERY_LIMITED_INFORMATION, QueryFullProcessImageNameW,
};

use super::TcpConn;

/// MIB_TCP_STATE_LISTEN.
const LISTEN: u32 = 2;

/// Port fields hold the port in network byte order in their low 16 bits.
fn port(raw: u32) -> u16 {
    u16::from_be((raw & 0xFFFF) as u16)
}

/// Every IPv4 and IPv6 TCP connection except listeners, with its owning process.
pub fn tcp_connections() -> Vec<TcpConn> {
    let mut out = Vec::new();
    if let Some(buf) = table(AF_INET as u32) {
        for row in rows::<MIB_TCPROW_OWNER_PID>(&buf) {
            if row.dwState == LISTEN {
                continue;
            }
            out.push(TcpConn {
                local: SocketAddr::new(
                    IpAddr::V4(Ipv4Addr::from(row.dwLocalAddr.to_le_bytes())),
                    port(row.dwLocalPort),
                ),
                remote: SocketAddr::new(
                    IpAddr::V4(Ipv4Addr::from(row.dwRemoteAddr.to_le_bytes())),
                    port(row.dwRemotePort),
                ),
                state: row.dwState,
                pid: row.dwOwningPid,
            });
        }
    }
    if let Some(buf) = table(AF_INET6 as u32) {
        for row in rows::<MIB_TCP6ROW_OWNER_PID>(&buf) {
            if row.dwState == LISTEN {
                continue;
            }
            let v6 = |raw: [u8; 16]| {
                let ip = Ipv6Addr::from(raw);
                ip.to_ipv4_mapped().map_or(IpAddr::V6(ip), IpAddr::V4)
            };
            out.push(TcpConn {
                local: SocketAddr::new(v6(row.ucLocalAddr), port(row.dwLocalPort)),
                remote: SocketAddr::new(v6(row.ucRemoteAddr), port(row.dwRemotePort)),
                state: row.dwState,
                pid: row.dwOwningPid,
            });
        }
    }
    out
}

/// Fetches a TCP table, growing the buffer as the API asks (connections come and go between
/// the size query and the read).
fn table(family: u32) -> Option<Vec<u8>> {
    let mut size: u32 = 0;
    for _ in 0..5 {
        let mut buf = vec![0u8; size as usize];
        // SAFETY: the buffer is valid for `size` bytes (or null-sized for the size query).
        let rc = unsafe {
            GetExtendedTcpTable(
                if buf.is_empty() {
                    std::ptr::null_mut()
                } else {
                    buf.as_mut_ptr().cast()
                },
                &mut size,
                0,
                family,
                TCP_TABLE_OWNER_PID_ALL,
                0,
            )
        };
        match rc {
            NO_ERROR => return Some(buf),
            ERROR_INSUFFICIENT_BUFFER => size = size.saturating_add(4096),
            _ => return None,
        }
    }
    None
}

/// Rows of a `MIB_TCP*TABLE_OWNER_PID`: a u32 count followed by the rows (4-byte aligned).
fn rows<T: Copy>(buf: &[u8]) -> Vec<T> {
    let Some(count) = buf
        .get(..4)
        .map(|b| u32::from_ne_bytes(b.try_into().unwrap()) as usize)
    else {
        return Vec::new();
    };
    let size = std::mem::size_of::<T>();
    (0..count)
        .map_while(|i| {
            let start = 4 + i * size;
            let bytes = buf.get(start..start + size)?;
            // SAFETY: `bytes` holds exactly one T as written by the API; read_unaligned copes
            // with any alignment.
            Some(unsafe { std::ptr::read_unaligned(bytes.as_ptr().cast::<T>()) })
        })
        .collect()
}

/// Full path of a process's executable, if it can be queried.
pub fn process_path(pid: u32) -> Option<String> {
    if pid == 0 || pid == 4 {
        return None;
    }
    // SAFETY: OpenProcess returns null on failure; the handle is closed below.
    let handle = unsafe { OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, pid) };
    if handle.is_null() {
        return None;
    }
    let mut buf = vec![0u16; 1024];
    let mut len = buf.len() as u32;
    // SAFETY: valid handle and a buffer of `len` UTF-16 units.
    let ok = unsafe {
        QueryFullProcessImageNameW(handle, PROCESS_NAME_WIN32, buf.as_mut_ptr(), &mut len)
    };
    // SAFETY: the handle came from OpenProcess.
    unsafe { CloseHandle(handle) };
    (ok != 0).then(|| String::from_utf16_lossy(&buf[..len as usize]))
}

/// Whether an ETW trace session with this name is running (EVENT_TRACE_CONTROL_QUERY).
/// Errors other than "not found" count as running: the watchdog must not restart a healthy
/// session because of a transient failure.
pub fn trace_session_exists(name: &str) -> bool {
    use windows_sys::Win32::Foundation::ERROR_WMI_INSTANCE_NOT_FOUND;
    use windows_sys::Win32::System::Diagnostics::Etw::{
        CONTROLTRACE_HANDLE, ControlTraceW, EVENT_TRACE_CONTROL_QUERY, EVENT_TRACE_PROPERTIES,
    };
    const NAMES: usize = 2 * 1024; // room for the logger and log file names
    let header = std::mem::size_of::<EVENT_TRACE_PROPERTIES>();
    // u64 storage keeps the properties struct suitably aligned.
    let mut buffer = vec![0u64; (header + NAMES).div_ceil(8)];
    let props = buffer.as_mut_ptr().cast::<EVENT_TRACE_PROPERTIES>();
    let wide: Vec<u16> = name.encode_utf16().chain(std::iter::once(0)).collect();
    // SAFETY: `buffer` is zeroed, aligned and large enough for the properties followed by the
    // two name strings whose offsets we declare; `wide` is NUL-terminated and outlives the call.
    let status = unsafe {
        (*props).Wnode.BufferSize = (buffer.len() * 8) as u32;
        (*props).LoggerNameOffset = header as u32;
        (*props).LogFileNameOffset = (header + NAMES / 2) as u32;
        ControlTraceW(
            CONTROLTRACE_HANDLE { Value: 0 },
            wide.as_ptr(),
            props,
            EVENT_TRACE_CONTROL_QUERY,
        )
    };
    status != ERROR_WMI_INSTANCE_NOT_FOUND
}

/// Names of every running ETW trace session (QueryAllTracesW; at most 64, the system limit).
pub fn trace_sessions() -> Vec<String> {
    use windows_sys::Win32::System::Diagnostics::Etw::{EVENT_TRACE_PROPERTIES, QueryAllTracesW};
    const MAX: usize = 64;
    const NAMES: usize = 2 * 1024;
    let header = std::mem::size_of::<EVENT_TRACE_PROPERTIES>();
    let per = (header + NAMES).div_ceil(8);
    let mut storage = vec![0u64; per * MAX];
    let base = storage.as_mut_ptr();
    let mut props: Vec<*mut EVENT_TRACE_PROPERTIES> = (0..MAX)
        // SAFETY: every slot lies inside `storage`.
        .map(|i| unsafe { base.add(i * per) }.cast::<EVENT_TRACE_PROPERTIES>())
        .collect();
    let mut count = 0u32;
    // SAFETY: each pointer addresses a zeroed, aligned block of `per * 8` bytes laid out as
    // declared below; `storage` outlives the call and the reads that follow.
    unsafe {
        for &p in &props {
            (*p).Wnode.BufferSize = (per * 8) as u32;
            (*p).LoggerNameOffset = header as u32;
            (*p).LogFileNameOffset = (header + NAMES / 2) as u32;
        }
        let status = QueryAllTracesW(props.as_mut_ptr(), MAX as u32, &mut count);
        if status != NO_ERROR && status != windows_sys::Win32::Foundation::ERROR_MORE_DATA {
            return Vec::new();
        }
        props
            .iter()
            .take((count as usize).min(MAX))
            .map(|&p| {
                let name = p
                    .cast::<u8>()
                    .add((*p).LoggerNameOffset as usize)
                    .cast::<u16>();
                let mut len = 0;
                while len < NAMES / 4 && *name.add(len) != 0 {
                    len += 1;
                }
                String::from_utf16_lossy(std::slice::from_raw_parts(name, len))
            })
            .collect()
    }
}

/// Whether a process with this ID is running.
pub fn process_alive(pid: u32) -> bool {
    use windows_sys::Win32::Foundation::STILL_ACTIVE;
    use windows_sys::Win32::System::Threading::GetExitCodeProcess;
    // SAFETY: the handle is checked and closed; the out pointer is valid.
    unsafe {
        let handle = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, pid);
        if handle.is_null() {
            // Access denied still means the process exists.
            return windows_sys::Win32::Foundation::GetLastError()
                == windows_sys::Win32::Foundation::ERROR_ACCESS_DENIED;
        }
        let mut code = 0u32;
        let ok = GetExitCodeProcess(handle, &mut code) != 0;
        CloseHandle(handle);
        ok && code == STILL_ACTIVE as u32
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ports_are_network_order() {
        assert_eq!(port(0xBB01), 443);
        assert_eq!(port(0xFFFF_BB01), 443, "high bits ignored");
    }

    #[test]
    fn rows_survive_short_buffers() {
        assert!(rows::<MIB_TCPROW_OWNER_PID>(&[]).is_empty());
        let mut buf = 3u32.to_ne_bytes().to_vec(); // claims 3 rows, holds none
        buf.extend_from_slice(&[0u8; 10]);
        assert!(rows::<MIB_TCPROW_OWNER_PID>(&buf).is_empty());
    }
}
