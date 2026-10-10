//! Which Windows users, besides Administrators with an elevated token, may read snetd.
//!
//! On macOS and Linux membership of the admin/sudo group is enough to use `snet` and the
//! app without elevating. Windows strips the Administrators group from normal (unelevated)
//! tokens, so `snetd install` records the accounts allowed to connect: the one running the
//! installation and the one signed in at the console. Their SIDs live in
//! `C:\ProgramData\spectraNET\clients.txt` (writable by Administrators only) and are added to
//! the pipe's access list when the service starts.
#![allow(unsafe_code)]

use std::path::{Path, PathBuf};

use windows_sys::Win32::Foundation::{CloseHandle, HANDLE, LocalFree};
use windows_sys::Win32::Security::Authorization::ConvertSidToStringSidW;
use windows_sys::Win32::Security::{
    GetTokenInformation, LookupAccountNameW, SID_NAME_USE, TOKEN_QUERY, TOKEN_USER, TokenUser,
};
use windows_sys::Win32::System::RemoteDesktop::{
    WTS_CURRENT_SERVER_HANDLE, WTSDomainName, WTSFreeMemory, WTSGetActiveConsoleSessionId,
    WTSQuerySessionInformationW, WTSUserName,
};
use windows_sys::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};

pub fn clients_file() -> PathBuf {
    Path::new(spectranet_proto::DEFAULT_DATA_DIR).join("clients.txt")
}

/// A SID in string form, as accepted inside an SDDL string (`S-1-5-21-…`).
pub fn is_sid(text: &str) -> bool {
    let mut parts = text.split('-');
    parts.next() == Some("S")
        && parts.next() == Some("1")
        && text.len() < 200
        && text.split('-').skip(2).count() >= 2
        && text
            .split('-')
            .skip(2)
            .all(|p| !p.is_empty() && p.bytes().all(|b| b.is_ascii_digit()))
}

/// SIDs allowed to connect (invalid lines are ignored: they would corrupt the SDDL).
pub fn allowed() -> Vec<String> {
    let Ok(text) = std::fs::read_to_string(clients_file()) else {
        return Vec::new();
    };
    let mut sids: Vec<String> = text
        .lines()
        .map(str::trim)
        .filter(|l| is_sid(l))
        .map(str::to_string)
        .collect();
    sids.sort();
    sids.dedup();
    sids
}

/// The pipe's access list: SYSTEM and Administrators, plus read/write for each SID.
pub fn pipe_sddl(sids: &[String]) -> String {
    let mut sddl = String::from("D:P(A;;GA;;;SY)(A;;GA;;;BA)");
    for sid in sids.iter().filter(|s| is_sid(s)) {
        sddl.push_str(&format!("(A;;GRGW;;;{sid})"));
    }
    sddl
}

fn sid_string(sid: *mut core::ffi::c_void) -> Option<String> {
    let mut text: *mut u16 = std::ptr::null_mut();
    // SAFETY: `sid` points to a valid SID; the string is freed with LocalFree.
    unsafe {
        if ConvertSidToStringSidW(sid, &mut text) == 0 || text.is_null() {
            return None;
        }
        let mut len = 0;
        while *text.add(len) != 0 {
            len += 1;
        }
        let s = String::from_utf16_lossy(std::slice::from_raw_parts(text, len));
        LocalFree(text.cast());
        Some(s)
    }
}

/// The account of this (possibly elevated) process.
fn process_user() -> Option<String> {
    // SAFETY: token handle checked and closed; buffer sized by the first call.
    unsafe {
        let mut token: HANDLE = std::ptr::null_mut();
        if OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token) == 0 {
            return None;
        }
        let mut size = 0u32;
        GetTokenInformation(token, TokenUser, std::ptr::null_mut(), 0, &mut size);
        let mut buffer = vec![0u64; (size as usize).div_ceil(8).max(1)];
        let ok = GetTokenInformation(
            token,
            TokenUser,
            buffer.as_mut_ptr().cast(),
            size,
            &mut size,
        );
        CloseHandle(token);
        if ok == 0 {
            return None;
        }
        let user = &*(buffer.as_ptr().cast::<TOKEN_USER>());
        sid_string(user.User.Sid)
    }
}

fn session_string(session: u32, class: i32) -> Option<String> {
    let mut buffer: *mut u16 = std::ptr::null_mut();
    let mut bytes = 0u32;
    // SAFETY: WTS allocates the buffer, freed with WTSFreeMemory.
    unsafe {
        if WTSQuerySessionInformationW(
            WTS_CURRENT_SERVER_HANDLE,
            session,
            class,
            &mut buffer,
            &mut bytes,
        ) == 0
            || buffer.is_null()
        {
            return None;
        }
        let len = (bytes as usize / 2).saturating_sub(1);
        let s = String::from_utf16_lossy(std::slice::from_raw_parts(buffer, len));
        WTSFreeMemory(buffer.cast());
        Some(s.trim_end_matches('\0').to_string())
    }
}

/// The account signed in at the console, if any.
fn console_user() -> Option<String> {
    // SAFETY: plain query with no arguments.
    let session = unsafe { WTSGetActiveConsoleSessionId() };
    if session == u32::MAX {
        return None;
    }
    let user = session_string(session, WTSUserName)?;
    if user.is_empty() {
        return None;
    }
    let domain = session_string(session, WTSDomainName).unwrap_or_default();
    let account: Vec<u16> = format!("{domain}\\{user}")
        .encode_utf16()
        .chain(Some(0))
        .collect();
    let mut sid = vec![0u64; 16]; // 128 bytes: larger than any SID
    let mut sid_size = 128u32;
    let mut domain_buf = vec![0u16; 256];
    let mut domain_len = 256u32;
    let mut kind: SID_NAME_USE = 0;
    // SAFETY: all buffers are sized as declared and outlive the call.
    let ok = unsafe {
        LookupAccountNameW(
            std::ptr::null(),
            account.as_ptr(),
            sid.as_mut_ptr().cast(),
            &mut sid_size,
            domain_buf.as_mut_ptr(),
            &mut domain_len,
            &mut kind,
        )
    };
    if ok == 0 {
        return None;
    }
    sid_string(sid.as_mut_ptr().cast())
}

/// Account name (`DOMAIN\\user`) and elevation of another process.
pub fn process_identity(pid: u32) -> Option<(String, bool)> {
    use windows_sys::Win32::Security::{LookupAccountSidW, TOKEN_ELEVATION, TokenElevation};
    use windows_sys::Win32::System::Threading::{OpenProcess, PROCESS_QUERY_LIMITED_INFORMATION};
    // SAFETY: handles are checked and closed; buffers are sized by the calls that fill them.
    unsafe {
        let process = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, pid);
        if process.is_null() {
            return None;
        }
        let mut token: HANDLE = std::ptr::null_mut();
        let opened = OpenProcessToken(process, TOKEN_QUERY, &mut token);
        CloseHandle(process);
        if opened == 0 {
            return None;
        }
        let mut elevation = TOKEN_ELEVATION { TokenIsElevated: 0 };
        let mut size = std::mem::size_of::<TOKEN_ELEVATION>() as u32;
        let elevated = GetTokenInformation(
            token,
            TokenElevation,
            (&mut elevation as *mut TOKEN_ELEVATION).cast(),
            size,
            &mut size,
        ) != 0
            && elevation.TokenIsElevated != 0;
        let mut needed = 0u32;
        GetTokenInformation(token, TokenUser, std::ptr::null_mut(), 0, &mut needed);
        let mut buffer = vec![0u64; (needed as usize).div_ceil(8).max(1)];
        let ok = GetTokenInformation(
            token,
            TokenUser,
            buffer.as_mut_ptr().cast(),
            needed,
            &mut needed,
        );
        CloseHandle(token);
        if ok == 0 {
            return None;
        }
        let sid = (*(buffer.as_ptr().cast::<TOKEN_USER>())).User.Sid;
        let mut name = vec![0u16; 256];
        let mut name_len = 256u32;
        let mut domain = vec![0u16; 256];
        let mut domain_len = 256u32;
        let mut kind: SID_NAME_USE = 0;
        let found = LookupAccountSidW(
            std::ptr::null(),
            sid,
            name.as_mut_ptr(),
            &mut name_len,
            domain.as_mut_ptr(),
            &mut domain_len,
            &mut kind,
        ) != 0;
        let account = if found {
            format!(
                "{}\\{}",
                String::from_utf16_lossy(&domain[..domain_len as usize]),
                String::from_utf16_lossy(&name[..name_len as usize])
            )
        } else {
            sid_string(sid).unwrap_or_else(|| "unknown".into())
        };
        Some((account, elevated))
    }
}

/// Records the installing and the console user as allowed clients (keeping earlier ones).
pub fn authorize_current_users() -> std::io::Result<Vec<String>> {
    let mut sids = allowed();
    sids.extend(process_user());
    sids.extend(console_user());
    sids.retain(|s| is_sid(s));
    sids.sort();
    sids.dedup();
    std::fs::create_dir_all(spectranet_proto::DEFAULT_DATA_DIR)?;
    std::fs::write(clients_file(), sids.join("\n") + "\n")?;
    Ok(sids)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_well_formed_sids_reach_the_sddl() {
        assert!(is_sid("S-1-5-21-1004336348-1177238915-682003330-1001"));
        assert!(is_sid("S-1-5-18"));
        assert!(!is_sid("S-1-5-21-12)(A;;GA;;;WD"), "injection attempt");
        assert!(!is_sid("WD"));
        assert!(!is_sid("S-1-"));
        assert!(!is_sid(""));
        let sddl = pipe_sddl(&["S-1-5-21-1-2-3-1001".into(), "evil)(A;;GA;;;WD".into()]);
        assert_eq!(
            sddl,
            "D:P(A;;GA;;;SY)(A;;GA;;;BA)(A;;GRGW;;;S-1-5-21-1-2-3-1001)"
        );
    }

    #[test]
    fn this_process_has_a_user() {
        assert!(process_user().is_some_and(|s| is_sid(&s)));
    }
}
