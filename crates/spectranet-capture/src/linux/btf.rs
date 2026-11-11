//! The running kernel's BTF, which the eBPF programs are relocated against (CO-RE).
//!
//! Read from `/sys/kernel/btf/vmlinux`, as libbpf does. Where that file can't be opened (a
//! strict snap: no interface grants it), the kernel hands out the same data through bpf():
//! walk the loaded BTF objects, find the one named `vmlinux` and read its raw bytes. That
//! needs the same privileges as loading the programs, nothing more.

use std::os::fd::{FromRawFd, OwnedFd};

use aya::Btf;

const BPF_OBJ_GET_INFO_BY_FD: libc::c_long = 15;
const BPF_BTF_GET_FD_BY_ID: libc::c_long = 19;
const BPF_BTF_GET_NEXT_ID: libc::c_long = 23;

/// `BTF_GET_NEXT_ID` / `BTF_GET_FD_BY_ID` arguments (the start of `union bpf_attr`).
#[repr(C)]
#[derive(Default)]
struct IdAttr {
    id: u32,
    next_id: u32,
    open_flags: u32,
}

/// `OBJ_GET_INFO_BY_FD` arguments.
#[repr(C)]
#[derive(Default)]
struct InfoAttr {
    bpf_fd: u32,
    info_len: u32,
    info: u64,
}

/// `struct bpf_btf_info` (kernel 5.11+ for `name` and `kernel_btf`).
#[repr(C)]
#[derive(Default)]
struct BtfInfo {
    btf: u64,
    btf_size: u32,
    id: u32,
    name: u64,
    name_len: u32,
    kernel_btf: u32,
}

/// The kernel's BTF: the sysfs file, else the kernel's own copy through bpf().
pub(crate) fn kernel_btf() -> Result<Btf, String> {
    let from_file = match Btf::from_sys_fs() {
        Ok(btf) => return Ok(btf),
        Err(e) => e.to_string(),
    };
    let data = vmlinux_from_bpf().map_err(|e| format!("{from_file}; through bpf(): {e}"))?;
    Btf::parse(&data, Default::default()).map_err(|e| e.to_string())
}

#[allow(unsafe_code)]
fn bpf<T>(cmd: libc::c_long, attr: &mut T) -> std::io::Result<libc::c_long> {
    // SAFETY: `attr` is a valid, initialised bpf_attr prefix of the size passed.
    let rc = unsafe {
        libc::syscall(
            libc::SYS_bpf,
            cmd,
            attr as *mut T as *mut libc::c_void,
            std::mem::size_of::<T>(),
        )
    };
    if rc < 0 {
        Err(std::io::Error::last_os_error())
    } else {
        Ok(rc)
    }
}

/// Fills `info` for the BTF object `fd` (with `name` and, if set, `btf` pointing at buffers).
fn btf_info(fd: &OwnedFd, info: &mut BtfInfo) -> std::io::Result<()> {
    use std::os::fd::AsRawFd;
    let mut attr = InfoAttr {
        bpf_fd: fd.as_raw_fd() as u32,
        info_len: std::mem::size_of::<BtfInfo>() as u32,
        info: info as *mut BtfInfo as u64,
    };
    bpf(BPF_OBJ_GET_INFO_BY_FD, &mut attr).map(drop)
}

#[allow(unsafe_code)]
fn vmlinux_from_bpf() -> std::io::Result<Vec<u8>> {
    let mut id = 0;
    loop {
        let mut next = IdAttr {
            id,
            ..Default::default()
        };
        bpf(BPF_BTF_GET_NEXT_ID, &mut next)?; // ENOENT once past the last one
        id = next.next_id;
        let mut open = IdAttr {
            id,
            ..Default::default()
        };
        let Ok(raw) = bpf(BPF_BTF_GET_FD_BY_ID, &mut open) else {
            continue; // unloaded meanwhile
        };
        // SAFETY: a new descriptor the kernel just handed us.
        let fd = unsafe { OwnedFd::from_raw_fd(raw as i32) };
        let mut name = [0u8; 64];
        let mut info = BtfInfo {
            name: name.as_mut_ptr() as u64,
            name_len: name.len() as u32,
            ..Default::default()
        };
        btf_info(&fd, &mut info)?;
        let len = name.iter().position(|&b| b == 0).unwrap_or(name.len());
        if info.kernel_btf == 0 || &name[..len] != b"vmlinux" {
            continue;
        }
        let mut data = vec![0u8; info.btf_size as usize];
        let mut info = BtfInfo {
            btf: data.as_mut_ptr() as u64,
            btf_size: data.len() as u32,
            ..Default::default()
        };
        btf_info(&fd, &mut info)?;
        data.truncate(info.btf_size as usize);
        return Ok(data);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_bpf_copy_matches_the_sysfs_file() {
        // Needs root (bpf()) and a kernel with BTF in sysfs; skipped otherwise.
        let (Ok(file), Ok(copy)) = (std::fs::read("/sys/kernel/btf/vmlinux"), vmlinux_from_bpf())
        else {
            eprintln!("skipped: needs root and /sys/kernel/btf/vmlinux");
            return;
        };
        assert_eq!(file, copy);
        assert!(Btf::parse(&copy, Default::default()).is_ok());
    }
}
