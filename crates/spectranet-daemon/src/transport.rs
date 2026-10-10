//! Where clients connect: a Unix socket on macOS and Linux, a named pipe on Windows.

use std::io::{self, Read, Write};
use std::path::Path;

use anyhow::Result;

/// A client connection, split into halves usable from one thread each.
pub struct Conn {
    pub reader: Box<dyn Read + Send>,
    pub writer: Box<dyn Write + Send>,
    pub peer: Peer,
}

/// Who is on the other end, as the operating system vouches for it.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Peer {
    pub pid: Option<u32>,
    /// Account name (`kiko`, `LAPTOP\\alice`), or `uid 501` if it has no name.
    pub user: String,
    /// root on Unix, an elevated (administrator) token on Windows.
    pub elevated: bool,
    /// Whether `user` and `elevated` are known yet (Windows looks them up lazily: the lookup
    /// can be slow and must not hold up the accept loop).
    pub resolved: bool,
}

impl Peer {
    /// Fills in the account and elevation if not done yet; only needed for actions.
    pub fn resolve(&mut self) {
        if self.resolved {
            return;
        }
        self.resolved = true;
        #[cfg(windows)]
        if let Some(pid) = self.pid
            && let Some((user, elevated)) = crate::winusers::process_identity(pid)
        {
            self.user = user;
            self.elevated = elevated;
        }
    }
}

pub use platform::{Listener, cleanup, wake};

#[cfg(unix)]
mod platform {
    use std::os::unix::fs::PermissionsExt;
    use std::os::unix::net::{UnixListener, UnixStream};
    use std::time::Duration;

    use anyhow::{Context, bail};

    use super::*;

    /// A client silent for this long is disconnected.
    const CLIENT_IDLE: Duration = Duration::from_secs(30);

    pub struct Listener(UnixListener);

    impl Listener {
        /// Binds the socket, replacing a stale one but refusing to run twice. With a group,
        /// its members may connect (mode 0660); otherwise only the owner (0600).
        pub fn bind(path: &Path, group: Option<u32>) -> Result<Self> {
            spectranet_proto::check_socket_path(path)?;
            if path.exists() {
                if UnixStream::connect(path).is_ok() {
                    bail!("another snetd is already running on {}", path.display());
                }
                std::fs::remove_file(path)
                    .with_context(|| format!("removing stale socket {}", path.display()))?;
            }
            if let Some(dir) = path.parent() {
                std::fs::create_dir_all(dir)?;
            }
            let listener = UnixListener::bind(path)
                .with_context(|| format!("listening on {}", path.display()))?;
            let mode = if group.is_some() { 0o660 } else { 0o600 };
            std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode))?;
            if let Some(gid) = group {
                std::os::unix::fs::chown(path, None, Some(gid))
                    .with_context(|| format!("setting group of {}", path.display()))?;
            }
            Ok(Self(listener))
        }

        pub fn accept(&self) -> io::Result<Conn> {
            let (stream, _) = self.0.accept()?;
            stream.set_read_timeout(Some(CLIENT_IDLE))?;
            stream.set_write_timeout(Some(CLIENT_IDLE))?;
            let peer = peer_of(&stream);
            let writer = stream.try_clone()?;
            Ok(Conn {
                reader: Box::new(stream),
                writer: Box::new(writer),
                peer,
            })
        }
    }

    /// Credentials of the process at the other end of a Unix socket.
    #[allow(unsafe_code)]
    fn peer_of(stream: &UnixStream) -> Peer {
        use std::os::fd::AsRawFd;
        let fd = stream.as_raw_fd();
        let (mut uid, mut pid): (Option<u32>, Option<u32>) = (None, None);
        #[cfg(target_os = "linux")]
        {
            let mut cred = libc::ucred {
                pid: 0,
                uid: 0,
                gid: 0,
            };
            let mut len = std::mem::size_of::<libc::ucred>() as libc::socklen_t;
            // SAFETY: valid socket fd and a buffer of the declared size.
            if unsafe {
                libc::getsockopt(
                    fd,
                    libc::SOL_SOCKET,
                    libc::SO_PEERCRED,
                    (&mut cred as *mut libc::ucred).cast(),
                    &mut len,
                )
            } == 0
            {
                uid = Some(cred.uid);
                pid = Some(cred.pid as u32);
            }
        }
        #[cfg(target_os = "macos")]
        {
            let (mut u, mut g): (libc::uid_t, libc::gid_t) = (0, 0);
            // SAFETY: valid socket fd and out pointers.
            if unsafe { libc::getpeereid(fd, &mut u, &mut g) } == 0 {
                uid = Some(u);
            }
            let mut p: libc::pid_t = 0;
            let mut len = std::mem::size_of::<libc::pid_t>() as libc::socklen_t;
            // SOL_LOCAL = 0, LOCAL_PEERPID = 2 (sys/un.h).
            // SAFETY: valid socket fd and a buffer of the declared size.
            if unsafe { libc::getsockopt(fd, 0, 2, (&mut p as *mut libc::pid_t).cast(), &mut len) }
                == 0
            {
                pid = Some(p as u32);
            }
        }
        let user = uid.map(user_name).unwrap_or_else(|| "unknown".into());
        Peer {
            pid,
            user,
            elevated: uid == Some(0),
            resolved: true,
        }
    }

    /// Account name for a uid.
    #[allow(unsafe_code)]
    fn user_name(uid: u32) -> String {
        let mut pwd: libc::passwd = unsafe { std::mem::zeroed() };
        let mut buf = vec![0 as libc::c_char; 4096];
        let mut result: *mut libc::passwd = std::ptr::null_mut();
        // SAFETY: getpwuid_r writes into our buffers only.
        let rc =
            unsafe { libc::getpwuid_r(uid, &mut pwd, buf.as_mut_ptr(), buf.len(), &mut result) };
        if rc == 0 && !result.is_null() && !pwd.pw_name.is_null() {
            // SAFETY: pw_name points into `buf`, NUL-terminated.
            unsafe { std::ffi::CStr::from_ptr(pwd.pw_name) }
                .to_string_lossy()
                .into_owned()
        } else {
            format!("uid {uid}")
        }
    }

    /// Removes the socket file.
    pub fn cleanup(path: &Path) {
        let _ = std::fs::remove_file(path);
    }

    /// Unblocks a pending `accept` so the serving thread can notice the service stopped.
    pub fn wake(path: &Path) {
        let _ = UnixStream::connect(path);
    }
}

#[cfg(windows)]
#[allow(unsafe_code)]
mod platform {
    use std::fs::File;
    use std::os::windows::ffi::OsStrExt;
    use std::os::windows::io::FromRawHandle;
    use std::sync::Mutex;

    use anyhow::bail;
    use windows_sys::Win32::Foundation::{
        CloseHandle, ERROR_ACCESS_DENIED, ERROR_PIPE_CONNECTED, GetLastError, HANDLE,
        INVALID_HANDLE_VALUE, LocalFree,
    };
    use windows_sys::Win32::Security::Authorization::{
        ConvertStringSecurityDescriptorToSecurityDescriptorW, SDDL_REVISION_1,
    };
    use windows_sys::Win32::Security::{PSECURITY_DESCRIPTOR, SECURITY_ATTRIBUTES};
    use windows_sys::Win32::Storage::FileSystem::{
        FILE_FLAG_FIRST_PIPE_INSTANCE, PIPE_ACCESS_DUPLEX,
    };
    use windows_sys::Win32::System::Pipes::{
        ConnectNamedPipe, CreateNamedPipeW, PIPE_READMODE_BYTE, PIPE_REJECT_REMOTE_CLIENTS,
        PIPE_TYPE_BYTE, PIPE_UNLIMITED_INSTANCES, PIPE_WAIT,
    };

    use super::*;

    const BUFFER: u32 = 64 * 1024;

    struct Handle(HANDLE);
    // SAFETY: a pipe handle may be used from any thread.
    unsafe impl Send for Handle {}

    pub struct Listener {
        name: Vec<u16>,
        security: Option<PSECURITY_DESCRIPTOR>,
        /// The instance waiting for the next client; there is always one, so a client never
        /// finds the pipe missing between two connections.
        pending: Mutex<Option<Handle>>,
    }

    // SAFETY: the security descriptor is immutable after creation and only read by
    // CreateNamedPipeW; the pending handle is behind a mutex.
    unsafe impl Send for Listener {}
    unsafe impl Sync for Listener {}

    impl Listener {
        /// Creates the pipe. With `restricted`, only SYSTEM and Administrators may connect.
        /// Fails if another snetd already owns the name.
        pub fn bind(path: &Path, restricted: Option<u32>) -> Result<Self> {
            let name: Vec<u16> = path.as_os_str().encode_wide().chain(Some(0)).collect();
            let security = match restricted {
                Some(_) => {
                    // Administrators, plus the users `snetd install` authorised.
                    let text = crate::winusers::pipe_sddl(&crate::winusers::allowed());
                    let sddl: Vec<u16> = text.encode_utf16().chain(Some(0)).collect();
                    let mut descriptor: PSECURITY_DESCRIPTOR = std::ptr::null_mut();
                    // SAFETY: valid NUL-terminated string; the descriptor is freed in Drop.
                    let ok = unsafe {
                        ConvertStringSecurityDescriptorToSecurityDescriptorW(
                            sddl.as_ptr(),
                            SDDL_REVISION_1,
                            &mut descriptor,
                            std::ptr::null_mut(),
                        )
                    };
                    if ok == 0 {
                        bail!(
                            "building the pipe's security descriptor failed: {}",
                            io::Error::last_os_error()
                        );
                    }
                    Some(descriptor)
                }
                None => None,
            };
            let listener = Self {
                name,
                security,
                pending: Mutex::new(None),
            };
            match listener.create(true) {
                Ok(first) => *listener.pending.lock().unwrap() = Some(first),
                Err(e) if e.raw_os_error() == Some(ERROR_ACCESS_DENIED as i32) => {
                    bail!("another snetd is already running on {}", path.display())
                }
                Err(e) => bail!("creating {}: {e}", path.display()),
            }
            Ok(listener)
        }

        fn create(&self, first: bool) -> io::Result<Handle> {
            let mut attributes = self.security.map(|descriptor| SECURITY_ATTRIBUTES {
                nLength: std::mem::size_of::<SECURITY_ATTRIBUTES>() as u32,
                lpSecurityDescriptor: descriptor,
                bInheritHandle: 0,
            });
            let open_mode = PIPE_ACCESS_DUPLEX
                | if first {
                    FILE_FLAG_FIRST_PIPE_INSTANCE
                } else {
                    0
                };
            // SAFETY: valid NUL-terminated name and optional attributes living for the call.
            let handle = unsafe {
                CreateNamedPipeW(
                    self.name.as_ptr(),
                    open_mode,
                    PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT | PIPE_REJECT_REMOTE_CLIENTS,
                    PIPE_UNLIMITED_INSTANCES,
                    BUFFER,
                    BUFFER,
                    0,
                    attributes
                        .as_mut()
                        .map_or(std::ptr::null(), |a| a as *const SECURITY_ATTRIBUTES),
                )
            };
            if handle == INVALID_HANDLE_VALUE {
                return Err(io::Error::last_os_error());
            }
            Ok(Handle(handle))
        }

        pub fn accept(&self) -> io::Result<Conn> {
            let handle = match self
                .pending
                .lock()
                .map_err(|_| io::Error::other("lock poisoned"))?
                .take()
            {
                Some(h) => h,
                None => self.create(false)?,
            };
            // SAFETY: valid pipe handle, synchronous (non-overlapped) wait.
            let connected = unsafe { ConnectNamedPipe(handle.0, std::ptr::null_mut()) } != 0
                // SAFETY: no preconditions.
                || unsafe { GetLastError() } == ERROR_PIPE_CONNECTED;
            // Have the next instance ready before handing this one over. Only one instance
            // waits at a time (a second one could take a client nobody is serving yet); in the
            // brief gap a client gets ERROR_PIPE_BUSY, which by Windows convention means "retry",
            // as `spectranet_proto::Client` does.
            let next = self.create(false);
            if let Ok(mut pending) = self.pending.lock() {
                *pending = next.ok();
            }
            if !connected {
                let error = io::Error::last_os_error();
                // SAFETY: the handle is ours and not used afterwards.
                unsafe { CloseHandle(handle.0) };
                return Err(error);
            }
            let peer = peer_of(handle.0);
            // SAFETY: the handle is a connected pipe we own; File takes over closing it.
            let file = unsafe { File::from_raw_handle(handle.0) };
            let writer = file.try_clone()?;
            Ok(Conn {
                reader: Box::new(file),
                writer: Box::new(writer),
                peer,
            })
        }
    }

    impl Drop for Listener {
        fn drop(&mut self) {
            if let Ok(mut pending) = self.pending.lock()
                && let Some(h) = pending.take()
            {
                // SAFETY: our own handle.
                unsafe { CloseHandle(h.0) };
            }
            if let Some(descriptor) = self.security {
                // SAFETY: allocated by ConvertStringSecurityDescriptorToSecurityDescriptorW.
                unsafe { LocalFree(descriptor) };
            }
        }
    }

    /// The client process of a connected pipe, its account and whether it is elevated.
    fn peer_of(pipe: HANDLE) -> Peer {
        use windows_sys::Win32::System::Pipes::GetNamedPipeClientProcessId;
        let mut pid = 0u32;
        // SAFETY: a connected pipe handle and an out pointer.
        if unsafe { GetNamedPipeClientProcessId(pipe, &mut pid) } == 0 {
            return Peer {
                pid: None,
                user: "unknown".into(),
                elevated: false,
                resolved: true,
            };
        }
        // Account and elevation are looked up later, on the connection's own thread.
        Peer {
            pid: Some(pid),
            user: "unknown".into(),
            elevated: false,
            resolved: false,
        }
    }

    /// Named pipes vanish with their last handle; nothing to remove.
    pub fn cleanup(_path: &Path) {}

    /// Unblocks a pending `accept` so the serving thread can notice the service stopped.
    pub fn wake(path: &Path) {
        let _ = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open(path);
    }
}
