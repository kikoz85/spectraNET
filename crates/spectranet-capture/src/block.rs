//! Enforcing blocks: an application or a remote address cut off from the network.
//!
//! These are the operating-system mechanisms only; snetd decides what may be blocked, for
//! how long, and records it. Every mechanism is tied to the snetd process: when it stops,
//! the blocks go away with it (and snetd puts them back when it starts again), so a crash
//! can never leave the machine blocked with no one to lift it.
//!
//! - Windows: Windows Filtering Platform filters on the application's executable and on
//!   remote addresses, in a dynamic session (removed by the system when snetd exits).
//! - Linux: an eBPF program on the root cgroup: a blocked executable can't open, connect or
//!   send on network sockets; packets from or to a blocked address are dropped. Bpf links
//!   owned by snetd, detached when it exits.
//! - macOS: a pf table in spectraNET's own anchor. pf can't tell applications apart, so an
//!   application is blocked by following it: snetd adds each address it talks to (see
//!   [`AppBlocking::Following`]).

use std::collections::HashMap;
use std::io;
use std::net::IpAddr;
use std::path::PathBuf;

/// How applications can be blocked on this system.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AppBlocking {
    /// By executable: every connection, at once.
    Full,
    /// By the addresses the application uses, as they are seen (macOS): a new destination
    /// can get through for about one sample, and a blocked address is blocked for every
    /// application.
    Following,
}

/// What this system supports, without starting anything.
pub fn support() -> Option<AppBlocking> {
    if cfg!(any(target_os = "linux", windows)) {
        Some(AppBlocking::Full)
    } else if cfg!(target_os = "macos") {
        Some(AppBlocking::Following)
    } else {
        None
    }
}

/// A running block mechanism. Dropping it lifts every block.
pub trait Enforcer: Send {
    /// How blocks are enforced, in a few words, for the user.
    fn method(&self) -> &'static str;
    fn app_blocking(&self) -> AppBlocking;
    /// Blocks every connection of these executables under `id` ([`AppBlocking::Full`]).
    fn block_app(&mut self, id: u64, executables: &[PathBuf]) -> io::Result<()>;
    /// Blocks an address under `id`. Several addresses may share one `id`.
    fn block_ip(&mut self, id: u64, ip: IpAddr) -> io::Result<()>;
    /// Lifts everything blocked under `id`.
    fn lift(&mut self, id: u64) -> io::Result<()>;
}

/// Starts the mechanism (needs root / an elevated service).
pub fn start() -> io::Result<Box<dyn Enforcer>> {
    platform::start()
}

/// Which block ids hold each item, so an item shared by two blocks stays until both go.
#[derive(Debug)]
struct Holders<K> {
    by_id: HashMap<u64, Vec<K>>,
}

impl<K> Default for Holders<K> {
    fn default() -> Self {
        Self {
            by_id: HashMap::new(),
        }
    }
}

impl<K: PartialEq + Clone> Holders<K> {
    fn held(&self, key: &K) -> bool {
        self.by_id.values().any(|keys| keys.contains(key))
    }

    /// Records `key` under `id`; true if nothing held it before (it must be put in force).
    fn add(&mut self, id: u64, key: K) -> bool {
        let fresh = !self.held(&key);
        let keys = self.by_id.entry(id).or_default();
        if !keys.contains(&key) {
            keys.push(key);
        }
        fresh
    }

    #[cfg_attr(not(target_os = "macos"), allow(dead_code))]
    fn contains(&self, id: u64, key: &K) -> bool {
        self.by_id.get(&id).is_some_and(|k| k.contains(key))
    }

    /// Forgets `id`; returns the keys nothing holds any more (to be lifted).
    fn remove(&mut self, id: u64) -> Vec<K> {
        let keys = self.by_id.remove(&id).unwrap_or_default();
        keys.into_iter().filter(|k| !self.held(k)).collect()
    }
}

#[cfg(target_os = "linux")]
mod platform {
    use std::fs::File;
    use std::os::unix::fs::MetadataExt;

    use aya::maps::{HashMap as BpfMap, MapData};
    use aya::programs::{
        CgroupAttachMode, CgroupSkb, CgroupSkbAttachType, CgroupSock, CgroupSockAddr,
    };
    use aya::{Btf, Ebpf, EbpfLoader};

    use super::*;

    const OBJECT: &[u8] = aya::include_bytes_aligned!(concat!(env!("OUT_DIR"), "/block.bpf.o"));
    const CGROUP_ROOT: &str = "/sys/fs/cgroup";

    /// Mirror of `struct exe_key`.
    #[repr(C)]
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    struct ExeKey {
        ino: u64,
        dev: u32,
        pad: u32,
    }

    // SAFETY: plain-old-data with explicit padding; any bit pattern is valid.
    #[allow(unsafe_code)]
    unsafe impl aya::Pod for ExeKey {}

    struct Ebpf_ {
        exes: BpfMap<MapData, ExeKey, u32>,
        ips: BpfMap<MapData, [u8; 16], u32>,
        app_keys: Holders<ExeKey>,
        ip_keys: Holders<[u8; 16]>,
        // Owns the programs and their links: dropping it detaches everything.
        _ebpf: Ebpf,
    }

    fn other(e: impl std::fmt::Display + std::fmt::Debug) -> io::Error {
        let text = format!("{e}: {e:?}");
        if text.contains("Operation not permitted") || text.contains("EPERM") {
            io::Error::new(io::ErrorKind::PermissionDenied, text)
        } else {
            io::Error::other(text)
        }
    }

    /// The kernel's encoding of a device number (`new_encode_dev`'s inverse is not what
    /// `stat` returns: the kernel keeps `major << 20 | minor` in `super_block.s_dev`).
    fn kernel_dev(dev: u64) -> u32 {
        let (major, minor) = (libc::major(dev), libc::minor(dev));
        (major << 20) | (minor & 0xFFFFF)
    }

    fn exe_key(path: &std::path::Path) -> io::Result<ExeKey> {
        let meta = std::fs::metadata(path)?;
        Ok(ExeKey {
            ino: meta.ino(),
            dev: kernel_dev(meta.dev()),
            pad: 0,
        })
    }

    pub(super) fn ip_key(ip: IpAddr) -> [u8; 16] {
        match ip {
            IpAddr::V4(v4) => v4.to_ipv6_mapped().octets(),
            IpAddr::V6(v6) => v6.octets(),
        }
    }

    pub fn start() -> io::Result<Box<dyn Enforcer>> {
        let btf = Btf::from_sys_fs().map_err(|e| other(format!("kernel BTF unavailable: {e}")))?;
        let mut ebpf = EbpfLoader::new()
            .btf(Some(&btf))
            .load(OBJECT)
            .map_err(other)?;
        let cgroup = File::open(CGROUP_ROOT)?;
        // With bpf links (kernel 5.7+) several programs coexist on a cgroup whatever the
        // mode, and the kernel refuses multi-attach flags on links.
        let mode = CgroupAttachMode::Single;
        {
            let p: &mut CgroupSock = ebpf
                .program_mut("block_sock_create")
                .ok_or_else(|| other("block_sock_create missing"))?
                .try_into()
                .map_err(other)?;
            p.load().map_err(other)?;
            p.attach(&cgroup, mode).map_err(other)?;
        }
        for name in [
            "block_connect4",
            "block_connect6",
            "block_sendmsg4",
            "block_sendmsg6",
        ] {
            let p: &mut CgroupSockAddr = ebpf
                .program_mut(name)
                .ok_or_else(|| other(format!("{name} missing")))?
                .try_into()
                .map_err(other)?;
            p.load().map_err(other)?;
            p.attach(&cgroup, mode).map_err(other)?;
        }
        for (name, kind) in [
            ("block_ingress", CgroupSkbAttachType::Ingress),
            ("block_egress", CgroupSkbAttachType::Egress),
        ] {
            let p: &mut CgroupSkb = ebpf
                .program_mut(name)
                .ok_or_else(|| other(format!("{name} missing")))?
                .try_into()
                .map_err(other)?;
            p.load().map_err(other)?;
            p.attach(&cgroup, kind, mode).map_err(other)?;
        }
        let exes = BpfMap::try_from(
            ebpf.take_map("blocked_exes")
                .ok_or_else(|| other("map blocked_exes missing"))?,
        )
        .map_err(other)?;
        let ips = BpfMap::try_from(
            ebpf.take_map("blocked_ips")
                .ok_or_else(|| other("map blocked_ips missing"))?,
        )
        .map_err(other)?;
        Ok(Box::new(Ebpf_ {
            exes,
            ips,
            app_keys: Holders::default(),
            ip_keys: Holders::default(),
            _ebpf: ebpf,
        }))
    }

    impl Enforcer for Ebpf_ {
        fn method(&self) -> &'static str {
            "eBPF (cgroup)"
        }

        fn app_blocking(&self) -> AppBlocking {
            AppBlocking::Full
        }

        fn block_app(&mut self, id: u64, executables: &[PathBuf]) -> io::Result<()> {
            let mut any = false;
            let mut last_error = None;
            for path in executables {
                match exe_key(path) {
                    Ok(key) => {
                        any = true;
                        if self.app_keys.add(id, key) {
                            self.exes.insert(key, 1, 0).map_err(other)?;
                        }
                    }
                    Err(e) => last_error = Some(e),
                }
            }
            match (any, last_error) {
                (true, _) => Ok(()),
                (false, Some(e)) => Err(e),
                (false, None) => Err(io::Error::new(
                    io::ErrorKind::NotFound,
                    "no executable to block",
                )),
            }
        }

        fn block_ip(&mut self, id: u64, ip: IpAddr) -> io::Result<()> {
            let key = ip_key(ip);
            if self.ip_keys.add(id, key) {
                self.ips.insert(key, 1, 0).map_err(other)?;
            }
            Ok(())
        }

        fn lift(&mut self, id: u64) -> io::Result<()> {
            for key in self.app_keys.remove(id) {
                let _ = self.exes.remove(&key);
            }
            for key in self.ip_keys.remove(id) {
                let _ = self.ips.remove(&key);
            }
            Ok(())
        }
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        #[test]
        fn exe_key_layout_matches_the_program() {
            assert_eq!(std::mem::size_of::<ExeKey>(), 16);
        }

        /// Live (root): a blocked address and a blocked executable can't connect; lifting
        /// the block restores them; other programs are untouched.
        #[test]
        fn blocks_addresses_and_executables_live() {
            use std::net::{TcpListener, TcpStream};
            let mut enforcer = match start() {
                Ok(e) => e,
                Err(e) if e.kind() == io::ErrorKind::PermissionDenied => {
                    eprintln!("not privileged, skipping: {e}");
                    return;
                }
                Err(e) => panic!("{e}"),
            };
            let listener = TcpListener::bind("0.0.0.0:0").unwrap();
            let port = listener.local_addr().unwrap().port();
            std::thread::spawn(move || for _ in listener.incoming() {});
            let blocked: IpAddr = "127.0.0.2".parse().unwrap();
            let target = std::net::SocketAddr::new(blocked, port);
            let timeout = std::time::Duration::from_secs(2);

            enforcer.block_ip(1, blocked).unwrap();
            assert!(
                TcpStream::connect_timeout(&target, timeout).is_err(),
                "address blocked"
            );
            assert!(
                TcpStream::connect(("127.0.0.1", port)).is_ok(),
                "other addresses untouched"
            );
            enforcer.lift(1).unwrap();
            assert!(
                TcpStream::connect_timeout(&target, timeout).is_ok(),
                "lifted"
            );

            // A blocked program (python3) can't even open a socket; we still can.
            let python = std::fs::canonicalize("/usr/bin/python3").unwrap();
            let script = format!(
                "import socket,sys\ntry:\n socket.create_connection(('127.0.0.1',{port}),2)\nexcept OSError:\n sys.exit(3)"
            );
            let run = || {
                std::process::Command::new(&python)
                    .args(["-c", &script])
                    .status()
                    .unwrap()
            };
            enforcer
                .block_app(2, std::slice::from_ref(&python))
                .unwrap();
            assert_eq!(run().code(), Some(3), "blocked program refused");
            assert!(
                TcpStream::connect(("127.0.0.1", port)).is_ok(),
                "we are not blocked"
            );
            enforcer.lift(2).unwrap();
            assert_eq!(run().code(), Some(0), "lifted");
            drop(enforcer);
        }

        #[test]
        fn device_numbers_use_the_kernel_encoding() {
            // sda1 is 8:1 → 8 << 20 | 1.
            assert_eq!(kernel_dev(libc::makedev(8, 1)), (8 << 20) | 1);
            assert_eq!(kernel_dev(libc::makedev(259, 70000)), (259 << 20) | 70000);
        }
    }
}

#[cfg(windows)]
#[allow(unsafe_code)]
mod platform {
    use std::os::windows::ffi::OsStrExt;

    use windows_sys::Win32::Foundation::HANDLE;
    use windows_sys::Win32::NetworkManagement::WindowsFilteringPlatform::{
        FWP_ACTION_BLOCK, FWP_BYTE_ARRAY16, FWP_BYTE_ARRAY16_TYPE, FWP_BYTE_BLOB,
        FWP_BYTE_BLOB_TYPE, FWP_MATCH_EQUAL, FWP_UINT32, FWPM_CONDITION_ALE_APP_ID,
        FWPM_CONDITION_IP_REMOTE_ADDRESS, FWPM_FILTER_CONDITION0, FWPM_FILTER0,
        FWPM_LAYER_ALE_AUTH_CONNECT_V4, FWPM_LAYER_ALE_AUTH_CONNECT_V6,
        FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V4, FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V6,
        FWPM_SESSION_FLAG_DYNAMIC, FWPM_SESSION0, FwpmEngineClose0, FwpmEngineOpen0,
        FwpmFilterAdd0, FwpmFilterDeleteById0, FwpmFreeMemory0, FwpmGetAppIdFromFileName0,
    };
    use windows_sys::Win32::System::Rpc::RPC_C_AUTHN_WINNT;
    use windows_sys::core::GUID;

    use super::*;

    struct Wfp {
        engine: HANDLE,
        filters: HashMap<u64, Vec<u64>>,
        ip_keys: Holders<IpAddr>,
        /// Filter ids of each blocked address (shared between block ids).
        ip_filters: HashMap<IpAddr, Vec<u64>>,
    }

    // SAFETY: the engine handle is only used through &mut self.
    unsafe impl Send for Wfp {}

    fn wide(s: &str) -> Vec<u16> {
        std::ffi::OsStr::new(s)
            .encode_wide()
            .chain(Some(0))
            .collect()
    }

    fn check(rc: u32, what: &str) -> io::Result<()> {
        if rc == 0 {
            Ok(())
        } else if rc == 5 || rc == 0x8032_0016 {
            Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                format!("{what}: access denied (needs the snetd service or an elevated prompt)"),
            ))
        } else {
            Err(io::Error::other(format!("{what}: error {rc:#x}")))
        }
    }

    pub fn start() -> io::Result<Box<dyn Enforcer>> {
        let mut name = wide("spectraNET blocks");
        let session = FWPM_SESSION0 {
            displayData: windows_sys::Win32::NetworkManagement::WindowsFilteringPlatform::FWPM_DISPLAY_DATA0 {
                name: name.as_mut_ptr(),
                description: std::ptr::null_mut(),
            },
            // Filters live as long as this session: the system removes them when snetd
            // exits, however it exits.
            flags: FWPM_SESSION_FLAG_DYNAMIC,
            ..Default::default()
        };
        let mut engine: HANDLE = std::ptr::null_mut();
        // SAFETY: valid session for the call; the handle is closed on drop.
        let rc = unsafe {
            FwpmEngineOpen0(
                std::ptr::null(),
                RPC_C_AUTHN_WINNT,
                std::ptr::null(),
                &session,
                &mut engine,
            )
        };
        check(rc, "opening the filtering engine")?;
        Ok(Box::new(Wfp {
            engine,
            filters: HashMap::new(),
            ip_keys: Holders::default(),
            ip_filters: HashMap::new(),
        }))
    }

    impl Drop for Wfp {
        fn drop(&mut self) {
            // SAFETY: handle from FwpmEngineOpen0; closing it removes the dynamic filters.
            unsafe { FwpmEngineClose0(self.engine) };
        }
    }

    impl Wfp {
        fn add(&self, layer: GUID, condition: &mut FWPM_FILTER_CONDITION0) -> io::Result<u64> {
            let mut name = wide("spectraNET block");
            let mut filter = FWPM_FILTER0 {
                layerKey: layer,
                numFilterConditions: 1,
                filterCondition: condition,
                ..Default::default()
            };
            filter.displayData.name = name.as_mut_ptr();
            filter.action.r#type = FWP_ACTION_BLOCK;
            let mut id = 0u64;
            // SAFETY: the filter and everything it points to live for the call.
            let rc = unsafe { FwpmFilterAdd0(self.engine, &filter, std::ptr::null_mut(), &mut id) };
            check(rc, "adding a filter")?;
            Ok(id)
        }

        fn delete(&self, ids: &[u64]) {
            for id in ids {
                // SAFETY: plain call with an id we added.
                unsafe { FwpmFilterDeleteById0(self.engine, *id) };
            }
        }
    }

    impl Enforcer for Wfp {
        fn method(&self) -> &'static str {
            "Windows Filtering Platform"
        }

        fn app_blocking(&self) -> AppBlocking {
            AppBlocking::Full
        }

        fn block_app(&mut self, id: u64, executables: &[PathBuf]) -> io::Result<()> {
            let mut added = Vec::new();
            let mut result = Ok(());
            for path in executables {
                let path = wide(&path.to_string_lossy());
                let mut blob: *mut FWP_BYTE_BLOB = std::ptr::null_mut();
                // SAFETY: valid string; the blob is freed below.
                let rc = unsafe { FwpmGetAppIdFromFileName0(path.as_ptr(), &mut blob) };
                if let Err(e) = check(rc, "finding the application") {
                    result = Err(e);
                    continue;
                }
                let mut condition = FWPM_FILTER_CONDITION0 {
                    fieldKey: FWPM_CONDITION_ALE_APP_ID,
                    matchType: FWP_MATCH_EQUAL,
                    ..Default::default()
                };
                condition.conditionValue.r#type = FWP_BYTE_BLOB_TYPE;
                condition.conditionValue.Anonymous.byteBlob = blob;
                for layer in [
                    FWPM_LAYER_ALE_AUTH_CONNECT_V4,
                    FWPM_LAYER_ALE_AUTH_CONNECT_V6,
                    FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V4,
                    FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V6,
                ] {
                    match self.add(layer, &mut condition) {
                        Ok(f) => added.push(f),
                        Err(e) => result = Err(e),
                    }
                }
                // SAFETY: allocated by FwpmGetAppIdFromFileName0.
                unsafe { FwpmFreeMemory0((&mut blob as *mut *mut FWP_BYTE_BLOB).cast()) };
            }
            if added.is_empty() {
                return result.and(Err(io::Error::other("no filter could be added")));
            }
            self.filters.entry(id).or_default().extend(added);
            Ok(())
        }

        fn block_ip(&mut self, id: u64, ip: IpAddr) -> io::Result<()> {
            if !self.ip_keys.add(id, ip) {
                return Ok(());
            }
            let mut condition = FWPM_FILTER_CONDITION0 {
                fieldKey: FWPM_CONDITION_IP_REMOTE_ADDRESS,
                matchType: FWP_MATCH_EQUAL,
                ..Default::default()
            };
            let mut v6 = FWP_BYTE_ARRAY16 {
                byteArray16: [0; 16],
            };
            let layers = match ip {
                IpAddr::V4(v4) => {
                    condition.conditionValue.r#type = FWP_UINT32;
                    condition.conditionValue.Anonymous.uint32 = u32::from(v4);
                    [
                        FWPM_LAYER_ALE_AUTH_CONNECT_V4,
                        FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V4,
                    ]
                }
                IpAddr::V6(v6addr) => {
                    v6.byteArray16 = v6addr.octets();
                    condition.conditionValue.r#type = FWP_BYTE_ARRAY16_TYPE;
                    condition.conditionValue.Anonymous.byteArray16 = &mut v6;
                    [
                        FWPM_LAYER_ALE_AUTH_CONNECT_V6,
                        FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V6,
                    ]
                }
            };
            let mut ids = Vec::new();
            for layer in layers {
                match self.add(layer, &mut condition) {
                    Ok(f) => ids.push(f),
                    Err(e) => {
                        self.delete(&ids);
                        self.ip_keys.remove(id);
                        return Err(e);
                    }
                }
            }
            self.ip_filters.insert(ip, ids);
            Ok(())
        }

        fn lift(&mut self, id: u64) -> io::Result<()> {
            if let Some(ids) = self.filters.remove(&id) {
                self.delete(&ids);
            }
            for ip in self.ip_keys.remove(id) {
                if let Some(ids) = self.ip_filters.remove(&ip) {
                    self.delete(&ids);
                }
            }
            Ok(())
        }
    }
}

#[cfg(all(test, windows))]
mod windows_tests {
    use super::*;

    /// Live (Administrator): a blocked address and a blocked program (curl) can't
    /// connect; lifting the block restores them; other programs are untouched.
    #[test]
    fn blocks_addresses_and_executables_live() {
        use std::net::{TcpListener, TcpStream};
        let mut enforcer = match start() {
            Ok(e) => e,
            Err(e) if e.kind() == io::ErrorKind::PermissionDenied => {
                eprintln!("not privileged, skipping: {e}");
                return;
            }
            Err(e) => panic!("{e}"),
        };
        let listener = TcpListener::bind("0.0.0.0:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        std::thread::spawn(move || for _ in listener.incoming() {});
        let blocked: IpAddr = "127.0.0.2".parse().unwrap();
        let target = std::net::SocketAddr::new(blocked, port);
        let timeout = std::time::Duration::from_secs(2);

        enforcer.block_ip(1, blocked).unwrap();
        assert!(
            TcpStream::connect_timeout(&target, timeout).is_err(),
            "address blocked"
        );
        assert!(
            TcpStream::connect(("127.0.0.1", port)).is_ok(),
            "others untouched"
        );
        enforcer.lift(1).unwrap();
        assert!(
            TcpStream::connect_timeout(&target, timeout).is_ok(),
            "lifted"
        );

        let curl = PathBuf::from(std::env::var("SystemRoot").unwrap()).join(r"System32\curl.exe");
        let url = format!("http://127.0.0.1:{port}/");
        // 7: couldn't connect.
        let run = || {
            std::process::Command::new(&curl)
                .args(["-s", "-m", "3", &url])
                .status()
                .unwrap()
                .code()
        };
        enforcer.block_app(2, std::slice::from_ref(&curl)).unwrap();
        assert_eq!(run(), Some(7), "blocked program refused");
        assert!(
            TcpStream::connect(("127.0.0.1", port)).is_ok(),
            "we are not blocked"
        );
        enforcer.lift(2).unwrap();
        assert_ne!(run(), Some(7), "lifted");
    }
}

#[cfg(target_os = "macos")]
mod platform {
    use std::process::{Command, Stdio};

    use super::*;

    /// Evaluated by the stock /etc/pf.conf (`anchor "com.apple/*"`), so the system
    /// configuration is never edited.
    const ANCHOR: &str = "com.apple/250.spectraNET";
    const TABLE: &str = "spectranet_blocked";

    struct Pf {
        /// Reference returned by `pfctl -E`: pf stays enabled while we hold it.
        token: Option<String>,
        ips: Holders<IpAddr>,
    }

    fn pfctl(args: &[&str], input: Option<&str>) -> io::Result<String> {
        let mut child = Command::new("/sbin/pfctl")
            .args(args)
            .stdin(if input.is_some() {
                Stdio::piped()
            } else {
                Stdio::null()
            })
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()?;
        if let (Some(text), Some(mut stdin)) = (input, child.stdin.take()) {
            use std::io::Write;
            stdin.write_all(text.as_bytes())?;
        }
        let out = child.wait_with_output()?;
        let stderr = String::from_utf8_lossy(&out.stderr).to_string();
        if out.status.success() {
            Ok(stderr + &String::from_utf8_lossy(&out.stdout))
        } else if stderr.contains("Permission denied") || stderr.contains("Operation not permitted")
        {
            Err(io::Error::new(io::ErrorKind::PermissionDenied, stderr))
        } else {
            Err(io::Error::other(format!(
                "pfctl {}: {}",
                args.join(" "),
                stderr.trim()
            )))
        }
    }

    pub fn start() -> io::Result<Box<dyn Enforcer>> {
        // Leftovers of a previous run that could not clean up.
        let _ = pfctl(&["-a", ANCHOR, "-F", "all"], None);
        let rules = format!(
            "table <{TABLE}> persist\n\
             block drop out quick to <{TABLE}>\n\
             block drop in quick from <{TABLE}>\n"
        );
        pfctl(&["-a", ANCHOR, "-f", "-"], Some(&rules))?;
        let enabled = pfctl(&["-E"], None)?;
        let token = enabled
            .lines()
            .find_map(|l| l.trim().strip_prefix("Token :"))
            .map(|t| t.trim().to_string());
        Ok(Box::new(Pf {
            token,
            ips: Holders::default(),
        }))
    }

    impl Drop for Pf {
        fn drop(&mut self) {
            let _ = pfctl(&["-a", ANCHOR, "-F", "all"], None);
            if let Some(token) = &self.token {
                let _ = pfctl(&["-X", token], None);
            }
        }
    }

    impl Enforcer for Pf {
        fn method(&self) -> &'static str {
            "pf, following the application's addresses"
        }

        fn app_blocking(&self) -> AppBlocking {
            AppBlocking::Following
        }

        fn block_app(&mut self, _: u64, _: &[PathBuf]) -> io::Result<()> {
            Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "pf blocks addresses, not applications",
            ))
        }

        fn block_ip(&mut self, id: u64, ip: IpAddr) -> io::Result<()> {
            if self.ips.contains(id, &ip) {
                return Ok(());
            }
            let text = ip.to_string();
            if self.ips.add(id, ip) {
                if let Err(e) = pfctl(&["-a", ANCHOR, "-t", TABLE, "-T", "add", &text], None) {
                    if let Some(keys) = self.ips.by_id.get_mut(&id) {
                        keys.retain(|x| *x != ip);
                    }
                    return Err(e);
                }
                // Established connections keep their pf state: end them.
                let any = if ip.is_ipv4() { "0.0.0.0/0" } else { "::/0" };
                let _ = pfctl(&["-k", any, "-k", &text], None);
                let _ = pfctl(&["-k", &text], None);
            }
            Ok(())
        }

        fn lift(&mut self, id: u64) -> io::Result<()> {
            for ip in self.ips.remove(id) {
                let _ = pfctl(
                    &["-a", ANCHOR, "-t", TABLE, "-T", "delete", &ip.to_string()],
                    None,
                );
            }
            Ok(())
        }
    }
}

#[cfg(all(test, target_os = "macos"))]
mod macos_tests {
    use super::*;

    /// Live (root): a blocked address can't be reached; lifting restores it; dropping the
    /// enforcer leaves pf as it was. Run with: sudo cargo test -p spectranet-capture block
    #[test]
    fn blocks_an_address_live() {
        // SAFETY: plain query.
        #[allow(unsafe_code)]
        if unsafe { libc::geteuid() } != 0 {
            eprintln!("not root, skipping");
            return;
        }
        let mut enforcer = start().unwrap();
        assert_eq!(enforcer.app_blocking(), AppBlocking::Following);
        let reach = || {
            std::process::Command::new("/usr/bin/curl")
                .args(["-s", "-m", "4", "-o", "/dev/null", "https://1.1.1.1"])
                .status()
                .unwrap()
                .code()
        };
        assert_eq!(reach(), Some(0), "reachable before");
        enforcer.block_ip(1, "1.1.1.1".parse().unwrap()).unwrap();
        assert_ne!(reach(), Some(0), "blocked");
        enforcer.lift(1).unwrap();
        assert_eq!(reach(), Some(0), "lifted");
        enforcer.block_ip(2, "1.1.1.1".parse().unwrap()).unwrap();
        drop(enforcer);
        assert_eq!(reach(), Some(0), "nothing left behind");
    }
}

#[cfg(not(any(target_os = "linux", target_os = "macos", windows)))]
mod platform {
    use super::*;

    pub fn start() -> io::Result<Box<dyn Enforcer>> {
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "blocking is not supported on this system",
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn shared_items_stay_until_their_last_block_goes() {
        let mut h = Holders::default();
        assert!(h.add(1, "a"));
        assert!(h.add(1, "b"));
        assert!(!h.add(2, "a"), "already in force");
        assert!(h.contains(2, &"a"));
        assert_eq!(h.remove(1), ["b"], "a is still held by block 2");
        assert_eq!(h.remove(2), ["a"]);
        assert!(h.remove(3).is_empty());
    }
}
