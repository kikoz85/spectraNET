//! Bindings to Apple's private NetworkStatistics framework — the data source behind `nettop(1)`.
//!
//! The kernel keeps per-socket byte counters and exposes them, without root, through this
//! framework. It is undocumented, so it is loaded at run time: if a future macOS changes or
//! removes it, `snet` reports a clear error instead of failing to start.
//!
//! Model: a *manager* delivers one *source* per TCP/UDP socket. Two kinds of query exist:
//! a *description* query yields the full property dictionary (PID, process name, addresses,
//! TCP state, byte counters), while a cheaper *counts* query yields only the counters.
//! Descriptions are fetched once per new socket, counts on every refresh. All callbacks run
//! on a private serial dispatch queue; results are collected in [`Shared`] behind a mutex.

use std::collections::HashMap;
use std::ffi::{CStr, c_char, c_void};
use std::net::SocketAddr;
use std::ptr;
use std::sync::{Arc, Mutex, mpsc};
use std::time::Duration;

use block2::{Block, RcBlock};
use libloading::Library;
use spectranet_model::Transport;

use super::sockaddr;

const FRAMEWORK: &str =
    "/System/Library/PrivateFrameworks/NetworkStatistics.framework/NetworkStatistics";

type CFTypeRef = *const c_void;
type ManagerRef = *mut c_void;
type SourceRef = *mut c_void;
type DispatchQueue = *mut c_void;

const UTF8: u32 = 0x0800_0100;
const CF_NUMBER_SINT64: isize = 4;

#[link(name = "CoreFoundation", kind = "framework")]
unsafe extern "C" {
    fn CFStringCreateWithCString(alloc: CFTypeRef, s: *const c_char, encoding: u32) -> CFTypeRef;
    fn CFStringGetCString(s: CFTypeRef, buf: *mut c_char, size: isize, encoding: u32) -> u8;
    fn CFStringGetTypeID() -> usize;
    fn CFNumberGetValue(n: CFTypeRef, number_type: isize, out: *mut c_void) -> u8;
    fn CFNumberGetTypeID() -> usize;
    fn CFDataGetLength(d: CFTypeRef) -> isize;
    fn CFDataGetBytePtr(d: CFTypeRef) -> *const u8;
    fn CFDataGetTypeID() -> usize;
    fn CFDictionaryGetValue(dict: CFTypeRef, key: CFTypeRef) -> CFTypeRef;
    fn CFGetTypeID(cf: CFTypeRef) -> usize;
    fn CFRelease(cf: CFTypeRef);
}

unsafe extern "C" {
    fn dispatch_queue_create(label: *const c_char, attr: *const c_void) -> DispatchQueue;
    fn dispatch_async(queue: DispatchQueue, block: &Block<dyn Fn()>);
    fn dispatch_sync(queue: DispatchQueue, block: &Block<dyn Fn()>);
    fn dispatch_release(object: *mut c_void);
}

/// Entry points resolved from the framework.
struct Api {
    _library: Library,
    manager_create: unsafe extern "C" fn(
        CFTypeRef,
        DispatchQueue,
        &Block<dyn Fn(SourceRef, *mut c_void)>,
    ) -> ManagerRef,
    manager_destroy: unsafe extern "C" fn(ManagerRef),
    add_all_tcp: unsafe extern "C" fn(ManagerRef),
    add_all_udp: unsafe extern "C" fn(ManagerRef),
    query_all_sources: unsafe extern "C" fn(ManagerRef, &Block<dyn Fn()>),
    query_all_descriptions: unsafe extern "C" fn(ManagerRef, &Block<dyn Fn()>),
    set_counts_block: unsafe extern "C" fn(SourceRef, &Block<dyn Fn(CFTypeRef)>),
    set_description_block: unsafe extern "C" fn(SourceRef, &Block<dyn Fn(CFTypeRef)>),
    set_removed_block: unsafe extern "C" fn(SourceRef, &Block<dyn Fn()>),
    query_description: unsafe extern "C" fn(SourceRef),
}

impl Api {
    fn load() -> Result<Self, String> {
        // SAFETY: loading a system framework runs only Apple's own initialisers.
        let library = unsafe { Library::new(FRAMEWORK) }.map_err(|e| e.to_string())?;
        macro_rules! sym {
            ($name:literal) => {
                // SAFETY: the declared signature matches the framework's C ABI, verified
                // against the system `nettop` behaviour on macOS 27.
                *unsafe { library.get(concat!($name, "\0").as_bytes()) }
                    .map_err(|e| format!("{}: {e}", $name))?
            };
        }
        Ok(Self {
            manager_create: sym!("NStatManagerCreate"),
            manager_destroy: sym!("NStatManagerDestroy"),
            add_all_tcp: sym!("NStatManagerAddAllTCP"),
            add_all_udp: sym!("NStatManagerAddAllUDP"),
            query_all_sources: sym!("NStatManagerQueryAllSources"),
            query_all_descriptions: sym!("NStatManagerQueryAllSourcesDescriptions"),
            set_counts_block: sym!("NStatSourceSetCountsBlock"),
            set_description_block: sym!("NStatSourceSetDescriptionBlock"),
            set_removed_block: sym!("NStatSourceSetRemovedBlock"),
            query_description: sym!("NStatSourceQueryDescription"),
            _library: library,
        })
    }
}

/// Dictionary keys, created once. CFStrings are immutable and safe to share across threads.
struct Keys {
    provider: CFTypeRef,
    pid: CFTypeRef,
    process_name: CFTypeRef,
    local: CFTypeRef,
    remote: CFTypeRef,
    tcp_state: CFTypeRef,
    rx_bytes: CFTypeRef,
    tx_bytes: CFTypeRef,
    rx_packets: CFTypeRef,
    tx_packets: CFTypeRef,
    start_time: CFTypeRef,
}

// SAFETY: the fields are immutable CFStrings, which CoreFoundation documents as thread-safe.
unsafe impl Send for Keys {}
unsafe impl Sync for Keys {}

impl Keys {
    fn new() -> Self {
        let make = |s: &CStr| unsafe { CFStringCreateWithCString(ptr::null(), s.as_ptr(), UTF8) };
        Self {
            provider: make(c"provider"),
            pid: make(c"processID"),
            process_name: make(c"processName"),
            local: make(c"localAddress"),
            remote: make(c"remoteAddress"),
            tcp_state: make(c"TCPState"),
            rx_bytes: make(c"rxBytes"),
            tx_bytes: make(c"txBytes"),
            rx_packets: make(c"rxPackets"),
            tx_packets: make(c"txPackets"),
            start_time: make(c"startAbsoluteTime"),
        }
    }
}

impl Drop for Keys {
    fn drop(&mut self) {
        for key in [
            self.provider,
            self.pid,
            self.process_name,
            self.local,
            self.remote,
            self.tcp_state,
            self.rx_bytes,
            self.tx_bytes,
            self.rx_packets,
            self.tx_packets,
            self.start_time,
        ] {
            if !key.is_null() {
                // SAFETY: each key was created by us with a +1 retain count.
                unsafe { CFRelease(key) };
            }
        }
    }
}

/// One socket as last reported by the kernel.
#[derive(Debug, Clone)]
pub struct RawFlow {
    pub pid: u32,
    pub process_name: String,
    pub transport: Transport,
    pub local: SocketAddr,
    pub remote: SocketAddr,
    /// TCP state name (`Established`, `Listen`, ...); `None` for UDP.
    pub tcp_state: Option<String>,
    /// Bytes received over the socket's lifetime.
    pub rx_bytes: u64,
    /// Bytes sent over the socket's lifetime.
    pub tx_bytes: u64,
    /// Packets received and sent over the socket's lifetime.
    pub rx_packets: u64,
    pub tx_packets: u64,
    /// Socket creation time in `mach_absolute_time` units.
    pub start_time: u64,
}

#[derive(Default)]
struct Tracked {
    flow: Option<RawFlow>,
    removed: bool,
}

#[derive(Default)]
struct Shared {
    /// Keyed by a sequence number assigned at registration, never by the source pointer:
    /// the framework reuses the memory of a closed socket for the next one, and a pointer key
    /// would let a new socket overwrite the final counters of the old one.
    sources: Mutex<HashMap<u64, Tracked>>,
    next_id: std::sync::atomic::AtomicU64,
}

/// A live connection to the kernel's network statistics.
pub struct NStat {
    api: Arc<Api>,
    manager: ManagerRef,
    queue: DispatchQueue,
    shared: Arc<Shared>,
}

impl NStat {
    pub fn open() -> Result<Self, String> {
        let api = Arc::new(Api::load()?);
        let keys = Arc::new(Keys::new());
        let shared = Arc::new(Shared::default());

        // SAFETY: a plain serial queue; released in Drop.
        let queue = unsafe { dispatch_queue_create(c"net.spectranet.nstat".as_ptr(), ptr::null()) };

        let on_source = {
            let (api, keys, shared) = (api.clone(), keys.clone(), shared.clone());
            RcBlock::new(move |source: SourceRef, _: *mut c_void| {
                register_source(&api, &keys, &shared, source);
            })
        };

        // SAFETY: the framework copies the block; the queue outlives the manager.
        let manager = unsafe { (api.manager_create)(ptr::null(), queue, &on_source) };
        if manager.is_null() {
            unsafe { dispatch_release(queue) };
            return Err("NStatManagerCreate returned null".into());
        }
        // SAFETY: valid manager; registration happens on its queue, as nettop does.
        let api_on_queue = api.clone();
        let manager_addr = manager as usize;
        let setup = RcBlock::new(move || unsafe {
            (api_on_queue.add_all_tcp)(manager_addr as ManagerRef);
            (api_on_queue.add_all_udp)(manager_addr as ManagerRef);
        });
        unsafe { dispatch_sync(queue, &setup) };

        Ok(Self {
            api,
            manager,
            queue,
            shared,
        })
    }

    /// Asks the kernel for fresh counters on every socket and returns the result.
    ///
    /// Sockets closed since the previous call are returned one last time with `removed = true`
    /// and then forgotten. Sockets whose description has not arrived yet are omitted.
    pub fn refresh(&self, timeout: Duration) -> Result<Vec<(u64, RawFlow, bool)>, String> {
        let (done_tx, done_rx) = mpsc::sync_channel::<()>(1);
        let api = self.api.clone();
        let shared = self.shared.clone();
        let manager_addr = self.manager as usize;
        let query = RcBlock::new(move || {
            let manager = manager_addr as ManagerRef;
            let done_tx = done_tx.clone();
            let api_counts = api.clone();
            let query_counts = RcBlock::new(move || {
                let done_tx = done_tx.clone();
                let completion = RcBlock::new(move || {
                    let _ = done_tx.try_send(());
                });
                // SAFETY: valid manager, called on its own queue.
                unsafe { (api_counts.query_all_sources)(manager, &completion) };
            });
            let undescribed = shared
                .sources
                .lock()
                .is_ok_and(|s| s.values().any(|t| t.flow.is_none() && !t.removed));
            // SAFETY: valid manager, called on its own queue; completions run on it too.
            unsafe {
                if undescribed {
                    (api.query_all_descriptions)(manager, &query_counts);
                } else {
                    query_counts.call(());
                }
            }
        });
        // SAFETY: dispatch copies the block before returning.
        unsafe { dispatch_async(self.queue, &query) };
        done_rx
            .recv_timeout(timeout)
            .map_err(|_| "timed out waiting for kernel network statistics".to_string())?;

        let mut sources = self
            .shared
            .sources
            .lock()
            .map_err(|_| "state lock poisoned")?;
        let result = sources
            .iter()
            .filter_map(|(key, t)| t.flow.clone().map(|f| (*key, f, t.removed)))
            .collect();
        sources.retain(|_, t| !t.removed);
        Ok(result)
    }
}

impl Drop for NStat {
    fn drop(&mut self) {
        let api = self.api.clone();
        let manager_addr = self.manager as usize;
        let destroy =
            RcBlock::new(move || unsafe { (api.manager_destroy)(manager_addr as ManagerRef) });
        // SAFETY: destroy on the manager's own queue so no callback runs concurrently,
        // then release the queue we created.
        unsafe {
            dispatch_sync(self.queue, &destroy);
            dispatch_release(self.queue);
        }
    }
}

// SAFETY: the manager and queue are only touched through dispatch onto the serial queue
// (or in Drop, which also syncs onto it); shared state is behind a mutex.
unsafe impl Send for NStat {}

/// Called on the manager's queue for every new socket.
fn register_source(api: &Arc<Api>, keys: &Arc<Keys>, shared: &Arc<Shared>, source: SourceRef) {
    let id = shared
        .next_id
        .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    if let Ok(mut sources) = shared.sources.lock() {
        sources.insert(id, Tracked::default());
    }

    let on_description = {
        let (keys, shared) = (keys.clone(), shared.clone());
        RcBlock::new(move |dict: CFTypeRef| {
            // SAFETY: the framework passes a valid CFDictionary for the call's duration.
            let Some(flow) = (unsafe { parse_description(&keys, dict) }) else {
                return;
            };
            if let Ok(mut sources) = shared.sources.lock() {
                sources.entry(id).or_default().flow = Some(flow);
            }
        })
    };
    let on_counts = {
        let (keys, shared) = (keys.clone(), shared.clone());
        RcBlock::new(move |dict: CFTypeRef| {
            let Ok(mut sources) = shared.sources.lock() else {
                return;
            };
            if let Some(flow) = sources.get_mut(&id).and_then(|t| t.flow.as_mut()) {
                // SAFETY: the framework passes a valid CFDictionary for the call's duration.
                unsafe { update_counts(&keys, dict, flow) };
            }
        })
    };
    let on_removed = {
        let shared = shared.clone();
        RcBlock::new(move || {
            if let Ok(mut sources) = shared.sources.lock() {
                sources.entry(id).or_default().removed = true;
            }
        })
    };
    // SAFETY: `source` is valid inside this callback; the framework copies the blocks.
    unsafe {
        (api.set_description_block)(source, &on_description);
        (api.set_counts_block)(source, &on_counts);
        (api.set_removed_block)(source, &on_removed);
        // Ask for the description right away: a connection may live only a few milliseconds.
        // Combined with the final counts the kernel delivers just before removal, even such
        // short connections are attributed with their exact byte totals.
        (api.query_description)(source);
    }
}

/// Extracts a [`RawFlow`] from a source's description dictionary.
///
/// # Safety
/// `dict` must be a valid CFDictionary.
unsafe fn parse_description(keys: &Keys, dict: CFTypeRef) -> Option<RawFlow> {
    unsafe {
        let transport = match cf_string(CFDictionaryGetValue(dict, keys.provider))?.as_str() {
            "TCP" => Transport::Tcp,
            "UDP" => Transport::Udp,
            _ => return None,
        };
        Some(RawFlow {
            pid: u32::try_from(cf_i64(CFDictionaryGetValue(dict, keys.pid))?).ok()?,
            process_name: cf_string(CFDictionaryGetValue(dict, keys.process_name))
                .unwrap_or_default(),
            transport,
            local: sockaddr::parse(cf_data(CFDictionaryGetValue(dict, keys.local))?)?,
            remote: sockaddr::parse(cf_data(CFDictionaryGetValue(dict, keys.remote))?)?,
            tcp_state: cf_string(CFDictionaryGetValue(dict, keys.tcp_state)),
            rx_bytes: cf_i64(CFDictionaryGetValue(dict, keys.rx_bytes))
                .unwrap_or(0)
                .max(0) as u64,
            tx_bytes: cf_i64(CFDictionaryGetValue(dict, keys.tx_bytes))
                .unwrap_or(0)
                .max(0) as u64,
            rx_packets: cf_i64(CFDictionaryGetValue(dict, keys.rx_packets))
                .unwrap_or(0)
                .max(0) as u64,
            tx_packets: cf_i64(CFDictionaryGetValue(dict, keys.tx_packets))
                .unwrap_or(0)
                .max(0) as u64,
            start_time: cf_i64(CFDictionaryGetValue(dict, keys.start_time))
                .unwrap_or(0)
                .max(0) as u64,
        })
    }
}

/// Refreshes the byte counters (and TCP state, when present) from a counts dictionary.
///
/// # Safety
/// `dict` must be a valid CFDictionary.
unsafe fn update_counts(keys: &Keys, dict: CFTypeRef, flow: &mut RawFlow) {
    unsafe {
        if let Some(rx) = cf_i64(CFDictionaryGetValue(dict, keys.rx_bytes)) {
            flow.rx_bytes = rx.max(0) as u64;
        }
        if let Some(tx) = cf_i64(CFDictionaryGetValue(dict, keys.tx_bytes)) {
            flow.tx_bytes = tx.max(0) as u64;
        }
        if let Some(rx) = cf_i64(CFDictionaryGetValue(dict, keys.rx_packets)) {
            flow.rx_packets = rx.max(0) as u64;
        }
        if let Some(tx) = cf_i64(CFDictionaryGetValue(dict, keys.tx_packets)) {
            flow.tx_packets = tx.max(0) as u64;
        }
        if let Some(state) = cf_string(CFDictionaryGetValue(dict, keys.tcp_state)) {
            flow.tcp_state = Some(state);
        }
    }
}

/// # Safety
/// `value` must be null or a valid CF object.
unsafe fn cf_string(value: CFTypeRef) -> Option<String> {
    unsafe {
        if value.is_null() || CFGetTypeID(value) != CFStringGetTypeID() {
            return None;
        }
        let mut buf = [0 as c_char; 1024];
        if CFStringGetCString(value, buf.as_mut_ptr(), buf.len() as isize, UTF8) == 0 {
            return None;
        }
        Some(CStr::from_ptr(buf.as_ptr()).to_string_lossy().into_owned())
    }
}

/// # Safety
/// `value` must be null or a valid CF object.
unsafe fn cf_i64(value: CFTypeRef) -> Option<i64> {
    unsafe {
        if value.is_null() || CFGetTypeID(value) != CFNumberGetTypeID() {
            return None;
        }
        let mut out: i64 = 0;
        CFNumberGetValue(value, CF_NUMBER_SINT64, (&mut out as *mut i64).cast());
        Some(out)
    }
}

/// # Safety
/// `value` must be null or a valid CF object that outlives the returned slice.
unsafe fn cf_data<'a>(value: CFTypeRef) -> Option<&'a [u8]> {
    unsafe {
        if value.is_null() || CFGetTypeID(value) != CFDataGetTypeID() {
            return None;
        }
        let len = usize::try_from(CFDataGetLength(value)).ok()?;
        let bytes = CFDataGetBytePtr(value);
        if bytes.is_null() {
            return None;
        }
        Some(std::slice::from_raw_parts(bytes, len))
    }
}
