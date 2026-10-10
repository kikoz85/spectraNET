//! Traffic sources: the platform backends that observe per-process network usage.
//!
//! Every backend implements [`TrafficSource`]. Callers sample it repeatedly; each call
//! returns the rates measured since the previous call.

use spectranet_model::Snapshot;

pub mod block;
pub mod control;
#[cfg(target_os = "linux")]
mod linux;
#[cfg(target_os = "macos")]
mod macos;
pub mod mock;
pub mod resources;
#[cfg(windows)]
mod windows;
// ETW event accounting for Windows: pure logic, compiled everywhere so it is tested in CI.
pub mod names;
#[cfg_attr(not(windows), allow(dead_code))]
#[path = "windows/accounting.rs"]
mod windows_accounting;

/// Errors raised while observing traffic.
#[derive(Debug, thiserror::Error)]
pub enum CaptureError {
    #[error("live capture is not available on this platform yet (try --mock)")]
    Unsupported,
    #[error("insufficient privileges: {0}")]
    PermissionDenied(String),
    #[error("capture backend failed: {0}")]
    Backend(String),
}

/// A source of per-process traffic snapshots.
pub trait TrafficSource: Send {
    /// Short identifier of the backend, copied into [`Snapshot::source`].
    fn name(&self) -> &'static str;

    /// Returns the traffic observed since the previous call.
    ///
    /// The first call establishes a baseline: its rates may be zero for backends that only
    /// see cumulative counters, so callers wanting meaningful rates sample twice.
    fn sample(&mut self) -> Result<Snapshot, CaptureError>;

    /// Human-readable remarks about degraded operation (e.g. hostnames unavailable without
    /// root). Empty when everything works.
    fn notices(&self) -> Vec<String> {
        Vec::new()
    }

    /// True when the very first sample already carries rates over a full interval (e.g. a
    /// source fed by a service that samples continuously), so callers need not wait.
    fn first_sample_has_rates(&self) -> bool {
        false
    }
}

/// How a live source should behave.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SourceOptions {
    /// Discover hostnames by observing DNS answers and TLS handshakes (needs root).
    pub resolve_names: bool,
    /// This source belongs to the snetd service. On Windows the service owns the
    /// well-known trace session; every other client gets a private one, so starting a client
    /// can never stop the service's capture.
    pub service: bool,
}

impl Default for SourceOptions {
    fn default() -> Self {
        Self {
            resolve_names: true,
            service: false,
        }
    }
}

/// Opens the live capture backend for the current platform.
#[cfg_attr(
    not(any(target_os = "macos", target_os = "linux")),
    allow(unused_variables)
)]
pub fn system_source(options: SourceOptions) -> Result<Box<dyn TrafficSource>, CaptureError> {
    #[cfg(target_os = "macos")]
    let source: Box<dyn TrafficSource> = Box::new(macos::MacosSource::open(options)?);

    #[cfg(target_os = "linux")]
    let source: Box<dyn TrafficSource> = Box::new(linux::LinuxSource::open(options)?);

    #[cfg(windows)]
    let source: Box<dyn TrafficSource> = Box::new(windows::WindowsSource::open(options)?);

    #[cfg(not(any(target_os = "macos", target_os = "linux", windows)))]
    return Err(CaptureError::Unsupported);

    // CPU, memory and parentage alongside the traffic, the same on every platform.
    #[cfg(any(target_os = "macos", target_os = "linux", windows))]
    Ok(Box::new(resources::WithResources::new(source)))
}
