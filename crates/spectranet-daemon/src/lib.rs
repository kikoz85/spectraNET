//! The spectraNET background service (`snetd`): the same service on macOS, Linux (Unix
//! socket; launchd or systemd) and Windows (named pipe; Service Control Manager).

pub mod actions;
pub mod alerts;
pub mod blocks;
pub mod cli;
pub mod config;
#[cfg(unix)]
pub mod install;
#[cfg(unix)]
pub mod man;
pub mod metrics;
pub mod service;
pub mod transport;
pub mod usage;
#[cfg(windows)]
pub mod winsvc;
#[cfg(windows)]
pub mod winusers;

use std::sync::atomic::AtomicBool;
use std::time::Duration;

use anyhow::Result;
use spectranet_capture::mock::MockSource;
use spectranet_capture::{SourceOptions, TrafficSource, system_source};

use crate::cli::RunArgs;
use crate::service::Config;

/// Runs the service until `stop` is set. `mock` serves simulated traffic.
pub fn run_live(mock: bool, args: &RunArgs, stop: &AtomicBool) -> Result<()> {
    let privileged = is_privileged();
    if !privileged && !mock {
        service::log(
            "warning: not running with administrator rights; capture will be limited or fail",
        );
    }
    let source: Box<dyn TrafficSource> = if mock {
        Box::new(MockSource::default())
    } else {
        system_source(SourceOptions {
            resolve_names: true,
            service: true,
        })?
    };
    let file = config::load(&args.data_dir);
    let config = Config {
        policy: actions::Policy {
            elevated_only: file.actions_elevated_only,
        },
        socket: args.socket.clone(),
        database: args
            .database
            .clone()
            .unwrap_or_else(|| args.data_dir.join("usage.sqlite")),
        interval: Duration::from_secs_f64(args.interval),
        flush_every: Duration::from_secs(30),
        socket_group: access_group(privileged),
        feeds_dir: args.data_dir.join(spectranet_proto::FEEDS_SUBDIR),
        update_feeds: !args.no_feed_updates && !mock && file.feed_updates,
        // The command line wins over the configuration file; both default to off.
        metrics: args.metrics.or(file.metrics),
        category_updates: file.category_updates,
        feeds_disabled: file.feeds_disabled.clone(),
        history_days: file.history_days,
        settings: file.settings(),
    };
    service::run(&config, source, stop)
}

/// The administrators' group allowed to use the endpoint (Unix), or a marker restricting
/// the named pipe to Administrators and SYSTEM (Windows).
fn access_group(privileged: bool) -> Option<u32> {
    #[cfg(unix)]
    return if privileged {
        install::admin_gid()
    } else {
        None
    };
    #[cfg(windows)]
    return privileged.then_some(0);
    #[cfg(not(any(unix, windows)))]
    return None;
}

#[cfg(unix)]
fn is_privileged() -> bool {
    // SAFETY: geteuid has no preconditions.
    #[allow(unsafe_code)]
    unsafe {
        libc::geteuid() == 0
    }
}

#[cfg(not(unix))]
fn is_privileged() -> bool {
    // A process that may open the Service Control Manager for creating services is elevated.
    #[cfg(windows)]
    return windows_service::service_manager::ServiceManager::local_computer(
        None::<&str>,
        windows_service::service_manager::ServiceManagerAccess::CREATE_SERVICE,
    )
    .is_ok();
    #[cfg(not(windows))]
    return false;
}
