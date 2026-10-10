//! snetd as a Windows service: registration with the Service Control Manager, the service
//! entry point, and removal.
//!
//! `snetd install` (from an Administrator prompt) copies snetd.exe and snet.exe to
//! `C:\Program Files\spectraNET`, registers the automatic-start service "snetd" running as
//! LocalSystem, and starts it. The service logs to `C:\ProgramData\spectraNET\snetd.log`.

use std::ffi::{OsStr, OsString};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

use anyhow::{Context, Result, bail};
use windows_service::service::{
    ServiceAccess, ServiceControl, ServiceControlAccept, ServiceErrorControl, ServiceExitCode,
    ServiceInfo, ServiceStartType, ServiceState, ServiceStatus, ServiceType,
};
use windows_service::service_control_handler::{self, ServiceControlHandlerResult};
use windows_service::service_manager::{ServiceManager, ServiceManagerAccess};
use windows_service::{define_windows_service, service_dispatcher};

use crate::service;

pub const SERVICE_NAME: &str = "snetd";
const DISPLAY_NAME: &str = "spectraNET network monitor";
const DESCRIPTION: &str =
    "Per-application network monitoring, history and alerts for spectraNET (snet).";
pub const INSTALL_DIR: &str = r"C:\Program Files\spectraNET";

pub fn log_path() -> PathBuf {
    Path::new(spectranet_proto::DEFAULT_DATA_DIR).join("snetd.log")
}

fn manager(access: ServiceManagerAccess) -> Result<ServiceManager> {
    ServiceManager::local_computer(None::<&str>, access).map_err(|e| {
        if format!("{e:?}").contains("Access") || format!("{e}").contains("denied") {
            anyhow::anyhow!("this needs an Administrator command prompt")
        } else {
            anyhow::anyhow!("opening the Service Control Manager: {e}")
        }
    })
}

/// Stops and deletes the service if it exists, waiting until it is really gone.
fn remove_service(manager: &ServiceManager) -> Result<bool> {
    let access = ServiceAccess::QUERY_STATUS | ServiceAccess::STOP | ServiceAccess::DELETE;
    let Ok(service) = manager.open_service(SERVICE_NAME, access) else {
        return Ok(false);
    };
    if service.query_status()?.current_state != ServiceState::Stopped {
        let _ = service.stop();
        let deadline = Instant::now() + Duration::from_secs(20);
        while service.query_status()?.current_state != ServiceState::Stopped {
            if Instant::now() > deadline {
                bail!("the running snetd service did not stop");
            }
            std::thread::sleep(Duration::from_millis(250));
        }
    }
    service.delete()?;
    drop(service);
    // Deletion completes once every handle is closed; wait for the name to be free.
    let deadline = Instant::now() + Duration::from_secs(10);
    while manager
        .open_service(SERVICE_NAME, ServiceAccess::QUERY_STATUS)
        .is_ok()
    {
        if Instant::now() > deadline {
            break;
        }
        std::thread::sleep(Duration::from_millis(200));
    }
    Ok(true)
}

/// The data folder holds the history and the list of allowed users: writable by SYSTEM and
/// Administrators only (ProgramData would otherwise let any user create files in it).
fn protect_data_dir() {
    let dir = spectranet_proto::DEFAULT_DATA_DIR;
    // Well-known SIDs, so this works whatever the system language. The folder gets an
    // explicit, non-inherited list; everything inside goes back to inheriting from it.
    let run = |args: &[&str]| {
        std::process::Command::new("icacls")
            .args(args)
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .status()
            .is_ok_and(|s| s.success())
    };
    let folder = run(&[
        dir,
        "/inheritance:r",
        "/grant:r",
        "*S-1-5-18:(OI)(CI)F",
        "*S-1-5-32-544:(OI)(CI)F",
        "*S-1-5-32-545:(OI)(CI)RX",
        "/Q",
    ]);
    let contents = run(&[&format!(r"{dir}\*"), "/reset", "/T", "/C", "/Q"]);
    if !(folder && contents) {
        println!("warning: could not restrict the permissions of {dir}");
    }
}

/// Case-insensitive path comparison, as Windows paths are.
trait SamePath {
    fn eq_ignore_ascii_case_path(&self, other: &Path) -> bool;
}

impl SamePath for PathBuf {
    fn eq_ignore_ascii_case_path(&self, other: &Path) -> bool {
        self.to_string_lossy()
            .trim_end_matches('\\')
            .eq_ignore_ascii_case(other.to_string_lossy().trim_end_matches('\\'))
    }
}

/// Copies to a temporary name, then renames: a binary is never half-written.
fn copy_atomically(from: &Path, to: &Path) -> Result<()> {
    let tmp = to.with_extension("exe.tmp");
    std::fs::copy(from, &tmp).with_context(|| format!("copying {}", from.display()))?;
    std::fs::rename(&tmp, to).with_context(|| format!("installing {}", to.display()))?;
    Ok(())
}

/// Applies new settings: restarts the registered service (nothing to do when there is none).
pub fn restart() -> Result<()> {
    let manager = manager(ServiceManagerAccess::CONNECT)?;
    let access = ServiceAccess::QUERY_STATUS | ServiceAccess::STOP | ServiceAccess::START;
    let Ok(service) = manager.open_service(SERVICE_NAME, access) else {
        return Ok(());
    };
    if service.query_status()?.current_state != ServiceState::Stopped {
        let _ = service.stop();
        let deadline = Instant::now() + Duration::from_secs(20);
        while service.query_status()?.current_state != ServiceState::Stopped {
            if Instant::now() > deadline {
                bail!("the running snetd service did not stop");
            }
            std::thread::sleep(Duration::from_millis(250));
        }
    }
    service
        .start::<&OsStr>(&[])
        .context("starting the snetd service")?;
    println!("snetd restarted");
    Ok(())
}

pub fn install() -> Result<()> {
    let manager = manager(ServiceManagerAccess::CONNECT | ServiceManagerAccess::CREATE_SERVICE)?;
    let here = std::env::current_exe()?;
    let dir = here.parent().context("locating snetd.exe")?.to_path_buf();
    let target_dir = PathBuf::from(INSTALL_DIR);
    // Run from the installed folder (the setup program does that), only register.
    let in_place = dir.eq_ignore_ascii_case_path(&target_dir);
    if remove_service(&manager)? {
        println!("stopped and removed the previous snetd service");
    }
    std::fs::create_dir_all(&target_dir)?;
    let daemon = target_dir.join("snetd.exe");
    if !in_place {
        copy_atomically(&here, &daemon)?;
        println!("installed {}", daemon.display());
        let cli = dir.join("snet.exe");
        if cli.exists() {
            copy_atomically(&cli, &target_dir.join("snet.exe"))?;
            println!("installed {}", target_dir.join("snet.exe").display());
        }
    }
    std::fs::create_dir_all(spectranet_proto::DEFAULT_DATA_DIR)?;
    protect_data_dir();
    match crate::winusers::authorize_current_users() {
        Ok(sids) => println!(
            "{} user account(s) may use snet and spectraNET without elevation",
            sids.len()
        ),
        Err(e) => println!("warning: could not record the allowed users: {e}"),
    }

    let info = ServiceInfo {
        name: OsString::from(SERVICE_NAME),
        display_name: OsString::from(DISPLAY_NAME),
        service_type: ServiceType::OWN_PROCESS,
        start_type: ServiceStartType::AutoStart,
        error_control: ServiceErrorControl::Normal,
        executable_path: daemon,
        launch_arguments: vec![OsString::from("service")],
        dependencies: vec![],
        account_name: None, // LocalSystem
        account_password: None,
    };
    let service = manager
        .create_service(
            &info,
            ServiceAccess::CHANGE_CONFIG | ServiceAccess::START | ServiceAccess::QUERY_STATUS,
        )
        .context("registering the snetd service")?;
    service.set_description(DESCRIPTION)?;
    service
        .start::<&OsStr>(&[])
        .context("starting the snetd service")?;

    let pipe = Path::new(spectranet_proto::DEFAULT_SOCKET);
    let deadline = Instant::now() + Duration::from_secs(15);
    while spectranet_proto::Client::connect(pipe, Duration::from_secs(1)).is_err() {
        if Instant::now() > deadline {
            bail!(
                "the service was registered but did not start; see {}",
                log_path().display()
            );
        }
        std::thread::sleep(Duration::from_millis(200));
    }
    println!("snetd is running. Try: snet status");
    println!("(add {INSTALL_DIR} to PATH to run snet from any prompt)");
    Ok(())
}

pub fn uninstall(purge: bool) -> Result<()> {
    let manager = manager(ServiceManagerAccess::CONNECT)?;
    if remove_service(&manager)? {
        println!("removed the snetd service");
    }
    // Run by the setup program's uninstaller from the installed folder: the files are its
    // to remove (and a running executable can't delete itself).
    let here = std::env::current_exe()?;
    if here.parent().is_some_and(|d| {
        d.to_path_buf()
            .eq_ignore_ascii_case_path(Path::new(INSTALL_DIR))
    }) {
        return Ok(());
    }
    for file in ["snetd.exe", "snet.exe"] {
        let path = Path::new(INSTALL_DIR).join(file);
        if path.exists() {
            std::fs::remove_file(&path).with_context(|| format!("removing {}", path.display()))?;
            println!("removed {}", path.display());
        }
    }
    let _ = std::fs::remove_dir(INSTALL_DIR);
    if purge && Path::new(spectranet_proto::DEFAULT_DATA_DIR).exists() {
        std::fs::remove_dir_all(spectranet_proto::DEFAULT_DATA_DIR)?;
        println!("removed {}", spectranet_proto::DEFAULT_DATA_DIR);
    } else if Path::new(spectranet_proto::DEFAULT_DATA_DIR).exists() {
        println!(
            "kept usage history in {} (use --purge to delete it)",
            spectranet_proto::DEFAULT_DATA_DIR
        );
    }
    Ok(())
}

define_windows_service!(ffi_service_main, service_main);

/// Hands the process over to the Service Control Manager (`snetd service`).
pub fn dispatch() -> Result<()> {
    service_dispatcher::start(SERVICE_NAME, ffi_service_main)
        .context("snetd service must be started by Windows")
}

fn service_main(_arguments: Vec<OsString>) {
    let _ = std::fs::create_dir_all(spectranet_proto::DEFAULT_DATA_DIR);
    service::set_log_file(&log_path());
    if let Err(e) = run_service() {
        service::log(&format!("service failed: {e:#}"));
    }
}

fn run_service() -> Result<()> {
    let stop = Arc::new(AtomicBool::new(false));
    let handler_stop = stop.clone();
    let status = service_control_handler::register(SERVICE_NAME, move |control| match control {
        ServiceControl::Stop | ServiceControl::Shutdown => {
            handler_stop.store(true, Ordering::Relaxed);
            ServiceControlHandlerResult::NoError
        }
        ServiceControl::Interrogate => ServiceControlHandlerResult::NoError,
        _ => ServiceControlHandlerResult::NotImplemented,
    })?;
    let report = |state: ServiceState, code: u32| {
        let _ = status.set_service_status(ServiceStatus {
            service_type: ServiceType::OWN_PROCESS,
            current_state: state,
            controls_accepted: if state == ServiceState::Running {
                ServiceControlAccept::STOP | ServiceControlAccept::SHUTDOWN
            } else {
                ServiceControlAccept::empty()
            },
            exit_code: ServiceExitCode::Win32(code),
            checkpoint: 0,
            wait_hint: Duration::from_secs(10),
            process_id: None,
        });
    };
    report(ServiceState::Running, 0);
    let result = crate::run_live(false, &crate::cli::RunArgs::service_defaults(), &stop);
    report(ServiceState::Stopped, u32::from(result.is_err()));
    result
}
