//! Installation as a system service — launchd on macOS, systemd on Linux — and removal.
//!
//! `snetd install` copies `snetd` and, when found next to it, `snet` into /usr/local, writes
//! their man pages, registers the service and starts it. `snetd uninstall` reverses all of
//! that; `--purge` also deletes the usage history (and the log file on macOS).

use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{Duration, Instant};

use anyhow::{Context, Result, bail, ensure};

pub const DAEMON_BIN: &str = "/usr/local/sbin/snetd";
pub const CLI_BIN: &str = "/usr/local/bin/snet";
/// `snetd` on every user's PATH: /usr/local/sbin is not on macOS's default PATH, nor on a
/// normal user's on Debian, so `sudo snetd uninstall` would not be found otherwise.
pub const DAEMON_LINK: &str = "/usr/local/bin/snetd";
pub const MAN1: &str = "/usr/local/share/man/man1";
pub const MAN8: &str = "/usr/local/share/man/man8";
pub const DATA_DIR: &str = spectranet_proto::DEFAULT_DATA_DIR;
#[cfg(target_os = "macos")]
pub const DATABASE: &str = "/Library/Application Support/spectraNET/usage.sqlite";
#[cfg(not(target_os = "macos"))]
pub const DATABASE: &str = "/var/lib/spectranet/usage.sqlite";

#[cfg(target_os = "macos")]
use launchd as platform;
#[cfg(target_os = "macos")]
pub use launchd::{LOG, SERVICE_FILE};
#[cfg(target_os = "linux")]
use systemd as platform;
#[cfg(target_os = "linux")]
pub use systemd::{LOG, SERVICE_FILE};

#[cfg(target_os = "macos")]
pub mod launchd {
    use super::*;

    pub const LABEL: &str = "net.spectranet.snetd";
    pub const SERVICE_FILE: &str = "/Library/LaunchDaemons/net.spectranet.snetd.plist";
    pub const LOG: &str = "/var/log/snetd.log";

    pub fn definition() -> Result<Vec<u8>> {
        plist(Path::new(DAEMON_BIN))
    }

    fn loaded() -> bool {
        Command::new("/bin/launchctl")
            .args(["print", &format!("system/{LABEL}")])
            .output()
            .is_ok_and(|o| o.status.success())
    }

    /// Stops the service and waits until launchd has really unloaded it: `bootout` returns
    /// before that, and bootstrapping the new version too early fails with
    /// "Bootstrap failed: 5: Input/output error".
    pub fn stop() {
        let _ = run("/bin/launchctl", &["bootout", &format!("system/{LABEL}")]);
        let _ = retry(50, Duration::from_millis(200), || {
            if loaded() {
                Err(anyhow::anyhow!("still loaded"))
            } else {
                Ok(())
            }
        });
    }

    pub fn start() -> Result<()> {
        retry(5, Duration::from_secs(1), || {
            run("/bin/launchctl", &["bootstrap", "system", SERVICE_FILE])
        })
    }

    pub fn after_removal() {}

    pub fn log_hint() -> String {
        format!("see {LOG}")
    }
}

#[cfg(target_os = "linux")]
pub mod systemd {
    use super::*;

    pub const SERVICE_FILE: &str = "/etc/systemd/system/snetd.service";
    /// systemd keeps the log in the journal; there is no log file.
    pub const LOG: &str = "journalctl -u snetd";

    /// The unit. Hardened as far as eBPF and packet capture allow: no new privileges, the
    /// system read-only except the service's own state and the socket directory.
    pub fn unit(daemon: &Path) -> String {
        format!(
            "[Unit]
Description=spectraNET network monitor
Documentation=man:snetd(8)
After=network-online.target
Wants=network-online.target

[Service]
ExecStart={} run
Restart=always
RestartSec=10
Nice=5
IOSchedulingClass=idle
NoNewPrivileges=yes
ProtectSystem=strict
ProtectHome=read-only
PrivateTmp=yes
StateDirectory=spectranet
ReadWritePaths=/run

[Install]
WantedBy=multi-user.target
",
            daemon.display()
        )
    }

    pub fn definition() -> Result<Vec<u8>> {
        Ok(unit(Path::new(DAEMON_BIN)).into_bytes())
    }

    pub fn stop() {
        let _ = run("systemctl", &["disable", "--now", "snetd.service"]);
    }

    pub fn start() -> Result<()> {
        run("systemctl", &["daemon-reload"])?;
        run("systemctl", &["enable", "--now", "snetd.service"])
    }

    pub fn after_removal() {
        let _ = run("systemctl", &["daemon-reload"]);
    }

    pub fn log_hint() -> String {
        "see: journalctl -u snetd".into()
    }
}

/// The LaunchDaemon definition (macOS).
#[cfg(target_os = "macos")]
pub fn plist(daemon: &Path) -> Result<Vec<u8>> {
    let mut dict = plist::Dictionary::new();
    dict.insert("Label".into(), launchd::LABEL.into());
    dict.insert(
        "ProgramArguments".into(),
        plist::Value::Array(vec![
            daemon.to_string_lossy().into_owned().into(),
            "run".into(),
        ]),
    );
    dict.insert("RunAtLoad".into(), true.into());
    dict.insert("KeepAlive".into(), true.into());
    // Restarted at most every 10 s if it keeps failing, so a fault cannot spin the CPU.
    dict.insert("ThrottleInterval".into(), 10.into());
    dict.insert("StandardErrorPath".into(), LOG.into());
    dict.insert("StandardOutPath".into(), LOG.into());
    dict.insert("ProcessType".into(), "Standard".into());
    dict.insert("Nice".into(), 5.into());
    dict.insert("LowPriorityIO".into(), true.into());
    let mut out = Vec::new();
    plist::to_writer_xml(&mut out, &plist::Value::Dictionary(dict))?;
    Ok(out)
}

fn require_root() -> Result<()> {
    // SAFETY: geteuid has no preconditions.
    #[allow(unsafe_code)]
    let euid = unsafe { libc::geteuid() };
    ensure!(
        euid == 0,
        "this needs administrator rights: run it with sudo"
    );
    Ok(())
}

/// Applies new settings: restarts the installed service (nothing to do when it isn't).
pub fn restart() -> Result<()> {
    require_root()?;
    if !Path::new(SERVICE_FILE).exists() {
        return Ok(());
    }
    platform::stop();
    platform::start().context("starting the service")?;
    println!("snetd restarted");
    Ok(())
}

pub fn install() -> Result<()> {
    require_root()?;
    let here = std::env::current_exe()?.canonicalize()?;
    let dir = here.parent().context("locating snetd")?.to_path_buf();
    if here == Path::new(DAEMON_BIN) {
        bail!("run install from the build directory (e.g. sudo ./target/release/snetd install)");
    }

    // Stop a previous version first so its binary can be replaced.
    platform::stop();

    copy_executable(&here, Path::new(DAEMON_BIN))?;
    println!("installed {DAEMON_BIN}");
    link_daemon()?;
    let cli = dir.join("snet");
    if cli.exists() {
        copy_executable(&cli, Path::new(CLI_BIN))?;
        println!("installed {CLI_BIN}");
    } else {
        println!(
            "note: {} not found; only the service was installed",
            cli.display()
        );
    }
    install_man_pages(&cli)?;

    std::fs::create_dir_all(DATA_DIR)?;
    write_atomically(Path::new(SERVICE_FILE), &platform::definition()?, 0o644)?;
    platform::start().context("starting the service")?;

    let socket = Path::new(spectranet_proto::DEFAULT_SOCKET);
    let deadline = Instant::now() + Duration::from_secs(15);
    while std::os::unix::net::UnixStream::connect(socket).is_err() {
        if Instant::now() > deadline {
            bail!(
                "the service was registered but did not start; {}",
                platform::log_hint()
            );
        }
        std::thread::sleep(Duration::from_millis(200));
    }
    println!("snetd is running. Try: snet status");
    Ok(())
}

pub fn uninstall(purge: bool) -> Result<()> {
    require_root()?;
    platform::stop();
    let mut removed = Vec::new();
    if is_our_link(Path::new(DAEMON_LINK)) && remove_if_present(Path::new(DAEMON_LINK))? {
        removed.push(DAEMON_LINK.to_string());
    }
    for path in [
        SERVICE_FILE,
        DAEMON_BIN,
        CLI_BIN,
        spectranet_proto::DEFAULT_SOCKET,
    ] {
        if remove_if_present(Path::new(path))? {
            removed.push(path.to_string());
        }
    }
    for (dir, prefix) in [(MAN1, "snet"), (MAN8, "snetd")] {
        if let Ok(entries) = std::fs::read_dir(dir) {
            for entry in entries.flatten() {
                let name = entry.file_name().to_string_lossy().into_owned();
                if name == format!("{prefix}.1")
                    || name == format!("{prefix}.8")
                    || name.starts_with("snet-")
                {
                    std::fs::remove_file(entry.path())?;
                    removed.push(entry.path().display().to_string());
                }
            }
        }
    }
    if purge {
        if Path::new(DATA_DIR).exists() {
            std::fs::remove_dir_all(DATA_DIR)?;
            removed.push(DATA_DIR.into());
        }
        if LOG.starts_with('/') && remove_if_present(Path::new(LOG))? {
            removed.push(LOG.into());
        }
    }
    platform::after_removal();
    for path in &removed {
        println!("removed {path}");
    }
    if !purge && Path::new(DATA_DIR).exists() {
        println!("kept usage history in {DATA_DIR} (use --purge to delete it)");
    }
    Ok(())
}

fn install_man_pages(cli: &Path) -> Result<()> {
    std::fs::create_dir_all(MAN8)?;
    crate::man::write_snetd_page(Path::new(MAN8))?;
    println!("installed {MAN8}/snetd.8");
    if cli.exists() {
        std::fs::create_dir_all(MAN1)?;
        let status = Command::new(cli).args(["generate", "man", MAN1]).output()?;
        ensure!(status.status.success(), "generating snet man pages failed");
        println!("installed snet man pages in {MAN1}");
    }
    Ok(())
}

/// Puts `snetd` on the PATH as a link to the installed service binary (a file of the same
/// name that is not our link is left alone).
fn link_daemon() -> Result<()> {
    let link = Path::new(DAEMON_LINK);
    if let Some(dir) = link.parent() {
        std::fs::create_dir_all(dir)?;
    }
    if link.symlink_metadata().is_ok() && !is_our_link(link) {
        println!("note: {DAEMON_LINK} exists and is not ours; left as it is");
        return Ok(());
    }
    let _ = std::fs::remove_file(link);
    std::os::unix::fs::symlink(DAEMON_BIN, link)
        .with_context(|| format!("linking {DAEMON_LINK}"))?;
    println!("linked {DAEMON_LINK} → {DAEMON_BIN}");
    Ok(())
}

fn is_our_link(path: &Path) -> bool {
    std::fs::read_link(path).is_ok_and(|target| target == Path::new(DAEMON_BIN))
}

/// Copies to a temporary name, then renames: a running binary is never half-written.
fn copy_executable(from: &Path, to: &Path) -> Result<()> {
    let bytes = std::fs::read(from).with_context(|| format!("reading {}", from.display()))?;
    write_atomically(to, &bytes, 0o755)
}

fn write_atomically(path: &Path, bytes: &[u8], mode: u32) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;
    let dir = path.parent().context("destination has no parent")?;
    std::fs::create_dir_all(dir)?;
    let tmp: PathBuf = dir.join(format!(
        ".{}.tmp",
        path.file_name().unwrap_or_default().to_string_lossy()
    ));
    std::fs::write(&tmp, bytes).with_context(|| format!("writing {}", tmp.display()))?;
    std::fs::set_permissions(&tmp, std::fs::Permissions::from_mode(mode))?;
    std::fs::rename(&tmp, path).with_context(|| format!("installing {}", path.display()))?;
    Ok(())
}

fn remove_if_present(path: &Path) -> Result<bool> {
    match std::fs::remove_file(path) {
        Ok(()) => Ok(true),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(e) => Err(e).with_context(|| format!("removing {}", path.display())),
    }
}

/// Calls `f` up to `attempts` times, `delay` apart, until it succeeds; returns the last error.
#[cfg_attr(not(target_os = "macos"), allow(dead_code))]
fn retry(attempts: u32, delay: Duration, mut f: impl FnMut() -> Result<()>) -> Result<()> {
    let mut last = Ok(());
    for attempt in 0..attempts.max(1) {
        if attempt > 0 {
            std::thread::sleep(delay);
        }
        last = f();
        if last.is_ok() {
            break;
        }
    }
    last
}

fn run(program: &str, args: &[&str]) -> Result<()> {
    let output = Command::new(program)
        .args(args)
        .output()
        .with_context(|| format!("running {program}"))?;
    ensure!(
        output.status.success(),
        "{program} {} failed: {}",
        args.join(" "),
        String::from_utf8_lossy(&output.stderr).trim()
    );
    Ok(())
}

/// Groups whose members administer the machine, in order of preference: `admin` on macOS,
/// `sudo` (Debian, Ubuntu) or `wheel` (Fedora, Arch) on Linux.
#[cfg(target_os = "macos")]
const ADMIN_GROUPS: [&std::ffi::CStr; 1] = [c"admin"];
#[cfg(not(target_os = "macos"))]
const ADMIN_GROUPS: [&std::ffi::CStr; 2] = [c"sudo", c"wheel"];

/// Group ID of the administrators' group, whose members may use the socket.
pub fn admin_gid() -> Option<u32> {
    ADMIN_GROUPS.iter().find_map(|name| {
        // SAFETY: getgrnam returns a pointer to static storage or null; we only read gr_gid
        // immediately. Called once at startup, before other threads could use getgrnam.
        #[allow(unsafe_code)]
        unsafe {
            let group = libc::getgrnam(name.as_ptr());
            (!group.is_null()).then(|| (*group).gr_gid)
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(target_os = "macos")]
    #[test]
    fn plist_is_valid_and_complete() {
        let xml = plist(Path::new(DAEMON_BIN)).unwrap();
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join("test.plist");
        std::fs::write(&file, &xml).unwrap();
        let lint = Command::new("/usr/bin/plutil")
            .arg("-lint")
            .arg(&file)
            .output()
            .unwrap();
        assert!(
            lint.status.success(),
            "{}",
            String::from_utf8_lossy(&lint.stdout)
        );

        let value = plist::Value::from_file(&file).unwrap();
        let dict = value.as_dictionary().unwrap();
        assert_eq!(
            dict.get("Label").and_then(|v| v.as_string()),
            Some(launchd::LABEL)
        );
        let args: Vec<_> = dict["ProgramArguments"]
            .as_array()
            .unwrap()
            .iter()
            .map(|v| v.as_string().unwrap())
            .collect();
        assert_eq!(args, [DAEMON_BIN, "run"]);
        assert_eq!(
            dict.get("KeepAlive").and_then(|v| v.as_boolean()),
            Some(true)
        );
    }

    #[test]
    fn retry_stops_at_first_success_and_reports_last_error() {
        let mut calls = 0;
        let ok = retry(5, Duration::ZERO, || {
            calls += 1;
            if calls < 3 {
                Err(anyhow::anyhow!("not yet"))
            } else {
                Ok(())
            }
        });
        assert!(ok.is_ok());
        assert_eq!(calls, 3);

        let mut calls = 0;
        let err = retry(4, Duration::ZERO, || {
            calls += 1;
            Err(anyhow::anyhow!("failure {calls}"))
        });
        assert_eq!(calls, 4);
        assert_eq!(err.unwrap_err().to_string(), "failure 4");
    }

    #[test]
    fn atomic_write_sets_mode_and_leaves_no_temp_file() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let target = dir.path().join("sub/bin");
        write_atomically(&target, b"one", 0o755).unwrap();
        write_atomically(&target, b"two", 0o755).unwrap();
        assert_eq!(std::fs::read(&target).unwrap(), b"two");
        assert_eq!(
            std::fs::metadata(&target).unwrap().permissions().mode() & 0o777,
            0o755
        );
        assert_eq!(
            std::fs::read_dir(dir.path().join("sub")).unwrap().count(),
            1
        );
    }

    #[test]
    fn install_requires_root() {
        // SAFETY: no preconditions.
        #[allow(unsafe_code)]
        let root = unsafe { libc::geteuid() } == 0;
        if !root {
            assert!(install().unwrap_err().to_string().contains("sudo"));
            assert!(uninstall(false).unwrap_err().to_string().contains("sudo"));
        }
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn admin_group_exists() {
        assert_eq!(admin_gid(), Some(80));
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn systemd_unit_is_valid() {
        let dir = tempfile::tempdir().unwrap();
        let unit = dir.path().join("snetd.service");
        std::fs::write(&unit, systemd::unit(Path::new("/bin/true"))).unwrap();
        let verify = Command::new("systemd-analyze")
            .arg("verify")
            .arg(&unit)
            .output();
        match verify {
            Ok(out) => {
                let stderr = String::from_utf8_lossy(&out.stderr);
                // Units outside the system directories trigger a harmless notice.
                let problems: Vec<_> = stderr
                    .lines()
                    .filter(|l| {
                        !l.contains("is not executable")
                            && !l.trim().is_empty()
                            && !l.contains("Failed to prepare filename")
                            && !l.contains("Command 'man ")
                    })
                    .collect();
                assert!(out.status.success() || problems.is_empty(), "{stderr}");
            }
            Err(_) => eprintln!("systemd-analyze not available; skipping"),
        }
        let text = systemd::unit(Path::new(DAEMON_BIN));
        assert!(text.contains("ExecStart=/usr/local/sbin/snetd run"));
        assert!(text.contains("WantedBy=multi-user.target"));
    }
}
