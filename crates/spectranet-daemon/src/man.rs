//! The snetd(8) man page.

use std::io::{self, Write};
use std::path::{Path, PathBuf};

use clap::CommandFactory;
use clap_mangen::Man;

use crate::cli::Cli;
use crate::install;

#[cfg(target_os = "macos")]
const FEEDS_DIR: &str = "/Library/Application Support/spectraNET/feeds";
#[cfg(not(target_os = "macos"))]
const FEEDS_DIR: &str = "/var/lib/spectranet/feeds";
#[cfg(target_os = "macos")]
const CONF: &str = "/Library/Application Support/spectraNET/snetd.conf";
#[cfg(not(target_os = "macos"))]
const CONF: &str = "/var/lib/spectranet/snetd.conf";

#[cfg(target_os = "macos")]
const SOCKET_TEXT: &str = "Socket on which snet talks to the service (group admin, mode 0660).";
#[cfg(not(target_os = "macos"))]
const SOCKET_TEXT: &str =
    "Socket on which snet talks to the service (group sudo or wheel, mode 0660).";

const FILES: [(&str, &str); 7] = [
    (CONF, "Optional configuration (see CONFIGURATION)."),
    (spectranet_proto::DEFAULT_SOCKET, SOCKET_TEXT),
    (
        install::DATABASE,
        "Per-day usage history, alerts and known applications (SQLite).",
    ),
    (FEEDS_DIR, "Reputation lists, refreshed every 12 hours."),
    (install::LOG, "Service log (on Linux: the systemd journal)."),
    (
        install::SERVICE_FILE,
        "Service definition written by snetd install (launchd or systemd).",
    ),
    (install::DAEMON_BIN, "Installed service executable."),
];

/// The CONFIGURATION section: snetd.conf and the Prometheus metrics.
const CONFIGURATION: &str = r#"The service reads an optional TOML file, snetd.conf, in its data directory. A missing file means the defaults; an invalid one is reported in the log and ignored.
.TP
.B actions = \(dqelevated\-only\(dq
Only root or an elevated administrator may end, pause, block or close connections. By default every user allowed to read snetd may act, after confirmation; protected system programs are always refused and every action is recorded in the audit log (snet audit).
.TP
.B metrics = \(dq127.0.0.1:9790\(dq
Serves Prometheus metrics at http://127.0.0.1:9790/metrics. Off by default. The same can be asked for on the command line with snetd run \-\-metrics ADDRESS, which takes precedence. Use a loopback address unless the metrics are meant to be reachable from the network: they reveal which applications run and how much they use the network.
.PP
Metrics: spectranet_app_receive_bytes_per_second, spectranet_app_transmit_bytes_per_second, spectranet_app_receive_bytes_total, spectranet_app_transmit_bytes_total, spectranet_app_connections, spectranet_app_processes, spectranet_app_cpu_percent, spectranet_app_memory_bytes (label app), and spectranet_samples_total, spectranet_clients, spectranet_alerts_last_24h, spectranet_blocks, spectranet_uptime_seconds, spectranet_build_info."#;

pub fn write_snetd_page(dir: &Path) -> io::Result<PathBuf> {
    let man = Man::new(Cli::command())
        .section("8")
        .title("SNETD")
        .manual("spectraNET Manual")
        .source(format!("spectraNET {}", env!("CARGO_PKG_VERSION")));
    let mut page = Vec::new();
    man.render_title(&mut page)?;
    man.render_name_section(&mut page)?;
    man.render_synopsis_section(&mut page)?;
    man.render_description_section(&mut page)?;
    man.render_subcommands_section(&mut page)?;
    writeln!(page, ".SH CONFIGURATION")?;
    writeln!(page, "{}", CONFIGURATION)?;
    writeln!(page, ".SH FILES")?;
    for (path, what) in FILES {
        writeln!(page, ".TP\n.I {}\n{}", escape(path), escape(what))?;
    }
    writeln!(
        page,
        ".SH \"EXIT STATUS\"\n.TP\n.B 0\nStopped normally.\n.TP\n.B 1\nFailed to start, or capture kept failing (the system restarts the service)."
    )?;
    writeln!(
        page,
        ".SH \"SEE ALSO\"\n.BR snet (1),\n.BR {} (1)",
        if cfg!(target_os = "macos") {
            "launchctl"
        } else {
            "systemctl"
        }
    )?;
    man.render_version_section(&mut page)?;
    let path = dir.join("snetd.8");
    std::fs::write(&path, page)?;
    Ok(path)
}

fn escape(text: &str) -> String {
    text.replace('\\', "\\e").replace('-', "\\-")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn page_has_unix_sections() {
        let dir = tempfile::tempdir().unwrap();
        let page = std::fs::read_to_string(write_snetd_page(dir.path()).unwrap()).unwrap();
        for section in [
            ".TH SNETD 8",
            ".SH SYNOPSIS",
            ".SH FILES",
            ".SH CONFIGURATION",
            "spectranet_app_receive_bytes_total",
            "/var/run/snetd.sock",
            ".SH \"EXIT STATUS\"",
            ".BR snet (1)",
        ] {
            assert!(page.contains(section), "missing {section}");
        }
        assert!(!page.contains("generate\\-man"), "hidden command leaked");
    }
}
