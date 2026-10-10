//! Command-line grammar of `snetd`; also the source of its man page.

use std::path::PathBuf;

use clap::{Args, Parser, Subcommand};

const LONG_ABOUT: &str = "\
snetd is the spectraNET background service. Running as root, it samples per-application \
network traffic every second, discovers hostnames from DNS answers, TLS and QUIC handshakes \
and the local network, and keeps a per-day history of data usage per application.

It also raises alerts: connections to addresses on public blocklists (abuse.ch Feodo Tracker, \
Spamhaus DROP, Tor exit nodes), unencrypted protocols towards the Internet, and applications \
reaching the network for the first time. The blocklists are downloaded every 12 hours; only \
the lists themselves are fetched, nothing about this computer's traffic is sent anywhere.

The snet command uses snetd automatically when it is running: no sudo is needed, hostnames \
are known even for connections opened long ago, and snet history becomes available.

snetd is normally managed by the system (launchd on macOS, systemd on Linux): install it once \
with 'sudo snetd install'.";

#[derive(Debug, Parser)]
#[command(name = "snetd", version, about = "spectraNET background service", long_about = LONG_ABOUT)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Command,
}

#[derive(Debug, Subcommand)]
pub enum Command {
    /// Run the service in the foreground (this is what launchd or systemd start)
    Run(RunArgs),
    /// Install snetd (and snet, with man pages) and start it at every boot; needs sudo
    Install,
    /// Stop and remove snetd, snet and their man pages; needs sudo
    Uninstall {
        /// Also delete the usage history and the log
        #[arg(long)]
        purge: bool,
    },
    /// Show or change the settings in snetd.conf (`set` needs sudo and restarts the service)
    Config {
        #[command(subcommand)]
        action: ConfigAction,
    },
    /// Entry point used by the Windows Service Control Manager
    #[command(hide = true)]
    Service,
    /// Write the snetd(8) man page into DIR (used by packaging)
    #[command(hide = true)]
    GenerateMan { dir: PathBuf },
}

#[derive(Debug, Subcommand)]
pub enum ConfigAction {
    /// Print the settings in force
    Show,
    /// Change settings and restart the service, e.g. `snetd config set history_days=90`.
    /// Keys: actions (elevated-only | allowed-users), metrics (ADDRESS | off),
    /// category_updates, feed_updates (true | false), feeds_disabled (comma-separated ids:
    /// feodo, spamhaus-drop, spamhaus-dropv6, tor-exits), history_days (0 = keep everything)
    Set {
        #[arg(required = true, value_name = "KEY=VALUE")]
        pairs: Vec<String>,
    },
}

#[derive(Debug, Args)]
pub struct RunArgs {
    /// Serve simulated traffic instead of live capture (for testing)
    #[arg(long)]
    pub mock: bool,

    /// Listen on this Unix socket
    #[arg(long, value_name = "PATH", default_value = spectranet_proto::DEFAULT_SOCKET)]
    pub socket: PathBuf,

    /// Keep history, alerts and reputation lists under this directory
    #[arg(long, value_name = "DIR", default_value = spectranet_proto::DEFAULT_DATA_DIR)]
    pub data_dir: PathBuf,

    /// Use this SQLite database instead of DIR/usage.sqlite
    #[arg(long, value_name = "PATH")]
    pub database: Option<PathBuf>,

    /// Never download reputation lists (use the ones already in DIR/feeds, if any)
    #[arg(long)]
    pub no_feed_updates: bool,

    /// Seconds between samples
    #[arg(long, value_name = "SECONDS", default_value = "1", value_parser = parse_interval)]
    pub interval: f64,

    /// Serve Prometheus metrics on this address, e.g. 127.0.0.1:9790 (default: off, or
    /// `metrics` in snetd.conf)
    #[arg(long, value_name = "ADDRESS")]
    pub metrics: Option<std::net::SocketAddr>,
}

impl RunArgs {
    /// The settings the installed service runs with.
    pub fn service_defaults() -> Self {
        Self {
            mock: false,
            socket: spectranet_proto::DEFAULT_SOCKET.into(),
            data_dir: spectranet_proto::DEFAULT_DATA_DIR.into(),
            database: None,
            no_feed_updates: false,
            interval: 1.0,
            metrics: None,
        }
    }
}

fn parse_interval(s: &str) -> Result<f64, String> {
    let v: f64 = s
        .parse()
        .map_err(|_| format!("'{s}' is not a number of seconds"))?;
    if (0.1..=60.0).contains(&v) {
        Ok(v)
    } else {
        Err("interval must be between 0.1 and 60 seconds".into())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::CommandFactory;

    #[test]
    fn grammar_is_consistent() {
        Cli::command().debug_assert();
    }

    #[test]
    fn interval_bounds() {
        assert_eq!(parse_interval("1"), Ok(1.0));
        assert!(parse_interval("0").is_err());
        assert!(parse_interval("1000").is_err());
        assert!(parse_interval("fast").is_err());
    }
}
