//! Command-line grammar. Also the single source of truth for the man pages and completions.

use std::time::Duration;

use clap::{Args, Parser, Subcommand, ValueEnum};

use crate::duration::parse_duration;

pub const ABOUT: &str = "Per-application network traffic monitor";

const LONG_ABOUT: &str = "\
snet is the command-line interface of spectraNET. It shows which applications on this \
computer are using the network, how much bandwidth each one consumes, which remote hosts \
they talk to, and whether any of that traffic looks suspicious.

Every command reads from a traffic source. By default that is the live capture backend for \
the current operating system; --mock selects a simulated workload instead, which needs no \
privileges and is useful for demos and testing.

Hostnames are discovered passively, by observing DNS answers and the server name sent in \
TLS handshakes; nothing is looked up on the network. This needs root (packet capture). \
Without it, or with -n, remote endpoints are shown as numeric addresses. Names appear for \
connections opened while snet is running.

Devices on the local network are also named actively: for private addresses only, snet asks \
mDNS (Bonjour), the local router's DNS and the device itself (NetBIOS). These queries never \
leave the local network; a public DNS resolver is never asked. -n disables them too.";

const AFTER_LONG_HELP: &str = "\
Examples:
  snet list                       Top applications by bandwidth over the next second
  snet list -c --sort down        Same, with each connection, sorted by download rate
  snet list --json | jq '.processes[0]'
  snet watch --name chrome        Live view of Chrome's traffic
  snet watch --flagged -i 2s      Live view of suspicious applications only";

#[derive(Debug, Parser)]
#[command(
    name = "snet",
    version,
    about = ABOUT,
    long_about = LONG_ABOUT,
    after_long_help = AFTER_LONG_HELP,
    propagate_version = true
)]
pub struct Cli {
    /// Use the simulated traffic source instead of live capture
    #[arg(long, global = true)]
    pub mock: bool,

    /// Show numeric addresses only: do not discover hostnames (no root needed)
    #[arg(short = 'n', long, global = true)]
    pub numeric: bool,

    /// Talk to snetd on this socket
    #[arg(long, global = true, value_name = "PATH", env = "SNET_SOCKET", default_value = spectranet_proto::DEFAULT_SOCKET)]
    pub socket: std::path::PathBuf,

    /// Capture directly even if snetd is running
    #[arg(long, global = true)]
    pub no_daemon: bool,

    /// When to use colors in human-readable output
    #[arg(long, global = true, value_name = "WHEN", default_value = "auto")]
    pub color: ColorWhen,

    #[command(subcommand)]
    pub command: Command,
}

#[derive(Debug, Subcommand)]
pub enum Command {
    /// List applications using the network, busiest first
    #[command(
        long_about = "Samples traffic for one interval, then prints a table of the applications \
                      that used the network, with their current download and upload rates, \
                      bytes transferred, number of connections, busiest destination and \
                      security status. Helper processes (e.g. a browser's renderers) are grouped under the \
                      application they belong to; use --by-process to list them separately.",
        after_long_help = "Examples:\n  snet list\n  snet list --sort up --limit 5\n  \
                           snet list -c --name spotify\n  snet list -cc --name chrome\n  snet list --json"
    )]
    List(ListArgs),

    /// Continuously display network usage, refreshing every interval
    #[command(
        long_about = "Redraws the application table every interval until interrupted with \
                      Ctrl-C (or until --count samples have been shown). With --json, prints \
                      one snapshot per line (NDJSON) instead, suitable for piping into other tools.",
        after_long_help = "Examples:\n  snet watch\n  snet watch --pid 4892 --connections\n  \
                           snet watch --json --count 10 > samples.ndjson"
    )]
    Watch(WatchArgs),

    /// Interactive full-screen view: graphs, sortable table, connection details
    #[command(
        long_about = "Opens a full-screen, interactive view of network usage in the terminal, in \
                      the spirit of htop: download and upload graphs for the last two minutes, \
                      the application table with CPU and memory beside the traffic, a process \
                      tree, an inspector for the connections of the selected application, and \
                      actions on processes and connections. Actions go through the snetd \
                      service, which refuses protected system processes and logs every \
                      request; each one asks for confirmation first.",
        after_long_help = TOP_KEYS
    )]
    Top(TopArgs),

    /// Show whether the snetd service is running, and how
    #[command(
        long_about = "Reports whether the snetd background service is running, its version, uptime, \
                      capture backend and any degraded-operation notices. Exits with status 69 \
                      when the service is not running."
    )]
    Status,

    /// Show data usage per application over the last days (needs snetd)
    #[command(
        long_about = "Prints how much data each application received and sent, summed over the \
                      last --days days (today included), busiest first. The history is recorded \
                      by the snetd service and only covers the time it has been running.",
        after_long_help = "Examples:\n  snet history\n  snet history --days 30 --limit 10\n  \
                           snet history --days 7 --json"
    )]
    History(HistoryArgs),

    /// Flight Recorder: record the network activity of applications to a file
    #[command(
        long_about = "Records, sample by sample, everything the selected applications do on the \
                      network — every connection, its destination, hostname, timing and bytes — \
                      into a JSON Lines file, until --duration elapses or Ctrl-C is pressed. \
                      With snetd running, no sample is missed or counted twice and short-lived \
                      connections are included. Analyse the file with 'snet analyze'.",
        after_long_help = "Examples:\n  snet record --name zoom --duration 10m\n  \
                           snet record --pid 4892 -o chrome-session.jsonl\n  \
                           snet record --name curl --name python --duration 1h"
    )]
    Record(RecordArgs),

    /// Analyse a Flight Recorder file: destinations, periodic contacts, risky traffic
    #[command(
        long_about = "Reads a recording made by 'snet record' and reports where the applications \
                      talked and how much, then what deserves attention: periodic contacts to the \
                      same server (beaconing), heavy uploads, unencrypted protocols and addresses \
                      on public blocklists. Damaged or interrupted recordings are analysed as far \
                      as they go.",
        after_long_help = "Examples:\n  snet analyze session.jsonl\n  snet analyze session.jsonl --json | jq '.findings'"
    )]
    Analyze(AnalyzeArgs),

    /// End a process (needs snetd; asks it politely unless --force)
    #[command(
        long_about = "Asks snetd to end a process with network activity: SIGTERM, or SIGKILL with \
                      --force (on Windows the process is always ended at once). snetd refuses \
                      protected system processes and records the request in its audit log.",
        after_long_help = "Examples:\n  snet kill 4892\n  snet kill --force 4892"
    )]
    Kill(KillArgs),

    /// Pause a process: it stops using CPU and network until resumed (needs snetd)
    #[command(
        long_about = "Freezes a process (SIGSTOP, or process suspension on Windows) through snetd. \
                      It keeps its memory and connections but sends and computes nothing until \
                      'snet resume'.",
        after_long_help = "Example:\n  snet pause 4892 && sleep 30 && snet resume 4892"
    )]
    Pause(PidArg),

    /// Resume a paused process (needs snetd)
    Resume(PidArg),

    /// Close one connection of a process, leaving the rest alone (needs snetd)
    #[command(
        long_about = "Closes a single connection, identified by its local and remote endpoints as \
                      shown by 'snet list -cc'. Linux closes TCP and UDP sockets (like ss -K); \
                      Windows closes IPv4 TCP connections. The application may reconnect.",
        after_long_help = "Example:\n  snet drop 4892 192.168.1.23:52114 142.250.180.142:443"
    )]
    Drop(DropArgs),

    /// Print what kind of traffic connections carry, as it is recognised
    #[command(
        long_about = "Prints a line each time a connection is recognised as video, audio, a call, \
                      web/API traffic, a download, an upload or a game, or its classification \
                      changes: time, process, destination, rate, kind, certainty and the main \
                      reason. The classification uses the host, the traffic pattern (bursts, \
                      sustained transfers, steady small packets), call-service ports and the \
                      protocol offered in the TLS handshake; nothing is decrypted and no content \
                      is read. With --json, one object per line (NDJSON).",
        after_long_help = "Examples:\n  snet stream --name chrome\n  snet stream --json --count 20\n  snet stream --pid 4102"
    )]
    Stream(StreamArgs),

    /// Show the network profile of a process: each connection, its kind and protocol
    #[command(
        long_about = "Samples for a few seconds (--wait), then shows each connection of the \
                      matching processes with what kind of traffic it carries and why, its \
                      protocol (TLS version, cipher suite, ALPN), the client's JA4 fingerprint, \
                      rates and packets per second. TLS details need live capture (macOS and \
                      Linux, with the snetd service or as root).",
        after_long_help = "Examples:\n  snet inspect --pid 4102\n  snet inspect --name spotify --wait 10s\n  snet inspect --name chrome --json"
    )]
    Inspect(InspectArgs),

    /// Cut an application or an address off the network (needs snetd)
    #[command(
        long_about = "Blocks every connection of an application, or every connection to and from \
                      an address, for a while or until lifted. TARGET is an IP address, or an \
                      application by PID, name or path as shown by 'snet list'. Connections \
                      already open are closed. Linux and Windows block the application's program \
                      file; macOS blocks the addresses the application uses as they are seen \
                      (a new destination may get through for about a second). snetd never blocks \
                      protected system programs, the gateway, the DNS servers or remote-access \
                      sessions, and records every block in its audit log. Blocks survive a \
                      restart of snetd and disappear when it is uninstalled.",
        after_long_help = "Examples:\n  snet block 185.220.101.34\n  snet block svc_update --for 15m\n  snet block 4892 --for forever\n  snet blocks\n  snet unblock 3"
    )]
    Block(BlockArgs),

    /// Lift a block, or all of them (needs snetd)
    Unblock(UnblockArgs),

    /// List the blocks in force (needs snetd)
    Blocks(JsonArg),

    /// Show the actions requested from snetd and their outcome
    #[command(
        long_about = "Lists the actions snetd was asked to carry out (end, pause, resume, close a \
                      connection), who asked, and whether they were done or refused, newest first.",
        after_long_help = "Examples:\n  snet audit\n  snet audit --since 7d --json"
    )]
    Audit(AlertsArgs),

    /// Show security alerts raised by snetd
    #[command(
        long_about = "Lists what snetd flagged, newest first: connections to addresses on public \
                      blocklists (botnet command-and-control servers, criminal networks, Tor exit \
                      nodes), unencrypted protocols towards the Internet, and applications \
                      reaching the network for the first time.",
        after_long_help = "Examples:\n  snet alerts\n  snet alerts --since 7d\n  snet alerts --since 1h --json"
    )]
    Alerts(AlertsArgs),

    /// Is my network slow? Router, internet and DNS checked in seconds, with a verdict
    #[command(
        visible_alias = "slow",
        long_about = "Measures, in parallel and in about five seconds, the round trip to the \
                      router, to internet targets (1.1.1.1 and 9.9.9.9 unless --target is given \
                      or snetd is configured otherwise) and the time the system's DNS takes to \
                      resolve a name, while watching which applications use the network. Then it \
                      says, first, where the problem is: the link to the router (Wi-Fi or \
                      cable), the line past the router (line or provider), slow DNS, or an \
                      application filling the connection; or that all is well.\n\n\
                      Latencies are measured with ICMP echo (ping) where the system allows it \
                      without privileges, otherwise with the time to open a TCP connection \
                      (shown as TCP:port). A measurement that can't be made is reported as not \
                      measurable. Only the router, the targets and the DNS server are contacted, \
                      and nothing leaves this computer otherwise.\n\n\
                      With snetd running, the service runs the check: it compares the latency \
                      with the usual one, the traffic with the recent peak, and keeps the result \
                      (see --history).\n\n\
                      Exit status: 0 all good, 1 a problem was found, 2 the check failed or \
                      nothing could be measured.",
        after_long_help = "Examples:\n  snet check\n  snet slow --path\n  snet check --target example.com --target 8.8.8.8\n  snet check --json | jq .verdict\n  snet check --history 20"
    )]
    Check(CheckArgs),

    /// Generate man pages or shell completions (used by packaging)
    #[command(hide = true)]
    Generate(GenerateArgs),
}

/// The KEYS section of snet-top(1); kept in step with the default bindings by a test.
pub const TOP_KEYS: &str =
    "Keys (defaults; change them in setup, F2, saved in ~/.config/spectranet/top.toml):
  Up k / Down j           move the selection
  PageUp Ctrl-b / PageDown Ctrl-f, Home / End G
                          jump
  Enter i                 inspect: connections, services, CPU, memory, owner; Tab moves
                          between the list and the connections
  /                       search: name (letters in order, e.g. gch), hostname or address
  F6 >                    choose the sort order; s S next / previous
  F5 t                    process tree; Right + l expand, Left - h collapse a branch
                          (a collapsed branch shows its whole subtree's traffic)
  F2                      setup: columns (PID, application, down, up, CPU, memory, total,
                          connections, user, destination, status) and key bindings
  F1 ?                    help
  Space z                 freeze / resume the screen
  F9 x                    end the selected process: t asks it to quit (SIGTERM), k forces it
                          (SIGKILL); on Windows it is always ended at once
  p                       pause / resume the selected process (SIGSTOP / SIGCONT, process
                          suspension on Windows)
  d                       close the selected connection (in the inspector); Linux and Windows
  b                       block the selected application, or in the inspector the selected
                          connection's address: 1 15 min, 2 1 hour, 3 8 hours, 4 1 day,
                          5 until lifted (macOS follows the application's addresses)
  g                       group helpers under their application / one row per process
  f                       Flow Inspector: each connection of the selection with what kind of
                          traffic it carries (video, call, web…) and why, its protocol, TLS
                          version, cipher and JA4 fingerprint, and live bandwidth and packet
                          waves; ↑↓ choose, d close, b block the address, f or Esc back
  F                       only applications with a warning or an alert
  q F10 Ctrl-c            quit; Esc closes panels, then clears the search, then quits

Actions need the snetd service (sudo snetd install). It refuses protected processes
(launchd, systemd, lsass, svchost, sshd, snetd, ...), and with actions = \"elevated-only\"
in snetd.conf it accepts them only from root or an elevated administrator.

Examples:
  snet top
  snet top --flagged
  snet top --sort cpu
  snet top --name chrome -i 2s";

/// Options shared by commands that display a snapshot.
#[derive(Debug, Args)]
pub struct ViewArgs {
    /// Sort order of the application table
    #[arg(short, long, value_name = "KEY", default_value = "rate")]
    pub sort: SortKey,

    /// Show at most N applications
    #[arg(short, long, value_name = "N")]
    pub limit: Option<usize>,

    /// Only show the application with this process ID (repeatable)
    #[arg(short, long = "pid", value_name = "PID")]
    pub pids: Vec<u32>,

    /// Only show applications matching TEXT: in their name (letters in order, e.g. "gch"
    /// for Google Chrome), or in a destination's hostname or address
    #[arg(long, value_name = "TEXT")]
    pub name: Option<String>,

    /// Only show applications with a warning or alert
    #[arg(short, long)]
    pub flagged: bool,

    /// Only show one domain: radio (software-defined radio and satellite reception)
    #[arg(long, value_name = "DOMAIN")]
    pub domain: Option<Domain>,

    /// Show one row per process instead of grouping helpers under their application
    #[arg(short = 'P', long)]
    pub by_process: bool,

    /// List each application's connections: -c shows the active ones and up to 10 in total,
    /// -cc shows all of them
    #[arg(short, long, action = clap::ArgAction::Count)]
    pub connections: u8,

    /// Print machine-readable JSON instead of a table
    #[arg(long)]
    pub json: bool,

    /// Length of the sampling interval (e.g. 500ms, 2s, 1m)
    #[arg(short, long, value_name = "DURATION", default_value = "1s", value_parser = parse_duration)]
    pub interval: Duration,
}

#[derive(Debug, Args)]
pub struct ListArgs {
    #[command(flatten)]
    pub view: ViewArgs,
}

#[derive(Debug, Args)]
pub struct TopArgs {
    #[command(flatten)]
    pub view: ViewArgs,
}

#[derive(Debug, Args)]
pub struct RecordArgs {
    /// Record applications whose name contains TEXT (repeatable; case-insensitive)
    #[arg(long = "name", value_name = "TEXT")]
    pub names: Vec<String>,

    /// Record the process with this ID (repeatable)
    #[arg(short, long = "pid", value_name = "PID")]
    pub pids: Vec<u32>,

    /// Stop after this long (e.g. 30s, 10m, 2h); default: until Ctrl-C
    #[arg(short, long, value_name = "DURATION", value_parser = crate::duration::parse_age)]
    pub duration: Option<Duration>,

    /// Write to FILE (default: snet-record-<date>-<time>.jsonl); never overwritten
    #[arg(short, long, value_name = "FILE")]
    pub output: Option<std::path::PathBuf>,

    /// Sampling interval when capturing directly (snetd sets its own)
    #[arg(short, long, value_name = "DURATION", default_value = "1s", value_parser = parse_duration)]
    pub interval: Duration,
}

#[derive(Debug, Args)]
pub struct AnalyzeArgs {
    /// Recording made by 'snet record'
    #[arg(value_name = "FILE")]
    pub file: std::path::PathBuf,

    /// Show at most N destinations
    #[arg(short, long, value_name = "N", default_value = "15")]
    pub limit: usize,

    /// Print the full analysis as JSON
    #[arg(long)]
    pub json: bool,
}

#[derive(Debug, Args)]
pub struct AlertsArgs {
    /// How far back to look (e.g. 30m, 24h, 7d)
    #[arg(short, long, value_name = "DURATION", default_value = "24h", value_parser = crate::duration::parse_age)]
    pub since: Duration,

    /// Show at most N alerts
    #[arg(short, long, value_name = "N", default_value = "50")]
    pub limit: u32,

    /// Print JSON instead of a table
    #[arg(long)]
    pub json: bool,
}

#[derive(Debug, Args)]
pub struct KillArgs {
    /// Process ID
    pub pid: u32,
    /// End it at once (SIGKILL) instead of asking it to quit
    #[arg(short = 'F', long)]
    pub force: bool,
}

#[derive(Debug, Args)]
pub struct BlockArgs {
    /// IP address, or application PID, name or path
    pub target: String,
    /// How long: 15m, 1h, 8h, 1d... or "forever" (until lifted)
    #[arg(short = 'f', long = "for", value_name = "DURATION", default_value = "1h", value_parser = crate::duration::parse_block_for)]
    pub ttl: u64,
}

#[derive(Debug, Args)]
#[group(required = true, multiple = false)]
pub struct UnblockArgs {
    /// Block number, as shown by 'snet blocks'
    pub id: Option<u64>,
    /// Lift every block
    #[arg(long)]
    pub all: bool,
}

#[derive(Debug, Args)]
pub struct JsonArg {
    /// Print JSON instead of a table
    #[arg(long)]
    pub json: bool,
}

#[derive(Debug, Args)]
pub struct PidArg {
    /// Process ID
    pub pid: u32,
}

#[derive(Debug, Args)]
pub struct DropArgs {
    /// Process owning the connection
    pub pid: u32,
    /// Local endpoint, e.g. 192.168.1.23:52114 or [fe80::1]:52114
    pub local: std::net::SocketAddr,
    /// Remote endpoint, e.g. 142.250.180.142:443
    pub remote: std::net::SocketAddr,
    /// The connection is UDP (default: TCP)
    #[arg(long)]
    pub udp: bool,
}

#[derive(Debug, Args)]
pub struct HistoryArgs {
    /// Number of days to cover, today included
    #[arg(short, long, value_name = "N", default_value = "1", value_parser = clap::value_parser!(u32).range(1..=3660))]
    pub days: u32,

    /// Show at most N applications
    #[arg(short, long, value_name = "N")]
    pub limit: Option<usize>,

    /// Print the per-day rows as JSON instead of a table
    #[arg(long)]
    pub json: bool,
}

#[derive(Debug, Args)]
pub struct WatchArgs {
    #[command(flatten)]
    pub view: ViewArgs,

    /// Stop after N refreshes
    #[arg(long, value_name = "N")]
    pub count: Option<u64>,
}

/// Groups of applications selected with `--domain`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, clap::ValueEnum)]
pub enum Domain {
    /// Software-defined radio and satellite reception: radio programs, and connections
    /// carrying IQ samples, radio audio, digital modes, telemetry or WebSDR.
    Radio,
}

#[derive(Debug, Args)]
pub struct StreamArgs {
    #[command(flatten)]
    pub view: ViewArgs,

    /// Stop after N lines
    #[arg(long, value_name = "N")]
    pub count: Option<u64>,
}

#[derive(Debug, Args)]
pub struct InspectArgs {
    #[command(flatten)]
    pub view: ViewArgs,

    /// How long to observe before reporting (patterns need a few seconds)
    #[arg(short, long, value_name = "DURATION", default_value = "5s", value_parser = parse_duration)]
    pub wait: Duration,
}

#[derive(Debug, Args)]
pub struct CheckArgs {
    /// Internet target to measure, a name or an address (repeatable; default 1.1.1.1 and
    /// 9.9.9.9)
    #[arg(short, long = "target", value_name = "HOST")]
    pub targets: Vec<String>,

    /// Also trace the path to the first target, hop by hop (up to a minute more)
    #[arg(short, long)]
    pub path: bool,

    /// Print the full report as JSON
    #[arg(long)]
    pub json: bool,

    /// Show the last N checks recorded by snetd instead of running one
    #[arg(long, value_name = "N", num_args = 0..=1, default_missing_value = "10")]
    pub history: Option<u32>,
}

#[derive(Debug, Args)]
pub struct GenerateArgs {
    #[command(subcommand)]
    pub what: GenerateWhat,
}

#[derive(Debug, Subcommand)]
pub enum GenerateWhat {
    /// Write snet.1 and one page per subcommand (snet-list.1, ...) into DIR
    Man {
        #[arg(value_name = "DIR")]
        dir: std::path::PathBuf,
    },
    /// Print a completion script for SHELL to standard output
    Completions {
        #[arg(value_name = "SHELL")]
        shell: clap_complete::Shell,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum SortKey {
    /// Combined download + upload rate
    Rate,
    /// Download rate
    Down,
    /// Upload rate
    Up,
    /// Bytes transferred over the connections' lifetime
    Total,
    /// Process ID
    Pid,
    /// Application name
    Name,
    /// CPU use of the application's processes
    Cpu,
    /// Memory of the application's processes
    Mem,
    /// Alerts first, then warnings, then the rest by rate
    Alerts,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum ColorWhen {
    Auto,
    Always,
    Never,
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::CommandFactory;

    #[test]
    fn grammar_is_consistent() {
        Cli::command().debug_assert();
    }
}
