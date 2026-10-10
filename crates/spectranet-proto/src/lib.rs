//! The local protocol between `snet` (client) and `snetd` (service).
//!
//! Transport: a Unix domain socket. Framing: one JSON object per line. Every message carries
//! the protocol version `v`; a peer receiving another version answers with an error instead
//! of guessing. Lines are size-limited so a misbehaving peer cannot exhaust memory.

use std::io::{self, BufRead, BufReader, Read, Write};
use std::net::SocketAddr;
use std::path::Path;
use std::time::Duration;

use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use spectranet_model::Snapshot;

pub const PROTOCOL_VERSION: u32 = 1;
/// Where `snetd` listens by default.
#[cfg(not(windows))]
pub const DEFAULT_SOCKET: &str = "/var/run/snetd.sock";
#[cfg(windows)]
pub const DEFAULT_SOCKET: &str = r"\\.\pipe\snetd";
/// Where `snetd` keeps its data (history, alerts, reputation lists).
#[cfg(target_os = "macos")]
pub const DEFAULT_DATA_DIR: &str = "/Library/Application Support/spectraNET";
#[cfg(windows)]
pub const DEFAULT_DATA_DIR: &str = r"C:\ProgramData\spectraNET";
#[cfg(not(any(target_os = "macos", windows)))]
pub const DEFAULT_DATA_DIR: &str = "/var/lib/spectranet";
/// Subdirectory of the data directory holding the reputation lists (world-readable).
pub const FEEDS_SUBDIR: &str = "feeds";
/// Requests are tiny; anything longer is rejected.
pub const MAX_REQUEST: usize = 64 * 1024;
/// Responses carry whole snapshots (thousands of connections on a busy host).
pub const MAX_RESPONSE: usize = 64 * 1024 * 1024;
/// Longest Unix socket path the system accepts (sun_path is 104 bytes on macOS, 108 on Linux;
/// the smaller bound, minus the terminating NUL, is used everywhere).
pub const MAX_SOCKET_PATH: usize = 103;

/// Checks a socket path against [`MAX_SOCKET_PATH`] with a readable error.
pub fn check_socket_path(path: &Path) -> io::Result<()> {
    let len = path.as_os_str().len();
    if len > MAX_SOCKET_PATH {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!(
                "socket path is {len} bytes long; Unix sockets allow at most {MAX_SOCKET_PATH}: {}",
                path.display()
            ),
        ));
    }
    Ok(())
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Request {
    pub v: u32,
    #[serde(flatten)]
    pub command: Command,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "cmd", rename_all = "snake_case")]
pub enum Command {
    /// Health and configuration of the service.
    Status,
    /// The most recent traffic snapshot.
    Snapshot,
    /// Data usage per application per day, for the last `days` days (today included).
    History { days: u32 },
    /// Security alerts raised in the last `since_s` seconds, newest first, at most `limit`.
    Alerts { since_s: u64, limit: u32 },
    /// Stream every new snapshot, each exactly once, until the client disconnects.
    Subscribe,
    /// Do something to a process or connection (see [`Action`]). Answered with
    /// [`Reply::Done`] or [`Reply::Error`].
    Act { action: Action },
    /// The firewall blocks currently in force.
    Blocks,
    /// Actions taken in the last `since_s` seconds, newest first, at most `limit`.
    Audit { since_s: u64, limit: u32 },
}

/// Something the service may do on a client's behalf. Every action is checked against the
/// protected list and recorded in the audit log.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum Action {
    /// End a process: politely first (SIGTERM), then for good if `force` (SIGKILL).
    /// On Windows processes are always ended at once.
    Kill { pid: u32, force: bool },
    /// Freeze a process (SIGSTOP / suspension): it stops using CPU and network at once.
    Pause { pid: u32 },
    /// Unfreeze a paused process.
    Resume { pid: u32 },
    /// Close one connection without touching the rest of the process.
    DropFlow {
        pid: u32,
        transport: spectranet_model::Transport,
        local: SocketAddr,
        remote: SocketAddr,
    },
    /// Block network access for `ttl_s` seconds, or until lifted when 0.
    Block { target: BlockTarget, ttl_s: u64 },
    /// Lift one block (by its id), or all of them.
    Unblock { id: Option<u64> },
}

/// What a block applies to.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(tag = "target", rename_all = "snake_case")]
pub enum BlockTarget {
    /// Every connection of an application (its path, as in [`spectranet_model::AppTraffic`]).
    App { path: String, name: String },
    /// Every connection to or from an address, whatever the application.
    Remote { ip: std::net::IpAddr },
}

/// A block in force.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BlockInfo {
    pub id: u64,
    #[serde(flatten)]
    pub target: BlockTarget,
    /// Seconds since the Unix epoch.
    pub created: u64,
    pub expires: u64,
    /// Who asked for it.
    pub by: String,
    /// How it is enforced on this system, in a few words (e.g. "pf, per connection").
    pub method: String,
}

/// One entry of the audit log.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuditEvent {
    pub ts: u64,
    /// Account that asked.
    pub by: String,
    pub action: Action,
    /// Human description of the target, e.g. `Google Chrome (pid 4892)`.
    pub target: String,
    pub ok: bool,
    pub message: String,
}

/// Actions this service can carry out on this system (see [`Status::capabilities`]).
pub mod capability {
    pub const KILL: &str = "kill";
    pub const PAUSE: &str = "pause";
    pub const DROP: &str = "drop";
    /// Dropping connections works by a technique that may not always succeed.
    pub const DROP_EXPERIMENTAL: &str = "drop-experimental";
    pub const BLOCK_APP: &str = "block-app";
    /// Applications are blocked by following the addresses they use (macOS: pf can't tell
    /// applications apart): a new destination may get through for about one sample.
    pub const BLOCK_APP_PARTIAL: &str = "block-app-partial";
    pub const BLOCK_IP: &str = "block-ip";
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Response {
    pub v: u32,
    #[serde(flatten)]
    pub reply: Reply,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum Reply {
    Status(Status),
    Snapshot(Snapshot),
    History {
        rows: Vec<UsageRow>,
    },
    Alerts {
        events: Vec<AlertEvent>,
    },
    /// An action succeeded; `message` says what happened, in plain words.
    Done {
        message: String,
    },
    Blocks {
        blocks: Vec<BlockInfo>,
    },
    Audit {
        events: Vec<AuditEvent>,
    },
    Error {
        message: String,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Status {
    pub version: String,
    pub pid: u32,
    /// Seconds since the service started.
    pub uptime_s: u64,
    /// Capture backend in use (e.g. `macos`).
    pub source: String,
    pub interval_ms: u64,
    /// Degraded-operation remarks from the capture backend (empty when all is well).
    pub notices: Vec<String>,
    /// Reputation lists loaded by the service.
    #[serde(default)]
    pub feeds: Vec<FeedInfo>,
    /// Alerts raised in the last 24 hours.
    #[serde(default)]
    pub alerts_24h: u64,
    /// Actions available on this system (see [`capability`]); empty from older services.
    #[serde(default)]
    pub capabilities: Vec<String>,
    /// Whether actions need an elevated client (`actions = "elevated-only"`).
    #[serde(default)]
    pub actions_elevated_only: bool,
    /// Blocks currently in force.
    #[serde(default)]
    pub blocks: u64,
    /// The settings of `snetd.conf` in force (absent from older services).
    #[serde(default)]
    pub settings: Option<ServiceSettings>,
}

/// The service's settings (`snetd.conf`), as reported to clients and changed with
/// `snetd config set`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ServiceSettings {
    /// Only elevated administrators may act on processes and connections.
    pub actions_elevated_only: bool,
    /// Prometheus metrics address, when enabled.
    pub metrics: Option<String>,
    /// Refresh the list of known services.
    pub category_updates: bool,
    /// Download the reputation lists.
    pub feed_updates: bool,
    /// Reputation lists not used (by id).
    pub feeds_disabled: Vec<String>,
    /// Days of usage history kept; 0 keeps everything.
    pub history_days: u32,
}

impl Default for ServiceSettings {
    fn default() -> Self {
        Self {
            actions_elevated_only: false,
            metrics: None,
            category_updates: true,
            feed_updates: true,
            feeds_disabled: Vec::new(),
            history_days: 0,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FeedInfo {
    /// Short identifier (e.g. `tor-exits`), for `feeds_disabled`; empty from older services.
    #[serde(default)]
    pub id: String,
    pub name: String,
    /// Address ranges loaded; 0 if the list has not been downloaded.
    pub ranges: u64,
    /// Last download, seconds since the Unix epoch.
    pub updated: Option<u64>,
}

/// Something that deserves the user's attention, as recorded by the service.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AlertEvent {
    /// Seconds since the Unix epoch.
    pub ts: u64,
    /// `info`, `warn` or `alert`.
    pub severity: String,
    /// Rule identifier, e.g. `reputation:feodo`, `cleartext:http`, `first-connection`.
    pub rule: String,
    pub app: String,
    /// Remote endpoint involved, if any.
    pub remote: Option<String>,
    /// Remote hostname, if known.
    pub host: Option<String>,
    pub message: String,
}

/// Bytes an application transferred on one day.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct UsageRow {
    /// Local calendar day, `YYYY-MM-DD`.
    pub day: String,
    /// Display name of the application.
    pub app: String,
    /// Stable identity of the application (bundle or executable path).
    pub key: String,
    pub rx: u64,
    pub tx: u64,
}

impl Request {
    pub fn new(command: Command) -> Self {
        Self {
            v: PROTOCOL_VERSION,
            command,
        }
    }
}

impl Response {
    pub fn new(reply: Reply) -> Self {
        Self {
            v: PROTOCOL_VERSION,
            reply,
        }
    }

    pub fn error(message: impl Into<String>) -> Self {
        Self::new(Reply::Error {
            message: message.into(),
        })
    }
}

/// Writes one message as a JSON line.
pub fn write_message<W: Write + ?Sized, T: Serialize>(
    writer: &mut W,
    message: &T,
) -> io::Result<()> {
    let mut line = serde_json::to_vec(message).map_err(io::Error::other)?;
    line.push(b'\n');
    writer.write_all(&line)?;
    writer.flush()
}

/// Reads one JSON line. `Ok(None)` at a clean end of stream; an error for oversized lines,
/// truncated lines or invalid JSON.
pub fn read_message<R: BufRead, T: DeserializeOwned>(
    reader: &mut R,
    limit: usize,
) -> io::Result<Option<T>> {
    let mut line = Vec::new();
    let read = reader.take(limit as u64 + 1).read_until(b'\n', &mut line)?;
    if read == 0 {
        return Ok(None);
    }
    if line.last() != Some(&b'\n') {
        let reason = if line.len() > limit {
            "message exceeds size limit"
        } else {
            "truncated message"
        };
        return Err(io::Error::new(io::ErrorKind::InvalidData, reason));
    }
    serde_json::from_slice(&line)
        .map(Some)
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))
}

/// Errors talking to the service.
#[derive(Debug)]
pub enum ClientError {
    /// Nothing is listening (service not installed or not running).
    NotRunning,
    /// The socket exists but we may not use it.
    PermissionDenied,
    Io(io::Error),
    /// The service answered with an error or something unexpected.
    Protocol(String),
    /// snetd does not exist on this platform yet.
    Unsupported,
}

impl std::fmt::Display for ClientError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NotRunning => write!(f, "snetd is not running"),
            Self::PermissionDenied => write!(f, "permission denied on the snetd socket"),
            Self::Io(e) => write!(f, "talking to snetd: {e}"),
            Self::Protocol(m) => write!(f, "snetd: {m}"),
            Self::Unsupported => write!(f, "snetd is not available on this platform yet"),
        }
    }
}

impl std::error::Error for ClientError {}

/// Read half of a connection to the service.
type ReadHalf = BufReader<Box<dyn Read + Send>>;
/// Write half of a connection to the service.
type WriteHalf = Box<dyn Write + Send>;

/// A connection to `snetd`: a Unix socket on macOS and Linux, a named pipe on Windows.
pub struct Client {
    reader: ReadHalf,
    writer: WriteHalf,
    /// Lets the subscription lengthen the read timeout (Unix only; pipes have none).
    set_read_timeout: Box<dyn Fn(Option<Duration>) -> io::Result<()> + Send>,
}

impl Client {
    pub fn connect(path: &Path, timeout: Duration) -> Result<Self, ClientError> {
        transport::connect(path, timeout)
    }

    /// Turns this connection into a stream of every snapshot the service takes.
    pub fn subscribe(mut self) -> Result<Subscription, ClientError> {
        write_message(&mut self.writer, &Request::new(Command::Subscribe))
            .map_err(ClientError::Io)?;
        // The service may sample as slowly as once a minute.
        (self.set_read_timeout)(Some(Duration::from_secs(180))).map_err(ClientError::Io)?;
        Ok(Subscription {
            reader: self.reader,
            _writer: self.writer,
        })
    }

    /// Sends a command and returns the reply; service-side errors become `Protocol`.
    pub fn call(&mut self, command: Command) -> Result<Reply, ClientError> {
        write_message(&mut self.writer, &Request::new(command)).map_err(ClientError::Io)?;
        let response: Response = read_message(&mut self.reader, MAX_RESPONSE)
            .map_err(ClientError::Io)?
            .ok_or_else(|| ClientError::Protocol("connection closed".into()))?;
        if response.v != PROTOCOL_VERSION {
            return Err(ClientError::Protocol(format!(
                "protocol version {} (this snet speaks {PROTOCOL_VERSION}); reinstall snet and snetd together",
                response.v
            )));
        }
        match response.reply {
            Reply::Error { message } => Err(ClientError::Protocol(message)),
            reply => Ok(reply),
        }
    }
}

#[cfg(unix)]
mod transport {
    use std::os::unix::net::UnixStream;

    use super::*;

    pub fn connect(path: &Path, timeout: Duration) -> Result<Client, ClientError> {
        check_socket_path(path).map_err(ClientError::Io)?;
        let stream = UnixStream::connect(path).map_err(|e| match e.kind() {
            io::ErrorKind::NotFound | io::ErrorKind::ConnectionRefused => ClientError::NotRunning,
            io::ErrorKind::PermissionDenied => ClientError::PermissionDenied,
            _ => ClientError::Io(e),
        })?;
        stream
            .set_read_timeout(Some(timeout))
            .map_err(ClientError::Io)?;
        stream
            .set_write_timeout(Some(timeout))
            .map_err(ClientError::Io)?;
        let writer = stream.try_clone().map_err(ClientError::Io)?;
        let control = stream.try_clone().map_err(ClientError::Io)?;
        Ok(Client {
            reader: BufReader::new(Box::new(stream)),
            writer: Box::new(writer),
            set_read_timeout: Box::new(move |t| control.set_read_timeout(t)),
        })
    }
}

#[cfg(windows)]
mod transport {
    use std::fs::OpenOptions;
    use std::time::Instant;

    use super::*;

    /// ERROR_PIPE_BUSY: every instance is in use; another frees up shortly.
    const PIPE_BUSY: i32 = 231;

    pub fn connect(path: &Path, timeout: Duration) -> Result<Client, ClientError> {
        let deadline = Instant::now() + timeout;
        let pipe = loop {
            match OpenOptions::new().read(true).write(true).open(path) {
                Ok(file) => break file,
                Err(e) if e.raw_os_error() == Some(PIPE_BUSY) && Instant::now() < deadline => {
                    std::thread::sleep(Duration::from_millis(20));
                }
                Err(e) => {
                    return Err(match e.kind() {
                        io::ErrorKind::NotFound => ClientError::NotRunning,
                        io::ErrorKind::PermissionDenied => ClientError::PermissionDenied,
                        _ => ClientError::Io(e),
                    });
                }
            }
        };
        let writer = pipe.try_clone().map_err(ClientError::Io)?;
        Ok(Client {
            reader: BufReader::new(Box::new(pipe)),
            writer: Box::new(writer),
            // Synchronous pipes have no read timeout; the service always answers promptly.
            set_read_timeout: Box::new(|_| Ok(())),
        })
    }
}

#[cfg(not(any(unix, windows)))]
mod transport {
    use super::*;

    pub fn connect(_path: &Path, _timeout: Duration) -> Result<Client, ClientError> {
        Err(ClientError::Unsupported)
    }
}

/// Snapshots streamed by [`Client::subscribe`].
pub struct Subscription {
    reader: ReadHalf,
    _writer: WriteHalf,
}

impl Iterator for Subscription {
    type Item = Result<spectranet_model::Snapshot, ClientError>;

    /// The next snapshot; `None` when the service closed the stream. A service-side error
    /// (e.g. this client fell behind) is yielded as `Err` and the stream continues.
    fn next(&mut self) -> Option<Self::Item> {
        match read_message::<_, Response>(&mut self.reader, MAX_RESPONSE) {
            Ok(None) => None,
            Err(e) => Some(Err(ClientError::Io(e))),
            Ok(Some(response)) => Some(match response.reply {
                Reply::Snapshot(snapshot) => Ok(snapshot),
                Reply::Error { message } => Err(ClientError::Protocol(message)),
                _ => Err(ClientError::Protocol(
                    "unexpected message in snapshot stream".into(),
                )),
            }),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    #[test]
    fn wire_format_is_stable() {
        let json = serde_json::to_string(&Request::new(Command::History { days: 7 })).unwrap();
        assert_eq!(json, r#"{"v":1,"cmd":"history","days":7}"#);
        let json = serde_json::to_string(&Request::new(Command::Snapshot)).unwrap();
        assert_eq!(json, r#"{"v":1,"cmd":"snapshot"}"#);
        let json = serde_json::to_string(&Response::error("nope")).unwrap();
        assert_eq!(json, r#"{"v":1,"type":"error","message":"nope"}"#);
    }

    #[test]
    fn actions_have_a_stable_wire_format() {
        let kill = Request::new(Command::Act {
            action: Action::Kill {
                pid: 42,
                force: false,
            },
        });
        assert_eq!(
            serde_json::to_string(&kill).unwrap(),
            r#"{"v":1,"cmd":"act","action":{"kind":"kill","pid":42,"force":false}}"#
        );
        let block = Request::new(Command::Act {
            action: Action::Block {
                target: BlockTarget::App {
                    path: "/Applications/X.app".into(),
                    name: "X".into(),
                },
                ttl_s: 3600,
            },
        });
        let json = serde_json::to_string(&block).unwrap();
        assert!(
            json.contains(r#""target":{"target":"app","path":"/Applications/X.app","name":"X"}"#),
            "{json}"
        );
        let back: Request = serde_json::from_str(&json).unwrap();
        assert_eq!(back, block);
        // Old services ignore what they don't know; new clients read old statuses.
        let old = r#"{"version":"0.1.0","pid":1,"uptime_s":5,"source":"macos","interval_ms":1000,"notices":[]}"#;
        let status: Status = serde_json::from_str(old).unwrap();
        assert!(status.capabilities.is_empty() && status.blocks == 0);
    }

    #[test]
    fn round_trips_through_framing() {
        let mut buf = Vec::new();
        let messages = [
            Request::new(Command::Status),
            Request::new(Command::Snapshot),
            Request::new(Command::History { days: 30 }),
        ];
        for m in &messages {
            write_message(&mut buf, m).unwrap();
        }
        let mut reader = Cursor::new(buf);
        for m in &messages {
            let got: Request = read_message(&mut reader, MAX_REQUEST).unwrap().unwrap();
            assert_eq!(&got, m);
        }
        assert!(
            read_message::<_, Request>(&mut reader, MAX_REQUEST)
                .unwrap()
                .is_none()
        );
    }

    #[test]
    fn rejects_oversized_truncated_and_invalid_lines() {
        let big = format!("{}\n", "x".repeat(200));
        let err = read_message::<_, Request>(&mut Cursor::new(big), 100).unwrap_err();
        assert!(err.to_string().contains("size limit"));

        let err = read_message::<_, Request>(&mut Cursor::new(r#"{"v":1,"cmd":"status"}"#), 100)
            .unwrap_err();
        assert!(err.to_string().contains("truncated"));

        for bad in [
            "not json\n",
            "{\"v\":1,\"cmd\":\"reboot\"}\n",
            "{\"cmd\":\"status\"}\n",
            "[]\n",
        ] {
            assert!(
                read_message::<_, Request>(&mut Cursor::new(bad), 100).is_err(),
                "{bad}"
            );
        }
    }

    #[test]
    fn unknown_fields_are_tolerated_for_forward_compatibility() {
        let line = "{\"v\":1,\"cmd\":\"status\",\"future\":true}\n";
        let got: Request = read_message(&mut Cursor::new(line), 100).unwrap().unwrap();
        assert_eq!(got.command, Command::Status);
    }

    #[test]
    fn long_socket_paths_are_explained() {
        let long = std::path::PathBuf::from(format!("/tmp/{}.sock", "x".repeat(120)));
        let err = check_socket_path(&long).unwrap_err().to_string();
        assert!(err.contains("at most 103"), "{err}");
        assert!(check_socket_path(Path::new(DEFAULT_SOCKET)).is_ok());
    }

    #[cfg(unix)]
    #[test]
    fn client_reports_missing_service() {
        let path =
            std::env::temp_dir().join(format!("snet-proto-missing-{}.sock", std::process::id()));
        assert!(matches!(
            Client::connect(&path, Duration::from_secs(1)),
            Err(ClientError::NotRunning)
        ));
    }
}
