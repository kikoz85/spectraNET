//! Sending actions to snetd from `snet top`, off the interface thread. Results come back
//! through a channel and are shown in the footer.

use std::path::PathBuf;
use std::sync::mpsc::{Receiver, Sender, channel};
use std::time::Duration;

use spectranet_proto::{Action, Client, Command, Reply, capability};

/// Where actions go.
pub trait ActionSink {
    /// Starts an action; its outcome arrives through [`ActionSink::results`].
    fn send(&mut self, action: Action);
    /// Outcomes received since the last call: `Ok(message)` or `Err(reason)`.
    fn results(&mut self) -> Vec<Result<String, String>>;
    /// Capabilities of the service, or why there is none.
    fn availability(&self) -> Result<&[String], &str>;
}

/// No service: every action explains how to get one.
pub struct Unavailable(pub String);

impl ActionSink for Unavailable {
    fn send(&mut self, _: Action) {}
    fn results(&mut self) -> Vec<Result<String, String>> {
        Vec::new()
    }
    fn availability(&self) -> Result<&[String], &str> {
        Err(&self.0)
    }
}

/// The real thing: one short connection to snetd per action.
pub struct Service {
    socket: PathBuf,
    capabilities: Vec<String>,
    tx: Sender<Result<String, String>>,
    rx: Receiver<Result<String, String>>,
}

impl Service {
    /// Connects once to learn what the service can do on this system.
    pub fn connect(socket: PathBuf) -> Result<Self, String> {
        let mut client =
            Client::connect(&socket, Duration::from_secs(2)).map_err(|e| e.to_string())?;
        let capabilities = match client.call(Command::Status).map_err(|e| e.to_string())? {
            Reply::Status(status) => status.capabilities,
            _ => Vec::new(),
        };
        let (tx, rx) = channel();
        Ok(Self {
            socket,
            capabilities,
            tx,
            rx,
        })
    }
}

impl ActionSink for Service {
    fn send(&mut self, action: Action) {
        let socket = self.socket.clone();
        let tx = self.tx.clone();
        let _ = std::thread::Builder::new()
            .name("snet-top-action".into())
            .spawn(move || {
                let outcome = Client::connect(&socket, Duration::from_secs(3))
                    .map_err(|e| e.to_string())
                    .and_then(|mut c| c.call(Command::Act { action }).map_err(|e| e.to_string()))
                    .and_then(|reply| match reply {
                        Reply::Done { message } => Ok(message),
                        Reply::Error { message } => Err(message),
                        _ => Err("unexpected reply from snetd".into()),
                    });
                let _ = tx.send(outcome);
            });
    }

    fn results(&mut self) -> Vec<Result<String, String>> {
        self.rx.try_iter().collect()
    }

    fn availability(&self) -> Result<&[String], &str> {
        if self.capabilities.is_empty() {
            Err("this snetd is older than snet: reinstall both to use actions")
        } else {
            Ok(&self.capabilities)
        }
    }
}

/// Whether `cap` is available, or why not.
pub fn check(sink: &dyn ActionSink, cap: &str) -> Result<(), String> {
    match sink.availability() {
        Err(why) => Err(why.to_string()),
        Ok(caps) if caps.iter().any(|c| c == cap) => Ok(()),
        Ok(caps)
            if cap == capability::DROP
                && caps.iter().any(|c| c == capability::DROP_EXPERIMENTAL) =>
        {
            Ok(())
        }
        Ok(_) => Err(match cap {
            capability::DROP => {
                "closing a single connection is not available on this system".into()
            }
            other => format!("'{other}' is not available on this system"),
        }),
    }
}

#[cfg(test)]
pub mod fake {
    use super::*;

    /// Records actions and answers them with a fixed outcome.
    pub struct Recorder {
        pub sent: Vec<Action>,
        pub caps: Vec<String>,
        pub answer: Result<String, String>,
        pending: usize,
    }

    impl Recorder {
        pub fn new(caps: &[&str]) -> Self {
            Self {
                sent: Vec::new(),
                caps: caps.iter().map(|c| c.to_string()).collect(),
                answer: Ok("done".into()),
                pending: 0,
            }
        }
    }

    impl ActionSink for Recorder {
        fn send(&mut self, action: Action) {
            self.sent.push(action);
            self.pending += 1;
        }
        fn results(&mut self) -> Vec<Result<String, String>> {
            let n = std::mem::take(&mut self.pending);
            vec![self.answer.clone(); n]
        }
        fn availability(&self) -> Result<&[String], &str> {
            Ok(&self.caps)
        }
    }
}
