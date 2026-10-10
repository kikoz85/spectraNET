//! `snet top`: the interactive full-screen view.

mod act;
mod flows;
mod keys;
mod state;
mod tree;
mod ui;

use std::io::IsTerminal;
use std::sync::mpsc::{self, Receiver, RecvTimeoutError};
use std::thread;
use std::time::Duration;

use anyhow::{Result, bail};
use ratatui::crossterm::event::{self, Event};
use spectranet_capture::TrafficSource;
use spectranet_model::Snapshot;

use crate::cli::ViewArgs;
use state::{Action, TopState};

/// How often input is checked when nothing else happens.
const INPUT_POLL: Duration = Duration::from_millis(50);

pub fn run(
    source: Box<dyn TrafficSource>,
    args: &ViewArgs,
    socket: &std::path::Path,
) -> Result<()> {
    if !std::io::stdout().is_terminal() || !std::io::stdin().is_terminal() {
        bail!("snet top needs an interactive terminal; use 'snet watch' for pipes and logs");
    }
    let mut state = TopState::new(args, source.name());
    state.notices = source.notices();
    let (settings, warning) = keys::Settings::load();
    state.settings = settings;
    state.message = warning.map(|w| (false, w));
    // Actions go through snetd, which has the rights and keeps the audit log.
    if source.name() == "snetd" {
        state.actions = match act::Service::connect(socket.to_path_buf()) {
            Ok(service) => Box::new(service),
            Err(e) => Box::new(act::Unavailable(format!("actions unavailable: {e}"))),
        };
    }
    let samples = spawn_sampler(source, args.interval);
    // `try_init` enters the alternate screen and raw mode, and installs a panic hook that
    // restores the terminal; `restore` below undoes it on every other exit path.
    let mut terminal = ratatui::try_init()?;
    let result = (|| -> Result<()> {
        loop {
            terminal.draw(|frame| ui::draw(frame, &state))?;
            if event::poll(INPUT_POLL)? {
                match event::read()? {
                    Event::Key(key) => {
                        if state.handle_key(key) == Action::Quit {
                            return Ok(());
                        }
                    }
                    Event::Resize(..) => {}
                    _ => continue,
                }
            }
            drain(&samples, &mut state)?;
            state.poll_actions();
        }
    })();
    ratatui::restore();
    result
}

/// Applies everything the sampler produced since the last frame.
fn drain(samples: &Receiver<Result<Snapshot, String>>, state: &mut TopState) -> Result<()> {
    loop {
        match samples.recv_timeout(Duration::ZERO) {
            Ok(Ok(snapshot)) => state.on_snapshot(snapshot),
            Ok(Err(message)) => state.on_error(message),
            Err(RecvTimeoutError::Timeout) => return Ok(()),
            Err(RecvTimeoutError::Disconnected) => {
                bail!("the sampling thread stopped unexpectedly")
            }
        }
    }
}

/// Samples on a background thread so the interface never blocks on capture. The thread
/// ends by itself when the receiver is dropped.
fn spawn_sampler(
    mut source: Box<dyn TrafficSource>,
    interval: Duration,
) -> Receiver<Result<Snapshot, String>> {
    let (tx, rx) = mpsc::sync_channel(4);
    let _ = thread::Builder::new()
        .name("snet-top-sampler".into())
        .spawn(move || {
            if !source.first_sample_has_rates() {
                let _ = source.sample();
                thread::sleep(interval);
            }
            loop {
                let sample = source.sample().map_err(|e| e.to_string());
                if tx.send(sample).is_err() {
                    return;
                }
                thread::sleep(interval);
            }
        });
    rx
}
