//! `snet` — the spectraNET command-line interface.

mod check;
mod cli;
mod daemon;
mod duration;
mod exit;
mod flows_cmd;
mod flowtext;
mod man;
mod recorder;
mod top;
mod units;
mod view;

use std::io::{IsTerminal, Write};
use std::process::ExitCode;
use std::thread;

use anyhow::Context;
use clap::{CommandFactory, Parser};
use spectranet_capture::mock::MockSource;
use spectranet_capture::{CaptureError, SourceOptions, TrafficSource, system_source};
use spectranet_model::Snapshot;

use crate::cli::{Cli, ColorWhen, Command, GenerateWhat, ViewArgs};
use crate::view::View;

fn main() -> ExitCode {
    let cli = Cli::parse();
    match cli.color {
        ColorWhen::Auto => {}
        ColorWhen::Always => anstream::ColorChoice::Always.write_global(),
        ColorWhen::Never => anstream::ColorChoice::Never.write_global(),
    }

    if let Command::Check(args) = &cli.command {
        return ExitCode::from(check::run(&cli, args) as u8);
    }
    let result = match &cli.command {
        Command::List(args) => {
            open_source(&cli).and_then(|mut source| list(source.as_mut(), &args.view))
        }
        Command::Watch(args) => {
            open_source(&cli).and_then(|mut source| watch(source.as_mut(), &args.view, args.count))
        }
        Command::Top(args) => {
            open_source_quiet(&cli).and_then(|source| top::run(source, &args.view, &cli.socket))
        }
        Command::Status => daemon::status(&cli.socket).map(|text| anstream::print!("{text}")),
        Command::History(args) => history(&cli.socket, args),
        Command::Alerts(args) => alerts(&cli.socket, args),
        Command::Kill(args) => act(
            &cli.socket,
            spectranet_proto::Action::Kill {
                pid: args.pid,
                force: args.force,
            },
        ),
        Command::Pause(args) => act(
            &cli.socket,
            spectranet_proto::Action::Pause { pid: args.pid },
        ),
        Command::Resume(args) => act(
            &cli.socket,
            spectranet_proto::Action::Resume { pid: args.pid },
        ),
        Command::Drop(args) => act(
            &cli.socket,
            spectranet_proto::Action::DropFlow {
                pid: args.pid,
                transport: if args.udp {
                    spectranet_model::Transport::Udp
                } else {
                    spectranet_model::Transport::Tcp
                },
                local: args.local,
                remote: args.remote,
            },
        ),
        Command::Stream(args) => {
            open_source(&cli).and_then(|mut source| flows_cmd::stream(source.as_mut(), args))
        }
        Command::Inspect(args) => {
            open_source(&cli).and_then(|mut source| flows_cmd::inspect(source.as_mut(), args))
        }
        Command::Block(args) => {
            daemon::block_target(&cli.socket, &args.target).and_then(|target| {
                act(
                    &cli.socket,
                    spectranet_proto::Action::Block {
                        target,
                        ttl_s: args.ttl,
                    },
                )
            })
        }
        Command::Unblock(args) => act(
            &cli.socket,
            spectranet_proto::Action::Unblock {
                id: if args.all { None } else { args.id },
            },
        ),
        Command::Blocks(args) => blocks(&cli.socket, args.json),
        Command::Audit(args) => audit(&cli.socket, args),
        Command::Record(args) => {
            record_feed(&cli, args).and_then(|feed| recorder::record(feed, args))
        }
        Command::Analyze(args) => recorder::analyze(args),
        Command::Generate(args) => generate(&args.what),
        Command::Check(_) => unreachable!("handled above"),
    };

    match result {
        Ok(()) => ExitCode::from(exit::SUCCESS as u8),
        Err(err) => {
            anstream::eprintln!("snet: {err:#}");
            ExitCode::from(exit::code_for(&err) as u8)
        }
    }
}

/// Like [`open_source`] but leaves notices to the caller (the full-screen view shows them
/// itself; printed before it starts they would vanish behind the alternate screen).
fn open_source_quiet(cli: &Cli) -> anyhow::Result<Box<dyn TrafficSource>> {
    open_source_inner(cli)
}

/// Picks the traffic source and prints its notices to standard error.
fn open_source(cli: &Cli) -> anyhow::Result<Box<dyn TrafficSource>> {
    let source = open_source_inner(cli)?;
    for notice in source.notices() {
        anstream::eprintln!("snet: {notice}");
    }
    Ok(source)
}

/// Picks the traffic source: the simulator, the snetd service when it is running, or direct
/// capture.
fn open_source_inner(cli: &Cli) -> anyhow::Result<Box<dyn TrafficSource>> {
    let mut source: Box<dyn TrafficSource> = if cli.mock {
        // The simulator gets the same classification as the real thing.
        Box::new(Classified {
            inner: Box::new(MockSource::default()),
            classifier: spectranet_intel::classify::Classifier::new(
                spectranet_intel::classify::Domains::builtin(),
            ),
        })
    } else if let Some(service) = (!cli.no_daemon).then(|| service_source(cli)).flatten() {
        service
    } else {
        let live = system_source(SourceOptions {
            resolve_names: !cli.numeric,
            service: false,
        })?;
        // Without the service, apply the same rules here, with whatever lists it downloaded.
        let feeds = std::path::Path::new(spectranet_proto::DEFAULT_DATA_DIR)
            .join(spectranet_proto::FEEDS_SUBDIR);
        Box::new(Annotated {
            inner: live,
            intel: spectranet_intel::Intel::load(&feeds),
            classifier: spectranet_intel::classify::Classifier::new(
                spectranet_intel::classify::Domains::load(&feeds),
            ),
        })
    };
    if cli.numeric {
        source = Box::new(Numeric(source));
    }
    Ok(source)
}

/// Where `snet record` takes its snapshots from: snetd's stream when it runs, else sampling
/// here.
fn record_feed(cli: &Cli, args: &cli::RecordArgs) -> anyhow::Result<recorder::Feed> {
    if !cli.mock && !cli.no_daemon {
        match daemon::connect(&cli.socket).and_then(spectranet_proto::Client::subscribe) {
            Ok(stream) => return Ok(recorder::Feed::Service(stream)),
            Err(
                spectranet_proto::ClientError::NotRunning
                | spectranet_proto::ClientError::Unsupported,
            ) => {}
            Err(e) => anstream::eprintln!("snet: not using snetd ({e}); capturing directly"),
        }
    }
    let source = open_source(cli)?;
    Ok(recorder::Feed::Direct {
        source,
        interval: args.interval,
        primed: false,
    })
}

/// snetd as a source, if it is running and we may talk to it.
fn service_source(cli: &Cli) -> Option<Box<dyn TrafficSource>> {
    match daemon::connect(&cli.socket).and_then(daemon::DaemonSource::new) {
        Ok(source) => Some(Box::new(source)),
        Err(
            spectranet_proto::ClientError::NotRunning | spectranet_proto::ClientError::Unsupported,
        ) => None,
        Err(e) => {
            anstream::eprintln!("snet: not using snetd ({e}); capturing directly");
            None
        }
    }
}

fn alerts(socket: &std::path::Path, args: &cli::AlertsArgs) -> anyhow::Result<()> {
    let events = daemon::alerts(socket, args.since, args.limit)?;
    let mut out = anstream::stdout().lock();
    if args.json {
        serde_json::to_writer(&mut out, &events)?;
        writeln!(out)?;
    } else {
        write!(out, "{}", daemon::render_alerts(&events, args.since))?;
    }
    Ok(())
}

fn act(socket: &std::path::Path, action: spectranet_proto::Action) -> anyhow::Result<()> {
    let message = daemon::act(socket, action)?;
    anstream::println!("{message}");
    Ok(())
}

fn blocks(socket: &std::path::Path, json: bool) -> anyhow::Result<()> {
    let list = daemon::blocks(socket)?;
    let mut out = anstream::stdout().lock();
    if json {
        serde_json::to_writer(&mut out, &list)?;
        writeln!(out)?;
    } else {
        write!(out, "{}", daemon::render_blocks(&list, daemon::now_s()))?;
    }
    Ok(())
}

fn audit(socket: &std::path::Path, args: &cli::AlertsArgs) -> anyhow::Result<()> {
    let events = daemon::audit(socket, args.since, args.limit)?;
    let mut out = anstream::stdout().lock();
    if args.json {
        serde_json::to_writer(&mut out, &events)?;
        writeln!(out)?;
    } else {
        write!(out, "{}", daemon::render_audit(&events, args.since))?;
    }
    Ok(())
}

fn history(socket: &std::path::Path, args: &cli::HistoryArgs) -> anyhow::Result<()> {
    let rows = daemon::history_rows(socket, args.days)?;
    let mut out = anstream::stdout().lock();
    if args.json {
        serde_json::to_writer(&mut out, &rows)?;
        writeln!(out)?;
    } else {
        write!(
            out,
            "{}",
            daemon::render_history(&rows, args.days, args.limit)
        )?;
    }
    Ok(())
}

/// Applies the security rules to a source that does not apply them itself.
struct Annotated {
    inner: Box<dyn TrafficSource>,
    intel: spectranet_intel::Intel,
    /// What kind of traffic each connection carries (snetd does it when it runs).
    classifier: spectranet_intel::classify::Classifier,
}

impl TrafficSource for Annotated {
    fn name(&self) -> &'static str {
        self.inner.name()
    }

    fn sample(&mut self) -> Result<Snapshot, CaptureError> {
        let mut snapshot = self.inner.sample()?;
        self.classifier.annotate(&mut snapshot);
        self.intel.annotate(&mut snapshot);
        Ok(snapshot)
    }

    fn notices(&self) -> Vec<String> {
        self.inner.notices()
    }

    fn first_sample_has_rates(&self) -> bool {
        self.inner.first_sample_has_rates()
    }
}

/// Classifies the traffic of a source that is not already classified (the simulator).
struct Classified {
    inner: Box<dyn TrafficSource>,
    classifier: spectranet_intel::classify::Classifier,
}

impl TrafficSource for Classified {
    fn name(&self) -> &'static str {
        self.inner.name()
    }

    fn sample(&mut self) -> Result<Snapshot, CaptureError> {
        let mut snapshot = self.inner.sample()?;
        self.classifier.annotate(&mut snapshot);
        Ok(snapshot)
    }

    fn notices(&self) -> Vec<String> {
        self.inner.notices()
    }

    fn first_sample_has_rates(&self) -> bool {
        self.inner.first_sample_has_rates()
    }
}

/// Hides hostnames from any source, for `-n/--numeric`.
struct Numeric(Box<dyn TrafficSource>);

impl TrafficSource for Numeric {
    fn name(&self) -> &'static str {
        self.0.name()
    }

    fn sample(&mut self) -> Result<Snapshot, CaptureError> {
        let mut snapshot = self.0.sample()?;
        for flow in snapshot
            .processes
            .iter_mut()
            .flat_map(|p| p.flows.iter_mut())
        {
            flow.remote_host = None;
        }
        Ok(snapshot)
    }

    fn notices(&self) -> Vec<String> {
        self.0.notices()
    }

    fn first_sample_has_rates(&self) -> bool {
        self.0.first_sample_has_rates()
    }
}

/// Samples twice, one interval apart, so the rates reflect a full interval.
fn list(source: &mut dyn TrafficSource, args: &ViewArgs) -> anyhow::Result<()> {
    if !source.first_sample_has_rates() {
        source.sample()?;
        thread::sleep(args.interval);
    }
    let view = view::select(source.sample()?, args);
    print_view(view, args, false)
}

fn watch(
    source: &mut dyn TrafficSource,
    args: &ViewArgs,
    count: Option<u64>,
) -> anyhow::Result<()> {
    let redraw = !args.json && std::io::stdout().is_terminal();
    source.sample()?;
    let mut shown = 0;
    while count.is_none_or(|c| shown < c) {
        thread::sleep(args.interval);
        let view = view::select(source.sample()?, args);
        if redraw {
            // Home the cursor and clear the screen, then draw the new frame.
            print!("\x1b[H\x1b[2J");
        } else if shown > 0 && !args.json {
            println!();
        }
        print_view(view, args, redraw)?;
        shown += 1;
    }
    Ok(())
}

fn print_view(view: View, args: &ViewArgs, live: bool) -> anyhow::Result<()> {
    let mut out = anstream::stdout().lock();
    if args.json {
        serde_json::to_writer(&mut out, &view.into_snapshot())?;
        writeln!(out)?;
    } else {
        if live {
            writeln!(
                out,
                "spectraNET · source: {} · every {:?} · Ctrl-C to quit\n",
                view.source, args.interval
            )?;
        }
        write!(out, "{}", view::table(&view, args.connections))?;
        writeln!(out, "\n{}", view::summary(&view))?;
    }
    out.flush()?;
    Ok(())
}

fn generate(what: &GenerateWhat) -> anyhow::Result<()> {
    match what {
        GenerateWhat::Man { dir } => {
            for page in man::generate(dir)
                .with_context(|| format!("writing man pages to {}", dir.display()))?
            {
                println!("{}", page.display());
            }
        }
        GenerateWhat::Completions { shell } => {
            clap_complete::generate(*shell, &mut Cli::command(), "snet", &mut std::io::stdout());
        }
    }
    Ok(())
}
