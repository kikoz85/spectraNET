//! `snetd` — the spectraNET background service.

use std::process::ExitCode;
use std::sync::Arc;
use std::sync::atomic::AtomicBool;

use anyhow::{Context, Result};
use clap::Parser;
use spectranet_daemon::cli::{Cli, Command, ConfigAction};

fn main() -> ExitCode {
    let cli = Cli::parse();
    let result = match cli.command {
        Command::Run(args) => {
            stop_on_signals().and_then(|stop| spectranet_daemon::run_live(args.mock, &args, &stop))
        }
        Command::Install => install(),
        Command::Uninstall { purge } => uninstall(purge),
        Command::GenerateMan { dir } => generate_man(&dir),
        Command::Config { action } => config(action),
        Command::Service => service(),
    };
    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("snetd: {e:#}");
            ExitCode::FAILURE
        }
    }
}

fn stop_on_signals() -> Result<Arc<AtomicBool>> {
    let stop = Arc::new(AtomicBool::new(false));
    #[cfg(unix)]
    let signals = [
        signal_hook::consts::SIGTERM,
        signal_hook::consts::SIGINT,
        signal_hook::consts::SIGHUP,
    ];
    #[cfg(not(unix))]
    let signals = [signal_hook::consts::SIGTERM, signal_hook::consts::SIGINT];
    for signal in signals {
        signal_hook::flag::register(signal, stop.clone()).context("installing signal handlers")?;
    }
    Ok(stop)
}

/// `snetd config show | set KEY=VALUE…`.
fn config(action: ConfigAction) -> Result<()> {
    use spectranet_daemon::config;
    let dir = std::path::Path::new(spectranet_proto::DEFAULT_DATA_DIR);
    match action {
        ConfigAction::Show => {
            print!("{}", config::load(dir).render());
            Ok(())
        }
        ConfigAction::Set { pairs } => {
            let saved = config::set_and_save(dir, &pairs)?;
            print!("{}", saved.render());
            restart()
        }
    }
}

#[cfg(unix)]
fn restart() -> Result<()> {
    spectranet_daemon::install::restart()
}
#[cfg(windows)]
fn restart() -> Result<()> {
    spectranet_daemon::winsvc::restart()
}

#[cfg(unix)]
fn install() -> Result<()> {
    spectranet_daemon::install::install()
}
#[cfg(windows)]
fn install() -> Result<()> {
    spectranet_daemon::winsvc::install()
}

#[cfg(unix)]
fn uninstall(purge: bool) -> Result<()> {
    spectranet_daemon::install::uninstall(purge)
}
#[cfg(windows)]
fn uninstall(purge: bool) -> Result<()> {
    spectranet_daemon::winsvc::uninstall(purge)
}

#[cfg(unix)]
fn generate_man(dir: &std::path::Path) -> Result<()> {
    let page = spectranet_daemon::man::write_snetd_page(dir)?;
    println!("{}", page.display());
    Ok(())
}
#[cfg(windows)]
fn generate_man(_dir: &std::path::Path) -> Result<()> {
    anyhow::bail!("man pages are not used on Windows")
}

#[cfg(windows)]
fn service() -> Result<()> {
    spectranet_daemon::winsvc::dispatch()
}
#[cfg(unix)]
fn service() -> Result<()> {
    anyhow::bail!("'snetd service' is for the Windows Service Control Manager; use 'snetd run'")
}
