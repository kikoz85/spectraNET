//! The service: samples traffic continuously, keeps history, answers clients.

use std::collections::VecDeque;
use std::io::{self, BufReader, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Condvar, Mutex, RwLock};
use std::thread;
use std::time::{Duration, Instant};

use anyhow::{Result, bail};
use spectranet_capture::TrafficSource;
use spectranet_intel::{Intel, feeds};
use spectranet_model::Snapshot;
use spectranet_proto::{
    Command, FeedInfo, MAX_REQUEST, PROTOCOL_VERSION, Reply, Request, Response, Status,
    read_message, write_message,
};

use crate::alerts::Watchdog;
use crate::transport::{self, Conn, Listener};
use crate::usage::{self, Accumulator, Store};

/// Simultaneous client connections served; more are refused immediately.
const MAX_CLIENTS: usize = 32;
/// Consecutive failed samples after which the service exits (launchd or systemd restart it).
const MAX_CONSECUTIVE_FAILURES: u32 = 10;
/// Longest history window a client may ask for.
const MAX_HISTORY_DAYS: u32 = 3_660;
/// Most alerts returned by one request.
const MAX_ALERTS: u32 = 10_000;
/// How often the reputation lists are checked for staleness.
const FEED_CHECK_EVERY: Duration = Duration::from_secs(3600);

#[derive(Debug, Clone)]
pub struct Config {
    pub socket: PathBuf,
    pub database: PathBuf,
    pub interval: Duration,
    pub flush_every: Duration,
    /// Group allowed to use the socket (mode 0660); `None` keeps it private to the owner.
    pub socket_group: Option<u32>,
    /// Directory of the reputation lists.
    pub feeds_dir: PathBuf,
    /// Download the reputation lists when missing or stale.
    pub update_feeds: bool,
    /// Who may act on processes and connections.
    pub policy: crate::actions::Policy,
    /// Serve Prometheus metrics here (opt-in).
    pub metrics: Option<std::net::SocketAddr>,
    /// Refresh the list of known services along with the reputation lists.
    pub category_updates: bool,
    /// Reputation lists turned off (by id).
    pub feeds_disabled: Vec<String>,
    /// Days of usage history kept; 0 keeps everything.
    pub history_days: u32,
    /// The settings file as read, reported to clients.
    pub settings: spectranet_proto::ServiceSettings,
    /// Internet targets of the network check (empty: the defaults).
    pub check_targets: Vec<String>,
    /// Minutes of high internet latency before alerting (0: no watch).
    pub latency_watch_minutes: u32,
}

struct Shared {
    /// The latest snapshot and its sequence number (incremented on every sample).
    latest: Mutex<(u64, Option<Snapshot>)>,
    fresh: Condvar,
    pending: Mutex<Accumulator>,
    store: Mutex<Store>,
    started: Instant,
    source: String,
    notices: Vec<String>,
    interval: Duration,
    clients: AtomicUsize,
    intel: RwLock<Intel>,
    watchdog: Mutex<Watchdog>,
    /// Set when the service stops: the accept loop then exits and closes the endpoint.
    stopping: AtomicBool,
    policy: crate::actions::Policy,
    /// Processes paused through snetd (so they can be resumed even when silent).
    paused: Mutex<std::collections::HashSet<u32>>,
    /// Applications and addresses blocked.
    blocks: Mutex<crate::blocks::Blocks>,
    metrics: Mutex<crate::metrics::Metrics>,
    /// What kind of traffic each connection carries.
    classifier: Mutex<spectranet_intel::classify::Classifier>,
    settings: spectranet_proto::ServiceSettings,
    feeds_disabled: Vec<String>,
    history_days: u32,
    /// The last minute of reconciliation with the interfaces: (interface bytes, attributed
    /// bytes) per sample, and the interfaces of the latest sample.
    coverage: Mutex<CoverageWindow>,
    /// The usual latency, the recent traffic peak and the watch's state.
    network: crate::netcheck::SharedMemory,
    check_targets: Vec<String>,
}

/// (interface bytes, attributed bytes) per sample, and the interfaces of the latest one.
type CoverageWindow = (VecDeque<(u64, u64)>, Vec<String>);

/// Samples kept for the coverage reported in the status.
const COVERAGE_WINDOW: usize = 60;

/// Runs until `stop` is set. Removes its socket on the way out.
pub fn run(config: &Config, mut source: Box<dyn TrafficSource>, stop: &AtomicBool) -> Result<()> {
    let mut store = Store::open(&config.database)?;
    let baseline_until = store.prepare_alerts(unix_now())?;
    store.prepare_actions(unix_now())?;
    store.prepare_checks()?;
    // The usual latency picks up where the last day's checks left it.
    let mut network = crate::netcheck::Memory::default();
    for report in store.checks(100).unwrap_or_default() {
        if report.started_ms / 1000 + 86_400 > unix_now()
            && let Some(ms) = crate::netcheck::internet_ms(&report)
        {
            network.add_latency(ms);
        }
    }
    let blocks = crate::blocks::Blocks::restore(&store, unix_now());
    let watchdog =
        Watchdog::new(store.seen_apps()?, baseline_until).with_fingerprints(store.fingerprints()?);
    let listener = Listener::bind(&config.socket, config.socket_group)?;
    let shared = Arc::new(Shared {
        latest: Mutex::new((0, None)),
        fresh: Condvar::new(),
        pending: Mutex::new(Accumulator::default()),
        store: Mutex::new(store),
        started: Instant::now(),
        source: source.name().to_string(),
        notices: source.notices(),
        interval: config.interval,
        clients: AtomicUsize::new(0),
        intel: RwLock::new(Intel::new(
            feeds::Feeds::load(&config.feeds_dir).without(&config.feeds_disabled),
        )),
        watchdog: Mutex::new(watchdog),
        stopping: AtomicBool::new(false),
        policy: config.policy,
        paused: Mutex::new(std::collections::HashSet::new()),
        blocks: Mutex::new(blocks),
        metrics: Mutex::new(crate::metrics::Metrics::default()),
        classifier: Mutex::new(spectranet_intel::classify::Classifier::new(
            spectranet_intel::classify::Domains::load(&config.feeds_dir),
        )),
        settings: config.settings.clone(),
        feeds_disabled: config.feeds_disabled.clone(),
        history_days: config.history_days,
        coverage: Mutex::new((VecDeque::new(), Vec::new())),
        network: Mutex::new(network),
        check_targets: config.check_targets.clone(),
    });
    prune_history(&shared);
    for notice in &shared.notices {
        log(&format!("notice: {notice}"));
    }
    log(&format!(
        "started: source {}, every {:?}, socket {}",
        shared.source,
        config.interval,
        config.socket.display()
    ));

    if config.latency_watch_minutes > 0 {
        let shared = shared.clone();
        let minutes = config.latency_watch_minutes;
        thread::Builder::new()
            .name("snetd-latency".into())
            .spawn(move || watch_latency(&shared, minutes))?;
    }

    if config.update_feeds {
        let shared = shared.clone();
        let dir = config.feeds_dir.clone();
        let categories = config.category_updates;
        thread::Builder::new()
            .name("snetd-feeds".into())
            .spawn(move || keep_feeds_fresh(&dir, categories, &shared))?;
    }

    if let Some(addr) = config.metrics {
        let shared = shared.clone();
        match crate::metrics::serve(addr, move || render_metrics(&shared)) {
            Ok(bound) => log(&format!("Prometheus metrics on http://{bound}/metrics")),
            Err(e) => log(&format!("metrics: cannot listen on {addr}: {e}")),
        }
    }

    let server = {
        let shared = shared.clone();
        thread::Builder::new()
            .name("snetd-server".into())
            .spawn(move || serve(&listener, &shared))?
    };

    let result = sample_loop(config, source.as_mut(), &shared, stop);

    flush(&shared);
    let _ = std::fs::remove_file(&config.socket);
    // Wake the accept loop so the server thread can notice the socket is gone.
    shared.stopping.store(true, Ordering::SeqCst);
    transport::cleanup(&config.socket);
    transport::wake(&config.socket);
    // The accept loop exits after the wake-up connection; bounded wait so a stuck accept can
    // never hold the service up.
    let deadline = Instant::now() + Duration::from_secs(2);
    while !server.is_finished() && Instant::now() < deadline {
        thread::sleep(Duration::from_millis(10));
    }
    log("stopped");
    result
}

fn render_metrics(shared: &Shared) -> String {
    let state = crate::metrics::ServiceState {
        version: env!("CARGO_PKG_VERSION"),
        uptime_s: shared.started.elapsed().as_secs(),
        clients: shared.clients.load(Ordering::Relaxed),
        alerts_24h: shared
            .store
            .lock()
            .ok()
            .and_then(|s| s.count_alerts_since(unix_now().saturating_sub(86_400)).ok())
            .unwrap_or(0),
        blocks: shared.blocks.lock().map(|b| b.len()).unwrap_or(0),
    };
    shared
        .metrics
        .lock()
        .map(|m| m.render(&state))
        .unwrap_or_default()
}

/// Lifts expired blocks (recording it) and keeps the others in force.
fn keep_blocks(shared: &Shared, snapshot: &Snapshot) {
    let Ok(mut blocks) = shared.blocks.lock() else {
        return;
    };
    if blocks.is_empty() {
        return;
    }
    let store = shared.store.lock().ok();
    let now = unix_now();
    for b in blocks.expire(store.as_deref(), now) {
        let action = spectranet_proto::Action::Unblock { id: Some(b.id) };
        let message = format!("block {} expired", b.id);
        if let Some(store) = store.as_deref() {
            let _ = store.record_action(
                now,
                "snetd",
                &action,
                &format!("block {}", b.id),
                true,
                &message,
            );
        }
        log(&message);
    }
    drop(store);
    blocks.on_snapshot(snapshot);
}

fn sample_loop(
    config: &Config,
    source: &mut dyn TrafficSource,
    shared: &Shared,
    stop: &AtomicBool,
) -> Result<()> {
    let mut failures = 0;
    let mut last_flush = Instant::now();
    let mut last_prune = Instant::now();
    let mut next = Instant::now();
    while !stop.load(Ordering::Relaxed) {
        match source.sample() {
            Ok(mut snapshot) => {
                failures = 0;
                if let Ok(mut classifier) = shared.classifier.lock() {
                    classifier.annotate(&mut snapshot);
                }
                let findings = shared
                    .intel
                    .read()
                    .map(|i| i.annotate(&mut snapshot))
                    .unwrap_or_default();
                if let (Ok(mut dog), Ok(mut store)) = (shared.watchdog.lock(), shared.store.lock())
                {
                    match dog.observe(&mut store, &snapshot, &findings, unix_now()) {
                        Ok(events) => {
                            for e in events.iter().filter(|e| e.severity != "info") {
                                log(&format!(
                                    "{}: {} → {}: {}",
                                    e.severity,
                                    e.app,
                                    e.host.as_deref().or(e.remote.as_deref()).unwrap_or("-"),
                                    e.message
                                ));
                            }
                        }
                        Err(e) => log(&format!("recording alerts failed: {e:#}")),
                    }
                }
                if let Ok(mut pending) = shared.pending.lock() {
                    pending.record(&usage::today(), &snapshot);
                }
                if let (Some(link), Ok(mut coverage)) = (&snapshot.link, shared.coverage.lock()) {
                    let secs = snapshot.interval_ms as f64 / 1000.0;
                    let bytes = |rate: u64| (rate as f64 * secs) as u64;
                    coverage.0.push_back((
                        bytes(link.rx_rate + link.tx_rate),
                        bytes(link.attributed_rx + link.attributed_tx),
                    ));
                    while coverage.0.len() > COVERAGE_WINDOW {
                        coverage.0.pop_front();
                    }
                    coverage.1.clone_from(&link.interfaces);
                }
                keep_blocks(shared, &snapshot);
                if config.metrics.is_some()
                    && let Ok(mut metrics) = shared.metrics.lock()
                {
                    metrics.observe(&snapshot);
                }
                if let Ok(mut network) = shared.network.lock() {
                    network.add_traffic(snapshot.rx_rate() + snapshot.tx_rate());
                }
                if let Ok(mut latest) = shared.latest.lock() {
                    *latest = (latest.0 + 1, Some(snapshot));
                }
                shared.fresh.notify_all();
            }
            Err(e) => {
                failures += 1;
                log(&format!(
                    "sample failed ({failures}/{MAX_CONSECUTIVE_FAILURES}): {e}"
                ));
                if failures >= MAX_CONSECUTIVE_FAILURES {
                    bail!("capture keeps failing: {e}");
                }
            }
        }
        if last_flush.elapsed() >= config.flush_every {
            flush(shared);
            last_flush = Instant::now();
        }
        if last_prune.elapsed() >= PRUNE_EVERY {
            prune_history(shared);
            last_prune = Instant::now();
        }
        next += config.interval;
        let now = Instant::now();
        if next <= now {
            // Fell behind (machine slept, or overloaded): start a fresh full interval rather
            // than sampling again at once, which would compute rates over a sliver of time.
            next = now + config.interval;
        }
        sleep_until(next, stop);
    }
    Ok(())
}

/// Downloads the reputation lists whenever they are missing or older than 12 hours, then
/// reloads the rules. Runs for the life of the service.
fn keep_feeds_fresh(dir: &Path, categories: bool, shared: &Shared) {
    loop {
        if feeds::needs_update(dir) {
            for (feed, result) in feeds::update_all(dir) {
                match result {
                    feeds::UpdateResult::Updated { ranges } => {
                        log(&format!("updated {} ({ranges} ranges)", feed.name))
                    }
                    feeds::UpdateResult::Failed(e) => {
                        log(&format!("could not update {}: {e}", feed.name))
                    }
                }
            }
            if let Ok(mut intel) = shared.intel.write() {
                *intel = Intel::new(feeds::Feeds::load(dir).without(&shared.feeds_disabled));
            }
            if categories {
                use spectranet_intel::classify;
                match classify::update(dir) {
                    Ok(n) => log(&format!("updated the list of known services ({n} domains)")),
                    Err(e) => log(&format!("could not update the list of known services: {e}")),
                }
                if let Ok(mut c) = shared.classifier.lock() {
                    c.set_domains(classify::Domains::load(dir));
                }
            }
        }
        thread::sleep(FEED_CHECK_EVERY);
    }
}

fn unix_now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_secs())
}

fn sleep_until(deadline: Instant, stop: &AtomicBool) {
    while !stop.load(Ordering::Relaxed) {
        let Some(left) = deadline.checked_duration_since(Instant::now()) else {
            return;
        };
        thread::sleep(left.min(Duration::from_millis(100)));
    }
}

/// Writes pending usage to the database; on failure keeps it for the next attempt.
/// How often old usage history is removed (when `history_days` is set).
const PRUNE_EVERY: Duration = Duration::from_secs(6 * 3600);

/// Removes usage history older than `history_days` (0 keeps everything).
fn prune_history(shared: &Shared) {
    if shared.history_days == 0 {
        return;
    }
    let first = usage::first_day(shared.history_days);
    if let Ok(store) = shared.store.lock() {
        match store.prune_before(&first) {
            Ok(0) => {}
            Ok(n) => log(&format!("removed {n} usage rows from before {first}")),
            Err(e) => log(&format!("removing old usage failed: {e:#}")),
        }
    }
}

fn flush(shared: &Shared) {
    let (Ok(mut pending), Ok(mut store)) = (shared.pending.lock(), shared.store.lock()) else {
        return;
    };
    if pending.is_empty() {
        return;
    }
    match store.add(&pending.rows()) {
        Ok(()) => pending.clear(),
        Err(e) => log(&format!("saving usage failed (will retry): {e:#}")),
    }
}

fn serve(listener: &Listener, shared: &Arc<Shared>) {
    while !shared.stopping.load(Ordering::SeqCst) {
        let Ok(mut conn) = listener.accept() else {
            thread::sleep(Duration::from_millis(50));
            continue;
        };
        if shared.stopping.load(Ordering::SeqCst) {
            break;
        }
        if shared.clients.fetch_add(1, Ordering::SeqCst) >= MAX_CLIENTS {
            shared.clients.fetch_sub(1, Ordering::SeqCst);
            let _ = write_message(&mut conn.writer, &Response::error("too many clients"));
            continue;
        }
        let shared_for_client = shared.clone();
        let spawned = thread::Builder::new()
            .name("snetd-client".into())
            .spawn(move || {
                let _ = handle_client(conn, &shared_for_client);
                shared_for_client.clients.fetch_sub(1, Ordering::SeqCst);
            });
        if spawned.is_err() {
            shared.clients.fetch_sub(1, Ordering::SeqCst);
        }
    }
}

fn handle_client(conn: Conn, shared: &Shared) -> io::Result<()> {
    let mut peer = conn.peer;
    let mut writer = conn.writer;
    let mut reader = BufReader::new(conn.reader);
    loop {
        let request: Request = match read_message(&mut reader, MAX_REQUEST) {
            Ok(Some(request)) => request,
            Ok(None) => return Ok(()),
            Err(e) => {
                // Malformed or oversized: say why, then hang up.
                let _ = write_message(
                    &mut writer,
                    &Response::error(format!("invalid request: {e}")),
                );
                return Ok(());
            }
        };
        if request.v == PROTOCOL_VERSION && request.command == Command::Subscribe {
            return stream_snapshots(&mut writer, shared);
        }
        let response = if request.v == PROTOCOL_VERSION {
            {
                if matches!(request.command, Command::Act { .. }) {
                    peer.resolve();
                }
                Response::new(answer(request.command, shared, &peer))
            }
        } else {
            Response::error(format!(
                "protocol version {} not supported (snetd speaks {PROTOCOL_VERSION}); reinstall snet and snetd together",
                request.v
            ))
        };
        write_message(&mut writer, &response)?;
    }
}

/// Sends every new snapshot, exactly once each, until the client goes away.
fn stream_snapshots(writer: &mut dyn Write, shared: &Shared) -> io::Result<()> {
    let mut last_sent = shared.latest.lock().map(|l| l.0).unwrap_or(0);
    loop {
        let next = {
            let guard = shared
                .latest
                .lock()
                .map_err(|_| io::Error::other("lock poisoned"))?;
            let (guard, _) = shared
                .fresh
                .wait_timeout_while(guard, shared.interval * 2, |l| l.0 <= last_sent)
                .map_err(|_| io::Error::other("lock poisoned"))?;
            (guard.0 > last_sent).then(|| (guard.0, guard.1.clone()))
        };
        match next {
            Some((seq, Some(snapshot))) => {
                if seq > last_sent + 1 && last_sent > 0 {
                    // The client fell behind; say so rather than silently skipping data.
                    write_message(
                        writer,
                        &Response::error(format!(
                            "subscriber too slow: {} samples skipped",
                            seq - last_sent - 1
                        )),
                    )?;
                }
                last_sent = seq;
                write_message(writer, &Response::new(Reply::Snapshot(snapshot)))?;
            }
            Some((seq, None)) => last_sent = seq,
            // Nothing new within two intervals: keep waiting; a vanished client is noticed
            // on the next write.
            None => {}
        }
    }
}

/// Every minute, a few pings to the check targets; alerts when the internet latency has been
/// high for `minutes` in a row (the same rule as the check).
fn watch_latency(shared: &Shared, minutes: u32) {
    let thresholds = spectranet_probe::Thresholds::default();
    loop {
        thread::sleep(Duration::from_secs(60));
        if shared.stopping.load(Ordering::SeqCst) {
            return;
        }
        let measured = crate::netcheck::watch_once(&shared.check_targets);
        let Ok(mut network) = shared.network.lock() else {
            continue;
        };
        let usual = network.baseline();
        let high = match (measured, usual) {
            (None, _) => true,
            (Some(ms), Some(u)) => {
                ms > u * thresholds.internet_factor && ms > u + thresholds.internet_margin_ms
            }
            (Some(ms), None) => ms > thresholds.internet_latency_ms,
        };
        if let Some(ms) = measured {
            network.add_latency(ms);
        }
        if network.watch_minute(high, minutes) {
            let event = crate::netcheck::latency_alert(
                unix_now(),
                minutes,
                measured.unwrap_or(f64::NAN),
                usual,
            );
            log(&format!("warn: {}", event.message));
            if let Ok(store) = shared.store.lock()
                && let Err(e) = store.record_alert(&event)
            {
                log(&format!("recording the latency alert failed: {e:#}"));
            }
        }
    }
}

/// Runs a network check here, with the applications' traffic and the usual latency.
fn run_check(shared: &Shared, targets: Vec<String>, path: bool) -> spectranet_probe::Report {
    let targets = if targets.is_empty() {
        shared.check_targets.clone()
    } else {
        targets
    };
    let (usual, peak) = shared
        .network
        .lock()
        .map(|n| (n.baseline(), n.peak()))
        .unwrap_or((None, None));
    let config = spectranet_probe::check::Config {
        targets,
        path,
        ..Default::default()
    };
    let report = spectranet_probe::check::run(
        &config,
        |window| {
            let snapshots = crate::netcheck::collect(window, || {
                let guard = shared.latest.lock().ok()?;
                let (seq, snapshot) = &*guard;
                snapshot.clone().map(|s| (*seq, s))
            });
            spectranet_probe::apps::from_snapshots(&snapshots, peak)
        },
        usual,
        |_| {},
    );
    if let Some(ms) = crate::netcheck::internet_ms(&report)
        && let Ok(mut network) = shared.network.lock()
    {
        network.add_latency(ms);
    }
    if let Ok(store) = shared.store.lock()
        && let Err(e) = store.record_check(&report)
    {
        log(&format!("recording the network check failed: {e:#}"));
    }
    report
}

fn answer(command: Command, shared: &Shared, peer: &crate::transport::Peer) -> Reply {
    match command {
        Command::Check { targets, path } => {
            Reply::Check(Box::new(run_check(shared, targets, path)))
        }
        Command::Checks { limit } => {
            match shared.store.lock().map(|s| s.checks(limit.clamp(1, 100))) {
                Ok(Ok(reports)) => Reply::Checks { reports },
                Ok(Err(e)) => Reply::Error {
                    message: format!("reading the checks: {e:#}"),
                },
                Err(_) => Reply::Error {
                    message: "store unavailable".into(),
                },
            }
        }
        Command::Status => Reply::Status(Status {
            version: env!("CARGO_PKG_VERSION").to_string(),
            pid: std::process::id(),
            uptime_s: shared.started.elapsed().as_secs(),
            source: shared.source.clone(),
            interval_ms: u64::try_from(shared.interval.as_millis()).unwrap_or(u64::MAX),
            notices: shared.notices.clone(),
            feeds: shared
                .intel
                .read()
                .map(|i| {
                    i.feeds()
                        .status()
                        .into_iter()
                        .map(|f| FeedInfo {
                            id: f.id,
                            name: f.name,
                            ranges: f.ranges as u64,
                            updated: f.updated,
                        })
                        .collect()
                })
                .unwrap_or_default(),
            alerts_24h: shared
                .store
                .lock()
                .ok()
                .and_then(|s| s.count_alerts_since(unix_now().saturating_sub(86_400)).ok())
                .unwrap_or(0),
            capabilities: crate::actions::capabilities(),
            actions_elevated_only: shared.policy.elevated_only,
            blocks: shared.blocks.lock().map(|b| b.len() as u64).unwrap_or(0),
            settings: Some(shared.settings.clone()),
            coverage: shared.coverage.lock().ok().and_then(|c| {
                (!c.0.is_empty()).then(|| spectranet_proto::Coverage {
                    seconds: c.0.len() as u64,
                    interface_bytes: c.0.iter().map(|s| s.0).sum(),
                    attributed_bytes: c.0.iter().map(|s| s.1).sum(),
                    interfaces: c.1.clone(),
                })
            }),
        }),
        Command::Act { action } => {
            let snapshot = latest(shared);
            let store = shared.store.lock().ok();
            let mut paused = shared.paused.lock().unwrap_or_else(|e| e.into_inner());
            let mut blocks = shared.blocks.lock().unwrap_or_else(|e| e.into_inner());
            match crate::actions::act(
                &action,
                peer,
                shared.policy,
                snapshot.as_ref(),
                &mut paused,
                &mut blocks,
                store.as_deref(),
                unix_now(),
            ) {
                Ok(message) => Reply::Done { message },
                Err(message) => Reply::Error { message },
            }
        }
        Command::Blocks => Reply::Blocks {
            blocks: shared.blocks.lock().map(|b| b.list()).unwrap_or_default(),
        },
        Command::Audit { since_s, limit } => {
            let since = unix_now().saturating_sub(since_s);
            match shared
                .store
                .lock()
                .map(|s| s.audit_since(since, limit.clamp(1, MAX_ALERTS)))
            {
                Ok(Ok(events)) => Reply::Audit { events },
                Ok(Err(e)) => Reply::Error {
                    message: format!("reading the audit log: {e:#}"),
                },
                Err(_) => Reply::Error {
                    message: "audit store unavailable".into(),
                },
            }
        }
        Command::Alerts { since_s, limit } => {
            let since = unix_now().saturating_sub(since_s);
            match shared
                .store
                .lock()
                .map(|s| s.alerts_since(since, limit.clamp(1, MAX_ALERTS)))
            {
                Ok(Ok(events)) => Reply::Alerts { events },
                Ok(Err(e)) => Reply::Error {
                    message: format!("reading alerts: {e:#}"),
                },
                Err(_) => Reply::Error {
                    message: "alert store unavailable".into(),
                },
            }
        }
        Command::Subscribe => Reply::Error {
            message: "subscribe is handled separately".into(),
        },
        Command::Snapshot => match latest(shared) {
            Some(snapshot) => Reply::Snapshot(snapshot),
            None => Reply::Error {
                message: "snetd is still taking its first sample; retry shortly".into(),
            },
        },
        Command::History { days } => {
            let days = days.clamp(1, MAX_HISTORY_DAYS);
            let first = usage::first_day(days);
            let stored = match shared.store.lock().map(|s| s.since(&first)) {
                Ok(Ok(rows)) => rows,
                Ok(Err(e)) => {
                    return Reply::Error {
                        message: format!("reading history: {e:#}"),
                    };
                }
                Err(_) => {
                    return Reply::Error {
                        message: "history store unavailable".into(),
                    };
                }
            };
            let pending = shared.pending.lock().map(|p| p.rows()).unwrap_or_default();
            let rows = usage::merge(
                stored
                    .into_iter()
                    .chain(pending.into_iter().filter(|r| r.day >= first)),
            );
            Reply::History { rows }
        }
    }
}

/// The latest snapshot, waiting briefly right after startup.
fn latest(shared: &Shared) -> Option<Snapshot> {
    let guard = shared.latest.lock().ok()?;
    let wait = shared.interval * 3;
    let (guard, _) = shared
        .fresh
        .wait_timeout_while(guard, wait, |s| s.1.is_none())
        .ok()?;
    guard.1.clone()
}

static LOG_FILE: Mutex<Option<std::fs::File>> = Mutex::new(None);
/// A log file over this size is started afresh when the service starts.
const LOG_LIMIT: u64 = 10 * 1024 * 1024;

/// Sends log lines to a file as well (Windows services have no console).
pub fn set_log_file(path: &Path) {
    if std::fs::metadata(path).is_ok_and(|m| m.len() > LOG_LIMIT) {
        let _ = std::fs::remove_file(path);
    }
    if let Ok(file) = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)
        && let Ok(mut slot) = LOG_FILE.lock()
    {
        *slot = Some(file);
    }
}

pub fn log(message: &str) {
    let now = jiff::Zoned::now().strftime("%Y-%m-%d %H:%M:%S");
    let line = format!("{now} snetd[{}]: {message}", std::process::id());
    eprintln!("{line}");
    if let Ok(mut slot) = LOG_FILE.lock()
        && let Some(file) = slot.as_mut()
    {
        let _ = writeln!(file, "{line}");
    }
}

#[cfg(test)]
mod tests {
    use std::io::{BufRead, Write};

    use spectranet_capture::mock::MockSource;
    use spectranet_proto::{Client, ClientError};

    use super::*;

    /// A socket path (Unix) or pipe name (Windows) unique to this test.
    fn endpoint(dir: &Path) -> PathBuf {
        #[cfg(unix)]
        return dir.join("snetd.sock");
        #[cfg(windows)]
        {
            use std::sync::atomic::AtomicU64;
            static NEXT: AtomicU64 = AtomicU64::new(0);
            let _ = dir;
            PathBuf::from(format!(
                r"\\.\pipe\snetd-test-{}-{}",
                std::process::id(),
                NEXT.fetch_add(1, Ordering::Relaxed)
            ))
        }
    }

    fn wait_until_listening(path: &Path) {
        let deadline = Instant::now() + Duration::from_secs(5);
        while Client::connect(path, Duration::from_secs(1)).is_err() {
            assert!(Instant::now() < deadline, "service did not start");
            thread::sleep(Duration::from_millis(10));
        }
    }

    /// A raw connection, for sending malformed requests.
    fn raw(path: &Path) -> (BufReader<Box<dyn std::io::Read>>, Box<dyn Write>) {
        #[cfg(unix)]
        {
            let stream = std::os::unix::net::UnixStream::connect(path).unwrap();
            let writer = stream.try_clone().unwrap();
            (BufReader::new(Box::new(stream)), Box::new(writer))
        }
        #[cfg(windows)]
        {
            // Like a real client: ERROR_PIPE_BUSY (231) means retry shortly.
            let deadline = Instant::now() + Duration::from_secs(5);
            let file = loop {
                match std::fs::OpenOptions::new()
                    .read(true)
                    .write(true)
                    .open(path)
                {
                    Ok(f) => break f,
                    Err(e) if e.raw_os_error() == Some(231) && Instant::now() < deadline => {
                        thread::sleep(Duration::from_millis(5))
                    }
                    Err(e) => panic!("{e}"),
                }
            };
            let writer = file.try_clone().unwrap();
            (BufReader::new(Box::new(file)), Box::new(writer))
        }
    }

    struct Running {
        config: Config,
        stop: Arc<AtomicBool>,
        handle: Option<thread::JoinHandle<Result<()>>>,
        _dir: tempfile::TempDir,
    }

    impl Running {
        fn start(interval_ms: u64) -> Self {
            let dir = tempfile::tempdir().unwrap();
            let config = Config {
                socket: endpoint(dir.path()),
                database: dir.path().join("usage.sqlite"),
                interval: Duration::from_millis(interval_ms),
                flush_every: Duration::from_millis(interval_ms * 3),
                socket_group: None,
                feeds_dir: dir.path().join("feeds"),
                update_feeds: false,
                policy: crate::actions::Policy::default(),
                metrics: None,
                category_updates: false,
                feeds_disabled: Vec::new(),
                history_days: 0,
                settings: Default::default(),
                check_targets: Vec::new(),
                latency_watch_minutes: 0,
            };
            let stop = Arc::new(AtomicBool::new(false));
            let handle = {
                let (config, stop) = (config.clone(), stop.clone());
                thread::spawn(move || run(&config, Box::new(MockSource::new(9)), &stop))
            };
            wait_until_listening(&config.socket);
            Self {
                config,
                stop,
                handle: Some(handle),
                _dir: dir,
            }
        }

        fn client(&self) -> Client {
            Client::connect(&self.config.socket, Duration::from_secs(5)).unwrap()
        }

        fn stop(mut self) -> Result<()> {
            self.stop.store(true, Ordering::Relaxed);
            self.handle.take().unwrap().join().unwrap()
        }
    }

    #[test]
    fn answers_status_snapshot_and_history() {
        let service = Running::start(50);
        let mut client = service.client();

        let Reply::Status(status) = client.call(Command::Status).unwrap() else {
            panic!()
        };
        assert_eq!(status.source, "mock");
        assert_eq!(status.pid, std::process::id());

        let Reply::Snapshot(snapshot) = client.call(Command::Snapshot).unwrap() else {
            panic!()
        };
        assert_eq!(snapshot.processes.len(), 7);

        thread::sleep(Duration::from_millis(400));
        let Reply::History { rows } = client.call(Command::History { days: 1 }).unwrap() else {
            panic!()
        };
        assert_eq!(rows.len(), 6, "one row per application today");
        assert!(rows.iter().all(|r| r.day == usage::today() && r.rx > 0));
        service.stop().unwrap();
    }

    /// The whole path of an action: request, policy and protected-list checks, reply, audit.
    /// Only refusals are exercised: the simulated PIDs may belong to real processes here.
    #[test]
    fn actions_are_checked_answered_and_audited() {
        use spectranet_proto::Action;
        let service = Running::start(50);
        let mut client = service.client();
        let Reply::Status(status) = client.call(Command::Status).unwrap() else {
            panic!()
        };
        assert!(
            status.capabilities.iter().any(|c| c == "kill"),
            "{:?}",
            status.capabilities
        );
        assert!(!status.actions_elevated_only);
        thread::sleep(Duration::from_millis(150));
        let Reply::Snapshot(snapshot) = client.call(Command::Snapshot).unwrap() else {
            panic!()
        };
        // mDNSResponder is in the simulated workload and on the protected list.
        let dns = snapshot
            .processes
            .iter()
            .find(|p| p.process.name == "mDNSResponder")
            .unwrap();
        let refused = client.call(Command::Act {
            action: Action::Kill {
                pid: dns.process.pid,
                force: true,
            },
        });
        let Err(spectranet_proto::ClientError::Protocol(message)) = refused else {
            panic!("{refused:?}")
        };
        assert!(message.contains("protected"), "{message}");
        // A connection that does not exist.
        let refused = client.call(Command::Act {
            action: Action::DropFlow {
                pid: dns.process.pid,
                transport: spectranet_model::Transport::Tcp,
                local: "10.9.9.9:1".parse().unwrap(),
                remote: "10.9.9.9:2".parse().unwrap(),
            },
        });
        assert!(refused.is_err(), "{refused:?}");
        let Reply::Audit { events } = client
            .call(Command::Audit {
                since_s: 3600,
                limit: 10,
            })
            .unwrap()
        else {
            panic!()
        };
        assert_eq!(events.len(), 2, "refusals are logged too");
        assert!(events.iter().all(|e| !e.ok && !e.by.is_empty()));
        let Reply::Blocks { blocks } = client.call(Command::Blocks).unwrap() else {
            panic!()
        };
        assert!(blocks.is_empty());
        service.stop().unwrap();
    }

    #[test]
    fn history_survives_restart() {
        let mut service = Running::start(20);
        thread::sleep(Duration::from_millis(300));
        let Reply::History { rows: before } =
            service.client().call(Command::History { days: 1 }).unwrap()
        else {
            panic!()
        };
        let database = service.config.database.clone();
        let keep_dir = std::mem::replace(&mut service._dir, tempfile::tempdir().unwrap());
        service.stop().unwrap();

        // After a clean stop everything pending is in the database.
        let store = Store::open(&database).unwrap();
        let stored = store.since(&usage::today()).unwrap();
        let total = |rows: &[spectranet_proto::UsageRow]| rows.iter().map(|r| r.rx).sum::<u64>();
        assert!(total(&stored) >= total(&before), "nothing lost at shutdown");
        drop(keep_dir);
    }

    #[cfg(unix)]
    #[test]
    fn socket_is_private_and_removed_on_stop() {
        use std::os::unix::fs::PermissionsExt;
        let service = Running::start(50);
        let mode = std::fs::metadata(&service.config.socket)
            .unwrap()
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(mode, 0o600);
        let socket = service.config.socket.clone();
        service.stop().unwrap();
        assert!(!socket.exists());
    }

    #[test]
    fn refuses_to_run_twice() {
        let service = Running::start(50);
        let err = Listener::bind(&service.config.socket, None)
            .err()
            .expect("second bind refused");
        assert!(err.to_string().contains("already running"));
        service.stop().unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn replaces_a_stale_socket() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("stale.sock");
        drop(std::os::unix::net::UnixListener::bind(&path).unwrap()); // file left, nobody listening
        assert!(path.exists());
        assert!(Listener::bind(&path, None).is_ok());
    }

    #[test]
    fn bad_clients_get_an_error_and_others_are_unaffected() {
        let service = Running::start(50);
        for garbage in [
            &b"hello\n"[..],
            b"{\"v\":1,\"cmd\":\"reboot\"}\n",
            b"{\"v\":99,\"cmd\":\"status\"}\n",
        ] {
            let (mut reader, mut writer) = raw(&service.config.socket);
            writer.write_all(garbage).unwrap();
            let mut line = String::new();
            reader.read_line(&mut line).unwrap();
            assert!(line.contains("\"type\":\"error\""), "{line}");
        }
        // An oversized request.
        let (mut reader, mut writer) = raw(&service.config.socket);
        let _ = writer.write_all(&vec![b'x'; MAX_REQUEST + 10]);
        let mut line = String::new();
        let _ = reader.read_line(&mut line);
        assert!(line.contains("size limit"), "{line}");

        let Reply::Status(_) = service.client().call(Command::Status).unwrap() else {
            panic!()
        };
        service.stop().unwrap();
    }

    /// Rapid connect/disconnect cycles must never find every pipe instance busy (Windows)
    /// or the socket unavailable.
    #[test]
    fn back_to_back_raw_connections_never_find_the_endpoint_busy() {
        let service = Running::start(50);
        for _ in 0..200 {
            let (mut reader, mut writer) = raw(&service.config.socket);
            writer.write_all(b"{\"v\":1,\"cmd\":\"status\"}\n").unwrap();
            let mut line = String::new();
            reader.read_line(&mut line).unwrap();
            assert!(line.contains("\"type\":\"status\""), "{line}");
        }
        service.stop().unwrap();
    }

    #[test]
    fn many_concurrent_clients() {
        let service = Running::start(30);
        let socket = service.config.socket.clone();
        let workers: Vec<_> = (0..20)
            .map(|_| {
                let socket = socket.clone();
                thread::spawn(move || {
                    let mut client = Client::connect(&socket, Duration::from_secs(5)).unwrap();
                    for _ in 0..20 {
                        assert!(matches!(
                            client.call(Command::Snapshot),
                            Ok(Reply::Snapshot(_))
                        ));
                    }
                })
            })
            .collect();
        for w in workers {
            w.join().unwrap();
        }
        service.stop().unwrap();
    }

    /// A source that is sometimes slower than the interval, as on a loaded machine.
    struct Sluggish(MockSource, u32);

    impl TrafficSource for Sluggish {
        fn name(&self) -> &'static str {
            "sluggish"
        }
        fn sample(&mut self) -> Result<Snapshot, spectranet_capture::CaptureError> {
            self.1 += 1;
            if self.1.is_multiple_of(3) {
                thread::sleep(Duration::from_millis(80));
            }
            self.0.sample()
        }
    }

    #[test]
    fn falling_behind_never_samples_back_to_back() {
        let dir = tempfile::tempdir().unwrap();
        let config = Config {
            socket: endpoint(dir.path()),
            database: dir.path().join("u.sqlite"),
            interval: Duration::from_millis(30),
            flush_every: Duration::from_secs(10),
            socket_group: None,
            feeds_dir: dir.path().join("feeds"),
            update_feeds: false,
            policy: crate::actions::Policy::default(),
            metrics: None,
            category_updates: false,
            feeds_disabled: Vec::new(),
            history_days: 0,
            settings: Default::default(),
            check_targets: Vec::new(),
            latency_watch_minutes: 0,
        };
        let stop = Arc::new(AtomicBool::new(false));
        let handle = {
            let (config, stop) = (config.clone(), stop.clone());
            thread::spawn(move || run(&config, Box::new(Sluggish(MockSource::new(1), 0)), &stop))
        };
        wait_until_listening(&config.socket);
        let stream = Client::connect(&config.socket, Duration::from_secs(5))
            .unwrap()
            .subscribe()
            .unwrap();
        let snapshots: Vec<Snapshot> = stream.take(10).map(Result::unwrap).collect();
        let gaps: Vec<u64> = snapshots
            .windows(2)
            .map(|pair| pair[1].timestamp_ms - pair[0].timestamp_ms)
            .collect();
        // The bug sampled back to back after every slow sample (3 times in 10). A busy test
        // machine may also stall the loop once mid-interval, which legitimately shortens one
        // gap: allow that, not more.
        let short = gaps.iter().filter(|g| **g < 10).count();
        assert!(short <= 1, "samples too close: {gaps:?} ms apart");
        stop.store(true, Ordering::Relaxed);
        handle.join().unwrap().unwrap();
    }

    #[test]
    fn subscription_delivers_every_sample_once() {
        let service = Running::start(30);
        let stream = service.client().subscribe().unwrap();
        let stamps: Vec<u64> = stream.take(8).map(|s| s.unwrap().timestamp_ms).collect();
        assert!(
            stamps.windows(2).all(|w| w[1] > w[0]),
            "strictly increasing, no repeats: {stamps:?}"
        );
        // Other clients keep working alongside a subscriber.
        assert!(matches!(
            service.client().call(Command::Status),
            Ok(Reply::Status(_))
        ));
        service.stop().unwrap();
    }

    #[test]
    fn subscriber_disconnect_frees_the_slot() {
        let service = Running::start(20);
        for _ in 0..(MAX_CLIENTS + 5) {
            let mut stream = service.client().subscribe().unwrap();
            assert!(stream.next().unwrap().is_ok());
        }
        thread::sleep(Duration::from_millis(200));
        assert!(
            matches!(service.client().call(Command::Status), Ok(Reply::Status(_))),
            "slots were released"
        );
        service.stop().unwrap();
    }

    #[test]
    fn client_sees_service_gone_after_stop() {
        let service = Running::start(50);
        let socket = service.config.socket.clone();
        service.stop().unwrap();
        assert!(matches!(
            Client::connect(&socket, Duration::from_secs(1)),
            Err(ClientError::NotRunning)
        ));
    }
}
