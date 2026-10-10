//! Everything `snet top` knows and how keys change it. No terminal I/O here.

use std::collections::{HashMap, HashSet, VecDeque};
use std::time::Duration;

use ratatui::crossterm::event::{KeyCode, KeyEvent, KeyEventKind, KeyModifiers};
use spectranet_model::{AppTraffic, Snapshot, Transport};
use spectranet_proto::{Action as Request, capability};

use super::act::{self, ActionSink};
use super::keys::{Cmd, Column, Settings, key_name};
use super::tree::{self, TreeRow};
use crate::cli::{SortKey, ViewArgs};
use crate::view::{self, View, connection_rows, endpoint};

/// Samples of total throughput kept for the graphs (two minutes at 1 s).
pub const HISTORY: usize = 120;
const PAGE: usize = 10;
pub const SORT_ORDER: [SortKey; 9] = [
    SortKey::Rate,
    SortKey::Down,
    SortKey::Up,
    SortKey::Total,
    SortKey::Cpu,
    SortKey::Mem,
    SortKey::Alerts,
    SortKey::Name,
    SortKey::Pid,
];

pub fn sort_label(key: SortKey) -> &'static str {
    match key {
        SortKey::Rate => "bandwidth (download + upload)",
        SortKey::Down => "download",
        SortKey::Up => "upload",
        SortKey::Total => "total bytes",
        SortKey::Cpu => "CPU",
        SortKey::Mem => "memory",
        SortKey::Alerts => "alerts first",
        SortKey::Name => "name",
        SortKey::Pid => "process ID",
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Action {
    Continue,
    Quit,
}

/// Which part of the screen the arrow keys move.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Focus {
    Table,
    Connections,
}

/// What is being confirmed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Confirm {
    Kill {
        pid: u32,
        name: String,
    },
    Pause {
        pid: u32,
        name: String,
        resume: bool,
    },
    Drop {
        pid: u32,
        transport: Transport,
        local: std::net::SocketAddr,
        remote: std::net::SocketAddr,
        label: String,
    },
    Block {
        target: spectranet_proto::BlockTarget,
        label: String,
    },
}

/// The lengths offered when blocking, by key 1..5: (seconds, label); 0 = until lifted.
pub const BLOCK_LENGTHS: [(u64, &str); 5] = [
    (900, "15 min"),
    (3600, "1 hour"),
    (8 * 3600, "8 hours"),
    (86_400, "1 day"),
    (0, "until lifted"),
];

/// The setup screen (F2).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Setup {
    /// 0: columns, 1: keys.
    pub tab: usize,
    pub selected: usize,
    /// Waiting for the key to bind to this command.
    pub capturing: Option<Cmd>,
}

/// A window over the main screen; only one at a time.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Modal {
    Help,
    SortMenu { selected: usize },
    Setup(Setup),
    Confirm(Confirm),
}

pub struct TopState {
    pub sort: SortKey,
    pub by_process: bool,
    pub flagged: bool,
    /// `--domain`: only one group of applications (e.g. radio).
    pub domain: Option<crate::cli::Domain>,
    pub pids: Vec<u32>,
    /// Applied search.
    pub filter: String,
    /// Search being typed, when the prompt is open.
    pub editing: Option<String>,
    /// The screen stops updating (data keeps arriving and is shown again when unfrozen).
    pub frozen: bool,
    pub details: bool,
    pub focus: Focus,
    pub connection: usize,
    pub tree: bool,
    pub collapsed: HashSet<u32>,
    pub modal: Option<Modal>,
    pub settings: Settings,
    pub interval: Duration,
    /// Last snapshot received, kept to re-sort/re-filter without waiting for new data.
    raw: Option<Snapshot>,
    pub view: Option<View>,
    /// The rows shown, in order (a tree when `tree` is on).
    pub rows: Vec<TreeRow>,
    pub selected: usize,
    /// Identity of the selected row, so selection follows it when ranks change.
    selected_key: Option<String>,
    pub rx_history: VecDeque<u64>,
    pub tx_history: VecDeque<u64>,
    pub error: Option<String>,
    pub source: String,
    /// Degraded-operation remarks from the source, shown under the header.
    pub notices: Vec<String>,
    /// Outcome of the last action or setting change: (success, text).
    pub message: Option<(bool, String)>,
    /// Processes this session paused (so `p` offers to resume them).
    pub paused: HashSet<u32>,
    pub actions: Box<dyn ActionSink>,
    /// The Flow Inspector is open on the selected application.
    pub flows: bool,
    /// The last minute of every connection: rates and packet rates per sample.
    pub flow_history: HashMap<FlowId, VecDeque<FlowSample>>,
}

/// A connection, across samples.
pub type FlowId = (u32, Transport, std::net::SocketAddr, std::net::SocketAddr);

/// One sample of a connection.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct FlowSample {
    pub rx: u64,
    pub tx: u64,
    pub rx_pps: Option<u32>,
    pub tx_pps: Option<u32>,
}

/// Samples kept per connection for the Flow Inspector's waves.
pub const FLOW_HISTORY: usize = 60;

impl TopState {
    pub fn new(args: &ViewArgs, source: &str) -> Self {
        Self {
            sort: args.sort,
            by_process: args.by_process,
            flagged: args.flagged,
            domain: args.domain,
            pids: args.pids.clone(),
            filter: args.name.clone().unwrap_or_default(),
            editing: None,
            frozen: false,
            details: false,
            focus: Focus::Table,
            connection: 0,
            tree: false,
            collapsed: HashSet::new(),
            modal: None,
            settings: Settings::default(),
            interval: args.interval,
            raw: None,
            view: None,
            rows: Vec::new(),
            selected: 0,
            selected_key: None,
            rx_history: VecDeque::with_capacity(HISTORY),
            tx_history: VecDeque::with_capacity(HISTORY),
            error: None,
            source: source.to_string(),
            notices: Vec::new(),
            message: None,
            paused: HashSet::new(),
            actions: Box::new(act::Unavailable(
                "actions need the snetd service: install it with 'sudo snetd install'".into(),
            )),
            flows: false,
            flow_history: HashMap::new(),
        }
    }

    /// Takes a new snapshot (ignored while frozen, except the very first).
    pub fn on_snapshot(&mut self, snapshot: Snapshot) {
        if self.frozen && self.raw.is_some() {
            return;
        }
        self.error = None;
        push_bounded(&mut self.rx_history, snapshot.rx_rate());
        push_bounded(&mut self.tx_history, snapshot.tx_rate());
        let mut live = HashSet::new();
        for p in &snapshot.processes {
            for f in &p.flows {
                let id = (p.process.pid, f.transport, f.local, f.remote);
                let h = self.flow_history.entry(id).or_default();
                h.push_back(FlowSample {
                    rx: f.rx_rate,
                    tx: f.tx_rate,
                    rx_pps: f.meta.rx_pps,
                    tx_pps: f.meta.tx_pps,
                });
                while h.len() > FLOW_HISTORY {
                    h.pop_front();
                }
                live.insert(id);
            }
        }
        self.flow_history.retain(|id, _| live.contains(id));
        self.raw = Some(snapshot);
        self.rebuild();
    }

    pub fn on_error(&mut self, message: String) {
        self.error = Some(message);
    }

    /// Collects the outcome of actions sent to snetd.
    pub fn poll_actions(&mut self) {
        for outcome in self.actions.results() {
            self.message = Some(match outcome {
                Ok(m) => (true, m),
                Err(m) => (false, m),
            });
        }
    }

    pub fn handle_key(&mut self, key: KeyEvent) -> Action {
        if key.kind != KeyEventKind::Press {
            return Action::Continue;
        }
        if key.modifiers.contains(KeyModifiers::CONTROL) && key.code == KeyCode::Char('c') {
            return Action::Quit;
        }
        if let Some(buffer) = &mut self.editing {
            match key.code {
                KeyCode::Enter => {
                    self.filter = buffer.trim().to_string();
                    self.editing = None;
                    self.rebuild();
                }
                KeyCode::Esc => self.editing = None,
                KeyCode::Backspace => {
                    buffer.pop();
                }
                KeyCode::Char(c) if !c.is_control() && buffer.chars().count() < 64 => {
                    buffer.push(c)
                }
                _ => {}
            }
            return Action::Continue;
        }
        if let Some(modal) = self.modal.take() {
            return self.modal_key(modal, key);
        }
        if key.code == KeyCode::Esc {
            if self.flows {
                self.flows = false;
                self.details = false;
                self.focus = Focus::Table;
            } else if self.focus == Focus::Connections {
                self.focus = Focus::Table;
            } else if self.details {
                self.details = false;
            } else if self.message.is_some() {
                self.message = None;
            } else if !self.filter.is_empty() {
                self.filter.clear();
                self.rebuild();
            } else {
                return Action::Quit;
            }
            return Action::Continue;
        }
        if key.code == KeyCode::Tab && self.details {
            self.focus = match self.focus {
                Focus::Table => Focus::Connections,
                Focus::Connections => Focus::Table,
            };
            return Action::Continue;
        }
        let Some(cmd) = self.settings.keys.command(&key) else {
            return Action::Continue;
        };
        self.command(cmd)
    }

    fn command(&mut self, cmd: Cmd) -> Action {
        let in_connections = self.details && self.focus == Focus::Connections;
        match cmd {
            Cmd::Quit => return Action::Quit,
            Cmd::Up if in_connections => self.move_connection(-1),
            Cmd::Down if in_connections => self.move_connection(1),
            Cmd::Up => self.move_by(-1),
            Cmd::Down => self.move_by(1),
            Cmd::PageUp => self.move_by(-(PAGE as isize)),
            Cmd::PageDown => self.move_by(PAGE as isize),
            Cmd::Home => self.move_to(0),
            Cmd::End => self.move_to(usize::MAX),
            Cmd::Inspect => {
                if self.details && self.focus == Focus::Table {
                    self.focus = Focus::Connections;
                } else if self.details {
                    self.details = false;
                    self.focus = Focus::Table;
                } else if self.selected_app().is_some() {
                    self.details = true;
                    self.focus = Focus::Table;
                    self.connection = 0;
                }
            }
            Cmd::Search => self.editing = Some(self.filter.clone()),
            Cmd::SortMenu => {
                let selected = SORT_ORDER.iter().position(|k| *k == self.sort).unwrap_or(0);
                self.modal = Some(Modal::SortMenu { selected });
            }
            Cmd::SortNext => self.cycle_sort(1),
            Cmd::SortPrev => self.cycle_sort(-1),
            Cmd::Tree => {
                self.tree = !self.tree;
                self.rebuild();
            }
            Cmd::Expand | Cmd::Collapse if self.tree => {
                if let Some(row) = self.rows.get(self.selected)
                    && (row.descendants > 0 || row.collapsed)
                {
                    let pid = row.app.pid;
                    if cmd == Cmd::Collapse {
                        self.collapsed.insert(pid);
                    } else {
                        self.collapsed.remove(&pid);
                    }
                    self.rebuild();
                }
            }
            Cmd::Expand | Cmd::Collapse => {}
            Cmd::Setup => {
                self.modal = Some(Modal::Setup(Setup {
                    tab: 0,
                    selected: 0,
                    capturing: None,
                }))
            }
            Cmd::Help => self.modal = Some(Modal::Help),
            Cmd::Freeze => self.frozen = !self.frozen,
            Cmd::Kill => self.ask_kill(),
            Cmd::Pause => self.ask_pause(),
            Cmd::Drop => self.ask_drop(),
            Cmd::Block => self.ask_block(),
            Cmd::Flows => {
                if self.flows {
                    self.flows = false;
                    self.details = false;
                    self.focus = Focus::Table;
                } else if self.selected_app().is_some() {
                    self.flows = true;
                    self.details = true;
                    self.focus = Focus::Connections;
                    self.connection = 0;
                } else {
                    self.refuse("select an application first".into());
                }
            }
            Cmd::Group => {
                self.by_process = !self.by_process;
                self.rebuild();
            }
            Cmd::Flagged => {
                self.flagged = !self.flagged;
                self.rebuild();
            }
        }
        Action::Continue
    }

    fn refuse(&mut self, why: String) {
        self.message = Some((false, why));
    }

    /// The process an action applies to: the selected row's representative process.
    fn target(&self) -> Option<(u32, String)> {
        let app = self.selected_app()?;
        Some((app.pid, format!("{} (pid {})", app.name, app.pid)))
    }

    fn ask_kill(&mut self) {
        if let Err(why) = act::check(self.actions.as_ref(), capability::KILL) {
            return self.refuse(why);
        }
        if let Some((pid, name)) = self.target() {
            self.modal = Some(Modal::Confirm(Confirm::Kill { pid, name }));
        }
    }

    fn ask_pause(&mut self) {
        if let Err(why) = act::check(self.actions.as_ref(), capability::PAUSE) {
            return self.refuse(why);
        }
        if let Some((pid, name)) = self.target() {
            let resume = self.paused.contains(&pid);
            self.modal = Some(Modal::Confirm(Confirm::Pause { pid, name, resume }));
        }
    }

    fn ask_drop(&mut self) {
        if !(self.details && self.focus == Focus::Connections) {
            return self.refuse(
                "open the inspector (Enter), move to a connection (Tab) and press the key again"
                    .into(),
            );
        }
        if let Err(why) = act::check(self.actions.as_ref(), capability::DROP) {
            return self.refuse(why);
        }
        let Some(app) = self.selected_app() else {
            return;
        };
        let rows = connection_rows(app);
        let Some(row) = rows.get(self.connection) else {
            return;
        };
        if row.count > 1 || row.flow.remote.ip().is_unspecified() {
            return self.refuse(
                "this row is several sockets without a remote end: choose a single connection"
                    .into(),
            );
        }
        if cfg!(windows) && row.flow.transport != Transport::Tcp {
            return self.refuse("Windows can only close TCP connections".into());
        }
        let confirm = Confirm::Drop {
            pid: row.owner.pid,
            transport: row.flow.transport,
            local: row.flow.local,
            remote: row.flow.remote,
            label: endpoint(&row.flow),
        };
        self.modal = Some(Modal::Confirm(confirm));
    }

    fn ask_block(&mut self) {
        let Some(app) = self.selected_app() else {
            return;
        };
        let confirm = if self.details && self.focus == Focus::Connections {
            let rows = connection_rows(app);
            let Some(row) = rows.get(self.connection) else {
                return;
            };
            let ip = row.flow.remote.ip();
            if ip.is_unspecified() {
                return self.refuse("this row has no remote address to block".into());
            }
            if let Err(why) = act::check(self.actions.as_ref(), capability::BLOCK_IP) {
                return self.refuse(why);
            }
            Confirm::Block {
                target: spectranet_proto::BlockTarget::Remote { ip },
                label: endpoint(&row.flow),
            }
        } else {
            let Some(path) = app.path.clone() else {
                return self.refuse(format!(
                    "the program file of {} is unknown, so it can't be blocked",
                    app.name
                ));
            };
            let partial = act::check(self.actions.as_ref(), capability::BLOCK_APP).is_err();
            if partial
                && let Err(why) = act::check(self.actions.as_ref(), capability::BLOCK_APP_PARTIAL)
            {
                return self.refuse(why);
            }
            let name = app.name.clone();
            let label = if partial {
                format!(
                    "{name} (by following its addresses: new ones may get through for a moment)"
                )
            } else {
                name.clone()
            };
            Confirm::Block {
                target: spectranet_proto::BlockTarget::App { path, name },
                label,
            }
        };
        self.modal = Some(Modal::Confirm(confirm));
    }

    fn modal_key(&mut self, modal: Modal, key: KeyEvent) -> Action {
        match modal {
            Modal::Help => {
                // Any key closes help; q still quits.
                if self.settings.keys.command(&key) == Some(Cmd::Quit) {
                    return Action::Quit;
                }
            }
            Modal::SortMenu { mut selected } => match key.code {
                KeyCode::Esc => {}
                KeyCode::Enter => {
                    self.sort = SORT_ORDER[selected];
                    self.rebuild();
                }
                _ => {
                    match self.settings.keys.command(&key) {
                        Some(Cmd::Up) => selected = selected.saturating_sub(1),
                        Some(Cmd::Down) => selected = (selected + 1).min(SORT_ORDER.len() - 1),
                        Some(Cmd::SortMenu) => return Action::Continue,
                        _ => {}
                    }
                    self.modal = Some(Modal::SortMenu { selected });
                }
            },
            Modal::Setup(setup) => self.setup_key(setup, key),
            Modal::Confirm(confirm) => self.confirm_key(confirm, key),
        }
        Action::Continue
    }

    fn confirm_key(&mut self, confirm: Confirm, key: KeyEvent) {
        if let Confirm::Block { target, .. } = &confirm {
            let choice = match key.code {
                KeyCode::Esc | KeyCode::Char('n') | KeyCode::Char('N') => {
                    self.message = Some((true, "cancelled".into()));
                    return;
                }
                KeyCode::Enter => Some(1),
                KeyCode::Char(c @ '1'..='5') => Some(c as usize - '1' as usize),
                _ => None,
            };
            let Some(choice) = choice else {
                self.modal = Some(Modal::Confirm(confirm));
                return;
            };
            self.message = Some((true, "sent to snetd…".into()));
            self.actions.send(Request::Block {
                target: target.clone(),
                ttl_s: BLOCK_LENGTHS[choice].0,
            });
            return;
        }
        let answer = match key.code {
            KeyCode::Esc | KeyCode::Char('n') | KeyCode::Char('N') => None,
            KeyCode::Enter | KeyCode::Char('y') | KeyCode::Char('Y') | KeyCode::Char('t') => {
                Some(false)
            }
            KeyCode::Char('k') | KeyCode::Char('K') => Some(true),
            _ => {
                self.modal = Some(Modal::Confirm(confirm));
                return;
            }
        };
        let Some(force) = answer else {
            self.message = Some((true, "cancelled".into()));
            return;
        };
        let request = match confirm {
            Confirm::Kill { pid, .. } => Request::Kill {
                pid,
                force: force || cfg!(windows),
            },
            Confirm::Pause {
                pid, resume: false, ..
            } => {
                self.paused.insert(pid);
                Request::Pause { pid }
            }
            Confirm::Pause {
                pid, resume: true, ..
            } => {
                self.paused.remove(&pid);
                Request::Resume { pid }
            }
            Confirm::Drop {
                pid,
                transport,
                local,
                remote,
                ..
            } => Request::DropFlow {
                pid,
                transport,
                local,
                remote,
            },
            Confirm::Block { .. } => unreachable!("handled above"),
        };
        self.message = Some((true, "sent to snetd…".into()));
        self.actions.send(request);
    }

    fn setup_key(&mut self, mut setup: Setup, key: KeyEvent) {
        if let Some(cmd) = setup.capturing.take() {
            if key.code == KeyCode::Esc {
                self.modal = Some(Modal::Setup(setup));
                return;
            }
            match key_name(&key) {
                Some(name) if self.settings.keys.bind(cmd, &name) => {
                    self.message = Some((true, format!("{name}: {}", cmd.describe())));
                }
                Some(name) => self.message = Some((false, format!("{name} can't be reassigned"))),
                None => self.message = Some((false, "that key can't be used".into())),
            }
            self.modal = Some(Modal::Setup(setup));
            return;
        }
        let items = if setup.tab == 0 {
            Column::ALL.len()
        } else {
            Cmd::ALL.len()
        };
        match key.code {
            KeyCode::Esc | KeyCode::F(2) => {
                self.message = Some(match self.settings.save() {
                    Ok(path) => (true, format!("settings saved in {}", path.display())),
                    Err(e) => (false, format!("settings not saved: {e}")),
                });
                return;
            }
            KeyCode::Tab | KeyCode::Left | KeyCode::Right => {
                setup.tab = 1 - setup.tab;
                setup.selected = 0;
            }
            KeyCode::Up | KeyCode::Char('k') => setup.selected = setup.selected.saturating_sub(1),
            KeyCode::Down | KeyCode::Char('j') => {
                setup.selected = (setup.selected + 1).min(items - 1)
            }
            KeyCode::Char(' ') | KeyCode::Enter if setup.tab == 0 => {
                let column = Column::ALL[setup.selected];
                if let Some(i) = self.settings.columns.iter().position(|c| *c == column) {
                    if self.settings.columns.len() > 1 {
                        self.settings.columns.remove(i);
                    }
                } else {
                    // Keep the canonical order.
                    self.settings.columns.push(column);
                    self.settings
                        .columns
                        .sort_by_key(|c| Column::ALL.iter().position(|x| x == c));
                }
            }
            KeyCode::Enter => setup.capturing = Some(Cmd::ALL[setup.selected]),
            KeyCode::Backspace | KeyCode::Delete if setup.tab == 1 => {
                self.settings.keys.reset(Cmd::ALL[setup.selected])
            }
            _ => {}
        }
        self.modal = Some(Modal::Setup(setup));
    }

    pub fn selected_app(&self) -> Option<&AppTraffic> {
        self.rows.get(self.selected).map(|r| &r.app)
    }

    pub fn has_data(&self) -> bool {
        self.raw.is_some()
    }

    fn cycle_sort(&mut self, step: isize) {
        let at = SORT_ORDER.iter().position(|k| *k == self.sort).unwrap_or(0) as isize;
        let next = (at + step).rem_euclid(SORT_ORDER.len() as isize) as usize;
        self.sort = SORT_ORDER[next];
        self.rebuild();
    }

    fn move_by(&mut self, delta: isize) {
        let target = (self.selected as isize).saturating_add(delta).max(0) as usize;
        self.move_to(target);
    }

    fn move_to(&mut self, index: usize) {
        self.selected = index.min(self.rows.len().saturating_sub(1));
        self.selected_key = self
            .selected_app()
            .map(|a| key_of(a, self.by_process || self.tree));
        self.connection = 0;
    }

    fn move_connection(&mut self, delta: isize) {
        let len = self.selected_app().map_or(0, |a| connection_rows(a).len());
        self.connection =
            ((self.connection as isize + delta).max(0) as usize).min(len.saturating_sub(1));
    }

    /// Recomputes the rows from the last snapshot and the current settings, keeping the
    /// selection on the same application when it is still listed.
    fn rebuild(&mut self) {
        let Some(raw) = &self.raw else { return };
        let args = ViewArgs {
            sort: self.sort,
            limit: None,
            pids: self.pids.clone(),
            name: (!self.filter.is_empty()).then(|| self.filter.clone()),
            flagged: self.flagged,
            domain: self.domain,
            // The tree is made of processes.
            by_process: self.by_process || self.tree,
            connections: 0,
            json: false,
            interval: self.interval,
        };
        let view = view::select(raw.clone(), &args);
        self.rows = if self.tree {
            tree::build(&view.apps, &self.collapsed)
        } else {
            view.apps
                .iter()
                .map(|a| TreeRow {
                    app: a.clone(),
                    depth: 0,
                    descendants: 0,
                    collapsed: false,
                    last: false,
                })
                .collect()
        };
        let per_process = self.by_process || self.tree;
        let position = self.selected_key.as_ref().and_then(|key| {
            self.rows
                .iter()
                .position(|r| &key_of(&r.app, per_process) == key)
        });
        self.view = Some(view);
        match position {
            Some(i) => self.selected = i,
            None => self.move_to(self.selected),
        }
        if self.selected_app().is_none() {
            self.details = false;
            self.focus = Focus::Table;
        }
        let len = self.selected_app().map_or(0, |a| connection_rows(a).len());
        self.connection = self.connection.min(len.saturating_sub(1));
    }
}

/// Identity of a row across refreshes. An application group is identified by its path (its
/// representative PID may change as helpers come and go); a standalone process, or any row in
/// per-process mode, also by its PID, since two `curl` processes share a path.
fn key_of(app: &AppTraffic, by_process: bool) -> String {
    let standalone = app
        .processes
        .first()
        .is_none_or(|p| p.process.app.is_none());
    let pid = if by_process || standalone { app.pid } else { 0 };
    format!("{}|{}|{pid}", app.path.as_deref().unwrap_or(""), app.name)
}

fn push_bounded(history: &mut VecDeque<u64>, value: u64) {
    if history.len() == HISTORY {
        history.pop_front();
    }
    history.push_back(value);
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cli::{Cli, Command};
    use crate::top::act::fake::Recorder;
    use clap::Parser;
    use spectranet_capture::mock::MockSource;

    fn state() -> TopState {
        let Command::List(list) = Cli::parse_from(["snet", "list"]).command else {
            unreachable!()
        };
        let mut state = TopState::new(&list.view, "mock");
        state.on_snapshot(snapshot(1));
        state
    }

    fn with_actions(caps: &[&str]) -> TopState {
        let mut s = state();
        s.actions = Box::new(Recorder::new(caps));
        s
    }

    fn snapshot(seed: u64) -> Snapshot {
        MockSource::new(seed).advance(Duration::from_secs(1))
    }

    fn press(state: &mut TopState, code: KeyCode) -> Action {
        state.handle_key(KeyEvent::new(code, KeyModifiers::NONE))
    }

    fn type_text(state: &mut TopState, text: &str) {
        for c in text.chars() {
            press(state, KeyCode::Char(c));
        }
    }

    #[test]
    fn navigation_is_clamped() {
        let mut s = state();
        let len = s.rows.len();
        press(&mut s, KeyCode::Up);
        assert_eq!(s.selected, 0);
        press(&mut s, KeyCode::End);
        assert_eq!(s.selected, len - 1);
        press(&mut s, KeyCode::Down);
        assert_eq!(s.selected, len - 1);
        press(&mut s, KeyCode::PageUp);
        assert_eq!(s.selected, 0);
        press(&mut s, KeyCode::Char('j'));
        assert_eq!(s.selected, 1);
        press(&mut s, KeyCode::Char('k'));
        assert_eq!(s.selected, 0);
    }

    #[test]
    fn selection_follows_the_app_when_ranks_change() {
        let mut s = state();
        press(&mut s, KeyCode::Down);
        press(&mut s, KeyCode::Down);
        let chosen = s.selected_app().unwrap().name.clone();
        for seed in 2..30 {
            s.on_snapshot(snapshot(seed));
            assert_eq!(s.selected_app().unwrap().name, chosen, "seed {seed}");
        }
        press(&mut s, KeyCode::Char('s'));
        assert_eq!(s.selected_app().unwrap().name, chosen);
    }

    #[test]
    fn search_prompt_edit_apply_cancel() {
        let mut s = state();
        press(&mut s, KeyCode::Char('/'));
        type_text(&mut s, "gch");
        press(&mut s, KeyCode::Enter);
        assert_eq!(s.filter, "gch");
        assert!(
            s.rows.iter().all(|r| r.app.name.contains("Chrome")),
            "fuzzy name search"
        );
        press(&mut s, KeyCode::Char('/'));
        assert_eq!(
            press(&mut s, KeyCode::Char('q')),
            Action::Continue,
            "q is text while typing"
        );
        press(&mut s, KeyCode::Esc);
        press(&mut s, KeyCode::Esc);
        assert!(s.filter.is_empty(), "Esc clears the search");
    }

    #[test]
    fn sort_menu_and_cycle() {
        let mut s = state();
        press(&mut s, KeyCode::F(6));
        assert!(matches!(s.modal, Some(Modal::SortMenu { .. })));
        for _ in 0..4 {
            press(&mut s, KeyCode::Down);
        }
        press(&mut s, KeyCode::Enter);
        assert_eq!(s.sort, SortKey::Cpu);
        assert!(
            s.rows
                .windows(2)
                .all(|w| w[0].app.cpu_tenths >= w[1].app.cpu_tenths)
        );
        press(&mut s, KeyCode::Char('s'));
        assert_eq!(s.sort, SortKey::Mem);
        press(&mut s, KeyCode::Char('S'));
        press(&mut s, KeyCode::Char('S'));
        assert_eq!(s.sort, SortKey::Total);
    }

    #[test]
    fn freeze_holds_the_screen_but_not_navigation() {
        let mut s = state();
        press(&mut s, KeyCode::Char(' '));
        assert!(s.frozen);
        let before = s.rows.clone();
        s.on_snapshot(snapshot(7));
        assert_eq!(s.rows, before);
        press(&mut s, KeyCode::Down);
        assert_eq!(s.selected, 1);
    }

    #[test]
    fn tree_view_expands_and_collapses() {
        let mut s = state();
        press(&mut s, KeyCode::F(5));
        assert!(s.tree);
        assert!(
            s.rows.iter().all(|r| r.app.processes.len() == 1),
            "one row per process"
        );
        press(&mut s, KeyCode::F(5));
        assert!(!s.tree);
    }

    #[test]
    fn inspector_focus_moves_between_table_and_connections() {
        let mut s = state();
        press(&mut s, KeyCode::Enter);
        assert!(s.details && s.focus == Focus::Table);
        press(&mut s, KeyCode::Tab);
        assert_eq!(s.focus, Focus::Connections);
        let before = s.selected;
        press(&mut s, KeyCode::Down);
        assert_eq!(s.selected, before, "arrows move within the connections");
        press(&mut s, KeyCode::Esc);
        assert_eq!(s.focus, Focus::Table);
        press(&mut s, KeyCode::Esc);
        assert!(!s.details);
    }

    #[test]
    fn kill_asks_first_and_can_be_cancelled() {
        let mut s = with_actions(&["kill", "pause", "drop"]);
        let pid = s.selected_app().unwrap().pid;
        press(&mut s, KeyCode::F(9));
        assert!(matches!(
            s.modal,
            Some(Modal::Confirm(Confirm::Kill { .. }))
        ));
        press(&mut s, KeyCode::Esc);
        assert!(s.modal.is_none());
        press(&mut s, KeyCode::Char('x'));
        press(&mut s, KeyCode::Char('t'));
        assert!(s.modal.is_none());
        s.poll_actions();
        assert_eq!(
            s.message,
            Some((true, "done".into())),
            "the outcome is shown"
        );
        assert_eq!(s.selected_app().unwrap().pid, pid);
    }

    #[test]
    fn block_asks_for_how_long() {
        let mut s = with_actions(&["block-app", "block-ip"]);
        press(&mut s, KeyCode::Char('b'));
        assert!(matches!(
            s.modal,
            Some(Modal::Confirm(Confirm::Block {
                target: spectranet_proto::BlockTarget::App { .. },
                ..
            }))
        ));
        press(&mut s, KeyCode::Char('9'));
        assert!(s.modal.is_some(), "not a choice: still asking");
        press(&mut s, KeyCode::Char('1'));
        assert!(s.modal.is_none());
        s.poll_actions();
        assert_eq!(s.message, Some((true, "done".into())));

        // macOS: applications are followed, and the question says so.
        let mut s = with_actions(&["block-app-partial", "block-ip"]);
        press(&mut s, KeyCode::Char('b'));
        assert!(matches!(
            &s.modal,
            Some(Modal::Confirm(Confirm::Block { label, .. })) if label.contains("following")
        ));

        let mut s = with_actions(&["kill"]);
        press(&mut s, KeyCode::Char('b'));
        assert!(s.modal.is_none(), "refused without the capability");
    }

    #[test]
    fn pause_toggles_to_resume() {
        let mut s = with_actions(&["kill", "pause"]);
        let pid = s.selected_app().unwrap().pid;
        press(&mut s, KeyCode::Char('p'));
        press(&mut s, KeyCode::Char('y'));
        assert!(s.paused.contains(&pid));
        press(&mut s, KeyCode::Char('p'));
        assert!(matches!(
            s.modal,
            Some(Modal::Confirm(Confirm::Pause { resume: true, .. }))
        ));
        press(&mut s, KeyCode::Enter);
        assert!(!s.paused.contains(&pid));
    }

    #[test]
    fn actions_explain_why_they_are_unavailable() {
        let mut s = state();
        press(&mut s, KeyCode::F(9));
        assert!(s.modal.is_none());
        assert!(s.message.as_ref().unwrap().1.contains("snetd install"));
        let mut s = with_actions(&["kill", "pause"]);
        press(&mut s, KeyCode::Char('d'));
        assert!(s.message.as_ref().unwrap().1.contains("inspector"));
        press(&mut s, KeyCode::Enter);
        press(&mut s, KeyCode::Tab);
        press(&mut s, KeyCode::Char('d'));
        assert!(
            s.message.as_ref().unwrap().1.contains("not available"),
            "{:?}",
            s.message
        );
    }

    #[test]
    fn setup_toggles_columns_and_rebinds_keys() {
        let mut s = state();
        press(&mut s, KeyCode::F(2));
        // Columns tab: the first column is PID; hide it.
        press(&mut s, KeyCode::Char(' '));
        assert!(!s.settings.columns.contains(&Column::Pid));
        press(&mut s, KeyCode::Char(' '));
        assert_eq!(s.settings.columns[0], Column::Pid, "canonical order kept");
        // Keys tab: rebind "move up" to w.
        press(&mut s, KeyCode::Tab);
        press(&mut s, KeyCode::Enter);
        press(&mut s, KeyCode::Char('w'));
        assert_eq!(
            s.settings
                .keys
                .command(&KeyEvent::new(KeyCode::Char('w'), KeyModifiers::NONE)),
            Some(Cmd::Up)
        );
        assert!(matches!(s.modal, Some(Modal::Setup(_))));
    }

    #[test]
    fn empty_search_result_closes_details_and_keeps_working() {
        let mut s = state();
        press(&mut s, KeyCode::Enter);
        press(&mut s, KeyCode::Char('/'));
        type_text(&mut s, "zzzzzz");
        press(&mut s, KeyCode::Enter);
        assert!(s.rows.is_empty() && !s.details);
        press(&mut s, KeyCode::Down);
        press(&mut s, KeyCode::F(9));
        press(&mut s, KeyCode::Enter);
    }
}
