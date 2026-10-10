//! What each key does in `snet top`, and the user's settings (`top.toml`): visible columns
//! and key bindings, both editable from the setup screen (F2).
//!
//! ```toml
//! columns = ["pid", "app", "down", "up", "cpu", "mem", "total", "conn", "destination", "status"]
//! [keys]
//! kill = ["F9", "x"]
//! ```

use std::collections::BTreeMap;
use std::path::PathBuf;

use ratatui::crossterm::event::{KeyCode, KeyEvent, KeyModifiers};
use serde::{Deserialize, Serialize};

/// Everything a key can do.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Cmd {
    Up,
    Down,
    PageUp,
    PageDown,
    Home,
    End,
    Inspect,
    Search,
    SortMenu,
    SortNext,
    SortPrev,
    Tree,
    Expand,
    Collapse,
    Setup,
    Help,
    Freeze,
    Kill,
    Pause,
    Drop,
    Block,
    Flows,
    Group,
    Flagged,
    Quit,
}

impl Cmd {
    pub const ALL: [Cmd; 25] = [
        Cmd::Up,
        Cmd::Down,
        Cmd::PageUp,
        Cmd::PageDown,
        Cmd::Home,
        Cmd::End,
        Cmd::Inspect,
        Cmd::Search,
        Cmd::SortMenu,
        Cmd::SortNext,
        Cmd::SortPrev,
        Cmd::Tree,
        Cmd::Expand,
        Cmd::Collapse,
        Cmd::Setup,
        Cmd::Help,
        Cmd::Freeze,
        Cmd::Kill,
        Cmd::Pause,
        Cmd::Drop,
        Cmd::Block,
        Cmd::Flows,
        Cmd::Group,
        Cmd::Flagged,
        Cmd::Quit,
    ];

    pub fn describe(self) -> &'static str {
        match self {
            Cmd::Up => "move up",
            Cmd::Down => "move down",
            Cmd::PageUp => "page up",
            Cmd::PageDown => "page down",
            Cmd::Home => "first row",
            Cmd::End => "last row",
            Cmd::Inspect => "inspect the selection: its connections, names, owner, resources",
            Cmd::Search => "search by name (fuzzy), hostname or address",
            Cmd::SortMenu => "choose the sort order",
            Cmd::SortNext => "next sort order",
            Cmd::SortPrev => "previous sort order",
            Cmd::Tree => "process tree: parents and their children",
            Cmd::Expand => "expand a branch of the tree",
            Cmd::Collapse => "collapse a branch (its traffic is summed into the parent)",
            Cmd::Setup => "setup: columns and key bindings",
            Cmd::Help => "help",
            Cmd::Freeze => "freeze / resume updates of the screen",
            Cmd::Kill => "end the selected process (asks first)",
            Cmd::Pause => "pause / resume the selected process (asks first)",
            Cmd::Drop => "close the selected connection (in the inspector; asks first)",
            Cmd::Block => {
                "block the selected application, or the selected connection's address (asks for how long)"
            }
            Cmd::Group => "group helpers under their application / one row per process",
            Cmd::Flagged => "only applications with a warning or an alert",
            Cmd::Flows => {
                "Flow Inspector: what kind of traffic each connection of the selection carries"
            }
            Cmd::Quit => "quit",
        }
    }

    fn defaults(self) -> &'static [&'static str] {
        match self {
            Cmd::Up => &["Up", "k"],
            Cmd::Down => &["Down", "j"],
            Cmd::PageUp => &["PageUp", "Ctrl-b"],
            Cmd::PageDown => &["PageDown", "Ctrl-f"],
            Cmd::Home => &["Home"],
            Cmd::End => &["End", "G"],
            Cmd::Inspect => &["Enter", "i"],
            Cmd::Search => &["/"],
            Cmd::SortMenu => &["F6", ">"],
            Cmd::SortNext => &["s"],
            Cmd::SortPrev => &["S"],
            Cmd::Tree => &["F5", "t"],
            Cmd::Expand => &["Right", "+", "l"],
            Cmd::Collapse => &["Left", "-", "h"],
            Cmd::Setup => &["F2"],
            Cmd::Help => &["F1", "?"],
            Cmd::Freeze => &["Space", "z"],
            Cmd::Kill => &["F9", "x"],
            Cmd::Pause => &["p"],
            Cmd::Drop => &["d"],
            Cmd::Block => &["b"],
            Cmd::Group => &["g"],
            Cmd::Flagged => &["F"],
            Cmd::Flows => &["f"],
            Cmd::Quit => &["q", "F10"],
        }
    }
}

/// A key as written in the settings and the help: `j`, `G`, `F9`, `Enter`, `Ctrl-b`.
pub fn key_name(key: &KeyEvent) -> Option<String> {
    let base = match key.code {
        KeyCode::Char(' ') => "Space".to_string(),
        KeyCode::Char(c) => c.to_string(),
        KeyCode::F(n) => format!("F{n}"),
        KeyCode::Enter => "Enter".into(),
        KeyCode::Tab => "Tab".into(),
        KeyCode::Backspace => "Backspace".into(),
        KeyCode::Up => "Up".into(),
        KeyCode::Down => "Down".into(),
        KeyCode::Left => "Left".into(),
        KeyCode::Right => "Right".into(),
        KeyCode::PageUp => "PageUp".into(),
        KeyCode::PageDown => "PageDown".into(),
        KeyCode::Home => "Home".into(),
        KeyCode::End => "End".into(),
        KeyCode::Delete => "Delete".into(),
        KeyCode::Insert => "Insert".into(),
        _ => return None,
    };
    let ctrl = key.modifiers.contains(KeyModifiers::CONTROL);
    let alt = key.modifiers.contains(KeyModifiers::ALT);
    Some(match (ctrl, alt) {
        (true, _) => format!("Ctrl-{base}"),
        (false, true) => format!("Alt-{base}"),
        _ => base,
    })
}

/// Key → command, built from the defaults overridden by `top.toml`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KeyMap {
    bindings: BTreeMap<Cmd, Vec<String>>,
}

impl Default for KeyMap {
    fn default() -> Self {
        Self {
            bindings: Cmd::ALL
                .iter()
                .map(|c| (*c, c.defaults().iter().map(|k| k.to_string()).collect()))
                .collect(),
        }
    }
}

impl KeyMap {
    pub fn command(&self, key: &KeyEvent) -> Option<Cmd> {
        let name = key_name(key)?;
        // Shifted letters arrive as uppercase chars, sometimes with SHIFT set too.
        self.bindings
            .iter()
            .find(|(_, keys)| keys.contains(&name))
            .map(|(c, _)| *c)
    }

    pub fn keys(&self, cmd: Cmd) -> &[String] {
        self.bindings.get(&cmd).map_or(&[], |v| v.as_slice())
    }

    /// Short form for the footer: the first key.
    pub fn first(&self, cmd: Cmd) -> &str {
        self.keys(cmd).first().map_or("", |k| k.as_str())
    }

    /// Binds `key` to `cmd`, taking it away from any other command. Ctrl-c always quits and
    /// can't be reassigned.
    pub fn bind(&mut self, cmd: Cmd, key: &str) -> bool {
        if key == "Ctrl-c" {
            return false;
        }
        for keys in self.bindings.values_mut() {
            keys.retain(|k| k != key);
        }
        let keys = self.bindings.entry(cmd).or_default();
        keys.insert(0, key.to_string());
        keys.truncate(3);
        true
    }

    pub fn reset(&mut self, cmd: Cmd) {
        let defaults: Vec<String> = cmd.defaults().iter().map(|k| k.to_string()).collect();
        for k in &defaults {
            for keys in self.bindings.values_mut() {
                keys.retain(|x| x != k);
            }
        }
        self.bindings.insert(cmd, defaults);
    }
}

/// A column of the application table.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Column {
    Pid,
    App,
    Down,
    Up,
    Cpu,
    Mem,
    Total,
    Conn,
    User,
    Destination,
    Status,
}

impl Column {
    pub const ALL: [Column; 11] = [
        Column::Pid,
        Column::App,
        Column::Down,
        Column::Up,
        Column::Cpu,
        Column::Mem,
        Column::Total,
        Column::Conn,
        Column::User,
        Column::Destination,
        Column::Status,
    ];

    pub fn title(self) -> &'static str {
        match self {
            Column::Pid => "PID",
            Column::App => "APPLICATION",
            Column::Down => "▼ DOWN",
            Column::Up => "▲ UP",
            Column::Cpu => "CPU%",
            Column::Mem => "MEM",
            Column::Total => "TOTAL",
            Column::Conn => "CONN",
            Column::User => "USER",
            Column::Destination => "TOP DESTINATION",
            Column::Status => "STATUS",
        }
    }

    pub fn describe(self) -> &'static str {
        match self {
            Column::Pid => "process ID",
            Column::App => "application or process name",
            Column::Down => "download speed",
            Column::Up => "upload speed",
            Column::Cpu => "CPU use (100 = one core)",
            Column::Mem => "resident memory",
            Column::Total => "bytes since the connections opened",
            Column::Conn => "open connections",
            Column::User => "account the process runs as",
            Column::Destination => "the busiest destination",
            Column::Status => "security verdict, paused processes",
        }
    }

    pub const DEFAULT: [Column; 10] = [
        Column::Pid,
        Column::App,
        Column::Down,
        Column::Up,
        Column::Cpu,
        Column::Mem,
        Column::Total,
        Column::Conn,
        Column::Destination,
        Column::Status,
    ];
}

/// The settings file as written on disk.
#[derive(Debug, Default, Serialize, Deserialize)]
struct File {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    columns: Option<Vec<Column>>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    keys: BTreeMap<Cmd, Vec<String>>,
}

/// Columns and key bindings.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Settings {
    pub columns: Vec<Column>,
    pub keys: KeyMap,
}

impl Default for Settings {
    fn default() -> Self {
        Self {
            columns: Column::DEFAULT.to_vec(),
            keys: KeyMap::default(),
        }
    }
}

/// `~/.config/spectranet/top.toml` (`$XDG_CONFIG_HOME`), or `%APPDATA%\spectraNET\top.toml`.
pub fn settings_path() -> Option<PathBuf> {
    if cfg!(windows) {
        return std::env::var_os("APPDATA")
            .map(|d| PathBuf::from(d).join("spectraNET").join("top.toml"));
    }
    let base = std::env::var_os("XDG_CONFIG_HOME")
        .map(PathBuf::from)
        .or_else(|| std::env::var_os("HOME").map(|h| PathBuf::from(h).join(".config")))?;
    Some(base.join("spectranet").join("top.toml"))
}

impl Settings {
    pub fn parse(text: &str) -> Result<Self, String> {
        let file: File = toml::from_str(text).map_err(|e| e.to_string())?;
        let mut settings = Settings::default();
        if let Some(columns) = file.columns {
            let mut seen = Vec::new();
            for c in columns {
                if !seen.contains(&c) {
                    seen.push(c);
                }
            }
            if !seen.is_empty() {
                settings.columns = seen;
            }
        }
        for (cmd, keys) in file.keys {
            settings.keys.bindings.insert(cmd, Vec::new());
            for k in keys.iter().rev() {
                settings.keys.bind(cmd, k);
            }
        }
        Ok(settings)
    }

    pub fn to_toml(&self) -> String {
        let defaults = KeyMap::default();
        let keys = self
            .keys
            .bindings
            .iter()
            .filter(|(cmd, keys)| defaults.keys(**cmd) != keys.as_slice())
            .map(|(c, k)| (*c, k.clone()))
            .collect();
        let file = File {
            columns: Some(self.columns.clone()),
            keys,
        };
        toml::to_string(&file).unwrap_or_default()
    }

    /// Reads the settings file; defaults if missing, defaults plus a message if broken.
    pub fn load() -> (Self, Option<String>) {
        let Some(path) = settings_path() else {
            return (Self::default(), None);
        };
        match std::fs::read_to_string(&path) {
            Err(_) => (Self::default(), None),
            Ok(text) => match Self::parse(&text) {
                Ok(s) => (s, None),
                Err(e) => (
                    Self::default(),
                    Some(format!("{}: {e}; using the defaults", path.display())),
                ),
            },
        }
    }

    pub fn save(&self) -> Result<PathBuf, String> {
        let path = settings_path().ok_or("no home directory to save the settings in")?;
        if let Some(dir) = path.parent() {
            std::fs::create_dir_all(dir).map_err(|e| e.to_string())?;
        }
        std::fs::write(&path, self.to_toml()).map_err(|e| format!("{}: {e}", path.display()))?;
        Ok(path)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key(code: KeyCode, modifiers: KeyModifiers) -> KeyEvent {
        KeyEvent::new(code, modifiers)
    }

    #[test]
    fn default_bindings_follow_vim_and_htop() {
        let k = KeyMap::default();
        assert_eq!(
            k.command(&key(KeyCode::Char('j'), KeyModifiers::NONE)),
            Some(Cmd::Down)
        );
        assert_eq!(
            k.command(&key(KeyCode::Char('k'), KeyModifiers::NONE)),
            Some(Cmd::Up)
        );
        assert_eq!(
            k.command(&key(KeyCode::F(9), KeyModifiers::NONE)),
            Some(Cmd::Kill)
        );
        assert_eq!(
            k.command(&key(KeyCode::Char('x'), KeyModifiers::NONE)),
            Some(Cmd::Kill)
        );
        assert_eq!(
            k.command(&key(KeyCode::F(5), KeyModifiers::NONE)),
            Some(Cmd::Tree)
        );
        assert_eq!(
            k.command(&key(KeyCode::F(6), KeyModifiers::NONE)),
            Some(Cmd::SortMenu)
        );
        assert_eq!(
            k.command(&key(KeyCode::F(2), KeyModifiers::NONE)),
            Some(Cmd::Setup)
        );
        assert_eq!(
            k.command(&key(KeyCode::Char('G'), KeyModifiers::SHIFT)),
            Some(Cmd::End)
        );
        assert_eq!(
            k.command(&key(KeyCode::Char('b'), KeyModifiers::CONTROL)),
            Some(Cmd::PageUp)
        );
        assert_eq!(
            k.command(&key(KeyCode::Char(' '), KeyModifiers::NONE)),
            Some(Cmd::Freeze)
        );
        // No key does two things.
        let mut all: Vec<&String> = Cmd::ALL.iter().flat_map(|c| k.keys(*c)).collect();
        let n = all.len();
        all.sort();
        all.dedup();
        assert_eq!(all.len(), n, "duplicate default binding");
    }

    #[test]
    fn rebinding_moves_a_key_and_ctrl_c_stays() {
        let mut k = KeyMap::default();
        assert!(k.bind(Cmd::Kill, "k"));
        assert_eq!(
            k.command(&key(KeyCode::Char('k'), KeyModifiers::NONE)),
            Some(Cmd::Kill)
        );
        assert!(
            !k.keys(Cmd::Up).contains(&"k".to_string()),
            "taken away from Up"
        );
        assert!(!k.bind(Cmd::Pause, "Ctrl-c"));
        k.reset(Cmd::Up);
        assert_eq!(
            k.command(&key(KeyCode::Char('k'), KeyModifiers::NONE)),
            Some(Cmd::Up)
        );
    }

    #[test]
    fn settings_round_trip_and_tolerate_mistakes() {
        let mut s = Settings {
            columns: vec![Column::App, Column::Cpu],
            ..Default::default()
        };
        s.keys.bind(Cmd::Drop, "D");
        let text = s.to_toml();
        assert!(text.contains("drop"), "{text}");
        assert!(!text.contains("page-up"), "only changes are written");
        assert_eq!(Settings::parse(&text).unwrap(), s);
        assert!(Settings::parse("columns = [\"nope\"]").is_err());
        assert_eq!(Settings::parse("").unwrap(), Settings::default());
        assert_eq!(
            Settings::parse("columns = []").unwrap().columns,
            Column::DEFAULT.to_vec()
        );
    }

    #[test]
    fn the_man_page_lists_every_default_key() {
        let man = crate::cli::TOP_KEYS;
        for cmd in Cmd::ALL {
            for key in cmd.defaults() {
                assert!(
                    man.contains(key),
                    "snet-top(1) does not mention {key} ({cmd:?})"
                );
            }
        }
    }

    #[test]
    fn key_names() {
        assert_eq!(
            key_name(&key(KeyCode::Char(' '), KeyModifiers::NONE)).as_deref(),
            Some("Space")
        );
        assert_eq!(
            key_name(&key(KeyCode::F(10), KeyModifiers::NONE)).as_deref(),
            Some("F10")
        );
        assert_eq!(
            key_name(&key(KeyCode::Char('c'), KeyModifiers::CONTROL)).as_deref(),
            Some("Ctrl-c")
        );
        assert_eq!(
            key_name(&key(KeyCode::Esc, KeyModifiers::NONE)),
            None,
            "Esc is never bindable"
        );
    }
}
