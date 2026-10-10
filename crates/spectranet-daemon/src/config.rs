//! The service's optional configuration file, `snetd.conf` in its data directory (TOML):
//!
//! ```toml
//! # Only root / elevated administrators may end, pause or block (default: everyone who may
//! # read snetd, i.e. the admin group, or the users authorised on Windows).
//! actions = "elevated-only"
//! # Prometheus metrics on this address (default: off). Keep it on 127.0.0.1 unless you
//! # mean to publish them.
//! metrics = "127.0.0.1:9790"
//! # Refresh the list of known services (video, calls, downloads…) used to tell what kind
//! # of traffic a connection carries (default: true; the built-in list is used otherwise).
//! category_updates = false
//! # Download the reputation lists (default: true).
//! feed_updates = true
//! # Reputation lists not to use: feodo, spamhaus-drop, spamhaus-dropv6, tor-exits.
//! feeds_disabled = ["tor-exits"]
//! # Days of usage history to keep (default: 0, everything).
//! history_days = 365
//! ```
//!
//! A missing file means the defaults; a broken one is reported and ignored, so a typo never
//! stops the service. `snetd config set KEY=VALUE…` changes it (as administrator) and restarts
//! the service; the desktop app's Options use that.

use std::net::SocketAddr;
use std::path::Path;

use serde::Deserialize;
use spectranet_proto::ServiceSettings;

pub const FILE_NAME: &str = "snetd.conf";

/// The longest history that may be asked for (ten years).
const MAX_HISTORY_DAYS: u32 = 3_660;

#[derive(Debug, Default, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
struct Raw {
    actions: Option<String>,
    metrics: Option<String>,
    category_updates: Option<bool>,
    feed_updates: Option<bool>,
    feeds_disabled: Option<Vec<String>>,
    history_days: Option<u32>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FileConfig {
    pub actions_elevated_only: bool,
    pub metrics: Option<SocketAddr>,
    pub category_updates: bool,
    pub feed_updates: bool,
    pub feeds_disabled: Vec<String>,
    pub history_days: u32,
}

impl Default for FileConfig {
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

impl FileConfig {
    /// As reported to clients.
    pub fn settings(&self) -> ServiceSettings {
        ServiceSettings {
            actions_elevated_only: self.actions_elevated_only,
            metrics: self.metrics.map(|a| a.to_string()),
            category_updates: self.category_updates,
            feed_updates: self.feed_updates,
            feeds_disabled: self.feeds_disabled.clone(),
            history_days: self.history_days,
        }
    }

    /// The file's text for these settings.
    pub fn render(&self) -> String {
        let quoted: Vec<String> = self
            .feeds_disabled
            .iter()
            .map(|id| format!("\"{id}\""))
            .collect();
        format!(
            "# snetd settings (see snetd(8)); written by `snetd config set`.\n\
             actions = \"{}\"\n\
             metrics = \"{}\"\n\
             category_updates = {}\n\
             feed_updates = {}\n\
             feeds_disabled = [{}]\n\
             history_days = {}\n",
            if self.actions_elevated_only {
                "elevated-only"
            } else {
                "allowed-users"
            },
            self.metrics
                .map_or_else(|| "off".to_string(), |a| a.to_string()),
            self.category_updates,
            self.feed_updates,
            quoted.join(", "),
            self.history_days,
        )
    }

    /// Applies one `key=value` from the command line.
    pub fn set(&mut self, pair: &str) -> Result<(), String> {
        let (key, value) = pair
            .split_once('=')
            .ok_or_else(|| format!("'{pair}': expected KEY=VALUE"))?;
        let (key, value) = (key.trim(), value.trim());
        let boolean = |v: &str| match v {
            "true" | "on" | "yes" => Ok(true),
            "false" | "off" | "no" => Ok(false),
            _ => Err(format!("{key} = {v}: expected true or false")),
        };
        match key {
            "actions" => {
                self.actions_elevated_only = match value {
                    "elevated-only" => true,
                    "allowed-users" => false,
                    _ => {
                        return Err(format!(
                            "actions = {value}: expected elevated-only or allowed-users"
                        ));
                    }
                }
            }
            "metrics" => self.metrics = parse_metrics(value)?,
            "category_updates" => self.category_updates = boolean(value)?,
            "feed_updates" => self.feed_updates = boolean(value)?,
            "feeds_disabled" => {
                self.feeds_disabled = parse_feeds(
                    value
                        .split(',')
                        .map(str::trim)
                        .filter(|s| !s.is_empty())
                        .map(String::from)
                        .collect(),
                )?
            }
            "history_days" => {
                self.history_days = parse_days(
                    value
                        .parse()
                        .map_err(|_| format!("history_days = {value}: expected a number"))?,
                )?
            }
            _ => {
                return Err(format!(
                    "unknown setting '{key}' (actions, metrics, category_updates, feed_updates, \
                     feeds_disabled, history_days)"
                ));
            }
        }
        Ok(())
    }
}

fn parse_metrics(value: &str) -> Result<Option<SocketAddr>, String> {
    match value {
        "" | "off" => Ok(None),
        addr => addr.parse().map(Some).map_err(|_| {
            format!("metrics = \"{addr}\": expected an address such as 127.0.0.1:9790")
        }),
    }
}

fn parse_feeds(ids: Vec<String>) -> Result<Vec<String>, String> {
    let known: Vec<&str> = spectranet_intel::feeds::FEEDS
        .iter()
        .map(|f| f.id)
        .collect();
    for id in &ids {
        if !known.contains(&id.as_str()) {
            return Err(format!(
                "feeds_disabled: unknown list '{id}' (known: {})",
                known.join(", ")
            ));
        }
    }
    Ok(ids)
}

fn parse_days(days: u32) -> Result<u32, String> {
    if days > MAX_HISTORY_DAYS {
        Err(format!(
            "history_days = {days}: at most {MAX_HISTORY_DAYS} (0 keeps everything)"
        ))
    } else {
        Ok(days)
    }
}

/// Parses the configuration text; errors name the offending setting.
pub fn parse(text: &str) -> Result<FileConfig, String> {
    let raw: Raw = toml::from_str(text).map_err(|e| e.to_string())?;
    let actions_elevated_only = match raw.actions.as_deref() {
        None | Some("allowed-users") => false,
        Some("elevated-only") => true,
        Some(other) => {
            return Err(format!(
                "actions = \"{other}\": expected \"elevated-only\" or \"allowed-users\""
            ));
        }
    };
    Ok(FileConfig {
        actions_elevated_only,
        metrics: parse_metrics(raw.metrics.as_deref().unwrap_or(""))?,
        category_updates: raw.category_updates.unwrap_or(true),
        feed_updates: raw.feed_updates.unwrap_or(true),
        feeds_disabled: parse_feeds(raw.feeds_disabled.unwrap_or_default())?,
        history_days: parse_days(raw.history_days.unwrap_or(0))?,
    })
}

/// Reads `snetd.conf` from the data directory; defaults if absent or broken.
pub fn load(data_dir: &Path) -> FileConfig {
    let path = data_dir.join(FILE_NAME);
    let Ok(text) = std::fs::read_to_string(&path) else {
        return FileConfig::default();
    };
    match parse(&text) {
        Ok(config) => config,
        Err(e) => {
            crate::service::log(&format!("{}: {e}; using the defaults", path.display()));
            FileConfig::default()
        }
    }
}

/// `snetd config set`: changes the settings in `data_dir` (a broken file is replaced by the
/// defaults plus the changes). The caller restarts the service.
pub fn set_and_save(data_dir: &Path, pairs: &[String]) -> anyhow::Result<FileConfig> {
    let path = data_dir.join(FILE_NAME);
    let mut config = std::fs::read_to_string(&path)
        .ok()
        .and_then(|t| parse(&t).ok())
        .unwrap_or_default();
    for pair in pairs {
        config.set(pair).map_err(anyhow::Error::msg)?;
    }
    let text = config.render();
    debug_assert_eq!(parse(&text).as_ref(), Ok(&config));
    std::fs::create_dir_all(data_dir)?;
    let tmp = path.with_extension("conf.tmp");
    std::fs::write(&tmp, text)?;
    std::fs::rename(&tmp, &path)?;
    Ok(config)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_the_documented_settings() {
        assert_eq!(parse("").unwrap(), FileConfig::default());
        let c = parse("actions = \"elevated-only\"\nmetrics = \"127.0.0.1:9790\"\n").unwrap();
        assert!(c.actions_elevated_only);
        assert_eq!(c.metrics, Some("127.0.0.1:9790".parse().unwrap()));
        assert_eq!(parse("metrics = \"off\"").unwrap().metrics, None);
        assert!(
            FileConfig::default().category_updates,
            "on unless turned off"
        );
        assert!(!parse("category_updates = false").unwrap().category_updates);
        let c = parse("feeds_disabled = [\"tor-exits\"]\nhistory_days = 30\nfeed_updates = false")
            .unwrap();
        assert_eq!(c.feeds_disabled, vec!["tor-exits".to_string()]);
        assert_eq!(c.history_days, 30);
        assert!(!c.feed_updates);
    }

    #[test]
    fn mistakes_are_explained() {
        assert!(
            parse("actions = \"maybe\"")
                .unwrap_err()
                .contains("elevated-only")
        );
        assert!(
            parse("metrics = \"everywhere\"")
                .unwrap_err()
                .contains("127.0.0.1")
        );
        assert!(
            parse("acitons = \"elevated-only\"").is_err(),
            "typos are not silently ignored"
        );
        assert!(
            parse("feeds_disabled = [\"nope\"]")
                .unwrap_err()
                .contains("tor-exits")
        );
        assert!(parse("history_days = 99999").is_err());
    }

    #[test]
    fn set_then_render_round_trips() {
        let mut c = FileConfig::default();
        for pair in [
            "actions=elevated-only",
            "metrics=127.0.0.1:9790",
            "category_updates=off",
            "feed_updates=false",
            "feeds_disabled=tor-exits, feodo",
            "history_days=90",
        ] {
            c.set(pair).unwrap();
        }
        assert_eq!(parse(&c.render()).unwrap(), c);
        c.set("feeds_disabled=").unwrap();
        c.set("metrics=off").unwrap();
        assert_eq!(parse(&c.render()).unwrap(), c);
        assert!(c.set("history_days=many").is_err());
        assert!(
            c.set("colour=blue")
                .unwrap_err()
                .contains("unknown setting")
        );
        assert!(c.set("noequals").is_err());
    }

    #[test]
    fn saving_writes_a_file_the_service_reads() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join(FILE_NAME), "this is not toml").unwrap();
        let saved = set_and_save(dir.path(), &["history_days=7".into()]).unwrap();
        assert_eq!(saved.history_days, 7);
        assert_eq!(load(dir.path()), saved);
    }
}
