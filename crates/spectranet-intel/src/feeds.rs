//! Public reputation lists: where they come from, how they are stored and refreshed.
//!
//! Lists are downloaded by the service into a data directory and read from there by everyone.
//! Downloading reveals nothing about this machine's traffic: the whole list is fetched and
//! all matching happens locally.

use std::net::IpAddr;
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime};

use serde::{Deserialize, Serialize};
use spectranet_model::Verdict;

use crate::ipset::IpSet;

/// One reputation list.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Feed {
    pub id: &'static str,
    pub name: &'static str,
    pub url: &'static str,
    pub verdict: Verdict,
    /// Shown to the user when a connection matches.
    pub reason: &'static str,
}

pub const FEEDS: [Feed; 4] = [
    Feed {
        id: "feodo",
        name: "abuse.ch Feodo Tracker",
        url: "https://feodotracker.abuse.ch/downloads/ipblocklist.txt",
        verdict: Verdict::Alert,
        reason: "known botnet command-and-control server (abuse.ch Feodo Tracker)",
    },
    Feed {
        id: "spamhaus-drop",
        name: "Spamhaus DROP",
        url: "https://www.spamhaus.org/drop/drop.txt",
        verdict: Verdict::Alert,
        reason: "network run by criminals or hijacked (Spamhaus DROP)",
    },
    Feed {
        id: "spamhaus-dropv6",
        name: "Spamhaus DROP (IPv6)",
        url: "https://www.spamhaus.org/drop/dropv6.txt",
        verdict: Verdict::Alert,
        reason: "network run by criminals or hijacked (Spamhaus DROP)",
    },
    Feed {
        id: "tor-exits",
        name: "Tor exit nodes",
        url: "https://check.torproject.org/torbulkexitlist",
        verdict: Verdict::Warn,
        reason: "Tor exit node: traffic leaves the Tor network here",
    },
];

/// Lists older than this are refreshed.
pub const MAX_AGE: Duration = Duration::from_secs(12 * 3600);
/// A downloaded list larger than this is refused (they are a few hundred KB at most).
const MAX_SIZE: u64 = 16 * 1024 * 1024;

/// What is loaded from one list.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FeedStatus {
    pub id: String,
    pub name: String,
    /// Number of address ranges loaded (0 when the list is missing).
    pub ranges: usize,
    /// When the file was last written, seconds since the Unix epoch.
    pub updated: Option<u64>,
}

/// All lists, loaded.
#[derive(Debug, Default)]
pub struct Feeds {
    loaded: Vec<(Feed, IpSet, Option<SystemTime>)>,
}

impl Feeds {
    /// Loads every list present in `dir`; missing or unreadable ones are simply absent.
    pub fn load(dir: &Path) -> Self {
        let loaded = FEEDS
            .iter()
            .filter_map(|feed| {
                let path = file_for(dir, feed);
                let text = std::fs::read_to_string(&path).ok()?;
                let modified = std::fs::metadata(&path).and_then(|m| m.modified()).ok();
                let (set, _) = IpSet::parse(&text);
                Some((*feed, set, modified))
            })
            .collect();
        Self { loaded }
    }

    /// Leaves out the lists named in `ids` (turned off in the settings).
    pub fn without(mut self, ids: &[String]) -> Self {
        self.loaded
            .retain(|(feed, _, _)| !ids.iter().any(|id| id == feed.id));
        self
    }

    /// The most severe list containing `ip`.
    pub fn lookup(&self, ip: IpAddr) -> Option<&Feed> {
        self.loaded
            .iter()
            .filter(|(_, set, _)| set.contains(ip))
            .map(|(feed, _, _)| feed)
            .max_by_key(|feed| feed.verdict)
    }

    pub fn status(&self) -> Vec<FeedStatus> {
        FEEDS
            .iter()
            .map(|feed| {
                let found = self.loaded.iter().find(|(f, _, _)| f.id == feed.id);
                FeedStatus {
                    id: feed.id.into(),
                    name: feed.name.into(),
                    ranges: found.map_or(0, |(_, set, _)| set.len()),
                    updated: found
                        .and_then(|(_, _, t)| *t)
                        .and_then(|t| t.duration_since(SystemTime::UNIX_EPOCH).ok())
                        .map(|d| d.as_secs()),
                }
            })
            .collect()
    }

    pub fn is_empty(&self) -> bool {
        self.loaded.is_empty()
    }
}

pub fn file_for(dir: &Path, feed: &Feed) -> PathBuf {
    dir.join(format!("{}.txt", feed.id))
}

/// Whether any list in `dir` is missing or older than [`MAX_AGE`].
pub fn needs_update(dir: &Path) -> bool {
    FEEDS.iter().any(|feed| {
        std::fs::metadata(file_for(dir, feed))
            .and_then(|m| m.modified())
            .ok()
            .and_then(|t| t.elapsed().ok())
            .is_none_or(|age| age > MAX_AGE)
    })
}

/// Outcome of refreshing one list.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum UpdateResult {
    Updated { ranges: usize },
    Failed(String),
}

/// Downloads every list into `dir`. Each file is replaced only by a download that parses into
/// a non-trivial list, so a failed or garbled download never erases good data.
pub fn update_all(dir: &Path) -> Vec<(Feed, UpdateResult)> {
    let agent: ureq::Agent = ureq::Agent::config_builder()
        .timeout_global(Some(Duration::from_secs(60)))
        .user_agent(concat!("spectraNET/", env!("CARGO_PKG_VERSION")))
        .build()
        .into();
    FEEDS
        .iter()
        .map(|feed| {
            let result = fetch(&agent, feed.url)
                .and_then(|body| install(dir, feed, &body))
                .map_or_else(UpdateResult::Failed, |ranges| UpdateResult::Updated {
                    ranges,
                });
            (*feed, result)
        })
        .collect()
}

fn fetch(agent: &ureq::Agent, url: &str) -> Result<String, String> {
    let mut response = agent.get(url).call().map_err(|e| e.to_string())?;
    let bytes = response
        .body_mut()
        .with_config()
        .limit(MAX_SIZE)
        .read_to_vec()
        .map_err(|e| e.to_string())?;
    String::from_utf8(bytes).map_err(|_| "not text".to_string())
}

/// Validates a downloaded list and atomically replaces the stored one.
pub fn install(dir: &Path, feed: &Feed, body: &str) -> Result<usize, String> {
    let (set, rejected) = IpSet::parse(body);
    if set.is_empty() {
        return Err("download contained no addresses".into());
    }
    // A list that is mostly unparsable is probably an error page, not a list.
    if rejected > set.len() {
        return Err(format!(
            "download looks wrong ({rejected} unreadable lines)"
        ));
    }
    std::fs::create_dir_all(dir).map_err(|e| e.to_string())?;
    let path = file_for(dir, feed);
    let tmp = path.with_extension("txt.tmp");
    std::fs::write(&tmp, body).map_err(|e| e.to_string())?;
    std::fs::rename(&tmp, &path).map_err(|e| e.to_string())?;
    Ok(set.len())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn install_validates_and_load_reads_back() {
        let dir = tempfile::tempdir().unwrap();
        let feodo = &FEEDS[0];
        let tor = &FEEDS[3];
        assert_eq!(
            install(dir.path(), feodo, "# list\n162.243.103.246\n"),
            Ok(1)
        );
        assert_eq!(
            install(dir.path(), tor, "185.220.101.5\n162.243.103.246\n"),
            Ok(2)
        );
        let feeds = Feeds::load(dir.path());
        let ip: IpAddr = "162.243.103.246".parse().unwrap();
        assert_eq!(
            feeds.lookup(ip).map(|f| f.id),
            Some("feodo"),
            "most severe list wins"
        );
        assert_eq!(
            feeds.lookup("185.220.101.5".parse().unwrap()).map(|f| f.id),
            Some("tor-exits")
        );
        assert_eq!(feeds.lookup("8.8.8.8".parse().unwrap()), None);
        let status = feeds.status();
        assert_eq!(status.len(), FEEDS.len());
        assert_eq!(status[0].ranges, 1);
        assert!(status[0].updated.is_some());
        assert_eq!(status[1].ranges, 0, "missing list reported as empty");
    }

    #[test]
    fn bad_downloads_never_replace_good_data() {
        let dir = tempfile::tempdir().unwrap();
        let feed = &FEEDS[0];
        install(dir.path(), feed, "1.2.3.4\n").unwrap();
        assert!(install(dir.path(), feed, "").is_err());
        assert!(
            install(
                dir.path(),
                feed,
                "<html><body>Rate limited</body></html>\n<p>x</p>\n9.9.9.9\n"
            )
            .is_err()
        );
        let feeds = Feeds::load(dir.path());
        assert!(feeds.lookup("1.2.3.4".parse().unwrap()).is_some());
        assert_eq!(
            std::fs::read_dir(dir.path()).unwrap().count(),
            1,
            "no temporary files left"
        );
    }

    #[test]
    fn missing_directory_loads_nothing() {
        let feeds = Feeds::load(Path::new("/nonexistent/spectranet"));
        assert!(feeds.is_empty());
        assert!(needs_update(Path::new("/nonexistent/spectranet")));
    }

    #[test]
    fn freshness() {
        let dir = tempfile::tempdir().unwrap();
        assert!(needs_update(dir.path()));
        for feed in &FEEDS {
            install(dir.path(), feed, "1.2.3.4\n").unwrap();
        }
        assert!(!needs_update(dir.path()));
    }

    /// Talks to the real list servers. Skipped (with a message) when offline.
    #[test]
    fn real_download() {
        let dir = tempfile::tempdir().unwrap();
        let results = update_all(dir.path());
        let ok: Vec<_> = results
            .iter()
            .filter(|(_, r)| matches!(r, UpdateResult::Updated { .. }))
            .collect();
        if ok.is_empty() {
            eprintln!("no list could be downloaded (offline?): {results:?}");
            return;
        }
        for (feed, result) in &results {
            eprintln!("{}: {result:?}", feed.name);
            if let UpdateResult::Updated { ranges } = result {
                assert!(*ranges > 0);
            }
        }
        assert!(!Feeds::load(dir.path()).is_empty());
    }
}
