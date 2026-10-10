//! The Flight Recorder file format: JSON Lines, one [`RecordLine`] per line.
//!
//! ```text
//! {"type":"header","format":"snet-record","version":1,...}
//! {"type":"sample","snapshot":{...}}        one per sampling interval
//! {"type":"footer","ended_ms":...,"samples":N}
//! ```
//! A recording cut short (power loss, `kill -9`) simply lacks the footer and stays readable.

use serde::{Deserialize, Serialize};

use crate::Snapshot;

pub const FORMAT: &str = "snet-record";
pub const VERSION: u32 = 1;

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum RecordLine {
    Header(Header),
    Sample { snapshot: Snapshot },
    Footer(Footer),
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Header {
    pub format: String,
    pub version: u32,
    /// Milliseconds since the Unix epoch.
    pub started_ms: u64,
    pub hostname: String,
    pub interval_ms: u64,
    /// Capture backend, e.g. `macos`.
    pub source: String,
    /// What was recorded: application/process name filters and PIDs (empty = everything).
    pub names: Vec<String>,
    pub pids: Vec<u32>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Footer {
    pub ended_ms: u64,
    pub samples: u64,
}

impl Header {
    pub fn new(
        started_ms: u64,
        hostname: String,
        interval_ms: u64,
        source: String,
        names: Vec<String>,
        pids: Vec<u32>,
    ) -> Self {
        Self {
            format: FORMAT.into(),
            version: VERSION,
            started_ms,
            hostname,
            interval_ms,
            source,
            names,
            pids,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn wire_format() {
        let header = RecordLine::Header(Header::new(
            1,
            "mac".into(),
            1000,
            "macos".into(),
            vec!["curl".into()],
            vec![],
        ));
        let json = serde_json::to_string(&header).unwrap();
        assert!(
            json.starts_with(r#"{"type":"header","format":"snet-record","version":1"#),
            "{json}"
        );
        let footer = serde_json::to_string(&RecordLine::Footer(Footer {
            ended_ms: 5,
            samples: 3,
        }))
        .unwrap();
        assert_eq!(footer, r#"{"type":"footer","ended_ms":5,"samples":3}"#);
        let back: RecordLine = serde_json::from_str(&json).unwrap();
        assert_eq!(back, header);
    }
}
