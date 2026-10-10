//! What is known about a connection beyond its byte counters: packet rates, the TLS
//! handshake (visible in clear on the wire) and what kind of traffic it probably carries.
//!
//! Nothing here comes from the content of the communication: rates, sizes and timing,
//! the host name, and the handshake fields every router on the path can read.

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct FlowMeta {
    /// Packets (or socket messages, depending on the platform) received per second during
    /// the last interval.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rx_pps: Option<u32>,
    /// Packets (or socket messages) sent per second during the last interval.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tx_pps: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tls: Option<TlsInfo>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub class: Option<Class>,
}

impl FlowMeta {
    pub fn is_empty(&self) -> bool {
        self == &Self::default()
    }
}

/// The handshake of a TLS (or QUIC) connection, as sent in clear.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct TlsInfo {
    /// Negotiated version, e.g. `TLS 1.3`, when the server's answer was seen.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub version: Option<String>,
    /// Negotiated cipher suite, e.g. `TLS_AES_256_GCM_SHA384`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cipher: Option<String>,
    /// Application protocols the client offered (ALPN), e.g. `h2`, `http/1.1`, `h3`.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub alpn: Vec<String>,
    /// JA4 fingerprint of the client's hello: identifies the TLS library or application.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ja4: Option<String>,
    /// Carried by QUIC (HTTP/3) rather than TCP.
    #[serde(default)]
    pub quic: bool,
}

/// What kind of traffic a connection probably carries.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Kind {
    /// Video streaming (buffered, bursty downloads).
    Video,
    /// Music, radio, podcasts.
    Audio,
    /// Voice or video call, conference (steady small packets both ways).
    Call,
    /// Web pages, APIs, messaging: short exchanges.
    Web,
    /// Large download or software update.
    Download,
    /// Backup, cloud sync, large upload.
    Upload,
    /// Online game.
    Game,
    /// Raw radio samples (IQ) from a software-defined radio, e.g. rtl_tcp, SpyServer.
    RawIq,
    /// Demodulated audio or DSP stream between radio programs.
    RadioAudio,
    /// Digital radio modes: FT8/WSJT-X, APRS, PSK Reporter spots.
    DigitalModes,
    /// Satellite telemetry and imagery, ADS-B and other decoded data.
    Telemetry,
    /// A web software-defined radio (OpenWebRX, KiwiSDR, WebSDR).
    WebSdr,
}

impl Kind {
    pub const ALL: [Kind; 12] = [
        Kind::Video,
        Kind::Audio,
        Kind::Call,
        Kind::Web,
        Kind::Download,
        Kind::Upload,
        Kind::Game,
        Kind::RawIq,
        Kind::RadioAudio,
        Kind::DigitalModes,
        Kind::Telemetry,
        Kind::WebSdr,
    ];

    /// The radio kinds (software-defined radio and satellite reception).
    pub const RADIO: [Kind; 5] = [
        Kind::RawIq,
        Kind::RadioAudio,
        Kind::DigitalModes,
        Kind::Telemetry,
        Kind::WebSdr,
    ];

    pub fn is_radio(self) -> bool {
        Self::RADIO.contains(&self)
    }

    pub fn name(self) -> &'static str {
        match self {
            Kind::Video => "video",
            Kind::Audio => "audio",
            Kind::Call => "call",
            Kind::Web => "web",
            Kind::Download => "download",
            Kind::Upload => "upload",
            Kind::Game => "game",
            Kind::RawIq => "raw_iq",
            Kind::RadioAudio => "radio_audio",
            Kind::DigitalModes => "digital_modes",
            Kind::Telemetry => "telemetry",
            Kind::WebSdr => "websdr",
        }
    }

    pub fn parse(text: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|k| k.name() == text)
    }
}

/// How sure the classification is.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Certainty {
    /// The traffic pattern suggests it.
    Likely,
    /// Pattern and host (or several signals) agree.
    VeryLikely,
    /// The host belongs to a service of this kind (from the list of known services).
    Declared,
}

/// One reason behind a classification, shown to the user in their language.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "reason", rename_all = "snake_case")]
pub enum Reason {
    /// The host is a known service of this kind.
    KnownHost { domain: String },
    /// Downloads come in bursts at regular intervals (a player filling its buffer).
    PeriodicBursts { every_s: u32, peak: u64 },
    /// A sustained transfer in one direction.
    Sustained { download: bool, rate: u64 },
    /// Many small packets at a steady pace (voice and video calls, games).
    SmallSteadyPackets { pps: u32, size: u32 },
    /// Short exchanges separated by pauses.
    ShortExchanges,
    /// A port used by this kind of service.
    WellKnownPort { port: u16 },
    /// The application protocol offered in the handshake.
    Protocol { alpn: String },
    /// The program is radio software.
    RadioProgram { program: String },
    /// A port used by a radio service.
    RadioPort { port: u16, service: String },
    /// A stream at a constant rate (radio samples, demodulated audio).
    ConstantRate { rate: u64 },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Class {
    pub kind: Kind,
    pub certainty: Certainty,
    #[serde(default)]
    pub reasons: Vec<Reason>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_meta_is_left_out_of_json() {
        assert!(FlowMeta::default().is_empty());
        let meta = FlowMeta {
            class: Some(Class {
                kind: Kind::Video,
                certainty: Certainty::Declared,
                reasons: vec![Reason::KnownHost {
                    domain: "googlevideo.com".into(),
                }],
            }),
            ..Default::default()
        };
        let json = serde_json::to_string(&meta).unwrap();
        assert_eq!(
            json,
            r#"{"class":{"kind":"video","certainty":"declared","reasons":[{"reason":"known_host","domain":"googlevideo.com"}]}}"#
        );
        assert_eq!(serde_json::from_str::<FlowMeta>(&json).unwrap(), meta);
        assert_eq!(
            serde_json::from_str::<FlowMeta>("{}").unwrap(),
            FlowMeta::default()
        );
    }

    #[test]
    fn kinds_round_trip_by_name() {
        for k in Kind::ALL {
            assert_eq!(Kind::parse(k.name()), Some(k));
        }
    }
}
