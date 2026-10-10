//! Words, symbols and colours for what kind of traffic a connection carries, shared by
//! `snet top`, `snet stream`, `snet inspect` and the connection lists.

use spectranet_model::Flow;
use spectranet_model::flowmeta::{Certainty, Kind, Reason};

use crate::units::rate;

/// Symbol, short tag and 24-bit colour of a kind of traffic.
pub fn kind_style(kind: Kind) -> (&'static str, &'static str, (u8, u8, u8)) {
    match kind {
        Kind::Video => ("🎥", "VIDEO", (0xc0, 0x84, 0xfc)),
        Kind::Audio => ("🔊", "AUDIO", (0x34, 0xd3, 0x99)),
        Kind::Call => ("📞", "CALL", (0x4a, 0xde, 0x80)),
        Kind::Web => ("🔤", "WEB/API", (0x22, 0xd3, 0xee)),
        Kind::Download => ("⬇", "DOWNLOAD", (0x60, 0xa5, 0xfa)),
        Kind::Upload => ("⬆", "UPLOAD", (0xf4, 0x72, 0xb6)),
        Kind::Game => ("🎮", "GAME", (0xfa, 0xcc, 0x15)),
        Kind::RawIq => ("📡", "RAW IQ", (0xf5, 0x9e, 0x0b)),
        Kind::RadioAudio => ("📻", "RADIO AUDIO", (0x2d, 0xd4, 0xbf)),
        Kind::DigitalModes => ("📶", "DIGITAL", (0xa3, 0xe6, 0x35)),
        Kind::Telemetry => ("🛰", "TELEMETRY", (0xfb, 0x92, 0x3c)),
        Kind::WebSdr => ("🌐", "WEBSDR", (0x38, 0xbd, 0xf8)),
    }
}

/// `video`, `call`… as a lowercase word for sentences.
pub fn kind_word(kind: Kind) -> &'static str {
    match kind {
        Kind::Video => "video streaming",
        Kind::Audio => "music or audio",
        Kind::Call => "voice or video call",
        Kind::Web => "web pages or APIs",
        Kind::Download => "download or update",
        Kind::Upload => "upload or backup",
        Kind::Game => "online game",
        Kind::RawIq => "raw radio samples (IQ) from a software-defined radio",
        Kind::RadioAudio => "demodulated radio audio or a DSP stream",
        Kind::DigitalModes => "digital radio modes (FT8, APRS, spots)",
        Kind::Telemetry => "satellite telemetry, imagery or decoded data",
        Kind::WebSdr => "a web software-defined radio",
    }
}

pub fn certainty_word(c: Certainty) -> &'static str {
    match c {
        Certainty::Likely => "likely",
        Certainty::VeryLikely => "very likely",
        Certainty::Declared => "known service",
    }
}

/// One reason in plain words.
pub fn reason_text(r: &Reason) -> String {
    match r {
        Reason::KnownHost { domain } => format!("{domain} is a known service of this kind"),
        Reason::PeriodicBursts { every_s, peak } => format!(
            "downloads in bursts every {every_s} s (up to {}), like a player filling its buffer",
            rate(*peak)
        ),
        Reason::Sustained { download, rate: r } => format!(
            "sustained {} at about {}",
            if *download { "download" } else { "upload" },
            rate(*r)
        ),
        Reason::SmallSteadyPackets { pps, size } => format!(
            "steady stream of small packets both ways ({pps} packets/s of about {size} bytes)"
        ),
        Reason::ShortExchanges => "short exchanges separated by pauses".into(),
        Reason::WellKnownPort { port } => format!("port {port} is used by call services"),
        Reason::Protocol { alpn } => format!("the client offered {alpn}"),
        Reason::RadioProgram { program } => format!("{program} is radio software"),
        Reason::RadioPort { port, service } => format!("port {port} is used by {service}"),
        Reason::ConstantRate { rate: r } => {
            format!("stream at a constant rate of about {}", rate(*r))
        }
    }
}

/// Protocol summary: `TLS 1.3 · h2`, `QUIC · h3`, or the service name.
pub fn protocol(flow: &Flow) -> String {
    let Some(tls) = &flow.meta.tls else {
        return String::new();
    };
    let mut parts = Vec::new();
    if tls.quic {
        parts.push("QUIC".to_string());
    } else if let Some(v) = &tls.version {
        parts.push(v.clone());
    } else {
        parts.push("TLS".into());
    }
    if let Some(a) = tls.alpn.first() {
        parts.push(a.clone());
    }
    parts.join(" · ")
}

/// Average packet size, when packet rates are known.
pub fn packet_size(rate: u64, pps: Option<u32>) -> Option<u64> {
    pps.filter(|p| *p > 0).map(|p| rate / u64::from(p))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_reason_reads_as_a_sentence() {
        for r in [
            Reason::KnownHost {
                domain: "googlevideo.com".into(),
            },
            Reason::PeriodicBursts {
                every_s: 4,
                peak: 2_000_000,
            },
            Reason::Sustained {
                download: true,
                rate: 300_000,
            },
            Reason::SmallSteadyPackets { pps: 50, size: 160 },
            Reason::ShortExchanges,
            Reason::WellKnownPort { port: 3478 },
            Reason::Protocol { alpn: "h2".into() },
            Reason::RadioProgram {
                program: "satdump".into(),
            },
            Reason::RadioPort {
                port: 1234,
                service: "rtl_tcp IQ stream".into(),
            },
            Reason::ConstantRate { rate: 2_400_000 },
        ] {
            let text = reason_text(&r);
            assert!(text.len() > 10 && !text.ends_with('.'), "{text}");
        }
        assert_eq!(packet_size(1500, Some(3)), Some(500));
        assert_eq!(packet_size(1500, Some(0)), None);
    }
}
