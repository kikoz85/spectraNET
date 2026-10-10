//! Software-defined radio and satellite reception: which programs and ports they use, and
//! what their connections carry.
//!
//! As for every classification, only names, ports and the shape of the traffic are used:
//! no IQ sample, audio or image is ever read.

use spectranet_model::Transport;
use spectranet_model::flowmeta::Kind;

/// Radio programs and the kind of traffic they typically produce when the pattern alone does
/// not decide (a decoder uploads telemetry, a receiver streams samples or audio).
const PROGRAMS: &[(&str, Kind)] = &[
    // Satellite and aircraft decoders.
    ("satdump", Kind::Telemetry),
    ("wxtoimg", Kind::Telemetry),
    ("noaa-apt", Kind::Telemetry),
    ("satnogs-client", Kind::Telemetry),
    ("gpredict", Kind::Telemetry),
    ("dump1090", Kind::Telemetry),
    ("dump1090-fa", Kind::Telemetry),
    ("readsb", Kind::Telemetry),
    ("rtl_433", Kind::Telemetry),
    ("multimon-ng", Kind::Telemetry),
    // Digital modes.
    ("wsjtx", Kind::DigitalModes),
    ("wsjt-x", Kind::DigitalModes),
    ("jtdx", Kind::DigitalModes),
    ("js8call", Kind::DigitalModes),
    ("fldigi", Kind::DigitalModes),
    ("direwolf", Kind::DigitalModes),
    ("gridtracker", Kind::DigitalModes),
    ("jtalert", Kind::DigitalModes),
    ("qsstv", Kind::DigitalModes),
    ("jnx", Kind::DigitalModes),
    // Web receivers.
    ("openwebrx", Kind::WebSdr),
    ("kiwirecorder", Kind::WebSdr),
    // Receivers and SDR back ends: samples or audio, decided by the rate.
    ("rtl_tcp", Kind::RawIq),
    ("rtl_sdr", Kind::RawIq),
    ("rtl_fm", Kind::RadioAudio),
    ("rtlsdr", Kind::RawIq),
    ("spyserver", Kind::RawIq),
    ("sdrpp", Kind::RawIq),
    ("sdr++", Kind::RawIq),
    ("gqrx", Kind::RawIq),
    ("cubicsdr", Kind::RawIq),
    ("sdrangel", Kind::RawIq),
    ("sdrsharp", Kind::RawIq),
    ("sdr#", Kind::RawIq),
    ("sdruno", Kind::RawIq),
    ("hdsdr", Kind::RawIq),
    ("linrad", Kind::RawIq),
    ("soapysdrserver", Kind::RawIq),
    ("hackrf_transfer", Kind::RawIq),
    ("gnuradio-companion", Kind::RawIq),
    ("gnuradio", Kind::RawIq),
];

/// The radio program a process is, if any, with its usual kind of traffic. Matches the
/// process name or its file, without case or `.exe`.
pub fn program(name: &str) -> Option<(&'static str, Kind)> {
    let lower = name.to_lowercase();
    let lower = lower.strip_suffix(".exe").unwrap_or(&lower);
    let lower = lower.rsplit(['/', '\\']).next().unwrap_or(lower);
    PROGRAMS
        .iter()
        .find(|(p, _)| {
            lower == *p
                || lower.starts_with(&format!("{p} "))
                || lower.starts_with(&format!("{p}-"))
        })
        .map(|(p, k)| (*p, *k))
}

/// How much a port says on its own.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PortTrust {
    /// Distinctive enough to classify alone.
    Alone,
    /// Shared with unrelated software (5555 is also Android's ADB, 1234 is everywhere): only
    /// with a radio program or a radio-like pattern.
    WithEvidence,
}

/// Ports of radio services: (transport, port, kind, service name, trust).
const PORTS: &[(Option<Transport>, u16, Kind, &str, PortTrust)] = &[
    (
        None,
        1234,
        Kind::RawIq,
        "rtl_tcp IQ stream",
        PortTrust::WithEvidence,
    ),
    (
        Some(Transport::Tcp),
        5555,
        Kind::RawIq,
        "SpyServer",
        PortTrust::WithEvidence,
    ),
    (
        Some(Transport::Tcp),
        8073,
        Kind::WebSdr,
        "OpenWebRX / KiwiSDR",
        PortTrust::Alone,
    ),
    (
        Some(Transport::Udp),
        2237,
        Kind::DigitalModes,
        "WSJT-X",
        PortTrust::Alone,
    ),
    (
        Some(Transport::Udp),
        2238,
        Kind::DigitalModes,
        "WSJT-X / JTDX",
        PortTrust::Alone,
    ),
    (
        Some(Transport::Tcp),
        14580,
        Kind::DigitalModes,
        "APRS-IS",
        PortTrust::Alone,
    ),
    (
        Some(Transport::Udp),
        4739,
        Kind::DigitalModes,
        "PSK Reporter",
        PortTrust::Alone,
    ),
    (
        Some(Transport::Tcp),
        30003,
        Kind::Telemetry,
        "ADS-B (SBS)",
        PortTrust::WithEvidence,
    ),
    (
        Some(Transport::Tcp),
        30005,
        Kind::Telemetry,
        "ADS-B (Beast)",
        PortTrust::WithEvidence,
    ),
];

/// The radio service behind a connection's ports (either end: a local server counts too).
pub fn port(
    transport: Transport,
    local: u16,
    remote: u16,
) -> Option<(u16, Kind, &'static str, PortTrust)> {
    PORTS.iter().find_map(|(t, p, k, name, trust)| {
        let transport_ok = t.is_none_or(|t| t == transport);
        (transport_ok && (*p == remote || *p == local)).then_some((*p, *k, *name, *trust))
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn programs_are_recognised_by_name_or_file() {
        assert_eq!(program("satdump").map(|p| p.1), Some(Kind::Telemetry));
        assert_eq!(program("SatDump.exe").map(|p| p.1), Some(Kind::Telemetry));
        assert_eq!(program("/usr/bin/rtl_tcp").map(|p| p.0), Some("rtl_tcp"));
        assert_eq!(program("WSJT-X").map(|p| p.1), Some(Kind::DigitalModes));
        assert_eq!(program("sdrpp").map(|p| p.1), Some(Kind::RawIq));
        assert_eq!(program("gqrx"), Some(("gqrx", Kind::RawIq)));
        assert_eq!(program("chrome"), None);
        assert_eq!(program("satdumpster"), None, "whole names only");
    }

    #[test]
    fn ports_say_how_much_they_can_be_trusted() {
        assert_eq!(
            port(Transport::Tcp, 50000, 8073).map(|p| (p.1, p.3)),
            Some((Kind::WebSdr, PortTrust::Alone))
        );
        assert_eq!(
            port(Transport::Tcp, 5555, 50000).map(|p| p.3),
            Some(PortTrust::WithEvidence),
            "a local server counts, and ADB shares 5555"
        );
        assert!(
            port(Transport::Tcp, 50000, 2237).is_none(),
            "WSJT-X speaks UDP"
        );
        assert_eq!(
            port(Transport::Udp, 50000, 1234).map(|p| p.1),
            Some(Kind::RawIq)
        );
    }
}
