//! Human-readable formatting of byte counts and rates (IEC units: KiB = 1024 B).

const UNITS: [&str; 5] = ["B", "KiB", "MiB", "GiB", "TiB"];

/// Formats a byte count, e.g. `1536` → `1.5 KiB`.
pub fn bytes(n: u64) -> String {
    let mut value = n as f64;
    let mut unit = 0;
    while value >= 1024.0 && unit < UNITS.len() - 1 {
        value /= 1024.0;
        unit += 1;
    }
    if unit == 0 {
        format!("{n} B")
    } else if value < 10.0 {
        format!("{value:.1} {}", UNITS[unit])
    } else {
        format!("{value:.0} {}", UNITS[unit])
    }
}

/// Formats a rate in bytes per second, e.g. `2048` → `2.0 KiB/s`.
pub fn rate(bytes_per_sec: u64) -> String {
    format!("{}/s", bytes(bytes_per_sec))
}

/// Shortens `text` to at most `max` characters, marking the cut with `…`.
pub fn truncate(text: &str, max: usize) -> String {
    if text.chars().count() <= max {
        return text.to_string();
    }
    let kept: String = text.chars().take(max.saturating_sub(1)).collect();
    format!("{kept}…")
}

/// Shortens `text` to at most `max` characters by cutting from the left, marking the cut
/// with `…`. Used for hostnames, whose most telling part is the end (`…googlevideo.com:443`).
pub fn truncate_left(text: &str, max: usize) -> String {
    let len = text.chars().count();
    if len <= max {
        return text.to_string();
    }
    let kept: String = text.chars().skip(len - max.saturating_sub(1)).collect();
    format!("…{kept}")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn formats_bytes() {
        assert_eq!(bytes(0), "0 B");
        assert_eq!(bytes(1023), "1023 B");
        assert_eq!(bytes(1536), "1.5 KiB");
        assert_eq!(bytes(300 * 1024), "300 KiB");
        assert_eq!(bytes(5 * 1024 * 1024 * 1024), "5.0 GiB");
    }

    #[test]
    fn formats_rates() {
        assert_eq!(rate(2048), "2.0 KiB/s");
    }

    #[test]
    fn truncates_by_characters() {
        assert_eq!(truncate("short", 10), "short");
        assert_eq!(truncate("a very long name", 6), "a ver…");
        assert_eq!(truncate("città", 4), "cit…");
    }

    #[test]
    fn truncates_hostnames_from_the_left() {
        let host = "rr1---sn-upnj5appu5-hm2l.googlevideo.com:443";
        let cut = truncate_left(host, 32);
        assert_eq!(cut.chars().count(), 32);
        assert!(
            cut.starts_with('…') && cut.ends_with("googlevideo.com:443"),
            "{cut}"
        );
        assert_eq!(truncate_left("short:443", 32), "short:443");
        assert_eq!(truncate_left("abc", 1), "…");
    }
}
