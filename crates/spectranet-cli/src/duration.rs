//! Parsing of human-friendly durations such as `500ms`, `2s` or `1m`.

use std::time::Duration;

/// Parses `<number><unit>` where unit is `ms`, `s`, `m` or `h`. A bare number means seconds.
pub fn parse_duration(input: &str) -> Result<Duration, String> {
    let input = input.trim();
    let split = input
        .find(|c: char| !(c.is_ascii_digit() || c == '.'))
        .unwrap_or(input.len());
    let (number, unit) = input.split_at(split);
    let value: f64 = number
        .parse()
        .map_err(|_| format!("invalid duration '{input}'"))?;
    let seconds = match unit {
        "ms" => value / 1000.0,
        "" | "s" => value,
        "m" => value * 60.0,
        "h" => value * 3600.0,
        _ => {
            return Err(format!(
                "unknown unit '{unit}' in '{input}' (use ms, s, m or h)"
            ));
        }
    };
    if seconds <= 0.0 {
        return Err("duration must be greater than zero".into());
    }
    Ok(Duration::from_secs_f64(seconds))
}

/// Like [`parse_duration`], plus days (`7d`), for look-back windows.
pub fn parse_age(input: &str) -> Result<Duration, String> {
    match input.trim().strip_suffix('d') {
        Some(days) => {
            let days: f64 = days
                .parse()
                .map_err(|_| format!("invalid duration '{input}'"))?;
            if days <= 0.0 || days > 3660.0 {
                return Err("days must be between 0 and 3660".into());
            }
            Ok(Duration::from_secs_f64(days * 86_400.0))
        }
        None => parse_duration(input),
    }
}

/// How long a block lasts: a duration with days allowed, or `forever` (until lifted, 0).
pub fn parse_block_for(input: &str) -> Result<u64, String> {
    match input.trim().to_lowercase().as_str() {
        "forever" | "always" | "0" => Ok(0),
        other => parse_age(other).map(|d| d.as_secs().max(1)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn block_lengths() {
        assert_eq!(parse_block_for("15m"), Ok(900));
        assert_eq!(parse_block_for("2d"), Ok(172_800));
        assert_eq!(parse_block_for("forever"), Ok(0));
        assert!(parse_block_for("soon").is_err());
    }

    #[test]
    fn parses_units() {
        assert_eq!(parse_duration("500ms"), Ok(Duration::from_millis(500)));
        assert_eq!(parse_duration("2s"), Ok(Duration::from_secs(2)));
        assert_eq!(parse_duration("3"), Ok(Duration::from_secs(3)));
        assert_eq!(parse_duration("1.5m"), Ok(Duration::from_secs(90)));
        assert_eq!(parse_duration("1h"), Ok(Duration::from_secs(3600)));
    }

    #[test]
    fn ages_accept_days() {
        assert_eq!(parse_age("7d"), Ok(Duration::from_secs(7 * 86_400)));
        assert_eq!(parse_age("24h"), Ok(Duration::from_secs(86_400)));
        assert!(parse_age("0d").is_err());
        assert!(parse_age("99999d").is_err());
        assert!(parse_age("d").is_err());
    }

    #[test]
    fn rejects_garbage() {
        assert!(parse_duration("").is_err());
        assert!(parse_duration("fast").is_err());
        assert!(parse_duration("5 parsecs").is_err());
        assert!(parse_duration("0s").is_err());
    }
}
