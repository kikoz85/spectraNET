//! A compact set of IP addresses and networks with logarithmic lookup.

use std::net::IpAddr;

/// Sorted, merged, inclusive address ranges.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct IpSet {
    v4: Vec<(u32, u32)>,
    v6: Vec<(u128, u128)>,
}

impl IpSet {
    /// Parses a blocklist: one address or CIDR network per line, anything after the first
    /// whitespace or `;` ignored, lines starting with `#` or `;` skipped. Returns the set and
    /// the number of lines that were not understood.
    pub fn parse(text: &str) -> (Self, usize) {
        let mut v4 = Vec::new();
        let mut v6 = Vec::new();
        let mut rejected = 0;
        for line in text.lines() {
            let entry = line
                .split([';', '#'])
                .next()
                .unwrap_or("")
                .split_whitespace()
                .next();
            let Some(entry) = entry else { continue };
            match parse_entry(entry) {
                Some(Range::V4(a, b)) => v4.push((a, b)),
                Some(Range::V6(a, b)) => v6.push((a, b)),
                None => rejected += 1,
            }
        }
        (
            Self {
                v4: merge(v4),
                v6: merge(v6),
            },
            rejected,
        )
    }

    pub fn contains(&self, ip: IpAddr) -> bool {
        match canonical(ip) {
            IpAddr::V4(v4) => find(&self.v4, u32::from(v4)),
            IpAddr::V6(v6) => find(&self.v6, u128::from(v6)),
        }
    }

    /// Number of distinct ranges (after merging).
    pub fn len(&self) -> usize {
        self.v4.len() + self.v6.len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

enum Range {
    V4(u32, u32),
    V6(u128, u128),
}

fn parse_entry(entry: &str) -> Option<Range> {
    let (addr, prefix) = match entry.split_once('/') {
        Some((a, p)) => (a, Some(p.parse::<u32>().ok()?)),
        None => (entry, None),
    };
    match addr.parse::<IpAddr>().ok()? {
        IpAddr::V4(v4) => {
            let prefix = prefix.unwrap_or(32);
            if prefix > 32 {
                return None;
            }
            let mask = if prefix == 0 {
                0
            } else {
                u32::MAX << (32 - prefix)
            };
            let start = u32::from(v4) & mask;
            Some(Range::V4(start, start | !mask))
        }
        IpAddr::V6(v6) => {
            let prefix = prefix.unwrap_or(128);
            if prefix > 128 {
                return None;
            }
            let mask = if prefix == 0 {
                0
            } else {
                u128::MAX << (128 - prefix)
            };
            let start = u128::from(v6) & mask;
            Some(Range::V6(start, start | !mask))
        }
    }
}

fn merge<T: Ord + Copy + num::Step>(mut ranges: Vec<(T, T)>) -> Vec<(T, T)> {
    ranges.sort_unstable();
    let mut merged: Vec<(T, T)> = Vec::with_capacity(ranges.len());
    for (start, end) in ranges {
        match merged.last_mut() {
            Some(last) if start <= last.1.next_or_max() => {
                if end > last.1 {
                    last.1 = end;
                }
            }
            _ => merged.push((start, end)),
        }
    }
    merged
}

fn find<T: Ord + Copy>(ranges: &[(T, T)], value: T) -> bool {
    let i = ranges.partition_point(|(start, _)| *start <= value);
    i > 0 && value <= ranges[i - 1].1
}

fn canonical(ip: IpAddr) -> IpAddr {
    match ip {
        IpAddr::V6(v6) => v6.to_ipv4_mapped().map_or(ip, IpAddr::V4),
        v4 => v4,
    }
}

/// Successor without overflow, so adjacent ranges merge.
mod num {
    pub trait Step {
        fn next_or_max(self) -> Self;
    }
    impl Step for u32 {
        fn next_or_max(self) -> Self {
            self.saturating_add(1)
        }
    }
    impl Step for u128 {
        fn next_or_max(self) -> Self {
            self.saturating_add(1)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    #[test]
    fn parses_real_feed_formats() {
        let text = "\
# abuse.ch Feodo Tracker
162.243.103.246
; Spamhaus DROP
1.10.16.0/20 ; SBL256894
2001:678:254::/48 ; SBL697648
   185.220.101.5
not-an-ip
10.0.0.0/33
";
        let (set, rejected) = IpSet::parse(text);
        assert_eq!(rejected, 2);
        assert_eq!(set.len(), 4);
        assert!(set.contains(ip("162.243.103.246")));
        assert!(!set.contains(ip("162.243.103.247")));
        assert!(set.contains(ip("1.10.16.0")) && set.contains(ip("1.10.31.255")));
        assert!(!set.contains(ip("1.10.32.0")) && !set.contains(ip("1.10.15.255")));
        assert!(set.contains(ip("2001:678:254:ffff::1")));
        assert!(!set.contains(ip("2001:678:255::1")));
        assert!(
            set.contains(ip("::ffff:185.220.101.5")),
            "IPv4-mapped form matches"
        );
    }

    #[test]
    fn overlapping_and_adjacent_ranges_merge() {
        let (set, _) = IpSet::parse("10.0.0.0/24\n10.0.1.0/24\n10.0.0.128/25\n10.0.3.7\n");
        assert_eq!(set.len(), 2);
        assert!(set.contains(ip("10.0.1.255")));
        assert!(!set.contains(ip("10.0.2.0")));
    }

    #[test]
    fn extremes() {
        let (set, _) = IpSet::parse("0.0.0.0/0\n");
        assert!(set.contains(ip("255.255.255.255")) && set.contains(ip("0.0.0.0")));
        let (set, _) = IpSet::parse("255.255.255.255\n::/0\n");
        assert!(set.contains(ip("255.255.255.255")));
        assert!(set.contains(ip("ffff::1")));
        let (empty, _) = IpSet::parse("");
        assert!(empty.is_empty() && !empty.contains(ip("1.2.3.4")));
    }

    #[test]
    fn host_bits_in_cidr_are_ignored() {
        let (set, _) = IpSet::parse("192.168.1.77/24\n");
        assert!(set.contains(ip("192.168.1.1")));
    }

    #[test]
    fn matches_linear_scan_on_random_data() {
        let mut state = 0x1234_5678u64;
        let mut next = || {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            state
        };
        let mut lines = String::new();
        let mut ranges = Vec::new();
        for _ in 0..500 {
            let base = (next() as u32) & 0x00FF_FFFF; // dense low space to force overlaps
            let prefix = 16 + (next() % 17) as u32;
            lines.push_str(&format!("{}/{prefix}\n", Ipv4Addr::from(base)));
            let mask = u32::MAX << (32 - prefix);
            ranges.push((base & mask, (base & mask) | !mask));
        }
        let (set, _) = IpSet::parse(&lines);
        for _ in 0..20_000 {
            let probe = (next() as u32) & 0x01FF_FFFF;
            let expected = ranges.iter().any(|(a, b)| *a <= probe && probe <= *b);
            assert_eq!(
                set.contains(IpAddr::V4(Ipv4Addr::from(probe))),
                expected,
                "{probe}"
            );
        }
    }
}
