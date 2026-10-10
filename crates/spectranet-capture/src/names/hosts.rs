//! The static host table, `/etc/hosts` (hosts(5)).

use std::net::IpAddr;

/// Names that describe the machine itself or broadcast, not a remote peer.
const GENERIC: [&str; 4] = [
    "localhost",
    "broadcasthost",
    "ip6-localhost",
    "ip6-loopback",
];

/// Parses hosts-file text into `(name, address)` pairs, using each line's canonical (first)
/// name. Comments, malformed lines and generic loopback names are skipped.
pub fn parse(text: &str) -> Vec<(String, IpAddr)> {
    text.lines()
        .filter_map(|line| {
            let line = line.split('#').next()?;
            let mut fields = line.split_whitespace();
            let ip: IpAddr = fields.next()?.parse().ok()?;
            let name = fields.next()?.to_ascii_lowercase();
            let name = name.trim_end_matches('.').to_string();
            (super::dns::valid_hostname(&name) && !GENERIC.contains(&name.as_str()))
                .then_some((name, ip))
        })
        .collect()
}

#[cfg(windows)]
const HOSTS: &str = r"C:\Windows\System32\drivers\etc\hosts";
#[cfg(not(windows))]
const HOSTS: &str = "/etc/hosts";

/// Reads the system hosts file; an unreadable file simply contributes nothing.
pub fn load_system() -> Vec<(String, IpAddr)> {
    std::fs::read_to_string(HOSTS)
        .map(|text| parse(&text))
        .unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_typical_file() {
        let text = "\
##
# Host Database
127.0.0.1\tlocalhost
255.255.255.255\tbroadcasthost
::1             localhost
192.168.1.50    n95server n95 # home server
192.168.1.47\tTreeX-Win.lan.
fe80::1%lo0\tlocalhost
not-an-ip       something
10.0.0.9
10.0.0.10   bad\u{1b}name
";
        assert_eq!(
            parse(text),
            [
                ("n95server".to_string(), "192.168.1.50".parse().unwrap()),
                ("treex-win.lan".to_string(), "192.168.1.47".parse().unwrap()),
            ]
        );
    }

    #[test]
    fn empty_and_binary_input() {
        assert!(parse("").is_empty());
        assert!(parse("\0\0\0\n\u{feff}1.2.3.4 x").len() <= 1);
    }

    #[test]
    fn system_file_loads_without_error() {
        for (name, _) in load_system() {
            assert!(super::super::dns::valid_hostname(&name));
        }
    }
}
