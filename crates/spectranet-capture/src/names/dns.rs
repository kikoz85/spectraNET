//! Minimal, defensive parser for DNS responses (RFC 1035): extracts which addresses a
//! queried hostname resolved to.
//!
//! Only what spectraNET needs is decoded: the question name and the A/AAAA records of the
//! answer section. Every length and offset is bounds-checked; malformed input yields `None`,
//! never a panic. Hostnames are validated so that nothing but hostname characters can ever
//! reach a terminal.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

const HEADER_LEN: usize = 12;
const MAX_NAME_LEN: usize = 253;
const MAX_POINTER_JUMPS: usize = 16;
const TYPE_A: u16 = 1;
const TYPE_AAAA: u16 = 28;
const TYPE_PTR: u16 = 12;
const CLASS_IN: u16 = 1;

/// The useful content of a successful DNS response.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Resolution {
    /// The name that was asked for (lowercase), e.g. `www.youtube.com` — not the CNAME target,
    /// because that is the name the user recognises.
    pub name: String,
    /// Addresses the name resolved to (A and AAAA records in the answer section).
    pub addrs: Vec<IpAddr>,
}

/// Parses a DNS message. Returns `None` unless it is a successful response to a single
/// question that carries at least one address.
pub fn parse_response(msg: &[u8]) -> Option<Resolution> {
    let header = msg.get(..HEADER_LEN)?;
    let flags = u16::from_be_bytes([header[2], header[3]]);
    let is_response = flags & 0x8000 != 0;
    let opcode = (flags >> 11) & 0xF;
    let rcode = flags & 0xF;
    let questions = u16::from_be_bytes([header[4], header[5]]);
    let answers = u16::from_be_bytes([header[6], header[7]]);
    if !is_response || opcode != 0 || rcode != 0 || questions != 1 || answers == 0 {
        return None;
    }

    let (name, mut pos) = read_name(msg, HEADER_LEN)?;
    pos = pos.checked_add(4)?; // QTYPE + QCLASS
    if pos > msg.len() {
        return None;
    }

    let mut addrs = Vec::new();
    for _ in 0..answers {
        let (_, after_name) = read_name(msg, pos)?;
        let fixed = msg.get(after_name..after_name.checked_add(10)?)?;
        let rtype = u16::from_be_bytes([fixed[0], fixed[1]]);
        let class = u16::from_be_bytes([fixed[2], fixed[3]]);
        let rdlen = usize::from(u16::from_be_bytes([fixed[8], fixed[9]]));
        let rdata_start = after_name + 10;
        let rdata = msg.get(rdata_start..rdata_start.checked_add(rdlen)?)?;
        if class == CLASS_IN {
            match (rtype, rdata.len()) {
                (TYPE_A, 4) => addrs.push(IpAddr::V4(Ipv4Addr::new(
                    rdata[0], rdata[1], rdata[2], rdata[3],
                ))),
                (TYPE_AAAA, 16) => {
                    let octets: [u8; 16] = rdata.try_into().ok()?;
                    addrs.push(IpAddr::V6(Ipv6Addr::from(octets)));
                }
                _ => {}
            }
        }
        pos = rdata_start + rdlen;
    }

    (!addrs.is_empty()).then_some(Resolution { name, addrs })
}

/// Parses a multicast DNS (Bonjour, RFC 6762) response: every A/AAAA record it carries,
/// in the answer *and* additional sections, as `(hostname, address)`. Devices announce
/// themselves this way (e.g. `n95server.local`), without anyone asking.
pub fn parse_mdns(msg: &[u8]) -> Vec<(String, IpAddr)> {
    parse_mdns_inner(msg).unwrap_or_default()
}

fn parse_mdns_inner(msg: &[u8]) -> Option<Vec<(String, IpAddr)>> {
    let header = msg.get(..HEADER_LEN)?;
    let flags = u16::from_be_bytes([header[2], header[3]]);
    if flags & 0x8000 == 0 || (flags >> 11) & 0xF != 0 {
        return None;
    }
    let count = |i: usize| u16::from_be_bytes([header[i], header[i + 1]]);
    let (questions, records) = (
        count(4),
        u32::from(count(6)) + u32::from(count(8)) + u32::from(count(10)),
    );
    let mut pos = HEADER_LEN;
    for _ in 0..questions {
        let (_, after) = read_name(msg, pos)?;
        pos = after.checked_add(4)?;
    }
    let mut found = Vec::new();
    for _ in 0..records {
        let (owner, after_name) = match read_name(msg, pos) {
            Some(v) => (Some(v.0), v.1),
            // Service-instance names may contain spaces etc.; skip the record, not the packet.
            None => (None, skip_name(msg, pos)?),
        };
        let fixed = msg.get(after_name..after_name.checked_add(10)?)?;
        let rtype = u16::from_be_bytes([fixed[0], fixed[1]]);
        let class = u16::from_be_bytes([fixed[2], fixed[3]]) & 0x7FFF; // top bit: cache-flush
        let rdlen = usize::from(u16::from_be_bytes([fixed[8], fixed[9]]));
        let rdata_start = after_name + 10;
        let rdata = msg.get(rdata_start..rdata_start.checked_add(rdlen)?)?;
        if let (Some(owner), CLASS_IN) = (owner, class) {
            let addr = match (rtype, rdata.len()) {
                (TYPE_A, 4) => Some(IpAddr::V4(Ipv4Addr::new(
                    rdata[0], rdata[1], rdata[2], rdata[3],
                ))),
                (TYPE_AAAA, 16) => <[u8; 16]>::try_from(rdata)
                    .ok()
                    .map(|o| IpAddr::V6(Ipv6Addr::from(o))),
                _ => None,
            };
            if let Some(addr) = addr {
                found.push((owner, addr));
            }
        }
        pos = rdata_start + rdlen;
    }
    Some(found)
}

/// Skips over a name without validating its characters; returns the offset after it.
fn skip_name(msg: &[u8], mut pos: usize) -> Option<usize> {
    loop {
        let len = *msg.get(pos)?;
        match len & 0xC0 {
            0x00 if len == 0 => return Some(pos + 1),
            0x00 => pos += 1 + usize::from(len),
            0xC0 => {
                msg.get(pos + 1)?;
                return Some(pos + 2);
            }
            _ => return None,
        }
    }
}

/// The reverse-lookup name for an address: `4.3.2.1.in-addr.arpa` or the nibble form under
/// `ip6.arpa`.
pub fn reverse_name(ip: IpAddr) -> String {
    match ip {
        IpAddr::V4(v4) => {
            let [a, b, c, d] = v4.octets();
            format!("{d}.{c}.{b}.{a}.in-addr.arpa")
        }
        IpAddr::V6(v6) => {
            let mut name = String::with_capacity(72);
            for byte in v6.octets().iter().rev() {
                name.push_str(&format!("{:x}.{:x}.", byte & 0x0F, byte >> 4));
            }
            name.push_str("ip6.arpa");
            name
        }
    }
}

/// Encodes a PTR query for `name`. `recursion` sets RD (unicast DNS); mDNS leaves it clear.
pub fn ptr_query(id: u16, name: &str, recursion: bool) -> Vec<u8> {
    let mut msg = Vec::with_capacity(HEADER_LEN + name.len() + 6);
    msg.extend_from_slice(&id.to_be_bytes());
    msg.extend_from_slice(if recursion {
        &[0x01, 0x00]
    } else {
        &[0x00, 0x00]
    });
    msg.extend_from_slice(&[0, 1, 0, 0, 0, 0, 0, 0]);
    for label in name.split('.') {
        msg.push(label.len() as u8);
        msg.extend_from_slice(label.as_bytes());
    }
    msg.push(0);
    msg.extend_from_slice(&TYPE_PTR.to_be_bytes());
    msg.extend_from_slice(&CLASS_IN.to_be_bytes());
    msg
}

/// Extracts the hostname from a response to [`ptr_query`]`(id, name, _)`.
/// The ID must match and the answer must be a PTR record owned by `name`.
pub fn parse_ptr(msg: &[u8], id: u16, name: &str) -> Option<String> {
    let header = msg.get(..HEADER_LEN)?;
    let flags = u16::from_be_bytes([header[2], header[3]]);
    if u16::from_be_bytes([header[0], header[1]]) != id || flags & 0x8000 == 0 || flags & 0xF != 0 {
        return None;
    }
    let questions = u16::from_be_bytes([header[4], header[5]]);
    let answers = u16::from_be_bytes([header[6], header[7]]);
    let mut pos = HEADER_LEN;
    for _ in 0..questions {
        pos = skip_name(msg, pos)?.checked_add(4)?;
    }
    for _ in 0..answers {
        let owner = read_name(msg, pos);
        let after_name = match &owner {
            Some((_, after)) => *after,
            None => skip_name(msg, pos)?,
        };
        let fixed = msg.get(after_name..after_name.checked_add(10)?)?;
        let rtype = u16::from_be_bytes([fixed[0], fixed[1]]);
        let class = u16::from_be_bytes([fixed[2], fixed[3]]) & 0x7FFF;
        let rdlen = usize::from(u16::from_be_bytes([fixed[8], fixed[9]]));
        let rdata_start = after_name + 10;
        msg.get(rdata_start..rdata_start.checked_add(rdlen)?)?;
        if rtype == TYPE_PTR
            && class == CLASS_IN
            && owner.is_some_and(|(o, _)| o == name)
            && let Some((target, _)) = read_name(msg, rdata_start)
        {
            return Some(target);
        }
        pos = rdata_start + rdlen;
    }
    None
}

/// Reads a possibly compressed domain name starting at `start`.
/// Returns the validated lowercase name and the offset just past it in the original stream.
fn read_name(msg: &[u8], start: usize) -> Option<(String, usize)> {
    let mut name = String::new();
    let mut pos = start;
    let mut end_of_name = None;
    let mut jumps = 0;
    // Start of the span being read since the last jump. Every pointer must land strictly
    // before it, so successive jumps move strictly backwards and loops are impossible.
    let mut segment_start = start;
    loop {
        let len = *msg.get(pos)?;
        match len & 0xC0 {
            0x00 if len == 0 => {
                let end = end_of_name.unwrap_or(pos + 1);
                return valid_hostname(&name).then_some((name, end));
            }
            0x00 => {
                let label = msg.get(pos + 1..pos + 1 + usize::from(len))?;
                if !name.is_empty() {
                    name.push('.');
                }
                for &b in label {
                    name.push(char::from(b.to_ascii_lowercase()));
                }
                if name.len() > MAX_NAME_LEN {
                    return None;
                }
                pos += 1 + usize::from(len);
            }
            0xC0 => {
                let target = usize::from(u16::from_be_bytes([len & 0x3F, *msg.get(pos + 1)?]));
                if target >= segment_start {
                    return None;
                }
                jumps += 1;
                if jumps > MAX_POINTER_JUMPS {
                    return None;
                }
                end_of_name.get_or_insert(pos + 2);
                pos = target;
                segment_start = target;
            }
            _ => return None, // 0x40 / 0x80: obsolete or reserved label types
        }
    }
}

/// Accepts `[a-z0-9-_]` labels of 1–63 characters separated by dots.
pub fn valid_hostname(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= MAX_NAME_LEN
        && name.split('.').all(|label| {
            !label.is_empty()
                && label.len() <= 63
                && label
                    .bytes()
                    .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-' || b == b'_')
        })
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    /// Builds a DNS response for `question` with the given answer records.
    /// Each record is `(owner, type, rdata)`; owners equal to the question are compressed.
    pub(crate) fn response(question: &str, records: &[(&str, u16, Vec<u8>)]) -> Vec<u8> {
        let mut msg = vec![0x12, 0x34, 0x81, 0x80, 0, 1];
        msg.extend_from_slice(&(records.len() as u16).to_be_bytes());
        msg.extend_from_slice(&[0, 0, 0, 0]);
        encode_name(&mut msg, question);
        msg.extend_from_slice(&[0, 1, 0, 1]);
        for (owner, rtype, rdata) in records {
            if *owner == question {
                msg.extend_from_slice(&[0xC0, 12]);
            } else {
                encode_name(&mut msg, owner);
            }
            msg.extend_from_slice(&rtype.to_be_bytes());
            msg.extend_from_slice(&[0, 1, 0, 0, 0x0E, 0x10]);
            msg.extend_from_slice(&(rdata.len() as u16).to_be_bytes());
            msg.extend_from_slice(rdata);
        }
        msg
    }

    fn encode_name(out: &mut Vec<u8>, name: &str) {
        for label in name.split('.') {
            out.push(label.len() as u8);
            out.extend_from_slice(label.as_bytes());
        }
        out.push(0);
    }

    fn name_rdata(name: &str) -> Vec<u8> {
        let mut v = Vec::new();
        encode_name(&mut v, name);
        v
    }

    #[test]
    fn a_record() {
        let msg = response(
            "example.com",
            &[("example.com", TYPE_A, vec![93, 184, 216, 34])],
        );
        assert_eq!(
            parse_response(&msg),
            Some(Resolution {
                name: "example.com".into(),
                addrs: vec!["93.184.216.34".parse().unwrap()],
            })
        );
    }

    #[test]
    fn cname_chain_maps_to_the_question() {
        let target = "youtube-ui.l.google.com";
        let msg = response(
            "www.youtube.com",
            &[
                ("www.youtube.com", 5, name_rdata(target)),
                (target, TYPE_A, vec![142, 250, 180, 14]),
                (target, TYPE_A, vec![142, 250, 180, 46]),
            ],
        );
        let r = parse_response(&msg).unwrap();
        assert_eq!(r.name, "www.youtube.com");
        assert_eq!(r.addrs.len(), 2);
    }

    #[test]
    fn aaaa_record_and_uppercase_name() {
        let ip: Ipv6Addr = "2a00:1450:4002:402::200e".parse().unwrap();
        let msg = response(
            "WWW.Google.COM",
            &[("WWW.Google.COM", TYPE_AAAA, ip.octets().to_vec())],
        );
        let r = parse_response(&msg).unwrap();
        assert_eq!(r.name, "www.google.com");
        assert_eq!(r.addrs, [IpAddr::V6(ip)]);
    }

    #[test]
    fn ignores_queries_errors_and_addressless_answers() {
        let mut query = response("example.com", &[("example.com", TYPE_A, vec![1, 2, 3, 4])]);
        query[2] &= 0x7F; // clear QR
        assert_eq!(parse_response(&query), None);

        let mut nxdomain = response("example.com", &[("example.com", TYPE_A, vec![1, 2, 3, 4])]);
        nxdomain[3] |= 3;
        assert_eq!(parse_response(&nxdomain), None);

        let txt_only = response("example.com", &[("example.com", 16, b"\x05hello".to_vec())]);
        assert_eq!(parse_response(&txt_only), None);

        let wrong_len = response("example.com", &[("example.com", TYPE_A, vec![1, 2, 3])]);
        assert_eq!(parse_response(&wrong_len), None);
    }

    #[test]
    fn rejects_truncation_at_every_length() {
        let msg = response("example.com", &[("example.com", TYPE_A, vec![1, 2, 3, 4])]);
        for len in 0..msg.len() {
            assert_eq!(parse_response(&msg[..len]), None, "truncated to {len}");
        }
        assert!(parse_response(&msg).is_some());
    }

    #[test]
    fn rejects_pointer_loops_and_forward_pointers() {
        // Question name is a pointer to itself.
        let mut msg = vec![0, 0, 0x81, 0x80, 0, 1, 0, 1, 0, 0, 0, 0, 0xC0, 12];
        msg.extend_from_slice(&[0, 1, 0, 1]);
        assert_eq!(parse_response(&msg), None);
        // Pointer to a later offset.
        msg[13] = 40;
        assert_eq!(parse_response(&msg), None);

        // A label followed by a pointer back to that same label: "a.a.a.a..." forever.
        let mut msg = vec![0, 0, 0x81, 0x80, 0, 1, 0, 1, 0, 0, 0, 0, 1, b'a', 0xC0, 12];
        msg.extend_from_slice(&[0, 1, 0, 1]);
        assert_eq!(parse_response(&msg), None);
    }

    #[test]
    fn rejects_hostile_names() {
        for bad in [
            "evil\u{1b}[31m.com",
            "a b.com",
            "under\0score.com",
            "dot..dot",
            "ünï.com",
        ] {
            let mut msg = vec![0, 0, 0x81, 0x80, 0, 1, 0, 1, 0, 0, 0, 0];
            for label in bad.split('.') {
                msg.push(label.len() as u8);
                msg.extend_from_slice(label.as_bytes());
            }
            msg.extend_from_slice(&[
                0, 0, 1, 0, 1, 0xC0, 12, 0, 1, 0, 1, 0, 0, 0, 1, 0, 4, 1, 2, 3, 4,
            ]);
            assert_eq!(parse_response(&msg), None, "{bad:?}");
        }
    }

    #[test]
    fn rejects_overlong_names() {
        let long = vec!["a".repeat(63); 5].join(".");
        let msg = response(&long, &[(&long, TYPE_A, vec![1, 2, 3, 4])]);
        assert_eq!(parse_response(&msg), None);
    }

    #[test]
    fn hostname_validation() {
        assert!(valid_hostname("a-b_c.example.com"));
        assert!(!valid_hostname(""));
        assert!(!valid_hostname("-.."));
        assert!(!valid_hostname(&"a".repeat(64)));
        assert!(!valid_hostname("UPPER.com"), "callers lowercase first");
    }

    /// Builds an unsolicited mDNS announcement: no questions, the given answers, plus an
    /// additional AAAA record, and a PTR record with a service name containing a space.
    fn mdns_announcement(host: &str, v4: [u8; 4], v6: Ipv6Addr) -> Vec<u8> {
        let mut msg = vec![0, 0, 0x84, 0x00, 0, 0, 0, 2, 0, 0, 0, 1];
        // PTR "My Server._smb._tcp.local" -> host (owner has a space: must be skipped, not fatal)
        for label in ["My Server", "_smb", "_tcp", "local"] {
            msg.push(label.len() as u8);
            msg.extend_from_slice(label.as_bytes());
        }
        msg.push(0);
        let target = name_rdata(host);
        msg.extend_from_slice(&[0, 12, 0x80, 1, 0, 0, 0x11, 0x94]);
        msg.extend_from_slice(&(target.len() as u16).to_be_bytes());
        let host_at = msg.len();
        msg.extend_from_slice(&target);
        // A record whose owner is a pointer to the host name inside the PTR rdata.
        msg.extend_from_slice(&[0xC0, host_at as u8, 0, 1, 0x80, 1, 0, 0, 0, 120, 0, 4]);
        msg.extend_from_slice(&v4);
        // Additional AAAA, same owner.
        msg.extend_from_slice(&[0xC0, host_at as u8, 0, 28, 0x80, 1, 0, 0, 0, 120, 0, 16]);
        msg.extend_from_slice(&v6.octets());
        msg
    }

    #[test]
    fn mdns_announcement_names_lan_hosts() {
        let v6: Ipv6Addr = "fe80::1c2b:3a4d:5e6f:7081".parse().unwrap();
        let msg = mdns_announcement("n95server.local", [192, 168, 1, 50], v6);
        let found = parse_mdns(&msg);
        assert_eq!(
            found,
            [
                (
                    "n95server.local".to_string(),
                    IpAddr::V4(Ipv4Addr::new(192, 168, 1, 50))
                ),
                ("n95server.local".to_string(), IpAddr::V6(v6)),
            ]
        );
    }

    #[test]
    fn mdns_queries_and_truncation_yield_nothing() {
        let msg = mdns_announcement("host.local", [10, 0, 0, 2], Ipv6Addr::LOCALHOST);
        let mut query = msg.clone();
        query[2] = 0;
        assert!(parse_mdns(&query).is_empty());
        for len in 0..msg.len() {
            assert!(parse_mdns(&msg[..len]).len() <= 2, "truncated to {len}");
        }
        assert!(
            parse_mdns(&msg[..msg.len() - 1]).is_empty(),
            "a cut record invalidates the packet"
        );
    }

    #[test]
    fn mdns_survives_random_corruption() {
        let base = mdns_announcement("n95server.local", [192, 168, 1, 50], Ipv6Addr::LOCALHOST);
        let mut state = 0x1234_5678_9ABC_DEF1u64;
        for _ in 0..30_000 {
            let mut msg = base.clone();
            for _ in 0..4 {
                state ^= state << 13;
                state ^= state >> 7;
                state ^= state << 17;
                let i = (state as usize) % msg.len();
                msg[i] = (state >> 24) as u8;
            }
            for (name, _) in parse_mdns(&msg) {
                assert!(valid_hostname(&name), "{name:?}");
            }
        }
    }

    /// A PTR response to `query` pointing at `target`, owner compressed to the question.
    pub(crate) fn ptr_response(query: &[u8], target: &str) -> Vec<u8> {
        let mut msg = query.to_vec();
        msg[2] |= 0x84; // QR + AA
        msg[7] = 1; // one answer
        msg.extend_from_slice(&[0xC0, 12, 0, 12, 0, 1, 0, 0, 0, 120]);
        let rdata = name_rdata(target);
        msg.extend_from_slice(&(rdata.len() as u16).to_be_bytes());
        msg.extend_from_slice(&rdata);
        msg
    }

    #[test]
    fn reverse_names() {
        assert_eq!(
            reverse_name("192.168.1.50".parse().unwrap()),
            "50.1.168.192.in-addr.arpa"
        );
        let v6 = reverse_name("2001:db8::567:89ab".parse().unwrap());
        assert_eq!(
            v6,
            "b.a.9.8.7.6.5.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.8.b.d.0.1.0.0.2.ip6.arpa"
        );
    }

    #[test]
    fn ptr_round_trip() {
        let name = reverse_name("192.168.1.50".parse().unwrap());
        let query = ptr_query(0xBEEF, &name, false);
        let reply = ptr_response(&query, "n95server.local");
        assert_eq!(
            parse_ptr(&reply, 0xBEEF, &name),
            Some("n95server.local".into())
        );
    }

    #[test]
    fn ptr_rejects_mismatches() {
        let name = reverse_name("192.168.1.50".parse().unwrap());
        let other = reverse_name("192.168.1.51".parse().unwrap());
        let reply = ptr_response(&ptr_query(7, &name, true), "host.lan");
        assert_eq!(parse_ptr(&reply, 8, &name), None, "wrong id");
        assert_eq!(
            parse_ptr(&reply, 7, &other),
            None,
            "answer for another address"
        );
        assert_eq!(
            parse_ptr(&ptr_query(7, &name, true), 7, &name),
            None,
            "a query is not an answer"
        );
        let hostile = ptr_response(&ptr_query(7, &name, true), "evil\u{1b}.lan");
        assert_eq!(parse_ptr(&hostile, 7, &name), None);
        for len in 0..reply.len() {
            assert_eq!(
                parse_ptr(&reply[..len], 7, &name),
                None,
                "truncated to {len}"
            );
        }
    }

    #[test]
    fn ptr_survives_random_corruption() {
        let name = reverse_name("10.0.0.7".parse().unwrap());
        let base = ptr_response(&ptr_query(1, &name, true), "printer.lan");
        let mut state = 0x5DEE_CE66_D1CE_4E5Bu64;
        for _ in 0..30_000 {
            let mut msg = base.clone();
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            let i = (state as usize) % msg.len();
            msg[i] = (state >> 32) as u8;
            if let Some(found) = parse_ptr(&msg, 1, &name) {
                assert!(valid_hostname(&found));
            }
        }
    }

    /// Mutates valid messages at random and feeds them to the parser: it must never panic.
    #[test]
    fn survives_random_corruption() {
        let base = response(
            "www.youtube.com",
            &[
                ("www.youtube.com", 5, name_rdata("youtube-ui.l.google.com")),
                ("youtube-ui.l.google.com", TYPE_A, vec![142, 250, 180, 14]),
            ],
        );
        let mut state = 0x9E37_79B9_7F4A_7C15u64;
        let mut next = || {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            state
        };
        for _ in 0..50_000 {
            let mut msg = base.clone();
            for _ in 0..(next() % 6 + 1) {
                let i = (next() as usize) % msg.len();
                msg[i] = next() as u8;
            }
            if next() % 4 == 0 {
                msg.truncate((next() as usize) % msg.len());
            }
            let _ = parse_response(&msg);
        }
        for len in 0..64 {
            let junk: Vec<u8> = (0..len).map(|_| next() as u8).collect();
            let _ = parse_response(&junk);
        }
    }
}
