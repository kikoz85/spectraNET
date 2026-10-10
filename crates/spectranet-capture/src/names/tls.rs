//! Extraction of the Server Name Indication (SNI) from a TLS ClientHello, and of the other
//! handshake fields sent in clear: offered application protocols (ALPN), the JA4 client
//! fingerprint, and the version and cipher suite the server chose.
//!
//! The SNI is the hostname a client asks for when opening a TLS connection; it is sent in
//! clear text in the first handshake message, even when DNS itself is encrypted (DoH/DoT).
//! A modern ClientHello (post-quantum key shares) often spans two TCP segments, so the parser
//! reports how many bytes it still needs instead of failing.

use super::dns::valid_hostname;

const RECORD_HEADER: usize = 5;
const CONTENT_HANDSHAKE: u8 = 0x16;
const HANDSHAKE_CLIENT_HELLO: u8 = 0x01;
const EXT_SERVER_NAME: u16 = 0x0000;
const NAME_TYPE_HOST: u8 = 0x00;
/// TLS caps a record at 2^14 bytes of plaintext (plus some slack for TLS 1.2 framing).
pub const MAX_RECORD: usize = (1 << 14) + 2048;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Sni {
    /// A complete ClientHello was parsed; it may or may not carry a hostname.
    Found(Option<String>),
    /// The stream looks like a ClientHello but this many bytes in total are required.
    NeedBytes(usize),
    /// Not the start of a TLS ClientHello (or malformed).
    NotClientHello,
}

/// Inspects the first bytes a client sent on a TCP connection.
pub fn parse_client_hello(stream: &[u8]) -> Sni {
    let Some(header) = stream.get(..RECORD_HEADER) else {
        return if looks_like_handshake_prefix(stream) {
            Sni::NeedBytes(RECORD_HEADER)
        } else {
            Sni::NotClientHello
        };
    };
    if header[0] != CONTENT_HANDSHAKE || header[1] != 0x03 || header[2] > 0x04 {
        return Sni::NotClientHello;
    }
    let record_len = usize::from(u16::from_be_bytes([header[3], header[4]]));
    if record_len == 0 || record_len > MAX_RECORD {
        return Sni::NotClientHello;
    }
    let total = RECORD_HEADER + record_len;
    let Some(record) = stream.get(RECORD_HEADER..total) else {
        return Sni::NeedBytes(total);
    };
    match parse_handshake(record) {
        Some(name) => Sni::Found(name),
        None => Sni::NotClientHello,
    }
}

/// Inspects a bare TLS handshake stream (no record layer), as carried in QUIC CRYPTO frames.
pub fn parse_handshake_stream(stream: &[u8]) -> Sni {
    match stream.first() {
        None => return Sni::NeedBytes(4),
        Some(&HANDSHAKE_CLIENT_HELLO) => {}
        Some(_) => return Sni::NotClientHello,
    }
    let Some(len) = stream.get(1..4) else {
        return Sni::NeedBytes(4);
    };
    let total = 4 + (usize::from(len[0]) << 16 | usize::from(len[1]) << 8 | usize::from(len[2]));
    if total > MAX_RECORD {
        return Sni::NotClientHello;
    }
    let Some(message) = stream.get(..total) else {
        return Sni::NeedBytes(total);
    };
    match parse_handshake(message) {
        Some(name) => Sni::Found(name),
        None => Sni::NotClientHello,
    }
}

fn looks_like_handshake_prefix(stream: &[u8]) -> bool {
    match stream {
        [] => false,
        [first, rest @ ..] => {
            *first == CONTENT_HANDSHAKE && rest.first().is_none_or(|v| *v == 0x03)
        }
    }
}

/// Parses the handshake message inside the record. `None` means malformed.
fn parse_handshake(record: &[u8]) -> Option<Option<String>> {
    let mut r = Reader(record);
    if r.u8()? != HANDSHAKE_CLIENT_HELLO {
        return None;
    }
    let body_len = r.u24()?;
    // A ClientHello larger than one record is legal but vanishingly rare; parse what we have.
    let mut body = Reader(r.0.get(..body_len.min(r.0.len()))?);
    body.skip(2 + 32)?; // legacy_version + random
    let session_id = usize::from(body.u8()?);
    body.skip(session_id)?;
    let suites = usize::from(body.u16()?);
    body.skip(suites)?;
    let compression = usize::from(body.u8()?);
    body.skip(compression)?;
    if body.0.is_empty() {
        return Some(None); // no extensions at all (very old clients)
    }
    let ext_len = usize::from(body.u16()?);
    let mut exts = Reader(body.take(ext_len)?);
    while !exts.0.is_empty() {
        let ext_type = exts.u16()?;
        let len = usize::from(exts.u16()?);
        let data = exts.take(len)?;
        if ext_type == EXT_SERVER_NAME {
            return Some(parse_server_name(data));
        }
    }
    Some(None)
}

fn parse_server_name(data: &[u8]) -> Option<String> {
    let mut r = Reader(data);
    let list_len = usize::from(r.u16()?);
    let mut list = Reader(r.take(list_len)?);
    while !list.0.is_empty() {
        let name_type = list.u8()?;
        let len = usize::from(list.u16()?);
        let name = list.take(len)?;
        if name_type == NAME_TYPE_HOST {
            let name = std::str::from_utf8(name).ok()?.to_ascii_lowercase();
            let name = name.trim_end_matches('.').to_string();
            return valid_hostname(&name).then_some(name);
        }
    }
    None
}

const HANDSHAKE_SERVER_HELLO: u8 = 0x02;
const EXT_ALPN: u16 = 0x0010;
const EXT_SIGNATURE_ALGORITHMS: u16 = 0x000d;
const EXT_SUPPORTED_VERSIONS: u16 = 0x002b;

/// What a ClientHello says about the client, besides the host name.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct HelloDetails {
    /// Application protocols offered (ALPN), in order.
    pub alpn: Vec<String>,
    /// JA4 fingerprint (FoxIO JA4, TLS client part).
    pub ja4: String,
}

/// GREASE values (RFC 8701) are random placeholders, ignored by fingerprints.
fn is_grease(v: u16) -> bool {
    v & 0x0f0f == 0x0a0a && v >> 8 == v & 0xff
}

fn version_code(v: u16) -> &'static str {
    match v {
        0x0304 => "13",
        0x0303 => "12",
        0x0302 => "11",
        0x0301 => "10",
        0x0300 => "s3",
        _ => "00",
    }
}

/// First 12 hex digits of the SHA-256 of `text`, or zeros when there is nothing to hash.
fn hash12(text: &str) -> String {
    use sha2::{Digest, Sha256};
    if text.is_empty() {
        return "000000000000".into();
    }
    Sha256::digest(text.as_bytes())
        .iter()
        .take(6)
        .map(|b| format!("{b:02x}"))
        .collect()
}

/// ALPN part of JA4: first and last character of the first protocol, or `00`.
fn alpn_code(alpn: Option<&[u8]>) -> String {
    match alpn {
        Some(p) if !p.is_empty() => {
            let (first, last) = (p[0], p[p.len() - 1]);
            if first.is_ascii_alphanumeric() && last.is_ascii_alphanumeric() {
                format!("{}{}", first as char, last as char)
            } else {
                let hex = format!("{first:02x}{last:02x}");
                format!("{}{}", &hex[..1], &hex[3..])
            }
        }
        _ => "00".into(),
    }
}

/// ALPN and JA4 of a ClientHello handshake message (no record header). `quic` selects the
/// JA4 transport letter.
pub fn hello_details(message: &[u8], quic: bool) -> Option<HelloDetails> {
    let mut r = Reader(message);
    if r.u8()? != HANDSHAKE_CLIENT_HELLO {
        return None;
    }
    let body_len = r.u24()?;
    let mut body = Reader(r.0.get(..body_len.min(r.0.len()))?);
    let legacy = body.u16()?;
    body.skip(32)?;
    let session_id = usize::from(body.u8()?);
    body.skip(session_id)?;
    let suites_len = usize::from(body.u16()?);
    let mut suites = Reader(body.take(suites_len)?);
    let mut ciphers = Vec::new();
    while let Some(c) = suites.u16() {
        if !is_grease(c) {
            ciphers.push(c);
        }
    }
    let compression = usize::from(body.u8()?);
    body.skip(compression)?;
    let mut extensions = Vec::new();
    let mut sni = false;
    let mut alpn = Vec::new();
    let mut signatures = Vec::new();
    let mut version = legacy;
    if !body.0.is_empty() {
        let ext_len = usize::from(body.u16()?);
        let mut exts = Reader(body.take(ext_len)?);
        while !exts.0.is_empty() {
            let ext_type = exts.u16()?;
            let len = usize::from(exts.u16()?);
            let data = exts.take(len)?;
            if is_grease(ext_type) {
                continue;
            }
            extensions.push(ext_type);
            match ext_type {
                EXT_SERVER_NAME => sni = true,
                EXT_ALPN => {
                    let mut d = Reader(data);
                    let list = usize::from(d.u16().unwrap_or(0));
                    let mut list = Reader(d.take(list).unwrap_or(&[]));
                    while let Some(n) = list.u8() {
                        match list.take(usize::from(n)) {
                            Some(p) => alpn.push(p.to_vec()),
                            None => break,
                        }
                    }
                }
                EXT_SIGNATURE_ALGORITHMS => {
                    let mut d = Reader(data);
                    let n = usize::from(d.u16().unwrap_or(0));
                    let mut list = Reader(d.take(n).unwrap_or(&[]));
                    while let Some(a) = list.u16() {
                        if !is_grease(a) {
                            signatures.push(a);
                        }
                    }
                }
                EXT_SUPPORTED_VERSIONS => {
                    let mut d = Reader(data);
                    let n = usize::from(d.u8().unwrap_or(0));
                    let mut list = Reader(d.take(n).unwrap_or(&[]));
                    let mut best = 0;
                    while let Some(v) = list.u16() {
                        if !is_grease(v) && v > best {
                            best = v;
                        }
                    }
                    if best != 0 {
                        version = best;
                    }
                }
                _ => {}
            }
        }
    }
    let a = format!(
        "{}{}{}{:02}{:02}{}",
        if quic { 'q' } else { 't' },
        version_code(version),
        if sni { 'd' } else { 'i' },
        ciphers.len().min(99),
        extensions.len().min(99),
        alpn_code(alpn.first().map(Vec::as_slice)),
    );
    let mut sorted_ciphers = ciphers.clone();
    sorted_ciphers.sort_unstable();
    let b = hash12(
        &sorted_ciphers
            .iter()
            .map(|c| format!("{c:04x}"))
            .collect::<Vec<_>>()
            .join(","),
    );
    let mut sorted_ext: Vec<u16> = extensions
        .iter()
        .copied()
        .filter(|e| *e != EXT_SERVER_NAME && *e != EXT_ALPN)
        .collect();
    sorted_ext.sort_unstable();
    let ext_text = sorted_ext
        .iter()
        .map(|e| format!("{e:04x}"))
        .collect::<Vec<_>>()
        .join(",");
    let sig_text = signatures
        .iter()
        .map(|a| format!("{a:04x}"))
        .collect::<Vec<_>>()
        .join(",");
    let c = if sig_text.is_empty() {
        hash12(&ext_text)
    } else {
        hash12(&format!("{ext_text}_{sig_text}"))
    };
    Some(HelloDetails {
        alpn: alpn
            .into_iter()
            .filter_map(|p| String::from_utf8(p).ok())
            .filter(|p| p.len() <= 32 && p.chars().all(|c| c.is_ascii_graphic()))
            .collect(),
        ja4: format!("{a}_{b}_{c}"),
    })
}

/// What a ServerHello settles: the TLS version and the cipher suite.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ServerChoice {
    pub version: String,
    pub cipher: String,
}

/// Parses a ServerHello at the start of a server's TCP stream (record layer included).
pub fn parse_server_hello(stream: &[u8]) -> Option<ServerChoice> {
    let header = stream.get(..RECORD_HEADER)?;
    if header[0] != CONTENT_HANDSHAKE || header[1] != 0x03 {
        return None;
    }
    let record_len = usize::from(u16::from_be_bytes([header[3], header[4]]));
    let record = stream.get(RECORD_HEADER..RECORD_HEADER + record_len)?;
    let mut r = Reader(record);
    if r.u8()? != HANDSHAKE_SERVER_HELLO {
        return None;
    }
    let body_len = r.u24()?;
    let mut body = Reader(r.take(body_len)?);
    let legacy = body.u16()?;
    body.skip(32)?;
    let session_id = usize::from(body.u8()?);
    body.skip(session_id)?;
    let cipher = body.u16()?;
    body.skip(1)?;
    let mut version = legacy;
    if let Some(len) = body.u16() {
        let mut exts = Reader(body.take(usize::from(len))?);
        while !exts.0.is_empty() {
            let ext_type = exts.u16()?;
            let len = usize::from(exts.u16()?);
            let data = exts.take(len)?;
            if ext_type == EXT_SUPPORTED_VERSIONS && data.len() == 2 {
                version = u16::from_be_bytes([data[0], data[1]]);
            }
        }
    }
    let version = match version {
        0x0304 => "TLS 1.3",
        0x0303 => "TLS 1.2",
        0x0302 => "TLS 1.1",
        0x0301 => "TLS 1.0",
        _ => return None,
    };
    Some(ServerChoice {
        version: version.into(),
        cipher: cipher_name(cipher),
    })
}

/// IANA names of the cipher suites seen in practice.
pub fn cipher_name(suite: u16) -> String {
    match suite {
        0x1301 => "TLS_AES_128_GCM_SHA256",
        0x1302 => "TLS_AES_256_GCM_SHA384",
        0x1303 => "TLS_CHACHA20_POLY1305_SHA256",
        0xc02b => "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256",
        0xc02c => "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384",
        0xc02f => "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
        0xc030 => "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",
        0xcca8 => "TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256",
        0xcca9 => "TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256",
        0xc013 => "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA",
        0xc014 => "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA",
        0x009c => "TLS_RSA_WITH_AES_128_GCM_SHA256",
        0x009d => "TLS_RSA_WITH_AES_256_GCM_SHA384",
        0x002f => "TLS_RSA_WITH_AES_128_CBC_SHA",
        0x0035 => "TLS_RSA_WITH_AES_256_CBC_SHA",
        other => return format!("0x{other:04x}"),
    }
    .into()
}

/// Bounds-checked big-endian cursor.
struct Reader<'a>(&'a [u8]);

impl<'a> Reader<'a> {
    fn take(&mut self, n: usize) -> Option<&'a [u8]> {
        if n > self.0.len() {
            return None;
        }
        let (head, tail) = self.0.split_at(n);
        self.0 = tail;
        Some(head)
    }
    fn skip(&mut self, n: usize) -> Option<()> {
        self.take(n).map(|_| ())
    }
    fn u8(&mut self) -> Option<u8> {
        self.take(1).map(|b| b[0])
    }
    fn u16(&mut self) -> Option<u16> {
        self.take(2).map(|b| u16::from_be_bytes([b[0], b[1]]))
    }
    fn u24(&mut self) -> Option<usize> {
        self.take(3)
            .map(|b| usize::from(b[0]) << 16 | usize::from(b[1]) << 8 | usize::from(b[2]))
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    /// Builds a syntactically valid ClientHello record. `pad` adds a padding extension
    /// (type 21) before SNI to make the hello large, as post-quantum key shares do.
    pub(crate) fn client_hello(sni: Option<&str>, pad: usize) -> Vec<u8> {
        let mut exts = Vec::new();
        if pad > 0 {
            exts.extend_from_slice(&21u16.to_be_bytes());
            exts.extend_from_slice(&(pad as u16).to_be_bytes());
            exts.extend(std::iter::repeat_n(0u8, pad));
        }
        if let Some(name) = sni {
            let mut entry = vec![NAME_TYPE_HOST];
            entry.extend_from_slice(&(name.len() as u16).to_be_bytes());
            entry.extend_from_slice(name.as_bytes());
            exts.extend_from_slice(&EXT_SERVER_NAME.to_be_bytes());
            exts.extend_from_slice(&((entry.len() + 2) as u16).to_be_bytes());
            exts.extend_from_slice(&(entry.len() as u16).to_be_bytes());
            exts.extend_from_slice(&entry);
        }
        // supported_versions after SNI, so the parser must stop at the right place.
        exts.extend_from_slice(&[0x00, 0x2b, 0x00, 0x03, 0x02, 0x03, 0x04]);

        let mut body = vec![0x03, 0x03];
        body.extend_from_slice(&[0xAB; 32]);
        body.push(32);
        body.extend_from_slice(&[0xCD; 32]);
        body.extend_from_slice(&[0x00, 0x04, 0x13, 0x01, 0x13, 0x02]);
        body.extend_from_slice(&[0x01, 0x00]);
        body.extend_from_slice(&(exts.len() as u16).to_be_bytes());
        body.extend_from_slice(&exts);

        let mut handshake = vec![HANDSHAKE_CLIENT_HELLO];
        handshake.extend_from_slice(&(body.len() as u32).to_be_bytes()[1..]);
        handshake.extend_from_slice(&body);

        let mut record = vec![CONTENT_HANDSHAKE, 0x03, 0x01];
        record.extend_from_slice(&(handshake.len() as u16).to_be_bytes());
        record.extend_from_slice(&handshake);
        record
    }

    #[test]
    fn extracts_sni() {
        let hello = client_hello(Some("www.Example.com"), 0);
        assert_eq!(
            parse_client_hello(&hello),
            Sni::Found(Some("www.example.com".into()))
        );
    }

    #[test]
    fn details_and_ja4() {
        // A hello with SNI, ALPN h2+http/1.1, two TLS 1.3 suites, a GREASE suite and
        // supported_versions 1.3.
        let mut hello = client_hello(Some("example.com"), 0);
        let details = hello_details(&hello[RECORD_HEADER..], false).unwrap();
        // Test builder: suites 1301, 1302; extensions SNI + supported_versions; no ALPN.
        assert!(details.alpn.is_empty());
        let parts: Vec<&str> = details.ja4.split('_').collect();
        assert_eq!(parts[0], "t13d020200");
        assert_eq!(parts[1], &hash12("1301,1302"));
        assert_eq!(parts[2], &hash12("002b"));
        // QUIC hellos use q; no SNI gives i.
        hello = client_hello(None, 0);
        let quic = hello_details(&hello[RECORD_HEADER..], true).unwrap();
        assert!(quic.ja4.starts_with("q13i0201"));
        assert!(hello_details(&[0x02, 0, 0, 0], false).is_none());
    }

    #[test]
    fn grease_and_alpn_codes() {
        assert!(is_grease(0x0a0a) && is_grease(0xfafa) && !is_grease(0x0a1a) && !is_grease(0x1301));
        assert_eq!(alpn_code(Some(b"h2")), "h2");
        assert_eq!(alpn_code(Some(b"http/1.1")), "h1");
        assert_eq!(alpn_code(None), "00");
        assert_eq!(hash12(""), "000000000000");
        assert_eq!(hash12("abc").len(), 12);
    }

    #[test]
    fn server_hello_version_and_cipher() {
        // ServerHello, legacy version 1.2, cipher 0x1302, supported_versions = 1.3.
        let mut body = vec![0x03, 0x03];
        body.extend_from_slice(&[0x11; 32]);
        body.push(0);
        body.extend_from_slice(&[0x13, 0x02, 0x00]);
        let exts = [0x00, 0x2b, 0x00, 0x02, 0x03, 0x04];
        body.extend_from_slice(&(exts.len() as u16).to_be_bytes());
        body.extend_from_slice(&exts);
        let mut hs = vec![0x02];
        hs.extend_from_slice(&(body.len() as u32).to_be_bytes()[1..]);
        hs.extend_from_slice(&body);
        let mut rec = vec![0x16, 0x03, 0x03];
        rec.extend_from_slice(&(hs.len() as u16).to_be_bytes());
        rec.extend_from_slice(&hs);
        assert_eq!(
            parse_server_hello(&rec),
            Some(ServerChoice {
                version: "TLS 1.3".into(),
                cipher: "TLS_AES_256_GCM_SHA384".into()
            })
        );
        assert!(parse_server_hello(&rec[..20]).is_none());
        assert!(parse_server_hello(&client_hello(Some("x.com"), 0)).is_none());
    }

    #[test]
    fn hello_without_sni() {
        assert_eq!(parse_client_hello(&client_hello(None, 0)), Sni::Found(None));
    }

    #[test]
    fn reports_missing_bytes_for_split_hellos() {
        let hello = client_hello(Some("big.example.com"), 1500);
        assert!(hello.len() > 1500);
        for cut in [1, 3, 5, 100, 1400, hello.len() - 1] {
            match parse_client_hello(&hello[..cut]) {
                Sni::NeedBytes(n) if cut < RECORD_HEADER => assert_eq!(n, RECORD_HEADER),
                Sni::NeedBytes(n) => assert_eq!(n, hello.len(), "cut at {cut}"),
                other => panic!("cut at {cut}: {other:?}"),
            }
        }
        assert_eq!(
            parse_client_hello(&hello),
            Sni::Found(Some("big.example.com".into()))
        );
    }

    #[test]
    fn bare_handshake_stream() {
        let message = client_hello(Some("quic.example.com"), 1500)[RECORD_HEADER..].to_vec();
        assert_eq!(
            parse_handshake_stream(&message),
            Sni::Found(Some("quic.example.com".into()))
        );
        assert_eq!(parse_handshake_stream(&[]), Sni::NeedBytes(4));
        assert_eq!(parse_handshake_stream(&message[..2]), Sni::NeedBytes(4));
        assert_eq!(
            parse_handshake_stream(&message[..900]),
            Sni::NeedBytes(message.len())
        );
        assert_eq!(
            parse_handshake_stream(&[0x02, 0, 0, 4, 0, 0, 0, 0]),
            Sni::NotClientHello
        );
        assert_eq!(
            parse_handshake_stream(&[0x01, 0xFF, 0xFF, 0xFF]),
            Sni::NotClientHello
        );
    }

    #[test]
    fn rejects_non_tls_streams() {
        for stream in [
            &b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n"[..],
            b"SSH-2.0-OpenSSH_9.9\r\n",
            &[0x17, 0x03, 0x03, 0x00, 0x10], // application data
            &[0x16, 0x03, 0x03, 0x00, 0x00], // empty record
            &[0x16, 0x02, 0x00, 0x00, 0x05], // SSLv2-ish version
            &[0x16, 0x03, 0x03, 0xFF, 0xFF], // absurd length
            &[],
        ] {
            assert_eq!(
                parse_client_hello(stream),
                Sni::NotClientHello,
                "{stream:?}"
            );
        }
    }

    #[test]
    fn server_hello_is_not_a_client_hello() {
        let mut hello = client_hello(Some("x.com"), 0);
        hello[RECORD_HEADER] = 0x02;
        assert_eq!(parse_client_hello(&hello), Sni::NotClientHello);
    }

    #[test]
    fn hostile_sni_is_dropped() {
        for bad in [
            "evil\u{1b}]0;pwned\u{7}.com",
            "a b.com",
            "..",
            "x".repeat(300).as_str(),
        ] {
            let hello = client_hello(Some(bad), 0);
            assert_eq!(parse_client_hello(&hello), Sni::Found(None), "{bad:?}");
        }
        let trailing_dot = client_hello(Some("example.com."), 0);
        assert_eq!(
            parse_client_hello(&trailing_dot),
            Sni::Found(Some("example.com".into()))
        );
    }

    #[test]
    fn inconsistent_lengths_are_malformed() {
        let mut hello = client_hello(Some("example.com"), 0);
        // Claim the extensions block is longer than the record.
        let ext_len_at = RECORD_HEADER + 4 + 2 + 32 + 1 + 32 + 2 + 4 + 2;
        hello[ext_len_at] = 0xFF;
        assert_eq!(parse_client_hello(&hello), Sni::NotClientHello);
    }

    /// A ClientHello produced by a real TLS client (the system `curl`), captured by a local
    /// listener: guards against our test builder and the parser sharing a misunderstanding.
    #[cfg(unix)]
    #[test]
    fn parses_a_real_client_hello_from_curl() {
        use std::io::Read;
        use std::net::TcpListener;
        use std::process::{Command, Stdio};
        use std::time::{Duration, Instant};

        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let host = "real-client.spectranet.test";
        let child = Command::new("curl")
            .args(["-s", "-k", "--max-time", "5", "--resolve"])
            .arg(format!("{host}:{port}:127.0.0.1"))
            .arg(format!("https://{host}:{port}/"))
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn();
        let Ok(mut child) = child else {
            eprintln!("curl not available; skipping");
            return;
        };
        let (mut conn, _) = listener.accept().unwrap();
        conn.set_read_timeout(Some(Duration::from_millis(200)))
            .unwrap();
        let mut stream = Vec::new();
        let deadline = Instant::now() + Duration::from_secs(5);
        let result = loop {
            let mut buf = [0u8; 4096];
            if let Ok(n) = conn.read(&mut buf) {
                stream.extend_from_slice(&buf[..n]);
            }
            match parse_client_hello(&stream) {
                Sni::NeedBytes(_) if Instant::now() < deadline => continue,
                other => break other,
            }
        };
        drop(conn);
        let _ = child.kill();
        let _ = child.wait();
        assert_eq!(
            result,
            Sni::Found(Some(host.into())),
            "{} bytes received",
            stream.len()
        );
    }

    #[test]
    fn survives_random_corruption() {
        let base = client_hello(Some("www.example.com"), 200);
        let mut state = 0xD1B5_4A32_D192_ED03u64;
        let mut next = || {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            state
        };
        for _ in 0..50_000 {
            let mut msg = base.clone();
            for _ in 0..(next() % 8 + 1) {
                let i = (next() as usize) % msg.len();
                msg[i] = next() as u8;
            }
            if next() % 3 == 0 {
                msg.truncate((next() as usize) % msg.len());
            }
            if let Sni::Found(Some(name)) = parse_client_hello(&msg) {
                assert!(valid_hostname(&name), "{name:?}");
            }
        }
    }
}
