//! Server name from QUIC (HTTP/3) connections.
//!
//! A QUIC client's first packets (*Initial* packets) carry the TLS ClientHello inside CRYPTO
//! frames. They are encrypted, but with keys derived from public values only (RFC 9001 §5.2):
//! any on-path observer can read them, and that is all this module does. Supported: QUIC v1
//! (RFC 9000) and v2 (RFC 9369).
//!
//! Browsers split the ClientHello over several Initial packets and, like Chrome's "chaos
//! protection", shuffle the CRYPTO frames inside them. Fragments are therefore reassembled by
//! offset, per connection, until the ClientHello is complete.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::time::{Duration, Instant};

use aes::Aes128;
use aes::cipher::{BlockCipherEncrypt, KeyInit};
use aes_gcm::{AeadInOut, Aes128Gcm};
use hkdf::Hkdf;
use sha2::Sha256;

use super::tls::{self, Sni};

const VERSION_1: u32 = 0x0000_0001;
const VERSION_2: u32 = 0x6b33_43cf;
const SALT_V1: [u8; 20] = [
    0x38, 0x76, 0x2c, 0xf7, 0xf5, 0x59, 0x34, 0xb3, 0x4d, 0x17, 0x9a, 0xe6, 0xa4, 0xc8, 0x0c, 0xad,
    0xcc, 0xbb, 0x7f, 0x0a,
];
const SALT_V2: [u8; 20] = [
    0x0d, 0xed, 0xe3, 0xde, 0xf7, 0x00, 0xa6, 0xdb, 0x81, 0x93, 0x81, 0xbe, 0x6e, 0x26, 0x9d, 0xcb,
    0xf9, 0xbd, 0x2e, 0xd9,
];
const TAG_LEN: usize = 16;
const SAMPLE_LEN: usize = 16;
const MAX_CID_LEN: usize = 20;
/// Largest ClientHello we are willing to buffer (they are ~2 KB with post-quantum shares).
const MAX_HELLO: usize = 16 * 1024;
const MAX_PENDING: usize = 1_024;
const PENDING_TIMEOUT: Duration = Duration::from_secs(10);

/// Packet protection keys for client Initial packets.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InitialKeys {
    pub key: [u8; 16],
    pub iv: [u8; 12],
    pub hp: [u8; 16],
}

impl InitialKeys {
    /// Derives the client's Initial keys from the Destination Connection ID it chose.
    pub fn client(version: u32, dcid: &[u8]) -> Option<Self> {
        let (salt, prefix) = match version {
            VERSION_1 => (&SALT_V1, "quic"),
            VERSION_2 => (&SALT_V2, "quicv2"),
            _ => return None,
        };
        let initial = Hkdf::<Sha256>::new(Some(salt), dcid);
        let mut client_secret = [0u8; 32];
        expand_label(&initial, "client in", &mut client_secret)?;
        let client = Hkdf::<Sha256>::from_prk(&client_secret).ok()?;
        let mut keys = Self {
            key: [0; 16],
            iv: [0; 12],
            hp: [0; 16],
        };
        expand_label(&client, &format!("{prefix} key"), &mut keys.key)?;
        expand_label(&client, &format!("{prefix} iv"), &mut keys.iv)?;
        expand_label(&client, &format!("{prefix} hp"), &mut keys.hp)?;
        Some(keys)
    }
}

/// TLS 1.3 HKDF-Expand-Label with an empty context (RFC 8446 §7.1).
fn expand_label(hkdf: &Hkdf<Sha256>, label: &str, out: &mut [u8]) -> Option<()> {
    let full = format!("tls13 {label}");
    let mut info = Vec::with_capacity(4 + full.len());
    info.extend_from_slice(&u16::try_from(out.len()).ok()?.to_be_bytes());
    info.push(u8::try_from(full.len()).ok()?);
    info.extend_from_slice(full.as_bytes());
    info.push(0);
    hkdf.expand(&info, out).ok()
}

/// The decrypted content of one client Initial packet.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InitialPacket {
    pub dcid: Vec<u8>,
    /// `(offset, data)` of each CRYPTO frame, in packet order.
    pub crypto: Vec<(u64, Vec<u8>)>,
}

/// Decrypts every client Initial packet in a UDP datagram (packets may be coalesced).
pub fn parse_datagram(datagram: &[u8]) -> Vec<InitialPacket> {
    let mut out = Vec::new();
    let mut rest = datagram;
    while let Some((packet, len)) = parse_long_header_packet(rest) {
        if let Some(p) = packet {
            out.push(p);
        }
        rest = &rest[len..];
    }
    out
}

/// Parses one long-header packet at the start of `buf`.
/// Returns the decoded Initial (if it was one and decrypted) and the packet's total length.
fn parse_long_header_packet(buf: &[u8]) -> Option<(Option<InitialPacket>, usize)> {
    let first = *buf.first()?;
    if first & 0x80 == 0 || first & 0x40 == 0 {
        return None; // short header (cannot be followed by anything we parse) or invalid
    }
    let version = u32::from_be_bytes(buf.get(1..5)?.try_into().ok()?);
    let packet_type = (first >> 4) & 0x03;
    let is_initial = match version {
        VERSION_1 => packet_type == 0b00,
        VERSION_2 => packet_type == 0b01,
        _ => return None,
    };
    let mut pos = 5;
    let dcid_len = usize::from(*buf.get(pos)?);
    if dcid_len > MAX_CID_LEN {
        return None;
    }
    let dcid = buf.get(pos + 1..pos + 1 + dcid_len)?;
    pos += 1 + dcid_len;
    let scid_len = usize::from(*buf.get(pos)?);
    if scid_len > MAX_CID_LEN {
        return None;
    }
    pos += 1 + scid_len;
    if is_initial {
        let (token_len, n) = varint(buf.get(pos..)?)?;
        pos = pos
            .checked_add(n)?
            .checked_add(usize::try_from(token_len).ok()?)?;
    } else if packet_type == retry_type(version) {
        return None; // Retry packets have no Length field and end the datagram
    }
    let (length, n) = varint(buf.get(pos..)?)?;
    let pn_offset = pos + n;
    let end = pn_offset.checked_add(usize::try_from(length).ok()?)?;
    if end > buf.len() {
        return None;
    }
    let decoded = if is_initial {
        decrypt_initial(&buf[..end], version, dcid, pn_offset)
    } else {
        None
    };
    Some((decoded, end))
}

fn retry_type(version: u32) -> u8 {
    if version == VERSION_2 { 0b00 } else { 0b11 }
}

/// Removes header protection and decrypts an Initial packet spanning exactly `packet`.
fn decrypt_initial(
    packet: &[u8],
    version: u32,
    dcid: &[u8],
    pn_offset: usize,
) -> Option<InitialPacket> {
    let keys = InitialKeys::client(version, dcid)?;
    let sample = packet.get(pn_offset + 4..pn_offset + 4 + SAMPLE_LEN)?;
    let mask = header_mask(&keys.hp, sample.try_into().ok()?);

    let mut header = packet.get(..pn_offset + 4)?.to_vec();
    header[0] ^= mask[0] & 0x0F;
    let pn_len = usize::from(header[0] & 0x03) + 1;
    header.truncate(pn_offset + pn_len);
    let mut packet_number = 0u64;
    for i in 0..pn_len {
        header[pn_offset + i] ^= mask[1 + i];
        packet_number = (packet_number << 8) | u64::from(header[pn_offset + i]);
    }

    let body = packet.get(pn_offset + pn_len..)?;
    if body.len() < TAG_LEN {
        return None;
    }
    let (ciphertext, tag) = body.split_at(body.len() - TAG_LEN);
    let mut nonce = keys.iv;
    for (i, b) in packet_number.to_be_bytes().iter().enumerate() {
        nonce[4 + i] ^= b;
    }
    let cipher = Aes128Gcm::new_from_slice(&keys.key).ok()?;
    let mut plaintext = ciphertext.to_vec();
    cipher
        .decrypt_inout_detached(
            &nonce.into(),
            &header,
            plaintext.as_mut_slice().into(),
            tag.try_into().ok()?,
        )
        .ok()?;

    Some(InitialPacket {
        dcid: dcid.to_vec(),
        crypto: crypto_frames(&plaintext)?,
    })
}

/// AES-ECB of the sample with the header protection key (RFC 9001 §5.4.3).
pub fn header_mask(hp: &[u8; 16], sample: &[u8; 16]) -> [u8; 16] {
    let cipher = Aes128::new(hp.into());
    let mut block = (*sample).into();
    cipher.encrypt_block(&mut block);
    block.into()
}

/// Extracts CRYPTO frames from a decrypted Initial payload. Only frame types allowed in
/// Initial packets are accepted (RFC 9000 §12.4); anything else means garbage.
fn crypto_frames(mut p: &[u8]) -> Option<Vec<(u64, Vec<u8>)>> {
    let mut frames = Vec::new();
    while let Some((&frame_type, rest)) = p.split_first() {
        p = rest;
        match frame_type {
            0x00 | 0x01 => {} // PADDING, PING
            0x02 | 0x03 => {
                // ACK: largest, delay, range count, first range, ranges, [ECN counts]
                let mut fields = vec![];
                for _ in 0..4 {
                    let (v, n) = varint(p)?;
                    fields.push(v);
                    p = &p[n..];
                }
                let ranges = fields[2];
                for _ in 0..ranges.checked_mul(2)? {
                    let (_, n) = varint(p)?;
                    p = &p[n..];
                }
                if frame_type == 0x03 {
                    for _ in 0..3 {
                        let (_, n) = varint(p)?;
                        p = &p[n..];
                    }
                }
            }
            0x06 => {
                let (offset, n) = varint(p)?;
                p = &p[n..];
                let (len, n) = varint(p)?;
                p = &p[n..];
                let len = usize::try_from(len).ok()?;
                let data = p.get(..len)?;
                frames.push((offset, data.to_vec()));
                p = &p[len..];
            }
            0x1c => return Some(frames), // CONNECTION_CLOSE ends meaningful content
            _ => return None,
        }
    }
    Some(frames)
}

/// QUIC variable-length integer (RFC 9000 §16): value and encoded length.
fn varint(buf: &[u8]) -> Option<(u64, usize)> {
    let first = *buf.first()?;
    let len = 1usize << (first >> 6);
    let bytes = buf.get(..len)?;
    let mut value = u64::from(first & 0x3F);
    for &b in &bytes[1..] {
        value = (value << 8) | u64::from(b);
    }
    Some((value, len))
}

struct PendingHello {
    /// Received bytes of the CRYPTO stream, possibly with holes (tracked by `filled`).
    data: Vec<u8>,
    filled: Vec<bool>,
    started: Instant,
}

impl PendingHello {
    fn insert(&mut self, offset: u64, chunk: &[u8]) -> Option<()> {
        let start = usize::try_from(offset).ok()?;
        let end = start.checked_add(chunk.len())?;
        if end > MAX_HELLO {
            return None;
        }
        if end > self.data.len() {
            self.data.resize(end, 0);
            self.filled.resize(end, false);
        }
        self.data[start..end].copy_from_slice(chunk);
        self.filled[start..end].iter_mut().for_each(|f| *f = true);
        Some(())
    }

    /// The gap-free prefix of the stream.
    fn contiguous(&self) -> &[u8] {
        let n = self
            .filled
            .iter()
            .position(|f| !f)
            .unwrap_or(self.filled.len());
        &self.data[..n]
    }
}

/// Reassembles ClientHellos across Initial packets, keyed by flow and connection ID.
#[derive(Default)]
pub struct QuicAssembler {
    pending: HashMap<(SocketAddr, SocketAddr, Vec<u8>), PendingHello>,
}

impl QuicAssembler {
    /// Feeds one client-to-server UDP datagram; returns the server name once known.
    pub fn push(&mut self, src: SocketAddr, dst: SocketAddr, datagram: &[u8]) -> Option<String> {
        self.push_details(src, dst, datagram).map(|(name, _)| name)
    }

    /// Like [`Self::push`], with the hello's ALPN and JA4 as well.
    pub fn push_details(
        &mut self,
        src: SocketAddr,
        dst: SocketAddr,
        datagram: &[u8],
    ) -> Option<(String, Option<tls::HelloDetails>)> {
        // Cheap pre-check before any cryptography: long header with a known version.
        let first = *datagram.first()?;
        if first & 0xC0 != 0xC0 {
            return None;
        }
        for packet in parse_datagram(datagram) {
            let key = (src, dst, packet.dcid.clone());
            if !self.pending.contains_key(&key) {
                self.make_room();
            }
            let entry = self
                .pending
                .entry(key.clone())
                .or_insert_with(|| PendingHello {
                    data: Vec::new(),
                    filled: Vec::new(),
                    started: Instant::now(),
                });
            let mut ok = true;
            for (offset, data) in &packet.crypto {
                ok &= entry.insert(*offset, data).is_some();
            }
            let outcome = if ok {
                tls::parse_handshake_stream(entry.contiguous())
            } else {
                Sni::NotClientHello
            };
            match outcome {
                Sni::NeedBytes(n) if n <= MAX_HELLO => {}
                Sni::Found(name) => {
                    let details = tls::hello_details(entry.contiguous(), true);
                    self.pending.remove(&key);
                    if let Some(name) = name {
                        return Some((name, details));
                    }
                }
                _ => {
                    self.pending.remove(&key);
                }
            }
        }
        None
    }

    pub fn expire(&mut self, now: Instant) {
        self.pending
            .retain(|_, p| now.duration_since(p.started) < PENDING_TIMEOUT);
    }

    pub fn pending(&self) -> usize {
        self.pending.len()
    }

    fn make_room(&mut self) {
        if self.pending.len() < MAX_PENDING {
            return;
        }
        self.expire(Instant::now());
        if self.pending.len() >= MAX_PENDING
            && let Some(oldest) = self
                .pending
                .iter()
                .min_by_key(|(_, p)| p.started)
                .map(|(k, _)| k.clone())
        {
            self.pending.remove(&oldest);
        }
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    fn hex(s: &str) -> Vec<u8> {
        let s: String = s.chars().filter(|c| !c.is_whitespace()).collect();
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
            .collect()
    }

    /// RFC 9001 Appendix A.1: keys for DCID 0x8394c8f03e515708.
    #[test]
    fn rfc9001_initial_keys() {
        let keys = InitialKeys::client(VERSION_1, &hex("8394c8f03e515708")).unwrap();
        assert_eq!(keys.key.to_vec(), hex("1f369613dd76d5467730efcbe3b1a22d"));
        assert_eq!(keys.iv.to_vec(), hex("fa044b2f42a3fd3b46fb255c"));
        assert_eq!(keys.hp.to_vec(), hex("9f50449e04a0e810283a1e9933adedd2"));
    }

    /// RFC 9001 Appendix A.2: header protection mask from the published sample.
    #[test]
    fn rfc9001_header_protection_mask() {
        let hp: [u8; 16] = hex("9f50449e04a0e810283a1e9933adedd2").try_into().unwrap();
        let sample: [u8; 16] = hex("d1b1c98dd7689fb8ec11d242b123dc9b").try_into().unwrap();
        assert_eq!(header_mask(&hp, &sample)[..5].to_vec(), hex("437b9aec36"));
    }

    #[test]
    fn unknown_versions_have_no_keys() {
        assert_eq!(InitialKeys::client(0xff00_001d, b"12345678"), None);
    }

    /// Builds a protected client Initial packet exactly as a sender would (RFC 9001 §5),
    /// using the same primitives the RFC vectors above validate.
    pub(crate) fn initial_packet(version: u32, dcid: &[u8], pn: u32, frames: &[u8]) -> Vec<u8> {
        let keys = InitialKeys::client(version, dcid).unwrap();
        let type_bits = if version == VERSION_2 { 0b01 } else { 0b00 };
        let mut payload = frames.to_vec();
        // Pad so the header-protection sample exists and the datagram meets the 1200-byte rule.
        payload.resize(payload.len().max(1162 - dcid.len()), 0);
        let mut header = vec![0xC0 | (type_bits << 4) | 0x03];
        header.extend_from_slice(&version.to_be_bytes());
        header.push(dcid.len() as u8);
        header.extend_from_slice(dcid);
        header.push(0); // empty SCID
        header.push(0); // empty token
        let length = 4 + payload.len() + TAG_LEN;
        header.extend_from_slice(&(0x4000u16 | length as u16).to_be_bytes());
        let pn_offset = header.len();
        header.extend_from_slice(&pn.to_be_bytes());

        let mut nonce = keys.iv;
        for (i, b) in u64::from(pn).to_be_bytes().iter().enumerate() {
            nonce[4 + i] ^= b;
        }
        let cipher = Aes128Gcm::new_from_slice(&keys.key).unwrap();
        let tag = cipher
            .encrypt_inout_detached(&nonce.into(), &header, payload.as_mut_slice().into())
            .unwrap();
        let mut packet = header.clone();
        packet.extend_from_slice(&payload);
        packet.extend_from_slice(&tag);

        let sample: [u8; 16] = packet[pn_offset + 4..pn_offset + 20].try_into().unwrap();
        let mask = header_mask(&keys.hp, &sample);
        packet[0] ^= mask[0] & 0x0F;
        for i in 0..4 {
            packet[pn_offset + i] ^= mask[1 + i];
        }
        packet
    }

    pub(crate) fn crypto_frame(offset: u64, data: &[u8]) -> Vec<u8> {
        let mut f = vec![0x06];
        f.extend_from_slice(&(0x8000_0000u32 | offset as u32).to_be_bytes());
        f.extend_from_slice(&(0x4000u16 | data.len() as u16).to_be_bytes());
        f.extend_from_slice(data);
        f
    }

    /// The TLS handshake message inside a ClientHello record (QUIC has no record layer).
    pub(crate) fn hello_message(sni: &str, pad: usize) -> Vec<u8> {
        tls::tests::client_hello(Some(sni), pad)[5..].to_vec()
    }

    fn flow() -> (SocketAddr, SocketAddr) {
        (
            "192.168.1.36:59646".parse().unwrap(),
            "142.250.180.14:443".parse().unwrap(),
        )
    }

    #[test]
    fn single_packet_hello() {
        let hello = hello_message("www.youtube.com", 0);
        let packet = initial_packet(
            VERSION_1,
            &hex("8394c8f03e515708"),
            0,
            &crypto_frame(0, &hello),
        );
        let (src, dst) = flow();
        assert_eq!(
            QuicAssembler::default().push(src, dst, &packet),
            Some("www.youtube.com".into())
        );
    }

    #[test]
    fn quic_v2() {
        let hello = hello_message("v2.example.com", 0);
        let packet = initial_packet(
            VERSION_2,
            b"\x01\x02\x03\x04\x05\x06\x07\x08",
            1,
            &crypto_frame(0, &hello),
        );
        let (src, dst) = flow();
        assert_eq!(
            QuicAssembler::default().push(src, dst, &packet),
            Some("v2.example.com".into())
        );
    }

    /// Chrome-style: a 2.5 KB hello in two packets, frames shuffled with PING/PADDING between.
    #[test]
    fn shuffled_fragments_across_packets() {
        let hello = hello_message("rr3---sn-hpa7zn7s.googlevideo.com", 2300);
        let dcid = hex("c0ffee0011223344");
        let cut = [0, 700, 1100, 1900, hello.len()];
        let frag = |i: usize| crypto_frame(cut[i] as u64, &hello[cut[i]..cut[i + 1]]);
        let mut first = frag(2);
        first.push(0x01);
        first.extend_from_slice(&frag(0));
        let mut second = vec![0x00, 0x00];
        second.extend_from_slice(&frag(3));
        second.extend_from_slice(&frag(1));

        let (src, dst) = flow();
        let mut asm = QuicAssembler::default();
        assert_eq!(
            asm.push(src, dst, &initial_packet(VERSION_1, &dcid, 0, &first)),
            None
        );
        assert_eq!(asm.pending(), 1);
        assert_eq!(
            asm.push(src, dst, &initial_packet(VERSION_1, &dcid, 1, &second)),
            Some("rr3---sn-hpa7zn7s.googlevideo.com".into())
        );
        assert_eq!(asm.pending(), 0);
    }

    #[test]
    fn coalesced_packets_in_one_datagram() {
        let hello = hello_message("coalesced.example.com", 0);
        let dcid = hex("0102030405060708");
        let mut datagram = initial_packet(VERSION_1, &dcid, 0, &crypto_frame(0, &hello[..100]));
        datagram.extend(initial_packet(
            VERSION_1,
            &dcid,
            1,
            &crypto_frame(100, &hello[100..]),
        ));
        let (src, dst) = flow();
        assert_eq!(
            QuicAssembler::default().push(src, dst, &datagram),
            Some("coalesced.example.com".into())
        );
    }

    #[test]
    fn tampered_packets_fail_authentication() {
        let hello = hello_message("x.example.com", 0);
        let packet = initial_packet(
            VERSION_1,
            &hex("8394c8f03e515708"),
            0,
            &crypto_frame(0, &hello),
        );
        let (src, dst) = flow();
        for i in [0, 20, 100, packet.len() - 1] {
            let mut bad = packet.clone();
            bad[i] ^= 0x40;
            assert_eq!(
                QuicAssembler::default().push(src, dst, &bad),
                None,
                "byte {i}"
            );
        }
    }

    #[test]
    fn short_header_and_non_quic_udp_are_ignored() {
        let (src, dst) = flow();
        let mut asm = QuicAssembler::default();
        assert_eq!(asm.push(src, dst, &[0x40, 1, 2, 3]), None);
        assert_eq!(asm.push(src, dst, b""), None);
        assert_eq!(asm.push(src, dst, &[0xC0, 0xFF, 0, 0, 0x1d, 8]), None);
        assert_eq!(asm.pending(), 0);
    }

    #[test]
    fn oversized_or_hostile_offsets_are_dropped() {
        let dcid = hex("0102030405060708");
        let (src, dst) = flow();
        let mut asm = QuicAssembler::default();
        let huge = initial_packet(VERSION_1, &dcid, 0, &crypto_frame(0x3FFF_0000, b"x"));
        assert_eq!(asm.push(src, dst, &huge), None);
        assert_eq!(asm.pending(), 0, "no state kept for impossible offsets");
    }

    #[test]
    fn pending_state_is_bounded_and_expires() {
        let partial = &hello_message("x.com", 2000)[..300];
        let (_, dst) = flow();
        let mut asm = QuicAssembler::default();
        for port in 0..(MAX_PENDING as u16 + 200) {
            let src = SocketAddr::new("10.0.0.1".parse().unwrap(), 2000 + port);
            asm.push(
                src,
                dst,
                &initial_packet(VERSION_1, &port.to_be_bytes(), 0, &crypto_frame(0, partial)),
            );
        }
        assert!(asm.pending() <= MAX_PENDING);
        asm.expire(Instant::now() + PENDING_TIMEOUT + Duration::from_secs(1));
        assert_eq!(asm.pending(), 0);
    }

    #[test]
    fn varints() {
        assert_eq!(varint(&[0x25]), Some((37, 1)));
        assert_eq!(varint(&[0x7b, 0xbd]), Some((15_293, 2)));
        assert_eq!(varint(&[0x9d, 0x7f, 0x3e, 0x7d]), Some((494_878_333, 4)));
        assert_eq!(
            varint(&hex("c2197c5eff14e88c")),
            Some((151_288_809_941_952_652, 8))
        );
        assert_eq!(varint(&[0x40]), None);
        assert_eq!(varint(&[]), None);
    }

    #[test]
    fn survives_random_corruption() {
        let hello = hello_message("fuzz.example.com", 400);
        let packet = initial_packet(
            VERSION_1,
            &hex("8394c8f03e515708"),
            0,
            &crypto_frame(0, &hello),
        );
        let (src, dst) = flow();
        let mut state = 0xA076_1D64_78BD_642Fu64;
        let mut asm = QuicAssembler::default();
        for _ in 0..3_000 {
            let mut p = packet.clone();
            for _ in 0..3 {
                state ^= state << 13;
                state ^= state >> 7;
                state ^= state << 17;
                let i = (state as usize) % p.len();
                p[i] = (state >> 40) as u8;
            }
            if state.is_multiple_of(5) {
                p.truncate((state as usize >> 8) % p.len());
            }
            let _ = asm.push(src, dst, &p);
        }
        // Frame parser fed with raw garbage must not panic either.
        for len in 0..200 {
            let junk: Vec<u8> = (0..len).map(|i| (i * 37 + len) as u8).collect();
            let _ = crypto_frames(&junk);
        }
    }
}
