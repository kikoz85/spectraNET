//! Robustness of the parsers that read packets off the network: DNS answers, TLS hellos, QUIC
//! Initial packets and link-layer frames come from anyone on the network, so no input may
//! make them panic, hang or allocate without bound. Real messages are mutated (bytes flipped,
//! cut, extended, spliced) and random bytes are thrown at every parser, with a fixed seed so
//! failures reproduce.

use super::{dns, packet, quic, tls};

/// xorshift64*: small, fast, reproducible.
struct Rng(u64);

impl Rng {
    fn next(&mut self) -> u64 {
        self.0 ^= self.0 >> 12;
        self.0 ^= self.0 << 25;
        self.0 ^= self.0 >> 27;
        self.0.wrapping_mul(0x2545_f491_4f6c_dd1d)
    }

    fn below(&mut self, n: usize) -> usize {
        (self.next() % n.max(1) as u64) as usize
    }

    fn bytes(&mut self, n: usize) -> Vec<u8> {
        (0..n).map(|_| self.next() as u8).collect()
    }

    /// A mutation of `seed`.
    fn mutate(&mut self, seed: &[u8]) -> Vec<u8> {
        let mut m = seed.to_vec();
        for _ in 0..=self.below(4) {
            match self.below(6) {
                // Flip a few bytes (lengths and counts are the interesting ones).
                0 | 1 if !m.is_empty() => {
                    let i = self.below(m.len());
                    m[i] = self.next() as u8;
                }
                // Extreme values where lengths usually live.
                2 if !m.is_empty() => {
                    let i = self.below(m.len());
                    m[i] = if self.next().is_multiple_of(2) {
                        0xff
                    } else {
                        0x00
                    };
                }
                // Cut.
                3 => m.truncate(self.below(m.len() + 1)),
                // Grow with garbage.
                4 => {
                    let extra = self.below(64);
                    let tail = self.bytes(extra);
                    m.extend(tail);
                }
                // Splice a chunk of itself somewhere else.
                _ if m.len() > 4 => {
                    let a = self.below(m.len());
                    let b = a + self.below(m.len() - a);
                    let chunk = m[a..b].to_vec();
                    let at = self.below(m.len());
                    m.splice(at..at, chunk);
                }
                _ => {}
            }
        }
        m
    }
}

const ROUNDS: usize = 20_000;

fn throw_at(seeds: &[Vec<u8>], mut parse: impl FnMut(&[u8])) {
    let mut rng = Rng(0x5eed_1234_abcd_0001);
    for i in 0..ROUNDS {
        let input = if i % 5 == 0 {
            let n = rng.below(1500);
            rng.bytes(n)
        } else {
            let seed = &seeds[i % seeds.len()];
            rng.mutate(seed)
        };
        parse(&input);
    }
}

#[test]
fn dns_answers_never_break_the_parser() {
    let seeds = vec![
        dns::tests::response("example.com", &[("example.com", 1, vec![93, 184, 216, 34])]),
        dns::tests::response(
            "www.example.org",
            &[
                ("www.example.org", 5, vec![3, b'c', b'd', b'n', 0]),
                (
                    "cdn",
                    28,
                    vec![0x20, 1, 0xd, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1],
                ),
            ],
        ),
    ];
    throw_at(&seeds, |m| {
        let _ = dns::parse_response(m);
        let _ = dns::parse_mdns(m);
        let _ = dns::parse_ptr(m, 0x1234, "34.216.184.93.in-addr.arpa");
    });
}

#[test]
fn tls_hellos_never_break_the_parser() {
    let seeds = vec![
        tls::tests::client_hello(Some("example.com"), 0),
        tls::tests::client_hello(Some("a.very.long.name.example.com"), 600),
        tls::tests::client_hello(None, 40),
    ];
    throw_at(&seeds, |m| {
        let _ = tls::parse_client_hello(m);
        let _ = tls::parse_handshake_stream(m);
        let _ = tls::parse_server_hello(m);
        // The handshake message alone, as QUIC carries it.
        if m.len() > 5 {
            let _ = tls::hello_details(&m[5..], false);
            let _ = tls::hello_details(&m[5..], true);
        }
    });
}

#[test]
fn quic_initials_never_break_the_parser() {
    let hello = tls::tests::client_hello(Some("example.com"), 0);
    let mut crypto = vec![0x06, 0x00, 0x40];
    crypto.push((hello.len() - 5) as u8);
    crypto.extend_from_slice(&hello[5..]);
    let seeds = vec![
        quic::tests::initial_packet(1, b"\x01\x02\x03\x04\x05\x06\x07\x08", 0, &crypto),
        quic::tests::initial_packet(0x6b33_43cf, b"abcdefgh", 1, &crypto),
    ];
    throw_at(&seeds, |m| {
        let _ = quic::parse_datagram(m);
    });
}

#[test]
fn link_frames_never_break_the_decoder() {
    let mut frame = vec![0u8; 12];
    frame.extend_from_slice(&[0x08, 0x00]);
    // IPv4 + UDP to port 53 carrying a DNS answer.
    let payload = dns::tests::response("example.com", &[("example.com", 1, vec![1, 2, 3, 4])]);
    let total = 20 + 8 + payload.len();
    frame.extend_from_slice(&[
        0x45,
        0,
        (total >> 8) as u8,
        total as u8,
        0,
        0,
        0,
        0,
        64,
        17,
        0,
        0,
    ]);
    frame.extend_from_slice(&[8, 8, 8, 8, 192, 168, 1, 36]);
    frame.extend_from_slice(&[
        0,
        53,
        0xc3,
        0x50,
        ((8 + payload.len()) >> 8) as u8,
        (8 + payload.len()) as u8,
        0,
        0,
    ]);
    frame.extend_from_slice(&payload);
    let seeds = vec![frame];
    throw_at(&seeds, |m| {
        for link in [
            packet::Link::Ethernet,
            packet::Link::Null,
            packet::Link::Loop,
            packet::Link::Raw,
            packet::Link::LinuxSll,
            packet::Link::LinuxSll2,
        ] {
            let _ = packet::decode(link, m);
        }
    });
}
