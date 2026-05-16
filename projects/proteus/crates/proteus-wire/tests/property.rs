//! Property-style fuzz tests for the wire decoders.
//!
//! These exercises feed deterministic-random byte sequences through
//! every public decoder API. The properties we check:
//!
//! 1. **No panic**. Any byte sequence must produce either a clean Ok
//!    or a typed `WireError`. A panic / unreachable! / unwrap-on-None
//!    is a fatal bug because the server otherwise drops the
//!    connection silently and the cover-forward path doesn't engage.
//! 2. **No infinite loop**. Each call returns within a bounded number
//!    of bytes consumed.
//! 3. **Round-trip safety**. For any valid-shaped struct we encode,
//!    decode-then-re-encode produces the exact original bytes.

use proteus_spec::AUTH_EXT_LEN_V10;
use proteus_wire::{alpha, varint, AuthExtension, InnerHeader, WireError};

/// Deterministic LCG so tests are reproducible across CI runs.
struct Rng {
    state: u64,
}

impl Rng {
    fn new(seed: u64) -> Self {
        Self { state: seed }
    }
    fn next(&mut self) -> u64 {
        self.state = self
            .state
            .wrapping_mul(6364136223846793005)
            .wrapping_add(1442695040888963407);
        self.state
    }
    fn byte(&mut self) -> u8 {
        (self.next() >> 56) as u8
    }
    fn bytes(&mut self, n: usize) -> Vec<u8> {
        (0..n).map(|_| self.byte()).collect()
    }
}

#[test]
fn fuzz_auth_extension_decode_never_panics() {
    let mut rng = Rng::new(0xDEADBEEFCAFEBABE);
    for _ in 0..2_000 {
        // Either an arbitrary length (1..=2*AUTH_EXT_LEN_V10) or exactly
        // the spec length — mix to exercise both length-rejection and
        // shape-rejection paths.
        let n = if rng.byte() & 1 == 0 {
            AUTH_EXT_LEN_V10
        } else {
            1 + ((rng.next() as usize) % (2 * AUTH_EXT_LEN_V10))
        };
        let buf = rng.bytes(n);
        let _ = AuthExtension::decode_payload(&buf);
    }
}

#[test]
fn fuzz_inner_header_decode_never_panics() {
    let mut rng = Rng::new(0xBADC0FFEE0DDF00D);
    for _ in 0..10_000 {
        let n = (rng.next() as usize) % 32;
        let buf = rng.bytes(n);
        let _ = InnerHeader::decode_wire(&buf);
    }
}

#[test]
fn fuzz_alpha_frame_decode_never_panics() {
    let mut rng = Rng::new(0x123456789ABCDEF0);
    for _ in 0..10_000 {
        let n = (rng.next() as usize) % 8192;
        let buf = rng.bytes(n);
        let _ = alpha::decode_frame(&buf);
    }
}

#[test]
fn fuzz_varint_decode_never_panics() {
    let mut rng = Rng::new(0x5555AAAA12345678);
    for _ in 0..10_000 {
        let n = (rng.next() as usize) % 16;
        let buf = rng.bytes(n);
        let _ = varint::decode(&buf);
    }
}

#[test]
fn varint_encode_decode_is_bijection() {
    // Exhaustive check at boundary regions.
    let values: Vec<u64> = vec![
        0,
        1,
        2,
        62,
        63,
        64,
        65,
        16382,
        16383,
        16384,
        16385,
        (1 << 30) - 2,
        (1 << 30) - 1,
        1 << 30,
        (1 << 30) + 1,
        (1 << 62) - 2,
        (1 << 62) - 1,
        varint::MAX,
    ];
    for v in values {
        let mut buf = Vec::new();
        varint::encode(v, &mut buf);
        let (decoded, consumed) = varint::decode(&buf).unwrap();
        assert_eq!(decoded, v);
        assert_eq!(consumed, buf.len());
    }
}

#[test]
fn alpha_frame_decode_handles_zero_length_body() {
    // Empty-body frame: kind + 1-byte varint(0).
    let buf = [alpha::FRAME_CLIENT_HELLO, 0u8];
    let (frame, consumed) = alpha::decode_frame(&buf).unwrap();
    assert_eq!(consumed, 2);
    assert_eq!(frame.kind, alpha::FRAME_CLIENT_HELLO);
    assert_eq!(frame.body, &[] as &[u8]);
}

#[test]
fn alpha_frame_decode_rejects_truncated_body() {
    // Claim body=10 but only 3 actual bytes.
    let mut buf = vec![alpha::FRAME_CLIENT_HELLO];
    varint::encode(10, &mut buf);
    buf.extend_from_slice(b"abc");
    match alpha::decode_frame(&buf) {
        Err(WireError::Short { .. }) => {}
        other => panic!("expected Short, got {other:?}"),
    }
}

#[test]
fn auth_extension_round_trip_random_payload() {
    let mut rng = Rng::new(0x0F0F0F0F0F0F0F0F);
    for _ in 0..50 {
        let ext = AuthExtension {
            version: proteus_spec::PROTEUS_VERSION_V10,
            profile_hint: match rng.byte() % 3 {
                0 => proteus_wire::ProfileHint::Alpha,
                1 => proteus_wire::ProfileHint::Beta,
                _ => proteus_wire::ProfileHint::Gamma,
            },
            client_nonce: rng.bytes(16).try_into().unwrap(),
            client_x25519_pub: rng.bytes(32).try_into().unwrap(),
            client_mlkem768_ct: rng.bytes(1088).try_into().unwrap(),
            client_id: rng.bytes(24).try_into().unwrap(),
            timestamp_unix_seconds: rng.next(),
            cover_profile_id: (rng.next() & 0xff) as u16,
            shape_seed: rng.next() as u32,
            anti_dos_difficulty: rng.byte(),
            anti_dos_solution: rng.bytes(7).try_into().unwrap(),
            client_kex_sig: rng.bytes(64).try_into().unwrap(),
            client_kex_sig_pq: rng.bytes(96).try_into().unwrap(),
            auth_tag: rng.bytes(32).try_into().unwrap(),
        };
        let encoded = ext.encode_payload();
        let decoded = AuthExtension::decode_payload(&encoded).expect("decode ok");
        let re_encoded = decoded.encode_payload();
        assert_eq!(encoded, re_encoded, "round-trip mismatch");
    }
}

#[test]
fn alpha_decode_frame_handles_back_to_back_frames() {
    // Encode three frames, decode them sequentially with draining.
    let mut buf = Vec::new();
    buf.extend_from_slice(&alpha::encode_handshake(
        alpha::FRAME_CLIENT_HELLO,
        b"first",
    ));
    buf.extend_from_slice(&alpha::encode_handshake(
        alpha::FRAME_SERVER_HELLO,
        b"second",
    ));
    buf.extend_from_slice(&alpha::encode_record(alpha::RECORD_DATA, b"third"));

    let (f1, n1) = alpha::decode_frame(&buf).unwrap();
    assert_eq!(f1.body, b"first");
    buf.drain(..n1);

    let (f2, n2) = alpha::decode_frame(&buf).unwrap();
    assert_eq!(f2.body, b"second");
    buf.drain(..n2);

    let (f3, n3) = alpha::decode_frame(&buf).unwrap();
    assert_eq!(f3.body, b"third");
    buf.drain(..n3);

    assert!(buf.is_empty());
}

/// Regression test for the bug that production hit: partial bytes left
/// in the buffer after one decode must NOT be lost.
#[test]
fn alpha_decode_frame_preserves_tail() {
    let mut buf = alpha::encode_handshake(alpha::FRAME_CLIENT_HELLO, b"first");
    buf.extend_from_slice(b"\x99\x99\x99TAIL");
    let (frame, consumed) = alpha::decode_frame(&buf).unwrap();
    assert_eq!(frame.body, b"first");
    let tail = &buf[consumed..];
    assert_eq!(tail, b"\x99\x99\x99TAIL");
}
