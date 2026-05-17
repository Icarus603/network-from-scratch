//! End-to-end Path A integration test: client → wire bytes →
//! server, via the REAL TLS ClientHello bytes a rustls
//! connector emits.
//!
//! The flow this test exercises is the full Path A loop minus
//! the rustls integration (which is iteration 5):
//!
//!   1. Server side: load PSK → mint ClientHello-side state
//!      (this test fakes the rustls part by crafting a
//!      minimal TLS 1.3 ClientHello with the session_id
//!      we'd inject in iteration 5).
//!   2. Client side: compute_knock(psk, client_random, now)
//!      → encode_session_id(token).
//!   3. Wire: the bytes are inlined into a TLS 1.3 ClientHello
//!      shape (TLS record header + handshake header +
//!      ClientHello body).
//!   4. Server side: parse_client_hello_with_components
//!      extracts client_random + session_id.
//!   5. Server side: decode_and_verify_session_id(psk,
//!      client_random, session_id, now) MUST return Ok.
//!
//! If this passes: the protocol's three layers (cryptographic
//! primitive, wire binding, parser) all agree on the byte
//! shape. Iteration 5's only remaining work is "make rustls
//! actually put our session_id into its ClientHello".

use proteus_fingerprint::ja4::parse_client_hello_with_components;
use proteus_handshake::knock::{compute_knock, KnockPsk, KNOCK_PSK_LEN};
use proteus_handshake::knock_wire::{
    decode_and_verify_session_id, encode_session_id, ENCODED_SESSION_ID_LEN,
};

/// Build a minimal-but-valid TLS 1.3 ClientHello record with
/// the given client_random + session_id. Cipher suites,
/// extensions, etc. are stubs sufficient for the
/// `parse_client_hello_with_components` invariants. NOT a real
/// rustls-emit ClientHello — just enough bytes that the JA4
/// parser walks the record and extracts the fields we care about.
fn craft_minimal_client_hello(client_random: &[u8; 32], session_id: &[u8]) -> Vec<u8> {
    let mut ch_body = Vec::with_capacity(256);
    // legacy_version = 0x0303 (TLS 1.2 — TLS 1.3 advertises via supported_versions)
    ch_body.extend_from_slice(&[0x03, 0x03]);
    // random (32 bytes)
    ch_body.extend_from_slice(client_random);
    // session_id length + bytes
    ch_body.push(session_id.len() as u8);
    ch_body.extend_from_slice(session_id);
    // cipher_suites: length=2, TLS_AES_128_GCM_SHA256 (0x1301)
    ch_body.extend_from_slice(&[0x00, 0x02, 0x13, 0x01]);
    // compression_methods: length=1, null=0
    ch_body.extend_from_slice(&[0x01, 0x00]);
    // extensions: length=0 (none)
    ch_body.extend_from_slice(&[0x00, 0x00]);

    // Handshake header: type=ClientHello(0x01), length (3 bytes)
    let hs_len = ch_body.len();
    let mut hs = Vec::with_capacity(4 + hs_len);
    hs.push(0x01);
    hs.extend_from_slice(&[
        ((hs_len >> 16) & 0xff) as u8,
        ((hs_len >> 8) & 0xff) as u8,
        (hs_len & 0xff) as u8,
    ]);
    hs.extend_from_slice(&ch_body);

    // TLS record: type=Handshake(0x16), version=0x0301, length
    let rec_len = hs.len();
    let mut rec = Vec::with_capacity(5 + rec_len);
    rec.extend_from_slice(&[0x16, 0x03, 0x01]);
    rec.extend_from_slice(&[((rec_len >> 8) & 0xff) as u8, (rec_len & 0xff) as u8]);
    rec.extend_from_slice(&hs);
    rec
}

#[test]
fn full_path_a_round_trip_through_real_clienthello_bytes() {
    let psk = KnockPsk::from_bytes([0xA5; KNOCK_PSK_LEN]);
    let client_random = {
        let mut r = [0u8; 32];
        for (i, b) in r.iter_mut().enumerate() {
            *b = (i as u8).wrapping_mul(7);
        }
        r
    };
    let now = 1_715_900_000u64;

    // ---- Client side ----
    let token = compute_knock(&psk, &client_random, now);
    let session_id = encode_session_id(&token);
    assert_eq!(session_id.len(), ENCODED_SESSION_ID_LEN);

    // ---- Wire ----
    let record_bytes = craft_minimal_client_hello(&client_random, &session_id);

    // ---- Server side ----
    let (_ja4, components) = parse_client_hello_with_components(&record_bytes, 't')
        .expect("crafted ClientHello must parse");
    // Parser extracted the client_random + session_id we put on the wire.
    assert_eq!(components.client_random, client_random);
    assert_eq!(components.session_id, session_id.to_vec());

    // Server's gate: extract session_id + run wire-format verify.
    decode_and_verify_session_id(&psk, &components.client_random, &components.session_id, now)
        .expect("full Path A round-trip must verify end-to-end");
}

#[test]
fn prober_with_random_session_id_fails_at_server_gate() {
    // GFW prober sends a real Chrome-like ClientHello with a
    // RANDOM 32-byte session_id (Chrome's default behavior for
    // middlebox-compatibility). The wire shape is correct; the
    // server's gate MUST reject because the bytes aren't a
    // valid knock.
    let psk = KnockPsk::from_bytes([0xA5; KNOCK_PSK_LEN]);
    let client_random = [0x11; 32];
    let now = 1_715_900_000u64;

    // Probe: random session_id, NO knock token embedded.
    let probe_session_id = {
        let mut s = [0u8; 32];
        for (i, b) in s.iter_mut().enumerate() {
            *b = (i as u8).wrapping_add(99);
        }
        s
    };
    let record_bytes = craft_minimal_client_hello(&client_random, &probe_session_id);

    let (_ja4, components) = parse_client_hello_with_components(&record_bytes, 't').unwrap();
    let err =
        decode_and_verify_session_id(&psk, &components.client_random, &components.session_id, now)
            .expect_err("random session_id MUST fail server gate");
    // Error variant should be Knock(BadTag), NOT Decode(WrongLength).
    use proteus_handshake::knock_wire::KnockWireError;
    assert!(
        matches!(err, KnockWireError::Knock(_)),
        "probe with correct-length-but-random session_id must surface as Knock error, got {err:?}"
    );
}

#[test]
fn captured_session_id_replayed_against_fresh_client_random_fails() {
    // Adversary captures a real client's ClientHello. Replays
    // the same session_id (=> same knock token) but to a NEW
    // TLS handshake with a different client_random. The
    // server's gate MUST reject — the cryptographic binding to
    // client_random is the whole point.
    let psk = KnockPsk::from_bytes([0xA5; KNOCK_PSK_LEN]);
    let original_random = [0x33; 32];
    let now = 1_715_900_000u64;
    let token = compute_knock(&psk, &original_random, now);
    let session_id = encode_session_id(&token);

    // Adversary's NEW handshake.
    let new_random = [0x44; 32];
    let record_bytes = craft_minimal_client_hello(&new_random, &session_id);
    let (_ja4, components) = parse_client_hello_with_components(&record_bytes, 't').unwrap();

    let err =
        decode_and_verify_session_id(&psk, &components.client_random, &components.session_id, now)
            .expect_err("replayed session_id with NEW client_random MUST fail");
    use proteus_handshake::knock_wire::KnockWireError;
    assert!(matches!(err, KnockWireError::Knock(_)));
}

#[test]
fn clienthello_with_zero_byte_session_id_is_rejected_cleanly() {
    // Some TLS 1.3 stacks legitimately emit a 0-byte
    // session_id (RFC 8446 allows). MUST NOT crash; must
    // surface as WrongLength so the server's gate routes to
    // cover (no knock present).
    let psk = KnockPsk::from_bytes([0xA5; KNOCK_PSK_LEN]);
    let client_random = [0x55; 32];
    let now = 1_715_900_000u64;
    let record_bytes = craft_minimal_client_hello(&client_random, &[]);
    let (_ja4, components) = parse_client_hello_with_components(&record_bytes, 't').unwrap();
    assert!(components.session_id.is_empty());
    let err =
        decode_and_verify_session_id(&psk, &components.client_random, &components.session_id, now)
            .unwrap_err();
    use proteus_handshake::knock_wire::{DecodeError, KnockWireError};
    assert!(matches!(
        err,
        KnockWireError::Decode(DecodeError::WrongLength { got: 0 })
    ));
}
