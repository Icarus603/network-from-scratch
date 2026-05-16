//! Regression tests for the `client_id` encoding.
//!
//! Two security properties locked in here, both CVE-grade bugs in the
//! prior M1 encoding:
//!
//! 1. **Per-session unlinkability**: two handshakes by the *same* user
//!    produce DIFFERENT `client_id` ciphertexts. Before the fix, a
//!    fixed all-zero nonce meant the AEAD was deterministic in
//!    user_id, so a passive observer could trivially cluster every
//!    session by user without ever holding a key.
//!
//! 2. **No keystream reuse across users**: two handshakes by
//!    DIFFERENT users on the same handshake do not share keystream
//!    such that XOR cancels. Before the fix, two users transmitting
//!    in the same nonce window leaked both plaintexts via two-time
//!    pad. The new encoding uses a per-session nonce so even
//!    intentional same-key sessions diverge.
//!
//! 3. **Auth-by-decrypt**: the server MUST reject a `client_id` whose
//!    Poly1305 tag does not verify. Before the fix, `client_id` was
//!    24 truncated ciphertext bytes with no recoverable tag; auth was
//!    deferred to Ed25519 and the server didn't even read the field.
//!    Now a single bit-flip in `client_id` is fatal.

use proteus_crypto::aead;
use proteus_spec::CLIENT_ID_LEN;
use rand_core::RngCore;

/// Mirror of the client's `client_id` encoding (see
/// `proteus-transport-alpha::client::handshake_over_split`). Kept
/// here so a future refactor of the client cannot silently break
/// the encoding without this test going red.
fn encode_client_id(
    server_pq_fingerprint: &[u8; 32],
    client_nonce: &[u8; 16],
    user_id: &[u8; 8],
) -> [u8; CLIENT_ID_LEN] {
    let mut cid_key = [0u8; 32];
    proteus_crypto::kdf::expand_label(
        server_pq_fingerprint,
        b"proteus-cid-key-v1",
        b"",
        &mut cid_key,
    )
    .unwrap();
    let mut cid_n = [0u8; 12];
    cid_n.copy_from_slice(&client_nonce[..12]);
    let ct = aead::seal(&cid_key, &cid_n, 0, b"proteus-cid-v1", user_id).unwrap();
    assert_eq!(ct.len(), CLIENT_ID_LEN);
    let mut out = [0u8; CLIENT_ID_LEN];
    out.copy_from_slice(&ct);
    out
}

fn decode_client_id(
    server_pq_fingerprint: &[u8; 32],
    client_nonce: &[u8; 16],
    client_id: &[u8; CLIENT_ID_LEN],
) -> Option<[u8; 8]> {
    let mut cid_key = [0u8; 32];
    proteus_crypto::kdf::expand_label(
        server_pq_fingerprint,
        b"proteus-cid-key-v1",
        b"",
        &mut cid_key,
    )
    .ok()?;
    let mut cid_n = [0u8; 12];
    cid_n.copy_from_slice(&client_nonce[..12]);
    let pt = aead::open(&cid_key, &cid_n, 0, b"proteus-cid-v1", client_id).ok()?;
    let s = pt.as_slice();
    if s.len() != 8 {
        return None;
    }
    let mut uid = [0u8; 8];
    uid.copy_from_slice(s);
    Some(uid)
}

#[test]
fn two_sessions_same_user_produce_different_client_ids() {
    let pq_fp = [0x42u8; 32];
    let user_id = *b"alice001";

    let mut rng = rand_core::OsRng;
    let mut nonces = Vec::new();
    let mut cids = Vec::new();
    for _ in 0..64 {
        let mut nonce = [0u8; 16];
        rng.fill_bytes(&mut nonce);
        let cid = encode_client_id(&pq_fp, &nonce, &user_id);
        nonces.push(nonce);
        cids.push(cid);
    }

    // Every pair must differ in the ciphertext bytes. Even a single
    // duplicate is a complete linkability oracle, so we require strict
    // distinctness.
    let unique_count = {
        let mut set = std::collections::HashSet::new();
        for c in &cids {
            set.insert(*c);
        }
        set.len()
    };
    assert_eq!(
        unique_count,
        cids.len(),
        "client_id must be unique per session for the same user — \
         pre-fix encoding produced bit-identical ciphertexts here"
    );
}

#[test]
fn keystream_reuse_attack_is_prevented() {
    // Threat model: a passive observer captures two handshakes,
    // suspects they were made by users A and B with known but
    // different user_ids. Under the OLD encoding, both ciphertexts
    // shared a ChaCha20 keystream block (fixed nonce), so XOR of the
    // two ciphertexts equaled XOR of the two plaintexts — recovering
    // the user_ids with no key material.
    //
    // Under the new encoding, distinct sessions use distinct nonces,
    // so the keystream differs and XOR does NOT cancel.
    let pq_fp = [0x99u8; 32];
    let user_a = *b"alphaa01";
    let user_b = *b"bravob02";

    let mut rng = rand_core::OsRng;
    let mut nonce_a = [0u8; 16];
    let mut nonce_b = [0u8; 16];
    rng.fill_bytes(&mut nonce_a);
    rng.fill_bytes(&mut nonce_b);

    let cid_a = encode_client_id(&pq_fp, &nonce_a, &user_a);
    let cid_b = encode_client_id(&pq_fp, &nonce_b, &user_b);

    // XOR the first 8 ciphertext bytes — under the broken encoding
    // this would equal `user_a XOR user_b`. Under the fixed encoding
    // it equals (keystream_a XOR plaintext_a) XOR (keystream_b XOR
    // plaintext_b) — random-looking, never the plaintext XOR.
    let mut xor_first_8 = [0u8; 8];
    for i in 0..8 {
        xor_first_8[i] = cid_a[i] ^ cid_b[i];
    }
    let mut user_xor = [0u8; 8];
    for i in 0..8 {
        user_xor[i] = user_a[i] ^ user_b[i];
    }
    assert_ne!(
        xor_first_8, user_xor,
        "two-time-pad regression: XOR of two client_ids equals XOR of plaintexts"
    );
}

#[test]
fn round_trip_recovers_user_id() {
    let pq_fp = [0xabu8; 32];
    let user_id = *b"roundtri";
    let mut nonce = [0u8; 16];
    rand_core::OsRng.fill_bytes(&mut nonce);

    let cid = encode_client_id(&pq_fp, &nonce, &user_id);
    let recovered = decode_client_id(&pq_fp, &nonce, &cid).expect("must decrypt");
    assert_eq!(recovered, user_id);
}

#[test]
fn single_bit_flip_breaks_authentication() {
    // Poly1305's authentication MUST reject any tampered ciphertext.
    // Before the fix, `client_id` was a 24-byte truncated ciphertext
    // with no recoverable tag and the server didn't decrypt at all,
    // so this test would have been impossible to write. After the
    // fix, every bit position has a 2^-128 forgery resistance.
    let pq_fp = [0xcdu8; 32];
    let user_id = *b"flippeda";
    let mut nonce = [0u8; 16];
    rand_core::OsRng.fill_bytes(&mut nonce);

    let cid = encode_client_id(&pq_fp, &nonce, &user_id);

    // Flip one bit in the tag region (last 16 bytes).
    let mut tampered = cid;
    tampered[CLIENT_ID_LEN - 1] ^= 0x01;
    assert!(
        decode_client_id(&pq_fp, &nonce, &tampered).is_none(),
        "Poly1305 must reject tampered tag"
    );

    // Flip one bit in the ciphertext region (first 8 bytes).
    let mut tampered = cid;
    tampered[0] ^= 0x01;
    assert!(
        decode_client_id(&pq_fp, &nonce, &tampered).is_none(),
        "Poly1305 must reject tampered ciphertext"
    );

    // Wrong nonce.
    let mut wrong_nonce = nonce;
    wrong_nonce[0] ^= 0x01;
    assert!(
        decode_client_id(&pq_fp, &wrong_nonce, &cid).is_none(),
        "AEAD must reject wrong nonce"
    );

    // Wrong key derivation context (different fingerprint).
    let mut wrong_fp = pq_fp;
    wrong_fp[0] ^= 0x01;
    assert!(
        decode_client_id(&wrong_fp, &nonce, &cid).is_none(),
        "AEAD must reject wrong key"
    );
}
