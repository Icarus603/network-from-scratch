//! Iter-138: a malformed `server_mlkem_pk_bytes` in the client
//! configuration MUST surface a typed `AlphaError::BadServerKey`,
//! NOT panic the client binary.
//!
//! Pre-iter-138 the client handshake parsed the EK with
//! `.expect("mlkem pk")` and a configuration error (operator typo
//! in `client.yaml`, base64 decode gone wrong, truncated key, etc.)
//! aborted the binary via the panic hook. systemd then restarted
//! the binary in a tight loop with no actionable signal to the
//! operator about WHAT was wrong with their configuration.
//!
//! This test exercises every failure mode the EK parse can take:
//! wrong length (too short / too long) + correct length but
//! contents the underlying ml_kem crate can't parse (we use the
//! length gate as the primary defense; the second arm is
//! belt-and-braces).

use proteus_transport_alpha::client::{handshake_over_tcp, ClientConfig};
use proteus_transport_alpha::error::AlphaError;
use proteus_transport_alpha::ProfileHint;
use rand_core::OsRng;
use tokio::net::TcpListener;

fn build_cfg(mlkem_pk_bytes: Vec<u8>) -> ClientConfig {
    let mut rng = OsRng;
    let client_id_sk = proteus_crypto::sig::generate(&mut rng);
    ClientConfig {
        server_mlkem_pk_bytes: mlkem_pk_bytes,
        server_x25519_pub: [0u8; 32],
        server_pq_fingerprint: [0u8; 32],
        client_id_sk,
        user_id: *b"test____",
        pow_difficulty: 0,
        profile_hint: ProfileHint::Alpha,
    }
}

#[tokio::test]
async fn empty_mlkem_pk_bytes_returns_bad_server_key_not_panic() {
    // Listener exists so the TCP connect succeeds; the handshake
    // function should hit the EK-parse gate BEFORE any wire I/O.
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        let _ = listener.accept().await;
    });
    let stream = tokio::net::TcpStream::connect(addr).await.unwrap();
    let cfg = build_cfg(Vec::new());
    let res = handshake_over_tcp(stream, &cfg).await;
    match res {
        Err(AlphaError::BadServerKey(msg)) => {
            assert!(
                msg.contains("ML-KEM-768"),
                "error message must name the key type: {msg}"
            );
        }
        Err(e) => panic!("expected BadServerKey, got {e:?}"),
        Ok(_) => panic!("expected BadServerKey, got Ok(_)"),
    }
}

#[tokio::test]
async fn truncated_mlkem_pk_bytes_returns_bad_server_key() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        let _ = listener.accept().await;
    });
    let stream = tokio::net::TcpStream::connect(addr).await.unwrap();
    let cfg = build_cfg(vec![0u8; 100]); // 100 << 1184
    let res = handshake_over_tcp(stream, &cfg).await;
    assert!(
        matches!(res, Err(AlphaError::BadServerKey(_))),
        "expected BadServerKey for 100-byte EK, got Err(other) or Ok"
    );
}

#[tokio::test]
async fn oversized_mlkem_pk_bytes_returns_bad_server_key() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        let _ = listener.accept().await;
    });
    let stream = tokio::net::TcpStream::connect(addr).await.unwrap();
    let cfg = build_cfg(vec![0u8; 4096]); // 4096 >> 1184
    let res = handshake_over_tcp(stream, &cfg).await;
    assert!(
        matches!(res, Err(AlphaError::BadServerKey(_))),
        "expected BadServerKey for 4096-byte EK, got Err(other) or Ok"
    );
}

#[tokio::test]
async fn correct_length_garbage_mlkem_pk_bytes_returns_bad_server_key_or_handshake_failure() {
    // 1184 bytes of zeros — passes the length gate but is not a
    // valid encoding under FIPS-203. The underlying `from_bytes`
    // does NOT itself error (the ml_kem crate parses bytes
    // optimistically) — the failure surfaces later during
    // encapsulate. We accept either outcome here; the test's
    // job is to prove the client doesn't PANIC.
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        let _ = listener.accept().await;
    });
    let stream = tokio::net::TcpStream::connect(addr).await.unwrap();
    let cfg = build_cfg(vec![0u8; 1184]);
    let res = handshake_over_tcp(stream, &cfg).await;
    // Any Err is acceptable — the contract is "no panic". We just
    // assert the function returned without unwinding the test.
    assert!(
        res.is_err(),
        "expected an error from handshake against all-zero EK, got Ok"
    );
}
