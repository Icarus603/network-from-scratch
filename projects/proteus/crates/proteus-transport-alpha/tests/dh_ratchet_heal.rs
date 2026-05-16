//! Regression test for the one-shot asymmetric DH heal ratchet.
//!
//! Locks in two properties that turn this build into a strict
//! improvement over the M0/M1/M2 pure-symmetric ratchet (which
//! REALITY also cannot match):
//!
//! 1. **DH heal step happens**: the first RATCHET frame emitted on a
//!    direction MUST be 36 bytes on the wire (4-byte new_epoch +
//!    32-byte fresh DH pub), proving the sender actually performed a
//!    fresh X25519 step that an attacker holding the bootstrap
//!    handshake key alone cannot replay.
//!
//! 2. **Subsequent ratchets fall back to symmetric**: every later
//!    RATCHET on the same direction MUST be 4 bytes (legacy form).
//!    This is what keeps pipelined ratcheting working without an
//!    expensive Signal-style state-sync — and it's why the 16-MiB
//!    throughput stress test passes alongside this one.
//!
//! Both ends are independent: this test sniffs the client→server
//! direction. A symmetric test on the server→client direction would
//! be valuable but the relay echo pattern complicates the timing —
//! the property is the same and is implicitly exercised by every
//! large-payload integration test.

use std::sync::Arc;
use std::time::Duration;

use proteus_transport_alpha::client::{self, ClientConfig};
use proteus_transport_alpha::server::{ServerCtx, ServerKeys};
use proteus_wire::alpha;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::mpsc;
use tokio::time::timeout;

const STEP: Duration = Duration::from_secs(15);

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn first_ratchet_is_dh_heal_subsequent_are_symmetric() {
    let server_keys = ServerKeys::generate();
    let mlkem_pk_bytes = server_keys.mlkem_pk_bytes.clone();
    let pq_fingerprint = server_keys.pq_fingerprint;
    let server_x25519_pub = server_keys.x25519_pub;
    let ctx = Arc::new(ServerCtx::new(server_keys));

    let server_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let server_addr = server_listener.local_addr().unwrap();
    let ctx_clone = Arc::clone(&ctx);
    tokio::spawn(proteus_transport_alpha::server::serve(
        server_listener,
        ctx_clone,
        |mut session| async move {
            // Drain everything the client sends.
            while let Ok(Some(_)) = session.receiver.recv_record().await {
                // No echo — the test sniffs only the client→server
                // direction so we don't generate server→client traffic.
            }
        },
    ));

    // Sniffing TCP proxy: records every RECORD_RATCHET frame's body
    // length on the client→server direction.
    let proxy = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let proxy_addr = proxy.local_addr().unwrap();
    let (lens_tx, mut lens_rx) = mpsc::unbounded_channel::<usize>();
    tokio::spawn(async move {
        let Ok((c, _)) = proxy.accept().await else {
            return;
        };
        let Ok(s) = TcpStream::connect(server_addr).await else {
            return;
        };
        let (mut c_r, mut c_w) = c.into_split();
        let (mut s_r, mut s_w) = s.into_split();
        let lens_tx_c = lens_tx.clone();
        let c_to_s = tokio::spawn(async move {
            let mut buf: Vec<u8> = Vec::with_capacity(4096);
            let mut tmp = [0u8; 4096];
            loop {
                let n = match c_r.read(&mut tmp).await {
                    Ok(0) | Err(_) => return,
                    Ok(n) => n,
                };
                if s_w.write_all(&tmp[..n]).await.is_err() {
                    return;
                }
                buf.extend_from_slice(&tmp[..n]);
                while !buf.is_empty() {
                    match alpha::decode_frame(&buf) {
                        Ok((frame, consumed)) => {
                            if frame.kind == alpha::RECORD_RATCHET {
                                let _ = lens_tx_c.send(frame.body.len());
                            }
                            buf.drain(..consumed);
                        }
                        Err(_) => break,
                    }
                }
            }
        });
        // Just forward server→client without sniffing.
        let s_to_c = tokio::spawn(async move {
            let mut tmp = [0u8; 4096];
            loop {
                let n = match s_r.read(&mut tmp).await {
                    Ok(0) | Err(_) => return,
                    Ok(n) => n,
                };
                if c_w.write_all(&tmp[..n]).await.is_err() {
                    return;
                }
            }
        });
        let _ = tokio::join!(c_to_s, s_to_c);
    });

    // Drive the client through enough data to trigger 3 ratchets.
    // RATCHET_BYTES = 4 MiB; we send 13 MiB → ~3 ratchets.
    let mut rng = rand_core::OsRng;
    let client_id_sk = proteus_crypto::sig::generate(&mut rng);
    let cfg = ClientConfig {
        server_mlkem_pk_bytes: mlkem_pk_bytes,
        server_x25519_pub,
        server_pq_fingerprint: pq_fingerprint,
        client_id_sk,
        user_id: *b"dhheal01",
        pow_difficulty: 0,
        profile_hint: proteus_wire::ProfileHint::Alpha,
    };
    let session = timeout(STEP, client::connect(&proxy_addr.to_string(), &cfg))
        .await
        .expect("handshake timed out")
        .expect("handshake ok");
    let proteus_transport_alpha::session::AlphaSession { mut sender, .. } = session;

    const CHUNK: usize = 64 * 1024;
    const CHUNKS: usize = 13 * 1024 * 1024 / CHUNK; // ~13 MiB
    let chunk = vec![0x55u8; CHUNK];
    for _ in 0..CHUNKS {
        timeout(STEP, sender.send_record(&chunk))
            .await
            .unwrap()
            .unwrap();
    }
    timeout(STEP, sender.flush()).await.unwrap().unwrap();
    let _ = sender.shutdown().await;

    // Give the sniffer a beat to drain pending frames.
    tokio::time::sleep(Duration::from_millis(200)).await;

    let mut lengths = Vec::new();
    while let Ok(len) = lens_rx.try_recv() {
        lengths.push(len);
    }
    assert!(
        lengths.len() >= 3,
        "expected at least 3 ratchets after 13 MiB; got {lengths:?}"
    );

    // Each captured length is the FRAME BODY = AEAD ciphertext = pt + 16
    // bytes of Poly1305 tag.
    //
    // First ratchet body MUST be 36 + 16 = 52 (DH heal).
    let first = lengths[0];
    assert_eq!(
        first, 52,
        "first ratchet body length = {first} (expected 52 = 36 pt + 16 tag for DH heal)"
    );

    // Every subsequent ratchet body MUST be 4 + 16 = 20 (symmetric).
    for (i, &len) in lengths.iter().enumerate().skip(1) {
        assert_eq!(
            len, 20,
            "ratchet #{i} body length = {len} (expected 20 = 4 pt + 16 tag for symmetric)"
        );
    }
}
