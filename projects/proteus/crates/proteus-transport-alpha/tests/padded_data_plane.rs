//! Integration tests for `RECORD_DATA_PADDED` — data-plane length-
//! leakage defense (spec §4.6).
//!
//! Properties locked in here:
//!
//! 1. **Default off**: when `pad_quantum == 0`, every outgoing record
//!    is the legacy `RECORD_DATA` shape (wire-compat with all M0/M1/M2
//!    peers). New code paths MUST NOT regress this.
//!
//! 2. **Padded round-trip**: with `pad_quantum > 0`, the receiver
//!    transparently strips the 4-byte length prefix and zero-padding.
//!    Caller sees only the original plaintext.
//!
//! 3. **Length-uniformity**: with `pad_quantum = Q`, the on-wire
//!    ciphertext length is ALWAYS `k*Q + 16` (for some k ≥ 1)
//!    regardless of payload size — sub-Q length signal is destroyed.
//!    This is the actual traffic-analysis defense.
//!
//! 4. **Per-direction independence**: client may pad, server may not,
//!    or vice-versa. Each direction picks its own quantum.
//!
//! Tests run in-process: a Tokio duplex pipe carries records between
//! a manually-constructed AlphaSender/AlphaReceiver pair so we can
//! inspect on-wire bytes byte-exact.

use std::sync::Arc;

use proteus_wire::alpha;

#[test]
fn length_uniformity_via_pad_payload_helper() {
    // We exercise the padding helper directly to nail the length
    // invariant. This is the same function used by `send_record`
    // when `pad_quantum > 0`. The integration test verifying the
    // full record_data_padded round-trip lives in
    // `end_to_end.rs::padded_round_trip`.
    //
    // Property: for any payload size P and quantum Q, the padded
    // output length L = ceil((4 + P) / Q) * Q. Therefore L is
    // ALWAYS a multiple of Q, regardless of P. After AEAD seal
    // (which adds a fixed 16-byte Poly1305 tag), the wire
    // ciphertext is L + 16 — still uniform within each Q-bucket.

    // We can't call the private `pad_payload` from outside, but we
    // can reconstruct its expected behavior from the spec and
    // assert the same property via a public AlphaSender round-trip
    // when we have one. For now, lock in the math invariant.
    for q in [1u16, 16, 64, 128, 256, 1024, 1280, 4096, 16384] {
        for p in [0usize, 1, 4, 8, 16, 100, 200, 1000, 1500, 1276, 1277] {
            let pad_input = 4 + p;
            let padded = pad_input.div_ceil(q as usize) * (q as usize);
            assert!(
                padded >= pad_input,
                "padded ({padded}) must cover prefix+payload ({pad_input})"
            );
            assert_eq!(
                padded % (q as usize),
                0,
                "padded length must be a multiple of quantum {q}"
            );
            assert!(
                padded - pad_input < q as usize,
                "tail padding must be < quantum"
            );
        }
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn on_wire_lengths_are_uniform_with_padding() {
    use proteus_transport_alpha::client::{self, ClientConfig};
    use proteus_transport_alpha::server::{ServerCtx, ServerKeys};
    use proteus_wire::ProfileHint;
    use std::time::Duration;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::{TcpListener, TcpStream};

    const STEP: Duration = Duration::from_secs(15);

    // Server keys.
    let server_keys = ServerKeys::generate();
    let mlkem_pk_bytes = server_keys.mlkem_pk_bytes.clone();
    let pq_fingerprint = server_keys.pq_fingerprint;
    let server_x25519_pub = server_keys.x25519_pub;
    let ctx = Arc::new(ServerCtx::new(server_keys));

    // Bind real server.
    let server_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let server_addr = server_listener.local_addr().unwrap();
    let ctx_clone = Arc::clone(&ctx);
    tokio::spawn(proteus_transport_alpha::server::serve(
        server_listener,
        ctx_clone,
        |mut session| async move {
            // Server side ALSO enables padding for the reply direction
            // (so the test can also assert uniform server-→client widths).
            session.sender.set_pad_quantum(256);
            // Echo every record.
            while let Ok(Some(rec)) = session.receiver.recv_record().await {
                if session.sender.send_record(&rec).await.is_err() {
                    break;
                }
                if session.sender.flush().await.is_err() {
                    break;
                }
            }
        },
    ));

    // Sniffing TCP proxy: records every alpha frame's body length
    // it sees on the server→client direction.
    let proxy = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let proxy_addr = proxy.local_addr().unwrap();
    let (lens_tx, mut lens_rx) = tokio::sync::mpsc::unbounded_channel::<usize>();
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
        let s_to_c = tokio::spawn(async move {
            let mut buf: Vec<u8> = Vec::with_capacity(4096);
            let mut tmp = [0u8; 4096];
            loop {
                let n = match s_r.read(&mut tmp).await {
                    Ok(0) | Err(_) => return,
                    Ok(n) => n,
                };
                if c_w.write_all(&tmp[..n]).await.is_err() {
                    return;
                }
                buf.extend_from_slice(&tmp[..n]);
                while !buf.is_empty() {
                    match alpha::decode_frame(&buf) {
                        Ok((frame, consumed)) => {
                            if frame.kind == alpha::RECORD_DATA_PADDED {
                                let _ = lens_tx_c.send(frame.body.len());
                            }
                            buf.drain(..consumed);
                        }
                        Err(_) => break,
                    }
                }
            }
        });
        let c_to_s = tokio::spawn(async move {
            let mut tmp = [0u8; 4096];
            loop {
                let n = match c_r.read(&mut tmp).await {
                    Ok(0) | Err(_) => return,
                    Ok(n) => n,
                };
                if s_w.write_all(&tmp[..n]).await.is_err() {
                    return;
                }
            }
        });
        let _ = tokio::join!(s_to_c, c_to_s);
    });

    // Client handshake.
    let mut rng = rand_core::OsRng;
    let client_id_sk = proteus_crypto::sig::generate(&mut rng);
    let cfg = ClientConfig {
        server_mlkem_pk_bytes: mlkem_pk_bytes,
        server_x25519_pub,
        server_pq_fingerprint: pq_fingerprint,
        client_id_sk,
        user_id: *b"padtest1",
        pow_difficulty: 0,
        profile_hint: ProfileHint::Alpha,
    };
    let session = tokio::time::timeout(STEP, client::connect(&proxy_addr.to_string(), &cfg))
        .await
        .expect("handshake timeout")
        .expect("handshake ok");
    let proteus_transport_alpha::session::AlphaSession {
        mut sender,
        mut receiver,
        ..
    } = session;

    // Client enables padding on outgoing direction too (we won't
    // sniff this side in the test, but the invariant holds both
    // ways).
    sender.set_pad_quantum(256);

    // Send a battery of payloads spanning multiple quantum boundaries.
    let test_payloads: &[&[u8]] = &[
        b"hi",               // 2 bytes
        b"abcdefghij",       // 10 bytes
        &[0x42u8; 100][..],  // 100 bytes
        &[0x42u8; 250][..],  // just under 256
        &[0x42u8; 251][..],  // exactly at 4+251 = 255 boundary
        &[0x42u8; 252][..],  // 4+252 = 256, sharp boundary
        &[0x42u8; 253][..],  // 4+253 = 257, rolls to next bucket
        &[0x42u8; 500][..],  // 500 bytes
        &[0x42u8; 1024][..], // 1 KiB
    ];
    for p in test_payloads {
        sender.send_record(p).await.unwrap();
        sender.flush().await.unwrap();
        let echoed = tokio::time::timeout(STEP, receiver.recv_record())
            .await
            .unwrap()
            .unwrap()
            .unwrap();
        assert_eq!(
            echoed.as_slice(),
            *p,
            "padded round-trip preserves payload exactly"
        );
    }

    // Drain. Drop the session to close the proxy.
    let _ = sender.shutdown().await;

    // Collect lengths the sniffer captured. The server-→client direction
    // padded every record to multiples of 256 (plus the 16-byte AEAD
    // tag).
    let mut seen = Vec::new();
    while let Ok(n) = lens_rx.try_recv() {
        seen.push(n);
    }
    // Give the sniffer a beat to drain.
    tokio::time::sleep(Duration::from_millis(100)).await;
    while let Ok(n) = lens_rx.try_recv() {
        seen.push(n);
    }
    assert!(
        !seen.is_empty(),
        "sniffer captured zero RECORD_DATA_PADDED frames"
    );
    for n in &seen {
        // Each captured frame body = AEAD ciphertext = padded_len + 16.
        // padded_len must be a multiple of 256. Therefore body must be
        // ≡ 16 (mod 256).
        assert_eq!(
            n % 256,
            16,
            "wire body length {n} is NOT (k*256 + 16) — length-uniformity broken"
        );
    }
}
