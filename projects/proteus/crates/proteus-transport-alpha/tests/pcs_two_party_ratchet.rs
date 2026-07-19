//! Production-path regression for the v1.3 fresh/fresh PCS ratchet.
//!
//! A 13 MiB one-way upload crosses three 4 MiB rekey boundaries. The
//! otherwise-idle server send half must wake to emit its OFFER/COMMIT,
//! and the otherwise-idle client receive half must consume those
//! controls so the client can commit. Every generation contributes
//! fresh X25519 shares from both endpoints.
//!
//! The sniffed client→server wire must contain matching 56-byte
//! ciphertext OFFER/COMMIT controls and no legacy `RECORD_RATCHET`.

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
async fn one_way_upload_completes_three_fresh_fresh_generations() {
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
        |session| async move {
            let proteus_transport_alpha::session::AlphaSession {
                mut sender,
                mut receiver,
                ..
            } = session;
            loop {
                tokio::select! {
                    biased;
                    pending = sender.wait_for_pcs_control() => {
                        if pending && sender.drive_two_party_pcs().await.is_err() {
                            break;
                        }
                    }
                    record = receiver.recv_record() => {
                        if !matches!(record, Ok(Some(_))) {
                            break;
                        }
                    }
                }
            }
        },
    ));

    // Sniffing TCP proxy: record every rekey control type/body length
    // on the client→server direction.
    let proxy = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let proxy_addr = proxy.local_addr().unwrap();
    let (controls_tx, mut controls_rx) = mpsc::unbounded_channel::<(u8, usize)>();
    tokio::spawn(async move {
        let Ok((c, _)) = proxy.accept().await else {
            return;
        };
        let Ok(s) = TcpStream::connect(server_addr).await else {
            return;
        };
        let (mut c_r, mut c_w) = c.into_split();
        let (mut s_r, mut s_w) = s.into_split();
        let controls_tx_c = controls_tx.clone();
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
                            if matches!(
                                frame.kind,
                                alpha::RECORD_RATCHET
                                    | alpha::RECORD_PCS_OFFER
                                    | alpha::RECORD_PCS_COMMIT
                            ) {
                                let _ = controls_tx_c.send((frame.kind, frame.body.len()));
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
    let proteus_transport_alpha::session::AlphaSession {
        mut sender,
        mut receiver,
        ..
    } = session;
    let mut receiver_task = tokio::spawn(async move {
        loop {
            match receiver.recv_record().await {
                Ok(Some(_)) => {}
                Ok(None) => return Ok::<(), String>(()),
                Err(error) => return Err(error.to_string()),
            }
        }
    });

    const CHUNK: usize = 64 * 1024;
    const CHUNKS: usize = 13 * 1024 * 1024 / CHUNK; // ~13 MiB
    let chunk = vec![0x55u8; CHUNK];
    for i in 0..CHUNKS {
        timeout(STEP, sender.send_record(&chunk))
            .await
            .unwrap()
            .unwrap();
        // The 65th, 130th, and 195th sends initiate generations 1-3
        // (the threshold is checked before each send). Wait for the
        // otherwise-idle reverse path to deliver the peer controls,
        // then install the local commit before measuring the next
        // 4 MiB window.
        if i >= 64 && (i - 64) % 65 == 0 {
            let pending = tokio::select! {
                response = timeout(STEP, sender.wait_for_pcs_control()) => {
                    response.expect("peer PCS response timed out")
                }
                result = &mut receiver_task => {
                    panic!("client receive half exited during PCS: {result:?}")
                }
            };
            assert!(pending, "peer PCS response did not queue local control");
            timeout(STEP, sender.drive_two_party_pcs())
                .await
                .expect("local PCS commit timed out")
                .expect("local PCS commit failed");
        }
    }
    timeout(STEP, sender.flush()).await.unwrap().unwrap();
    let _ = sender.shutdown().await;
    receiver_task.abort();

    // Give the sniffer a beat to drain pending frames.
    tokio::time::sleep(Duration::from_millis(200)).await;

    let mut controls = Vec::new();
    while let Ok(control) = controls_rx.try_recv() {
        controls.push(control);
    }
    let offers = controls
        .iter()
        .filter(|(kind, _)| *kind == alpha::RECORD_PCS_OFFER)
        .count();
    let commits = controls
        .iter()
        .filter(|(kind, _)| *kind == alpha::RECORD_PCS_COMMIT)
        .count();
    assert!(
        offers >= 3 && commits >= 3,
        "expected at least 3 OFFER/COMMIT pairs after 13 MiB; got {controls:?}"
    );
    for (kind, len) in &controls {
        assert_ne!(
            *kind,
            alpha::RECORD_RATCHET,
            "v1.3 emitted forbidden legacy RECORD_RATCHET"
        );
        assert_eq!(
            *len, 56,
            "PCS control ciphertext must be 40-byte plaintext + 16-byte tag"
        );
    }
}
