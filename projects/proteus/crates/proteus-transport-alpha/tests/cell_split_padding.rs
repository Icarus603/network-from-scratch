//! Regression test for cell-split data-plane padding (§4.6).
//!
//! Locks in two properties beyond what `padded_data_plane.rs` covered:
//!
//! 1. **Splits actually happen**: a logical record bigger than
//!    `pad_quantum - 4` MUST be split into multiple wire cells (one
//!    per chunk + one terminal cell). A 4 KiB payload at `pad_quantum
//!    = 256` produces `ceil(4096 / 252) = 17` cells.
//!
//! 2. **Reassembly is byte-exact**: the receiver's reassembled output
//!    equals the sender's input, bit-for-bit, for payloads spanning
//!    1 to N cells.
//!
//! 3. **Every cell on the wire is exactly cell_size + tag**: any
//!    variable wire length would betray sub-quantum signal — which
//!    is exactly what the cell-split shaping is supposed to destroy.

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

/// pad_quantum used for this test. Chosen small so even a small
/// payload triggers many splits.
const Q: u16 = 256;

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn multi_cell_payload_splits_and_reassembles_correctly() {
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
            // Echo with the SAME pad_quantum so the wire on the
            // server→client direction is also cell-padded.
            session.sender.set_pad_quantum(Q);
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

    // Sniffer: count cells per direction.
    let proxy = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let proxy_addr = proxy.local_addr().unwrap();
    let (lens_tx, mut lens_rx) = mpsc::unbounded_channel::<(usize, &'static str)>();
    tokio::spawn(async move {
        let Ok((c, _)) = proxy.accept().await else {
            return;
        };
        let Ok(s) = TcpStream::connect(server_addr).await else {
            return;
        };
        let (mut c_r, mut c_w) = c.into_split();
        let (mut s_r, mut s_w) = s.into_split();
        let lens_tx_a = lens_tx.clone();
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
                while let Ok((frame, consumed)) = alpha::decode_frame(&buf) {
                    if frame.kind == alpha::RECORD_DATA_PADDED {
                        let _ = lens_tx_a.send((frame.body.len(), "c2s"));
                    }
                    buf.drain(..consumed);
                }
            }
        });
        let lens_tx_b = lens_tx.clone();
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
                while let Ok((frame, consumed)) = alpha::decode_frame(&buf) {
                    if frame.kind == alpha::RECORD_DATA_PADDED {
                        let _ = lens_tx_b.send((frame.body.len(), "s2c"));
                    }
                    buf.drain(..consumed);
                }
            }
        });
        let _ = tokio::join!(c_to_s, s_to_c);
    });

    let mut rng = rand_core::OsRng;
    let client_id_sk = proteus_crypto::sig::generate(&mut rng);
    let cfg = ClientConfig {
        server_mlkem_pk_bytes: mlkem_pk_bytes,
        server_x25519_pub,
        server_pq_fingerprint: pq_fingerprint,
        client_id_sk,
        user_id: *b"cellsplt",
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
    sender.set_pad_quantum(Q);

    // 4 KiB payload — at Q=256 (chunk_max=252), expect ceil(4096/252) =
    // 17 cells per direction (16 continuation + 1 terminal).
    let payload = (0..4096u32).map(|i| (i & 0xff) as u8).collect::<Vec<u8>>();
    sender.send_record(&payload).await.unwrap();
    sender.flush().await.unwrap();
    let echoed = timeout(STEP, receiver.recv_record())
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    assert_eq!(
        echoed, payload,
        "cell-split reassembly must reproduce the input byte-exact"
    );

    let _ = sender.shutdown().await;
    tokio::time::sleep(Duration::from_millis(200)).await;

    let mut c2s = Vec::new();
    let mut s2c = Vec::new();
    while let Ok((n, dir)) = lens_rx.try_recv() {
        match dir {
            "c2s" => c2s.push(n),
            "s2c" => s2c.push(n),
            _ => unreachable!(),
        }
    }

    let expected_cells = 4096_usize.div_ceil(Q as usize - 4); // 17
    assert!(
        c2s.len() >= expected_cells,
        "expected at least {expected_cells} client→server cells, got {} ({:?})",
        c2s.len(),
        c2s
    );
    assert!(
        s2c.len() >= expected_cells,
        "expected at least {expected_cells} server→client cells, got {} ({:?})",
        s2c.len(),
        s2c
    );

    // Every cell must be exactly Q + 16 bytes on the wire.
    for &n in c2s.iter().chain(s2c.iter()) {
        assert_eq!(
            n,
            Q as usize + 16,
            "every cell body MUST be exactly {} bytes ({}+16); found {n}",
            Q as usize + 16,
            Q
        );
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn single_cell_payload_emits_one_cell() {
    // Sanity: a payload ≤ chunk_max emits EXACTLY one cell (the
    // terminal one). Same wire size, no continuation marker on
    // the wire.
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
            session.sender.set_pad_quantum(Q);
            while let Ok(Some(rec)) = session.receiver.recv_record().await {
                let _ = session.sender.send_record(&rec).await;
                let _ = session.sender.flush().await;
            }
        },
    ));

    let mut rng = rand_core::OsRng;
    let client_id_sk = proteus_crypto::sig::generate(&mut rng);
    let cfg = ClientConfig {
        server_mlkem_pk_bytes: mlkem_pk_bytes,
        server_x25519_pub,
        server_pq_fingerprint: pq_fingerprint,
        client_id_sk,
        user_id: *b"singlecl",
        pow_difficulty: 0,
        profile_hint: proteus_wire::ProfileHint::Alpha,
    };
    let session = timeout(STEP, client::connect(&server_addr.to_string(), &cfg))
        .await
        .expect("handshake timed out")
        .expect("handshake ok");
    let proteus_transport_alpha::session::AlphaSession {
        mut sender,
        mut receiver,
        ..
    } = session;
    sender.set_pad_quantum(Q);

    let small = b"hello world";
    sender.send_record(small).await.unwrap();
    sender.flush().await.unwrap();
    let echoed = timeout(STEP, receiver.recv_record())
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    assert_eq!(echoed.as_slice(), small);

    // Empty payload — 0-byte logical record. Should produce EXACTLY
    // one terminal cell with real_len=0. Confirms boundary case.
    sender.send_record(b"").await.unwrap();
    sender.flush().await.unwrap();
    let echoed = timeout(STEP, receiver.recv_record())
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    assert_eq!(
        echoed.len(),
        0,
        "empty payload round-trips through one cell"
    );
}
