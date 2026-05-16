//! Regression test for cover-traffic heartbeat cells.
//!
//! Locks in three properties of the heartbeat shaping primitive:
//!
//! 1. **Wire indistinguishability**: a heartbeat cell on the wire is
//!    byte-identical in length and frame type to a real data cell.
//!    A passive observer counting cells per second cannot tell
//!    "session is idle, emitting cover" from "session is bulk-
//!    transferring".
//!
//! 2. **Receiver silently consumes**: `recv_record` MUST skip
//!    heartbeats — they never surface as `Ok(Some(...))` to the
//!    application layer. Mixing heartbeats between real data
//!    records must preserve the exact data stream.
//!
//! 3. **Metrics counters tick**: `metrics.heartbeats_sent` /
//!    `heartbeats_recv` increment per cover cell. This is the only
//!    operator-visible signal that cover traffic is being emitted —
//!    important for capacity planning.

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
const Q: u16 = 256;

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn heartbeat_cell_is_wire_indistinguishable_from_data_cell() {
    let server_keys = ServerKeys::generate();
    let mlkem_pk_bytes = server_keys.mlkem_pk_bytes.clone();
    let pq_fingerprint = server_keys.pq_fingerprint;
    let server_x25519_pub = server_keys.x25519_pub;
    let ctx = Arc::new(ServerCtx::new(server_keys));

    let server_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let server_addr = server_listener.local_addr().unwrap();
    let (received_tx, mut received_rx) = mpsc::unbounded_channel::<Vec<u8>>();
    let ctx_clone = Arc::clone(&ctx);
    tokio::spawn(proteus_transport_alpha::server::serve(
        server_listener,
        ctx_clone,
        move |mut session| {
            let tx = received_tx.clone();
            async move {
                while let Ok(Some(rec)) = session.receiver.recv_record().await {
                    if tx.send(rec).is_err() {
                        break;
                    }
                }
                // The heartbeats SHOULD NOT show up here — receiver
                // strips them silently. If they did, the assertion
                // below would fail.
            }
        },
    ));

    // Sniffer: capture every RECORD_DATA_PADDED frame's body length on
    // the client→server direction.
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
                while let Ok((frame, consumed)) = alpha::decode_frame(&buf) {
                    if frame.kind == alpha::RECORD_DATA_PADDED {
                        let _ = lens_tx_c.send(frame.body.len());
                    }
                    buf.drain(..consumed);
                }
            }
        });
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

    let mut rng = rand_core::OsRng;
    let client_id_sk = proteus_crypto::sig::generate(&mut rng);
    let cfg = ClientConfig {
        server_mlkem_pk_bytes: mlkem_pk_bytes,
        server_x25519_pub,
        server_pq_fingerprint: pq_fingerprint,
        client_id_sk,
        user_id: *b"hbcover1",
        pow_difficulty: 0,
        profile_hint: proteus_wire::ProfileHint::Alpha,
    };
    let session = timeout(STEP, client::connect(&proxy_addr.to_string(), &cfg))
        .await
        .expect("handshake")
        .expect("handshake ok");
    let proteus_transport_alpha::session::AlphaSession {
        mut sender,
        receiver,
        metrics,
        ..
    } = session;
    sender.set_pad_quantum(Q);

    // Interleave: data, heartbeat, heartbeat, data, heartbeat, data.
    // After this sequence, the server's `received_rx` should contain
    // EXACTLY the three data payloads in order — heartbeats are
    // invisible at the application layer.
    let data: &[&[u8]] = &[
        b"first-real-record",
        b"second-real-record",
        b"third-real-record",
    ];

    sender.send_record(data[0]).await.unwrap();
    sender.send_heartbeat().await.unwrap();
    sender.send_heartbeat().await.unwrap();
    sender.send_record(data[1]).await.unwrap();
    sender.send_heartbeat().await.unwrap();
    sender.send_record(data[2]).await.unwrap();
    sender.flush().await.unwrap();

    // Drain expected payloads from the server side.
    for expected in data {
        let got = timeout(STEP, received_rx.recv())
            .await
            .expect("server never received expected payload")
            .expect("server channel closed unexpectedly");
        assert_eq!(
            got.as_slice(),
            *expected,
            "heartbeats must not corrupt the data stream"
        );
    }

    let _ = sender.shutdown().await;
    drop(receiver);
    tokio::time::sleep(Duration::from_millis(200)).await;

    // Collect all sniffed cell lengths. The client emitted 3 data
    // records + 3 heartbeats = 6 cells (each fits in one cell since
    // data payloads are smaller than Q-4=252 bytes).
    let mut lengths = Vec::new();
    while let Ok(n) = lens_rx.try_recv() {
        lengths.push(n);
    }
    assert!(
        lengths.len() >= 6,
        "expected ≥6 c→s cells (3 data + 3 heartbeat); got {} ({:?})",
        lengths.len(),
        lengths
    );

    // PROPERTY: every cell on the wire is exactly Q+16 bytes. A
    // passive observer cannot use length to tell data from
    // heartbeat — that's the whole point of cover traffic.
    for &n in &lengths {
        assert_eq!(
            n,
            Q as usize + 16,
            "every cell (data OR heartbeat) MUST be {} bytes; got {n}",
            Q as usize + 16,
        );
    }

    // PROPERTY: metrics counter ticks for the heartbeats.
    let snap = metrics.snapshot();
    assert_eq!(
        snap.heartbeats_sent, 3,
        "heartbeats_sent counter MUST be 3 (we emitted 3); got {}",
        snap.heartbeats_sent
    );
    // tx_records counts ALL cells emitted (3 data records, multi-cell
    // for some, plus heartbeats wouldn't increment record_tx since
    // record_tx is only called for application payloads). Note that
    // each data record's send_record() bumps tx_records exactly once
    // regardless of cell count.
    assert_eq!(
        snap.tx_records, 3,
        "tx_records counter MUST be 3 application records; got {}",
        snap.tx_records,
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn heartbeat_requires_cell_mode() {
    // Heartbeats are wire-indistinguishable ONLY when cell-mode is on.
    // Calling send_heartbeat in non-padded mode must error out cleanly
    // rather than emit a distinguishable record type.
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
        |mut session| async move { while let Ok(Some(_)) = session.receiver.recv_record().await {} },
    ));

    let mut rng = rand_core::OsRng;
    let client_id_sk = proteus_crypto::sig::generate(&mut rng);
    let cfg = ClientConfig {
        server_mlkem_pk_bytes: mlkem_pk_bytes,
        server_x25519_pub,
        server_pq_fingerprint: pq_fingerprint,
        client_id_sk,
        user_id: *b"hbnopad1",
        pow_difficulty: 0,
        profile_hint: proteus_wire::ProfileHint::Alpha,
    };
    let session = timeout(STEP, client::connect(&server_addr.to_string(), &cfg))
        .await
        .expect("handshake")
        .expect("handshake ok");
    let proteus_transport_alpha::session::AlphaSession { mut sender, .. } = session;
    // pad_quantum is 0 by default; do NOT set it.
    let res = sender.send_heartbeat().await;
    assert!(
        res.is_err(),
        "send_heartbeat in non-cell-mode must error; got {res:?}"
    );
}
