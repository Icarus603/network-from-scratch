//! Regression test for per-session ephemeral server X25519 (Perfect
//! Forward Secrecy on the classical half).
//!
//! Property: two handshakes against the SAME server must NEVER reuse
//! the same X25519 public-key share in the ServerHello frame. Reuse
//! is a complete classical-FS failure — an adversary who later seizes
//! one session's X25519 secret can recover the K_classic of every
//! captured session, because the same secret was used everywhere.
//!
//! This test sniffs the wire by intercepting the server's accept loop
//! and recording every SH body it emits. We dial twice, then assert
//! the two SH bodies differ. Strict inequality is the property — even
//! one byte of overlap would mean a partial X25519 secret reuse.

use std::sync::Arc;
use std::time::Duration;

use proteus_transport_alpha::client::{self, ClientConfig};
use proteus_transport_alpha::server::{ServerCtx, ServerKeys};
use proteus_wire::alpha::{self, FRAME_SERVER_HELLO};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::time::timeout;

const STEP: Duration = Duration::from_secs(15);

/// Sniffing proxy: relays bytes between client and server, ships an
/// SH-body snapshot through a oneshot channel when it sees one. Keeps
/// running until both halves close so the handshake can actually
/// complete (a sniffer that returns early would tear the proxy down
/// mid-handshake and the client would see Closed).
async fn run_sniff_proxy(
    inbound: TcpListener,
    upstream_addr: std::net::SocketAddr,
    sh_tx: tokio::sync::oneshot::Sender<[u8; 32]>,
) {
    let Ok((c, _)) = inbound.accept().await else {
        return;
    };
    let Ok(s) = TcpStream::connect(upstream_addr).await else {
        return;
    };
    let (mut c_r, mut c_w) = c.into_split();
    let (mut s_r, mut s_w) = s.into_split();

    // s → c with sniff.
    let s_to_c = tokio::spawn(async move {
        let mut buf: Vec<u8> = Vec::with_capacity(4096);
        let mut tmp = [0u8; 4096];
        let mut sh_tx = Some(sh_tx);
        loop {
            let n = match s_r.read(&mut tmp).await {
                Ok(0) | Err(_) => return,
                Ok(n) => n,
            };
            if c_w.write_all(&tmp[..n]).await.is_err() {
                return;
            }
            buf.extend_from_slice(&tmp[..n]);
            // Scan for the FIRST SH frame; once captured, just keep
            // forwarding without parsing.
            if sh_tx.is_some() {
                while !buf.is_empty() {
                    match alpha::decode_frame(&buf) {
                        Ok((frame, consumed)) => {
                            if frame.kind == FRAME_SERVER_HELLO && frame.body.len() == 32 {
                                let mut out = [0u8; 32];
                                out.copy_from_slice(frame.body);
                                if let Some(tx) = sh_tx.take() {
                                    let _ = tx.send(out);
                                }
                                break;
                            }
                            buf.drain(..consumed);
                        }
                        Err(_) => break,
                    }
                }
            }
        }
    });
    // c → s pure forward.
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
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn two_sessions_yield_distinct_server_x25519_pubs() {
    // Single server, generate keys once. The static `x25519_pub` on
    // ServerKeys exists for back-compat of the ClientConfig surface
    // but should NEVER appear in any SH frame after the PFS fix.
    let server_keys = ServerKeys::generate();
    let static_server_x25519_pub = server_keys.x25519_pub;
    let mlkem_pk_bytes = server_keys.mlkem_pk_bytes.clone();
    let pq_fingerprint = server_keys.pq_fingerprint;
    let ctx = Arc::new(ServerCtx::new(server_keys));

    // Spawn the Proteus server.
    let server_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let server_addr = server_listener.local_addr().unwrap();
    let ctx_clone = Arc::clone(&ctx);
    tokio::spawn(proteus_transport_alpha::server::serve(
        server_listener,
        ctx_clone,
        |mut session| async move {
            // Trivial handler — echo one record then close.
            if let Ok(Some(rec)) = session.receiver.recv_record().await {
                let _ = session.sender.send_record(&rec).await;
                let _ = session.sender.flush().await;
            }
        },
    ));

    // Helper: run one handshake through a sniffing proxy and return
    // the SH body.
    async fn one_session(server_addr: std::net::SocketAddr, cfg: &ClientConfig) -> [u8; 32] {
        let proxy = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let proxy_addr = proxy.local_addr().unwrap();
        let (sh_tx, sh_rx) = tokio::sync::oneshot::channel();
        let proxy_task = tokio::spawn(run_sniff_proxy(proxy, server_addr, sh_tx));

        // Connect through the proxy.
        let session = timeout(STEP, client::connect(&proxy_addr.to_string(), cfg))
            .await
            .expect("handshake timed out")
            .expect("handshake ok");
        // Drive one record so the session completes cleanly.
        let proteus_transport_alpha::session::AlphaSession {
            mut sender,
            mut receiver,
            ..
        } = session;
        let _ = sender.send_record(b"ping").await;
        let _ = sender.flush().await;
        let _ = receiver.recv_record().await;
        let _ = sender.shutdown().await;

        let sh = timeout(STEP, sh_rx)
            .await
            .expect("sh_rx timed out")
            .expect("sh_rx sender dropped");
        proxy_task.abort();
        sh
    }

    let mut rng = rand_core::OsRng;
    let mk_cfg = |sk: ed25519_dalek::SigningKey| ClientConfig {
        server_mlkem_pk_bytes: mlkem_pk_bytes.clone(),
        server_x25519_pub: static_server_x25519_pub,
        server_pq_fingerprint: pq_fingerprint,
        client_id_sk: sk,
        user_id: *b"pfstest1",
        pow_difficulty: 0,
        profile_hint: proteus_wire::ProfileHint::Alpha,
    };

    // Two independent handshakes. Each generates a fresh client signing
    // key so the only deliberate variance is the per-session server
    // ephemeral.
    let sk_a = proteus_crypto::sig::generate(&mut rng);
    let sk_b = proteus_crypto::sig::generate(&mut rng);
    let sh_a = one_session(server_addr, &mk_cfg(sk_a)).await;
    let sh_b = one_session(server_addr, &mk_cfg(sk_b)).await;

    assert_ne!(
        sh_a, sh_b,
        "PFS regression: two SH frames carried the SAME X25519 pub. \
         Server is reusing a long-term X25519 key — a future-leak \
         scenario recovers every captured session's K_classic."
    );
    assert_ne!(
        sh_a, static_server_x25519_pub,
        "PFS regression: SH carried the LONG-TERM static X25519 pub \
         instead of a fresh ephemeral. This is the exact bug we fixed."
    );
    assert_ne!(
        sh_b, static_server_x25519_pub,
        "PFS regression: SH carried the LONG-TERM static X25519 pub \
         instead of a fresh ephemeral. This is the exact bug we fixed."
    );
}
