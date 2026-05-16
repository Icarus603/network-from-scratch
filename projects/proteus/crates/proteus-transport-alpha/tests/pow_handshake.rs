//! Verify that the server enforces the anti-DoS proof-of-work setting:
//! - With `pow_difficulty=8`, a client that supplies the correct
//!   difficulty handshakes successfully.
//! - With the same server setting, a client that lies and sends
//!   `pow_difficulty=0` (no work done) is rejected by the server's
//!   PoW check (handshake fails).

use std::sync::Arc;
use std::time::Duration;

use proteus_transport_alpha::client::{self, ClientConfig};
use proteus_transport_alpha::server::{self, ServerCtx, ServerKeys};
use rand_core::OsRng;
use tokio::net::TcpListener;
use tokio::time::timeout;

const STEP: Duration = Duration::from_secs(20);

async fn spawn_server(difficulty: u8) -> (std::net::SocketAddr, Vec<u8>, [u8; 32], [u8; 32]) {
    let server_keys = ServerKeys::generate();
    let mlkem_pk_bytes = server_keys.mlkem_pk_bytes.clone();
    let pq_fingerprint = server_keys.pq_fingerprint;
    let server_x25519_pub = server_keys.x25519_pub;
    let ctx = Arc::new(ServerCtx::new(server_keys).with_pow_difficulty(difficulty));

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let server_ctx = Arc::clone(&ctx);
    tokio::spawn(async move {
        loop {
            let (stream, _) = match listener.accept().await {
                Ok(t) => t,
                Err(_) => return,
            };
            let ctx = Arc::clone(&server_ctx);
            tokio::spawn(async move {
                let mut session = match server::handshake_over_tcp(stream, &ctx).await {
                    Ok(s) => s,
                    Err(_) => return,
                };
                while let Ok(Some(msg)) = session.receiver.recv_record().await {
                    let _ = session.sender.send_record(&msg).await;
                    let _ = session.sender.flush().await;
                }
            });
        }
    });
    (addr, mlkem_pk_bytes, pq_fingerprint, server_x25519_pub)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn handshake_succeeds_when_client_solves_pow() {
    let difficulty = 8u8;
    let (addr, mlkem_pk_bytes, pq_fingerprint, server_x25519_pub) = spawn_server(difficulty).await;

    let mut rng = OsRng;
    let client_id_sk = proteus_crypto::sig::generate(&mut rng);
    let mut client_cfg = ClientConfig::new(
        mlkem_pk_bytes,
        server_x25519_pub,
        pq_fingerprint,
        client_id_sk,
        *b"pow_good",
    );
    client_cfg.pow_difficulty = difficulty; // honest client matches server

    let mut session = timeout(STEP, client::connect(&addr.to_string(), &client_cfg))
        .await
        .expect("connect timed out")
        .expect("handshake should succeed when PoW is solved");

    timeout(STEP, session.sender.send_record(b"hi"))
        .await
        .unwrap()
        .unwrap();
    timeout(STEP, session.sender.flush())
        .await
        .unwrap()
        .unwrap();
    let echoed = timeout(STEP, session.receiver.recv_record())
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    assert_eq!(echoed, b"hi");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn handshake_fails_when_client_skips_pow() {
    let difficulty = 8u8;
    let (addr, mlkem_pk_bytes, pq_fingerprint, server_x25519_pub) = spawn_server(difficulty).await;

    let mut rng = OsRng;
    let client_id_sk = proteus_crypto::sig::generate(&mut rng);
    let mut client_cfg = ClientConfig::new(
        mlkem_pk_bytes,
        server_x25519_pub,
        pq_fingerprint,
        client_id_sk,
        *b"pow_skip",
    );
    client_cfg.pow_difficulty = 0; // lie: claim no work needed

    // Server has no cover endpoint, so a rejected handshake yields a
    // TCP EOF on the client read side. Expect either an explicit error
    // from connect() or an immediate close on the first send.
    let connect_result = timeout(STEP, client::connect(&addr.to_string(), &client_cfg)).await;

    // The server-side reject closes the TCP socket after sending nothing
    // back. Depending on timing, `connect` may surface this as an Err
    // (the read-side returns Closed) or `Ok(session)` whose first
    // send/recv fails. Either is acceptable; the key invariant is that
    // the session cannot survive long enough to echo a record.
    match connect_result {
        Ok(Ok(mut session)) => {
            let _ = session.sender.send_record(b"hi").await;
            let _ = session.sender.flush().await;
            let echoed = timeout(Duration::from_secs(2), session.receiver.recv_record()).await;
            assert!(
                matches!(echoed, Ok(Ok(None)) | Ok(Err(_)) | Err(_)),
                "session should not survive PoW reject"
            );
        }
        Ok(Err(_)) => {
            // Explicit handshake error — fine.
        }
        Err(_) => {
            panic!("client connect timed out — server should reject quickly");
        }
    }
}
