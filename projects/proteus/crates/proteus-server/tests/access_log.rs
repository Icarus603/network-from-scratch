//! End-to-end access-log integration test.
//!
//! Stand up an in-process Proteus server with a tempfile-backed
//! AccessLogger and a client allowlist that authenticates one user.
//! The client opens a session, sends a CONNECT to an echo upstream,
//! ping-pongs a small payload, then drops. The server must emit
//! exactly one JSON Lines record describing the session — including
//! the matched user_id, the peer addr, non-zero duration_ms, the
//! tx/rx byte counts, and a sensible close_reason.

use std::sync::Arc;
use std::time::Duration;

use proteus_server::relay::{self, encode_connect, RelayConfig};
use proteus_transport_alpha::access_log::AccessLogger;
use proteus_transport_alpha::client::{self, ClientConfig};
use proteus_transport_alpha::metrics::ServerMetrics;
use proteus_transport_alpha::server::{self, ServerCtx, ServerKeys};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::time::timeout;

const STEP: Duration = Duration::from_secs(15);

async fn spawn_echo_upstream() -> std::net::SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        loop {
            let (mut stream, _) = match listener.accept().await {
                Ok(t) => t,
                Err(_) => return,
            };
            tokio::spawn(async move {
                let mut buf = vec![0u8; 4096];
                loop {
                    let n = match stream.read(&mut buf).await {
                        Ok(0) | Err(_) => break,
                        Ok(n) => n,
                    };
                    if stream.write_all(&buf[..n]).await.is_err() {
                        break;
                    }
                }
            });
        }
    });
    addr
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn access_log_emits_one_record_per_session() {
    let echo_addr = spawn_echo_upstream().await;

    // Server: allow exactly one user id "logtest1".
    let mut server_keys = ServerKeys::generate();
    let mlkem_pk_bytes = server_keys.mlkem_pk_bytes.clone();
    let pq_fingerprint = server_keys.pq_fingerprint;
    let server_x25519_pub = server_keys.x25519_pub;

    let mut rng = rand_core::OsRng;
    let client_sk = proteus_crypto::sig::generate(&mut rng);
    let client_vk = ed25519_dalek::VerifyingKey::from(&client_sk);
    server_keys.allow(*b"logtest1", client_vk);
    let ctx =
        Arc::new(ServerCtx::new(server_keys).with_metrics(Arc::new(ServerMetrics::default())));

    // Open the access log into a tempfile.
    let tmpdir = std::env::temp_dir().join(format!("proteus-acclog-int-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&tmpdir);
    std::fs::create_dir_all(&tmpdir).unwrap();
    let log_path = tmpdir.join("access.log");
    let logger = AccessLogger::spawn(&log_path).await.unwrap();

    let relay_cfg = RelayConfig {
        idle_timeout: Some(Duration::from_secs(5)),
        metrics: None,
        access_log: Some(Arc::new(logger)),
    };

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let proxy_addr = listener.local_addr().unwrap();
    let server_task = tokio::spawn(server::serve(listener, ctx, move |session| {
        let cfg = relay_cfg.clone();
        async move {
            let _ = relay::handle_session(session, cfg).await;
        }
    }));

    // Client.
    let client_cfg = ClientConfig {
        server_mlkem_pk_bytes: mlkem_pk_bytes,
        server_x25519_pub,
        server_pq_fingerprint: pq_fingerprint,
        client_id_sk: client_sk,
        user_id: *b"logtest1",
        pow_difficulty: 0,
    };
    let stream = TcpStream::connect(proxy_addr).await.unwrap();
    let mut session = timeout(STEP, client::handshake_over_tcp(stream, &client_cfg))
        .await
        .expect("connect timed out")
        .expect("handshake ok");

    let connect = encode_connect("127.0.0.1", echo_addr.port());
    session.sender.send_record(&connect).await.unwrap();
    session.sender.flush().await.unwrap();

    // One round trip.
    let payload = b"hello-access-log";
    session.sender.send_record(payload).await.unwrap();
    session.sender.flush().await.unwrap();
    let echoed = timeout(STEP, session.receiver.recv_record())
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    assert_eq!(echoed, payload);

    // Close the client's send half. The server's upstream pump will
    // see EOF and tear down; the access logger gets one record.
    let _ = timeout(STEP, session.sender.shutdown()).await;
    // Drain anything the server still has to send (specifically the
    // CLOSE record) so the server-side pump can finish.
    let _ = timeout(Duration::from_secs(2), session.receiver.recv_record()).await;
    let _ = timeout(Duration::from_secs(2), session.receiver.recv_record()).await;

    // Give the spawned session task time to finish + the writer task
    // to flush the line to disk. Poll up to 5 seconds.
    let log_ready = async {
        loop {
            if std::fs::metadata(&log_path)
                .map(|m| m.len() > 0)
                .unwrap_or(false)
            {
                return;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    };
    let _ = timeout(Duration::from_secs(5), log_ready).await;
    // Extra slack — BufWriter may have one record pending.
    tokio::time::sleep(Duration::from_millis(200)).await;

    let body = std::fs::read_to_string(&log_path).expect("read access log");
    let lines: Vec<&str> = body.lines().collect();
    assert_eq!(
        lines.len(),
        1,
        "expected exactly one access-log record, got:\n{body}"
    );
    let line = lines[0];
    assert!(
        line.contains(r#""user_id":"logtest1""#),
        "missing user_id: {line}"
    );
    assert!(
        line.contains(r#""peer":"127.0.0.1:"#),
        "missing peer: {line}"
    );
    assert!(
        line.contains(r#""duration_ms":"#),
        "missing duration: {line}"
    );
    assert!(line.contains(r#""tx_bytes":"#), "missing tx_bytes: {line}");
    assert!(line.contains(r#""rx_bytes":"#), "missing rx_bytes: {line}");
    assert!(
        line.contains(r#""close_reason":"#),
        "missing close_reason: {line}"
    );
    // Sanity: line is well-formed JSON-ish (starts/ends correctly).
    assert!(line.starts_with('{') && line.ends_with('}'));

    server_task.abort();
    let _ = std::fs::remove_dir_all(&tmpdir);
}
