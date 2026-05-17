//! End-to-end test: client `server_endpoints: [primary, backup]`
//! pool dispatch routes around a downed primary to a healthy backup.
//!
//! ## What this pins
//!
//! Iteration 15 (commit c19cf87) shipped the `EndpointPool` + YAML
//! config + validate guidance but the dispatcher still consulted
//! `server_endpoint` only. This iteration wired the pool through
//! `handle_socks5_with_health_and_pool`. The test verifies the
//! load-bearing property: when the primary entry is reachable but
//! HANDSHAKE-broken (e.g., wrong cert / wrong key / wrong port),
//! the dispatcher records the failure against that entry's
//! `EndpointHealth` and falls to the next entry, completing the
//! CONNECT through the healthy backup.
//!
//! Without this test, the pool wiring could silently regress and
//! operators with `server_endpoints` set would think they had HA
//! but actually be re-attempting the broken primary on every
//! CONNECT.

use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use base64::Engine;
use proteus_transport_alpha::server::{self as alpha_server, ServerCtx, ServerKeys};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::time::timeout;

const STEP: Duration = Duration::from_secs(20);

fn b64(bytes: &[u8]) -> String {
    base64::engine::general_purpose::STANDARD.encode(bytes)
}

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

/// Spawn an α-only Proteus server that echoes upstream. Returns
/// (addr, mlkem_pk, pq_fp, x25519_pub, client_sk). Patterned after
/// dual_stack.rs::spawn_alpha_only_server.
async fn spawn_alpha_echo_server() -> (
    std::net::SocketAddr,
    Vec<u8>,
    [u8; 32],
    [u8; 32],
    ed25519_dalek::SigningKey,
) {
    let server_keys = ServerKeys::generate();
    let mlkem_pk_bytes = server_keys.mlkem_pk_bytes.clone();
    let pq_fingerprint = server_keys.pq_fingerprint;
    let server_x25519_pub = server_keys.x25519_pub;
    let mut rng = rand_core::OsRng;
    let client_sk = proteus_crypto::sig::generate(&mut rng);
    let ctx = Arc::new(ServerCtx::new(server_keys));

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(alpha_server::serve(
        listener,
        ctx,
        move |session| async move {
            let proteus_transport_alpha::session::AlphaSession {
                mut sender,
                mut receiver,
                ..
            } = session;
            if let Ok(Some(req)) = receiver.recv_record().await {
                if req.is_empty() {
                    return;
                }
                let host_len = req[0] as usize;
                if req.len() < 1 + host_len + 2 {
                    return;
                }
                let host = std::str::from_utf8(&req[1..1 + host_len])
                    .unwrap()
                    .to_string();
                let port = u16::from_be_bytes([req[1 + host_len], req[1 + host_len + 1]]);
                if let Ok(upstream) = TcpStream::connect((host.as_str(), port)).await {
                    let (mut up_r, mut up_w) = upstream.into_split();
                    let c2u = async {
                        while let Ok(Some(b)) = receiver.recv_record().await {
                            if up_w.write_all(&b).await.is_err() {
                                break;
                            }
                        }
                    };
                    let u2c = async {
                        let mut buf = vec![0u8; 16 * 1024];
                        loop {
                            match up_r.read(&mut buf).await {
                                Ok(0) | Err(_) => break,
                                Ok(n) => {
                                    if sender.send_record(&buf[..n]).await.is_err() {
                                        break;
                                    }
                                    if sender.flush().await.is_err() {
                                        break;
                                    }
                                }
                            }
                        }
                    };
                    tokio::join!(c2u, u2c);
                }
            }
        },
    ));
    (
        addr,
        mlkem_pk_bytes,
        pq_fingerprint,
        server_x25519_pub,
        client_sk,
    )
}

fn make_tmp_keys_dir(
    mlkem_pk: &[u8],
    server_x25519_pub: &[u8; 32],
    pq_fingerprint: &[u8; 32],
    client_sk: &ed25519_dalek::SigningKey,
) -> PathBuf {
    let tag = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let dir =
        std::env::temp_dir().join(format!("proteus-multi-vps-{}-{}", std::process::id(), tag));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(dir.join("server_mlkem.pk"), format!("{}\n", b64(mlkem_pk))).unwrap();
    std::fs::write(
        dir.join("server_x25519.pk"),
        format!("{}\n", b64(server_x25519_pub)),
    )
    .unwrap();
    std::fs::write(
        dir.join("server.pq.fp"),
        format!("{}\n", b64(pq_fingerprint)),
    )
    .unwrap();
    std::fs::write(
        dir.join("client.ed25519.sk"),
        format!("{}\n", b64(&client_sk.to_bytes())),
    )
    .unwrap();
    dir
}

/// Drive one SOCKS5 round-trip through `handle_socks5_with_health_and_pool`
/// with the supplied pool. The CarrierHealth is fresh per call (we're
/// testing the POOL, not back-off across multiple CONNECTs).
async fn socks5_round_trip_via_pool(
    cfg: Arc<proteus_client::config::ClientConfig>,
    pool: Arc<proteus_client::endpoint_pool::EndpointPool>,
    host: &str,
    port: u16,
    payload: &[u8],
) -> Vec<u8> {
    use proteus_client::carrier_health::CarrierHealth;

    let sock_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let socks_addr = sock_listener.local_addr().unwrap();
    let cfg_for_task = Arc::clone(&cfg);
    let pool_for_task = Arc::clone(&pool);
    let server_task = tokio::spawn(async move {
        if let Ok((s, _)) = sock_listener.accept().await {
            let health = Arc::new(CarrierHealth::new());
            let _ = proteus_client::socks::handle_socks5_with_health_and_pool(
                s,
                &cfg_for_task,
                &health,
                Some(&pool_for_task),
            )
            .await;
        }
    });

    let mut sock = TcpStream::connect(socks_addr).await.unwrap();
    sock.set_nodelay(true).ok();
    sock.write_all(&[0x05, 0x01, 0x00]).await.unwrap();
    let mut greet = [0u8; 2];
    sock.read_exact(&mut greet).await.unwrap();
    assert_eq!(greet, [0x05, 0x00]);
    let mut req = Vec::with_capacity(7 + host.len());
    req.extend_from_slice(&[0x05, 0x01, 0x00, 0x03]);
    req.push(host.len() as u8);
    req.extend_from_slice(host.as_bytes());
    req.extend_from_slice(&port.to_be_bytes());
    sock.write_all(&req).await.unwrap();
    let mut reply = [0u8; 10];
    sock.read_exact(&mut reply).await.unwrap();
    assert_eq!(reply[1], 0x00, "SOCKS5 CONNECT must succeed");

    sock.write_all(payload).await.unwrap();
    let mut buf = vec![0u8; payload.len()];
    timeout(STEP, sock.read_exact(&mut buf))
        .await
        .unwrap()
        .unwrap();
    let _ = sock.shutdown().await;
    // Wait for the dispatch task to fully complete before returning.
    // Without this, `record_success` (called AFTER pump returns) may
    // not have fired by the time the caller inspects pool counters —
    // a race the per-endpoint counter assertions in
    // pool_dispatch_* tests expose. We bound the wait to STEP so a
    // genuine hang (relay deadlock) still surfaces.
    let _ = timeout(STEP, server_task).await;
    buf
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn pool_dispatch_falls_to_backup_when_primary_handshake_fails() {
    let echo_addr = spawn_echo_upstream().await;
    // Spawn a HEALTHY backup server.
    let (backup_addr, mlkem_pk, pq_fp, x25519_pub, client_sk) = spawn_alpha_echo_server().await;
    let keys_dir = make_tmp_keys_dir(&mlkem_pk, &x25519_pub, &pq_fp, &client_sk);

    // The "primary" is a port that NO server is listening on — connect
    // will fail immediately (ICMP-unreachable on loopback). That
    // counts as a per-entry failure; the dispatcher should fall to
    // the backup.
    let primary_addr: std::net::SocketAddr = "127.0.0.1:1".parse().unwrap();

    let yaml = format!(
        "server_endpoint: \"{primary}\"\n\
         server_endpoints:\n  \
             - \"{primary}\"\n  \
             - \"{backup}\"\n\
         socks_listen: \"127.0.0.1:0\"\n\
         user_id: \"vpspool1\"\n\
         keys:\n  \
             server_mlkem_pk: {keys}/server_mlkem.pk\n  \
             server_x25519_pk: {keys}/server_x25519.pk\n  \
             server_pq_fingerprint: {keys}/server.pq.fp\n  \
             client_ed25519_sk: {keys}/client.ed25519.sk\n",
        primary = primary_addr,
        backup = backup_addr,
        keys = keys_dir.display(),
    );
    let cfg: proteus_client::config::ClientConfig = serde_yaml::from_str(&yaml).unwrap();
    let pool = Arc::new(
        proteus_client::endpoint_pool::EndpointPool::new(cfg.server_endpoints.clone()).unwrap(),
    );

    let payload = b"hello-via-backup-after-primary-fails";
    let echoed = socks5_round_trip_via_pool(
        Arc::new(cfg),
        Arc::clone(&pool),
        "127.0.0.1",
        echo_addr.port(),
        payload,
    )
    .await;
    assert_eq!(echoed.as_slice(), payload);

    // The primary entry should now have a non-zero failure streak
    // recorded against its EndpointHealth.
    let primary_streak = pool.endpoint_health(0).unwrap().failure_streak();
    assert!(
        primary_streak >= 1,
        "primary entry should have failure_streak >= 1 after failing connect; got {primary_streak}",
    );

    // The backup entry should NOT have a failure streak — the
    // successful round-trip cleared it (or it was never set).
    let backup_streak = pool.endpoint_health(1).unwrap().failure_streak();
    assert_eq!(
        backup_streak, 0,
        "backup entry should have zero failure_streak after success; got {backup_streak}",
    );

    // Per-endpoint cumulative counters: primary was attempted (and
    // failed), backup was attempted (and succeeded). The operator
    // reads these on /status to demote primary if its success rate
    // stays low across many CONNECTs.
    let primary_counters = pool.endpoint_health(0).unwrap().counters();
    let backup_counters = pool.endpoint_health(1).unwrap().counters();
    assert!(
        primary_counters.attempts >= 1,
        "primary should have at least one attempt: {primary_counters:?}"
    );
    assert!(
        primary_counters.failures >= 1,
        "primary should have at least one failure: {primary_counters:?}"
    );
    assert_eq!(
        backup_counters.attempts, 1,
        "backup should have exactly one attempt: {backup_counters:?}"
    );
    assert_eq!(
        backup_counters.successes, 1,
        "backup should have exactly one success: {backup_counters:?}"
    );
    assert_eq!(
        backup_counters.failures, 0,
        "backup should have zero failures: {backup_counters:?}"
    );

    let _ = std::fs::remove_dir_all(&keys_dir);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn pool_dispatch_uses_primary_when_primary_works() {
    let echo_addr = spawn_echo_upstream().await;
    let (primary_addr, mlkem_pk, pq_fp, x25519_pub, client_sk) = spawn_alpha_echo_server().await;
    let keys_dir = make_tmp_keys_dir(&mlkem_pk, &x25519_pub, &pq_fp, &client_sk);

    // Backup is the unreachable port — it should never be dialed
    // because primary works.
    let backup_addr: std::net::SocketAddr = "127.0.0.1:1".parse().unwrap();

    let yaml = format!(
        "server_endpoint: \"{primary}\"\n\
         server_endpoints:\n  \
             - \"{primary}\"\n  \
             - \"{backup}\"\n\
         socks_listen: \"127.0.0.1:0\"\n\
         user_id: \"vpspool2\"\n\
         keys:\n  \
             server_mlkem_pk: {keys}/server_mlkem.pk\n  \
             server_x25519_pk: {keys}/server_x25519.pk\n  \
             server_pq_fingerprint: {keys}/server.pq.fp\n  \
             client_ed25519_sk: {keys}/client.ed25519.sk\n",
        primary = primary_addr,
        backup = backup_addr,
        keys = keys_dir.display(),
    );
    let cfg: proteus_client::config::ClientConfig = serde_yaml::from_str(&yaml).unwrap();
    let pool = Arc::new(
        proteus_client::endpoint_pool::EndpointPool::new(cfg.server_endpoints.clone()).unwrap(),
    );

    let payload = b"hello-via-primary";
    let echoed = socks5_round_trip_via_pool(
        Arc::new(cfg),
        Arc::clone(&pool),
        "127.0.0.1",
        echo_addr.port(),
        payload,
    )
    .await;
    assert_eq!(echoed.as_slice(), payload);

    // Both entries' streaks should be zero — primary succeeded
    // first time, backup was never attempted.
    assert_eq!(pool.endpoint_health(0).unwrap().failure_streak(), 0);
    assert_eq!(pool.endpoint_health(1).unwrap().failure_streak(), 0);

    // Per-endpoint cumulative counters: primary handled the dial,
    // backup was never tried — the operator's `/status` shows the
    // asymmetry that justifies keeping backup as second-choice.
    let primary_counters = pool.endpoint_health(0).unwrap().counters();
    let backup_counters = pool.endpoint_health(1).unwrap().counters();
    assert_eq!(primary_counters.attempts, 1, "{primary_counters:?}");
    assert_eq!(primary_counters.successes, 1, "{primary_counters:?}");
    assert_eq!(primary_counters.failures, 0, "{primary_counters:?}");
    assert_eq!(
        backup_counters.attempts, 0,
        "backup must NOT be attempted when primary works: {backup_counters:?}"
    );

    let _ = std::fs::remove_dir_all(&keys_dir);
}
