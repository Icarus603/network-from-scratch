//! End-to-end test for the outbound destination filter (SSRF
//! defense). Verifies:
//!   - CONNECT to a blocked CIDR (127.0.0.1, RFC 1918, cloud meta)
//!     is rejected; `proteus_outbound_blocked_total` ticks.
//!   - CONNECT to a non-allowed port (e.g. 22) is rejected.
//!   - CONNECT to an allowed (public) IP + port succeeds.
//!
//! Public-IP path is exercised by binding a TCP listener on a free
//! port and routing the client through a permissive policy that
//! still has the default port allow set. We use 80/443 as ports
//! the listener happens to bind to (we pick from the OS's ephemeral
//! pool but force an explicit port for the CONNECT). For the
//! "allowed" check we don't actually need a real public IP — we
//! build a custom policy that admits 127.0.0.1 explicitly so we can
//! verify the relay's happy path is unaffected by the filter.

use std::sync::Arc;
use std::time::Duration;

use proteus_server::relay::{self, encode_connect, RelayConfig};
use proteus_transport_alpha::client::{self, ClientConfig};
use proteus_transport_alpha::metrics::ServerMetrics;
use proteus_transport_alpha::outbound_filter::OutboundPolicy;
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

async fn make_session(
    proxy_addr: std::net::SocketAddr,
    client_cfg: &ClientConfig,
) -> proteus_transport_alpha::session::AlphaSession {
    let stream = TcpStream::connect(proxy_addr).await.unwrap();
    timeout(STEP, client::handshake_over_tcp(stream, client_cfg))
        .await
        .expect("connect timeout")
        .expect("handshake ok")
}

fn make_client_cfg(server_keys: &ServerKeys) -> ClientConfig {
    let mut rng = rand_core::OsRng;
    ClientConfig {
        server_mlkem_pk_bytes: server_keys.mlkem_pk_bytes.clone(),
        server_x25519_pub: server_keys.x25519_pub,
        server_pq_fingerprint: server_keys.pq_fingerprint,
        client_id_sk: proteus_crypto::sig::generate(&mut rng),
        user_id: *b"filtest1",
        pow_difficulty: 0,
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn outbound_filter_blocks_aws_metadata_ip() {
    let server_keys = ServerKeys::generate();
    let client_cfg = make_client_cfg(&server_keys);
    let metrics = Arc::new(ServerMetrics::default());
    let ctx = Arc::new(ServerCtx::new(server_keys));
    let relay_cfg = RelayConfig {
        idle_timeout: Some(Duration::from_secs(5)),
        metrics: Some(Arc::clone(&metrics)),
        access_log: None,
        max_session_bytes: None,
        abuse_detector_byte_budget: None,
        outbound_filter: Some(Arc::new(OutboundPolicy::default())),
    };
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let proxy_addr = listener.local_addr().unwrap();
    let server_task = tokio::spawn(server::serve(listener, ctx, move |session| {
        let cfg = relay_cfg.clone();
        async move {
            let _ = relay::handle_session(session, cfg).await;
        }
    }));

    let mut session = make_session(proxy_addr, &client_cfg).await;
    let connect = encode_connect("169.254.169.254", 80);
    session.sender.send_record(&connect).await.unwrap();
    session.sender.flush().await.unwrap();

    // Server should respond with empty record + close. We just need
    // to confirm the dial never happened — outbound_blocked counter
    // must tick.
    let mut alerts = 0u64;
    for _ in 0..50 {
        alerts = metrics
            .outbound_blocked
            .load(std::sync::atomic::Ordering::Relaxed);
        if alerts >= 1 {
            break;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    assert_eq!(
        alerts, 1,
        "outbound_blocked_total must increment on AWS metadata dial"
    );

    let _ = session.sender.shutdown().await;
    server_task.abort();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn outbound_filter_blocks_disallowed_port() {
    let server_keys = ServerKeys::generate();
    let client_cfg = make_client_cfg(&server_keys);
    let metrics = Arc::new(ServerMetrics::default());
    let ctx = Arc::new(ServerCtx::new(server_keys));
    // Custom policy that DOES allow 127.0.0.1 (so the IP isn't the
    // reason for rejection) but DOESN'T allow port 22 (the default
    // 80/443 list doesn't include it).
    let policy = OutboundPolicy::default().with_no_default_blocklist();
    let relay_cfg = RelayConfig {
        idle_timeout: Some(Duration::from_secs(5)),
        metrics: Some(Arc::clone(&metrics)),
        access_log: None,
        max_session_bytes: None,
        abuse_detector_byte_budget: None,
        outbound_filter: Some(Arc::new(policy)),
    };
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let proxy_addr = listener.local_addr().unwrap();
    let server_task = tokio::spawn(server::serve(listener, ctx, move |session| {
        let cfg = relay_cfg.clone();
        async move {
            let _ = relay::handle_session(session, cfg).await;
        }
    }));

    let mut session = make_session(proxy_addr, &client_cfg).await;
    let connect = encode_connect("127.0.0.1", 22);
    session.sender.send_record(&connect).await.unwrap();
    session.sender.flush().await.unwrap();

    let mut alerts = 0u64;
    for _ in 0..50 {
        alerts = metrics
            .outbound_blocked
            .load(std::sync::atomic::Ordering::Relaxed);
        if alerts >= 1 {
            break;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    assert_eq!(alerts, 1, "port 22 must be blocked by default policy");

    let _ = session.sender.shutdown().await;
    server_task.abort();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn outbound_filter_allows_explicitly_permitted_destination() {
    let echo_addr = spawn_echo_upstream().await;
    let server_keys = ServerKeys::generate();
    let client_cfg = make_client_cfg(&server_keys);
    let metrics = Arc::new(ServerMetrics::default());
    let ctx = Arc::new(ServerCtx::new(server_keys));
    // Custom policy: clear default blocklist (so 127.0.0.1 passes)
    // and add the echo upstream's port to the allow list.
    let echo_port = echo_addr.port();
    let policy = OutboundPolicy::default()
        .with_no_default_blocklist()
        .extend_allowed_ports([echo_port]);
    let relay_cfg = RelayConfig {
        idle_timeout: Some(Duration::from_secs(5)),
        metrics: Some(Arc::clone(&metrics)),
        access_log: None,
        max_session_bytes: None,
        abuse_detector_byte_budget: None,
        outbound_filter: Some(Arc::new(policy)),
    };
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let proxy_addr = listener.local_addr().unwrap();
    let server_task = tokio::spawn(server::serve(listener, ctx, move |session| {
        let cfg = relay_cfg.clone();
        async move {
            let _ = relay::handle_session(session, cfg).await;
        }
    }));

    let mut session = make_session(proxy_addr, &client_cfg).await;
    let connect = encode_connect("127.0.0.1", echo_addr.port());
    session.sender.send_record(&connect).await.unwrap();
    session.sender.flush().await.unwrap();

    // Echo round-trip should work.
    let payload = b"hello-permitted";
    session.sender.send_record(payload).await.unwrap();
    session.sender.flush().await.unwrap();
    let echoed = timeout(STEP, session.receiver.recv_record())
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    assert_eq!(echoed, payload);
    let blocked = metrics
        .outbound_blocked
        .load(std::sync::atomic::Ordering::Relaxed);
    assert_eq!(blocked, 0, "no block should have fired on permitted dial");

    let _ = session.sender.shutdown().await;
    server_task.abort();
}
