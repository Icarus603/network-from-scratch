//! Both carriers concurrent on the SAME ServerCtx.
//!
//! Production daemons need to expose α (TCP+TLS) for "anything that
//! survives strict-TCP networks" + β (QUIC) for "anywhere UDP is
//! allowed and we want throughput". The two MUST share state:
//!   - one client allowlist (no double-configuration)
//!   - one rate limiter (per-IP and per-user budgets work across
//!     both carriers — a flooding client that switches profiles
//!     mid-attack is still limited)
//!   - one ServerMetrics (aggregate observability)
//!   - one abuse detector (catches a credential abusing both)
//!
//! This test stands up one ServerCtx, binds α on TCP + β on UDP,
//! exchanges a record on each, asserts BOTH increment the SAME
//! `sessions_accepted` counter.

use std::sync::Arc;
use std::time::Duration;

use proteus_transport_alpha::client::{self as alpha_client, ClientConfig};
use proteus_transport_alpha::metrics::ServerMetrics;
use proteus_transport_alpha::server::{self as alpha_server, ServerCtx, ServerKeys};
use proteus_transport_alpha::ProfileHint;
use rcgen::generate_simple_self_signed;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use tokio::net::{TcpListener, TcpStream};
use tokio::time::timeout;

const STEP: Duration = Duration::from_secs(20);

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn alpha_and_beta_share_one_server_ctx() {
    // Self-signed cert (β requires TLS; α path here is plain TCP for
    // test simplicity — same ServerCtx still drives both).
    let ck = generate_simple_self_signed(vec!["localhost".to_string()]).unwrap();
    let cert_der = CertificateDer::from(ck.cert.der().to_vec());
    let key_der = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(ck.key_pair.serialize_der()));

    // ONE ServerKeys, ONE ServerCtx, ONE ServerMetrics — shared.
    let server_keys = ServerKeys::generate();
    let mlkem_pk_bytes = server_keys.mlkem_pk_bytes.clone();
    let pq_fingerprint = server_keys.pq_fingerprint;
    let server_x25519_pub = server_keys.x25519_pub;
    let metrics = Arc::new(ServerMetrics::default());
    let ctx = Arc::new(ServerCtx::new(server_keys).with_metrics(Arc::clone(&metrics)));

    // ----- α (plain TCP) -----
    let alpha_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let alpha_addr = alpha_listener.local_addr().unwrap();
    let alpha_ctx = Arc::clone(&ctx);
    let alpha_metrics = Arc::clone(&metrics);
    let alpha_task = tokio::spawn(alpha_server::serve(
        alpha_listener,
        alpha_ctx,
        move |mut session| {
            let metrics = Arc::clone(&alpha_metrics);
            async move {
                metrics
                    .sessions_accepted
                    .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                // Echo one record.
                if let Ok(Some(rec)) = session.receiver.recv_record().await {
                    let _ = session.sender.send_record(&rec).await;
                    let _ = session.sender.flush().await;
                }
            }
        },
    ));

    // ----- β (QUIC) on a separate UDP port -----
    let beta_bind: std::net::SocketAddr = "127.0.0.1:0".parse().unwrap();
    let beta_endpoint =
        proteus_transport_beta::server::make_endpoint(beta_bind, vec![cert_der.clone()], key_der)
            .expect("β endpoint");
    let beta_addr = beta_endpoint.local_addr().unwrap();
    let beta_ctx = Arc::clone(&ctx);
    let beta_metrics = Arc::clone(&metrics);
    let beta_task = tokio::spawn(async move {
        let _ =
            proteus_transport_beta::server::serve(beta_endpoint, beta_ctx, move |mut session| {
                let metrics = Arc::clone(&beta_metrics);
                async move {
                    metrics
                        .sessions_accepted
                        .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                    if let Ok(Some(rec)) = session.receiver.recv_record().await {
                        let _ = session.sender.send_record(&rec).await;
                        let _ = session.sender.flush().await;
                    }
                }
            })
            .await;
    });

    // ----- Client #1: α handshake -----
    let mut rng = rand_core::OsRng;
    let alpha_cfg = ClientConfig {
        server_mlkem_pk_bytes: mlkem_pk_bytes.clone(),
        server_x25519_pub,
        server_pq_fingerprint: pq_fingerprint,
        client_id_sk: proteus_crypto::sig::generate(&mut rng),
        user_id: *b"dualtst1",
        pow_difficulty: 0,
        profile_hint: ProfileHint::Alpha,
    };
    let stream = TcpStream::connect(alpha_addr).await.unwrap();
    let mut alpha_session = timeout(STEP, alpha_client::handshake_over_tcp(stream, &alpha_cfg))
        .await
        .expect("α connect timed out")
        .expect("α handshake ok");
    alpha_session
        .sender
        .send_record(b"hello-from-alpha")
        .await
        .unwrap();
    alpha_session.sender.flush().await.unwrap();
    let echoed = timeout(STEP, alpha_session.receiver.recv_record())
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    assert_eq!(echoed, b"hello-from-alpha");

    // ----- Client #2: β handshake (SAME server keys) -----
    let beta_cfg = ClientConfig {
        server_mlkem_pk_bytes: mlkem_pk_bytes,
        server_x25519_pub,
        server_pq_fingerprint: pq_fingerprint,
        client_id_sk: proteus_crypto::sig::generate(&mut rng),
        user_id: *b"dualtst2",
        pow_difficulty: 0,
        profile_hint: ProfileHint::Beta,
    };
    let mut beta_client = timeout(
        STEP,
        proteus_transport_beta::client::connect("localhost", beta_addr, vec![cert_der], beta_cfg),
    )
    .await
    .expect("β connect timed out")
    .expect("β handshake ok");
    beta_client
        .session
        .sender
        .send_record(b"hello-from-beta")
        .await
        .unwrap();
    beta_client.session.sender.flush().await.unwrap();
    let echoed_b = timeout(STEP, beta_client.session.receiver.recv_record())
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    assert_eq!(echoed_b, b"hello-from-beta");

    // Wait briefly for the metrics increments from both handler
    // tasks to flush.
    for _ in 0..50 {
        if metrics
            .sessions_accepted
            .load(std::sync::atomic::Ordering::Relaxed)
            >= 2
        {
            break;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    let total = metrics
        .sessions_accepted
        .load(std::sync::atomic::Ordering::Relaxed);
    assert_eq!(
        total, 2,
        "shared ServerMetrics should aggregate both carriers; got {total}"
    );

    // Cleanup.
    let proteus_transport_alpha::session::AlphaSession {
        sender: alpha_send, ..
    } = alpha_session;
    let _ = timeout(STEP, alpha_send.shutdown()).await;
    let proteus_transport_alpha::session::AlphaSession {
        sender: beta_send, ..
    } = beta_client.session;
    let _ = timeout(STEP, beta_send.shutdown()).await;
    beta_client.connection.close(0u32.into(), b"bye");
    drop(beta_client.endpoint);

    alpha_task.abort();
    beta_task.abort();
}
