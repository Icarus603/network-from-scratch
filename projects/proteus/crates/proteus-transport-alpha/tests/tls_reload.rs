//! SIGHUP-style TLS certificate hot-reload integration test.
//!
//! Scenario:
//! 1. Stand up a Proteus server with a self-signed cert for "localhost".
//! 2. A client connects, completes the TLS+Proteus handshake, echoes a
//!    payload. (Baseline — the initial cert works.)
//! 3. Operator hot-reloads the acceptor with a *new* self-signed cert
//!    (different keypair) — simulates `certbot --post-hook`.
//! 4. A second client connects. Its CA bundle trusts ONLY the new
//!    cert, so its TLS handshake would have failed against the old
//!    cert. If it succeeds, the reload took effect.
//! 5. The first session — opened against the old cert — is still
//!    flowing data, proving the reload didn't disturb in-flight
//!    sessions.

use std::sync::Arc;
use std::time::Duration;

use proteus_transport_alpha::client::{self, ClientConfig};
use proteus_transport_alpha::server::{self, ServerCtx, ServerKeys};
use proteus_transport_alpha::tls::{self, ReloadableAcceptor};
use rand_core::OsRng;
use rcgen::generate_simple_self_signed;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use tokio::net::{TcpListener, TcpStream};
use tokio::time::timeout;

const STEP: Duration = Duration::from_secs(20);

fn fresh_cert() -> (CertificateDer<'static>, PrivateKeyDer<'static>) {
    let ck = generate_simple_self_signed(vec!["localhost".to_string()]).unwrap();
    let cert_der = CertificateDer::from(ck.cert.der().to_vec());
    let key_der = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(ck.key_pair.serialize_der()));
    (cert_der, key_der)
}

fn connector_trusting(cert: CertificateDer<'static>) -> tokio_rustls::TlsConnector {
    let mut roots = rustls::RootCertStore::empty();
    roots.add(cert).unwrap();
    let mut cfg = rustls::ClientConfig::builder_with_protocol_versions(&[&rustls::version::TLS13])
        .with_root_certificates(roots)
        .with_no_client_auth();
    cfg.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
    tokio_rustls::TlsConnector::from(Arc::new(cfg))
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn sighup_style_reload_swaps_cert_without_dropping_inflight() {
    // ----- two distinct self-signed certs -----
    let (cert_a, key_a) = fresh_cert();
    let (cert_b, key_b) = fresh_cert();
    // Sanity: the two certs must be different bytes.
    assert_ne!(cert_a.as_ref(), cert_b.as_ref());

    let acceptor_a = tls::build_acceptor(vec![cert_a.clone()], key_a).unwrap();
    let reloadable = ReloadableAcceptor::new(acceptor_a);

    // ----- Proteus server -----
    let server_keys = ServerKeys::generate();
    let mlkem_pk_bytes = server_keys.mlkem_pk_bytes.clone();
    let pq_fingerprint = server_keys.pq_fingerprint;
    let server_x25519_pub = server_keys.x25519_pub;
    let ctx = Arc::new(ServerCtx::new(server_keys));

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();

    let server_ctx = Arc::clone(&ctx);
    let server_reload = reloadable.clone();
    let server_task = tokio::spawn(server::serve_tls_reloadable(
        listener,
        server_ctx,
        server_reload,
        |mut session| async move {
            while let Ok(Some(msg)) = session.receiver.recv_record().await {
                if session.sender.send_record(&msg).await.is_err() {
                    break;
                }
                if session.sender.flush().await.is_err() {
                    break;
                }
            }
        },
    ));

    // ----- client #1: trusts cert_a, connects, sends payload -----
    let connector_a = connector_trusting(cert_a.clone());
    let mk_cfg = |user_id: &[u8; 8]| ClientConfig {
        server_mlkem_pk_bytes: mlkem_pk_bytes.clone(),
        server_x25519_pub,
        server_pq_fingerprint: pq_fingerprint,
        client_id_sk: proteus_crypto::sig::generate(&mut OsRng),
        user_id: *user_id,
        pow_difficulty: 0,
        profile_hint: proteus_wire::ProfileHint::Alpha,
    };
    let stream1 = TcpStream::connect(addr).await.unwrap();
    let mut session1 = timeout(
        STEP,
        client::handshake_over_tls(stream1, &connector_a, "localhost", &mk_cfg(b"client_a")),
    )
    .await
    .expect("connect a timed out")
    .expect("handshake a ok");
    timeout(STEP, session1.sender.send_record(b"hello-from-a"))
        .await
        .unwrap()
        .unwrap();
    timeout(STEP, session1.sender.flush())
        .await
        .unwrap()
        .unwrap();
    let echoed = timeout(STEP, session1.receiver.recv_record())
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    assert_eq!(echoed, b"hello-from-a");

    // ----- reload to cert_b -----
    let acceptor_b = tls::build_acceptor(vec![cert_b.clone()], key_b).unwrap();
    reloadable.reload(acceptor_b);

    // ----- client #2: trusts ONLY cert_b. If reload didn't take, this
    //       handshake would fail with UnknownIssuer. -----
    let connector_b = connector_trusting(cert_b.clone());
    let stream2 = TcpStream::connect(addr).await.unwrap();
    let mut session2 = timeout(
        STEP,
        client::handshake_over_tls(stream2, &connector_b, "localhost", &mk_cfg(b"client_b")),
    )
    .await
    .expect("connect b timed out")
    .expect("handshake b ok — reload didn't take?");
    timeout(STEP, session2.sender.send_record(b"hello-from-b"))
        .await
        .unwrap()
        .unwrap();
    timeout(STEP, session2.sender.flush())
        .await
        .unwrap()
        .unwrap();
    let echoed2 = timeout(STEP, session2.receiver.recv_record())
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    assert_eq!(echoed2, b"hello-from-b");

    // ----- the OLD session must still work — reload doesn't disturb
    //       in-flight TLS state. -----
    timeout(STEP, session1.sender.send_record(b"still-alive"))
        .await
        .unwrap()
        .unwrap();
    timeout(STEP, session1.sender.flush())
        .await
        .unwrap()
        .unwrap();
    let echoed3 = timeout(STEP, session1.receiver.recv_record())
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    assert_eq!(echoed3, b"still-alive");

    // ----- and now client #1's connector (trusting only cert_a) should
    //       FAIL to open a new connection, confirming the swap is
    //       genuine — not just "both certs accepted". -----
    let stream3 = TcpStream::connect(addr).await.unwrap();
    let result = timeout(
        STEP,
        client::handshake_over_tls(stream3, &connector_a, "localhost", &mk_cfg(b"client_c")),
    )
    .await
    .expect("connect c timed out");
    assert!(
        result.is_err(),
        "new connection against old cert must fail after reload"
    );

    let _ = timeout(STEP, session1.sender.shutdown()).await;
    let _ = timeout(STEP, session2.sender.shutdown()).await;
    server_task.abort();
}
