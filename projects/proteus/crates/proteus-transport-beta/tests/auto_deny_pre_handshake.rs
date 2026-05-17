//! Wire-level test: pre-QUIC-handshake auto-deny short-circuit.
//!
//! ## What this pins
//!
//! When the operator has wired an `AutoDenyList` AND a peer's /24
//! prefix is on the deny list, the β server MUST `Incoming::ignore()`
//! the incoming connection — quinn sends NO response packet, the
//! peer sees no QUIC handshake reply at all. From the prober's
//! wire POV, the server is unreachable.
//!
//! This is a stricter property than "the server closes the
//! connection" — it means the server does not even pay the
//! TLS+QUIC handshake CPU cost on probes from already-known-bad
//! prefixes. A sustained QUIC prober that previously triggered the
//! anomaly detector now consumes ZERO ML-KEM-decap budget per
//! probe.
//!
//! ## Construction
//!
//! Stand up a β server with an auto-deny list that already
//! contains the loopback /24. A QUIC client (loopback src) tries
//! to connect; the connect attempt MUST time out without any
//! response. As a control, we then clear the deny list and verify
//! the connect succeeds (proving the test setup is otherwise
//! healthy and the timeout was caused by auto-deny, not by
//! infrastructure flakes).

use std::net::IpAddr;
use std::sync::Arc;
use std::time::Duration;

use proteus_transport_alpha::auto_deny::AutoDenyList;
use proteus_transport_alpha::server::{ServerCtx, ServerKeys};
use rcgen::generate_simple_self_signed;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use tokio::time::timeout;

const STEP: Duration = Duration::from_secs(15);

/// Build the client-side quinn endpoint pointed at `server_addr`,
/// trusting `cert_der` as the only root CA. Returns the live endpoint
/// (caller drops it at scope end).
fn make_client_endpoint(cert_der: CertificateDer<'static>) -> quinn::Endpoint {
    let mut roots = rustls::RootCertStore::empty();
    roots.add(cert_der).unwrap();
    let mut client_cfg =
        rustls::ClientConfig::builder_with_protocol_versions(&[&rustls::version::TLS13])
            .with_root_certificates(roots)
            .with_no_client_auth();
    client_cfg.alpn_protocols = vec![proteus_transport_beta::ALPN.to_vec()];
    let crypto = Arc::new(quinn::crypto::rustls::QuicClientConfig::try_from(client_cfg).unwrap());
    let mut endpoint = quinn::Endpoint::client("127.0.0.1:0".parse().unwrap()).unwrap();
    endpoint.set_default_client_config(quinn::ClientConfig::new(crypto));
    endpoint
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn denied_prefix_gets_silent_ignore_pre_quic_handshake() {
    // Pre-populate the auto-deny list with the loopback /24 so the
    // very first probe is rejected pre-handshake — no need to first
    // trigger an anomaly burst, this isolates the wire-behavior
    // assertion from the detector's own timing.
    let auto_deny = Arc::new(AutoDenyList::new(Duration::from_secs(300), 1024));
    auto_deny.insert(
        IpAddr::V4(std::net::Ipv4Addr::new(127, 0, 0, 1)),
        std::time::Instant::now(),
    );
    assert!(
        auto_deny.is_denied(
            IpAddr::V4(std::net::Ipv4Addr::new(127, 0, 0, 1)),
            std::time::Instant::now()
        ),
        "test pre-condition: loopback /24 should be in the deny list"
    );

    let ck = generate_simple_self_signed(vec!["localhost".to_string()]).unwrap();
    let cert_der = CertificateDer::from(ck.cert.der().to_vec());
    let key_der = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(ck.key_pair.serialize_der()));

    let server_keys = ServerKeys::generate();
    let ctx = Arc::new(ServerCtx::new(server_keys).with_auto_deny_list(Arc::clone(&auto_deny)));

    let bind: std::net::SocketAddr = "127.0.0.1:0".parse().unwrap();
    let endpoint =
        proteus_transport_beta::server::make_endpoint(bind, vec![cert_der.clone()], key_der)
            .expect("make_endpoint");
    let server_addr = endpoint.local_addr().expect("local_addr");
    let server_ctx = Arc::clone(&ctx);
    let server_task = tokio::spawn(async move {
        let _ =
            proteus_transport_beta::server::serve(endpoint, server_ctx, |_session| async {}).await;
    });

    // Client dial: with the server using `Incoming::ignore()`, the
    // client gets no response and quinn's internal handshake
    // timeout fires. We bound our wait to 3 seconds — enough time
    // for several quinn Initial retransmits + plenty of margin for
    // a real reply, but short enough that the test runs fast.
    let client_ep = make_client_endpoint(cert_der.clone());
    let connect_fut = client_ep.connect(server_addr, "localhost").unwrap();
    let result = timeout(Duration::from_secs(3), connect_fut).await;
    assert!(
        result.is_err(),
        "denied client connect should TIME OUT (server is sending NO QUIC packets); \
         instead got: {result:?}",
    );

    // Control: clear the deny entry and verify a fresh connect
    // succeeds — proves the test infrastructure is otherwise
    // healthy (server is up, cert is valid, network works).
    // We do this by creating a new client endpoint after wiping
    // the deny state; the existing one's first connect attempt
    // may still be in retry-backoff.
    drop(client_ep);

    // Build a fresh auto-deny list with no entries and rebuild
    // the server ctx — quinn doesn't expose a way to forcibly
    // remove pending entries on the server side, but starting a
    // second server instance proves the wire path itself is sound.
    let server_keys2 = ServerKeys::generate();
    let auto_deny2 = Arc::new(AutoDenyList::new(Duration::from_secs(300), 1024));
    let ctx2 = Arc::new(ServerCtx::new(server_keys2).with_auto_deny_list(auto_deny2));
    let ck2 = generate_simple_self_signed(vec!["localhost".to_string()]).unwrap();
    let cert_der2 = CertificateDer::from(ck2.cert.der().to_vec());
    let key_der2 = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(ck2.key_pair.serialize_der()));
    let endpoint2 = proteus_transport_beta::server::make_endpoint(
        "127.0.0.1:0".parse().unwrap(),
        vec![cert_der2.clone()],
        key_der2,
    )
    .unwrap();
    let server_addr2 = endpoint2.local_addr().unwrap();
    let server_task2 = tokio::spawn(async move {
        let _ = proteus_transport_beta::server::serve(endpoint2, ctx2, |_session| async {}).await;
    });
    let client_ep2 = make_client_endpoint(cert_der2);
    let result2 = timeout(STEP, client_ep2.connect(server_addr2, "localhost").unwrap()).await;
    assert!(
        result2.is_ok(),
        "control: fresh server with EMPTY deny list should accept the QUIC handshake; got {result2:?}",
    );
    let _ = result2.unwrap();

    server_task.abort();
    server_task2.abort();
}

/// Sanity: when auto-deny is NOT wired (operator hasn't opted in),
/// the pre-handshake fast path is bypassed entirely and the QUIC
/// handshake completes normally. Existing behavior verified to be
/// preserved by the conditional in `serve`.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn no_auto_deny_means_no_pre_handshake_intervention() {
    let ck = generate_simple_self_signed(vec!["localhost".to_string()]).unwrap();
    let cert_der = CertificateDer::from(ck.cert.der().to_vec());
    let key_der = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(ck.key_pair.serialize_der()));

    let server_keys = ServerKeys::generate();
    // No `with_auto_deny_list(...)` → ctx.auto_deny() returns None →
    // the pre-handshake branch in serve() is skipped.
    let ctx = Arc::new(ServerCtx::new(server_keys));

    let endpoint = proteus_transport_beta::server::make_endpoint(
        "127.0.0.1:0".parse().unwrap(),
        vec![cert_der.clone()],
        key_der,
    )
    .unwrap();
    let server_addr = endpoint.local_addr().unwrap();
    let server_task = tokio::spawn(async move {
        let _ = proteus_transport_beta::server::serve(endpoint, ctx, |_session| async {}).await;
    });

    let client_ep = make_client_endpoint(cert_der);
    let result = timeout(STEP, client_ep.connect(server_addr, "localhost").unwrap()).await;
    assert!(
        result.is_ok(),
        "without auto-deny wired the QUIC handshake should complete normally; got {result:?}",
    );
    let _ = result.unwrap();

    server_task.abort();
}
