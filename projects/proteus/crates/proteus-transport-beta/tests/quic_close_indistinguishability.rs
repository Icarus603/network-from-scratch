//! Regression test: every β server-side close MUST be NO_ERROR (0x00)
//! with an empty reason phrase — indistinguishable on the wire from a
//! generic QUIC server's normal close.
//!
//! ## Why this matters
//!
//! QUIC's `CONNECTION_CLOSE` frame (RFC 9000 §19.19) carries
//! `error_code` and a `reason_phrase` that are emitted UNENCRYPTED at
//! the transport level inside the 1-RTT packet. An on-path observer
//! (GFW, ISP DPI, hostile NAT) that can decrypt the 1-RTT packets
//! (the prober itself, after completing the TLS handshake) reads these
//! fields verbatim.
//!
//! Earlier revisions of the β server surfaced reasons like
//! "admission-denied" / "max-connections" / "alpn-mismatch" /
//! "bi-stream-timeout" / "no-exporter" with distinct error codes
//! (1, 2, 0, 3, 4). An active GFW prober that retries the handshake
//! under different invariants — fresh IP vs. blocked IP, fresh
//! user_id vs. unknown user_id, varied ALPN — could read these and
//! CLASSIFY the server's policy, distinguishing Proteus from generic
//! QUIC services that close with NO_ERROR + empty reason.
//!
//! This test pins the hardened behavior. If a future refactor
//! reintroduces a distinct close code / reason on ANY server-side
//! rejection branch, this test fails loudly.
//!
//! ## What we pin
//!
//! Trigger three independent server-side close branches and assert
//! all three produce `ApplicationClose { error_code: 0, reason: empty }`:
//!
//!   (a) `max_connections` cap exhausted (handshake-time admission)
//!   (b) `accept_bi` deadline exceeded (slowloris-over-QUIC)
//!   (c) normal session completion (control: must already match)

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use proteus_transport_alpha::client::ClientConfig;
use proteus_transport_alpha::server::{ServerCtx, ServerKeys};
use proteus_transport_alpha::ProfileHint;
use quinn::{ConnectionError, VarInt};
use rcgen::generate_simple_self_signed;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use tokio::time::timeout;

const STEP: Duration = Duration::from_secs(20);

/// The single canonical close-reason fingerprint Proteus β presents
/// on every server-initiated close. Any deviation = wire-visible
/// distinguisher = GFW classifier signal.
const CANONICAL_ERROR_CODE: u64 = 0;
const CANONICAL_REASON: &[u8] = b"";

/// Match a `ConnectionError` against the canonical Proteus close
/// fingerprint. Returns `Ok(())` if it matches, `Err(diagnostic)`
/// otherwise.
fn assert_canonical_close(err: &ConnectionError, branch: &str) {
    match err {
        ConnectionError::ApplicationClosed(app) => {
            let code = app.error_code.into_inner();
            assert_eq!(
                code, CANONICAL_ERROR_CODE,
                "β [{branch}]: close error_code MUST be 0 (NO_ERROR) for \
                 indistinguishability from generic QUIC services; got {code}. \
                 A non-zero code is a wire-visible classifier signal."
            );
            assert_eq!(
                app.reason.as_ref(),
                CANONICAL_REASON,
                "β [{branch}]: close reason MUST be empty for \
                 indistinguishability; got {:?}. The diagnostic must \
                 stay in operator metrics, NEVER on the wire.",
                app.reason
            );
        }
        // LocallyClosed only fires on the side that called .close() —
        // for the client-side observation it MUST be ApplicationClosed
        // (received from the remote endpoint).
        other => panic!(
            "β [{branch}]: expected ApplicationClosed (server-initiated \
             with our canonical fingerprint); got {other:?}. The server \
             must signal close via QUIC's CONNECTION_CLOSE app frame, \
             not by TransportError or by dropping the socket."
        ),
    }
}

/// Branch (a): `max_connections` cap = 0 → every connection rejected
/// by the post-QUIC-handshake admission gate. Client MUST observe
/// `ApplicationClosed { error_code: 0, reason: empty }`.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn beta_max_connections_close_is_canonical() {
    let ck = generate_simple_self_signed(vec!["localhost".to_string()]).unwrap();
    let cert_der = CertificateDer::from(ck.cert.der().to_vec());
    let key_der = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(ck.key_pair.serialize_der()));

    let server_keys = ServerKeys::generate();
    let mlkem_pk_bytes = server_keys.mlkem_pk_bytes.clone();
    let pq_fingerprint = server_keys.pq_fingerprint;
    let server_x25519_pub = server_keys.x25519_pub;

    // cap=0 → every connection rejected at the admission gate.
    let ctx = Arc::new(ServerCtx::new(server_keys).with_max_connections(0));

    let bind: SocketAddr = "127.0.0.1:0".parse().unwrap();
    let endpoint =
        proteus_transport_beta::server::make_endpoint(bind, vec![cert_der.clone()], key_der)
            .expect("make_endpoint");
    let local = endpoint.local_addr().expect("local_addr");

    let server_ctx = Arc::clone(&ctx);
    let server_task = tokio::spawn(async move {
        let _ =
            proteus_transport_beta::server::serve(endpoint, server_ctx, |_session| async {}).await;
    });

    // Client side. Even though the inner Proteus handshake will never
    // start (server closes first), we still drive `connect` and grab
    // the underlying quinn::Connection from the error path. Because
    // the server closes mid-flight, `connect` returns Err — but the
    // close fingerprint observation needs us to peek at the QUIC
    // connection BEFORE the inner handshake. We build the QUIC client
    // ourselves to avoid the inner-handshake noise.
    let mut roots = rustls::RootCertStore::empty();
    roots.add(cert_der).unwrap();
    let mut client_cfg =
        rustls::ClientConfig::builder_with_protocol_versions(&[&rustls::version::TLS13])
            .with_root_certificates(roots)
            .with_no_client_auth();
    client_cfg.alpn_protocols = vec![proteus_transport_beta::ALPN.to_vec()];
    let crypto = Arc::new(quinn::crypto::rustls::QuicClientConfig::try_from(client_cfg).unwrap());
    let mut endpoint_c = quinn::Endpoint::client("127.0.0.1:0".parse().unwrap()).unwrap();
    endpoint_c.set_default_client_config(quinn::ClientConfig::new(crypto));
    let conn = timeout(STEP, endpoint_c.connect(local, "localhost").unwrap())
        .await
        .expect("connect timeout")
        .expect("QUIC handshake should complete before server close");

    // Now wait for the server's CONNECTION_CLOSE to land. The server
    // closes immediately after `try_acquire_connection` returns
    // Rejected.
    let close_err = timeout(STEP, conn.closed()).await.expect("closed timeout");
    assert_canonical_close(&close_err, "max_connections");

    server_task.abort();
    drop(endpoint_c);
    let _ = mlkem_pk_bytes;
    let _ = pq_fingerprint;
    let _ = server_x25519_pub;
}

/// Branch (b): peer completes QUIC handshake but never opens a bidi
/// stream within `handshake_deadline`. The β server fires the
/// timeout branch and closes. MUST present the canonical fingerprint.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn beta_bi_stream_timeout_close_is_canonical() {
    let ck = generate_simple_self_signed(vec!["localhost".to_string()]).unwrap();
    let cert_der = CertificateDer::from(ck.cert.der().to_vec());
    let key_der = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(ck.key_pair.serialize_der()));

    let server_keys = ServerKeys::generate();
    // Aggressive 500 ms deadline so the test doesn't dawdle.
    let ctx =
        Arc::new(ServerCtx::new(server_keys).with_handshake_deadline(Duration::from_millis(500)));

    let bind: SocketAddr = "127.0.0.1:0".parse().unwrap();
    let endpoint =
        proteus_transport_beta::server::make_endpoint(bind, vec![cert_der.clone()], key_der)
            .expect("make_endpoint");
    let local = endpoint.local_addr().expect("local_addr");

    let server_ctx = Arc::clone(&ctx);
    let server_task = tokio::spawn(async move {
        let _ =
            proteus_transport_beta::server::serve(endpoint, server_ctx, |_session| async {}).await;
    });

    let mut roots = rustls::RootCertStore::empty();
    roots.add(cert_der).unwrap();
    let mut client_cfg =
        rustls::ClientConfig::builder_with_protocol_versions(&[&rustls::version::TLS13])
            .with_root_certificates(roots)
            .with_no_client_auth();
    client_cfg.alpn_protocols = vec![proteus_transport_beta::ALPN.to_vec()];
    let crypto = Arc::new(quinn::crypto::rustls::QuicClientConfig::try_from(client_cfg).unwrap());
    let mut endpoint_c = quinn::Endpoint::client("127.0.0.1:0".parse().unwrap()).unwrap();
    endpoint_c.set_default_client_config(quinn::ClientConfig::new(crypto));
    let conn = timeout(STEP, endpoint_c.connect(local, "localhost").unwrap())
        .await
        .expect("connect timeout")
        .expect("QUIC handshake should complete");

    // Deliberately DO NOT open a bidi stream. After 500 ms the server
    // hits the bi-stream-timeout branch and closes.
    let close_err = timeout(STEP, conn.closed()).await.expect("closed timeout");
    assert_canonical_close(&close_err, "bi_stream_timeout");

    server_task.abort();
    drop(endpoint_c);
}

/// Branch (c) (control): a successful session shutting down naturally
/// must also present the canonical fingerprint. If the natural close
/// already deviates from (a)/(b), the indistinguishability claim is
/// already broken before any of the rejection branches run.
///
/// Marked `#[ignore]` because the server's natural close uses the
/// 10 s post-handler grace period (intentional — see server.rs
/// "After the handler returns, wait for the peer to close" comment),
/// so this test always takes ~10 s. Run on demand:
/// `cargo test -p proteus-transport-beta -- --ignored beta_natural_close`.
#[ignore]
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn beta_natural_close_after_session_is_canonical() {
    let ck = generate_simple_self_signed(vec!["localhost".to_string()]).unwrap();
    let cert_der = CertificateDer::from(ck.cert.der().to_vec());
    let key_der = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(ck.key_pair.serialize_der()));

    let server_keys = ServerKeys::generate();
    let mlkem_pk_bytes = server_keys.mlkem_pk_bytes.clone();
    let pq_fingerprint = server_keys.pq_fingerprint;
    let server_x25519_pub = server_keys.x25519_pub;
    let ctx = Arc::new(ServerCtx::new(server_keys));

    let bind: SocketAddr = "127.0.0.1:0".parse().unwrap();
    let endpoint =
        proteus_transport_beta::server::make_endpoint(bind, vec![cert_der.clone()], key_der)
            .expect("make_endpoint");
    let local = endpoint.local_addr().expect("local_addr");

    let server_ctx = Arc::clone(&ctx);
    let server_task = tokio::spawn(async move {
        let _ =
            proteus_transport_beta::server::serve(endpoint, server_ctx, |mut session| async move {
                if let Ok(Some(rec)) = session.receiver.recv_record().await {
                    let _ = session.sender.send_record(&rec).await;
                    let _ = session.sender.flush().await;
                }
                let _ = session.sender.shutdown().await;
            })
            .await;
    });

    let mut rng = rand_core::OsRng;
    let client_id_sk = proteus_crypto::sig::generate(&mut rng);
    let client_cfg = ClientConfig {
        server_mlkem_pk_bytes: mlkem_pk_bytes,
        server_x25519_pub,
        server_pq_fingerprint: pq_fingerprint,
        client_id_sk,
        user_id: *b"closetst",
        pow_difficulty: 0,
        profile_hint: ProfileHint::Beta,
    };
    let mut client = timeout(
        STEP,
        proteus_transport_beta::client::connect("localhost", local, vec![cert_der], client_cfg),
    )
    .await
    .expect("connect timeout")
    .expect("β connect ok");

    // Drive one round-trip, then close from the client side. The
    // server's handler returns immediately after the echo + shutdown;
    // its accept-loop scope exit drops `conn`, which is what produces
    // the natural close. The client's `closed()` reports the
    // fingerprint we want to pin.
    timeout(STEP, client.session.sender.send_record(b"ping"))
        .await
        .unwrap()
        .unwrap();
    timeout(STEP, client.session.sender.flush())
        .await
        .unwrap()
        .unwrap();
    let _ = timeout(STEP, client.session.receiver.recv_record())
        .await
        .unwrap()
        .unwrap();

    // Half-close our send side without sending a QUIC CONNECTION_CLOSE
    // ourselves — we want the server's close fingerprint, not our own.
    let proteus_transport_alpha::session::AlphaSession { sender, .. } = client.session;
    let _ = sender.shutdown().await;

    // The server's serve() task drops `conn` after its 10 s
    // post-handler grace timeout — but in practice it drops as soon
    // as our shutdown-induced FIN reaches it and `conn.closed()`
    // resolves on the server side. We just await our local view.
    let close_err = timeout(STEP, client.connection.closed())
        .await
        .expect("closed timeout");
    // The server hands us a clean NO_ERROR / empty-reason close.
    // (LocallyClosed would mean WE closed first, which we deliberately
    // didn't — we only called sender.shutdown() on the QUIC stream,
    // not connection.close().)
    match &close_err {
        ConnectionError::ApplicationClosed(app) => {
            assert_canonical_close(&close_err, "natural_close");
            assert_eq!(app.error_code, VarInt::from_u32(0));
        }
        // It's also acceptable for our local stack to surface
        // LocallyClosed if the runtime races our endpoint drop ahead
        // of the server's close frame — but in that case there's no
        // wire-visible distinguisher to test, so skip the assertion.
        ConnectionError::LocallyClosed => { /* test inapplicable */ }
        other => panic!("natural close: unexpected variant {other:?}"),
    }

    server_task.abort();
}

/// Static audit (no I/O): grep the server source for the canonical
/// close pattern and assert NO close-site uses a non-zero code or a
/// non-empty reason string. This catches future regressions even if
/// the dynamic branch tests above can't be triggered (e.g. a new
/// rejection branch is added with its own distinct code/reason).
///
/// The audit is intentionally allow-listed — the only sanctioned
/// `conn.close(` call shape is `conn.close(0u32.into(), b"")`.
#[test]
fn beta_server_source_only_uses_canonical_close_shape() {
    let src = include_str!("../src/server.rs");
    let mut violations: Vec<String> = Vec::new();

    for (lineno, line) in src.lines().enumerate() {
        let trimmed = line.trim_start();
        // Skip comments — the doc-comment INTENTIONALLY mentions
        // the old distinct codes as a "do not do this" example.
        if trimmed.starts_with("//") {
            continue;
        }
        if let Some(rest) = trimmed.strip_prefix("conn.close(") {
            // We allow exactly: 0u32.into(), b"")
            let canonical = "0u32.into(), b\"\")";
            let canonical_alt = "0u32.into(),b\"\")";
            if !rest.starts_with(canonical) && !rest.starts_with(canonical_alt) {
                violations.push(format!(
                    "server.rs:{}: non-canonical close shape: `{}`",
                    lineno + 1,
                    line.trim()
                ));
            }
        }
    }

    assert!(
        violations.is_empty(),
        "β server.rs MUST use only the canonical close shape \
         `conn.close(0u32.into(), b\"\")` on every close-site. \
         A non-zero code or non-empty reason becomes a wire-visible \
         GFW classifier signal (RFC 9000 §19.19). Violations:\n  {}",
        violations.join("\n  "),
    );
}
