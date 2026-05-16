//! β-profile end-to-end smoke test.
//!
//! Verifies the full QUIC path:
//!   - server binds a UDP socket + quinn endpoint with TLS 1.3
//!   - client dials with proteus-β-v1 ALPN, completes QUIC handshake
//!   - both sides run the same Proteus inner handshake as α
//!   - a record round-trips through the QUIC stream
//!
//! Uses a self-signed cert generated at test time.

use std::sync::Arc;
use std::time::Duration;

use proteus_transport_alpha::client::ClientConfig;
use proteus_transport_alpha::server::{ServerCtx, ServerKeys};
use proteus_transport_alpha::ProfileHint;
use rcgen::generate_simple_self_signed;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use tokio::time::timeout;

const STEP: Duration = Duration::from_secs(20);

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn beta_quic_round_trip() {
    // Self-signed cert for "localhost".
    let ck = generate_simple_self_signed(vec!["localhost".to_string()]).unwrap();
    let cert_der = CertificateDer::from(ck.cert.der().to_vec());
    let key_der = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(ck.key_pair.serialize_der()));

    // Server side.
    let server_keys = ServerKeys::generate();
    let mlkem_pk_bytes = server_keys.mlkem_pk_bytes.clone();
    let pq_fingerprint = server_keys.pq_fingerprint;
    let server_x25519_pub = server_keys.x25519_pub;
    let ctx = Arc::new(ServerCtx::new(server_keys));

    // Bind to ephemeral UDP port.
    let bind: std::net::SocketAddr = "127.0.0.1:0".parse().unwrap();
    let endpoint =
        proteus_transport_beta::server::make_endpoint(bind, vec![cert_der.clone()], key_der)
            .expect("make_endpoint");
    let local = endpoint.local_addr().expect("local_addr");

    let server_ctx = Arc::clone(&ctx);
    let server_task = tokio::spawn(async move {
        let _ =
            proteus_transport_beta::server::serve(endpoint, server_ctx, |mut session| async move {
                // Echo loop: bounce one record back, then close.
                if let Ok(Some(rec)) = session.receiver.recv_record().await {
                    let _ = session.sender.send_record(&rec).await;
                    let _ = session.sender.flush().await;
                }
                let _ = session.sender.shutdown().await;
            })
            .await;
    });

    // Client side.
    let mut rng = rand_core::OsRng;
    let client_id_sk = proteus_crypto::sig::generate(&mut rng);
    let client_cfg = ClientConfig {
        server_mlkem_pk_bytes: mlkem_pk_bytes,
        server_x25519_pub,
        server_pq_fingerprint: pq_fingerprint,
        client_id_sk,
        user_id: *b"betateE2",
        pow_difficulty: 0,
        profile_hint: ProfileHint::Beta,
    };
    let mut client = timeout(
        STEP,
        proteus_transport_beta::client::connect("localhost", local, vec![cert_der], client_cfg),
    )
    .await
    .expect("connect timed out")
    .expect("β connect ok");

    let payload = b"hello-from-beta-quic";
    timeout(STEP, client.session.sender.send_record(payload))
        .await
        .unwrap()
        .unwrap();
    timeout(STEP, client.session.sender.flush())
        .await
        .unwrap()
        .unwrap();
    let echoed = timeout(STEP, client.session.receiver.recv_record())
        .await
        .expect("recv timed out")
        .expect("recv ok")
        .expect("server closed early");
    assert_eq!(echoed, payload);

    // Move the sender out so we can shutdown (it consumes self).
    let proteus_transport_alpha::session::AlphaSession { sender, .. } = client.session;
    let _ = timeout(STEP, sender.shutdown()).await;
    // Explicit close so the server's await on `conn.closed()`
    // returns promptly instead of waiting for idle timeout.
    client.connection.close(0u32.into(), b"bye");
    drop(client.endpoint);
    server_task.abort();
}

#[test]
fn alpn_constant_decodes_to_expected_string() {
    let s = std::str::from_utf8(proteus_transport_beta::ALPN).unwrap();
    assert_eq!(s, "proteus-β-v1");
}
