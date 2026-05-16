//! End-to-end test of the **TLS 1.3 outer + Proteus inner** stack.
//!
//! Verifies that wrapping the α-profile handshake in real TLS 1.3 still
//! delivers correct round-trips. Uses a generated self-signed cert.

use std::sync::Arc;
use std::time::Duration;

use proteus_transport_alpha::client::{self, ClientConfig};
use proteus_transport_alpha::server::{self, ServerCtx, ServerKeys};
use proteus_transport_alpha::tls;
use rand_core::OsRng;
use rcgen::generate_simple_self_signed;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use tokio::net::{TcpListener, TcpStream};
use tokio::time::timeout;

const STEP: Duration = Duration::from_secs(20);

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn tls_wrapped_handshake_and_echo_round_trip() {
    // ----- generate self-signed cert for "localhost" -----
    let ck = generate_simple_self_signed(vec!["localhost".to_string()]).unwrap();
    let cert_der = CertificateDer::from(ck.cert.der().to_vec());
    let key_der = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(ck.key_pair.serialize_der()));

    let acceptor = tls::build_acceptor(vec![cert_der.clone()], key_der).unwrap();

    // Build a connector that trusts our generated cert.
    let mut roots = rustls::RootCertStore::empty();
    roots.add(cert_der).unwrap();
    let mut client_cfg_tls =
        rustls::ClientConfig::builder_with_protocol_versions(&[&rustls::version::TLS13])
            .with_root_certificates(roots)
            .with_no_client_auth();
    client_cfg_tls.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
    let connector = tokio_rustls::TlsConnector::from(Arc::new(client_cfg_tls));

    // ----- Proteus server -----
    let server_keys = ServerKeys::generate();
    let mlkem_pk_bytes = server_keys.mlkem_pk_bytes.clone();
    let pq_fingerprint = server_keys.pq_fingerprint;
    let server_x25519_pub = server_keys.x25519_pub;
    let ctx = Arc::new(ServerCtx::new(server_keys));

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let server_ctx = Arc::clone(&ctx);
    let server_acceptor = acceptor.clone();
    let server_task = tokio::spawn(async move {
        loop {
            let (stream, _) = match listener.accept().await {
                Ok(t) => t,
                Err(_) => return,
            };
            let ctx = Arc::clone(&server_ctx);
            let acceptor = server_acceptor.clone();
            tokio::spawn(async move {
                let mut session = match server::handshake_over_tls(stream, &acceptor, &ctx).await {
                    Ok(s) => s,
                    Err(_) => return,
                };
                while let Ok(Some(msg)) = session.receiver.recv_record().await {
                    if session.sender.send_record(&msg).await.is_err() {
                        break;
                    }
                    if session.sender.flush().await.is_err() {
                        break;
                    }
                }
            });
        }
    });

    // ----- Proteus client over TLS -----
    let mut rng = OsRng;
    let client_id_sk = proteus_crypto::sig::generate(&mut rng);
    let client_cfg = ClientConfig {
        server_mlkem_pk_bytes: mlkem_pk_bytes,
        server_x25519_pub,
        server_pq_fingerprint: pq_fingerprint,
        client_id_sk,
        user_id: *b"tls_test",
        pow_difficulty: 0,
        profile_hint: proteus_wire::ProfileHint::Alpha,
    };
    let stream = TcpStream::connect(addr).await.unwrap();
    let mut session = timeout(
        STEP,
        client::handshake_over_tls(stream, &connector, "localhost", &client_cfg),
    )
    .await
    .expect("connect timed out")
    .expect("handshake ok");

    for i in 0u32..10 {
        let mut payload = vec![0u8; 16 + (i as usize * 64)];
        for (j, b) in payload.iter_mut().enumerate() {
            *b = (i as u8).wrapping_add(j as u8);
        }
        timeout(STEP, session.sender.send_record(&payload))
            .await
            .expect("send timed out")
            .expect("send ok");
        timeout(STEP, session.sender.flush())
            .await
            .expect("flush timed out")
            .expect("flush ok");
        let echoed = timeout(STEP, session.receiver.recv_record())
            .await
            .expect("recv timed out")
            .expect("recv ok")
            .expect("server closed early");
        assert_eq!(echoed, payload, "round-trip mismatch at i={i}");
    }

    let _ = timeout(STEP, session.sender.shutdown()).await;
    server_task.abort();
}
