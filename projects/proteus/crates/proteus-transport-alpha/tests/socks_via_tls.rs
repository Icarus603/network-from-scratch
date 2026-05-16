//! Production-realistic end-to-end test:
//!
//! 1. Stand up an upstream HTTP-style echo server on `127.0.0.1:E`.
//! 2. Stand up a Proteus server with TLS 1.3 outer (self-signed cert)
//!    on `127.0.0.1:S` whose relay forwards inner streams to upstream.
//! 3. Open a client that wraps a Proteus α handshake inside a TLS 1.3
//!    connection, then sends a CONNECT request for the upstream.
//! 4. Verify that a byte payload round-trips client → server → upstream → server → client.
//!
//! Exercises every layer in the production stack except SOCKS5
//! handshake parsing (which has its own unit-level tests in the client
//! binary). The path here is what every real session looks like.

use std::sync::Arc;
use std::time::Duration;

use proteus_transport_alpha::client::{self, ClientConfig};
use proteus_transport_alpha::server::{self, ServerCtx, ServerKeys};
use proteus_transport_alpha::tls;
use rand_core::OsRng;
use rcgen::generate_simple_self_signed;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::time::timeout;

const STEP: Duration = Duration::from_secs(20);

/// Spin up a one-shot TCP echo server that reads up to 1 MiB from any
/// client and echoes it back. Returns the bound addr.
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
                let mut buf = vec![0u8; 1024];
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

/// Stand up the Proteus TLS server with a self-signed cert; return the
/// bind addr + the cert (so the test client can pin it).
async fn spawn_proteus_tls_server() -> (
    std::net::SocketAddr,
    CertificateDer<'static>,
    [u8; 32],
    Vec<u8>,
    [u8; 32],
) {
    // ---- TLS cert ----
    let ck = generate_simple_self_signed(vec!["localhost".to_string()]).unwrap();
    let cert_der = CertificateDer::from(ck.cert.der().to_vec());
    let key_der = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(ck.key_pair.serialize_der()));
    let acceptor = tls::build_acceptor(vec![cert_der.clone()], key_der).unwrap();

    // ---- Proteus server ----
    let server_keys = ServerKeys::generate();
    let mlkem_pk_bytes = server_keys.mlkem_pk_bytes.clone();
    let pq_fingerprint = server_keys.pq_fingerprint;
    let server_x25519_pub = server_keys.x25519_pub;
    let ctx = Arc::new(ServerCtx::new(server_keys));

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
            let acceptor = acceptor.clone();
            tokio::spawn(async move {
                let mut session = match server::handshake_over_tls(stream, &acceptor, &ctx).await {
                    Ok(s) => s,
                    Err(_) => return,
                };
                // CONNECT relay: first record = host_len|host|port_be.
                let req = match session.receiver.recv_record().await {
                    Ok(Some(b)) => b,
                    _ => return,
                };
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
                let upstream = match TcpStream::connect((host.as_str(), port)).await {
                    Ok(s) => s,
                    Err(_) => return,
                };
                let (mut up_r, mut up_w) = upstream.into_split();
                let proteus_transport_alpha::session::AlphaSession {
                    mut sender,
                    mut receiver,
                    ..
                } = session;
                let c2u = async {
                    while let Ok(Some(b)) = receiver.recv_record().await {
                        if up_w.write_all(&b).await.is_err() {
                            break;
                        }
                    }
                    let _ = up_w.shutdown().await;
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
                    let _ = sender.shutdown().await;
                };
                tokio::join!(c2u, u2c);
            });
        }
    });
    (
        addr,
        cert_der,
        pq_fingerprint,
        mlkem_pk_bytes,
        server_x25519_pub,
    )
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn socks_request_via_tls_to_echo_upstream() {
    // 1. Upstream echo server.
    let upstream_addr = spawn_echo_upstream().await;

    // 2. Proteus TLS server.
    let (proxy_addr, cert_der, pq_fingerprint, mlkem_pk_bytes, server_x25519_pub) =
        spawn_proteus_tls_server().await;

    // 3. Client side: build TLS connector trusting our self-signed cert.
    let mut roots = rustls::RootCertStore::empty();
    roots.add(cert_der).unwrap();
    let mut tls_cfg =
        rustls::ClientConfig::builder_with_protocol_versions(&[&rustls::version::TLS13])
            .with_root_certificates(roots)
            .with_no_client_auth();
    tls_cfg.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
    let connector = tokio_rustls::TlsConnector::from(Arc::new(tls_cfg));

    let mut rng = OsRng;
    let client_id_sk = proteus_crypto::sig::generate(&mut rng);
    let client_cfg = ClientConfig {
        server_mlkem_pk_bytes: mlkem_pk_bytes,
        server_x25519_pub,
        server_pq_fingerprint: pq_fingerprint,
        client_id_sk,
        user_id: *b"socks_e2",
        pow_difficulty: 0,
        profile_hint: proteus_wire::ProfileHint::Alpha,
    };

    let tcp = TcpStream::connect(proxy_addr).await.unwrap();
    let mut session = timeout(
        STEP,
        client::handshake_over_tls(tcp, &connector, "localhost", &client_cfg),
    )
    .await
    .expect("connect timed out")
    .expect("handshake ok");

    // 4. Send the CONNECT request: host_len|host|port_be.
    let mut connect_req = Vec::new();
    let host = "127.0.0.1".to_string();
    connect_req.push(host.len() as u8);
    connect_req.extend_from_slice(host.as_bytes());
    connect_req.extend_from_slice(&upstream_addr.port().to_be_bytes());
    timeout(STEP, session.sender.send_record(&connect_req))
        .await
        .unwrap()
        .unwrap();
    timeout(STEP, session.sender.flush())
        .await
        .unwrap()
        .unwrap();

    // 5. Round-trip a payload via upstream echo.
    //
    // Note: TCP does not preserve record boundaries. The upstream echo
    // service reads in 1024-byte chunks and writes each chunk back; the
    // relay turns each read into one outbound Proteus record. So a
    // single send may produce multiple inbound records on the client
    // side — accumulate until we have the same byte count back.
    let payloads: &[&[u8]] = &[b"hello", b"proteus", b"production-ready", &[0xa5u8; 8192]];
    for p in payloads {
        timeout(STEP, session.sender.send_record(p))
            .await
            .unwrap()
            .unwrap();
        timeout(STEP, session.sender.flush())
            .await
            .unwrap()
            .unwrap();
        let mut echoed = Vec::with_capacity(p.len());
        while echoed.len() < p.len() {
            let chunk = timeout(STEP, session.receiver.recv_record())
                .await
                .expect("recv timed out")
                .expect("recv ok")
                .expect("upstream closed early");
            echoed.extend_from_slice(&chunk);
        }
        assert_eq!(echoed.len(), p.len(), "byte-count mismatch");
        assert_eq!(echoed.as_slice(), *p, "content mismatch");
    }

    // 6. Clean shutdown.
    let _ = timeout(STEP, session.sender.shutdown()).await;
}
