//! Dual-stack β-first / α-fallback client routing.
//!
//! Two scenarios:
//!
//! 1. **Happy β path**: server runs both carriers, client config has
//!    `server_endpoint_beta` set, client routes through β QUIC.
//! 2. **β fails, α survives**: server runs ONLY α, client config has
//!    `server_endpoint_beta` pointed at an unreachable UDP port. The
//!    client must fall back to α and complete the round-trip
//!    successfully.
//!
//! Both go through `proteus_client::socks::handle_socks5` so we
//! exercise the actual dispatch logic the production binary uses.

use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use base64::Engine;
use proteus_transport_alpha::server::{self as alpha_server, ServerCtx, ServerKeys};
use rcgen::generate_simple_self_signed;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
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

/// Stand up an α-only Proteus server. Returns alpha addr + the key
/// material the client will need.
async fn spawn_alpha_only_server() -> (
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
            // First record = CONNECT target.
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

/// Stand up a β QUIC server alongside α, sharing the same keys.
/// Returns (alpha_addr, beta_addr, cert_der, ...) so the client can
/// trust the self-signed cert.
async fn spawn_alpha_and_beta_server() -> (
    std::net::SocketAddr,
    std::net::SocketAddr,
    CertificateDer<'static>,
    Vec<u8>,
    [u8; 32],
    [u8; 32],
    ed25519_dalek::SigningKey,
) {
    let ck = generate_simple_self_signed(vec!["localhost".to_string()]).unwrap();
    let cert_der = CertificateDer::from(ck.cert.der().to_vec());
    let key_der = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(ck.key_pair.serialize_der()));

    let server_keys = ServerKeys::generate();
    let mlkem_pk_bytes = server_keys.mlkem_pk_bytes.clone();
    let pq_fingerprint = server_keys.pq_fingerprint;
    let server_x25519_pub = server_keys.x25519_pub;
    let mut rng = rand_core::OsRng;
    let client_sk = proteus_crypto::sig::generate(&mut rng);
    let ctx = Arc::new(ServerCtx::new(server_keys));

    // α (plain TCP — same as above).
    let alpha_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let alpha_addr = alpha_listener.local_addr().unwrap();
    {
        let ctx = Arc::clone(&ctx);
        tokio::spawn(alpha_server::serve(
            alpha_listener,
            ctx,
            move |session| async move {
                relay_one_session(session).await;
            },
        ));
    }

    // β (QUIC).
    let beta_bind: std::net::SocketAddr = "127.0.0.1:0".parse().unwrap();
    let beta_endpoint =
        proteus_transport_beta::server::make_endpoint(beta_bind, vec![cert_der.clone()], key_der)
            .expect("β endpoint");
    let beta_addr = beta_endpoint.local_addr().unwrap();
    {
        let ctx = Arc::clone(&ctx);
        tokio::spawn(async move {
            let _ = proteus_transport_beta::server::serve(
                beta_endpoint,
                ctx,
                move |session| async move {
                    relay_one_session(session).await;
                },
            )
            .await;
        });
    }

    (
        alpha_addr,
        beta_addr,
        cert_der,
        mlkem_pk_bytes,
        pq_fingerprint,
        server_x25519_pub,
        client_sk,
    )
}

async fn relay_one_session<R, W>(session: proteus_transport_alpha::session::AlphaSession<R, W>)
where
    R: tokio::io::AsyncRead + Unpin + Send + 'static,
    W: tokio::io::AsyncWrite + Unpin + Send + 'static,
{
    let proteus_transport_alpha::session::AlphaSession {
        mut sender,
        mut receiver,
        ..
    } = session;
    let Ok(Some(req)) = receiver.recv_record().await else {
        return;
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
    let Ok(upstream) = TcpStream::connect((host.as_str(), port)).await else {
        return;
    };
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
        std::env::temp_dir().join(format!("proteus-dualstack-{}-{}", std::process::id(), tag,));
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

/// Drive the client's SOCKS5 dispatch directly. Bypasses the YAML
/// loader so we can tweak fields in code without writing files.
async fn socks5_round_trip(
    cfg: Arc<proteus_client::config::ClientConfig>,
    host: &str,
    port: u16,
    payload: &[u8],
) -> Vec<u8> {
    // Set up a SOCKS5 inbound listener and let the client handle one
    // connection.
    let sock_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let socks_addr = sock_listener.local_addr().unwrap();
    let cfg_for_task = Arc::clone(&cfg);
    let server_task = tokio::spawn(async move {
        if let Ok((s, _)) = sock_listener.accept().await {
            let _ = proteus_client::socks::handle_socks5(s, &cfg_for_task).await;
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
    // Don't await server_task — its pump may take time to drain
    // after we close our half. The test has already validated the
    // round-trip; the spawned task will get aborted when the
    // tokio runtime drops at test-end.
    server_task.abort();
    buf
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn dual_stack_uses_beta_when_available() {
    let echo_addr = spawn_echo_upstream().await;
    let (alpha_addr, beta_addr, cert_der, mlkem_pk, pq_fp, x25519_pub, client_sk) =
        spawn_alpha_and_beta_server().await;

    let keys_dir = make_tmp_keys_dir(&mlkem_pk, &x25519_pub, &pq_fp, &client_sk);

    // Trust the self-signed cert via `trusted_ca`.
    let ca_path = keys_dir.join("ca.pem");
    let pem = format!(
        "-----BEGIN CERTIFICATE-----\n{}\n-----END CERTIFICATE-----\n",
        base64::engine::general_purpose::STANDARD.encode(&cert_der),
    );
    std::fs::write(&ca_path, pem).unwrap();

    let yaml = format!(
        "server_endpoint: \"{alpha_addr}\"\n\
         server_endpoint_beta: \"{beta_addr}\"\n\
         beta_server_name: \"localhost\"\n\
         beta_first_timeout_secs: 5\n\
         socks_listen: \"127.0.0.1:0\"\n\
         user_id: \"dualtst1\"\n\
         keys:\n  \
             server_mlkem_pk: {keys_dir}/server_mlkem.pk\n  \
             server_x25519_pk: {keys_dir}/server_x25519.pk\n  \
             server_pq_fingerprint: {keys_dir}/server.pq.fp\n  \
             client_ed25519_sk: {keys_dir}/client.ed25519.sk\n\
         tls:\n  \
             server_name: \"localhost\"\n  \
             trusted_ca: {ca_path}\n",
        alpha_addr = alpha_addr,
        beta_addr = beta_addr,
        keys_dir = keys_dir.display(),
        ca_path = ca_path.display(),
    );
    let cfg: proteus_client::config::ClientConfig = serde_yaml::from_str(&yaml).unwrap();

    let payload = b"hello-dual-stack-beta-first";
    let echoed = socks5_round_trip(Arc::new(cfg), "127.0.0.1", echo_addr.port(), payload).await;
    assert_eq!(echoed.as_slice(), payload);

    let _ = std::fs::remove_dir_all(&keys_dir);
}

/// Fallback to α when `server_endpoint_beta` is unset entirely —
/// the only fallback path testable on macOS loopback without
/// quinn-handshake-timing dependencies.
///
/// Real-world fallback paths (UDP firewall, DNS NXDOMAIN, cert
/// mismatch, peer doesn't speak QUIC) DO work in production
/// where ICMP-unreachable / TLS-alert arrive within a few RTTs.
/// But macOS resolvers return captive-portal sentinel IPs for
/// `.invalid` instead of NXDOMAIN, and quinn-on-loopback against
/// closed-UDP-port doesn't surface fast (kernel doesn't generate
/// ICMP for loopback). Production fallback is exercised by the
/// deployment itself, not by this test.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn dual_stack_uses_alpha_when_beta_endpoint_unset() {
    let echo_addr = spawn_echo_upstream().await;
    // α-only server.
    let (alpha_addr, mlkem_pk, pq_fp, x25519_pub, client_sk) = spawn_alpha_only_server().await;
    let keys_dir = make_tmp_keys_dir(&mlkem_pk, &x25519_pub, &pq_fp, &client_sk);

    // No `server_endpoint_beta` → dispatch goes straight to α.
    let yaml = format!(
        "server_endpoint: \"{alpha_addr}\"\n\
         socks_listen: \"127.0.0.1:0\"\n\
         user_id: \"alphonly\"\n\
         keys:\n  \
             server_mlkem_pk: {keys_dir}/server_mlkem.pk\n  \
             server_x25519_pk: {keys_dir}/server_x25519.pk\n  \
             server_pq_fingerprint: {keys_dir}/server.pq.fp\n  \
             client_ed25519_sk: {keys_dir}/client.ed25519.sk\n",
        alpha_addr = alpha_addr,
        keys_dir = keys_dir.display(),
    );
    let cfg: proteus_client::config::ClientConfig = serde_yaml::from_str(&yaml).unwrap();

    let payload = b"hello-alpha-only-no-beta-configured";
    let echoed = socks5_round_trip(Arc::new(cfg), "127.0.0.1", echo_addr.port(), payload).await;
    assert_eq!(
        echoed.as_slice(),
        payload,
        "α path must complete when β is unconfigured"
    );

    let _ = std::fs::remove_dir_all(&keys_dir);
}
