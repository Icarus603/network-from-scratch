//! Integration test that spawns the real `proteus-client` binary
//! with a YAML config that declares `server_endpoint_beta` and
//! verifies the binary actually uses the β QUIC path end-to-end.
//!
//! The companion `binary_launch.rs` covers the α-only path; this
//! file covers the dual-stack case the production-recommended
//! deployment uses.

use std::path::Path;
use std::process::{Command, Stdio};
use std::sync::Arc;
use std::time::Duration;

use base64::Engine;
use proteus_transport_alpha::server::{ServerCtx, ServerKeys};
use rcgen::generate_simple_self_signed;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::time::timeout;

const STEP: Duration = Duration::from_secs(30);

fn write_b64(path: &Path, bytes: &[u8]) {
    let s = base64::engine::general_purpose::STANDARD.encode(bytes);
    std::fs::write(path, format!("{s}\n")).unwrap();
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

async fn pick_free_port() -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    drop(listener);
    port
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

async fn socks5_connect(
    proxy_addr: std::net::SocketAddr,
    host: &str,
    port: u16,
) -> std::io::Result<TcpStream> {
    let mut sock = TcpStream::connect(proxy_addr).await?;
    sock.set_nodelay(true).ok();
    sock.write_all(&[0x05, 0x01, 0x00]).await?;
    let mut greet = [0u8; 2];
    sock.read_exact(&mut greet).await?;
    assert_eq!(greet, [0x05, 0x00]);
    let mut req = Vec::with_capacity(7 + host.len());
    req.extend_from_slice(&[0x05, 0x01, 0x00, 0x03]);
    req.push(host.len() as u8);
    req.extend_from_slice(host.as_bytes());
    req.extend_from_slice(&port.to_be_bytes());
    sock.write_all(&req).await?;
    let mut reply = [0u8; 10];
    sock.read_exact(&mut reply).await?;
    assert_eq!(reply[1], 0x00, "SOCKS5 CONNECT must succeed");
    Ok(sock)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn client_binary_dual_stack_routes_through_beta() {
    let tmp = {
        let dir = std::env::var("CARGO_TARGET_TMPDIR").unwrap_or_else(|_| "/tmp".to_string());
        let pid = std::process::id();
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        std::path::PathBuf::from(format!("{dir}/proteus-client-bintest-beta-{pid}-{nanos}"))
    };
    let _ = std::fs::remove_dir_all(&tmp);
    std::fs::create_dir_all(&tmp).unwrap();
    let keys_dir = tmp.join("keys");
    std::fs::create_dir_all(&keys_dir).unwrap();

    // 1. Upstream echo.
    let echo_addr = spawn_echo_upstream().await;

    // 2. Self-signed cert for "localhost" (β requires TLS).
    let ck = generate_simple_self_signed(vec!["localhost".to_string()]).unwrap();
    let cert_der = CertificateDer::from(ck.cert.der().to_vec());
    let key_der = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(ck.key_pair.serialize_der()));

    // 3. Server with both α (TLS) and β (QUIC) listeners.
    let server_keys = ServerKeys::generate();
    let mlkem_pk = server_keys.mlkem_pk_bytes.clone();
    let pq_fp = server_keys.pq_fingerprint;
    let x25519_pub = server_keys.x25519_pub;
    let mut rng = rand_core::OsRng;
    let client_sk = proteus_crypto::sig::generate(&mut rng);
    let ctx = Arc::new(ServerCtx::new(server_keys));

    // α TLS server.
    let acceptor =
        proteus_transport_alpha::tls::build_acceptor(vec![cert_der.clone()], key_der.clone_key())
            .expect("build_acceptor");
    let alpha_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let alpha_addr = alpha_listener.local_addr().unwrap();
    {
        let ctx = Arc::clone(&ctx);
        tokio::spawn(proteus_transport_alpha::server::serve_tls(
            alpha_listener,
            ctx,
            acceptor,
            move |session| async move {
                relay_one_session(session).await;
            },
        ));
    }
    // β QUIC server.
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

    // 4. Write client key files.
    write_b64(&keys_dir.join("server_mlkem.pk"), &mlkem_pk);
    write_b64(&keys_dir.join("server_x25519.pk"), &x25519_pub);
    write_b64(&keys_dir.join("server.pq.fp"), &pq_fp);
    write_b64(&keys_dir.join("client.ed25519.sk"), &client_sk.to_bytes());

    // 5. Write CA pem so the client trusts the self-signed cert.
    let ca_path = keys_dir.join("ca.pem");
    let pem = format!(
        "-----BEGIN CERTIFICATE-----\n{}\n-----END CERTIFICATE-----\n",
        base64::engine::general_purpose::STANDARD.encode(&cert_der),
    );
    std::fs::write(&ca_path, pem).unwrap();

    // 6. Write client.yaml exercising BOTH server_endpoint and
    //    server_endpoint_beta — this is the production dual-stack
    //    deployment shape.
    let socks_port = pick_free_port().await;
    let client_yaml = tmp.join("client.yaml");
    std::fs::write(
        &client_yaml,
        format!(
            "server_endpoint: \"{alpha_addr}\"\n\
             server_endpoint_beta: \"{beta_addr}\"\n\
             beta_server_name: \"localhost\"\n\
             beta_first_timeout_secs: 5\n\
             socks_listen: \"127.0.0.1:{socks_port}\"\n\
             user_id: \"betaclnt\"\n\
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
            socks_port = socks_port,
            keys_dir = keys_dir.display(),
            ca_path = ca_path.display(),
        ),
    )
    .unwrap();

    // 7. Spawn the proteus-client binary.
    let client_bin = env!("CARGO_BIN_EXE_proteus-client");
    let mut client = Command::new(client_bin)
        .args(["run", "--config"])
        .arg(&client_yaml)
        .env("RUST_LOG", "warn")
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("client spawn");

    // 8. Wait for SOCKS5 listener.
    let socks_addr: std::net::SocketAddr = format!("127.0.0.1:{socks_port}").parse().unwrap();
    let mut ready = false;
    for _ in 0..50 {
        if TcpStream::connect(socks_addr).await.is_ok() {
            ready = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    assert!(ready, "client SOCKS5 listener never came up");

    // 9. SOCKS5 CONNECT → β QUIC → server → echo upstream.
    let mut tunnel = timeout(
        STEP,
        socks5_connect(socks_addr, "127.0.0.1", echo_addr.port()),
    )
    .await
    .expect("socks connect timed out")
    .expect("socks connect ok");

    let payload = b"hello-via-dual-stack-beta-binary";
    timeout(STEP, tunnel.write_all(payload))
        .await
        .unwrap()
        .unwrap();

    let mut buf = vec![0u8; payload.len()];
    timeout(STEP, tunnel.read_exact(&mut buf))
        .await
        .expect("read echo timed out")
        .expect("read echo ok");
    assert_eq!(buf.as_slice(), payload);

    // 10. Cleanup.
    let _ = tunnel.shutdown().await;
    let _ = client.kill();
    let _ = client.wait();
    let _ = std::fs::remove_dir_all(&tmp);
}
