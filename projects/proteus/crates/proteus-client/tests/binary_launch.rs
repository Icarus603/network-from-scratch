//! Integration test that spawns the real `proteus-client` binary, has
//! it run as a SOCKS5 inbound to an in-process Proteus server, and
//! verifies that a SOCKS5 CONNECT round-trips a payload through to an
//! upstream echo server.
//!
//! Covers: clap parsing, YAML loader, key file decoders, SOCKS5
//! handshake, Proteus handshake, bidirectional pump.

use std::path::Path;
use std::process::{Command, Stdio};
use std::sync::Arc;
use std::time::Duration;

use base64::Engine;
use proteus_transport_alpha::server::{self, ServerCtx, ServerKeys};
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

/// Stand up an in-process Proteus server that loops accept → handshake
/// → relay-to-host:port. Returns the server's listen addr + the keys
/// the client needs.
async fn spawn_proteus_server() -> (
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
    let client_sk_bytes: [u8; 32] = {
        use rand_core::RngCore;
        let mut b = [0u8; 32];
        rng.fill_bytes(&mut b);
        b
    };
    let client_sk = ed25519_dalek::SigningKey::from_bytes(&client_sk_bytes);

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
            tokio::spawn(async move {
                let session = match server::handshake_over_tcp(stream, &ctx).await {
                    Ok(s) => s,
                    Err(_) => return,
                };
                let proteus_transport_alpha::session::AlphaSession {
                    mut sender,
                    mut receiver,
                    ..
                } = session;
                // First record = CONNECT target.
                let req = match receiver.recv_record().await {
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
        mlkem_pk_bytes,
        pq_fingerprint,
        server_x25519_pub,
        client_sk,
    )
}

async fn socks5_connect(
    proxy_addr: std::net::SocketAddr,
    host: &str,
    port: u16,
) -> std::io::Result<TcpStream> {
    let mut sock = TcpStream::connect(proxy_addr).await?;
    sock.set_nodelay(true).ok();
    // Greeting: ver=5, nmethods=1, methods=[0x00].
    sock.write_all(&[0x05, 0x01, 0x00]).await?;
    let mut greet = [0u8; 2];
    sock.read_exact(&mut greet).await?;
    assert_eq!(greet, [0x05, 0x00]);
    // CONNECT request: ver=5, cmd=1, rsv=0, atyp=3 (domain), len, host, port.
    let mut req = Vec::with_capacity(7 + host.len());
    req.extend_from_slice(&[0x05, 0x01, 0x00, 0x03]);
    req.push(host.len() as u8);
    req.extend_from_slice(host.as_bytes());
    req.extend_from_slice(&port.to_be_bytes());
    sock.write_all(&req).await?;
    let mut reply = [0u8; 10]; // ver,rep,rsv,atyp(1)+ipv4(4)+port(2)
    sock.read_exact(&mut reply).await?;
    assert_eq!(reply[1], 0x00, "SOCKS5 CONNECT must succeed");
    Ok(sock)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn client_binary_socks5_to_upstream() {
    let tmp = {
        let dir = std::env::var("CARGO_TARGET_TMPDIR").unwrap_or_else(|_| "/tmp".to_string());
        let pid = std::process::id();
        std::path::PathBuf::from(format!("{dir}/proteus-client-bintest-{pid}"))
    };
    let _ = std::fs::remove_dir_all(&tmp);
    std::fs::create_dir_all(&tmp).unwrap();
    let keys_dir = tmp.join("keys");
    std::fs::create_dir_all(&keys_dir).unwrap();

    // 1. Upstream echo.
    let echo_addr = spawn_echo_upstream().await;

    // 2. In-process Proteus server (no TLS for this test).
    let (proxy_addr, mlkem_pk, pq_fp, x25519_pub, client_sk) = spawn_proteus_server().await;

    // 3. Write key files for the client binary to load.
    write_b64(&keys_dir.join("server_mlkem.pk"), &mlkem_pk);
    write_b64(&keys_dir.join("server_x25519.pk"), &x25519_pub);
    write_b64(&keys_dir.join("server.pq.fp"), &pq_fp);
    write_b64(&keys_dir.join("client.ed25519.sk"), &client_sk.to_bytes());

    // 4. Pick a SOCKS5 port and write client.yaml.
    let socks_port = pick_free_port().await;
    let client_yaml = tmp.join("client.yaml");
    std::fs::write(
        &client_yaml,
        format!(
            "server_endpoint: \"{proxy_addr}\"\n\
             socks_listen: \"127.0.0.1:{socks_port}\"\n\
             user_id: \"binclnt1\"\n\
             keys:\n  \
                 server_mlkem_pk: {keys_dir}/server_mlkem.pk\n  \
                 server_x25519_pk: {keys_dir}/server_x25519.pk\n  \
                 server_pq_fingerprint: {keys_dir}/server.pq.fp\n  \
                 client_ed25519_sk: {keys_dir}/client.ed25519.sk\n",
            proxy_addr = proxy_addr,
            socks_port = socks_port,
            keys_dir = keys_dir.display(),
        ),
    )
    .unwrap();

    // 5. Spawn the proteus-client binary.
    let client_bin = env!("CARGO_BIN_EXE_proteus-client");
    let mut client = Command::new(client_bin)
        .args(["run", "--config"])
        .arg(&client_yaml)
        .env("RUST_LOG", "warn")
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("client spawn");

    // 6. Wait for SOCKS5 listener.
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

    // 7. SOCKS5 CONNECT through the client → server → echo upstream.
    let mut tunnel = timeout(
        STEP,
        socks5_connect(socks_addr, "127.0.0.1", echo_addr.port()),
    )
    .await
    .expect("socks connect timed out")
    .expect("socks connect ok");

    let payload = b"hello-via-socks5-client-binary";
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

    // 8. Cleanup.
    let _ = tunnel.shutdown().await;
    let _ = client.kill();
    let _ = client.wait();
    let _ = std::fs::remove_dir_all(&tmp);
}
