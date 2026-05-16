//! Integration test that spawns the real `proteus-server` binary,
//! drives the full handshake from an in-process `proteus-client`
//! library call, and verifies a CONNECT relay round-trips a payload
//! through an upstream echo server.
//!
//! This is the **production-acceptance** test for the binary itself:
//! it verifies the YAML config loader, the keygen → run pipeline, the
//! relay logic, and the SIGTERM graceful drain. Any production
//! regression in the binary will surface here.

use std::path::Path;
use std::process::{Command, Stdio};
use std::time::Duration;

use base64::Engine;
use proteus_transport_alpha::client::{self, ClientConfig};
use rand_core::OsRng;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::time::timeout;

const STEP: Duration = Duration::from_secs(30);

fn read_b64_file(path: &Path) -> Vec<u8> {
    let raw = std::fs::read(path).unwrap();
    let trimmed: Vec<u8> = raw
        .iter()
        .copied()
        .filter(|b| !b.is_ascii_whitespace())
        .collect();
    base64::engine::general_purpose::STANDARD
        .decode(&trimmed)
        .unwrap()
}

/// Bring up a TCP echo server on `127.0.0.1:0`. Returns the bound addr.
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

/// Pick an unused TCP port by binding ephemerally and dropping.
async fn pick_free_port() -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    drop(listener);
    port
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn binary_run_handshake_and_relay() {
    // tmp dir for keys + config
    let tmp = tempfile_in_target();
    let _ = std::fs::remove_dir_all(&tmp);
    std::fs::create_dir_all(&tmp).unwrap();
    let keys_dir = tmp.join("keys");

    // 1. Generate server keys via the binary.
    let server_bin = env!("CARGO_BIN_EXE_proteus-server");
    let status = Command::new(server_bin)
        .args(["keygen", "--out"])
        .arg(&keys_dir)
        .status()
        .expect("keygen exec");
    assert!(status.success(), "keygen failed");
    assert!(keys_dir.join("server_lt.mlkem768.pk").exists());

    // 2. Pick a port for the server to listen on.
    let listen_port = pick_free_port().await;

    // 3. Spawn upstream echo first so the relay has somewhere to connect.
    let echo_addr = spawn_echo_upstream().await;

    // 4. Write a minimal server.yaml (NO TLS — keep this binary test
    //    independent of cert provisioning).
    let server_yaml = tmp.join("server.yaml");
    std::fs::write(
        &server_yaml,
        format!(
            "listen_alpha: \"127.0.0.1:{port}\"\n\
             drain_secs: 1\n\
             outbound_filter:\n  \
                 disabled: true\n\
             keys:\n  \
                 mlkem_pk: {keys_dir}/server_lt.mlkem768.pk\n  \
                 mlkem_sk: {keys_dir}/server_lt.mlkem768.sk\n  \
                 x25519_pk: {keys_dir}/server_lt.x25519.pk\n  \
                 x25519_sk: {keys_dir}/server_lt.x25519.sk\n",
            port = listen_port,
            keys_dir = keys_dir.display(),
        ),
    )
    .unwrap();

    // 5. Spawn the server binary.
    let mut server = Command::new(server_bin)
        .args(["run", "--config"])
        .arg(&server_yaml)
        .env("RUST_LOG", "warn")
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("server spawn");

    // Give the binary up to 5 s to bind the listener. Probe TCP until
    // it accepts a connection.
    let listen_addr: std::net::SocketAddr = format!("127.0.0.1:{listen_port}").parse().unwrap();
    let mut ready = false;
    for _ in 0..50 {
        if TcpStream::connect(listen_addr).await.is_ok() {
            ready = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    assert!(ready, "server binary failed to bind listener");

    // 6. Construct an in-process client config matching the server's
    //    on-disk keys.
    let mlkem_pk = read_b64_file(&keys_dir.join("server_lt.mlkem768.pk"));
    let x25519_pk_bytes = read_b64_file(&keys_dir.join("server_lt.x25519.pk"));
    assert_eq!(x25519_pk_bytes.len(), 32);
    let mut server_x25519_pub = [0u8; 32];
    server_x25519_pub.copy_from_slice(&x25519_pk_bytes);
    let fp_bytes = read_b64_file(&keys_dir.join("server_lt.pq.fingerprint"));
    assert_eq!(fp_bytes.len(), 32);
    let mut server_pq_fingerprint = [0u8; 32];
    server_pq_fingerprint.copy_from_slice(&fp_bytes);

    let mut rng = OsRng;
    let client_id_sk = proteus_crypto::sig::generate(&mut rng);
    let client_cfg = ClientConfig::new(
        mlkem_pk,
        server_x25519_pub,
        server_pq_fingerprint,
        client_id_sk,
        *b"bintest1",
    );

    // 7. Drive a full handshake.
    let mut session = timeout(STEP, client::connect(&listen_addr.to_string(), &client_cfg))
        .await
        .expect("client connect timed out")
        .expect("client handshake ok");

    // 8. Send CONNECT request for the upstream echo, then a payload,
    //    receive echoed bytes.
    let host = "127.0.0.1";
    let mut connect_req = Vec::new();
    connect_req.push(host.len() as u8);
    connect_req.extend_from_slice(host.as_bytes());
    connect_req.extend_from_slice(&echo_addr.port().to_be_bytes());
    timeout(STEP, session.sender.send_record(&connect_req))
        .await
        .unwrap()
        .unwrap();
    timeout(STEP, session.sender.flush())
        .await
        .unwrap()
        .unwrap();

    let payload = b"hello-binary-test";
    timeout(STEP, session.sender.send_record(payload))
        .await
        .unwrap()
        .unwrap();
    timeout(STEP, session.sender.flush())
        .await
        .unwrap()
        .unwrap();

    let mut echoed = Vec::new();
    while echoed.len() < payload.len() {
        let chunk = timeout(STEP, session.receiver.recv_record())
            .await
            .expect("recv timed out")
            .expect("recv ok")
            .expect("session closed early");
        echoed.extend_from_slice(&chunk);
    }
    assert_eq!(echoed.as_slice(), payload);

    // 9. Shut down the client cleanly, then send SIGTERM to the server
    //    binary and verify it exits within the 30 s drain window.
    let _ = timeout(STEP, session.sender.shutdown()).await;
    send_sigterm(&server);
    // drain_secs: 1 in yaml → server should exit within 5s.
    let wait_status = wait_with_timeout(&mut server, Duration::from_secs(5));
    assert!(wait_status.is_some(), "server failed to drain on SIGTERM");

    let _ = std::fs::remove_dir_all(&tmp);
}

fn tempfile_in_target() -> std::path::PathBuf {
    let dir = std::env::var("CARGO_TARGET_TMPDIR").unwrap_or_else(|_| "/tmp".to_string());
    let pid = std::process::id();
    std::path::PathBuf::from(format!("{dir}/proteus-bin-test-{pid}"))
}

#[cfg(unix)]
#[allow(unsafe_code)] // tightly-scoped: libc::kill on a positive pid
fn send_sigterm(child: &std::process::Child) {
    // SAFETY: child.id() returns the OS pid. libc::kill(pid, SIGTERM)
    // sends to that single process. Documented libc FFI.
    unsafe {
        libc::kill(child.id() as libc::pid_t, libc::SIGTERM);
    }
}

#[cfg(not(unix))]
fn send_sigterm(_child: &std::process::Child) {
    // No SIGTERM on Windows; rely on kill() in the wait helper.
}

fn wait_with_timeout(
    child: &mut std::process::Child,
    timeout: Duration,
) -> Option<std::process::ExitStatus> {
    let start = std::time::Instant::now();
    loop {
        match child.try_wait() {
            Ok(Some(status)) => return Some(status),
            Ok(None) => {
                if start.elapsed() > timeout {
                    let _ = child.kill();
                    let _ = child.wait();
                    return None;
                }
                std::thread::sleep(Duration::from_millis(100));
            }
            Err(_) => return None,
        }
    }
}
