//! Cross-language RFC 9849 gate: Go uTLS Chrome profile → Path A →
//! Rust/BoringSSL ECH termination.

use std::fs;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::mpsc;
use std::sync::Arc;
use std::time::Duration;
use std::time::{SystemTime, UNIX_EPOCH};

use base64::Engine as _;
use proteus_ech::{EchAcceptor, EchKey, EXPORTER_LEN};
use proteus_handshake::knock::KnockPsk;
use proteus_transport_alpha::client::ClientConfig;
use proteus_transport_alpha::knock_dispatch::{
    dispatch_or_local_terminate, DispatchConfig, PathARouting,
};
use proteus_transport_alpha::server::{self, ServerCtx, ServerKeys};
use rand_core::OsRng;
use rcgen::{CertificateParams, KeyPair};
use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};

const PUBLIC_NAME: &str = "public.example";
const INNER_NAME: &str = "secret.example";

#[derive(Debug)]
struct ServerOutcome {
    accepted: bool,
    exporter: Option<[u8; EXPORTER_LEN]>,
    wire: Vec<u8>,
    error: Option<String>,
}

struct TempDir(PathBuf);

impl TempDir {
    fn new() -> Self {
        let unique = format!(
            "proteus-utls-ech-{}-{}",
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .expect("clock after epoch")
                .as_nanos()
        );
        let path = std::env::temp_dir().join(unique);
        fs::create_dir(&path).expect("create temporary interop directory");
        Self(path)
    }
}

struct ChildGuard(Child);

impl Drop for ChildGuard {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn ech_material(config_id: u8, retry_config: bool) -> (EchKey, Vec<u8>) {
    let mut generated =
        proteus_ech::generate_ech_key(config_id, PUBLIC_NAME, INNER_NAME.len() as u8)
            .expect("generate ECH interop material");
    generated.key.retry_config = retry_config;
    (generated.key, generated.config_list)
}

fn write_public(path: &Path, bytes: &[u8]) {
    fs::write(path, bytes).expect("write public test material");
}

fn write_secret(path: &Path, bytes: &[u8]) {
    #[cfg(unix)]
    {
        use std::io::Write as _;
        use std::os::unix::fs::OpenOptionsExt as _;
        let mut file = fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(path)
            .expect("create secret test material");
        file.write_all(bytes).expect("write secret test material");
    }
    #[cfg(not(unix))]
    write_public(path, bytes);
}

fn contains(haystack: &[u8], needle: &[u8]) -> bool {
    haystack
        .windows(needle.len())
        .any(|window| window == needle)
}

fn spawn_server(
    acceptor: EchAcceptor,
    knock_psk: [u8; 32],
) -> (SocketAddr, std::thread::JoinHandle<ServerOutcome>) {
    let (addr_tx, addr_rx) = mpsc::sync_channel(1);
    let handle = std::thread::spawn(move || {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("build Tokio runtime");
        runtime.block_on(async move {
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
                .await
                .expect("bind interop server");
            addr_tx
                .send(listener.local_addr().expect("interop local address"))
                .expect("publish interop address");
            let (stream, _) = listener.accept().await.expect("accept uTLS client");
            let dispatch = DispatchConfig {
                psk: Some(KnockPsk::from_bytes(knock_psk)),
                cover_endpoint: Some("127.0.0.1:9".to_owned()),
                ..DispatchConfig::default()
            };
            match dispatch_or_local_terminate(
                stream,
                &dispatch,
                SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .expect("clock after epoch")
                    .as_secs(),
            )
            .await
            {
                PathARouting::TerminateLocally(stream) => {
                    let wire = stream.sniffed_prefix().to_vec();
                    match acceptor.accept_required(stream).await {
                        Ok(accepted) => ServerOutcome {
                            accepted: true,
                            exporter: Some(*accepted.exporter),
                            wire,
                            error: None,
                        },
                        Err(error) => ServerOutcome {
                            accepted: false,
                            exporter: None,
                            wire,
                            error: Some(error.to_string()),
                        },
                    }
                }
                other => ServerOutcome {
                    accepted: false,
                    exporter: None,
                    wire: Vec::new(),
                    error: Some(format!("Path A did not terminate locally: {other:?}")),
                },
            }
        })
    });
    (addr_rx.recv().expect("receive interop address"), handle)
}

fn run_go_client(
    temp: &Path,
    addr: SocketAddr,
    config_list: &[u8],
    expect_success: bool,
) -> std::process::Output {
    let config_path = temp.join("echconfiglist.b64");
    write_public(
        &config_path,
        base64::engine::general_purpose::STANDARD
            .encode(config_list)
            .as_bytes(),
    );
    Command::new("go")
        .args([
            "test",
            "-run",
            "^TestRustECHInteropClient$",
            "-count=1",
            "-v",
        ])
        .current_dir(Path::new(env!("CARGO_MANIFEST_DIR")).join("../../bridges/utls"))
        // Homebrew/mise upgrades can leave a stale inherited GOROOT
        // pointing at a different patch release. Let the selected
        // `go` binary use its compiled-in root.
        .env_remove("GOROOT")
        .env("PROTEUS_UTLS_ECH_TARGET", addr.to_string())
        .env("PROTEUS_UTLS_ECH_SERVER_NAME", INNER_NAME)
        .env("PROTEUS_UTLS_ECH_CA", temp.join("cert.pem"))
        .env("PROTEUS_UTLS_ECH_CONFIG_LIST", config_path)
        .env("PROTEUS_UTLS_ECH_KNOCK_PSK", temp.join("knock.psk"))
        .env("PROTEUS_UTLS_ECH_EXPORTER_OUT", temp.join("exporter.b64"))
        .env(
            "PROTEUS_UTLS_ECH_EXPECT",
            if expect_success { "success" } else { "failure" },
        )
        .output()
        .expect("run Go uTLS interop client")
}

fn assert_case(
    label: &str,
    temp: &Path,
    acceptor: EchAcceptor,
    knock_psk: [u8; 32],
    config_list: &[u8],
    expect_success: bool,
) {
    let exporter_path = temp.join("exporter.b64");
    let _ = fs::remove_file(&exporter_path);
    let (addr, server) = spawn_server(acceptor, knock_psk);
    let output = run_go_client(temp, addr, config_list, expect_success);
    assert!(
        output.status.success(),
        "{label}: Go client failed\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    let outcome = server.join().expect("join ECH server");
    assert!(
        !outcome.wire.is_empty(),
        "{label}: Path A never admitted the uTLS ClientHello: {:?}",
        outcome.error
    );
    assert!(
        contains(&outcome.wire, PUBLIC_NAME.as_bytes()),
        "{label}: ClientHelloOuter lacks the public name"
    );
    assert!(
        !contains(&outcome.wire, INNER_NAME.as_bytes()),
        "{label}: real inner SNI leaked onto the wire"
    );
    assert_eq!(
        outcome.accepted, expect_success,
        "{label}: unexpected ECH acceptance: {:?}",
        outcome.error
    );
    if expect_success {
        let go_exporter = base64::engine::general_purpose::STANDARD
            .decode(fs::read(&exporter_path).expect("read Go exporter"))
            .expect("decode Go exporter");
        assert_eq!(
            outcome
                .exporter
                .as_ref()
                .map(|exporter| exporter.as_slice()),
            Some(go_exporter.as_slice()),
            "{label}: Go and Rust TLS exporters differ"
        );
    } else {
        assert!(
            !exporter_path.exists(),
            "{label}: rejected ECH unexpectedly exported channel binding"
        );
    }
}

fn assert_full_inner_handshake(
    temp: &Path,
    acceptor: EchAcceptor,
    knock_psk: [u8; 32],
    config_list: &[u8],
) {
    let mut server_keys = ServerKeys::generate();
    let client_signing = proteus_crypto::sig::generate(&mut OsRng);
    let user_id = *b"ech_full";
    server_keys.allow(user_id, client_signing.verifying_key());
    let client_config = ClientConfig::new(
        server_keys.mlkem_pk_bytes.clone(),
        server_keys.x25519_pub,
        server_keys.pq_fingerprint,
        client_signing,
        user_id,
    );
    let server_context = Arc::new(ServerCtx::new(server_keys));

    let (addr_tx, addr_rx) = mpsc::sync_channel(1);
    let server_thread = std::thread::spawn(move || {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("build full-handshake server runtime");
        runtime.block_on(async move {
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
                .await
                .expect("bind full-handshake server");
            addr_tx
                .send(listener.local_addr().expect("full server address"))
                .expect("publish full server address");
            let (stream, _) = listener.accept().await.expect("accept full uTLS client");
            let dispatch = DispatchConfig {
                psk: Some(KnockPsk::from_bytes(knock_psk)),
                cover_endpoint: Some("127.0.0.1:9".to_owned()),
                ..DispatchConfig::default()
            };
            let PathARouting::TerminateLocally(stream) = dispatch_or_local_terminate(
                stream,
                &dispatch,
                SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .expect("clock after epoch")
                    .as_secs(),
            )
            .await
            else {
                panic!("full ECH ClientHello failed Path A");
            };
            let wire = stream.sniffed_prefix().to_vec();
            let mut session = server::handshake_over_ech_io(stream, &acceptor, &server_context)
                .await
                .expect("server ECH + inner Proteus handshake");
            let payload = session
                .receiver
                .recv_record()
                .await
                .expect("server receive record")
                .expect("client closed before record");
            session
                .sender
                .send_record(&payload)
                .await
                .expect("server echo record");
            session.sender.flush().await.expect("server echo flush");
            wire
        })
    });
    let addr = addr_rx.recv().expect("receive full server address");

    let config_path = temp.join("full.echconfiglist.b64");
    write_public(
        &config_path,
        base64::engine::general_purpose::STANDARD
            .encode(config_list)
            .as_bytes(),
    );
    let bridge_path = temp.join("proteus-utls-bridge");
    let build = Command::new("go")
        .args(["build", "-trimpath", "-o"])
        .arg(&bridge_path)
        .arg(".")
        .current_dir(Path::new(env!("CARGO_MANIFEST_DIR")).join("../../bridges/utls"))
        .env_remove("GOROOT")
        .output()
        .expect("build uTLS bridge");
    assert!(
        build.status.success(),
        "build uTLS bridge failed\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&build.stdout),
        String::from_utf8_lossy(&build.stderr)
    );
    let socket_path = temp.join("bridge.sock");
    let child = Command::new(&bridge_path)
        .args(["--listen"])
        .arg(&socket_path)
        .args(["--knock-psk"])
        .arg(temp.join("knock.psk"))
        .args(["--trusted-ca"])
        .arg(temp.join("cert.pem"))
        .args(["--ech-config-list"])
        .arg(&config_path)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("start uTLS bridge");
    let _bridge = ChildGuard(child);
    for _ in 0..500 {
        if socket_path.exists() {
            break;
        }
        std::thread::sleep(Duration::from_millis(10));
    }
    assert!(socket_path.exists(), "uTLS bridge socket did not appear");

    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("build full-handshake client runtime");
    runtime.block_on(async move {
        let target = addr.to_string();
        let mut bridge = tokio::net::UnixStream::connect(&socket_path)
            .await
            .expect("connect uTLS bridge");
        let mut request = Vec::with_capacity(9 + target.len() + INNER_NAME.len());
        request.extend_from_slice(b"PUTL");
        request.push(1);
        request.extend_from_slice(&(target.len() as u16).to_be_bytes());
        request.extend_from_slice(&(INNER_NAME.len() as u16).to_be_bytes());
        request.extend_from_slice(target.as_bytes());
        request.extend_from_slice(INNER_NAME.as_bytes());
        bridge
            .write_all(&request)
            .await
            .expect("request uTLS connection");
        let status = bridge.read_u8().await.expect("read bridge status");
        if status != 0 {
            let message_len = bridge.read_u16().await.expect("read bridge error length");
            let mut message = vec![0u8; usize::from(message_len)];
            bridge
                .read_exact(&mut message)
                .await
                .expect("read bridge error");
            panic!("uTLS bridge failed: {}", String::from_utf8_lossy(&message));
        }
        let mut exporter = [0u8; EXPORTER_LEN];
        bridge
            .read_exact(&mut exporter)
            .await
            .expect("read uTLS exporter");
        let (read, write) = tokio::io::split(bridge);
        let mut session = proteus_transport_alpha::client::handshake_over_split_bound(
            read,
            write,
            &client_config,
            Some(exporter),
        )
        .await
        .expect("client exporter-bound inner Proteus handshake");
        let payload = b"uTLS ECH binds the hybrid Proteus transcript";
        session
            .sender
            .send_record(payload)
            .await
            .expect("client send record");
        session.sender.flush().await.expect("client flush record");
        let echoed = session
            .receiver
            .recv_record()
            .await
            .expect("client receive echo")
            .expect("server closed before echo");
        assert_eq!(echoed, payload);
    });
    let wire = server_thread.join().expect("join full ECH server");
    assert!(contains(&wire, PUBLIC_NAME.as_bytes()));
    assert!(!contains(&wire, INNER_NAME.as_bytes()));
}

#[test]
fn utls_real_ech_overlap_rotation_is_fail_closed() {
    let go = Command::new("go")
        .arg("version")
        .env_remove("GOROOT")
        .output()
        .expect("the cross-language ECH gate requires a Go toolchain");
    assert!(
        go.status.success(),
        "Go toolchain is unusable: {}",
        String::from_utf8_lossy(&go.stderr)
    );

    let temp = TempDir::new();
    let key_pair = KeyPair::generate().expect("generate test certificate key");
    let params = CertificateParams::new(vec![INNER_NAME.to_owned(), PUBLIC_NAME.to_owned()])
        .expect("build certificate parameters");
    let certificate = params
        .self_signed(&key_pair)
        .expect("self-sign test certificate");
    write_public(&temp.0.join("cert.pem"), certificate.pem().as_bytes());
    write_secret(&temp.0.join("key.pem"), key_pair.serialize_pem().as_bytes());

    let knock_psk = [0x5au8; 32];
    let knock_body = base64::engine::general_purpose::STANDARD.encode(knock_psk);
    write_secret(&temp.0.join("knock.psk"), knock_body.as_bytes());

    let (old_key, old_list) = ech_material(7, false);
    let (new_key, new_list) = ech_material(8, true);
    let overlap = EchAcceptor::from_pem_files(
        &temp.0.join("cert.pem"),
        &temp.0.join("key.pem"),
        &[new_key.clone(), old_key.clone()],
    )
    .expect("build overlap ECH acceptor");
    assert_case(
        "old key during overlap",
        &temp.0,
        overlap.clone(),
        knock_psk,
        &old_list,
        true,
    );
    assert_case(
        "new key after publication",
        &temp.0,
        overlap.clone(),
        knock_psk,
        &new_list,
        true,
    );
    assert_full_inner_handshake(&temp.0, overlap, knock_psk, &new_list);

    let new_only = EchAcceptor::from_pem_files(
        &temp.0.join("cert.pem"),
        &temp.0.join("key.pem"),
        &[new_key],
    )
    .expect("build post-overlap ECH acceptor");
    assert_case(
        "old key after retirement",
        &temp.0,
        new_only,
        knock_psk,
        &old_list,
        false,
    );
}
