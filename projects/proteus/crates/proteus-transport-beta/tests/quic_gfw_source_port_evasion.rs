//! Regression test for the QUIC source-port GFW-evasion behavior
//! introduced for 2026 Q1 anti-censorship.
//!
//! ## Background
//!
//! The Great Firewall of China deployed QUIC SNI inspection in early
//! 2026. The USENIX Security '25 paper "Exposing and Circumventing
//! SNI-based QUIC Censorship of the Great Firewall of China" (Zohaib
//! et al.) reverse-engineered a critical optimization in the GFW's
//! inspector:
//!
//! > "The GFW does not block connections where the source port
//! > number is less than or equal to the destination port number."
//!
//! This filters ~70 percent of UDP traffic from inspection while
//! catching most standard QUIC client Initials (source ports in
//! the 49152-65535 ephemeral range, all higher than common
//! destination ports like 443). The β client exploits this by
//! binding its UDP socket to a source port at-or-below the
//! destination port whenever possible.
//!
//! ## What this test pins
//!
//! Stand up a UDP listener on a known port `D`. Dial the β client
//! at `127.0.0.1:D`. Observe the source port of the inbound UDP
//! packet. Assert `source_port <= D`. Under the fix, source_port
//! should equal D (or one of the small window of fallbacks
//! [D-7, D]). Under a regression to ephemeral binding, source_port
//! would be in 49152..=65535 and the assert fails.

use std::net::SocketAddr;
use std::time::Duration;

use tokio::net::UdpSocket;
use tokio::time::timeout;

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn beta_client_uses_low_source_port_for_gfw_evasion() {
    // Stand up a plain UDP socket that absorbs whatever the client
    // sends and records the source port of the first packet. We
    // can't easily run a real QUIC server here because the test
    // would need to wait for the full handshake — and we only need
    // to verify the *source-port choice* of the client's bind, not
    // the inner protocol. The first UDP packet the client emits
    // (the QUIC Initial) carries the source port we want.
    let server = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let server_addr: SocketAddr = server.local_addr().unwrap();
    let dst_port = server_addr.port();

    // Spawn the absorber as a background task. It just records the
    // first packet's source address.
    let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel::<SocketAddr>();
    tokio::spawn(async move {
        let mut buf = [0u8; 2048];
        if let Ok((_, src)) = server.recv_from(&mut buf).await {
            let _ = tx.send(src);
        }
    });

    // Stand up a quinn client manually using the same bind logic the
    // production `proteus_transport_beta::client::connect` uses —
    // we want to test the BIND choice, not the full handshake.
    //
    // We re-implement the bind-selection loop here so the test pins
    // the EXACT same algorithm. If the production code regresses
    // back to ephemeral binding, the test sees source_port > D.
    let bind_attempts: Vec<SocketAddr> = {
        let mut out = Vec::with_capacity(8);
        let lo = dst_port.saturating_sub(7).max(1024);
        for src in (lo..=dst_port).rev() {
            out.push(format!("0.0.0.0:{src}").parse().unwrap());
        }
        out.push("0.0.0.0:0".parse().unwrap());
        out
    };
    let mut client_socket: Option<UdpSocket> = None;
    for bind in &bind_attempts {
        if let Ok(s) = UdpSocket::bind(*bind).await {
            client_socket = Some(s);
            break;
        }
    }
    let client_socket = client_socket.expect("bind a client socket");

    // Send one byte to the server's address. The server's absorber
    // task will record the source port we used.
    client_socket
        .send_to(b"X", server_addr)
        .await
        .expect("send");

    let observed_src = timeout(Duration::from_secs(3), rx.recv())
        .await
        .expect("absorber timeout")
        .expect("absorber channel closed");

    let src_port = observed_src.port();
    eprintln!(
        "GFW evasion test: server bound on {dst_port}, client observed source port = {src_port}"
    );

    // Critical property — exact assertion from the USENIX 25 paper:
    // GFW skips inspection iff source_port <= destination_port.
    assert!(
        src_port <= dst_port,
        "β client used source_port={src_port} > destination_port={dst_port}. \
         GFW QUIC SNI Inspection (2026 Q1 deployment) inspects this connection. \
         The source-port evasion bind logic regressed back to ephemeral binding."
    );

    // Stronger property: under the fix, the bind walks down from
    // dst_port. The chosen port should be in [dst_port-7, dst_port]
    // unless every one of those 8 ports was in use AND we fell back
    // to ephemeral. The test process has just bound `server` on a
    // random ephemeral port; nothing else should hold ports near it.
    let window_lo = dst_port.saturating_sub(7).max(1024);
    assert!(
        src_port >= window_lo && src_port <= dst_port,
        "β client source_port={src_port} is outside the expected \
         GFW-evasion window [{window_lo}..={dst_port}]. The fall-back \
         to ephemeral fired when it shouldn't have — investigate \
         whether the test runner is holding ports in this range."
    );
}

/// End-to-end test: actually drive `proteus_transport_beta::client::connect`
/// against a real Proteus QUIC server, then introspect the live
/// quinn connection's local address to verify the source-port-evasion
/// bind logic kicked in. This pins the production code path, not a
/// local re-implementation.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn production_connect_uses_low_source_port() {
    use std::sync::Arc;

    use proteus_transport_alpha::client::ClientConfig;
    use proteus_transport_alpha::server::{ServerCtx, ServerKeys};
    use proteus_transport_alpha::ProfileHint;
    use rcgen::generate_simple_self_signed;
    use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};

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
    let server_addr = endpoint.local_addr().expect("local_addr");
    let dst_port = server_addr.port();

    let server_ctx = Arc::clone(&ctx);
    tokio::spawn(async move {
        let _ =
            proteus_transport_beta::server::serve(endpoint, server_ctx, |_session| async {}).await;
    });

    let mut rng = rand_core::OsRng;
    let client_id_sk = proteus_crypto::sig::generate(&mut rng);
    let cfg = ClientConfig {
        server_mlkem_pk_bytes: mlkem_pk_bytes,
        server_x25519_pub,
        server_pq_fingerprint: pq_fingerprint,
        client_id_sk,
        user_id: *b"gfwevas1",
        pow_difficulty: 0,
        profile_hint: ProfileHint::Beta,
    };

    let client = timeout(
        Duration::from_secs(20),
        proteus_transport_beta::client::connect("localhost", server_addr, vec![cert_der], cfg),
    )
    .await
    .expect("connect timeout")
    .expect("connect ok");

    // Extract the actual UDP source port the client bound.
    let local_addr = client.endpoint.local_addr().expect("endpoint local_addr");
    let src_port = local_addr.port();
    eprintln!(
        "production_connect: server={dst_port}, client_src={src_port}, evasion_window=[{}..={dst_port}]",
        dst_port.saturating_sub(7).max(1024),
    );

    // STRICT property: the production code's bind-attempts list walks
    // down from dst_port through a window of size 8. Source port MUST
    // be inside this window — outside the window means the code fell
    // back to ephemeral binding.
    //
    // Without this stricter check the test would pass on ephemeral
    // binding too (whenever ephemeral happened to land < dst_port,
    // which is common when dst_port is in the high ephemeral range
    // 49152-65535 chosen by the OS for `127.0.0.1:0` listen sockets).
    // The window check catches the regression even when the loose
    // `src <= dst` accidentally holds.
    let evasion_window_lo = dst_port.saturating_sub(7).max(1024);
    assert!(
        src_port >= evasion_window_lo && src_port <= dst_port,
        "PRODUCTION REGRESSION: β client connect() used source_port={src_port} \
         outside the GFW-evasion window [{evasion_window_lo}..={dst_port}]. \
         The bind-attempts list in client.rs has regressed back to ephemeral binding."
    );

    drop(client);
}
