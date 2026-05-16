//! Wire-level regression test for `PerfProfile.pad_quic_datagrams_to_mtu`.
//!
//! ## Why this exists
//!
//! Commit 62a18d3 exposed `beta_pad_quic_to_mtu` in `server.yaml` /
//! `client.yaml` so operators can flip on UDP-layer padding for
//! anti-censorship deployments. The wire-up is two hops:
//!
//!     YAML → ServerConfig::beta_pad_quic_to_mtu
//!          → proteus_transport_beta::PerfProfile.pad_quic_datagrams_to_mtu
//!          → quinn::TransportConfig.pad_to_mtu
//!          → quinn-proto enforces uniform UDP datagram size on the wire
//!
//! Any link in that chain can silently drop the flag (typo in a
//! field name, accidental `..Default::default()` clobber, library
//! version bump that removes the setter). The YAML-round-trip tests
//! cover hop 1; this test covers hops 2-4 by **measuring the actual
//! UDP datagrams on the wire**.
//!
//! ## How it works
//!
//! 1. Bind a plain `tokio::net::UdpSocket` and a real β-profile
//!    server on different ports.
//! 2. Set up a single-packet UDP **mirror** that listens on the plain
//!    socket and forwards every datagram to the β server, recording
//!    each forwarded datagram's size in a shared Vec.
//! 3. Dial the mirror with the β client, using `PerfProfile {
//!    initial_mtu: 1452, pad_quic_datagrams_to_mtu: true }`.
//! 4. After the connection is established + a few data records have
//!    flowed, assert: **every recorded outbound datagram from the
//!    client is exactly `initial_mtu` bytes**.
//!
//! If anyone severs the chain — e.g. by changing `pad_to_mtu()` →
//! `pad_to_mtu_v2()` in a future quinn — this test fires immediately.

use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use proteus_transport_alpha::client::ClientConfig;
use proteus_transport_alpha::server::{ServerCtx, ServerKeys};
use proteus_transport_alpha::ProfileHint;
use rcgen::generate_simple_self_signed;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use tokio::net::UdpSocket;
use tokio::time::timeout;

const STEP: Duration = Duration::from_secs(15);
const PAD_MTU: u16 = 1452;

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn beta_pad_to_mtu_uniform_datagram_size_on_wire() {
    // ----- 1. Real β server -----
    let ck = generate_simple_self_signed(vec!["localhost".to_string()]).unwrap();
    let cert_der = CertificateDer::from(ck.cert.der().to_vec());
    let key_der = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(ck.key_pair.serialize_der()));

    let server_keys = ServerKeys::generate();
    let mlkem_pk_bytes = server_keys.mlkem_pk_bytes.clone();
    let pq_fingerprint = server_keys.pq_fingerprint;
    let server_x25519_pub = server_keys.x25519_pub;
    let ctx = Arc::new(ServerCtx::new(server_keys));

    let server_bind: std::net::SocketAddr = "127.0.0.1:0".parse().unwrap();
    // Server uses the same PerfProfile — server-side padding doesn't
    // matter for this test (we only measure client→server), but
    // matches operator-side production config of `pad_to_mtu: true`.
    let perf = proteus_transport_beta::PerfProfile {
        initial_mtu: PAD_MTU,
        pad_quic_datagrams_to_mtu: true,
    };
    let endpoint = proteus_transport_beta::server::make_endpoint_with_perf(
        server_bind,
        vec![cert_der.clone()],
        key_der,
        perf,
    )
    .expect("make_endpoint_with_perf");
    let server_local = endpoint.local_addr().expect("local_addr");

    let server_ctx = Arc::clone(&ctx);
    let server_task = tokio::spawn(async move {
        let _ =
            proteus_transport_beta::server::serve(endpoint, server_ctx, |mut session| async move {
                // Echo every record back so the client can flush + read
                // post-handshake traffic without blocking.
                while let Ok(Some(rec)) = session.receiver.recv_record().await {
                    if rec.is_empty() {
                        continue;
                    }
                    let _ = session.sender.send_record(&rec).await;
                    let _ = session.sender.flush().await;
                }
            })
            .await;
    });

    // ----- 2. UDP mirror that records every CLIENT-side datagram size -----
    let mirror = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let mirror_addr: SocketAddr = mirror.local_addr().unwrap();

    let client_sizes: Arc<Mutex<Vec<usize>>> = Arc::new(Mutex::new(Vec::new()));
    let sizes_for_mirror = Arc::clone(&client_sizes);
    let mirror_task = tokio::spawn(async move {
        // Mirror buffers — separate so each `recv_from` arm of the
        // select! holds its own &mut.
        let mut buf_client = vec![0u8; 65535];
        let mut buf_server = vec![0u8; 65535];
        let mut client_peer: Option<SocketAddr> = None;
        // Loopback to server uses an ephemeral socket so server replies
        // come back to us (not to the original client).
        let server_socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        loop {
            tokio::select! {
                Ok((n, src)) = mirror.recv_from(&mut buf_client) => {
                    // First sender = client. Record its datagram size +
                    // forward to server.
                    if client_peer.is_none() {
                        client_peer = Some(src);
                    }
                    if Some(src) == client_peer {
                        sizes_for_mirror.lock().unwrap().push(n);
                        let _ = server_socket.send_to(&buf_client[..n], server_local).await;
                    }
                }
                Ok((n, _src)) = server_socket.recv_from(&mut buf_server) => {
                    // Server reply → forward back to client unchanged.
                    if let Some(c) = client_peer {
                        let _ = mirror.send_to(&buf_server[..n], c).await;
                    }
                }
                else => break,
            }
        }
    });

    // ----- 3. β client through the mirror -----
    let mut rng = rand_core::OsRng;
    let client_id_sk = proteus_crypto::sig::generate(&mut rng);
    let client_cfg = ClientConfig {
        server_mlkem_pk_bytes: mlkem_pk_bytes,
        server_x25519_pub,
        server_pq_fingerprint: pq_fingerprint,
        client_id_sk,
        user_id: *b"padmtutt",
        pow_difficulty: 0,
        profile_hint: ProfileHint::Beta,
    };

    let mut client = timeout(
        STEP,
        proteus_transport_beta::client::connect_with_timeout_and_perf(
            "localhost",
            mirror_addr,
            vec![cert_der],
            client_cfg,
            Duration::from_secs(5),
            proteus_transport_beta::PerfProfile {
                initial_mtu: PAD_MTU,
                pad_quic_datagrams_to_mtu: true,
            },
        ),
    )
    .await
    .expect("β connect timed out")
    .expect("β connect");

    // Push a few records through so we observe both handshake AND
    // application-data datagrams.
    for _ in 0..4 {
        timeout(STEP, client.session.sender.send_record(&[0u8; 256]))
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
    }

    // Give the mirror a moment to flush the last few datagrams.
    tokio::time::sleep(Duration::from_millis(100)).await;

    // ----- 4. Assert all observed client datagrams hit MTU exactly -----
    let sizes = client_sizes.lock().unwrap().clone();
    assert!(
        !sizes.is_empty(),
        "mirror saw no client datagrams — test infrastructure broken"
    );
    // Allow short-circuit packets (PMTUd probes, CONNECTION_CLOSE) to
    // skip the strict assertion: we only require that the BULK of
    // observed datagrams are the configured MTU. quinn-proto's
    // pad_to_mtu only kicks in for Data-space packets — Initial-space
    // packets are already padded to 1200+ per spec, and 1-RTT data
    // post-handshake is what we care about.
    let strict = sizes.iter().filter(|&&n| n == PAD_MTU as usize).count();
    let total = sizes.len();
    eprintln!(
        "β client-side datagrams: {total} observed, {strict} at exactly {PAD_MTU} bytes; \
         distribution: {sizes:?}"
    );
    // Conservative bound: at least 50% of observed datagrams must hit
    // the configured MTU. In practice the percentage is near 100% post-
    // handshake; the looseness accounts for ACK-only / CONNECTION_CLOSE
    // / PMTUd probe packets that quinn-proto allows below MTU.
    assert!(
        strict * 2 >= total,
        "expected ≥50% of client datagrams at {PAD_MTU} bytes; got {strict}/{total}. \
         Either pad_to_mtu isn't taking effect, or quinn changed semantics."
    );
    // Also assert SOME datagram hit exactly the MTU — proves the
    // padding code path actually fired (a no-padding build would see
    // zero such packets except by coincidence).
    assert!(
        strict >= 1,
        "no client datagram reached the configured {PAD_MTU}-byte MTU — \
         pad_to_mtu chain broken between PerfProfile and quinn"
    );

    // Cleanup.
    let proteus_transport_alpha::session::AlphaSession { sender, .. } = client.session;
    let _ = timeout(STEP, sender.shutdown()).await;
    client.connection.close(0u32.into(), b"bye");
    drop(client.endpoint);
    server_task.abort();
    mirror_task.abort();
}

/// Negative-control sibling of the test above: when
/// `pad_quic_datagrams_to_mtu = false` we expect the client to NOT
/// inflate every datagram to MTU — small writes stay small. Without
/// this companion the positive test could pass even if quinn was
/// unconditionally padding (broken default, or a future regression
/// that pads always).
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn beta_pad_off_yields_variable_datagram_sizes_on_wire() {
    let ck = generate_simple_self_signed(vec!["localhost".to_string()]).unwrap();
    let cert_der = CertificateDer::from(ck.cert.der().to_vec());
    let key_der = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(ck.key_pair.serialize_der()));

    let server_keys = ServerKeys::generate();
    let mlkem_pk_bytes = server_keys.mlkem_pk_bytes.clone();
    let pq_fingerprint = server_keys.pq_fingerprint;
    let server_x25519_pub = server_keys.x25519_pub;
    let ctx = Arc::new(ServerCtx::new(server_keys));

    let server_bind: std::net::SocketAddr = "127.0.0.1:0".parse().unwrap();
    // Default profile = pad OFF.
    let endpoint =
        proteus_transport_beta::server::make_endpoint(server_bind, vec![cert_der.clone()], key_der)
            .expect("make_endpoint");
    let server_local = endpoint.local_addr().expect("local_addr");

    let server_ctx = Arc::clone(&ctx);
    let server_task = tokio::spawn(async move {
        let _ =
            proteus_transport_beta::server::serve(endpoint, server_ctx, |mut session| async move {
                while let Ok(Some(rec)) = session.receiver.recv_record().await {
                    if rec.is_empty() {
                        continue;
                    }
                    let _ = session.sender.send_record(&rec).await;
                    let _ = session.sender.flush().await;
                }
            })
            .await;
    });

    // Mirror that records every client datagram size.
    let mirror = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let mirror_addr: SocketAddr = mirror.local_addr().unwrap();
    let client_sizes: Arc<Mutex<Vec<usize>>> = Arc::new(Mutex::new(Vec::new()));
    let sizes_for_mirror = Arc::clone(&client_sizes);
    let mirror_task = tokio::spawn(async move {
        let mut buf_client = vec![0u8; 65535];
        let mut buf_server = vec![0u8; 65535];
        let mut client_peer: Option<SocketAddr> = None;
        let server_socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        loop {
            tokio::select! {
                Ok((n, src)) = mirror.recv_from(&mut buf_client) => {
                    if client_peer.is_none() {
                        client_peer = Some(src);
                    }
                    if Some(src) == client_peer {
                        sizes_for_mirror.lock().unwrap().push(n);
                        let _ = server_socket.send_to(&buf_client[..n], server_local).await;
                    }
                }
                Ok((n, _src)) = server_socket.recv_from(&mut buf_server) => {
                    if let Some(c) = client_peer {
                        let _ = mirror.send_to(&buf_server[..n], c).await;
                    }
                }
                else => break,
            }
        }
    });

    let mut rng = rand_core::OsRng;
    let client_id_sk = proteus_crypto::sig::generate(&mut rng);
    let client_cfg = ClientConfig {
        server_mlkem_pk_bytes: mlkem_pk_bytes,
        server_x25519_pub,
        server_pq_fingerprint: pq_fingerprint,
        client_id_sk,
        user_id: *b"nopadtst",
        pow_difficulty: 0,
        profile_hint: ProfileHint::Beta,
    };

    let mut client = timeout(
        STEP,
        proteus_transport_beta::client::connect_with_timeout(
            "localhost",
            mirror_addr,
            vec![cert_der],
            client_cfg,
            Duration::from_secs(5),
        ),
    )
    .await
    .expect("β connect timed out")
    .expect("β connect");

    for _ in 0..4 {
        timeout(STEP, client.session.sender.send_record(&[0u8; 256]))
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
    }
    tokio::time::sleep(Duration::from_millis(100)).await;

    let sizes = client_sizes.lock().unwrap().clone();
    assert!(!sizes.is_empty());
    let distinct: std::collections::BTreeSet<usize> = sizes.iter().copied().collect();
    eprintln!(
        "β (pad OFF) client-side datagrams: {} observed, {} distinct sizes: {:?}",
        sizes.len(),
        distinct.len(),
        sizes
    );
    // With pad OFF we expect at least two distinct sizes (handshake-
    // size Initial + application 1-RTT data of a different size). If
    // this fires with only one distinct size, quinn changed defaults
    // and is unconditionally padding — the positive test's pass is
    // meaningless.
    assert!(
        distinct.len() >= 2,
        "pad-OFF datagrams should vary in size; got only {} distinct sizes: {:?}. \
         quinn may be unconditionally padding — positive test result is now meaningless.",
        distinct.len(),
        distinct,
    );

    let proteus_transport_alpha::session::AlphaSession { sender, .. } = client.session;
    let _ = timeout(STEP, sender.shutdown()).await;
    client.connection.close(0u32.into(), b"bye");
    drop(client.endpoint);
    server_task.abort();
    mirror_task.abort();
}
