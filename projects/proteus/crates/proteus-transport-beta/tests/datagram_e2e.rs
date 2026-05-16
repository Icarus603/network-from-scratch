//! End-to-end test for the β-profile QUIC DATAGRAM channel.
//!
//! Real Proteus handshake over QUIC, then both sides derive the
//! datagram subkeys from their established session secrets and
//! exchange one datagram in each direction. Verifies:
//!   - Symmetric key derivation: client's send-side key == server's
//!     receive-side key. Both directions tested.
//!   - AEAD seal/open round-trips correctly.
//!   - QUIC's `max_datagram_size` is reported sensibly (loopback
//!     MTU is huge but quinn caps to its config).
//!
//! Note: the datagram channel piggybacks on an existing β session
//! that ALSO has a live reliable stream. This test holds the
//! session open (storing the BetaClientSession) so the connection
//! stays alive through the datagram exchange.

use std::sync::Arc;
use std::time::Duration;

use proteus_transport_alpha::client::ClientConfig;
use proteus_transport_alpha::server::{ServerCtx, ServerKeys};
use proteus_transport_alpha::ProfileHint;
use proteus_transport_beta::datagram::Channel;
use rcgen::generate_simple_self_signed;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use tokio::sync::oneshot;
use tokio::time::timeout;

const STEP: Duration = Duration::from_secs(20);

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn datagram_round_trip_both_directions() {
    let ck = generate_simple_self_signed(vec!["localhost".to_string()]).unwrap();
    let cert_der = CertificateDer::from(ck.cert.der().to_vec());
    let key_der = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(ck.key_pair.serialize_der()));

    let server_keys = ServerKeys::generate();
    let mlkem_pk_bytes = server_keys.mlkem_pk_bytes.clone();
    let pq_fingerprint = server_keys.pq_fingerprint;
    let server_x25519_pub = server_keys.x25519_pub;
    let ctx = Arc::new(ServerCtx::new(server_keys));

    let bind: std::net::SocketAddr = "127.0.0.1:0".parse().unwrap();
    let endpoint =
        proteus_transport_beta::server::make_endpoint(bind, vec![cert_der.clone()], key_der)
            .expect("make_endpoint");
    let local = endpoint.local_addr().expect("local_addr");

    // Channel for the server task to publish the Channel handle it
    // builds from the session. The main test thread then sends a
    // datagram through it.
    let (server_chan_tx, server_chan_rx) = oneshot::channel::<Channel>();
    // And the inverse — main thread publishes the message the
    // server should expect to receive, lets the server confirm
    // receipt.
    let (server_recv_done_tx, server_recv_done_rx) = oneshot::channel::<Vec<u8>>();

    let server_ctx = Arc::clone(&ctx);
    let server_task = tokio::spawn(async move {
        // We need the QUIC connection handle inside the per-session
        // closure. Use a one-shot channel and a custom serve loop
        // because the prebuilt server::serve doesn't expose conn.
        let conn = endpoint.accept().await.expect("accept").await.unwrap();
        // Extract the channel-binding tag from the same outer QUIC
        // session the client sees (commit 906ab22 wired this for α,
        // this commit wires it for β). The production `serve` loop
        // does this automatically; here we replicate it inline because
        // the test bypasses `serve` to access the Connection handle.
        let mut binding = [0u8; proteus_transport_alpha::client::CHANNEL_BINDING_LEN];
        conn.export_keying_material(
            &mut binding[..],
            proteus_transport_alpha::client::TLS_EXPORTER_LABEL,
            b"",
        )
        .expect("β QUIC exporter");
        let (send, recv) = conn.accept_bi().await.expect("accept_bi");
        let session = proteus_transport_alpha::server::handshake_over_split_bound(
            recv,
            send,
            &server_ctx,
            Some(binding),
        )
        .await
        .expect("server handshake");
        let chan = Channel::from_session(&session, conn.clone()).expect("from_session");

        // Send the channel handle (clone) back so main can use the
        // server-side endpoint for its own send.
        let _ = server_chan_tx.send(chan.clone());

        // Server receives one datagram and reports what arrived.
        let received = chan.recv().await.expect("server recv");
        let _ = server_recv_done_tx.send(received);

        // Keep the connection alive until the test aborts.
        let _ = tokio::time::timeout(Duration::from_secs(30), conn.closed()).await;
    });

    let mut rng = rand_core::OsRng;
    let client_id_sk = proteus_crypto::sig::generate(&mut rng);
    let client_cfg = ClientConfig {
        server_mlkem_pk_bytes: mlkem_pk_bytes,
        server_x25519_pub,
        server_pq_fingerprint: pq_fingerprint,
        client_id_sk,
        user_id: *b"dgrame2e",
        pow_difficulty: 0,
        profile_hint: ProfileHint::Beta,
    };
    let client = timeout(
        STEP,
        proteus_transport_beta::client::connect("localhost", local, vec![cert_der], client_cfg),
    )
    .await
    .expect("connect timeout")
    .expect("β connect ok");

    // Build the client-side datagram channel.
    let client_chan =
        Channel::from_session(&client.session, client.connection.clone()).expect("client channel");

    // Sanity: max_plaintext_size should be reported (some positive
    // number). Loopback MTU is large; quinn defaults to ~1452 bytes
    // for the conservative path.
    let max = client_chan
        .max_plaintext_size()
        .expect("peer supports DATAGRAM");
    assert!(max >= 100, "max_plaintext_size suspiciously small: {max}");

    // === Direction 1: client → server ===
    let payload_c2s = b"hello-via-datagram-c2s";
    client_chan.try_send(payload_c2s).expect("client try_send");

    let received_by_server = timeout(STEP, server_recv_done_rx)
        .await
        .expect("server recv timed out")
        .expect("server recv channel closed");
    assert_eq!(
        received_by_server, payload_c2s,
        "client→server datagram payload mismatch"
    );

    // === Direction 2: server → client ===
    let server_chan = timeout(STEP, server_chan_rx)
        .await
        .expect("server channel never published")
        .expect("server channel closed");
    let payload_s2c = b"reply-via-datagram-s2c";
    server_chan.try_send(payload_s2c).expect("server try_send");

    let received_by_client = timeout(STEP, client_chan.recv())
        .await
        .expect("client recv timed out")
        .expect("client recv error");
    assert_eq!(
        received_by_client, payload_s2c,
        "server→client datagram payload mismatch"
    );

    drop(client_chan);
    drop(server_chan);
    drop(client);
    server_task.abort();
}
