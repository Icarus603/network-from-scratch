//! Regression test for QUIC connection migration — USENIX Security 25
//! evasion #4 against the GFW's 180-second 5-tuple drop.
//!
//! ## The 2026 attack
//!
//! When the GFW's QUIC SNI Inspector flags a connection (forbidden
//! SNI, source-port heuristic miss, etc.), it triggers a 180-second
//! drop of every packet on the 4-tuple
//! `(src_ip, dst_ip, src_port, dst_port)`. Standard QUIC clients
//! lose the connection entirely and have to redial — exposing the
//! handshake to inspection again.
//!
//! ## The evasion
//!
//! QUIC's native connection-migration protocol (RFC 9000 §9) lets
//! the client switch to a new local UDP socket mid-session. The
//! existing connection ID stays valid; quinn negotiates path
//! validation transparently. From the GFW's POV the migrated
//! connection has a different 4-tuple, isn't in the drop table,
//! and traffic flows again.
//!
//! ## What this test pins
//!
//! Open a real β session. Send one record, receive its echo.
//! Note the local UDP source port. Call `session.migrate()`. Send
//! a second record on the SAME session, receive its echo. Assert:
//!   1. The migrate succeeded.
//!   2. The new local port differs from the original.
//!   3. The second record round-tripped through the SAME Proteus
//!      session (proves the inner-session state survived the
//!      transport-layer migration — channel binding, AEAD keys,
//!      ratchet state, everything).

use std::sync::Arc;
use std::time::Duration;

use proteus_transport_alpha::client::ClientConfig;
use proteus_transport_alpha::server::{ServerCtx, ServerKeys};
use proteus_transport_alpha::ProfileHint;
use rcgen::generate_simple_self_signed;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use tokio::time::timeout;

const STEP: Duration = Duration::from_secs(15);

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn migration_preserves_session_across_source_port_change() {
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
    let server_addr = endpoint.local_addr().expect("local_addr");

    // Server: echo every record back.
    let server_ctx = Arc::clone(&ctx);
    tokio::spawn(async move {
        let _ =
            proteus_transport_beta::server::serve(endpoint, server_ctx, |mut session| async move {
                while let Ok(Some(rec)) = session.receiver.recv_record().await {
                    if session.sender.send_record(&rec).await.is_err() {
                        break;
                    }
                    if session.sender.flush().await.is_err() {
                        break;
                    }
                }
            })
            .await;
    });

    let mut rng = rand_core::OsRng;
    let client_id_sk = proteus_crypto::sig::generate(&mut rng);
    let cfg = ClientConfig {
        server_mlkem_pk_bytes: mlkem_pk_bytes,
        server_x25519_pub,
        server_pq_fingerprint: pq_fingerprint,
        client_id_sk,
        user_id: *b"migrate1",
        pow_difficulty: 0,
        profile_hint: ProfileHint::Beta,
    };
    let mut client = timeout(
        STEP,
        proteus_transport_beta::client::connect("localhost", server_addr, vec![cert_der], cfg),
    )
    .await
    .expect("connect timeout")
    .expect("connect ok");

    // ---- Pre-migration record exchange ----
    let pre_payload = b"before-migration";
    timeout(STEP, client.session.sender.send_record(pre_payload))
        .await
        .unwrap()
        .unwrap();
    timeout(STEP, client.session.sender.flush())
        .await
        .unwrap()
        .unwrap();
    let echoed = timeout(STEP, client.session.receiver.recv_record())
        .await
        .expect("pre recv timeout")
        .expect("pre recv ok")
        .expect("pre session closed");
    assert_eq!(echoed.as_slice(), pre_payload);

    let pre_local_addr = client.endpoint.local_addr().expect("pre local_addr");
    eprintln!("pre-migration: client local = {pre_local_addr}");

    // ---- Trigger migration ----
    let post_local_addr = client.migrate().expect("migrate ok");
    eprintln!("post-migration: client local = {post_local_addr}");

    assert_ne!(
        pre_local_addr.port(),
        post_local_addr.port(),
        "migrate did not change the local source port — the rebind was a no-op. \
         (Both bound to port {})",
        pre_local_addr.port()
    );

    // ---- Post-migration record exchange ----
    //
    // Path validation needs a brief window after rebind; quinn
    // sends PATH_CHALLENGE on the next outbound packet. Our
    // send_record below IS that next packet, so validation
    // happens on the first record exchange after migrate().
    let post_payload = b"after-migration-survived";
    timeout(STEP, client.session.sender.send_record(post_payload))
        .await
        .unwrap()
        .unwrap();
    timeout(STEP, client.session.sender.flush())
        .await
        .unwrap()
        .unwrap();
    let echoed = timeout(STEP, client.session.receiver.recv_record())
        .await
        .expect("post recv timeout — quinn's path validation may have failed")
        .expect("post recv ok")
        .expect("post session closed — migration broke the inner Proteus session");
    assert_eq!(
        echoed.as_slice(),
        post_payload,
        "post-migration record content corruption — channel binding may have been invalidated"
    );

    drop(client);
}
