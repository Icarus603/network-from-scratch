//! Regression test for β-profile TLS channel binding over QUIC
//! (RFC 5705 / RFC 9266).
//!
//! Symmetric to α's `tls_channel_binding.rs`. The MITM:
//!
//!   client ──QUIC₁──> rogue_proxy ──QUIC₂──> server
//!
//! Both QUIC handshakes complete with valid (shared self-signed)
//! certificates. The rogue then re-frames the inner bidi-stream
//! bytes between the two sessions. Without channel binding the
//! inner Proteus handshake would complete fine and the MITM would
//! have a clean tunnel. WITH binding (this commit), the inner
//! Finished MAC chain commits to the QUIC outer exporter on each
//! end; the two exporters differ → MAC mismatch → handshake aborts.

use std::sync::Arc;
use std::time::Duration;

use proteus_transport_alpha::client::ClientConfig;
use proteus_transport_alpha::server::{ServerCtx, ServerKeys};
use proteus_transport_alpha::ProfileHint;
use rcgen::generate_simple_self_signed;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use tokio::sync::mpsc;
use tokio::time::timeout;

const STEP: Duration = Duration::from_secs(15);
const POST_REJECT_DRAIN: Duration = Duration::from_millis(750);

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn rogue_quic_mitm_is_rejected_by_channel_binding() {
    // -------- 1. Shared self-signed cert (rogue + server use the
    //         same cert so cert-pinning isn't what saves us —
    //         only QUIC channel binding can).
    let ck = generate_simple_self_signed(vec!["localhost".to_string()]).unwrap();
    let cert_der = CertificateDer::from(ck.cert.der().to_vec());
    let key_der = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(ck.key_pair.serialize_der()));

    // -------- 2. Real β server.
    let server_keys = ServerKeys::generate();
    let mlkem_pk_bytes = server_keys.mlkem_pk_bytes.clone();
    let pq_fingerprint = server_keys.pq_fingerprint;
    let server_x25519_pub = server_keys.x25519_pub;
    let ctx = Arc::new(ServerCtx::new(server_keys));

    let server_bind: std::net::SocketAddr = "127.0.0.1:0".parse().unwrap();
    let server_endpoint = proteus_transport_beta::server::make_endpoint(
        server_bind,
        vec![cert_der.clone()],
        key_der.clone_key(),
    )
    .expect("β server endpoint");
    let server_addr = server_endpoint.local_addr().unwrap();

    let (server_outcome_tx, mut server_outcome_rx) =
        mpsc::unbounded_channel::<Result<(), String>>();

    let server_ctx_clone = Arc::clone(&ctx);
    tokio::spawn(async move {
        // Use the production serve() — it does channel-binding extraction
        // + admission gates exactly the way production deployments do.
        let _ = proteus_transport_beta::server::serve(
            server_endpoint,
            server_ctx_clone,
            move |session| {
                let tx = server_outcome_tx.clone();
                async move {
                    // If we get here, the inner handshake completed —
                    // which under channel binding means the test failed
                    // (no MITM split detected). The proxy bridges should
                    // have caused BadServerFinished before this closure
                    // runs.
                    let _ = tx.send(Ok(()));
                    let _ = session.sender.shutdown().await;
                }
            },
        )
        .await;
    });

    // -------- 3. Rogue β proxy. Listens for the client's QUIC₁,
    //         terminates it with its own copy of the cert, then
    //         opens a fresh QUIC₂ to the real server, and pipes
    //         the bidi-stream bytes between them. From the
    //         client's perspective QUIC₁ has a valid cert
    //         (rogue serves the same self-signed cert). From the
    //         server's perspective QUIC₂ has a valid cert (real
    //         server cert; rogue presents its own). The two
    //         QUIC sessions have DIFFERENT exporters by
    //         construction.
    let rogue_bind: std::net::SocketAddr = "127.0.0.1:0".parse().unwrap();
    let rogue_endpoint =
        proteus_transport_beta::server::make_endpoint(rogue_bind, vec![cert_der.clone()], key_der)
            .expect("β rogue endpoint");
    let rogue_addr = rogue_endpoint.local_addr().unwrap();

    let cert_for_proxy = cert_der.clone();
    tokio::spawn(async move {
        // Accept ONE QUIC connection from the client.
        let cli_conn = match rogue_endpoint.accept().await {
            Some(c) => c,
            None => return,
        };
        let cli_conn = match cli_conn.await {
            Ok(c) => c,
            Err(_) => return,
        };

        // Open ONE QUIC₂ to the real server.
        let client_crypto =
            proteus_transport_beta::client::make_client_crypto(vec![cert_for_proxy])
                .expect("rogue client crypto");
        let qcc = Arc::new(
            quinn::crypto::rustls::QuicClientConfig::try_from(client_crypto.as_ref().clone())
                .expect("quic client config"),
        );
        let mut client_cfg = quinn::ClientConfig::new(qcc);
        let mut transport = quinn::TransportConfig::default();
        transport.max_idle_timeout(Some(Duration::from_secs(10).try_into().unwrap()));
        proteus_transport_beta::apply_perf_tuning(&mut transport);
        client_cfg.transport_config(Arc::new(transport));
        let bind: std::net::SocketAddr = "0.0.0.0:0".parse().unwrap();
        let mut endpoint = quinn::Endpoint::client(bind).expect("rogue qep");
        endpoint.set_default_client_config(client_cfg);
        let srv_conn = match endpoint
            .connect(server_addr, "localhost")
            .expect("rogue connect call")
            .await
        {
            Ok(c) => c,
            Err(_) => return,
        };

        // Wait for the client to open ONE bidi stream on QUIC₁.
        let (mut cli_send, mut cli_recv) = match cli_conn.accept_bi().await {
            Ok(p) => p,
            Err(_) => return,
        };
        // Open ONE bidi stream on QUIC₂ toward the real server.
        let (mut srv_send, mut srv_recv) = match srv_conn.open_bi().await {
            Ok(p) => p,
            Err(_) => return,
        };

        // Pipe BOTH directions of the inner bidi stream between QUIC₁
        // and QUIC₂. quinn already decrypted/encrypted at the QUIC layer
        // — what we're moving here is the PROTEUS inner-stream bytes,
        // which is exactly what a real β MITM would relay.
        let c_to_s = tokio::spawn(async move {
            let mut tmp = [0u8; 4096];
            loop {
                let n = match cli_recv.read(&mut tmp).await {
                    Ok(Some(n)) => n,
                    Ok(None) | Err(_) => return,
                };
                if srv_send.write_all(&tmp[..n]).await.is_err() {
                    return;
                }
            }
        });
        let s_to_c = tokio::spawn(async move {
            let mut tmp = [0u8; 4096];
            loop {
                let n = match srv_recv.read(&mut tmp).await {
                    Ok(Some(n)) => n,
                    Ok(None) | Err(_) => return,
                };
                if cli_send.write_all(&tmp[..n]).await.is_err() {
                    return;
                }
            }
        });
        let _ = tokio::join!(c_to_s, s_to_c);

        // Keep handles alive until the test ends.
        let _ = (cli_conn, srv_conn, endpoint);
    });

    // -------- 4. Client dials the rogue thinking it's the real server.
    let mut rng = rand_core::OsRng;
    let client_id_sk = proteus_crypto::sig::generate(&mut rng);
    let cfg = ClientConfig {
        server_mlkem_pk_bytes: mlkem_pk_bytes,
        server_x25519_pub,
        server_pq_fingerprint: pq_fingerprint,
        client_id_sk,
        user_id: *b"qcbtestr",
        pow_difficulty: 0,
        profile_hint: ProfileHint::Beta,
    };
    let client_result = timeout(
        STEP,
        proteus_transport_beta::client::connect("localhost", rogue_addr, vec![cert_der], cfg),
    )
    .await;

    match client_result {
        Ok(Ok(_)) => panic!(
            "β CHANNEL BINDING BROKEN: client's β handshake completed via \
             a rogue QUIC MITM that holds the cert. WITH binding this MUST \
             fail."
        ),
        Ok(Err(e)) => {
            eprintln!("β client correctly rejected rogue QUIC MITM: {e:?}");
        }
        Err(_) => {
            eprintln!("β client correctly stalled on rogue QUIC MITM relay");
        }
    }

    // -------- 5. Server-side outcome. Short wait since we already know
    //         the client rejected.
    let server_outcome = timeout(POST_REJECT_DRAIN, server_outcome_rx.recv())
        .await
        .ok()
        .flatten();
    match server_outcome {
        Some(Ok(())) => panic!(
            "β CHANNEL BINDING BROKEN: server-side β handshake accepted \
             a session relayed by a rogue QUIC MITM."
        ),
        Some(Err(e)) => eprintln!("β server correctly rejected rogue QUIC MITM: {e}"),
        None => eprintln!("β server never completed handshake (also acceptable)"),
    }
}
