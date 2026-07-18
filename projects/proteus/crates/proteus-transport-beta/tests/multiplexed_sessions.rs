//! Reusable-carrier regression coverage.
//!
//! Proves that one QUIC/TLS carrier can host sequential and
//! concurrent, independently handshaken Proteus sessions, and that
//! an idle interval longer than the inner-handshake deadline does
//! not kill the warm carrier.

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
async fn one_carrier_hosts_warm_and_concurrent_sessions() {
    let ck = generate_simple_self_signed(vec!["localhost".to_string()]).unwrap();
    let cert_der = CertificateDer::from(ck.cert.der().to_vec());
    let key_der = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(ck.key_pair.serialize_der()));

    let server_keys = ServerKeys::generate();
    let mlkem_pk_bytes = server_keys.mlkem_pk_bytes.clone();
    let pq_fingerprint = server_keys.pq_fingerprint;
    let server_x25519_pub = server_keys.x25519_pub;
    let ctx = Arc::new(
        ServerCtx::new(server_keys)
            .with_max_connections(8)
            .with_handshake_deadline(Duration::from_millis(500)),
    );

    let endpoint = proteus_transport_beta::server::make_endpoint(
        "127.0.0.1:0".parse().unwrap(),
        vec![cert_der.clone()],
        key_der,
    )
    .unwrap();
    let server_addr = endpoint.local_addr().unwrap();
    let server_task = tokio::spawn(async move {
        let _ = proteus_transport_beta::server::serve(endpoint, ctx, |mut session| async move {
            if let Ok(Some(record)) = session.receiver.recv_record().await {
                let _ = session.sender.send_record(&record).await;
                let _ = session.sender.flush().await;
            }
            let _ = session.sender.shutdown().await;
        })
        .await;
    });

    let crypto = proteus_transport_beta::client::build_client_crypto_cache(vec![cert_der]).unwrap();
    let carrier = proteus_transport_beta::client::connect_carrier_with_timeout_perf_cached_crypto(
        "localhost",
        server_addr,
        &crypto,
        Duration::from_secs(5),
        proteus_transport_beta::PerfProfile::default(),
    )
    .await
    .unwrap();
    let carrier_id = carrier.stable_id();

    let make_cfg = || ClientConfig {
        server_mlkem_pk_bytes: mlkem_pk_bytes.clone(),
        server_x25519_pub,
        server_pq_fingerprint: pq_fingerprint,
        client_id_sk: proteus_crypto::sig::generate(&mut rand_core::OsRng),
        user_id: *b"multiplx",
        pow_difficulty: 0,
        profile_hint: ProfileHint::Beta,
    };

    let pre_auth_probe = carrier
        .run_authenticated_probe(
            proteus_transport_beta::recovery::RecoveryDirection::ClientToServer,
            proteus_transport_beta::recovery::RecoveryProfile::Standard,
            proteus_transport_beta::probe::PROBE_PAYLOAD_BYTES,
        )
        .await
        .unwrap_err();
    assert!(pre_auth_probe.to_string().contains("authenticated carrier"));

    async fn round_trip(
        mut session: proteus_transport_alpha::session::AlphaSession<
            quinn::RecvStream,
            quinn::SendStream,
        >,
        payload: &[u8],
    ) {
        session.sender.send_record(payload).await.unwrap();
        session.sender.flush().await.unwrap();
        let echoed = session.receiver.recv_record().await.unwrap().unwrap();
        assert_eq!(echoed, payload);
        session.sender.shutdown().await.unwrap();
    }

    let first = timeout(
        STEP,
        carrier.open_session(make_cfg(), Duration::from_secs(5)),
    )
    .await
    .unwrap()
    .unwrap();
    round_trip(first, b"first").await;

    for direction in [
        proteus_transport_beta::recovery::RecoveryDirection::ClientToServer,
        proteus_transport_beta::recovery::RecoveryDirection::ServerToClient,
    ] {
        let probe = timeout(
            STEP,
            carrier.run_authenticated_probe(
                direction,
                proteus_transport_beta::recovery::RecoveryProfile::Standard,
                proteus_transport_beta::probe::PROBE_PAYLOAD_BYTES,
            ),
        )
        .await
        .unwrap()
        .unwrap();
        assert_eq!(probe.direction, direction);
        assert_eq!(
            probe.payload_bytes,
            u64::from(proteus_transport_beta::probe::PROBE_PAYLOAD_BYTES)
        );
        assert!(probe.completion_time > Duration::ZERO);
        assert!(probe.counters.sent_packets > 0);
    }

    for direction in [
        proteus_transport_beta::recovery::RecoveryDirection::ClientToServer,
        proteus_transport_beta::recovery::RecoveryDirection::ServerToClient,
    ] {
        let mut selector = proteus_transport_beta::recovery::RecoverySelector::new(
            direction,
            proteus_transport_beta::recovery::RecoveryPolicy::default(),
        )
        .unwrap();
        let mut decision = None;
        for round in 1..=7 {
            decision = Some(
                timeout(
                    STEP,
                    carrier.run_matched_recovery_round(&mut selector, round),
                )
                .await
                .unwrap()
                .unwrap(),
            );
        }
        let decision = decision.unwrap();
        assert_eq!(
            decision.profile(),
            proteus_transport_beta::recovery::RecoveryProfile::Standard
        );
        assert!(!matches!(
            decision,
            proteus_transport_beta::recovery::RecoveryDecision::Collecting { .. }
        ));
    }

    // This exceeds the inner-handshake deadline. The carrier must
    // remain reusable; only an in-progress handshake is deadline
    // bounded, not an idle accept_bi wait.
    tokio::time::sleep(Duration::from_millis(800)).await;
    let warm = timeout(
        STEP,
        carrier.open_session(make_cfg(), Duration::from_secs(5)),
    )
    .await
    .unwrap()
    .unwrap();
    round_trip(warm, b"warm-after-idle").await;

    let (left, right) = tokio::join!(
        carrier.open_session(make_cfg(), Duration::from_secs(5)),
        carrier.open_session(make_cfg(), Duration::from_secs(5)),
    );
    let (left, right) = (left.unwrap(), right.unwrap());
    tokio::join!(
        round_trip(left, b"parallel-left"),
        round_trip(right, b"parallel-right")
    );

    assert!(carrier.is_usable());
    assert_eq!(carrier.stable_id(), carrier_id);
    carrier.close();
    server_task.abort();
}
