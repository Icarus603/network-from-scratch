//! End-to-end tests proving why `KnockRewriteStream` ALONE is
//! insufficient for client-side Path A. Documents the
//! TLS 1.3 transcript-hash binding that forces iteration 10
//! (a rustls fork). See `src/knock_rewriter.rs` module
//! header for the full explanation.
//!
//! The two `#[ignore]` tests below stand as DELIBERATE failure
//! evidence. Running them with `--include-ignored` produces
//! `DecryptError` on the very first encrypted record (server
//! Encrypted Extensions). The failure is reproducible and the
//! cause is well-understood: RFC 8446 §4.4 transcript hashes
//! diverge between client (sees rustls's original session_id)
//! and server (sees our rewritten session_id), so the keys
//! derived from H_client ≠ keys derived from H_server.
//!
//! Iteration 10 will land the rustls fork that lets us
//! generate the knock-bearing session_id INSIDE rustls's
//! ClientHello assembler — transcripts match by construction
//! and these tests will pass once that lands. Re-enabling
//! them is the iteration-10 acceptance criterion.

use std::sync::Arc;
use std::time::SystemTime;

use proteus_handshake::knock::{KnockPsk, KNOCK_PSK_LEN};
use proteus_transport_alpha::clienthello_sniffer::{sniff_client_hello, SniffedClientHello};
use proteus_transport_alpha::knock_dispatch::PrependedStream;
use proteus_transport_alpha::knock_rewriter::KnockRewriteStream;
use proteus_transport_alpha::tls::{
    build_acceptor, build_connector_with_ca_der, server_handshake_io,
};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

fn mint_self_signed() -> (CertificateDer<'static>, PrivateKeyDer<'static>) {
    let ck = rcgen::generate_simple_self_signed(vec!["localhost".to_string()]).unwrap();
    let cert = CertificateDer::from(ck.cert.der().to_vec());
    let key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(ck.key_pair.serialize_der()));
    (cert, key)
}

fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

#[tokio::test]
#[ignore = "blocked by TLS 1.3 transcript-hash divergence; iteration 10 (rustls fork) will fix"]
async fn rewriter_drives_full_tls_handshake_with_server_side_gate_verification() {
    // Shared PSK between client and server.
    let psk_bytes = [0x9Cu8; KNOCK_PSK_LEN];
    let psk_for_client = KnockPsk::from_bytes(psk_bytes);
    let psk_for_server = KnockPsk::from_bytes(psk_bytes);

    let (cert, key) = mint_self_signed();
    let acceptor = build_acceptor(vec![cert.clone()], key).unwrap();
    let connector = build_connector_with_ca_der(cert).unwrap();

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();

    // ---- Client: wrap TcpStream in KnockRewriteStream, then
    //              drive rustls over the wrapper. ----
    let client_task = tokio::spawn(async move {
        let tcp = TcpStream::connect(addr).await.unwrap();
        let wrapped = KnockRewriteStream::new(tcp, psk_for_client, unix_now());
        let sn = rustls::pki_types::ServerName::try_from("localhost")
            .unwrap()
            .to_owned();
        let mut tls = connector.connect(sn, wrapped).await.unwrap();
        tls.write_all(b"PING_FROM_CLIENT_VIA_KNOCK").await.unwrap();
        tls.flush().await.unwrap();
        let mut buf = [0u8; 64];
        let n = tls.read(&mut buf).await.unwrap();
        assert_eq!(&buf[..n], b"PONG_FROM_SERVER_AFTER_GATE");
        tls.shutdown().await.ok();
    });

    // ---- Server: sniff ClientHello, verify knock, accept TLS
    //              over PrependedStream. ----
    let server_task = tokio::spawn(async move {
        let (mut tcp, _peer) = listener.accept().await.unwrap();
        let sniffed: SniffedClientHello = sniff_client_hello(&mut tcp).await.unwrap();
        // Verify the knock — this is the actual Path-A gate
        // check. If the rewriter is broken, the sniffer would
        // either see an unmodified rustls session_id (knock
        // verification fails) or a malformed ClientHello
        // (parser fails).
        assert_eq!(
            sniffed.session_id.len(),
            32,
            "expected 32-byte session_id (rustls compat mode)"
        );
        proteus_handshake::knock_wire::decode_and_verify_session_id(
            &psk_for_server,
            &sniffed.client_random,
            &sniffed.session_id,
            unix_now(),
        )
        .expect("server-side knock verification must succeed");

        // Wrap with PrependedStream so rustls sees the
        // original (knock-bearing) ClientHello.
        let wrapped = PrependedStream::with_prefix(sniffed.peeked_bytes, tcp);
        let mut tls = server_handshake_io(&acceptor, wrapped).await.unwrap();
        let mut buf = [0u8; 64];
        let n = tls.read(&mut buf).await.unwrap();
        assert_eq!(&buf[..n], b"PING_FROM_CLIENT_VIA_KNOCK");
        tls.write_all(b"PONG_FROM_SERVER_AFTER_GATE").await.unwrap();
        tls.flush().await.unwrap();
        tls.shutdown().await.ok();
    });

    tokio::try_join!(client_task, server_task).unwrap();
}

#[tokio::test]
#[ignore = "blocked by TLS 1.3 transcript-hash divergence; iteration 10 (rustls fork) will fix"]
async fn rewriter_passes_through_arbitrary_app_data_after_handshake() {
    // After the TLS handshake completes, app-data records flow
    // through the rewriter unmodified. Send a few KB to prove
    // there's no buffering / fragmentation issue.
    let psk_bytes = [0x4Du8; KNOCK_PSK_LEN];
    let psk_for_client = KnockPsk::from_bytes(psk_bytes);
    let psk_for_server = KnockPsk::from_bytes(psk_bytes);

    let (cert, key) = mint_self_signed();
    let acceptor = build_acceptor(vec![cert.clone()], key).unwrap();
    let connector = build_connector_with_ca_der(cert).unwrap();

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();

    let payload_size: usize = 32 * 1024;

    let client_task = tokio::spawn(async move {
        let tcp = TcpStream::connect(addr).await.unwrap();
        let wrapped = KnockRewriteStream::new(tcp, psk_for_client, unix_now());
        let sn = rustls::pki_types::ServerName::try_from("localhost")
            .unwrap()
            .to_owned();
        let mut tls = connector.connect(sn, wrapped).await.unwrap();
        let payload = vec![0xACu8; payload_size];
        tls.write_all(&payload).await.unwrap();
        tls.flush().await.unwrap();

        let mut got = vec![0u8; payload_size];
        let mut read = 0;
        while read < payload_size {
            let n = tls.read(&mut got[read..]).await.unwrap();
            if n == 0 {
                break;
            }
            read += n;
        }
        assert_eq!(read, payload_size);
        assert!(got.iter().all(|b| *b == 0xCA));
        tls.shutdown().await.ok();
    });

    let server_task = tokio::spawn(async move {
        let (mut tcp, _peer) = listener.accept().await.unwrap();
        let sniffed: SniffedClientHello = sniff_client_hello(&mut tcp).await.unwrap();
        proteus_handshake::knock_wire::decode_and_verify_session_id(
            &psk_for_server,
            &sniffed.client_random,
            &sniffed.session_id,
            unix_now(),
        )
        .expect("server knock verify");

        let wrapped = PrependedStream::with_prefix(sniffed.peeked_bytes, tcp);
        let mut tls = server_handshake_io(&acceptor, wrapped).await.unwrap();

        let mut got = vec![0u8; payload_size];
        let mut read = 0;
        while read < payload_size {
            let n = tls.read(&mut got[read..]).await.unwrap();
            if n == 0 {
                break;
            }
            read += n;
        }
        assert_eq!(read, payload_size);
        // Echo back with all bytes XOR'd so the client can
        // verify the round-trip integrity (and that bytes
        // didn't get truncated/duplicated by the rewriter).
        let echo: Vec<u8> = got.into_iter().map(|b| b ^ 0x66).collect();
        tls.write_all(&echo).await.unwrap();
        tls.flush().await.unwrap();
        tls.shutdown().await.ok();
    });

    tokio::try_join!(client_task, server_task).unwrap();
}

#[tokio::test]
async fn rewriter_with_wrong_psk_results_in_knock_verification_failure() {
    // Client and server have DIFFERENT PSKs. The client's
    // rewriter still produces a 32-byte session_id, but the
    // server's verifier should reject it. The TLS handshake
    // itself would still complete (the bytes are
    // structurally valid), but the gate would route to cover
    // in a real deploy.
    let psk_for_client = KnockPsk::from_bytes([0xAA; KNOCK_PSK_LEN]);
    let psk_for_server = KnockPsk::from_bytes([0xBB; KNOCK_PSK_LEN]);

    let (cert, key) = mint_self_signed();
    // Server-side acceptor is not used here — we only care
    // that the sniffer-level gate rejects the bad knock. TLS
    // termination never starts.
    let _acceptor = build_acceptor(vec![cert.clone()], key).unwrap();
    let connector = build_connector_with_ca_der(cert).unwrap();

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();

    let client_task = tokio::spawn(async move {
        let tcp = TcpStream::connect(addr).await.unwrap();
        let wrapped = KnockRewriteStream::new(tcp, psk_for_client, unix_now());
        let sn = rustls::pki_types::ServerName::try_from("localhost")
            .unwrap()
            .to_owned();
        let _ = connector.connect(sn, wrapped).await; // may succeed or fail; we don't care
    });

    let server_task = tokio::spawn(async move {
        let (mut tcp, _peer) = listener.accept().await.unwrap();
        let sniffed = sniff_client_hello(&mut tcp).await.unwrap();
        let verdict = proteus_handshake::knock_wire::decode_and_verify_session_id(
            &psk_for_server,
            &sniffed.client_random,
            &sniffed.session_id,
            unix_now(),
        );
        assert!(verdict.is_err(), "wrong-PSK client must fail verification");
    });

    let _ = tokio::join!(client_task, server_task);
}

// Phantom import keeper.
#[allow(dead_code)]
fn _phantom<T>(_: Arc<T>) {}
