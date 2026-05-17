//! Integration test: prove that `server_handshake_io` driving
//! rustls over a `PrependedStream` (Path-A's wrap of TcpStream)
//! produces the same TLS termination behavior as the legacy
//! `server_handshake` over a bare TcpStream.
//!
//! Why this matters: iteration 7 lifts `server_handshake` off
//! the concrete `TcpStream` type so the gated accept loop can
//! drive rustls over a `PrependedStream`. The PrependedStream
//! yields the original ClientHello bytes (peeked by the gate)
//! BEFORE forwarding from the underlying socket. If the generic
//! IO refactor is wrong, rustls either blocks forever (never
//! gets enough bytes) or sees a corrupted ClientHello (the gate
//! consumed some bytes the prepend doesn't replay correctly).
//!
//! This test stands up a real rustls server + a real rustls
//! client over a loopback TCP pair, peeks the ClientHello on
//! the server side, wraps the TCP stream in a PrependedStream
//! that replays the peeked bytes, then drives the TLS handshake
//! through `server_handshake_io`. Expected: TLS handshake
//! completes; an echo round-trip works.

use std::sync::Arc;

use proteus_transport_alpha::clienthello_sniffer::{sniff_client_hello, SniffedClientHello};
use proteus_transport_alpha::knock_dispatch::PrependedStream;
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

#[tokio::test]
async fn server_handshake_io_completes_tls_over_prepended_stream() {
    // ---- Mint cert + acceptor + connector ----
    let (cert, key) = mint_self_signed();
    let chain = vec![cert.clone()];
    let acceptor = build_acceptor(chain.clone(), key).unwrap();
    let connector = build_connector_with_ca_der(cert).unwrap();

    // ---- Loopback listener ----
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();

    // ---- Client task: drive TLS handshake + echo + close ----
    let client_task = tokio::spawn(async move {
        let tcp = TcpStream::connect(addr).await.unwrap();
        let sn = rustls::pki_types::ServerName::try_from("localhost")
            .unwrap()
            .to_owned();
        let mut tls = connector.connect(sn, tcp).await.unwrap();
        tls.write_all(b"PING_FROM_CLIENT").await.unwrap();
        tls.flush().await.unwrap();
        let mut buf = [0u8; 64];
        let n = tls.read(&mut buf).await.unwrap();
        assert_eq!(&buf[..n], b"PONG_FROM_SERVER");
        tls.shutdown().await.ok();
    });

    // ---- Server task: peek ClientHello, wrap, run TLS handshake ----
    let server_task = tokio::spawn(async move {
        let (mut tcp, _peer) = listener.accept().await.unwrap();
        // Peek the ClientHello — this is what the gate does.
        let sniffed: SniffedClientHello = sniff_client_hello(&mut tcp).await.unwrap();
        // Wrap with PrependedStream so the TLS terminator sees
        // the original ClientHello bytes followed by live
        // socket data.
        let wrapped = PrependedStream::with_prefix(sniffed.peeked_bytes, tcp);
        // Drive TLS through the generic-IO server_handshake_io.
        let mut tls = server_handshake_io(&acceptor, wrapped).await.unwrap();
        // Echo + close.
        let mut buf = [0u8; 64];
        let n = tls.read(&mut buf).await.unwrap();
        assert_eq!(&buf[..n], b"PING_FROM_CLIENT");
        tls.write_all(b"PONG_FROM_SERVER").await.unwrap();
        tls.flush().await.unwrap();
        tls.shutdown().await.ok();
    });

    tokio::try_join!(client_task, server_task).unwrap();
}

#[tokio::test]
async fn server_handshake_io_works_with_empty_prefix_passthrough() {
    // Sanity: when the PrependedStream has an empty prefix
    // (Path A disabled mode), server_handshake_io behaves
    // identically to the legacy server_handshake over a bare
    // TcpStream. Operators who haven't opted into Path A but
    // happen to use the new API path still get correct TLS
    // termination.
    let (cert, key) = mint_self_signed();
    let chain = vec![cert.clone()];
    let acceptor = build_acceptor(chain.clone(), key).unwrap();
    let connector = build_connector_with_ca_der(cert).unwrap();

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();

    let client_task = tokio::spawn(async move {
        let tcp = TcpStream::connect(addr).await.unwrap();
        let sn = rustls::pki_types::ServerName::try_from("localhost")
            .unwrap()
            .to_owned();
        let mut tls = connector.connect(sn, tcp).await.unwrap();
        tls.write_all(b"BARE").await.unwrap();
        tls.flush().await.unwrap();
        let mut buf = [0u8; 16];
        let n = tls.read(&mut buf).await.unwrap();
        assert_eq!(&buf[..n], b"ECHO");
        tls.shutdown().await.ok();
    });

    let server_task = tokio::spawn(async move {
        let (tcp, _) = listener.accept().await.unwrap();
        // Passthrough wrap — empty prefix.
        let wrapped = PrependedStream::passthrough(tcp);
        let mut tls = server_handshake_io(&acceptor, wrapped).await.unwrap();
        let mut buf = [0u8; 16];
        let n = tls.read(&mut buf).await.unwrap();
        assert_eq!(&buf[..n], b"BARE");
        tls.write_all(b"ECHO").await.unwrap();
        tls.flush().await.unwrap();
        tls.shutdown().await.ok();
    });

    tokio::try_join!(client_task, server_task).unwrap();
}

// Note: Arc import kept for future test fixtures that may wrap
// the acceptor — suppresses unused-import warning if added back.
#[allow(dead_code)]
fn _phantom_arc<T>(_: Arc<T>) {}
