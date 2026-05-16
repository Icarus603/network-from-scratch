//! Regression test for the QUIC prefix-noise GFW-evasion behavior.
//!
//! ## Background
//!
//! The 2026 GFW QUIC SNI Inspector has an optimization documented in
//! the USENIX Security '25 paper "Exposing and Circumventing
//! SNI-based QUIC Censorship of the Great Firewall of China"
//! (Zohaib et al.): it only inspects the FIRST UDP datagram in a
//! flow (`(src_ip, dst_ip, src_port, dst_port)` 4-tuple, 60-second
//! flow-state timeout). The paper recommends sending one random-
//! payload UDP datagram BEFORE the QUIC Initial; the GFW classifies
//! it as the "first datagram", fails to find a QUIC Initial header,
//! and gives up. The real QUIC Initial arrives as the SECOND
//! datagram on that 4-tuple and never gets inspected.
//!
//! The β client implements this by binding a `std::net::UdpSocket`
//! itself, sending a 16-byte random datagram, then handing the
//! socket to `quinn::Endpoint::new`. The same socket is used for
//! both the noise AND the QUIC traffic, so the flow 4-tuple stays
//! consistent across both.
//!
//! ## What this test pins
//!
//! Stand up a UDP listener that records the first TWO datagrams it
//! sees from a single source. Use the production β client to dial.
//! Assert:
//!   1. First datagram is NOT a valid QUIC Initial (16 bytes random
//!      noise — first byte's long-header bit is statistically
//!      unlikely to be both set AND match a valid QUIC version).
//!   2. Second datagram IS a valid QUIC Initial (long-header bit
//!      set, version field is one of the known QUIC v1 values).
//!   3. Both came from the SAME source 4-tuple — proving the noise
//!      and the Initial use the same socket and would be seen by
//!      the GFW as the same flow.

use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use tokio::net::UdpSocket;

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn beta_client_emits_noise_before_quic_initial() {
    // Plain UDP absorber on a random port. Records every datagram's
    // (source_addr, first 32 bytes) in arrival order.
    let server = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let server_addr: SocketAddr = server.local_addr().unwrap();
    let dst_port = server_addr.port();

    type Capture = (SocketAddr, Vec<u8>);
    let captures: Arc<Mutex<Vec<Capture>>> = Arc::new(Mutex::new(Vec::new()));
    let cap_clone = Arc::clone(&captures);
    tokio::spawn(async move {
        let mut buf = [0u8; 2048];
        loop {
            match server.recv_from(&mut buf).await {
                Ok((n, src)) => {
                    let prefix = buf[..n.min(32)].to_vec();
                    let mut g = cap_clone.lock().unwrap();
                    g.push((src, prefix));
                    if g.len() >= 4 {
                        return;
                    }
                }
                Err(_) => return,
            }
        }
    });

    // Use the production β client to dial. The connect will fail at
    // the QUIC handshake stage because the absorber doesn't speak
    // QUIC — but the client WILL emit the noise + QUIC Initial first,
    // which is what we measure.
    let mut rng = rand_core::OsRng;
    let client_id_sk = proteus_crypto::sig::generate(&mut rng);
    let cfg = proteus_transport_alpha::client::ClientConfig {
        server_mlkem_pk_bytes: vec![0u8; 1184], // bogus — connect fails after QUIC handshake
        server_x25519_pub: [0u8; 32],
        server_pq_fingerprint: [0u8; 32],
        client_id_sk,
        user_id: *b"noisetst",
        pow_difficulty: 0,
        profile_hint: proteus_transport_alpha::ProfileHint::Beta,
    };

    // Fire-and-forget — we only care about what the client emits
    // before the QUIC handshake gives up. 2-second connect timeout
    // is plenty since there's no real peer.
    let _connect_task = tokio::spawn(async move {
        let _ = proteus_transport_beta::client::connect_with_timeout(
            "localhost",
            server_addr,
            vec![],
            cfg,
            Duration::from_secs(2),
        )
        .await;
    });

    // Wait for the absorber to record at least 2 datagrams. quinn
    // retransmits Initial on a fast schedule (~10 ms initial backoff),
    // so getting 2 datagrams within 1 second is reliable.
    let deadline = std::time::Instant::now() + Duration::from_secs(5);
    while std::time::Instant::now() < deadline {
        if captures.lock().unwrap().len() >= 2 {
            break;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }

    let caps = captures.lock().unwrap().clone();
    eprintln!(
        "captured {} datagrams; first 2: lengths=({}, {})",
        caps.len(),
        caps.first().map_or(0, |c| c.1.len()),
        caps.get(1).map_or(0, |c| c.1.len()),
    );
    assert!(
        caps.len() >= 2,
        "expected >=2 datagrams (noise + QUIC Initial); got {} ({} bytes each)",
        caps.len(),
        caps.iter()
            .map(|(_, p)| p.len().to_string())
            .collect::<Vec<_>>()
            .join(", "),
    );

    let (src0, payload0) = &caps[0];
    let (src1, payload1) = &caps[1];

    // PROPERTY 1: same source address (= same 4-tuple from GFW POV).
    assert_eq!(
        src0, src1,
        "first two datagrams from DIFFERENT source addrs ({src0} vs {src1}) — \
         GFW would see them as separate flows, evasion broken"
    );

    // PROPERTY 2: first datagram is the noise (NOT a valid QUIC Initial).
    //
    // A QUIC Initial packet has:
    //   - byte 0: high bit (0x80) = Long Header form, second bit
    //     (0x40) = Fixed Bit (always 1 for QUIC v1).
    //     Top two bits of byte 0 = 0b11xx_xxxx for any valid QUIC v1
    //     long-header packet.
    //   - bytes 1..5: Version field. For QUIC v1: 0x00000001.
    //
    // Our noise is 16 random bytes. Probability of randomly looking
    // like a valid QUIC v1 long header (top 2 bits of byte 0 set
    // AND version bytes == 0x00000001) is ~2^-34 — negligible.
    let looks_like_quic_v1_initial = |pkt: &[u8]| -> bool {
        if pkt.len() < 5 {
            return false;
        }
        let long_header_bits_ok = (pkt[0] & 0xc0) == 0xc0;
        let version = u32::from_be_bytes([pkt[1], pkt[2], pkt[3], pkt[4]]);
        // QUIC v1 = 0x00000001 (RFC 9000). quinn's initial uses v1.
        long_header_bits_ok && version == 0x0000_0001
    };
    assert!(
        !looks_like_quic_v1_initial(payload0),
        "first datagram unexpectedly looks like a valid QUIC v1 Initial — \
         either the prefix-noise feature regressed, OR the random 16 bytes \
         got astronomically unlucky (2^-34 chance). First few bytes: {:02x?}",
        &payload0[..payload0.len().min(8)],
    );

    // PROPERTY 3: second datagram IS a valid QUIC v1 Initial.
    assert!(
        looks_like_quic_v1_initial(payload1),
        "second datagram is NOT a valid QUIC v1 Initial — what did the \
         client emit? First few bytes: {:02x?}",
        &payload1[..payload1.len().min(8)],
    );

    eprintln!(
        "GFW-evasion prefix-noise test: src={src0} dst={dst_port}, \
         datagram[0]={} bytes (noise), datagram[1]={} bytes (real QUIC Initial)",
        payload0.len(),
        payload1.len(),
    );
}
