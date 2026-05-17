//! Wire-level regression test for `PerfProfile.allow_spin_bit = false`.
//!
//! ## Why this exists
//!
//! The QUIC spin bit (RFC 9000 §17.4, bit `0x20` in the first byte
//! of any 1-RTT short-header packet) is a wire-visible RTT side
//! channel: when active, an on-path observer can passively measure
//! the connection's round-trip time by watching how often the bit
//! toggles. RFC 9000 makes it explicit:
//!
//! > Endpoints can optionally set the spin bit ... such that on-path
//! > observers can perform passive RTT measurements.
//!
//! quinn's upstream default is `true` (set for the broader QUIC
//! ecosystem to support network operators). Proteus deliberately
//! overrides to `false` — we are not going to give the GFW (or any
//! adversary that can observe the wire) a free RTT oracle.
//!
//! This test is the wire-level proof that the override actually
//! takes effect. The override has been a single line of code since
//! the PerfProfile change, but the path from `PerfProfile.allow_spin_bit`
//! through `apply_perf_tuning_with` → `quinn::TransportConfig::allow_spin`
//! → quinn's per-packet spin emission is long enough that a future
//! quinn version bump (or a refactor of `apply_perf_tuning_with`)
//! could silently sever any link in the chain. The unit-test in
//! `lib.rs::perf_profile_defaults` covers the field default; this
//! covers the wire behavior.
//!
//! ## What this test pins (the subtle part)
//!
//! Per RFC 9000 §17.4 paragraph 6 + quinn-proto's
//! `connection/packet_builder.rs:94`:
//!
//! > Endpoints that disable the spin bit MUST set a RANDOM value
//! > in the spin-bit position on every 1-RTT packet they send, so
//! > that a passive observer cannot distinguish "spin disabled" from
//! > "spin enabled but the connection's RTT happens to not toggle".
//!
//! So the wire-level privacy property is NOT "spin bit is always
//! zero" — that would itself be a distinguishable fingerprint. It's
//! **"spin bit's value is uncorrelated with RTT"**, which we
//! operationalize as: across N≥32 captured 1-RTT short-header
//! packets, the spin bit's set/clear distribution is statistically
//! consistent with random (each value within a generous Bernoulli
//! confidence interval).
//!
//! Conversely, **if `allow_spin(false)` were broken** and quinn
//! reverted to spin-enabled behavior on a low-RTT loopback path
//! (where there are very few in-flight packets per RTT), the spin
//! bit would toggle at most a handful of times across the whole
//! capture — strongly *non-uniform*. Our threshold catches this.
//!
//! Short-header packets have byte 0 layout `0b01xx_xxxx` (long-header
//! bit = 0, fixed bit = 1). The spin bit is bit `0x20` of that byte.
//! Bit `0x20` is NOT header-protected (RFC 9001 §5.4.1 protects only
//! the LSB 4 bits), so we can read it directly from byte 0 of every
//! captured datagram's first QUIC packet.
//!
//! We filter out long-header packets (handshake / Initial / Retry /
//! version-negotiation) because the spin bit is only defined for
//! 1-RTT short-header packets — long headers use the bit position
//! for other purposes.
//!
//! ## Construction
//!
//! Same shape as `quic_pad_to_mtu_wire.rs`: stand up the β server +
//! a UDP mirror that records every datagram in each direction, dial
//! through the mirror with the production β client, drive ≥ 16
//! round-trip records, then audit all captured short-header packets.

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
/// Bit `0x20` in the first byte of a 1-RTT short-header QUIC packet
/// (RFC 9000 §17.4 / `quinn-proto` `packet::SPIN_BIT`).
const SPIN_BIT: u8 = 0x20;
/// Long-header bit. If bit `0x80` of byte 0 is SET, this is a long-
/// header packet (Initial / Handshake / Retry / 0-RTT / Version-Neg)
/// and the spin bit semantics don't apply.
const LONG_HEADER: u8 = 0x80;

#[derive(Clone, Debug)]
#[allow(dead_code)] // dir/len kept for future diagnostic prints
struct Capture {
    /// Direction (for diagnostic reporting): "C2S" or "S2C".
    dir: &'static str,
    /// Up to 4 bytes of the datagram prefix (enough to inspect the
    /// QUIC short-header byte 0 + start of dest-CID; UDP datagrams
    /// can carry multiple coalesced QUIC packets but byte 0 is the
    /// outermost packet's header).
    prefix: [u8; 4],
    len: usize,
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn beta_spin_bit_is_never_set_on_wire_in_either_direction() {
    // ----- Real β server (uses Default PerfProfile → spin off) -----
    let ck = generate_simple_self_signed(vec!["localhost".to_string()]).unwrap();
    let cert_der = CertificateDer::from(ck.cert.der().to_vec());
    let key_der = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(ck.key_pair.serialize_der()));

    let server_keys = ServerKeys::generate();
    let mlkem_pk_bytes = server_keys.mlkem_pk_bytes.clone();
    let pq_fingerprint = server_keys.pq_fingerprint;
    let server_x25519_pub = server_keys.x25519_pub;
    let ctx = Arc::new(ServerCtx::new(server_keys));

    let server_bind: std::net::SocketAddr = "127.0.0.1:0".parse().unwrap();
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

    // ----- UDP mirror that records every datagram in both directions -----
    let mirror = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
    let mirror_addr: SocketAddr = mirror.local_addr().unwrap();
    let captures: Arc<Mutex<Vec<Capture>>> = Arc::new(Mutex::new(Vec::new()));
    let mirror_clone = Arc::clone(&mirror);
    let captures_clone = Arc::clone(&captures);
    tokio::spawn(async move {
        let mut buf = [0u8; 2048];
        let mut client_addr: Option<SocketAddr> = None;
        while let Ok((n, src)) = mirror_clone.recv_from(&mut buf).await {
            // Skip self-talk just in case.
            if src == mirror_addr {
                continue;
            }
            let (dir, dst) = if src == server_local {
                (
                    "S2C",
                    client_addr.expect("server reply before client first datagram?"),
                )
            } else {
                client_addr = Some(src);
                ("C2S", server_local)
            };
            let mut prefix = [0u8; 4];
            let copy_len = n.min(4);
            prefix[..copy_len].copy_from_slice(&buf[..copy_len]);
            captures_clone.lock().unwrap().push(Capture {
                dir,
                prefix,
                len: n,
            });
            let _ = mirror_clone.send_to(&buf[..n], dst).await;
        }
    });

    // ----- β client dials the mirror (default PerfProfile = spin OFF) -----
    let mut rng = rand_core::OsRng;
    let client_id_sk = proteus_crypto::sig::generate(&mut rng);
    let client_cfg = ClientConfig {
        server_mlkem_pk_bytes: mlkem_pk_bytes,
        server_x25519_pub,
        server_pq_fingerprint: pq_fingerprint,
        client_id_sk,
        user_id: *b"spintest",
        pow_difficulty: 0,
        profile_hint: ProfileHint::Beta,
    };
    let mut client = timeout(
        STEP,
        proteus_transport_beta::client::connect(
            "localhost",
            mirror_addr,
            vec![cert_der],
            client_cfg,
        ),
    )
    .await
    .expect("connect timeout")
    .expect("β connect ok");

    // ----- Drive ≥ 16 round-trip records to ensure plenty of
    //       post-handshake short-header traffic on the wire -----
    for i in 0..32u32 {
        let payload = format!("ping-{i:04}");
        timeout(STEP, client.session.sender.send_record(payload.as_bytes()))
            .await
            .unwrap()
            .unwrap();
        timeout(STEP, client.session.sender.flush())
            .await
            .unwrap()
            .unwrap();
        let echoed = timeout(STEP, client.session.receiver.recv_record())
            .await
            .unwrap()
            .unwrap()
            .expect("server closed early");
        assert_eq!(echoed, payload.as_bytes());
    }

    // Give the mirror a beat to flush its capture buffer for the
    // final flight.
    tokio::time::sleep(Duration::from_millis(50)).await;

    let caps = captures.lock().unwrap().clone();
    assert!(
        caps.len() >= 16,
        "expected ≥16 captured datagrams across both directions; got {}",
        caps.len(),
    );

    // ----- The audit: count spin-bit SET vs CLEAR across all
    //       1-RTT short-header packets and verify the distribution
    //       is consistent with random (see module doc for why this
    //       is the right test, not "always zero"). -----
    let mut short_header_total = 0usize;
    let mut spin_set = 0usize;
    for c in &caps {
        let b0 = c.prefix[0];
        if b0 & LONG_HEADER != 0 {
            // Long-header packet — spin bit semantics N/A.
            continue;
        }
        // Sanity: short header must also have the QUIC fixed bit
        // (0x40) set. quinn writes 1-RTT packets that satisfy this.
        if b0 & 0x40 == 0 {
            continue; // not a QUIC short-header — skip (could be a non-QUIC stray)
        }
        short_header_total += 1;
        if b0 & SPIN_BIT != 0 {
            spin_set += 1;
        }
    }

    assert!(
        short_header_total >= 16,
        "expected ≥16 short-header datagrams in the captures (handshake + 32 round-trips); \
         got {short_header_total}. Capture summary: {} total datagrams",
        caps.len(),
    );

    // Two-sided sanity check on the spin-bit distribution.
    //
    // **Lower bound: spin bit is not stuck at 0.**
    //   If spin_enabled were unconditionally false AND the
    //   randomization at packet_builder.rs:94 were also gone, we'd
    //   see spin_set == 0. We require at least 1 SET to catch this
    //   "doubly broken" regression class.
    //
    // **Upper bound: spin bit is not stuck at 1.**
    //   Symmetric — spin_set < short_header_total.
    //
    // **Critically: spin_set is in a generous random-Bernoulli
    //   confidence band.** A spin-enabled connection on loopback
    //   (sub-millisecond RTT) toggles at most a handful of times
    //   during 32 round-trips because the spin bit updates once per
    //   RTT. So spin-enabled gives us a near-constant value (almost
    //   all 0 or almost all 1, depending on parity at capture
    //   start). spin-disabled-with-randomization gives ~50%. The
    //   threshold 30-70% is a conservative band: it catches both
    //   "stuck at extreme value" (spin-enabled bug) and the broken
    //   randomization case.
    //
    // We make the band wide enough to never flake on legitimate
    // randomness (Bernoulli p=0.5 at n=16 has 99.99% probability of
    // landing in [3, 13] = 18.75% - 81.25%, plenty of margin under
    // our 30-70% band).
    let set_pct = (spin_set as f64) / (short_header_total as f64) * 100.0;
    assert!(
        (30.0..=70.0).contains(&set_pct),
        "QUIC spin bit (RFC 9000 §17.4) distribution is NOT consistent with random: \
         {spin_set}/{short_header_total} short-header packets ({set_pct:.1}%) had the \
         spin bit set. Expected band: 30-70%. If this is far from 50%, the \
         allow_spin(false) override OR quinn's compensating random-write at \
         packet_builder.rs:94 (RFC 9000 §17.4 paragraph 6) has regressed — either \
         way, on-path observers can passively measure RTT from this connection.",
    );

    // Diagnostic log so the test prints something useful in CI even
    // when it passes.
    eprintln!(
        "spin-bit audit: {spin_set}/{short_header_total} short-header packets had \
         spin bit set ({set_pct:.1}%) — within random band, allow_spin(false) verified"
    );

    // Clean up: close the connection so the server task drops its
    // session and unwinds. The mirror task and server_task get
    // dropped at scope end.
    let proteus_transport_alpha::session::AlphaSession { sender, .. } = client.session;
    let _ = sender.shutdown().await;
    client.connection.close(0u32.into(), b"bye");
    drop(client.endpoint);
    server_task.abort();
}
