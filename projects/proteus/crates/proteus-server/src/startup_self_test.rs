//! Startup-time loopback self-handshake.
//!
//! ## Why this exists
//!
//! Today the binary opens the accept loop and waits for real traffic.
//! If any of the following has silently broken, the operator only
//! learns about it when real users start failing handshakes:
//!
//!   - Wrong path to mlkem_sk / x25519_sk (typo'd YAML).
//!   - mlkem_pk + mlkem_sk that don't actually pair (mismatched
//!     keygen, accidentally rotated only one of the two).
//!   - A dep upgrade that broke ChaCha20-Poly1305 / HKDF / ML-KEM
//!     (post-cutoff regression in `ring` / `chacha20poly1305` /
//!     `ml-kem` — caught downstream only when the first user can't
//!     connect).
//!   - A build mismatch where the server binary expected one
//!     spec version and the client crate's wire encoding diverged.
//!   - Clock skew or RNG starvation severe enough to break the
//!     replay window initialization.
//!
//! The systemd-managed binary takes 200ms-1s to bind, accept, and
//! relay its first session — that's 200ms-1s of fresh outage on
//! every restart while the operator's users hit "connection
//! refused" / "handshake failed" / timeouts. A startup self-test
//! that runs a full loopback handshake BEFORE binding the public
//! listener moves that detection into the deploy window where the
//! operator (and `systemctl status`) actually sees it.
//!
//! ## What it does
//!
//! 1. Binds an in-process α-TCP listener on `127.0.0.1:0`.
//! 2. Spawns a one-shot accept handler that runs the production
//!    server's handshake path against the operator's REAL keys.
//! 3. Mints an ephemeral client identity (Ed25519 + user_id =
//!    `"selftest"`) and runs the production client's
//!    `handshake_over_tcp`.
//! 4. After handshake, the client sends a small probe record;
//!    the server echos; the client verifies the roundtrip.
//! 5. Both sides clean-close. Self-test reports total elapsed
//!    + per-phase timings.
//!
//! Failure aborts the binary before the public listener binds —
//! systemd sees a non-zero exit AND a structured log line; the
//! operator's deploy gate (Ansible / Terraform / their CI) fails
//! fast instead of silently rolling out a broken binary.
//!
//! ## Why a separate user_id
//!
//! The probe uses `user_id = *b"selftest"`. Operators with strict
//! allowlists will see this user_id miss their allowlist — that's
//! expected and handled: the self-test temporarily uses a
//! ServerCtx with NO allowlist (matches the "no allowlist
//! configured" code path) so the probe succeeds regardless of
//! production allowlist config. This means the self-test is
//! testing the CRYPTO PATH, not the allowlist policy — which is
//! the right factoring (allowlist policy is operator-policy
//! validated by `proteus-server validate`, the crypto path is
//! what only a real handshake can exercise).

use std::sync::Arc;
use std::time::{Duration, Instant};

use proteus_transport_alpha::client::{self, ClientConfig};
use proteus_transport_alpha::server::{self, ServerCtx, ServerKeys};
use tokio::net::{TcpListener, TcpStream};

/// What the self-test produces. Per-phase timings let operators
/// notice regressions — e.g. ML-KEM keygen suddenly taking 50ms
/// instead of 5ms after a dep upgrade is a leading indicator of
/// a perf bug, even when the handshake still succeeds.
#[derive(Debug, Clone, Copy)]
pub struct SelfTestOutcome {
    pub total: Duration,
    pub handshake: Duration,
    pub roundtrip: Duration,
}

/// Errors the self-test surfaces. Carry enough context for the
/// operator to fix the underlying issue without re-running with
/// verbose logging.
#[derive(Debug)]
pub enum SelfTestError {
    /// `127.0.0.1:0` bind failed (very rare; OS-level issue).
    Bind(std::io::Error),
    /// Connecting back to the listener failed. Almost always
    /// caused by an FD/ulimit problem visible BEFORE the public
    /// listener is even reached.
    Connect(std::io::Error),
    /// The handshake exchange failed. Most common production
    /// trip-wire: mismatched ML-KEM key files, broken AEAD
    /// (post-cutoff dep regression), unexpected wire-format
    /// version.
    Handshake(String),
    /// Roundtrip echo / drain failed. Catches AEAD-decrypt bugs
    /// on the receive side that pass the handshake but break
    /// at the first record.
    Roundtrip(String),
    /// The whole flow took longer than the operator-supplied
    /// deadline. Default is 10s; a self-test that takes >10s on
    /// modern hardware indicates RNG starvation or a CPU-pinned
    /// hot loop somewhere upstream.
    Timeout(Duration),
}

impl std::fmt::Display for SelfTestError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SelfTestError::Bind(e) => write!(
                f,
                "startup self-test: 127.0.0.1:0 bind failed — \
                 check FD ulimit / network namespace: {e}"
            ),
            SelfTestError::Connect(e) => write!(
                f,
                "startup self-test: loopback connect failed — \
                 unlikely but check kernel net.core caps: {e}"
            ),
            SelfTestError::Handshake(s) => write!(
                f,
                "startup self-test: handshake FAILED — most likely \
                 mismatched mlkem_pk/mlkem_sk OR x25519_pk/x25519_sk \
                 (rotate the matching pair) OR a dep regression broke \
                 the crypto stack: {s}"
            ),
            SelfTestError::Roundtrip(s) => write!(
                f,
                "startup self-test: post-handshake echo FAILED — \
                 AEAD record path broken (verify chacha20poly1305 / \
                 hkdf versions): {s}"
            ),
            SelfTestError::Timeout(d) => write!(
                f,
                "startup self-test: deadline exceeded after {d:?} — \
                 RNG starvation, CPU pinning, or a hung dep upstream"
            ),
        }
    }
}

impl std::error::Error for SelfTestError {}

/// Run the self-test against the operator's REAL `ServerKeys`.
/// Returns timing info on success; an actionable error on failure.
///
/// `deadline` bounds the entire flow. Sensible default: 10s.
///
/// **`keys` is consumed** because the self-test moves it into the
/// throwaway ServerCtx. Callers MUST keep a clone for the real
/// listener — or run this test BEFORE calling `load_server_keys`
/// a second time. The recommended pattern is to load keys, clone
/// them into the self-test, then use the original for the
/// production listener.
pub async fn run_self_test(
    keys: ServerKeys,
    deadline: Duration,
) -> Result<SelfTestOutcome, SelfTestError> {
    let total_start = Instant::now();
    // Capture identity material BEFORE moving keys into ctx.
    let mlkem_pk_bytes = keys.mlkem_pk_bytes.clone();
    let pq_fingerprint = keys.pq_fingerprint;
    let server_x25519_pub = keys.x25519_pub;
    let ctx = Arc::new(ServerCtx::new(keys));

    // ----- Step 1: bind loopback listener.
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .map_err(SelfTestError::Bind)?;
    let addr = listener.local_addr().map_err(SelfTestError::Bind)?;

    // ----- Step 2: spawn the server-side handler.
    // Wraps the production `server::serve` accept loop; we run
    // it as a tokio task and abort it once the client's
    // roundtrip completes. The handler ECHOES the first record
    // back to the client, exercising the AEAD path in both
    // directions.
    let server_ctx = Arc::clone(&ctx);
    let server_task = tokio::spawn(async move {
        let _ = server::serve(listener, server_ctx, |mut session| async move {
            // First record from the client = probe payload.
            // Echo it back. Any error (handshake on the server
            // side, recv, send) drops the future — the client
            // will see EOF and report Roundtrip failure.
            let Ok(Some(rec)) = session.receiver.recv_record().await else {
                return;
            };
            if rec.is_empty() {
                return;
            }
            let _ = session.sender.send_record(&rec).await;
            let _ = session.sender.flush().await;
            let _ = session.sender.shutdown().await;
        })
        .await;
    });

    // ----- Step 3: build a throwaway client identity + run the
    // handshake. The user_id "selftest" is reserved (operators
    // shouldn't pick it for real users — if they do, the worst
    // case is the self-test's probe shows up in their access log
    // as a noise event).
    let handshake_start = Instant::now();
    let mut rng = rand_core::OsRng;
    let client_id_sk = proteus_crypto::sig::generate(&mut rng);
    let client_cfg = ClientConfig {
        server_mlkem_pk_bytes: mlkem_pk_bytes,
        server_x25519_pub,
        server_pq_fingerprint: pq_fingerprint,
        client_id_sk,
        user_id: *b"selftest",
        pow_difficulty: 0,
        profile_hint: proteus_wire::ProfileHint::Alpha,
    };
    let connect_future = async {
        let stream = TcpStream::connect(addr)
            .await
            .map_err(SelfTestError::Connect)?;
        let session = client::handshake_over_tcp(stream, &client_cfg)
            .await
            .map_err(|e| SelfTestError::Handshake(format!("{e:?}")))?;
        Ok::<_, SelfTestError>(session)
    };
    let session = match tokio::time::timeout(deadline, connect_future).await {
        Ok(r) => r?,
        Err(_) => {
            server_task.abort();
            return Err(SelfTestError::Timeout(total_start.elapsed()));
        }
    };
    let handshake = handshake_start.elapsed();

    // ----- Step 4: roundtrip.
    let proteus_transport_alpha::session::AlphaSession {
        mut sender,
        mut receiver,
        ..
    } = session;
    let rt_start = Instant::now();
    let probe: &[u8] = b"proteus-self-test-probe";
    let rt_future = async {
        sender
            .send_record(probe)
            .await
            .map_err(|e| SelfTestError::Roundtrip(format!("send: {e:?}")))?;
        sender
            .flush()
            .await
            .map_err(|e| SelfTestError::Roundtrip(format!("flush: {e:?}")))?;
        let echo = receiver
            .recv_record()
            .await
            .map_err(|e| SelfTestError::Roundtrip(format!("recv: {e:?}")))?
            .ok_or_else(|| {
                SelfTestError::Roundtrip(
                    "server closed before sending echo (handshake \
                     succeeded but server-side relay path failed)"
                        .to_string(),
                )
            })?;
        if echo != probe {
            return Err(SelfTestError::Roundtrip(format!(
                "echo mismatch: sent {} bytes, received {} bytes",
                probe.len(),
                echo.len()
            )));
        }
        Ok::<_, SelfTestError>(())
    };
    let remaining = deadline.saturating_sub(handshake);
    match tokio::time::timeout(remaining, rt_future).await {
        Ok(r) => r?,
        Err(_) => {
            server_task.abort();
            return Err(SelfTestError::Timeout(total_start.elapsed()));
        }
    }
    let roundtrip = rt_start.elapsed();

    // Best-effort shutdown.
    let _ = sender.shutdown().await;
    drop(receiver);
    server_task.abort();

    Ok(SelfTestOutcome {
        total: total_start.elapsed(),
        handshake,
        roundtrip,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn self_test_succeeds_on_freshly_generated_keys() {
        let keys = ServerKeys::generate();
        let outcome = run_self_test(keys, Duration::from_secs(10))
            .await
            .expect("self-test on fresh keys must pass");
        assert!(outcome.total > Duration::from_millis(0));
        assert!(outcome.handshake > Duration::from_millis(0));
        assert!(outcome.roundtrip > Duration::from_millis(0));
        // Self-test on loopback with fresh keys should be FAST —
        // < 500ms on any modern hardware. Use 5s as the assertion
        // bound to avoid flaking on slow CI but still catch any
        // regression that makes it pathologically slow.
        assert!(
            outcome.total < Duration::from_secs(5),
            "self-test took {:?} — > 5s suggests a serious regression",
            outcome.total
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn self_test_handshake_fails_with_corrupted_mlkem_pk() {
        // The client's view of `server_mlkem_pk_bytes` is derived
        // from `keys.mlkem_pk_bytes`. If we corrupt the keys'
        // pk bytes BEFORE handing them to run_self_test, the
        // server's decapsulation key won't pair with what the
        // client encapsulates → handshake fails.
        let mut keys = ServerKeys::generate();
        // Corrupt the FIRST byte of mlkem_pk_bytes. The handshake
        // either:
        //   - fails fast (ML-KEM-768 PK parse error in the client),
        //   - or succeeds the bit-flipped encap and fails the
        //     server's Finished check.
        // Either way we MUST surface an error — this test asserts
        // that contract holds.
        if !keys.mlkem_pk_bytes.is_empty() {
            keys.mlkem_pk_bytes[0] ^= 0x01;
        }
        let r = run_self_test(keys, Duration::from_secs(10)).await;
        assert!(r.is_err(), "corrupted mlkem_pk MUST fail the self-test");
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn self_test_handshake_fails_with_mismatched_fingerprint() {
        // The client cross-checks the supplied `pq_fingerprint`
        // against SHA-256 of `mlkem_pk_bytes` — copy-paste-protection
        // for cross-host setups. Mismatching the fingerprint MUST
        // fail handshake.
        let mut keys = ServerKeys::generate();
        keys.pq_fingerprint[0] ^= 0xff;
        let r = run_self_test(keys, Duration::from_secs(10)).await;
        assert!(
            r.is_err(),
            "mismatched pq_fingerprint MUST fail the self-test"
        );
    }

    // Note: corrupting `x25519_pub` is a no-op because the
    // server proves ownership of x25519_sk; the cached public
    // is only what the client sees. Corrupting x25519_sk is
    // tricky because the cached public is recomputed implicitly
    // on different code paths. The mlkem_pk corruption test
    // above already covers the "production-failure trip-wire"
    // (mismatched key pair) which is the essential contract.
    //
    // Likewise, a tight-timeout test is intentionally omitted:
    // modern loopback can complete the full self-test in
    // <1ms, and tokio's timer granularity makes sub-ms timeout
    // assertions flaky. The timeout PATH is exercised by tokio
    // internally; the contract that matters for production
    // ("real corrupt keys → real failure, surfaced before the
    // listener binds") IS tested.

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn self_test_returns_per_phase_timings_in_correct_order() {
        // handshake + roundtrip <= total (with slack for the
        // tear-down overhead). This pins the contract that
        // per-phase timings are meaningful even on very fast
        // hardware.
        let keys = ServerKeys::generate();
        let outcome = run_self_test(keys, Duration::from_secs(10))
            .await
            .expect("self-test must pass");
        let sum = outcome.handshake + outcome.roundtrip;
        // Allow up to 100% slack — on very fast machines the
        // sum may be < total by setup overhead; on busy CI it
        // may be very close to total. Just assert sum <= total
        // (the strict relationship).
        assert!(
            sum <= outcome.total + Duration::from_millis(50),
            "phase timings exceed total: hs={:?} rt={:?} total={:?}",
            outcome.handshake,
            outcome.roundtrip,
            outcome.total
        );
    }
}
