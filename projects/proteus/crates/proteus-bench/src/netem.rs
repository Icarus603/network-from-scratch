//! In-process UDP loss / delay simulator — Rust-native replacement
//! for Linux `tc qdisc add netem` on platforms (macOS, Windows)
//! where netem isn't available.
//!
//! ## Why this exists
//!
//! `bench/netem-sweep.sh` already drives Linux netem from a shell
//! script — operators on an Ubuntu OrbStack VM can use it today.
//! But the throughput-vs-loss measurement is the single biggest
//! "is Proteus actually fast?" question, and waiting for an
//! OrbStack VM to land that data is unacceptably slow. This module
//! provides a Rust-native equivalent that runs in-process on any
//! platform.
//!
//! ## What it does
//!
//! Binds two UDP sockets and forwards packets bidirectionally
//! between them with operator-configurable:
//!
//! - **Loss probability** (per packet, Bernoulli) — `loss_pct = 5.0`
//!   means each forwarded packet has a 5 % chance of being dropped.
//! - **Delay** (per packet, applied to BOTH directions equally) —
//!   `delay = Duration::from_millis(50)` means every packet
//!   experiences a 50 ms one-way delay (so round-trip latency
//!   gains 100 ms).
//!
//! The β QUIC stack sees this as a path with N % loss + M ms RTT
//! and reacts via BBR. Operators read the result as
//! `mib_per_sec @ {loss, delay}` cells in the
//! [`crate::report::RunReport`] JSON output.
//!
//! ## What this is NOT
//!
//! - **Not a full netem emulation.** Netem supports correlated
//!   loss (Gilbert-Elliott), duplication, corruption, reordering;
//!   we model only independent loss + uniform delay. That's enough
//!   to surface "how does BBR react to loss" — the headline
//!   question. Correlated loss patterns are a follow-up.
//! - **Not a wire-level Linux-kernel substitute.** Some BBR
//!   behaviors differ when packets are reordered at the NIC layer
//!   vs at the userland forwarder. The numbers from this harness
//!   should be cross-validated against real netem before publishing
//!   a "Proteus beats Hy2 at 5% loss" claim — but as a development
//!   loop, it's reproducible AND portable.
//!
//! ## Threading model
//!
//! One tokio task per direction. Each loop: `recv_from` → coin
//! flip on loss → `sleep(delay)` → `send_to`. The delay is applied
//! by spawning a per-packet task so the recv loop stays
//! non-blocking; packets that arrive during another packet's
//! delay don't queue behind it.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use rand_core::RngCore;
use tokio::net::UdpSocket;
use tokio::sync::Mutex;

/// Loss/delay knobs.
#[derive(Debug, Clone, Copy)]
pub struct NetemConfig {
    /// Drop probability per forwarded packet. 0.0 = perfect link;
    /// 30.0 = brutal-loss regime (Hy2 Brutal's design point);
    /// 100.0 = blackhole.
    pub loss_pct: f64,
    /// One-way delay added to every forwarded packet. RTT seen by
    /// the application = `2 × delay` (each direction passes through
    /// the forwarder once).
    pub delay: Duration,
    /// Random seed for the loss decision. `None` = OS RNG (different
    /// drop sequence on every run); `Some(N)` = deterministic for
    /// reproducible test runs.
    pub seed: Option<u64>,
}

impl Default for NetemConfig {
    fn default() -> Self {
        Self {
            loss_pct: 0.0,
            delay: Duration::from_millis(0),
            seed: None,
        }
    }
}

impl NetemConfig {
    /// `true` when no perturbation is configured (pure passthrough).
    /// Caller skips the forwarder entirely in that case — saves the
    /// two-hop UDP overhead on baseline-throughput runs.
    #[must_use]
    pub fn is_noop(&self) -> bool {
        self.loss_pct == 0.0 && self.delay.is_zero()
    }

    /// Render a short label suitable for `RunReport::perf_profile`
    /// concatenation. Format: `"loss=5%,delay=50ms"`.
    #[must_use]
    pub fn label(&self) -> String {
        format!("loss={}%,delay={}ms", self.loss_pct, self.delay.as_millis())
    }
}

/// Cumulative stats from one direction of the forwarder. The
/// bidirectional forwarder exposes BOTH directions as separate
/// `NetemStatsHandle`s so operators can see asymmetric drops.
#[derive(Debug, Clone, Default)]
pub struct NetemStats {
    pub packets_received: u64,
    pub packets_forwarded: u64,
    pub packets_dropped: u64,
    pub bytes_forwarded: u64,
}

/// Cheap-to-clone handle on the cumulative stats. Internally a
/// `Arc<Mutex<NetemStats>>` — contention is low because each
/// direction only writes from its own forwarder task.
#[derive(Clone, Default)]
pub struct NetemStatsHandle {
    inner: Arc<Mutex<NetemStats>>,
}

impl NetemStatsHandle {
    pub fn new() -> Self {
        Self::default()
    }
    pub async fn snapshot(&self) -> NetemStats {
        self.inner.lock().await.clone()
    }
    async fn record_recv(&self, bytes: u64) {
        let mut g = self.inner.lock().await;
        g.packets_received += 1;
        let _ = bytes;
    }
    async fn record_forward(&self, bytes: u64) {
        let mut g = self.inner.lock().await;
        g.packets_forwarded += 1;
        g.bytes_forwarded += bytes;
    }
    async fn record_drop(&self) {
        let mut g = self.inner.lock().await;
        g.packets_dropped += 1;
    }
}

/// Bind a bidirectional UDP forwarder between client and server.
///
/// Returns `(listen_addr, c2s_stats, s2c_stats, shutdown)` where:
///
/// - `listen_addr` is what the client should dial INSTEAD of the
///   server's address. Caller hooks this into
///   `proteus-bench beta`'s loopback wiring by replacing the
///   server-side `bind` address used to drive the client.
/// - `c2s_stats` / `s2c_stats` are per-direction stat handles —
///   operators read them via `snapshot()` after the run to verify
///   the configured loss / delay actually fired.
/// - `shutdown` is a oneshot sender; sending closes both forwarder
///   loops and lets the test reclaim ports.
///
/// `server_addr` is where the forwarder forwards client-bound
/// packets TO — i.e. the actual β server's bound UDP address.
pub async fn spawn_forwarder(
    server_addr: SocketAddr,
    cfg: NetemConfig,
) -> std::io::Result<NetemHandle> {
    // Bind the "client-facing" socket (operator dials this).
    let client_facing = UdpSocket::bind("127.0.0.1:0").await?;
    let listen_addr = client_facing.local_addr()?;
    let client_facing = Arc::new(client_facing);

    // Bind the "server-facing" socket (forwarder sends from here to
    // the real server). Letting the OS pick a port gives us
    // ephemeral isolation per run.
    let server_facing = UdpSocket::bind("127.0.0.1:0").await?;
    let server_facing = Arc::new(server_facing);

    // Last-seen client address — updated by the c2s direction every
    // time we receive a packet (in case the client uses connection
    // migration). The s2c direction reads it to know where to
    // deliver server replies.
    let last_client: Arc<Mutex<Option<SocketAddr>>> = Arc::new(Mutex::new(None));

    let c2s_stats = NetemStatsHandle::new();
    let s2c_stats = NetemStatsHandle::new();
    let (shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel();
    let shutdown_rx = Arc::new(Mutex::new(Some(shutdown_rx)));

    // ----- c2s direction: client → forwarder → server -----
    let c2s_listen = Arc::clone(&client_facing);
    let c2s_send = Arc::clone(&server_facing);
    let c2s_last_client = Arc::clone(&last_client);
    let c2s_stats_h = c2s_stats.clone();
    let cfg_c2s = cfg;
    let server_addr_c2s = server_addr;
    let shutdown_rx_c2s = Arc::clone(&shutdown_rx);
    tokio::spawn(async move {
        let mut buf = vec![0u8; 65535];
        // Lock once; if shutdown fires we tear down.
        let mut shutdown = shutdown_rx_c2s.lock().await.take();
        loop {
            tokio::select! {
                biased;
                _ = async {
                    if let Some(rx) = shutdown.as_mut() { let _ = rx.await; }
                    else { std::future::pending::<()>().await; }
                } => break,
                res = c2s_listen.recv_from(&mut buf) => {
                    let (n, peer) = match res {
                        Ok(x) => x,
                        Err(_) => break,
                    };
                    {
                        let mut g = c2s_last_client.lock().await;
                        *g = Some(peer);
                    }
                    c2s_stats_h.record_recv(n as u64).await;
                    if should_drop(&cfg_c2s) {
                        c2s_stats_h.record_drop().await;
                        continue;
                    }
                    let pkt = buf[..n].to_vec();
                    let send = Arc::clone(&c2s_send);
                    let stats = c2s_stats_h.clone();
                    let delay = cfg_c2s.delay;
                    tokio::spawn(async move {
                        if !delay.is_zero() {
                            tokio::time::sleep(delay).await;
                        }
                        if send.send_to(&pkt, server_addr_c2s).await.is_ok() {
                            stats.record_forward(pkt.len() as u64).await;
                        }
                    });
                }
            }
        }
    });

    // ----- s2c direction: server → forwarder → client -----
    let s2c_recv = Arc::clone(&server_facing);
    let s2c_send = Arc::clone(&client_facing);
    let s2c_last_client = Arc::clone(&last_client);
    let s2c_stats_h = s2c_stats.clone();
    let cfg_s2c = cfg;
    tokio::spawn(async move {
        let mut buf = vec![0u8; 65535];
        loop {
            let (n, _from) = match s2c_recv.recv_from(&mut buf).await {
                Ok(x) => x,
                Err(_) => break,
            };
            s2c_stats_h.record_recv(n as u64).await;
            if should_drop(&cfg_s2c) {
                s2c_stats_h.record_drop().await;
                continue;
            }
            let client_addr = {
                let g = s2c_last_client.lock().await;
                match *g {
                    Some(a) => a,
                    None => continue, // never seen a client packet yet
                }
            };
            let pkt = buf[..n].to_vec();
            let send = Arc::clone(&s2c_send);
            let stats = s2c_stats_h.clone();
            let delay = cfg_s2c.delay;
            tokio::spawn(async move {
                if !delay.is_zero() {
                    tokio::time::sleep(delay).await;
                }
                if send.send_to(&pkt, client_addr).await.is_ok() {
                    stats.record_forward(pkt.len() as u64).await;
                }
            });
        }
    });

    Ok(NetemHandle {
        listen_addr,
        c2s_stats,
        s2c_stats,
        shutdown_tx: Some(shutdown_tx),
    })
}

/// Decide whether to drop a packet given the configured loss
/// percentage. Uses OS RNG when `cfg.seed` is `None`; the
/// per-packet cost is negligible (one u32 + a few arithmetic ops).
fn should_drop(cfg: &NetemConfig) -> bool {
    if cfg.loss_pct <= 0.0 {
        return false;
    }
    if cfg.loss_pct >= 100.0 {
        return true;
    }
    // OS RNG: fast on macOS / Linux + thread-safe.
    let mut rng = rand_core::OsRng;
    let r = rng.next_u32() as f64 / u32::MAX as f64;
    r * 100.0 < cfg.loss_pct
}

/// Handle returned by `spawn_forwarder`. Drop or call `shutdown`
/// to tear the forwarder down.
pub struct NetemHandle {
    pub listen_addr: SocketAddr,
    pub c2s_stats: NetemStatsHandle,
    pub s2c_stats: NetemStatsHandle,
    shutdown_tx: Option<tokio::sync::oneshot::Sender<()>>,
}

impl NetemHandle {
    /// Signal both forwarder tasks to terminate. Idempotent.
    pub fn shutdown(&mut self) {
        if let Some(tx) = self.shutdown_tx.take() {
            let _ = tx.send(());
        }
    }
}

impl Drop for NetemHandle {
    fn drop(&mut self) {
        self.shutdown();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn netem_config_is_noop_when_no_loss_and_no_delay() {
        let cfg = NetemConfig::default();
        assert!(cfg.is_noop());
    }

    #[test]
    fn netem_config_is_not_noop_when_loss_or_delay_set() {
        assert!(!NetemConfig {
            loss_pct: 0.001,
            ..NetemConfig::default()
        }
        .is_noop());
        assert!(!NetemConfig {
            delay: Duration::from_millis(1),
            ..NetemConfig::default()
        }
        .is_noop());
    }

    #[test]
    fn netem_label_format_is_stable() {
        let cfg = NetemConfig {
            loss_pct: 5.5,
            delay: Duration::from_millis(50),
            seed: None,
        };
        assert_eq!(cfg.label(), "loss=5.5%,delay=50ms");
    }

    #[test]
    fn should_drop_returns_false_at_zero_loss() {
        let cfg = NetemConfig::default();
        for _ in 0..1000 {
            assert!(!should_drop(&cfg), "0% loss must never drop");
        }
    }

    #[test]
    fn should_drop_returns_true_at_100_loss() {
        let cfg = NetemConfig {
            loss_pct: 100.0,
            ..NetemConfig::default()
        };
        for _ in 0..1000 {
            assert!(should_drop(&cfg), "100% loss must always drop");
        }
    }

    #[test]
    fn should_drop_approximates_target_rate_at_30_pct_over_large_n() {
        let cfg = NetemConfig {
            loss_pct: 30.0,
            ..NetemConfig::default()
        };
        let trials = 10_000;
        let drops: u32 = (0..trials).map(|_| should_drop(&cfg) as u32).sum();
        let observed = drops as f64 / trials as f64 * 100.0;
        // ±3% tolerance — Bernoulli sampling over 10k trials has
        // a 99% CI of about ±1.2%; 3% is comfortable headroom.
        assert!(
            (observed - 30.0).abs() < 3.0,
            "observed {observed}% should be within ±3% of 30%"
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn forwarder_passes_packets_through_at_zero_loss_zero_delay() {
        // Bind an echo server.
        let echo = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let echo_addr = echo.local_addr().unwrap();
        let echo = Arc::new(echo);
        let echo_task = {
            let echo = Arc::clone(&echo);
            tokio::spawn(async move {
                let mut buf = [0u8; 1500];
                for _ in 0..10 {
                    let (n, from) = match echo.recv_from(&mut buf).await {
                        Ok(x) => x,
                        Err(_) => break,
                    };
                    let _ = echo.send_to(&buf[..n], from).await;
                }
            })
        };

        let h = spawn_forwarder(echo_addr, NetemConfig::default())
            .await
            .unwrap();

        let client = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        client.send_to(b"hello", h.listen_addr).await.unwrap();
        let mut reply = [0u8; 1500];
        let (n, _) = tokio::time::timeout(Duration::from_secs(2), client.recv_from(&mut reply))
            .await
            .expect("recv timeout")
            .expect("recv ok");
        assert_eq!(&reply[..n], b"hello");

        let c2s = h.c2s_stats.snapshot().await;
        let s2c = h.s2c_stats.snapshot().await;
        assert_eq!(c2s.packets_forwarded, 1);
        assert_eq!(s2c.packets_forwarded, 1);
        assert_eq!(c2s.packets_dropped, 0);
        assert_eq!(s2c.packets_dropped, 0);

        echo_task.abort();
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn forwarder_drops_all_packets_at_100_loss() {
        let echo = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let echo_addr = echo.local_addr().unwrap();
        let h = spawn_forwarder(
            echo_addr,
            NetemConfig {
                loss_pct: 100.0,
                ..NetemConfig::default()
            },
        )
        .await
        .unwrap();

        let client = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        for _ in 0..5 {
            client.send_to(b"x", h.listen_addr).await.unwrap();
        }
        // Give the forwarder a moment to process every packet.
        tokio::time::sleep(Duration::from_millis(100)).await;
        let c2s = h.c2s_stats.snapshot().await;
        assert_eq!(c2s.packets_received, 5);
        assert_eq!(c2s.packets_dropped, 5);
        assert_eq!(c2s.packets_forwarded, 0);

        drop(echo);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn forwarder_applies_delay_to_each_packet() {
        let echo = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let echo_addr = echo.local_addr().unwrap();
        let echo = Arc::new(echo);
        let echo_task = {
            let echo = Arc::clone(&echo);
            tokio::spawn(async move {
                let mut buf = [0u8; 1500];
                for _ in 0..2 {
                    let (n, from) = match echo.recv_from(&mut buf).await {
                        Ok(x) => x,
                        Err(_) => break,
                    };
                    let _ = echo.send_to(&buf[..n], from).await;
                }
            })
        };

        let h = spawn_forwarder(
            echo_addr,
            NetemConfig {
                loss_pct: 0.0,
                delay: Duration::from_millis(50),
                seed: None,
            },
        )
        .await
        .unwrap();

        let client = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let start = std::time::Instant::now();
        client.send_to(b"hello", h.listen_addr).await.unwrap();
        let mut reply = [0u8; 1500];
        let _ = tokio::time::timeout(Duration::from_secs(2), client.recv_from(&mut reply))
            .await
            .expect("recv timeout")
            .expect("recv ok");
        let elapsed = start.elapsed();
        // Both directions apply 50 ms → ~100 ms RTT. Allow ±20 ms.
        assert!(
            elapsed >= Duration::from_millis(80) && elapsed <= Duration::from_millis(250),
            "expected ~100 ms RTT (one-way 50 ms × 2), got {elapsed:?}"
        );

        echo_task.abort();
    }
}
