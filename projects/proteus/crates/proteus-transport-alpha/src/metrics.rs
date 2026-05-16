//! Per-session metrics. Cheap atomic counters that the server / client
//! can scrape for Prometheus-style exposition.

use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;

/// Per-session metrics. All counters are monotonically increasing.
#[derive(Default, Debug)]
pub struct SessionMetrics {
    pub tx_bytes: AtomicU64,
    pub rx_bytes: AtomicU64,
    pub tx_records: AtomicU64,
    pub rx_records: AtomicU64,
    pub aead_drops: AtomicU64,
    pub ratchets: AtomicU64,
    pub close_sent: AtomicU64,
    pub close_recv: AtomicU64,
}

impl SessionMetrics {
    /// Record an outgoing plaintext payload of `n` bytes.
    pub fn record_tx(&self, n: u64) {
        self.tx_bytes.fetch_add(n, Ordering::Relaxed);
        self.tx_records.fetch_add(1, Ordering::Relaxed);
    }

    /// Record an incoming plaintext payload of `n` bytes (after AEAD verify).
    pub fn record_rx(&self, n: u64) {
        self.rx_bytes.fetch_add(n, Ordering::Relaxed);
        self.rx_records.fetch_add(1, Ordering::Relaxed);
    }

    /// An AEAD record failed authentication and was silently dropped.
    pub fn record_aead_drop(&self) {
        self.aead_drops.fetch_add(1, Ordering::Relaxed);
    }

    /// A symmetric ratchet was performed (in either direction).
    pub fn record_ratchet(&self) {
        self.ratchets.fetch_add(1, Ordering::Relaxed);
    }

    /// A CLOSE record was sent.
    pub fn record_close_sent(&self) {
        self.close_sent.fetch_add(1, Ordering::Relaxed);
    }

    /// A CLOSE record was received and authenticated.
    pub fn record_close_recv(&self) {
        self.close_recv.fetch_add(1, Ordering::Relaxed);
    }

    /// Snapshot all counters into a plain struct.
    #[must_use]
    pub fn snapshot(&self) -> SessionMetricsSnapshot {
        SessionMetricsSnapshot {
            tx_bytes: self.tx_bytes.load(Ordering::Relaxed),
            rx_bytes: self.rx_bytes.load(Ordering::Relaxed),
            tx_records: self.tx_records.load(Ordering::Relaxed),
            rx_records: self.rx_records.load(Ordering::Relaxed),
            aead_drops: self.aead_drops.load(Ordering::Relaxed),
            ratchets: self.ratchets.load(Ordering::Relaxed),
            close_sent: self.close_sent.load(Ordering::Relaxed),
            close_recv: self.close_recv.load(Ordering::Relaxed),
        }
    }
}

/// RAII guard: increment `in_flight_sessions` on construct, decrement
/// on drop. Holds a reference to a session's [`SessionMetricsSnapshot`]
/// so the per-session totals are merged into the server-level counters
/// on drop, **even if the handler panics**.
///
/// Previously the binary did this with explicit `fetch_add` /
/// `fetch_sub` pairs around `relay::handle_session(...).await`. That
/// pattern leaks the gauge upward forever if the handler ever panics
/// (the decrement is unreachable). With a guard, the drop runs as
/// part of panic unwinding, so the counter stays honest.
pub struct InFlightGuard {
    server: Arc<ServerMetrics>,
    /// Snapshot taken at construction time. Merged into server totals
    /// on drop. None means "do not merge" (used by tests that don't
    /// want to mutate state).
    snapshot: Option<SessionMetricsSnapshot>,
}

impl InFlightGuard {
    /// Construct the guard. Increments `in_flight_sessions` immediately.
    pub fn enter(server: Arc<ServerMetrics>, snapshot: SessionMetricsSnapshot) -> Self {
        server.in_flight_sessions.fetch_add(1, Ordering::Relaxed);
        Self {
            server,
            snapshot: Some(snapshot),
        }
    }
}

impl Drop for InFlightGuard {
    fn drop(&mut self) {
        if let Some(snap) = self.snapshot.take() {
            self.server.merge_session(&snap);
        }
        self.server
            .in_flight_sessions
            .fetch_sub(1, Ordering::Relaxed);
    }
}

/// Immutable snapshot for export.
#[derive(Debug, Clone, Copy, Default)]
pub struct SessionMetricsSnapshot {
    pub tx_bytes: u64,
    pub rx_bytes: u64,
    pub tx_records: u64,
    pub rx_records: u64,
    pub aead_drops: u64,
    pub ratchets: u64,
    pub close_sent: u64,
    pub close_recv: u64,
}

/// Aggregate metrics across multiple sessions, e.g. on the server.
///
/// Also carries the **liveness/readiness flags** consumed by the
/// `/healthz` and `/readyz` HTTP probes. Liveness flips to `true` once
/// the accept loop has bound; readiness flips to `true` once the
/// server is willing to accept new traffic, and flips back to `false`
/// during graceful drain so load balancers stop sending it work.
#[derive(Debug)]
pub struct ServerMetrics {
    pub sessions_accepted: AtomicU64,
    pub handshakes_succeeded: AtomicU64,
    pub handshakes_failed: AtomicU64,
    pub handshake_timeouts: AtomicU64,
    pub rate_limited: AtomicU64,
    pub conn_limit_rejected: AtomicU64,
    pub firewall_denied: AtomicU64,
    pub cover_forwards: AtomicU64,
    pub total_tx_bytes: AtomicU64,
    pub total_rx_bytes: AtomicU64,
    pub total_aead_drops: AtomicU64,
    pub total_ratchets: AtomicU64,
    /// Sessions torn down by the relay's per-direction idle timeout.
    /// Distinct from `handshake_timeouts` (which fires during setup).
    pub session_idle_reaped: AtomicU64,
    /// In-flight session count (incremented on accept, decremented on
    /// session completion). Exported as a Prometheus gauge.
    pub in_flight_sessions: AtomicU64,
    /// `/healthz` flag — process is alive and event loop running.
    /// Set to `true` once the listener is bound; never flipped back.
    pub alive: AtomicBool,
    /// `/readyz` flag — server is willing to accept new traffic.
    /// Flipped to `false` on graceful shutdown so load balancers
    /// stop steering traffic before in-flight sessions complete.
    pub ready: AtomicBool,
}

impl Default for ServerMetrics {
    fn default() -> Self {
        Self {
            sessions_accepted: AtomicU64::new(0),
            handshakes_succeeded: AtomicU64::new(0),
            handshakes_failed: AtomicU64::new(0),
            handshake_timeouts: AtomicU64::new(0),
            rate_limited: AtomicU64::new(0),
            conn_limit_rejected: AtomicU64::new(0),
            firewall_denied: AtomicU64::new(0),
            cover_forwards: AtomicU64::new(0),
            total_tx_bytes: AtomicU64::new(0),
            total_rx_bytes: AtomicU64::new(0),
            total_aead_drops: AtomicU64::new(0),
            total_ratchets: AtomicU64::new(0),
            session_idle_reaped: AtomicU64::new(0),
            in_flight_sessions: AtomicU64::new(0),
            // Default to "not alive, not ready". The accept loop flips
            // alive→true once it binds; the operator flips ready→true
            // once they're satisfied the process has warmed up.
            alive: AtomicBool::new(false),
            ready: AtomicBool::new(false),
        }
    }
}

impl ServerMetrics {
    /// Merge a per-session snapshot into the server-level totals.
    pub fn merge_session(&self, snap: &SessionMetricsSnapshot) {
        self.total_tx_bytes
            .fetch_add(snap.tx_bytes, Ordering::Relaxed);
        self.total_rx_bytes
            .fetch_add(snap.rx_bytes, Ordering::Relaxed);
        self.total_aead_drops
            .fetch_add(snap.aead_drops, Ordering::Relaxed);
        self.total_ratchets
            .fetch_add(snap.ratchets, Ordering::Relaxed);
    }

    /// Emit Prometheus exposition format.
    #[must_use]
    pub fn prometheus(&self) -> String {
        let s = |c: &AtomicU64| c.load(Ordering::Relaxed);
        format!(
            "# HELP proteus_sessions_accepted_total Number of TCP connections accepted.\n\
             # TYPE proteus_sessions_accepted_total counter\n\
             proteus_sessions_accepted_total {}\n\
             # HELP proteus_handshakes_succeeded_total Successful Proteus handshakes.\n\
             # TYPE proteus_handshakes_succeeded_total counter\n\
             proteus_handshakes_succeeded_total {}\n\
             # HELP proteus_handshakes_failed_total Failed Proteus handshakes (forwarded to cover).\n\
             # TYPE proteus_handshakes_failed_total counter\n\
             proteus_handshakes_failed_total {}\n\
             # HELP proteus_handshake_timeouts_total Handshakes that exceeded the deadline (slowloris).\n\
             # TYPE proteus_handshake_timeouts_total counter\n\
             proteus_handshake_timeouts_total {}\n\
             # HELP proteus_rate_limited_total Connections rejected by per-IP rate limiter.\n\
             # TYPE proteus_rate_limited_total counter\n\
             proteus_rate_limited_total {}\n\
             # HELP proteus_conn_limit_rejected_total Connections rejected because max_connections was reached.\n\
             # TYPE proteus_conn_limit_rejected_total counter\n\
             proteus_conn_limit_rejected_total {}\n\
             # HELP proteus_firewall_denied_total Connections denied by CIDR firewall (allow/deny rules).\n\
             # TYPE proteus_firewall_denied_total counter\n\
             proteus_firewall_denied_total {}\n\
             # HELP proteus_cover_forwards_total Connections forwarded to the cover endpoint.\n\
             # TYPE proteus_cover_forwards_total counter\n\
             proteus_cover_forwards_total {}\n\
             # HELP proteus_tx_bytes_total Plaintext bytes sent (server→client).\n\
             # TYPE proteus_tx_bytes_total counter\n\
             proteus_tx_bytes_total {}\n\
             # HELP proteus_rx_bytes_total Plaintext bytes received (client→server).\n\
             # TYPE proteus_rx_bytes_total counter\n\
             proteus_rx_bytes_total {}\n\
             # HELP proteus_aead_drops_total AEAD-failed records silently dropped.\n\
             # TYPE proteus_aead_drops_total counter\n\
             proteus_aead_drops_total {}\n\
             # HELP proteus_ratchets_total Key ratchets performed.\n\
             # TYPE proteus_ratchets_total counter\n\
             proteus_ratchets_total {}\n\
             # HELP proteus_session_idle_reaped_total Sessions torn down by the per-direction idle timeout.\n\
             # TYPE proteus_session_idle_reaped_total counter\n\
             proteus_session_idle_reaped_total {}\n\
             # HELP proteus_in_flight_sessions In-flight sessions (gauge).\n\
             # TYPE proteus_in_flight_sessions gauge\n\
             proteus_in_flight_sessions {}\n\
             # HELP proteus_up 1 if the server is alive, 0 otherwise.\n\
             # TYPE proteus_up gauge\n\
             proteus_up {}\n\
             # HELP proteus_ready 1 if the server is accepting new traffic, 0 otherwise.\n\
             # TYPE proteus_ready gauge\n\
             proteus_ready {}\n",
            s(&self.sessions_accepted),
            s(&self.handshakes_succeeded),
            s(&self.handshakes_failed),
            s(&self.handshake_timeouts),
            s(&self.rate_limited),
            s(&self.conn_limit_rejected),
            s(&self.firewall_denied),
            s(&self.cover_forwards),
            s(&self.total_tx_bytes),
            s(&self.total_rx_bytes),
            s(&self.total_aead_drops),
            s(&self.total_ratchets),
            s(&self.session_idle_reaped),
            s(&self.in_flight_sessions),
            u64::from(self.alive.load(Ordering::Relaxed)),
            u64::from(self.ready.load(Ordering::Relaxed)),
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn session_counters_increment() {
        let m = SessionMetrics::default();
        m.record_tx(100);
        m.record_tx(50);
        m.record_rx(200);
        m.record_aead_drop();
        m.record_ratchet();
        let snap = m.snapshot();
        assert_eq!(snap.tx_bytes, 150);
        assert_eq!(snap.tx_records, 2);
        assert_eq!(snap.rx_bytes, 200);
        assert_eq!(snap.rx_records, 1);
        assert_eq!(snap.aead_drops, 1);
        assert_eq!(snap.ratchets, 1);
    }

    #[test]
    fn server_prometheus_has_expected_lines() {
        let m = ServerMetrics::default();
        m.sessions_accepted.fetch_add(7, Ordering::Relaxed);
        m.handshakes_succeeded.fetch_add(5, Ordering::Relaxed);
        let text = m.prometheus();
        assert!(text.contains("proteus_sessions_accepted_total 7"));
        assert!(text.contains("proteus_handshakes_succeeded_total 5"));
        assert!(text.contains("# TYPE proteus_handshakes_failed_total counter"));
    }

    #[test]
    fn merge_session_aggregates() {
        let server = ServerMetrics::default();
        let session = SessionMetricsSnapshot {
            tx_bytes: 10,
            rx_bytes: 20,
            tx_records: 1,
            rx_records: 1,
            aead_drops: 0,
            ratchets: 0,
            close_sent: 0,
            close_recv: 0,
        };
        server.merge_session(&session);
        server.merge_session(&session);
        assert_eq!(server.total_tx_bytes.load(Ordering::Relaxed), 20);
        assert_eq!(server.total_rx_bytes.load(Ordering::Relaxed), 40);
    }

    #[test]
    fn in_flight_guard_normal_drop_decrements_and_merges() {
        let server = Arc::new(ServerMetrics::default());
        let snap = SessionMetricsSnapshot {
            tx_bytes: 7,
            rx_bytes: 11,
            ..SessionMetricsSnapshot::default()
        };
        {
            let _guard = InFlightGuard::enter(Arc::clone(&server), snap);
            assert_eq!(server.in_flight_sessions.load(Ordering::Relaxed), 1);
        }
        assert_eq!(server.in_flight_sessions.load(Ordering::Relaxed), 0);
        assert_eq!(server.total_tx_bytes.load(Ordering::Relaxed), 7);
        assert_eq!(server.total_rx_bytes.load(Ordering::Relaxed), 11);
    }

    #[test]
    fn in_flight_guard_decrements_on_panic_unwind() {
        // Spawn a closure that panics while holding the guard. Drop
        // runs as part of unwinding → the counter must end at 0.
        let server = Arc::new(ServerMetrics::default());
        let server_clone = Arc::clone(&server);
        let r = std::panic::catch_unwind(std::panic::AssertUnwindSafe(move || {
            let _guard =
                InFlightGuard::enter(Arc::clone(&server_clone), SessionMetricsSnapshot::default());
            assert_eq!(server_clone.in_flight_sessions.load(Ordering::Relaxed), 1);
            panic!("simulated handler panic");
        }));
        assert!(r.is_err(), "panic should have propagated");
        assert_eq!(
            server.in_flight_sessions.load(Ordering::Relaxed),
            0,
            "InFlightGuard MUST decrement even when the handler panics"
        );
    }

    #[test]
    fn in_flight_guard_concurrent_enter_and_drop() {
        // Stress: spawn 64 threads that each construct + drop a guard;
        // the gauge must wind back to 0.
        let server = Arc::new(ServerMetrics::default());
        let mut handles = Vec::new();
        for _ in 0..64 {
            let s = Arc::clone(&server);
            handles.push(std::thread::spawn(move || {
                let _g = InFlightGuard::enter(s, SessionMetricsSnapshot::default());
                std::thread::yield_now();
            }));
        }
        for h in handles {
            h.join().unwrap();
        }
        assert_eq!(server.in_flight_sessions.load(Ordering::Relaxed), 0);
    }
}
