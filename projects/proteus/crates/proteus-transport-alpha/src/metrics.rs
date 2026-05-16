//! Per-session metrics. Cheap atomic counters that the server / client
//! can scrape for Prometheus-style exposition.

use std::sync::atomic::{AtomicU64, Ordering};

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
#[derive(Default, Debug)]
pub struct ServerMetrics {
    pub sessions_accepted: AtomicU64,
    pub handshakes_succeeded: AtomicU64,
    pub handshakes_failed: AtomicU64,
    pub handshake_timeouts: AtomicU64,
    pub rate_limited: AtomicU64,
    pub cover_forwards: AtomicU64,
    pub total_tx_bytes: AtomicU64,
    pub total_rx_bytes: AtomicU64,
    pub total_aead_drops: AtomicU64,
    pub total_ratchets: AtomicU64,
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
             proteus_ratchets_total {}\n",
            s(&self.sessions_accepted),
            s(&self.handshakes_succeeded),
            s(&self.handshakes_failed),
            s(&self.handshake_timeouts),
            s(&self.rate_limited),
            s(&self.cover_forwards),
            s(&self.total_tx_bytes),
            s(&self.total_rx_bytes),
            s(&self.total_aead_drops),
            s(&self.total_ratchets),
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
}
