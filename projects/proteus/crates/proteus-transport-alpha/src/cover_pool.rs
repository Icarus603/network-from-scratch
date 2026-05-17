//! Cover-endpoint pool with per-source-IP affinity routing.
//!
//! ## Why this exists (2026 GFW threat-intel main line 4)
//!
//! The single-`cover_endpoint` configuration shipped today gives an
//! operator one URL to splice auth-failed connections to (e.g.
//! `www.cloudflare.com:443`). That defeats *request-layer* active
//! probing — a single probe attempt sees a real HTTPS response from
//! Cloudflare and walks away — but leaves Proteus exposed to
//! *time-series* active probing: a Tiangou-class adversary that
//! sends repeated probe ClientHellos to the same Proteus IP over
//! hours will see the same cover URL replied to every time, which
//! is itself a distinguisher from "real cover-server's actual
//! traffic distribution".
//!
//! ## Design choice: affinity routing, not pure round-robin
//!
//! Naive pool design: round-robin or random across the N URLs. This
//! has a worse failure mode than the single-cover case:
//!
//!   - Single observer (one VP), single src IP, many probes → sees
//!     ROTATING cover URLs. No real cover server changes its
//!     destination URL between back-to-back requests. The rotation
//!     itself is a fingerprint.
//!
//! Affinity-routing design: hash `peer_ip` consistently into the
//! pool. From any single observer's perspective:
//!
//!   - The observer's own probes always hit the SAME cover URL —
//!     looks identical to the single-cover case.
//!   - The observer cannot see what other src IPs receive — they're
//!     not on the wire from their POV.
//!
//! The Tiangou cross-deployment shared-blocklist threat changes the
//! calculus slightly: if Geedge customers in two different countries
//! probe the same Proteus IP and cross-reference results, they see
//! two different cover URLs and can infer pooling. That's a real
//! capability worth defending against — but it requires two
//! coordinated observers, which is a strictly weaker adversary class
//! than "the server keeps spitting different URLs to me". We accept
//! that residual exposure as the price of defeating the more common
//! time-series probe pattern.
//!
//! ## Why /24 affinity, not full /32
//!
//! Hashing on the full IPv4 /32 (or /128 for IPv6) means a single
//! attacker behind CGNAT effectively gets a free re-pick on every
//! NAT rebinding event (typically minutes-to-hours). Hashing on the
//! /24 (IPv4) or /48 (IPv6) collapses an entire small-network
//! origin to one cover URL — the adversary cannot escape the
//! affinity by rotating IPs within their NAT or their hosting
//! provider's /24. This costs nothing on the legitimate side because
//! a real user's IP is stable within their NAT's external block.

use std::collections::hash_map::DefaultHasher;
use std::hash::{Hash, Hasher};
use std::net::{IpAddr, SocketAddr};

/// A pool of cover endpoints with deterministic per-source-IP affinity.
///
/// Construction options:
/// - `CoverEndpointPool::single(endpoint)` — single-endpoint mode,
///   identical to the pre-pool behavior. Every source IP routes to
///   the same endpoint.
/// - `CoverEndpointPool::new(vec_of_endpoints)` — N-endpoint pool;
///   each source IP's /24 (v4) or /48 (v6) prefix consistently hashes
///   to one endpoint.
///
/// The pool is intentionally immutable post-construction. Operators
/// who want to rotate endpoints over time do so by reloading the
/// server config (SIGHUP) — not by mutating the pool from inside.
#[derive(Debug, Clone)]
pub struct CoverEndpointPool {
    endpoints: Vec<String>,
}

impl CoverEndpointPool {
    /// Construct a pool from a list of `host:port` endpoint strings.
    /// Returns `None` if the list is empty; the server's startup
    /// surface treats `None` cover as "drop the connection silently"
    /// per the existing semantics.
    #[must_use]
    pub fn new(endpoints: Vec<String>) -> Option<Self> {
        if endpoints.is_empty() {
            return None;
        }
        Some(Self { endpoints })
    }

    /// Single-endpoint pool — exactly mirrors the pre-pool behavior.
    /// Provided for backward-compat with `ServerCtx::with_cover` so
    /// existing operators upgrading don't have to touch their YAML.
    #[must_use]
    pub fn single(endpoint: String) -> Self {
        Self {
            endpoints: vec![endpoint],
        }
    }

    /// Number of endpoints in the pool. A pool of size 1 behaves
    /// identically to single-endpoint mode (the hash is moot when the
    /// table only has one bucket).
    #[must_use]
    pub fn len(&self) -> usize {
        self.endpoints.len()
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.endpoints.is_empty()
    }

    /// Borrow the underlying endpoint list (for diagnostic / metrics
    /// surfaces; do NOT use this for actual routing — call
    /// `select_for` instead so the affinity policy is enforced).
    #[must_use]
    pub fn endpoints(&self) -> &[String] {
        &self.endpoints
    }

    /// Select a cover endpoint for the given peer address, applying
    /// per-source-IP /24 (v4) or /48 (v6) affinity.
    ///
    /// Returns a `String` (clone of the endpoint) because the cover-
    /// forward path is asynchronous and may outlive the pool's borrow
    /// lifetime — the cost is one short string allocation per
    /// cover-forward, dominated by the TCP dial that follows.
    #[must_use]
    pub fn select_for(&self, peer: &SocketAddr) -> String {
        if self.endpoints.len() == 1 {
            return self.endpoints[0].clone();
        }
        let key = affinity_key(peer.ip());
        let mut h = DefaultHasher::new();
        key.hash(&mut h);
        let idx = (h.finish() as usize) % self.endpoints.len();
        self.endpoints[idx].clone()
    }

    /// Select the canonical endpoint when no peer address is
    /// available (e.g. callers that lost the address before reaching
    /// the cover-forward branch).
    ///
    /// Uses index 0 — NOT a random pick, NOT round-robin. The
    /// rationale matches `select_for`'s affinity discipline: a
    /// deterministic fallback is observable but consistent; a random
    /// fallback would itself be a rotation signal.
    #[must_use]
    pub fn select_canonical(&self) -> String {
        self.endpoints[0].clone()
    }
}

/// Compute the affinity key for a source IP — a /24 prefix for v4,
/// a /48 prefix for v6. The key is what we hash into the bucket
/// table. See module doc for why we collapse below the full address.
fn affinity_key(ip: IpAddr) -> Vec<u8> {
    match ip {
        IpAddr::V4(v4) => v4.octets()[..3].to_vec(),
        IpAddr::V6(v6) => v6.octets()[..6].to_vec(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    fn sa4(ip: [u8; 4], port: u16) -> SocketAddr {
        SocketAddr::new(IpAddr::V4(Ipv4Addr::new(ip[0], ip[1], ip[2], ip[3])), port)
    }

    #[test]
    fn empty_pool_is_none() {
        assert!(CoverEndpointPool::new(Vec::new()).is_none());
    }

    #[test]
    fn single_pool_always_returns_the_endpoint() {
        let pool = CoverEndpointPool::single("www.example.com:443".into());
        assert_eq!(pool.len(), 1);
        let peer = sa4([1, 2, 3, 4], 12345);
        assert_eq!(pool.select_for(&peer), "www.example.com:443");
    }

    #[test]
    fn multi_pool_selects_consistently_for_same_peer_ip() {
        let pool = CoverEndpointPool::new(vec![
            "a.example.com:443".into(),
            "b.example.com:443".into(),
            "c.example.com:443".into(),
            "d.example.com:443".into(),
        ])
        .unwrap();
        let peer = sa4([198, 51, 100, 42], 12345);
        let first = pool.select_for(&peer);
        for _ in 0..10 {
            assert_eq!(pool.select_for(&peer), first);
        }
    }

    #[test]
    fn multi_pool_collapses_within_same_slash24() {
        // 198.51.100.{1, 2, 3, 254} all map to the same /24 (198.51.100.x)
        // and so MUST receive the same cover endpoint. Defeats
        // "rotate src IP within my /24 to escape affinity".
        let pool = CoverEndpointPool::new(vec![
            "a.example.com:443".into(),
            "b.example.com:443".into(),
            "c.example.com:443".into(),
            "d.example.com:443".into(),
        ])
        .unwrap();
        let p1 = sa4([198, 51, 100, 1], 1);
        let p254 = sa4([198, 51, 100, 254], 65535);
        assert_eq!(pool.select_for(&p1), pool.select_for(&p254));
    }

    #[test]
    fn multi_pool_distributes_across_different_slash24s() {
        // Different /24s should not all collapse to the same bucket.
        // We sweep 256 different /24s and assert ≥ 2 distinct cover
        // URLs are picked (a stronger assertion would be uniformity,
        // but DefaultHasher's distribution quality is not part of
        // our threat model — we only need "not constant").
        let pool = CoverEndpointPool::new(vec![
            "a.example.com:443".into(),
            "b.example.com:443".into(),
            "c.example.com:443".into(),
            "d.example.com:443".into(),
        ])
        .unwrap();
        let mut seen = std::collections::HashSet::new();
        for octet in 0..=255u8 {
            let peer = sa4([10, 0, octet, 1], 12345);
            seen.insert(pool.select_for(&peer));
        }
        assert!(
            seen.len() >= 2,
            "pool of size 4 hashed only into {} distinct buckets across 256 \
             /24s — distribution is suspicious",
            seen.len(),
        );
    }

    #[test]
    fn ipv6_affinity_collapses_within_same_slash48() {
        let pool = CoverEndpointPool::new(vec![
            "a.example.com:443".into(),
            "b.example.com:443".into(),
            "c.example.com:443".into(),
        ])
        .unwrap();
        let p1: SocketAddr = "[2001:db8:abcd::1]:443".parse().unwrap();
        let p2: SocketAddr = "[2001:db8:abcd:beef::99]:443".parse().unwrap();
        assert_eq!(pool.select_for(&p1), pool.select_for(&p2));

        // A different /48 may or may not pick a different bucket
        // (modulo coincidence). What MUST hold is that the choice
        // is independent — repeat for stability.
        let p3: SocketAddr = "[2001:db8:9999::1]:443".parse().unwrap();
        let pick3 = pool.select_for(&p3);
        for _ in 0..10 {
            assert_eq!(pool.select_for(&p3), pick3);
        }
    }

    #[test]
    fn canonical_fallback_picks_first_entry_deterministically() {
        let pool = CoverEndpointPool::new(vec![
            "first.example.com:443".into(),
            "second.example.com:443".into(),
        ])
        .unwrap();
        assert_eq!(pool.select_canonical(), "first.example.com:443");
        // Repeat — must be deterministic (no random pick).
        assert_eq!(pool.select_canonical(), "first.example.com:443");
    }

    /// Anti-rotation regression: probing the same Proteus IP from
    /// the same src IP across N probe rounds MUST receive the same
    /// cover URL every round. If this ever flakes, the affinity
    /// policy regressed and the time-series-probing defense broke.
    #[test]
    fn anti_rotation_same_peer_same_cover_across_many_probes() {
        let pool = CoverEndpointPool::new(vec![
            "a.example.com:443".into(),
            "b.example.com:443".into(),
            "c.example.com:443".into(),
            "d.example.com:443".into(),
            "e.example.com:443".into(),
        ])
        .unwrap();
        let peer = sa4([203, 0, 113, 42], 54321);
        let first = pool.select_for(&peer);
        // 100 probes — the kind of number a real GFW prober would
        // accumulate over hours/days.
        for round in 0..100u32 {
            assert_eq!(
                pool.select_for(&peer),
                first,
                "rotation detected at probe round {round}",
            );
        }
    }
}
