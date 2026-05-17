//! TTL-bounded auto-deny list for source-IP /24 (v4) / /48 (v6)
//! prefixes that the probe-anomaly detector has flagged as actively
//! probing the server.
//!
//! ## What this closes
//!
//! The probe-anomaly detector (`probe_anomaly.rs`) emits a structured
//! WARN + Prometheus alert on every threshold-crossing burst, but
//! takes no policy action — by design, since alerting and enforcement
//! are different layers and operators have varying tolerance for
//! false positives. The `admin status` recent-fires diagnostic + the
//! `proteus_probe_anomaly_recent_secs` labelled gauge give the
//! operator the prefix to blackhole, but require either a human in
//! the loop or an external pipeline (Prometheus alertmanager →
//! `iptables` script) to actually drop traffic.
//!
//! `AutoDenyList` closes that loop **inside the binary**: when the
//! operator opts in via `probe_anomaly.autodeny_minutes > 0`, every
//! anomaly fire automatically inserts the offending prefix into a
//! TTL-bounded deny list. Subsequent connections from that prefix
//! get short-circuited at the top of `admission_ok` — they don't
//! even reach the firewall snapshot, the global handshake budget,
//! or the per-IP rate limiter. The deny entry expires after the
//! configured TTL, so transient false positives self-heal without
//! operator intervention.
//!
//! ## Why an in-binary policy layer instead of feeding the firewall
//!
//! Two design alternatives we considered + rejected:
//!
//!   1. **Auto-mutate `ReloadableFirewall`** by appending the
//!      offending prefix to its deny list. Rejected because the
//!      operator's static firewall rules and the auto-deny entries
//!      have different lifecycles — confusing to mix them in one
//!      SIGHUP-reloadable surface. Operators editing the YAML and
//!      kicking a SIGHUP would inadvertently wipe pending auto-deny
//!      entries.
//!   2. **Call out to `iptables` / `nft` from inside the binary.**
//!      Rejected for portability (macOS dev doesn't have nft, BSDs
//!      have pf, k8s has its own policy plane) AND for blast radius
//!      (binary touching the kernel firewall is a security-review
//!      magnet). The in-binary list serves the same operational
//!      purpose without leaving Proteus's own admission path.
//!
//! ## Threading
//!
//! Single `Mutex<HashMap<PrefixKey, Instant>>` — the deny map. Lookups
//! happen on every connection (admission_ok hot path), inserts only
//! on anomaly fires (cold path; one per /24 per burst). Vacuum runs
//! on every lookup as a cheap O(1) amortized pass — we only walk
//! when the map is non-empty and we haven't vacuumed in
//! `VACUUM_INTERVAL`.

use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::Mutex;
use std::time::{Duration, Instant};

use crate::probe_anomaly::{IpFamily, ProbeAnomalyDetector};

/// The prefix-key shape from `probe_anomaly.rs`. Re-aliased here so
/// the auto-deny module can use the same /24 (v4) / /48 (v6)
/// aggregation discipline without cross-importing the type.
pub type PrefixKey = [u8; 6];

/// One row in the auto-deny snapshot — what an operator-visible
/// dashboard / `admin status` row needs to know about a currently-
/// denied prefix. Sorted by `expires_in_secs` ascending (soonest-
/// to-expire first) by `active_snapshot`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ActiveDenial {
    /// Operator-readable prefix string, e.g. `"198.51.100.0/24"`.
    pub prefix: String,
    /// Seconds remaining before this entry expires + heals
    /// automatically. Smaller = closer to clearing.
    pub expires_in_secs: u64,
}

/// How often the in-memory map gets vacuumed of expired entries. A
/// real attack pushes ~10s of /24s into the map over a minute; the
/// vacuum runs cheaply when we hit it AND when the next lookup would
/// have otherwise read a stale entry, so this is just a "don't pay
/// the O(N) scan on every single connection" guard.
const VACUUM_INTERVAL: Duration = Duration::from_secs(30);

/// Bounded auto-deny list keyed by /24 (v4) / /48 (v6) prefix.
///
/// Hold inside an `Arc` to share across the accept-loop's per-
/// connection tasks. Cheap to clone.
pub struct AutoDenyList {
    /// Value tuple is `(deadline, family)`. The family lets us
    /// reconstruct the human-readable prefix string at snapshot time
    /// without storing the original IpAddr (PrefixKey alone is
    /// ambiguous: a v4 /24's first 3 octets look identical to
    /// SOME v6 /48's first 3 bytes — without family info we'd
    /// render the wrong format).
    entries: Mutex<HashMap<PrefixKey, (Instant, IpFamily)>>,
    last_vacuum: Mutex<Instant>,
    /// How long each inserted prefix stays denied. 0 = the deny
    /// surface is disabled (every `is_denied` returns false; every
    /// `insert` is a no-op). This is the operator's main knob.
    ttl: Duration,
    /// Hard cap on map size. Same defense as
    /// `ProbeAnomalyDetector::max_prefixes` — an attacker who
    /// sweeps src IPs to inflate the deny list cannot evict
    /// existing entries; new inserts past the cap are silently
    /// refused.
    max_entries: usize,
    refused_inserts: std::sync::atomic::AtomicU64,
    inserted_total: std::sync::atomic::AtomicU64,
}

/// Default cap on the auto-deny map (4 K entries × ~32 bytes
/// ≈ 128 KiB bookkeeping per detector — small even on a
/// constrained VPS).
pub const DEFAULT_MAX_ENTRIES: usize = 4096;

impl AutoDenyList {
    /// Construct an auto-deny list with the supplied TTL + map cap.
    /// A `ttl` of zero produces a disabled list (`is_denied` always
    /// returns `false`, `insert` is a no-op); use this when the
    /// operator hasn't opted in.
    #[must_use]
    pub fn new(ttl: Duration, max_entries: usize) -> Self {
        Self {
            entries: Mutex::new(HashMap::new()),
            last_vacuum: Mutex::new(Instant::now()),
            ttl,
            max_entries: max_entries.max(1),
            refused_inserts: std::sync::atomic::AtomicU64::new(0),
            inserted_total: std::sync::atomic::AtomicU64::new(0),
        }
    }

    /// True iff the auto-deny surface is active (non-zero TTL).
    #[must_use]
    pub fn is_enabled(&self) -> bool {
        !self.ttl.is_zero()
    }

    /// Compute the prefix key for an `IpAddr` — /24 for v4, /48 for v6.
    /// Same discipline as `probe_anomaly::ProbeAnomalyDetector::prefix_key`.
    #[must_use]
    pub fn prefix_key(ip: IpAddr) -> PrefixKey {
        ProbeAnomalyDetector::prefix_key(ip)
    }

    /// Check whether `peer_ip` falls in a currently-denied prefix.
    /// Returns `false` when the auto-deny surface is disabled OR the
    /// prefix is not in the map OR its TTL has expired.
    ///
    /// This is the hot-path admission check; called on every
    /// connection. Cheap: one hash-map lookup + one TTL comparison.
    /// The vacuum runs at most once per `VACUUM_INTERVAL` and only
    /// when the map is non-empty.
    pub fn is_denied(&self, peer_ip: IpAddr, now: Instant) -> bool {
        if !self.is_enabled() {
            return false;
        }
        let key = Self::prefix_key(peer_ip);
        self.maybe_vacuum(now);
        let entries = self
            .entries
            .lock()
            .expect("AutoDenyList entries lock poisoned");
        match entries.get(&key) {
            Some(&(deadline, _family)) => now < deadline,
            None => false,
        }
    }

    /// Insert `peer_ip`'s prefix into the deny list with the
    /// configured TTL. Returns `true` on insert, `false` if the
    /// surface is disabled OR the map cap was hit.
    pub fn insert(&self, peer_ip: IpAddr, now: Instant) -> bool {
        if !self.is_enabled() {
            return false;
        }
        let key = Self::prefix_key(peer_ip);
        let family = match peer_ip {
            IpAddr::V4(_) => IpFamily::V4,
            IpAddr::V6(_) => IpFamily::V6,
        };
        let mut entries = self
            .entries
            .lock()
            .expect("AutoDenyList entries lock poisoned");
        // Capture the pre-match length so we can decide the cap
        // BEFORE taking the mut borrow via Entry. Using the Entry
        // API afterwards collapses lookup + insert into one hash
        // walk (clippy's `map_entry` lint wants this shape).
        let at_capacity_for_new_insert =
            entries.len() >= self.max_entries && !entries.contains_key(&key);
        if at_capacity_for_new_insert {
            self.refused_inserts
                .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            return false;
        }
        // Now safely insert/refresh — by construction we either have
        // a slot to spare OR the key is already in the map. The
        // family is captured per-insert so we can render the prefix
        // correctly at snapshot time.
        entries.insert(key, (now + self.ttl, family));
        self.inserted_total
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        true
    }

    /// Number of distinct prefixes currently in the deny map (after
    /// vacuum). Diagnostic accessor — exposed via Prometheus +
    /// admin status.
    #[must_use]
    pub fn tracked(&self) -> usize {
        let entries = self.entries.lock().ok();
        entries.map(|e| e.len()).unwrap_or(0)
    }

    /// Total insert attempts that succeeded (counter; refreshes
    /// of existing entries count).
    #[must_use]
    pub fn inserted_total(&self) -> u64 {
        self.inserted_total
            .load(std::sync::atomic::Ordering::Relaxed)
    }

    /// Total insert attempts refused because the map cap was hit.
    /// Operationally critical: rising = either raise the cap or
    /// engage the firewall.
    #[must_use]
    pub fn refused_inserts(&self) -> u64 {
        self.refused_inserts
            .load(std::sync::atomic::Ordering::Relaxed)
    }

    /// Effective TTL (operator-configured).
    #[must_use]
    pub fn ttl(&self) -> Duration {
        self.ttl
    }

    /// Vacuum the map if VACUUM_INTERVAL has elapsed since the last
    /// vacuum. O(N) on the map; amortized O(1) per lookup.
    fn maybe_vacuum(&self, now: Instant) {
        let mut last = match self.last_vacuum.lock() {
            Ok(l) => l,
            Err(_) => return,
        };
        if now.duration_since(*last) < VACUUM_INTERVAL {
            return;
        }
        *last = now;
        drop(last);
        let mut entries = match self.entries.lock() {
            Ok(e) => e,
            Err(_) => return,
        };
        entries.retain(|_, &mut (deadline, _family)| now < deadline);
    }

    /// Snapshot the currently-active denials, sorted soonest-to-
    /// expire first. Reconstructs human-readable prefix strings
    /// from the (`PrefixKey`, `IpFamily`) pair stored at insert
    /// time.
    ///
    /// Operationally exposed via the Prometheus extension AND the
    /// `admin status` block so operators can see "WHO is the binary
    /// currently blocking and for how much longer" without
    /// grepping logs or waiting for a fire to re-occur.
    #[must_use]
    pub fn active_snapshot(&self, now: Instant) -> Vec<ActiveDenial> {
        let entries = match self.entries.lock() {
            Ok(e) => e,
            Err(_) => return Vec::new(),
        };
        let mut out: Vec<ActiveDenial> = entries
            .iter()
            .filter_map(|(key, (deadline, family))| {
                // Skip already-expired entries (vacuum may not have
                // run yet) so the snapshot is accurate even between
                // vacuum sweeps.
                let remaining = deadline.checked_duration_since(now)?;
                let prefix = render_prefix(key, *family);
                Some(ActiveDenial {
                    prefix,
                    expires_in_secs: remaining.as_secs(),
                })
            })
            .collect();
        // Soonest-to-expire first — operators triaging a deny see
        // the entries that are about to heal at the top.
        out.sort_by_key(|d| d.expires_in_secs);
        out
    }

    /// Prometheus exposition snippet for the auto-deny surface.
    /// Emits four series:
    ///   - `proteus_auto_deny_active_prefixes` (gauge — current map size)
    ///   - `proteus_auto_deny_inserted_total` (counter)
    ///   - `proteus_auto_deny_refused_inserts_total` (counter — IP-sweep cap hits)
    ///   - `proteus_auto_deny_remaining_secs{prefix="…"}` (one labelled
    ///     gauge per active entry, value = seconds remaining)
    ///
    /// Designed to be appended to the server's metrics body when
    /// the auto-deny surface is wired into ServerCtx.
    #[must_use]
    pub fn prometheus_extension(&self, now: Instant) -> String {
        let active = self.active_snapshot(now);
        let mut out = String::with_capacity(512);
        out.push_str(
            "# HELP proteus_auto_deny_active_prefixes Number of /24 (v4) / /48 (v6) prefixes currently in the auto-deny list (post-vacuum).\n",
        );
        out.push_str("# TYPE proteus_auto_deny_active_prefixes gauge\n");
        out.push_str(&format!(
            "proteus_auto_deny_active_prefixes {}\n",
            active.len()
        ));
        out.push_str(
            "# HELP proteus_auto_deny_inserted_total Total auto-deny inserts (counts entry refreshes; rising = sustained anomaly traffic).\n",
        );
        out.push_str("# TYPE proteus_auto_deny_inserted_total counter\n");
        out.push_str(&format!(
            "proteus_auto_deny_inserted_total {}\n",
            self.inserted_total()
        ));
        out.push_str(
            "# HELP proteus_auto_deny_refused_inserts_total Auto-deny inserts refused because max_entries was reached (IP-sweep memory-cap signal).\n",
        );
        out.push_str("# TYPE proteus_auto_deny_refused_inserts_total counter\n");
        out.push_str(&format!(
            "proteus_auto_deny_refused_inserts_total {}\n",
            self.refused_inserts()
        ));
        out.push_str(
            "# HELP proteus_auto_deny_remaining_secs Seconds remaining before this prefix's auto-deny entry expires. One line per currently-active entry.\n",
        );
        out.push_str("# TYPE proteus_auto_deny_remaining_secs gauge\n");
        for d in &active {
            out.push_str(&format!(
                "proteus_auto_deny_remaining_secs{{prefix=\"{}\"}} {}\n",
                d.prefix, d.expires_in_secs,
            ));
        }
        out
    }
}

/// Render a `(PrefixKey, IpFamily)` pair into the conventional
/// `a.b.c.0/24` (v4) or `a:b:c::/48` (v6) human-readable form.
/// Sibling of `RecentFire::prefix_string` in `probe_anomaly.rs`;
/// duplicated here intentionally so callers don't have to construct
/// a synthetic `RecentFire` just to format a prefix string.
fn render_prefix(key: &PrefixKey, family: IpFamily) -> String {
    match family {
        IpFamily::V4 => format!("{}.{}.{}.0/24", key[0], key[1], key[2]),
        IpFamily::V6 => {
            let h0 = u16::from_be_bytes([key[0], key[1]]);
            let h1 = u16::from_be_bytes([key[2], key[3]]);
            let h2 = u16::from_be_bytes([key[4], key[5]]);
            format!("{h0:x}:{h1:x}:{h2:x}::/48")
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    fn ip4(a: u8, b: u8, c: u8, d: u8) -> IpAddr {
        IpAddr::V4(Ipv4Addr::new(a, b, c, d))
    }

    #[test]
    fn disabled_list_never_denies_anything() {
        let list = AutoDenyList::new(Duration::from_secs(0), 1024);
        assert!(!list.is_enabled());
        let now = Instant::now();
        assert!(!list.insert(ip4(1, 2, 3, 4), now));
        assert!(!list.is_denied(ip4(1, 2, 3, 4), now));
        assert_eq!(list.tracked(), 0);
    }

    #[test]
    fn insert_then_is_denied_within_ttl() {
        let list = AutoDenyList::new(Duration::from_secs(60), 1024);
        let now = Instant::now();
        assert!(list.insert(ip4(198, 51, 100, 7), now));
        assert!(list.is_denied(ip4(198, 51, 100, 7), now));
        // Different IP, same /24 → also denied (the load-bearing
        // /24 aggregation property).
        assert!(list.is_denied(ip4(198, 51, 100, 250), now));
        // Just before TTL expiry: still denied.
        assert!(list.is_denied(ip4(198, 51, 100, 7), now + Duration::from_secs(59)));
        // Just after TTL: not denied.
        assert!(!list.is_denied(ip4(198, 51, 100, 7), now + Duration::from_secs(61)));
    }

    #[test]
    fn different_slash24s_dont_cross_contaminate() {
        let list = AutoDenyList::new(Duration::from_secs(60), 1024);
        let now = Instant::now();
        list.insert(ip4(10, 0, 0, 1), now);
        assert!(list.is_denied(ip4(10, 0, 0, 99), now));
        // Different /24 → independent.
        assert!(!list.is_denied(ip4(10, 0, 1, 1), now));
        // Different /16 → also independent (we key on /24).
        assert!(!list.is_denied(ip4(10, 1, 0, 1), now));
    }

    #[test]
    fn refresh_extends_ttl_for_existing_entry() {
        let list = AutoDenyList::new(Duration::from_secs(60), 1024);
        let t0 = Instant::now();
        list.insert(ip4(203, 0, 113, 1), t0);
        // 50s later: refresh.
        list.insert(ip4(203, 0, 113, 1), t0 + Duration::from_secs(50));
        // At t0+90s: would have expired without refresh, but the
        // refresh pushed deadline to t0+110s. Still denied.
        assert!(list.is_denied(ip4(203, 0, 113, 1), t0 + Duration::from_secs(90)));
        // At t0+120s: past the refreshed deadline.
        assert!(!list.is_denied(ip4(203, 0, 113, 1), t0 + Duration::from_secs(120)));
    }

    #[test]
    fn cap_refuses_new_inserts_but_allows_refresh() {
        let list = AutoDenyList::new(Duration::from_secs(60), 3);
        let now = Instant::now();
        for i in 0..3u8 {
            assert!(list.insert(ip4(10, 0, i, 1), now));
        }
        assert_eq!(list.tracked(), 3);
        // 4th distinct /24 → refused.
        assert!(!list.insert(ip4(10, 0, 99, 1), now));
        assert_eq!(list.refused_inserts(), 1);
        // But REFRESHING an existing /24 still works.
        assert!(list.insert(ip4(10, 0, 0, 1), now + Duration::from_secs(10)));
        assert_eq!(list.tracked(), 3);
    }

    #[test]
    fn vacuum_clears_expired_entries() {
        // Use a TTL shorter than VACUUM_INTERVAL so we exercise the
        // expire-before-vacuum path: entries expire at t+5s but
        // vacuum hasn't run yet at t+10s. After advancing past
        // VACUUM_INTERVAL the map is reaped.
        let list = AutoDenyList::new(Duration::from_secs(5), 1024);
        let t0 = Instant::now();
        list.insert(ip4(10, 0, 0, 1), t0);
        list.insert(ip4(10, 0, 1, 1), t0);
        list.insert(ip4(10, 0, 2, 1), t0);
        assert_eq!(list.tracked(), 3);
        // Trigger a lookup AFTER VACUUM_INTERVAL passed AND after
        // all TTLs expired.
        let t_vacuum = t0 + VACUUM_INTERVAL + Duration::from_secs(1);
        // First lookup at this time triggers vacuum.
        assert!(!list.is_denied(ip4(10, 0, 0, 1), t_vacuum));
        // Map should now be empty.
        assert_eq!(
            list.tracked(),
            0,
            "vacuum should have reaped all 3 expired entries"
        );
    }

    #[test]
    fn ipv6_slash48_aggregation() {
        let list = AutoDenyList::new(Duration::from_secs(60), 1024);
        let now = Instant::now();
        let p1: IpAddr = "2001:db8:cafe::1".parse().unwrap();
        let p2: IpAddr = "2001:db8:cafe:beef::99".parse().unwrap();
        let p3: IpAddr = "2001:db8:dead::1".parse().unwrap();
        list.insert(p1, now);
        // p2 shares /48 with p1 → denied.
        assert!(list.is_denied(p2, now));
        // p3 is a different /48 → independent.
        assert!(!list.is_denied(p3, now));
    }

    #[test]
    fn counters_track_inserts_and_refusals() {
        let list = AutoDenyList::new(Duration::from_secs(60), 2);
        let now = Instant::now();
        list.insert(ip4(1, 1, 1, 1), now);
        list.insert(ip4(2, 2, 2, 1), now);
        list.insert(ip4(3, 3, 3, 1), now); // refused (cap = 2)
        list.insert(ip4(1, 1, 1, 1), now); // refresh (counts as inserted)
        assert_eq!(list.inserted_total(), 3);
        assert_eq!(list.refused_inserts(), 1);
    }

    #[test]
    fn default_max_entries_is_sensible() {
        assert_eq!(DEFAULT_MAX_ENTRIES, 4096);
    }

    // ---------- active_snapshot + Prometheus extension ----------

    #[test]
    fn active_snapshot_empty_when_no_inserts() {
        let list = AutoDenyList::new(Duration::from_secs(60), 1024);
        let snap = list.active_snapshot(Instant::now());
        assert!(snap.is_empty());
    }

    #[test]
    fn active_snapshot_reflects_v4_prefix_with_correct_format() {
        let list = AutoDenyList::new(Duration::from_secs(60), 1024);
        let now = Instant::now();
        list.insert(ip4(198, 51, 100, 7), now);
        let snap = list.active_snapshot(now);
        assert_eq!(snap.len(), 1);
        assert_eq!(snap[0].prefix, "198.51.100.0/24");
        // expires_in_secs should be close to TTL (60s) — allow a
        // small margin for the now->snapshot elapsed time.
        assert!(
            snap[0].expires_in_secs >= 58 && snap[0].expires_in_secs <= 60,
            "expires_in_secs out of expected range: {}",
            snap[0].expires_in_secs
        );
    }

    #[test]
    fn active_snapshot_reflects_v6_prefix_with_correct_format() {
        let list = AutoDenyList::new(Duration::from_secs(60), 1024);
        let now = Instant::now();
        let p: IpAddr = "2001:db8:cafe::99".parse().unwrap();
        list.insert(p, now);
        let snap = list.active_snapshot(now);
        assert_eq!(snap.len(), 1);
        assert_eq!(snap[0].prefix, "2001:db8:cafe::/48");
    }

    #[test]
    fn active_snapshot_sorted_soonest_to_expire_first() {
        // Three /24s inserted at staggered times so each has a
        // different deadline. Snapshot at a single instant; the
        // entry inserted FIRST (oldest, soonest to expire) must
        // appear first.
        let list = AutoDenyList::new(Duration::from_secs(60), 1024);
        let t0 = Instant::now();
        list.insert(ip4(10, 0, 0, 1), t0); // expires at t0+60
        list.insert(ip4(10, 0, 1, 1), t0 + Duration::from_secs(5)); // t0+65
        list.insert(ip4(10, 0, 2, 1), t0 + Duration::from_secs(10)); // t0+70
        let snap = list.active_snapshot(t0 + Duration::from_secs(15));
        assert_eq!(snap.len(), 3);
        // 10.0.0.x expires first (45s remaining at scrape time);
        // 10.0.2.x last (55s).
        assert_eq!(snap[0].prefix, "10.0.0.0/24");
        assert!(snap[0].expires_in_secs < snap[1].expires_in_secs);
        assert!(snap[1].expires_in_secs < snap[2].expires_in_secs);
        assert_eq!(snap[2].prefix, "10.0.2.0/24");
    }

    #[test]
    fn active_snapshot_omits_expired_entries_pre_vacuum() {
        // Insert with short TTL so the deadline passes before
        // VACUUM_INTERVAL kicks in. The snapshot must STILL omit
        // expired entries (filters at snapshot time).
        let list = AutoDenyList::new(Duration::from_secs(2), 1024);
        let t0 = Instant::now();
        list.insert(ip4(192, 0, 2, 1), t0);
        // Past the TTL, but before vacuum would run.
        let snap = list.active_snapshot(t0 + Duration::from_secs(3));
        assert!(
            snap.is_empty(),
            "snapshot must filter expired entries even pre-vacuum: {:?}",
            snap
        );
    }

    #[test]
    fn prometheus_extension_includes_all_four_series() {
        let list = AutoDenyList::new(Duration::from_secs(60), 4);
        let t0 = Instant::now();
        list.insert(ip4(203, 0, 113, 1), t0);
        list.insert(ip4(198, 51, 100, 1), t0);
        // Force one refused insert by overflowing the cap.
        list.insert(ip4(10, 0, 0, 1), t0);
        list.insert(ip4(10, 0, 1, 1), t0);
        list.insert(ip4(10, 0, 2, 1), t0); // 5th distinct → refused (cap = 4)

        let body = list.prometheus_extension(t0 + Duration::from_secs(10));

        assert!(body.contains("# HELP proteus_auto_deny_active_prefixes"));
        assert!(body.contains("# TYPE proteus_auto_deny_active_prefixes gauge"));
        assert!(body.contains("proteus_auto_deny_active_prefixes 4"));

        assert!(body.contains("# HELP proteus_auto_deny_inserted_total"));
        assert!(body.contains("# TYPE proteus_auto_deny_inserted_total counter"));
        // inserted_total includes the 4 accepted (refused doesn't count).
        assert!(body.contains("proteus_auto_deny_inserted_total 4"));

        assert!(body.contains("# HELP proteus_auto_deny_refused_inserts_total"));
        assert!(body.contains("proteus_auto_deny_refused_inserts_total 1"));

        assert!(body.contains("# TYPE proteus_auto_deny_remaining_secs gauge"));
        // 4 labelled lines (one per active entry).
        let labelled_lines = body
            .lines()
            .filter(|l| l.starts_with("proteus_auto_deny_remaining_secs{prefix="))
            .count();
        assert_eq!(labelled_lines, 4);
        // 10s elapsed → 50s remaining.
        assert!(
            body.contains("proteus_auto_deny_remaining_secs{prefix=\"203.0.113.0/24\"} 50"),
            "labelled line not found in:\n{body}"
        );
    }

    #[test]
    fn prometheus_extension_disabled_list_emits_zeros() {
        let list = AutoDenyList::new(Duration::from_secs(0), 1024);
        let body = list.prometheus_extension(Instant::now());
        // Disabled list — inserts no-op, snapshot empty, but the
        // counter lines still emit zeros so a Prometheus query
        // doesn't see a missing series.
        assert!(body.contains("proteus_auto_deny_active_prefixes 0"));
        assert!(body.contains("proteus_auto_deny_inserted_total 0"));
        assert!(body.contains("proteus_auto_deny_refused_inserts_total 0"));
        let labelled_lines = body
            .lines()
            .filter(|l| l.starts_with("proteus_auto_deny_remaining_secs{"))
            .count();
        assert_eq!(labelled_lines, 0);
    }
}
