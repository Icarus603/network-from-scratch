//! Per-process resource snapshots — open FD count and resident
//! memory bytes. Linux-only (via `/proc/self/{fd,status}`), `None`
//! on other platforms.
//!
//! ## Why this exists
//!
//! The soak harness (`proteus-bench soak`) proves the binary
//! doesn't leak over a 60-second run on this dev box. Production
//! deployments need a CONTINUOUS leak detector — a PromQL alert
//! that pages when `proteus_process_open_fds` ticks upward over
//! hours without a corresponding session count. Without the
//! gauges there's nothing to alert on.
//!
//! ## Linux-only by design
//!
//! Production VPS deployments are Linux. macOS / Windows are
//! development environments. Reading `/proc/self/*` is free on
//! Linux + portable across distributions; the alternative
//! (procfs crate, sysinfo crate, libc calls behind `unsafe`)
//! drags in either a large surface or platform-specific code.
//! We pick the minimal Linux-only path:
//!
//! - `open_fds()`: counts entries in `/proc/self/fd/` (each entry
//!   = one open file descriptor in this process).
//! - `resident_memory_bytes()`: parses `VmRSS:` from
//!   `/proc/self/status`.
//!
//! Both return `None` on non-Linux. The Prometheus emitter omits
//! the corresponding gauge when `None`, so non-Linux scrapes stay
//! clean (no zero-valued series that look like "0 FDs open").

/// Snapshot of cross-platform-ish per-process resource counters.
/// All fields are `Option<u64>`: `Some(n)` when the platform
/// supports the lookup, `None` when it doesn't or the read failed.
#[derive(Debug, Clone, Default)]
pub struct ProcessResources {
    /// Count of open file descriptors held by this process.
    /// Linux: number of entries in `/proc/self/fd/`. Other
    /// platforms: `None`.
    pub open_fds: Option<u64>,
    /// Resident set size in bytes (= physical memory currently
    /// used by this process). Linux: parsed from
    /// `/proc/self/status`'s `VmRSS:` line. Other platforms:
    /// `None`.
    pub resident_memory_bytes: Option<u64>,
}

impl ProcessResources {
    /// Take a fresh snapshot. Cheap (~10 µs on Linux for the two
    /// `/proc` reads). Safe to call on every Prometheus scrape.
    #[must_use]
    pub fn capture() -> Self {
        Self {
            open_fds: open_fds(),
            resident_memory_bytes: resident_memory_bytes(),
        }
    }

    /// Emit the Prometheus gauges. Uses `metric_prefix` so the
    /// server emits `proteus_process_*` and the client emits
    /// `proteus_client_process_*` (mirrors the convention from
    /// `process_info`).
    ///
    /// Each gauge is emitted ONLY when its value is `Some` — on
    /// macOS / Windows the series are absent, which PromQL
    /// `absent()` alerting can match if the operator wants to
    /// page on "this deployment isn't Linux".
    #[must_use]
    pub fn prometheus_with_prefix(&self, metric_prefix: &str) -> String {
        use std::fmt::Write as _;
        let mut s = String::with_capacity(256);
        if let Some(fds) = self.open_fds {
            let _ = writeln!(
                s,
                "# HELP {metric_prefix}_process_open_fds Open file descriptors held by this process (Linux: /proc/self/fd/ count)."
            );
            let _ = writeln!(s, "# TYPE {metric_prefix}_process_open_fds gauge");
            let _ = writeln!(s, "{metric_prefix}_process_open_fds {fds}");
        }
        if let Some(rss) = self.resident_memory_bytes {
            let _ = writeln!(
                s,
                "# HELP {metric_prefix}_process_resident_memory_bytes Resident set size in bytes (Linux: /proc/self/status VmRSS)."
            );
            let _ = writeln!(
                s,
                "# TYPE {metric_prefix}_process_resident_memory_bytes gauge"
            );
            let _ = writeln!(s, "{metric_prefix}_process_resident_memory_bytes {rss}");
        }
        s
    }

    /// `true` when both lookups returned `None`. The Prometheus
    /// emitter produces an empty string in this case — convenient
    /// for the caller's "skip the block if no data" check.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.open_fds.is_none() && self.resident_memory_bytes.is_none()
    }
}

/// Count entries in `/proc/self/fd/`. Linux-only.
#[cfg(target_os = "linux")]
fn open_fds() -> Option<u64> {
    let dir = std::fs::read_dir("/proc/self/fd").ok()?;
    // Filter for entries that successfully parse as a u64 — defends
    // against the rare `.` / `..` returns on some kernels (most
    // strip them but kernel quirks have been observed) and any
    // transient errors from concurrent FD churn.
    let count = dir
        .filter_map(Result::ok)
        .filter(|e| {
            e.file_name()
                .to_str()
                .and_then(|s| s.parse::<u64>().ok())
                .is_some()
        })
        .count();
    Some(count as u64)
}

#[cfg(not(target_os = "linux"))]
fn open_fds() -> Option<u64> {
    None
}

/// Parse `VmRSS:` from `/proc/self/status`. Linux-only.
///
/// The line shape is `VmRSS:\t <kB>` (e.g. `VmRSS:\t  12345 kB`).
/// We return bytes (= kB × 1024) so the Prometheus gauge name
/// matches the canonical `process_resident_memory_bytes` shape
/// (vs. Go's `process_resident_memory_bytes` etc.).
#[cfg(target_os = "linux")]
fn resident_memory_bytes() -> Option<u64> {
    let text = std::fs::read_to_string("/proc/self/status").ok()?;
    for line in text.lines() {
        let rest = match line.strip_prefix("VmRSS:") {
            Some(r) => r,
            None => continue,
        };
        // Trim whitespace, take first numeric token, multiply by 1024.
        let kb: u64 = rest.split_whitespace().next()?.parse::<u64>().ok()?;
        return Some(kb * 1024);
    }
    None
}

#[cfg(not(target_os = "linux"))]
fn resident_memory_bytes() -> Option<u64> {
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn capture_returns_some_on_linux_none_elsewhere() {
        let r = ProcessResources::capture();
        if cfg!(target_os = "linux") {
            assert!(r.open_fds.is_some(), "Linux must populate open_fds: {r:?}");
            assert!(
                r.resident_memory_bytes.is_some(),
                "Linux must populate resident_memory_bytes: {r:?}"
            );
            // Sanity: a running process always has at least 3 FDs
            // (stdin/stdout/stderr).
            assert!(r.open_fds.unwrap() >= 3);
            // And at least 1 MiB RSS (it's a Rust binary with the
            // full transport-alpha pulled in).
            assert!(r.resident_memory_bytes.unwrap() >= 1024 * 1024);
        } else {
            assert!(r.open_fds.is_none(), "non-Linux must return None: {r:?}");
            assert!(
                r.resident_memory_bytes.is_none(),
                "non-Linux must return None: {r:?}"
            );
        }
    }

    #[test]
    fn is_empty_when_both_fields_none() {
        let r = ProcessResources {
            open_fds: None,
            resident_memory_bytes: None,
        };
        assert!(r.is_empty());
    }

    #[test]
    fn is_not_empty_when_either_field_some() {
        assert!(!ProcessResources {
            open_fds: Some(10),
            resident_memory_bytes: None,
        }
        .is_empty());
        assert!(!ProcessResources {
            open_fds: None,
            resident_memory_bytes: Some(1024),
        }
        .is_empty());
    }

    #[test]
    fn prometheus_emits_nothing_when_both_none() {
        let r = ProcessResources::default();
        let s = r.prometheus_with_prefix("proteus");
        assert!(s.is_empty(), "expected empty block, got: {s}");
    }

    #[test]
    fn prometheus_emits_fds_only_when_only_fds_set() {
        let r = ProcessResources {
            open_fds: Some(42),
            resident_memory_bytes: None,
        };
        let s = r.prometheus_with_prefix("proteus");
        assert!(s.contains("proteus_process_open_fds 42"), "{s}");
        assert!(
            !s.contains("resident_memory_bytes"),
            "should NOT emit RSS when None: {s}"
        );
    }

    #[test]
    fn prometheus_emits_rss_only_when_only_rss_set() {
        let r = ProcessResources {
            open_fds: None,
            resident_memory_bytes: Some(123_456_789),
        };
        let s = r.prometheus_with_prefix("proteus");
        assert!(
            s.contains("proteus_process_resident_memory_bytes 123456789"),
            "{s}"
        );
        assert!(
            !s.contains("open_fds"),
            "should NOT emit FDs when None: {s}"
        );
    }

    #[test]
    fn prometheus_emits_both_under_custom_prefix() {
        let r = ProcessResources {
            open_fds: Some(15),
            resident_memory_bytes: Some(2 * 1024 * 1024),
        };
        let s = r.prometheus_with_prefix("proteus_client");
        assert!(s.contains("proteus_client_process_open_fds 15"), "{s}");
        assert!(
            s.contains("proteus_client_process_resident_memory_bytes 2097152"),
            "{s}"
        );
        // HELP/TYPE rows must appear for both.
        assert_eq!(
            s.matches("# HELP proteus_client_process_open_fds ").count(),
            1
        );
        assert_eq!(
            s.matches("# HELP proteus_client_process_resident_memory_bytes ")
                .count(),
            1
        );
    }

    #[test]
    fn prometheus_default_prefix_proteus_matches_with_prefix_proteus() {
        let r = ProcessResources {
            open_fds: Some(5),
            resident_memory_bytes: Some(1024),
        };
        let a = r.prometheus_with_prefix("proteus");
        let b = r.prometheus_with_prefix("proteus");
        assert_eq!(a, b);
    }
}
