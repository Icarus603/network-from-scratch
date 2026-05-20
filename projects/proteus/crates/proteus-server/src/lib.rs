//! Internal helpers for the `proteus-server` binary.
//!
//! Exposed as a library target alongside the `[[bin]]` so integration
//! tests under `tests/` can exercise the per-session relay logic
//! (CONNECT parsing, idle timeout, EOF semantics) without re-spawning
//! the entire binary. The binary itself just calls `relay::handle_session`.

pub mod admin;
pub mod admin_alerts_check;
pub mod config;
pub mod host_preflight;
pub mod ip_reputation;
pub mod knock_keygen;
pub mod preflight;
pub mod preflight_orchestrator;
pub mod process_access_log_stats;
pub mod process_panic_counter;
pub mod relay;
pub mod restart_tracker;
pub mod startup;
pub mod startup_self_test;
pub mod tls_fingerprint_observer;
pub mod validate;

/// Return true if `addr` is a loopback bind address (127/8, ::1, or
/// the bare hostname `localhost`). Used by the main binary's
/// startup warning and the `validate` preflight check.
///
/// Iter-181: also recognize `localhost:port` as loopback. The
/// pre-iter-181 implementation only parsed as `SocketAddr`, which
/// only accepts numeric IP forms. Operators who wrote
/// `metrics_listen: "localhost:9090"` (a perfectly valid bind
/// target — tokio resolves it via libc to 127.0.0.1 or ::1, both
/// loopback) hit the wildcard-bind warning + FAIL paths in
/// validate even though their binary was binding loopback. The
/// new path strips the `:port` suffix and checks for the literal
/// `localhost` host (case-insensitive per RFC 6761 §6.3 which
/// reserves `localhost` as a loopback alias).
#[must_use]
pub fn is_loopback(addr: &str) -> bool {
    if let Ok(sa) = addr.parse::<std::net::SocketAddr>() {
        return sa.ip().is_loopback();
    }
    // Non-numeric form: strip the trailing `:port` and check for
    // the reserved `localhost` alias (RFC 6761 §6.3). The bracket
    // form for IPv6 (`[::1]:port`) is already handled by the
    // SocketAddr parse above; we only need to catch the bare
    // hostname here. Note: any other hostname (e.g.
    // `my.server.com`) returns false because we cannot resolve
    // without a DNS query at validate time, and the conservative
    // assumption for the warning path is "not loopback".
    if let Some((host, port_str)) = addr.rsplit_once(':') {
        // Reject empty host (the iter-159-style empty-host shape).
        if host.is_empty() {
            return false;
        }
        // Reject if port isn't a valid u16.
        if port_str.parse::<u16>().is_err() {
            return false;
        }
        // RFC 6761 §6.3: `localhost` is reserved as a loopback alias.
        // Case-insensitive per RFC 4343 §3.
        if host.eq_ignore_ascii_case("localhost") {
            return true;
        }
    }
    false
}

#[cfg(test)]
mod is_loopback_tests {
    use super::is_loopback;

    /// Pre-iter-181 cases (numeric forms parse as SocketAddr).
    #[test]
    fn numeric_loopback_forms_still_recognized() {
        for ok in [
            "127.0.0.1:8080",
            "127.255.255.254:1",
            "[::1]:443",
            "[::1]:1",
        ] {
            assert!(
                is_loopback(ok),
                "iter-181: {ok:?} must be loopback (numeric form regression)"
            );
        }
    }

    #[test]
    fn numeric_non_loopback_rejected() {
        for not_lb in [
            "0.0.0.0:8080",
            "1.1.1.1:443",
            "[::]:443",
            "[2001:db8::1]:443",
            "203.0.113.42:443",
        ] {
            assert!(
                !is_loopback(not_lb),
                "iter-181: {not_lb:?} must NOT be loopback (numeric form regression)"
            );
        }
    }

    /// Iter-181: the new path — `localhost:port` recognized as
    /// loopback per RFC 6761 §6.3. Case-insensitive per RFC 4343.
    #[test]
    fn iter181_localhost_recognized_as_loopback() {
        for ok in [
            "localhost:9090",
            "localhost:1",
            "localhost:65535",
            // Case-insensitive per RFC 4343 §3.
            "LOCALHOST:9090",
            "Localhost:9090",
            "LocalHost:443",
        ] {
            assert!(
                is_loopback(ok),
                "iter-181: {ok:?} must be loopback (RFC 6761 §6.3 + case-insensitive)"
            );
        }
    }

    /// Iter-181: non-localhost hostnames stay conservatively
    /// non-loopback. We don't resolve at validate time, so
    /// `my.server.com` cannot prove it's loopback even if it
    /// IS bound to 127.0.0.1 via /etc/hosts.
    #[test]
    fn iter181_other_hostnames_still_non_loopback() {
        for not_lb in [
            "my.server.com:443",
            "example.com:8080",
            "vps.example.com:8443",
            // Garbage shapes: empty host, missing port, bad port.
            ":9090",
            "localhost",        // missing port
            "localhost:notnum", // non-u16 port
        ] {
            assert!(
                !is_loopback(not_lb),
                "iter-181: {not_lb:?} must NOT be loopback"
            );
        }
    }
}
