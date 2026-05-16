//! Internal helpers for the `proteus-server` binary.
//!
//! Exposed as a library target alongside the `[[bin]]` so integration
//! tests under `tests/` can exercise the per-session relay logic
//! (CONNECT parsing, idle timeout, EOF semantics) without re-spawning
//! the entire binary. The binary itself just calls `relay::handle_session`.

pub mod config;
pub mod relay;
pub mod startup;
pub mod validate;

/// Return true if `addr` parses as a loopback `host:port` (127/8 or
/// ::1). Used by both the main binary's startup warning and the
/// `validate` preflight check.
#[must_use]
pub fn is_loopback(addr: &str) -> bool {
    match addr.parse::<std::net::SocketAddr>() {
        Ok(sa) => sa.ip().is_loopback(),
        Err(_) => false,
    }
}
