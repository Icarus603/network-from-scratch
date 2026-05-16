//! Internal helpers for the `proteus-server` binary.
//!
//! Exposed as a library target alongside the `[[bin]]` so integration
//! tests under `tests/` can exercise the per-session relay logic
//! (CONNECT parsing, idle timeout, EOF semantics) without re-spawning
//! the entire binary. The binary itself just calls `relay::handle_session`.

pub mod relay;
