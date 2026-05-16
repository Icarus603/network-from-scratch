//! Handshake state machine and anti-replay window (spec §5, §8).
//!
//! This crate exposes:
//!
//! - [`state`] — the 15-state finite automaton (spec §5.1).
//! - [`replay`] — server-side sliding-window replay detector and timestamp
//!   guard (spec §8.1, §8.2).
//! - [`auth_tag`] — HMAC-SHA-256 auth-tag compute / verify routines used
//!   on the auth extension's pre-tag bytes (spec §4.1.3).
//!
//! The full key-schedule wiring (consuming `proteus_crypto::kex` /
//! `proteus_crypto::kdf` to produce per-direction record keys) lives in
//! `crates/proteus-transport/*` and is part of the M1 milestone.

#![deny(missing_docs)]

pub mod auth_tag;
pub mod replay;
pub mod state;
