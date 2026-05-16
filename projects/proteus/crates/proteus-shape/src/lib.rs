//! Proteus shaping engine.
//!
//! v1.0 ships the following sub-modules:
//!
//! - [`cell`] — per-datagram padding-to-cell-size logic (spec §4.6, §9.1).
//! - [`shift`] — deterministic shape-shift schedule driven by the 32-bit
//!   `shape_seed` carried in the auth extension (spec §22).
//!
//! The Maybenot adapter (§9.2, §20) and the cover-IAT online learning
//! pipeline are M3 deliverables and are intentionally absent here. The
//! types declared below have stable APIs so M3 can plug in without
//! disturbing M0/M1/M2 callers.

#![deny(missing_docs)]

pub mod cell;
pub mod shift;
