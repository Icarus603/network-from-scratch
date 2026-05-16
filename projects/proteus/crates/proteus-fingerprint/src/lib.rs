//! TLS ClientHello fingerprint extractor.
//!
//! Implements **JA4** (FoxIO 2023) on parsed-from-the-wire TLS 1.2/1.3
//! ClientHello records. JA4 is what enterprise DPI / modern censor
//! tooling is moving to in 2024+ — it's deterministic, GREASE-aware,
//! and matches the per-byte shape of the handshake far more tightly
//! than the legacy JA3 (MD5-based, GREASE-unaware) does.
//!
//! ## Why this crate exists
//!
//! REALITY's entire stealth advantage is that its TLS ClientHello is
//! a bit-perfect replay of a real Chrome (or Firefox) ClientHello —
//! so JA4 = `t13d1517h2_8daaf6152771_b0da82dd1658` (Chrome 124 JA4
//! at time of writing), indistinguishable from the genuine browser.
//!
//! Proteus α currently uses rustls's default ClientHello — which
//! emits its own distinctive JA4 signature, NOT a Chrome/Firefox one.
//! Until uTLS-grade fingerprint replay ships, any GFW operator
//! running JA4 classifiers can flag Proteus traffic by fingerprint
//! alone, regardless of all the cryptographic strength below the TLS
//! layer.
//!
//! This crate is the **measurement infrastructure** that will gate
//! the uTLS work:
//!   - extract JA4 from a raw ClientHello byte stream
//!   - lock the current Proteus baseline in a regression test
//!   - any future change to the outer-TLS shape (e.g. when uTLS
//!     replay lands) shows up as a JA4 diff in CI — operators can
//!     audit exactly what the wire shape looks like at every commit
//!
//! ## What this crate does NOT yet do
//!
//! - JA3 (deferred — MD5 dep, less useful in 2024+).
//! - ClientHello mutation (the actual uTLS-equivalent work — multi-
//!   week build, requires forking rustls or using a custom
//!   handshake encoder).
//! - Server-side fingerprint detection (Proteus only acts as a TLS
//!   client toward its own server; a defender-side JA4-of-incoming-
//!   traffic feature is server-side work for a future commit).

#![forbid(unsafe_code)]
#![deny(missing_docs)]

pub mod ja4;

pub use ja4::{Ja4, Ja4Error, GREASE_VALUES};
