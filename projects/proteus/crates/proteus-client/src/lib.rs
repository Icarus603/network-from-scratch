//! Library target for `proteus-client`.
//!
//! Exposed alongside the `[[bin]]` so integration tests can drive
//! the SOCKS5 dispatch path directly without going through the
//! YAML loader + clap parser. The binary still does `mod config;
//! mod socks;` internally — both compile to the same module
//! instances thanks to Cargo's bin+lib coexistence.

pub mod config;
pub mod socks;
