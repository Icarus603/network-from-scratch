//! Library target for `proteus-client`.
//!
//! Exposed alongside the `[[bin]]` so integration tests can drive
//! the SOCKS5 dispatch path directly without going through the
//! YAML loader + clap parser. The binary still does `mod config;
//! mod socks;` internally — both compile to the same module
//! instances thanks to Cargo's bin+lib coexistence.

pub mod admin;
pub mod admin_alerts_check;
pub mod beta_pool;
pub mod bootstrap;
pub mod carrier_health;
pub mod config;
pub mod connect_test;
pub mod ctx;
pub mod endpoint_pool;
pub mod host_preflight;
pub mod knock_psk;
pub mod process_panic_counter;
pub mod socks;
pub mod validate;
