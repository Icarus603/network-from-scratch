//! Proteus throughput / latency benchmark harness.
//!
//! ## Why this exists
//!
//! The repo-level README has long carried this line:
//!
//! > **no "β beats Hy2" claim is honest without [netem] numbers**.
//!
//! The in-tree `throughput_smoke` tests measure *loopback echo* — they
//! catch performance regressions (BBR window collapse, lost
//! `BufWriter`, hot-path ratchet) but they say nothing about how the
//! carrier holds up under real network conditions:
//!
//! - Bandwidth caps (operator's actual 100 Mbps VPS link)
//! - Bulk-flow packet loss (1% / 5% / 15% / 30% are the GFW throttling
//!   regimes worth measuring against)
//! - RTT (10 ms LAN / 50 ms regional / 200 ms intercontinental)
//!
//! `proteus-bench` exposes the same workload as the smoke tests, but
//! split into separate `server` + `client` binaries so the two can
//! run on different hosts (or one host either side of a Linux netem
//! qdisc). The client emits a structured **JSON line per run** with
//! the actual throughput, configured payload size, and the perf knobs
//! used — suitable for piping through `jq` into a CSV for a
//! reproducible throughput-vs-loss curve.
//!
//! ## Scope
//!
//! This crate intentionally provides the *measurement* infrastructure
//! only. It does NOT include:
//!
//! - The netem qdisc setup itself (that's `bench/netem-sweep.sh` —
//!   a thin bash wrapper around `tc qdisc add netem loss N% delay N
//!   ms rate N mbit` because netem is Linux-kernel-only and can't be
//!   driven from this Rust crate without root + capabilities).
//! - A side-by-side Hy2 / TUIC client (we don't bundle competitors;
//!   the operator runs them with their official binaries and feeds
//!   the resulting JSON into the same comparison script).
//!
//! Both gaps are deliberate — the harness's job is producing
//! *reproducible Proteus numbers*, not implementing every competitor.
//!
//! ## Profile coverage
//!
//! - **α** (TCP + TLS 1.3 + Proteus framing): full support in two
//!   variants — `raw-tcp` (no outer TLS, mirrors the in-tree
//!   `throughput_smoke` test) and `tls` (production-shape, TLS 1.3 +
//!   ALPN h2/http/1.1 + RFC 5705 channel binding). Cross-host TLS
//!   bench uses the same 5-line identity banner as β plus the
//!   leaf cert hex pinned by `--server-leaf-cert-hex`.
//! - **β** (QUIC + BBR + perf-profile): full support. Operators can
//!   sweep `PerfProfile` knobs (`pad_quic_datagrams_to_mtu`,
//!   `initial_mtu`) to compare configurations on the same physical
//!   path.

pub mod alpha;
pub mod beta;
pub mod external;
pub mod netem;
pub mod report;
pub mod soak;
