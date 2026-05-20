//! `proteus-server admin status` — SSH-friendly snapshot.
//!
//! Operators triaging a live server want one quick look at:
//! - Process up/ready state.
//! - In-flight sessions + lifetime totals.
//! - Defense layer rejection counters (so they can spot a fresh DoS).
//! - Sessions reaped by idle / byte budget.
//!
//! `curl /metrics | grep` works but means remembering the metric
//! names and the bearer token. This subcommand wraps that with
//! semantic grouping + a one-pass parser.
//!
//! Reads `--url` (default `http://127.0.0.1:9090/metrics`). Auth via
//! `--token-file` (or `PROTEUS_METRICS_TOKEN` env var). No external
//! Prometheus client lib: the exposition format is line-based plain
//! text, easy to parse by hand.

use std::collections::BTreeMap;
use std::fmt;
use std::io::{Read, Write};
use std::net::{SocketAddr, TcpStream, ToSocketAddrs};
use std::path::Path;
use std::time::Duration;

/// All counters / gauges we recognize. Unknown counter names from the
/// exposition are ignored (forward-compatible — newer servers can add
/// counters without breaking older admin clients).
#[derive(Debug, Default, Clone)]
pub struct MetricsSnapshot {
    pub up: u64,
    pub ready: u64,
    pub in_flight_sessions: u64,
    pub sessions_accepted: u64,
    pub handshakes_succeeded: u64,
    pub handshakes_failed: u64,
    pub handshake_timeouts: u64,
    pub handshake_budget_rejected: u64,
    pub rate_limited: u64,
    pub conn_limit_rejected: u64,
    pub firewall_denied: u64,
    pub user_rate_rejected: u64,
    pub cover_forwards: u64,
    pub probe_anomalies_fired: u64,
    /// Number of distinct /24 (v4) / /48 (v6) prefixes currently
    /// being tracked by the probe-anomaly detector (gauge — current
    /// sliding-window population, not a cumulative count). Sourced
    /// from `proteus_probe_anomaly_tracked_prefixes`.
    pub probe_anomaly_tracked: u64,
    /// Times the detector refused to track a NEW prefix because
    /// `max_prefixes` was reached (IP-sweep memory-cap signal).
    /// A rising counter here = either operator should raise the
    /// cap (legitimate scale) OR an attacker is sieve-probing
    /// (firewall / rate-limit should engage). Sourced from
    /// `proteus_probe_anomaly_dropped_inserts_total`.
    pub probe_anomaly_dropped_inserts: u64,
    /// Recent fires from the bounded ring buffer. Each entry is
    /// `(prefix_string, seconds_since_fire)`. Sourced by parsing
    /// the labelled `proteus_probe_anomaly_recent_secs{prefix="…"}`
    /// gauge lines. Pretty-printed at the bottom of `admin status`
    /// text output + emitted as a JSON array in `admin status
    /// --format json`. The most operationally critical signal in
    /// this snapshot for IR work: "which /24 do I blackhole-route?"
    pub probe_anomaly_recent: Vec<ProbeAnomalyRecentFire>,
    /// Active auto-deny entries — operator-opt-in via
    /// `probe_anomaly.autodeny_minutes > 0`. Sourced from
    /// `proteus_auto_deny_active_prefixes` (gauge),
    /// `proteus_auto_deny_inserted_total` (counter),
    /// `proteus_auto_deny_refused_inserts_total` (counter),
    /// `proteus_auto_deny_remaining_secs{prefix="…"}` (per-entry).
    pub auto_deny_active: u64,
    pub auto_deny_inserted_total: u64,
    pub auto_deny_refused_inserts_total: u64,
    /// Per-prefix entries from the auto-deny list. Each entry is
    /// `(prefix_string, expires_in_secs)`. Sorted soonest-to-expire
    /// first in the rendered output (parser preserves emission
    /// order; sorting happens at render time).
    pub auto_deny_entries: Vec<AutoDenyEntry>,
    /// Leaf TLS cert `notAfter` as Unix seconds. `None` means TLS
    /// observability is not wired (legacy startup path OR no `tls:`
    /// block in config). Sourced from
    /// `proteus_tls_cert_not_after_unix_seconds` Prometheus gauge.
    /// Negative values are invalid and parsed as `None`.
    pub tls_cert_not_after_unix: Option<i64>,
    /// SIGHUP-style TLS reload attempt counter. Sourced from
    /// `proteus_tls_reload_attempts_total`. `None` if TLS
    /// observability is not wired.
    pub tls_reload_attempts: Option<u64>,
    /// Subset of `tls_reload_attempts` whose new chain parsed cleanly
    /// AND swapped in. The gap `attempts - succeeded` is the silent-
    /// SIGHUP-failure signal operators alert on. Sourced from
    /// `proteus_tls_reload_succeeded_total`.
    pub tls_reload_succeeded: Option<u64>,
    /// **SIGHUP firewall / rate-limit / handshake-budget reload
    /// counters.** Each pair has the same `attempts - succeeded`
    /// alert semantics as `tls_reload`. Zero-valued when no SIGHUP
    /// has happened OR when the YAML doesn't have the corresponding
    /// section configured (the *_attempts counter is bumped per
    /// SIGHUP regardless, but `_succeeded` only bumps when the
    /// section was actually applicable). Operators alert on
    /// `attempts - succeeded > 0` to catch silent SIGHUP failures.
    pub firewall_reload_attempts: u64,
    pub firewall_reload_succeeded: u64,
    pub rate_limit_reload_attempts: u64,
    pub rate_limit_reload_succeeded: u64,
    pub user_rate_limit_reload_attempts: u64,
    pub user_rate_limit_reload_succeeded: u64,
    pub handshake_budget_reload_attempts: u64,
    pub handshake_budget_reload_succeeded: u64,
    /// **Config-presence snapshot.** Set of section names where
    /// `proteus_config_section_active{section="..."} 1` was observed
    /// on the wire. Operators read this to answer "did my YAML edit
    /// even land?" without re-reading the on-disk file. Empty when
    /// the server is older than 2026-05-19 OR when the operator
    /// scraped a metrics endpoint that doesn't expose the
    /// `proteus_config_section_active` series (e.g. test rigs that
    /// don't wire `config_presence` into v4).
    pub config_active_sections: std::collections::BTreeSet<String>,
    /// `proteus_config_cover_endpoint_pool_size` (gauge). Zero when
    /// the cover-endpoint pool isn't configured.
    pub config_cover_endpoint_pool_size: u64,
    /// `proteus_config_client_allowlist_size` (gauge).
    pub config_client_allowlist_size: u64,
    /// **Process-lifecycle gauges.** Sourced from
    /// `proteus_process_start_unix_seconds` (Unix-seconds wall-
    /// clock start) and `proteus_process_uptime_seconds`
    /// (monotonic uptime). `None` when the metrics endpoint
    /// doesn't expose process-lifecycle (older server / test rig
    /// without process_info wired).
    pub process_start_unix_seconds: Option<u64>,
    pub process_uptime_seconds: Option<u64>,
    /// **Build metadata** parsed from `proteus_build_info{...}`.
    /// `(version, rustc, target)` triple. Empty Strings preserve
    /// what's on the wire; `None` means the gauge wasn't present.
    pub process_build_info: Option<BuildInfo>,
    pub tx_bytes: u64,
    pub rx_bytes: u64,
    pub aead_drops: u64,
    pub ratchets: u64,
    pub session_idle_reaped: u64,
    pub session_byte_budget_exhausted: u64,
    /// Counters we recognized by name but don't have a dedicated
    /// field for yet. Operators see them under "Other".
    pub other: BTreeMap<String, u64>,
}

/// One row of the probe-anomaly recent-fires ring buffer, parsed out
/// of the labelled Prometheus gauge `proteus_probe_anomaly_recent_secs`.
#[derive(Debug, Clone, Default)]
pub struct ProbeAnomalyRecentFire {
    /// Prefix string as emitted by the server, e.g. `"198.51.100.0/24"`
    /// or `"2001:db8::/48"`. Already operator-readable; no further
    /// transformation needed.
    pub prefix: String,
    /// Seconds elapsed between the fire and the scrape time. Smaller
    /// = more recent; 0 = just fired.
    pub secs_ago: u64,
}

/// One row of the auto-deny active list, parsed out of the labelled
/// Prometheus gauge `proteus_auto_deny_remaining_secs`.
#[derive(Debug, Clone, Default)]
pub struct AutoDenyEntry {
    /// Prefix string, e.g. `"198.51.100.0/24"` or `"2001:db8::/48"`.
    pub prefix: String,
    /// Seconds remaining before the entry auto-expires.
    pub expires_in_secs: u64,
}

/// Build metadata parsed from `proteus_build_info{version="…",
/// rustc="…",target="…"} 1`. Empty fields are preserved (the
/// emitter may legitimately emit `""` for fields it doesn't know).
#[derive(Debug, Clone, Default)]
pub struct BuildInfo {
    pub version: String,
    pub rustc: String,
    pub target: String,
}

/// Output format for `admin status` / `diff` / `watch`. The
/// hand-rolled JSON shape is stable across releases: existing
/// fields will not be renamed or have their types changed; new
/// fields are append-only.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum OutputFormat {
    /// Human-friendly table (default).
    #[default]
    Text,
    /// One canonical JSON document per invocation. Fields are
    /// snake_case `u64` (counters / gauges) or `bool` (alive,
    /// ready, counter_reset). Suitable for `jq` post-processing
    /// and scripted alerting.
    Json,
}

impl std::str::FromStr for OutputFormat {
    type Err = String;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "text" | "human" => Ok(Self::Text),
            "json" => Ok(Self::Json),
            other => Err(format!(
                "unknown format {other:?} (expected 'text' or 'json')"
            )),
        }
    }
}

impl MetricsSnapshot {
    /// Parse a Prometheus 0.0.4 exposition body.
    ///
    /// Tolerant: silently ignores `#` comment lines, blank lines,
    /// label-bearing series (none of our counters have labels), and
    /// malformed value lines. We deliberately use the simplest
    /// possible parser — the body is generated by our own
    /// hand-rolled emitter, so format guarantees are tight.
    #[must_use]
    pub fn parse(body: &str) -> Self {
        let mut s = Self::default();
        for line in body.lines() {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            // Each value line is `name value`; rather than rejecting
            // every line with a `{`, we recognize ONE specific
            // labelled series — `proteus_probe_anomaly_recent_secs
            // {prefix="..."} <value>` — and route it to the
            // recent-fires ring. Everything else with a `{` stays
            // skipped (no other Proteus metric has labels).
            let (name, value) = match line.split_once(' ') {
                Some((n, v)) => (n.trim(), v.trim()),
                None => continue,
            };
            if name.contains('{') {
                // Parse the recent_secs labelled lines.
                if let Some(fire) = parse_probe_anomaly_recent(name, value) {
                    s.probe_anomaly_recent.push(fire);
                } else if let Some(entry) = parse_auto_deny_remaining(name, value) {
                    s.auto_deny_entries.push(entry);
                } else if let Some((section, present)) = parse_config_section_active(name, value) {
                    if present {
                        s.config_active_sections.insert(section);
                    }
                } else if let Some(bi) = parse_build_info(name, value) {
                    s.process_build_info = Some(bi);
                }
                continue;
            }
            // TLS observability gauges/counters are parsed separately
            // because the cert-expiry gauge is naturally i64 (Unix
            // timestamp; positive in practice but the type is signed).
            // We branch on the name BEFORE the u64 parse so we don't
            // silently drop the gauge if some future test uses a
            // negative sentinel.
            if name == "proteus_tls_cert_not_after_unix_seconds" {
                if let Ok(ts) = value.parse::<i64>() {
                    if ts >= 0 {
                        s.tls_cert_not_after_unix = Some(ts);
                    }
                }
                continue;
            }
            let v: u64 = match value.parse() {
                Ok(v) => v,
                Err(_) => continue,
            };
            match name {
                "proteus_up" => s.up = v,
                "proteus_ready" => s.ready = v,
                "proteus_in_flight_sessions" => s.in_flight_sessions = v,
                "proteus_sessions_accepted_total" => s.sessions_accepted = v,
                "proteus_handshakes_succeeded_total" => s.handshakes_succeeded = v,
                "proteus_handshakes_failed_total" => s.handshakes_failed = v,
                "proteus_handshake_timeouts_total" => s.handshake_timeouts = v,
                "proteus_handshake_budget_rejected_total" => s.handshake_budget_rejected = v,
                "proteus_rate_limited_total" => s.rate_limited = v,
                "proteus_conn_limit_rejected_total" => s.conn_limit_rejected = v,
                "proteus_firewall_denied_total" => s.firewall_denied = v,
                "proteus_user_rate_rejected_total" => s.user_rate_rejected = v,
                "proteus_cover_forwards_total" => s.cover_forwards = v,
                "proteus_probe_anomalies_fired_total" => s.probe_anomalies_fired = v,
                "proteus_probe_anomaly_tracked_prefixes" => s.probe_anomaly_tracked = v,
                "proteus_probe_anomaly_dropped_inserts_total" => {
                    s.probe_anomaly_dropped_inserts = v;
                }
                "proteus_auto_deny_active_prefixes" => s.auto_deny_active = v,
                "proteus_auto_deny_inserted_total" => s.auto_deny_inserted_total = v,
                "proteus_auto_deny_refused_inserts_total" => {
                    s.auto_deny_refused_inserts_total = v;
                }
                "proteus_tls_reload_attempts_total" => {
                    s.tls_reload_attempts = Some(v);
                }
                "proteus_tls_reload_succeeded_total" => {
                    s.tls_reload_succeeded = Some(v);
                }
                "proteus_firewall_reload_attempts_total" => {
                    s.firewall_reload_attempts = v;
                }
                "proteus_firewall_reload_succeeded_total" => {
                    s.firewall_reload_succeeded = v;
                }
                "proteus_rate_limit_reload_attempts_total" => {
                    s.rate_limit_reload_attempts = v;
                }
                "proteus_rate_limit_reload_succeeded_total" => {
                    s.rate_limit_reload_succeeded = v;
                }
                "proteus_user_rate_limit_reload_attempts_total" => {
                    s.user_rate_limit_reload_attempts = v;
                }
                "proteus_user_rate_limit_reload_succeeded_total" => {
                    s.user_rate_limit_reload_succeeded = v;
                }
                "proteus_handshake_budget_reload_attempts_total" => {
                    s.handshake_budget_reload_attempts = v;
                }
                "proteus_handshake_budget_reload_succeeded_total" => {
                    s.handshake_budget_reload_succeeded = v;
                }
                "proteus_config_cover_endpoint_pool_size" => {
                    s.config_cover_endpoint_pool_size = v;
                }
                "proteus_config_client_allowlist_size" => {
                    s.config_client_allowlist_size = v;
                }
                "proteus_process_start_unix_seconds" => {
                    s.process_start_unix_seconds = Some(v);
                }
                "proteus_process_uptime_seconds" => {
                    s.process_uptime_seconds = Some(v);
                }
                "proteus_tx_bytes_total" => s.tx_bytes = v,
                "proteus_rx_bytes_total" => s.rx_bytes = v,
                "proteus_aead_drops_total" => s.aead_drops = v,
                "proteus_ratchets_total" => s.ratchets = v,
                "proteus_session_idle_reaped_total" => s.session_idle_reaped = v,
                "proteus_session_byte_budget_exhausted_total" => {
                    s.session_byte_budget_exhausted = v;
                }
                // Unknown counter — keep it under "Other" so a future
                // metric still surfaces to the operator without an
                // admin-CLI rebuild.
                _ if name.starts_with("proteus_") => {
                    s.other.insert(name.to_string(), v);
                }
                _ => {}
            }
        }
        s
    }

    /// Sum of all rejection counters (DoS-defense pipeline).
    #[must_use]
    pub fn total_rejected(&self) -> u64 {
        self.firewall_denied
            .saturating_add(self.handshake_budget_rejected)
            .saturating_add(self.rate_limited)
            .saturating_add(self.conn_limit_rejected)
            .saturating_add(self.user_rate_rejected)
    }

    /// Render as a single-line JSON document with a trailing newline.
    /// Field names are snake_case and stable across releases. Unknown
    /// counters (`other`) are emitted as a nested object so consumers
    /// can index into them by name.
    #[must_use]
    pub fn to_json(&self) -> String {
        let mut s = String::with_capacity(512);
        s.push('{');
        push_json_bool(&mut s, "alive", self.up == 1, true);
        push_json_bool(&mut s, "ready", self.ready == 1, false);
        push_json_u64(&mut s, "in_flight_sessions", self.in_flight_sessions, false);
        push_json_u64(&mut s, "sessions_accepted", self.sessions_accepted, false);
        push_json_u64(
            &mut s,
            "handshakes_succeeded",
            self.handshakes_succeeded,
            false,
        );
        push_json_u64(&mut s, "handshakes_failed", self.handshakes_failed, false);
        push_json_u64(&mut s, "handshake_timeouts", self.handshake_timeouts, false);
        push_json_u64(
            &mut s,
            "handshake_budget_rejected",
            self.handshake_budget_rejected,
            false,
        );
        push_json_u64(&mut s, "rate_limited", self.rate_limited, false);
        push_json_u64(
            &mut s,
            "conn_limit_rejected",
            self.conn_limit_rejected,
            false,
        );
        push_json_u64(&mut s, "firewall_denied", self.firewall_denied, false);
        push_json_u64(&mut s, "user_rate_rejected", self.user_rate_rejected, false);
        push_json_u64(&mut s, "cover_forwards", self.cover_forwards, false);
        push_json_u64(
            &mut s,
            "probe_anomalies_fired",
            self.probe_anomalies_fired,
            false,
        );
        push_json_u64(
            &mut s,
            "probe_anomaly_tracked",
            self.probe_anomaly_tracked,
            false,
        );
        push_json_u64(
            &mut s,
            "probe_anomaly_dropped_inserts",
            self.probe_anomaly_dropped_inserts,
            false,
        );
        // Recent-fires ring as a JSON array. Always emit (even when
        // empty) so scripts can rely on the key's presence. Sorted
        // freshest-first to match the text-output ordering.
        s.push_str(r#","probe_anomaly_recent":["#);
        let mut sorted = self.probe_anomaly_recent.clone();
        sorted.sort_by_key(|r| r.secs_ago);
        let mut first = true;
        for fire in &sorted {
            if !first {
                s.push(',');
            }
            first = false;
            s.push_str(r#"{"prefix":""#);
            json_escape_str(&fire.prefix, &mut s);
            s.push_str(r#"","secs_ago":"#);
            s.push_str(&fire.secs_ago.to_string());
            s.push('}');
        }
        s.push(']');
        // Auto-deny flat counters + per-entry array.
        push_json_u64(&mut s, "auto_deny_active", self.auto_deny_active, false);
        push_json_u64(
            &mut s,
            "auto_deny_inserted_total",
            self.auto_deny_inserted_total,
            false,
        );
        push_json_u64(
            &mut s,
            "auto_deny_refused_inserts_total",
            self.auto_deny_refused_inserts_total,
            false,
        );
        // auto_deny_entries as a JSON array sorted soonest-to-expire
        // first. Always emit (even when empty) so scripts can rely
        // on the key's presence.
        s.push_str(r#","auto_deny_entries":["#);
        let mut sorted = self.auto_deny_entries.clone();
        sorted.sort_by_key(|d| d.expires_in_secs);
        let mut first = true;
        for d in &sorted {
            if !first {
                s.push(',');
            }
            first = false;
            s.push_str(r#"{"prefix":""#);
            json_escape_str(&d.prefix, &mut s);
            s.push_str(r#"","expires_in_secs":"#);
            s.push_str(&d.expires_in_secs.to_string());
            s.push('}');
        }
        s.push(']');
        // TLS observability — leaf cert expiry + reload-counters.
        // Emit `null` when the field is absent (TLS not configured OR
        // startup path bypassed the v3 acceptor wiring) so scripts
        // can distinguish "not configured" from "zero/expired" with
        // `(.tls_cert_not_after_unix // 0) > 0` style guards.
        s.push_str(r#","tls_cert_not_after_unix":"#);
        match self.tls_cert_not_after_unix {
            Some(ts) => s.push_str(&ts.to_string()),
            None => s.push_str("null"),
        }
        s.push_str(r#","tls_reload_attempts":"#);
        match self.tls_reload_attempts {
            Some(v) => s.push_str(&v.to_string()),
            None => s.push_str("null"),
        }
        s.push_str(r#","tls_reload_succeeded":"#);
        match self.tls_reload_succeeded {
            Some(v) => s.push_str(&v.to_string()),
            None => s.push_str("null"),
        }
        // SIGHUP reload counters for firewall + rate limits.
        // Always present as concrete u64 (zero-valued at startup);
        // operators script `attempts - succeeded > 0` to alert on
        // silent SIGHUP failures the same way they would for the
        // existing TLS reload counters above.
        push_json_u64(
            &mut s,
            "firewall_reload_attempts",
            self.firewall_reload_attempts,
            false,
        );
        push_json_u64(
            &mut s,
            "firewall_reload_succeeded",
            self.firewall_reload_succeeded,
            false,
        );
        push_json_u64(
            &mut s,
            "rate_limit_reload_attempts",
            self.rate_limit_reload_attempts,
            false,
        );
        push_json_u64(
            &mut s,
            "rate_limit_reload_succeeded",
            self.rate_limit_reload_succeeded,
            false,
        );
        push_json_u64(
            &mut s,
            "user_rate_limit_reload_attempts",
            self.user_rate_limit_reload_attempts,
            false,
        );
        push_json_u64(
            &mut s,
            "user_rate_limit_reload_succeeded",
            self.user_rate_limit_reload_succeeded,
            false,
        );
        push_json_u64(
            &mut s,
            "handshake_budget_reload_attempts",
            self.handshake_budget_reload_attempts,
            false,
        );
        push_json_u64(
            &mut s,
            "handshake_budget_reload_succeeded",
            self.handshake_budget_reload_succeeded,
            false,
        );
        // Config-presence snapshot — operators script
        // `.config_active_sections | contains(["firewall"])` to
        // assert the deployed config shape.
        s.push_str(r#","config_active_sections":["#);
        let mut first = true;
        for sec in &self.config_active_sections {
            if !first {
                s.push(',');
            }
            first = false;
            s.push('"');
            json_escape_str(sec, &mut s);
            s.push('"');
        }
        s.push(']');
        push_json_u64(
            &mut s,
            "config_cover_endpoint_pool_size",
            self.config_cover_endpoint_pool_size,
            false,
        );
        push_json_u64(
            &mut s,
            "config_client_allowlist_size",
            self.config_client_allowlist_size,
            false,
        );
        // Process-lifecycle: Option<u64> emitted as JSON null when
        // the metrics endpoint didn't expose them (old server / non-
        // v5 path). Scripts use `(.process_uptime_seconds // 0)` to
        // gate.
        s.push_str(r#","process_start_unix_seconds":"#);
        match self.process_start_unix_seconds {
            Some(v) => s.push_str(&v.to_string()),
            None => s.push_str("null"),
        }
        s.push_str(r#","process_uptime_seconds":"#);
        match self.process_uptime_seconds {
            Some(v) => s.push_str(&v.to_string()),
            None => s.push_str("null"),
        }
        s.push_str(r#","process_build_info":"#);
        match &self.process_build_info {
            Some(bi) => {
                s.push_str(r#"{"version":""#);
                json_escape_str(&bi.version, &mut s);
                s.push_str(r#"","rustc":""#);
                json_escape_str(&bi.rustc, &mut s);
                s.push_str(r#"","target":""#);
                json_escape_str(&bi.target, &mut s);
                s.push_str(r#""}"#);
            }
            None => s.push_str("null"),
        }
        push_json_u64(&mut s, "total_rejected", self.total_rejected(), false);
        push_json_u64(&mut s, "tx_bytes", self.tx_bytes, false);
        push_json_u64(&mut s, "rx_bytes", self.rx_bytes, false);
        push_json_u64(&mut s, "aead_drops", self.aead_drops, false);
        push_json_u64(&mut s, "ratchets", self.ratchets, false);
        push_json_u64(
            &mut s,
            "session_idle_reaped",
            self.session_idle_reaped,
            false,
        );
        push_json_u64(
            &mut s,
            "session_byte_budget_exhausted",
            self.session_byte_budget_exhausted,
            false,
        );

        // Always emit the "other" object so scripts can rely on its
        // presence regardless of which extra counters happen to be
        // present.
        s.push_str(r#","other":{"#);
        let mut first = true;
        for (k, v) in &self.other {
            if !first {
                s.push(',');
            }
            first = false;
            s.push('"');
            json_escape_str(k, &mut s);
            s.push_str("\":");
            s.push_str(&v.to_string());
        }
        s.push('}');

        s.push('}');
        s.push('\n');
        s
    }
}

impl fmt::Display for MetricsSnapshot {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let live_marker = if self.up == 1 { "LIVE" } else { "DOWN" };
        let ready_marker = if self.ready == 1 { "READY" } else { "DRAINING" };
        writeln!(
            f,
            "============================================================"
        )?;
        writeln!(f, " proteus-server status — {live_marker} / {ready_marker}",)?;
        writeln!(
            f,
            "============================================================"
        )?;

        macro_rules! row {
            ($label:expr, $value:expr) => {
                writeln!(f, "  {:<32} {}", $label, $value)
            };
        }

        writeln!(f, " Sessions")?;
        row!("in_flight_sessions", self.in_flight_sessions)?;
        row!("sessions_accepted_total", self.sessions_accepted)?;
        row!("handshakes_succeeded_total", self.handshakes_succeeded)?;
        row!("handshakes_failed_total", self.handshakes_failed)?;
        row!("handshake_timeouts_total", self.handshake_timeouts)?;
        writeln!(f)?;

        writeln!(f, " Defense pipeline (rejections)")?;
        row!("firewall_denied", self.firewall_denied)?;
        row!("handshake_budget_rejected", self.handshake_budget_rejected)?;
        row!("rate_limited", self.rate_limited)?;
        row!("conn_limit_rejected", self.conn_limit_rejected)?;
        row!("user_rate_rejected", self.user_rate_rejected)?;
        row!("cover_forwards", self.cover_forwards)?;
        row!("probe_anomalies_fired", self.probe_anomalies_fired)?;
        row!("total_rejected", self.total_rejected())?;
        writeln!(f)?;

        // Probe-anomaly diagnostic block. Only printed when the
        // operator has actually wired the detector (tracked > 0 OR
        // a fire has been recorded). Keeps the default snapshot
        // compact for the common case where the detector is inactive.
        if self.probe_anomalies_fired > 0
            || self.probe_anomaly_tracked > 0
            || !self.probe_anomaly_recent.is_empty()
        {
            writeln!(f, " Probe-anomaly diagnostics")?;
            row!("tracked_prefixes_gauge", self.probe_anomaly_tracked)?;
            row!("dropped_inserts_total", self.probe_anomaly_dropped_inserts)?;
            if self.probe_anomaly_recent.is_empty() {
                row!("recent_fires", "(none in ring)")?;
            } else {
                writeln!(
                    f,
                    "  recent_fires ({} entries, freshest first):",
                    self.probe_anomaly_recent.len()
                )?;
                // Sort by secs_ago ascending = freshest first. Operators
                // care most about the just-fired prefixes for IR.
                let mut sorted = self.probe_anomaly_recent.clone();
                sorted.sort_by_key(|r| r.secs_ago);
                for fire in sorted.iter().take(20) {
                    writeln!(f, "    {} fired {}s ago", fire.prefix, fire.secs_ago,)?;
                }
                if sorted.len() > 20 {
                    writeln!(
                        f,
                        "    … ({} more — query Prometheus `topk(N, \
                         proteus_probe_anomaly_recent_secs)` for the full list)",
                        sorted.len() - 20
                    )?;
                }
            }
            writeln!(f)?;
        }

        // Auto-deny diagnostic block — operator-opt-in via
        // `probe_anomaly.autodeny_minutes > 0`. Only printed when
        // the surface is actively in use (active > 0 OR a refused
        // insert has happened OR any inserts have been recorded).
        // Quiet by default for the alert-only configuration.
        if self.auto_deny_active > 0
            || self.auto_deny_inserted_total > 0
            || self.auto_deny_refused_inserts_total > 0
        {
            writeln!(f, " Auto-deny list (operator-opt-in)")?;
            row!("active_prefixes_gauge", self.auto_deny_active)?;
            row!("inserted_total", self.auto_deny_inserted_total)?;
            row!(
                "refused_inserts_total",
                self.auto_deny_refused_inserts_total
            )?;
            if self.auto_deny_entries.is_empty() {
                row!("active_entries", "(none — all expired)")?;
            } else {
                writeln!(
                    f,
                    "  active_entries ({} prefixes, soonest-to-expire first):",
                    self.auto_deny_entries.len()
                )?;
                // Sort by expires_in_secs ascending so the entries
                // about to heal appear first (most relevant for
                // operator triage).
                let mut sorted = self.auto_deny_entries.clone();
                sorted.sort_by_key(|d| d.expires_in_secs);
                for d in sorted.iter().take(20) {
                    writeln!(f, "    {} expires in {}s", d.prefix, d.expires_in_secs,)?;
                }
                if sorted.len() > 20 {
                    writeln!(
                        f,
                        "    … ({} more — query Prometheus `proteus_auto_deny_remaining_secs` for the full list)",
                        sorted.len() - 20
                    )?;
                }
            }
            writeln!(f)?;
        }

        // TLS observability block — leaf cert expiry + reload-counter
        // delta. Quiet when TLS isn't configured (all three Option
        // fields are None) so unrelated deployments (LAN test rigs)
        // don't get a confusing empty section.
        if self.tls_cert_not_after_unix.is_some()
            || self.tls_reload_attempts.is_some()
            || self.tls_reload_succeeded.is_some()
        {
            writeln!(f, " TLS cert")?;
            if let Some(ts) = self.tls_cert_not_after_unix {
                // Wall-clock comparison: positive ⇒ days until expiry;
                // negative ⇒ already expired (urgent). We compute it
                // at render time so the snapshot stays a pure data
                // structure (no embedded SystemTime).
                let now = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .map(|d| d.as_secs() as i64)
                    .unwrap_or(0);
                let days = (ts - now) / 86_400;
                let label = if days < 0 {
                    format!("{ts} (EXPIRED {} days ago)", -days)
                } else if days < 14 {
                    format!("{ts} (expires in {days}d — RENEW NOW)")
                } else {
                    format!("{ts} (expires in {days}d)")
                };
                row!("not_after_unix_seconds", label)?;
            }
            if let (Some(att), Some(suc)) = (self.tls_reload_attempts, self.tls_reload_succeeded) {
                let failed = att.saturating_sub(suc);
                let label = if failed > 0 {
                    format!("{att} ({suc} ok, {failed} failed — check journalctl for parse errors)")
                } else {
                    format!("{att} ({suc} ok)")
                };
                row!("reload_attempts_total", label)?;
            }
            writeln!(f)?;
        }

        // SIGHUP reload block for firewall + 3 rate-limit sections.
        // Quiet-by-default: only rendered after the first SIGHUP so
        // operators who never use SIGHUP don't see noise. Each pair
        // formats as `attempts (succeeded ok[, failed missing])`
        // where "missing" means the operator SIGHUPed but the
        // section either isn't in config OR the matching limiter
        // wasn't installed at startup (= silent reload failure).
        let any_reload = self.firewall_reload_attempts
            + self.rate_limit_reload_attempts
            + self.user_rate_limit_reload_attempts
            + self.handshake_budget_reload_attempts
            > 0;
        if any_reload {
            writeln!(f, " SIGHUP reloads")?;
            for (label, att, suc) in [
                (
                    "firewall",
                    self.firewall_reload_attempts,
                    self.firewall_reload_succeeded,
                ),
                (
                    "rate_limit",
                    self.rate_limit_reload_attempts,
                    self.rate_limit_reload_succeeded,
                ),
                (
                    "user_rate_limit",
                    self.user_rate_limit_reload_attempts,
                    self.user_rate_limit_reload_succeeded,
                ),
                (
                    "handshake_budget",
                    self.handshake_budget_reload_attempts,
                    self.handshake_budget_reload_succeeded,
                ),
            ] {
                if att == 0 && suc == 0 {
                    continue;
                }
                let missing = att.saturating_sub(suc);
                let cell = if missing > 0 {
                    format!("{att} ({suc} ok, {missing} missing — section not in config OR no limiter installed at startup)")
                } else {
                    format!("{att} ({suc} ok)")
                };
                row!(label, cell)?;
            }
            writeln!(f)?;
        }

        // Config-presence section. Quiet by default — only rendered
        // when the metrics endpoint included the
        // `proteus_config_section_active{...}` series (= the server
        // is new enough AND was wired with the v4 metrics endpoint).
        if !self.config_active_sections.is_empty()
            || self.config_cover_endpoint_pool_size > 0
            || self.config_client_allowlist_size > 0
        {
            writeln!(f, " Active config sections")?;
            let mut secs: Vec<&str> = self
                .config_active_sections
                .iter()
                .map(String::as_str)
                .collect();
            secs.sort_unstable();
            if secs.is_empty() {
                row!("sections", "(none)")?;
            } else {
                row!("sections", secs.join(", "))?;
            }
            row!(
                "cover_endpoint_pool_size",
                self.config_cover_endpoint_pool_size
            )?;
            row!("client_allowlist_size", self.config_client_allowlist_size)?;
            writeln!(f)?;
        }

        // Process-lifecycle block. Quiet by default (older server
        // scrapes); when ANY of the three fields is present, render
        // the whole block. Uptime is computed at scrape time on the
        // server so the rendered value is from that moment — we
        // don't subtract again here.
        if self.process_start_unix_seconds.is_some()
            || self.process_uptime_seconds.is_some()
            || self.process_build_info.is_some()
        {
            writeln!(f, " Process")?;
            if let Some(ts) = self.process_start_unix_seconds {
                row!("start_unix_seconds", ts)?;
            }
            if let Some(up) = self.process_uptime_seconds {
                let h = up / 3600;
                let m = (up % 3600) / 60;
                let sec = up % 60;
                row!("uptime", format!("{up}s ({h}h {m}m {sec}s)"))?;
            }
            if let Some(bi) = &self.process_build_info {
                row!(
                    "build",
                    format!(
                        "version={} rustc={} target={}",
                        if bi.version.is_empty() {
                            "(unset)"
                        } else {
                            &bi.version
                        },
                        if bi.rustc.is_empty() {
                            "(unset)"
                        } else {
                            &bi.rustc
                        },
                        if bi.target.is_empty() {
                            "(unset)"
                        } else {
                            &bi.target
                        }
                    )
                )?;
            }
            writeln!(f)?;
        }

        writeln!(f, " Session teardown causes")?;
        row!("session_idle_reaped", self.session_idle_reaped)?;
        row!(
            "session_byte_budget_exhausted",
            self.session_byte_budget_exhausted
        )?;
        writeln!(f)?;

        writeln!(f, " Throughput")?;
        row!(
            "tx_bytes_total",
            format!("{} ({})", self.tx_bytes, human_bytes(self.tx_bytes))
        )?;
        row!(
            "rx_bytes_total",
            format!("{} ({})", self.rx_bytes, human_bytes(self.rx_bytes))
        )?;
        row!("ratchets_total", self.ratchets)?;
        row!("aead_drops_total", self.aead_drops)?;

        if !self.other.is_empty() {
            writeln!(f)?;
            writeln!(f, " Other (unrecognized counters)")?;
            for (k, v) in &self.other {
                row!(k.as_str(), v)?;
            }
        }
        writeln!(
            f,
            "============================================================"
        )?;
        Ok(())
    }
}

/// Render `n` as `"X.YZ unit"` (KiB/MiB/GiB/TiB). Duplicated from
/// the startup module to keep this file dep-free; admin CLI ships
/// as a separate code path.
fn human_bytes(n: u64) -> String {
    const KIB: u64 = 1024;
    const MIB: u64 = 1024 * KIB;
    const GIB: u64 = 1024 * MIB;
    const TIB: u64 = 1024 * GIB;
    if n >= TIB {
        format!("{:.2} TiB", n as f64 / TIB as f64)
    } else if n >= GIB {
        format!("{:.2} GiB", n as f64 / GIB as f64)
    } else if n >= MIB {
        format!("{:.2} MiB", n as f64 / MIB as f64)
    } else if n >= KIB {
        format!("{:.2} KiB", n as f64 / KIB as f64)
    } else {
        format!("{n} B")
    }
}

/// Errors surfaced by the `status` HTTP client.
#[derive(Debug, thiserror::Error)]
pub enum AdminError {
    #[error("URL must look like http://host:port/path, got {0:?}")]
    BadUrl(String),
    #[error("resolve {0:?}: {1}")]
    Resolve(String, std::io::Error),
    #[error("token file {0:?}: {1}")]
    Token(String, std::io::Error),
    #[error("connect {0}: {1}")]
    Connect(SocketAddr, std::io::Error),
    #[error("write: {0}")]
    Write(std::io::Error),
    #[error("read: {0}")]
    Read(std::io::Error),
    #[error("HTTP status {0}: {1}")]
    Status(u16, String),
    #[error("response missing body")]
    NoBody,
}

/// Read a bearer token from `path`. Strips trailing newline +
/// whitespace; rejects empty.
pub fn read_token_file(path: &Path) -> Result<String, AdminError> {
    let raw = std::fs::read_to_string(path)
        .map_err(|e| AdminError::Token(path.display().to_string(), e))?;
    let token = raw.trim().to_string();
    if token.is_empty() {
        return Err(AdminError::Token(
            path.display().to_string(),
            std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "token file is empty after trimming whitespace",
            ),
        ));
    }
    // Iter-155: reject control bytes embedded inside the token
    // (after trim already stripped leading/trailing whitespace).
    // Belt-and-braces with the iter-154 `http_get` runtime gate +
    // the iter-154 validate-time gate. Catches the case where a
    // caller (future / third-party) reads the token via this
    // helper but DOES NOT pipe it through `http_get` (e.g. a new
    // RPC mechanism). Centralizes the "tokens never contain
    // control bytes" invariant at the single I/O surface.
    if token
        .bytes()
        .any(|b| b == 0 || b == b'\r' || b == b'\n' || b == b'\t')
    {
        return Err(AdminError::Token(
            path.display().to_string(),
            std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "token contains a control byte (NUL / CR / LF / TAB) — \
                 HTTP request smuggling defense-in-depth. Regenerate \
                 with `openssl rand -base64 24 > {path}`.",
            ),
        ));
    }
    Ok(token)
}

/// Parse one `proteus_probe_anomaly_recent_secs{prefix="..."}` line
/// into a `ProbeAnomalyRecentFire`. Returns `None` for any other
/// labelled line so the caller can quietly skip it.
///
/// Robust to whitespace variations and the small Prometheus quoting
/// rules (we only ever emit `"…"` values without internal quotes/
/// backslashes, so the parser doesn't need to handle escape
/// sequences).
fn parse_probe_anomaly_recent(name: &str, value: &str) -> Option<ProbeAnomalyRecentFire> {
    let metric_prefix = "proteus_probe_anomaly_recent_secs{";
    let (prefix, secs) = parse_labelled_prefix(name, value, metric_prefix)?;
    Some(ProbeAnomalyRecentFire {
        prefix,
        secs_ago: secs,
    })
}

/// Parse one `proteus_auto_deny_remaining_secs{prefix="..."}` line
/// into an `AutoDenyEntry`. Same shape as `parse_probe_anomaly_recent`
/// — different metric name + different output field. Both share the
/// `parse_labelled_prefix` helper so a parser fix only has to land
/// in one place.
fn parse_auto_deny_remaining(name: &str, value: &str) -> Option<AutoDenyEntry> {
    let metric_prefix = "proteus_auto_deny_remaining_secs{";
    let (prefix, secs) = parse_labelled_prefix(name, value, metric_prefix)?;
    Some(AutoDenyEntry {
        prefix,
        expires_in_secs: secs,
    })
}

/// Parse one `proteus_build_info{version="…",rustc="…",target="…"} 1`
/// line. Returns `None` for non-matching names or malformed labels.
/// Tolerates missing labels (sets the corresponding field to "") so
/// a server that only knows `version` still produces a usable
/// snapshot.
fn parse_build_info(name: &str, _value: &str) -> Option<BuildInfo> {
    let metric_prefix = "proteus_build_info{";
    let rest = name.strip_prefix(metric_prefix)?;
    let rest = rest.strip_suffix('}')?;
    let mut bi = BuildInfo::default();
    // Labels are `key="value"` pairs separated by `,`. Split on `,`
    // OUTSIDE quotes; emitter output is well-formed so simple split
    // suffices.
    for pair in rest.split(',') {
        let (k, v) = pair.split_once('=')?;
        let k = k.trim();
        let v = v.trim().strip_prefix('"')?.strip_suffix('"')?;
        match k {
            "version" => bi.version = v.to_string(),
            "rustc" => bi.rustc = v.to_string(),
            "target" => bi.target = v.to_string(),
            _ => {} // ignore unknown labels for forward compat
        }
    }
    Some(bi)
}

/// Parse one `proteus_config_section_active{section="..."} 0|1` line
/// into `(section_name, present)`. Returns `None` for non-matching
/// metric names or malformed labels. The section name is operator-
/// readable text the renderer prints verbatim.
fn parse_config_section_active(name: &str, value: &str) -> Option<(String, bool)> {
    let metric_prefix = "proteus_config_section_active{";
    let rest = name.strip_prefix(metric_prefix)?;
    let rest = rest.strip_suffix('}')?;
    let (k, v) = rest.split_once('=')?;
    if k.trim() != "section" {
        return None;
    }
    let v = v.trim().strip_prefix('"')?;
    let section = v.strip_suffix('"')?.to_string();
    let n: u64 = value.parse().ok()?;
    Some((section, n != 0))
}

/// Shared helper for the two `…{prefix="…"} <u64>` line shapes.
/// Returns `(prefix_string, value_u64)` on success.
fn parse_labelled_prefix(name: &str, value: &str, metric_prefix: &str) -> Option<(String, u64)> {
    let rest = name.strip_prefix(metric_prefix)?;
    let rest = rest.strip_suffix('}')?;
    let (k, v) = rest.split_once('=')?;
    if k.trim() != "prefix" {
        return None;
    }
    let v = v.trim();
    let v = v.strip_prefix('"')?;
    let prefix = v.strip_suffix('"')?.to_string();
    let secs: u64 = value.parse().ok()?;
    Some((prefix, secs))
}

/// Parse a `http://host:port/path` URL into `(host, port, path)`.
/// Deliberately minimal — we accept only `http://` (the metrics
/// endpoint is always plain HTTP; rely on bind-loopback or VPN for
/// confidentiality and bearer for auth, not TLS).
pub fn parse_http_url(url: &str) -> Result<(String, u16, String), AdminError> {
    // Iter-116: actionable error messages for the three common
    // typos that previously got the bare AdminError::BadUrl(url):
    //   - https:// (admin endpoint is HTTP-only, loopback-by-
    //     default; HTTPS isn't supported)
    //   - missing scheme entirely (raw host:port)
    //   - missing explicit port (the runtime needs one; no
    //     default 80 fallback for the admin endpoint)
    if let Some(rest) = url.strip_prefix("https://") {
        let _ = rest; // silence unused warning if any
        return Err(AdminError::BadUrl(format!(
            "{url:?}: admin endpoint is HTTP-only (loopback-by-default; no TLS terminator \
             between the operator and the binary). Use `http://` not `https://`."
        )));
    }
    let rest = url.strip_prefix("http://").ok_or_else(|| {
        AdminError::BadUrl(format!(
            "{url:?}: missing `http://` scheme prefix. Expected `http://host:port[/path]`."
        ))
    })?;
    let (authority, path) = match rest.find('/') {
        Some(idx) => (&rest[..idx], &rest[idx..]),
        None => (rest, "/"),
    };
    let (host, port) = match authority.rsplit_once(':') {
        Some((h, p)) => {
            let port: u16 = p.parse().map_err(|_| {
                AdminError::BadUrl(format!("{url:?}: port {p:?} isn't a valid u16 (1-65535)"))
            })?;
            (h.to_string(), port)
        }
        None => {
            return Err(AdminError::BadUrl(format!(
                "{url:?}: missing explicit `:port` — the admin endpoint has no default port. \
                 Example: `http://127.0.0.1:9090/metrics`."
            )));
        }
    };
    if host.is_empty() {
        return Err(AdminError::BadUrl(format!(
            "{url:?}: host portion is empty (likely `http://:port` without a host)."
        )));
    }
    // Iter-159: reject port 0. Mirrors the iter-158 cover-endpoint
    // port-0 gate + the iter-153 client `parse_host_port` gate.
    // TCP-connect to port 0 fails with EADDRNOTAVAIL on every
    // platform (port 0 is reserved for bind/listen 'any free
    // port'), so an admin URL pointing at port 0 is never a
    // legitimate config — only a placeholder-template typo the
    // bare `u16::parse` accepted silently.
    if port == 0 {
        return Err(AdminError::BadUrl(format!(
            "{url:?}: port 0 is invalid as a TCP-connect target (reserved for bind/listen \
             'any free port')."
        )));
    }
    // Iter-147: reject CRLF / NUL / TAB anywhere in host or path.
    // The host and path get embedded verbatim into the HTTP
    // request line + Host header in `http_get`; without this
    // gate, an operator (or a config-templating tool) that pulls
    // a URL from an untrusted source could inject arbitrary
    // headers into the GET. Same defense-in-depth class as
    // iter-146 on the inner CONNECT path. Probably never
    // triggered in practice (operators hand-type the URL or
    // copy it from the deploy guide) but the absence of any
    // validation was wrong on principle.
    if host
        .bytes()
        .any(|b| b == 0 || b == b'\r' || b == b'\n' || b == b'\t' || b == b' ')
    {
        return Err(AdminError::BadUrl(format!(
            "{url:?}: host contains a forbidden control character (NUL / CR / LF / TAB / space). \
             HTTP request smuggling defense-in-depth — the host is embedded into the \
             Host: header. Strip the offending byte from the --url argument."
        )));
    }
    if path
        .bytes()
        .any(|b| b == 0 || b == b'\r' || b == b'\n' || b == b'\t')
    {
        return Err(AdminError::BadUrl(format!(
            "{url:?}: path contains a forbidden control character (NUL / CR / LF / TAB). \
             HTTP request smuggling defense-in-depth — the path is embedded into the \
             GET request line. Strip the offending byte from the --url argument."
        )));
    }
    Ok((host, port, path.to_string()))
}

/// Synchronous HTTP GET against a `/metrics`-style endpoint. Returns
/// the response body on 200, an [`AdminError::Status`] on anything
/// else. Hand-rolled: no `reqwest` / `ureq` dep needed for one
/// request from inside a CLI.
pub fn http_get(url: &str, token: Option<&str>, timeout: Duration) -> Result<String, AdminError> {
    let (host, port, path) = parse_http_url(url)?;
    // Iter-154: validate the token BEFORE any network I/O so a
    // CRLF-tainted token gets surfaced as a config error, not a
    // connect-refused error. The pre-iter-154 order put this
    // check AFTER TcpStream::connect, which masked the iter-154
    // signal whenever the target host happened to be down.
    if let Some(t) = token {
        if t.bytes().any(|b| b == 0 || b == b'\r' || b == b'\n') {
            return Err(AdminError::BadUrl(
                "supplied admin token contains a control byte (NUL / CR / LF). \
                 The token is embedded into the HTTP Authorization header; a control \
                 byte would smuggle attacker-chosen headers into the request. \
                 Strip the offending byte from the token source (env var / \
                 metrics_token_file / CLI flag)."
                    .to_string(),
            ));
        }
    }
    let addrs = (host.as_str(), port)
        .to_socket_addrs()
        .map_err(|e| AdminError::Resolve(host.clone(), e))?
        .collect::<Vec<_>>();
    let addr = addrs.into_iter().next().ok_or_else(|| {
        AdminError::Resolve(
            host.clone(),
            std::io::Error::new(std::io::ErrorKind::AddrNotAvailable, "no addrs"),
        )
    })?;

    let mut sock =
        TcpStream::connect_timeout(&addr, timeout).map_err(|e| AdminError::Connect(addr, e))?;
    sock.set_read_timeout(Some(timeout)).ok();
    sock.set_write_timeout(Some(timeout)).ok();

    let mut req = format!(
        "GET {path} HTTP/1.1\r\nHost: {host}:{port}\r\nUser-Agent: proteus-admin\r\nConnection: close\r\n",
    );
    if let Some(t) = token {
        use std::fmt::Write as _;
        let _ = write!(&mut req, "Authorization: Bearer {t}\r\n");
    }
    req.push_str("\r\n");
    sock.write_all(req.as_bytes()).map_err(AdminError::Write)?;

    let mut raw = Vec::with_capacity(8192);
    sock.read_to_end(&mut raw).map_err(AdminError::Read)?;
    let text = String::from_utf8_lossy(&raw).into_owned();

    // Split headers / body on the first \r\n\r\n.
    let split = text.find("\r\n\r\n").ok_or(AdminError::NoBody)?;
    let head = &text[..split];
    let body = &text[split + 4..];

    let mut head_lines = head.lines();
    let status_line = head_lines.next().unwrap_or("");
    let status: u16 = status_line
        .split(' ')
        .nth(1)
        .and_then(|s| s.parse().ok())
        .unwrap_or(0);
    if status != 200 {
        return Err(AdminError::Status(status, body.to_string()));
    }
    Ok(body.to_string())
}

/// Top-level driver for the `admin status` subcommand. Fetches
/// `/metrics`, parses, prints. Returns `Ok(())` on success — the
/// caller decides exit code.
pub fn run(
    url: &str,
    token: Option<&str>,
    timeout: Duration,
    format: OutputFormat,
) -> Result<(), Box<dyn std::error::Error>> {
    let body = http_get(url, token, timeout)?;
    let snap = MetricsSnapshot::parse(&body);
    let rendered = match format {
        OutputFormat::Text => snap.to_string(),
        OutputFormat::Json => snap.to_json(),
    };
    let _ = std::io::stdout().write_all(rendered.as_bytes());
    Ok(())
}

/// Counter-delta between two snapshots. Positive numbers only:
/// counters can only go up over time (the gauges `in_flight`, `up`,
/// `ready` are absolute values, not deltas — we surface them as
/// `now: N` instead).
///
/// "After minus before" semantics. A negative would mean the counter
/// reset between scrapes (process restart); we saturate-clamp to 0
/// and surface a banner warning.
#[derive(Debug, Default, Clone)]
pub struct MetricsDelta {
    /// Wall-clock seconds between the two scrapes. Used to render
    /// per-second rates ("3 rejected/s").
    pub interval_secs: f64,
    pub sessions_accepted: u64,
    pub handshakes_succeeded: u64,
    pub handshakes_failed: u64,
    pub handshake_timeouts: u64,
    pub handshake_budget_rejected: u64,
    pub rate_limited: u64,
    pub conn_limit_rejected: u64,
    pub firewall_denied: u64,
    pub user_rate_rejected: u64,
    pub cover_forwards: u64,
    pub probe_anomalies_fired: u64,
    pub tx_bytes: u64,
    pub rx_bytes: u64,
    pub aead_drops: u64,
    pub ratchets: u64,
    pub session_idle_reaped: u64,
    pub session_byte_budget_exhausted: u64,
    /// Snapshot at the END of the interval (for gauges).
    pub now_in_flight: u64,
    pub now_up: u64,
    pub now_ready: u64,
    /// True if any counter went DOWN between scrapes — almost
    /// certainly a process restart. Operators want to know.
    pub counter_reset: bool,
}

impl MetricsDelta {
    /// Compute `(b - a)` clamped to non-negative. If `b` is older
    /// than `a` by clock skew the `interval_secs` may be ≤ 0; the
    /// caller can decide whether to render rates.
    #[must_use]
    pub fn between(a: &MetricsSnapshot, b: &MetricsSnapshot, interval_secs: f64) -> Self {
        let mut counter_reset = false;
        // `delta_counter` clamps b<a to 0 and records the reset.
        let delta = |before: u64, after: u64, reset: &mut bool| -> u64 {
            if after < before {
                *reset = true;
                0
            } else {
                after - before
            }
        };
        Self {
            interval_secs,
            sessions_accepted: delta(a.sessions_accepted, b.sessions_accepted, &mut counter_reset),
            handshakes_succeeded: delta(
                a.handshakes_succeeded,
                b.handshakes_succeeded,
                &mut counter_reset,
            ),
            handshakes_failed: delta(a.handshakes_failed, b.handshakes_failed, &mut counter_reset),
            handshake_timeouts: delta(
                a.handshake_timeouts,
                b.handshake_timeouts,
                &mut counter_reset,
            ),
            handshake_budget_rejected: delta(
                a.handshake_budget_rejected,
                b.handshake_budget_rejected,
                &mut counter_reset,
            ),
            rate_limited: delta(a.rate_limited, b.rate_limited, &mut counter_reset),
            conn_limit_rejected: delta(
                a.conn_limit_rejected,
                b.conn_limit_rejected,
                &mut counter_reset,
            ),
            firewall_denied: delta(a.firewall_denied, b.firewall_denied, &mut counter_reset),
            user_rate_rejected: delta(
                a.user_rate_rejected,
                b.user_rate_rejected,
                &mut counter_reset,
            ),
            cover_forwards: delta(a.cover_forwards, b.cover_forwards, &mut counter_reset),
            probe_anomalies_fired: delta(
                a.probe_anomalies_fired,
                b.probe_anomalies_fired,
                &mut counter_reset,
            ),
            tx_bytes: delta(a.tx_bytes, b.tx_bytes, &mut counter_reset),
            rx_bytes: delta(a.rx_bytes, b.rx_bytes, &mut counter_reset),
            aead_drops: delta(a.aead_drops, b.aead_drops, &mut counter_reset),
            ratchets: delta(a.ratchets, b.ratchets, &mut counter_reset),
            session_idle_reaped: delta(
                a.session_idle_reaped,
                b.session_idle_reaped,
                &mut counter_reset,
            ),
            session_byte_budget_exhausted: delta(
                a.session_byte_budget_exhausted,
                b.session_byte_budget_exhausted,
                &mut counter_reset,
            ),
            now_in_flight: b.in_flight_sessions,
            now_up: b.up,
            now_ready: b.ready,
            counter_reset,
        }
    }

    /// Sum of all rejection deltas — one-glance "is anything being
    /// rejected RIGHT NOW?".
    #[must_use]
    pub fn total_rejected(&self) -> u64 {
        self.firewall_denied
            .saturating_add(self.handshake_budget_rejected)
            .saturating_add(self.rate_limited)
            .saturating_add(self.conn_limit_rejected)
            .saturating_add(self.user_rate_rejected)
    }

    /// Render as a single-line JSON document with a trailing newline.
    /// Field names are snake_case and stable across releases. Counter
    /// fields are deltas; gauges (`alive`, `ready`, `in_flight`) are
    /// end-of-interval values. `interval_secs` is the wall-clock
    /// width of the window; `counter_reset` is a bool flag.
    #[must_use]
    pub fn to_json(&self) -> String {
        let mut s = String::with_capacity(512);
        s.push('{');
        // Interval / state up front so a one-line jq is readable.
        push_json_f64(&mut s, "interval_secs", self.interval_secs, true);
        push_json_bool(&mut s, "alive", self.now_up == 1, false);
        push_json_bool(&mut s, "ready", self.now_ready == 1, false);
        push_json_bool(&mut s, "counter_reset", self.counter_reset, false);
        push_json_u64(&mut s, "in_flight_sessions", self.now_in_flight, false);
        // Counter deltas.
        push_json_u64(&mut s, "sessions_accepted", self.sessions_accepted, false);
        push_json_u64(
            &mut s,
            "handshakes_succeeded",
            self.handshakes_succeeded,
            false,
        );
        push_json_u64(&mut s, "handshakes_failed", self.handshakes_failed, false);
        push_json_u64(&mut s, "handshake_timeouts", self.handshake_timeouts, false);
        push_json_u64(
            &mut s,
            "handshake_budget_rejected",
            self.handshake_budget_rejected,
            false,
        );
        push_json_u64(&mut s, "rate_limited", self.rate_limited, false);
        push_json_u64(
            &mut s,
            "conn_limit_rejected",
            self.conn_limit_rejected,
            false,
        );
        push_json_u64(&mut s, "firewall_denied", self.firewall_denied, false);
        push_json_u64(&mut s, "user_rate_rejected", self.user_rate_rejected, false);
        push_json_u64(&mut s, "cover_forwards", self.cover_forwards, false);
        push_json_u64(
            &mut s,
            "probe_anomalies_fired",
            self.probe_anomalies_fired,
            false,
        );
        push_json_u64(&mut s, "total_rejected", self.total_rejected(), false);
        push_json_u64(&mut s, "tx_bytes", self.tx_bytes, false);
        push_json_u64(&mut s, "rx_bytes", self.rx_bytes, false);
        push_json_u64(&mut s, "aead_drops", self.aead_drops, false);
        push_json_u64(&mut s, "ratchets", self.ratchets, false);
        push_json_u64(
            &mut s,
            "session_idle_reaped",
            self.session_idle_reaped,
            false,
        );
        push_json_u64(
            &mut s,
            "session_byte_budget_exhausted",
            self.session_byte_budget_exhausted,
            false,
        );
        s.push('}');
        s.push('\n');
        s
    }
}

// ---- minimal hand-rolled JSON emitter helpers ----

fn push_json_u64(out: &mut String, key: &str, value: u64, first: bool) {
    if !first {
        out.push(',');
    }
    out.push('"');
    out.push_str(key);
    out.push_str("\":");
    out.push_str(&value.to_string());
}

fn push_json_bool(out: &mut String, key: &str, value: bool, first: bool) {
    if !first {
        out.push(',');
    }
    out.push('"');
    out.push_str(key);
    out.push_str("\":");
    out.push_str(if value { "true" } else { "false" });
}

fn push_json_f64(out: &mut String, key: &str, value: f64, first: bool) {
    if !first {
        out.push(',');
    }
    out.push('"');
    out.push_str(key);
    out.push_str("\":");
    // NaN/Inf are not valid JSON. Map them to 0 so the output is
    // always a parseable JSON document.
    if value.is_finite() {
        // {:.3} keeps three decimal places; trailing zeros are harmless
        // to consumers but stable across runs.
        use std::fmt::Write as _;
        let _ = write!(out, "{value:.3}");
    } else {
        out.push('0');
    }
}

fn json_escape_str(s: &str, out: &mut String) {
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if (c as u32) < 0x20 => {
                use std::fmt::Write as _;
                let _ = write!(out, "\\u{:04x}", c as u32);
            }
            c => out.push(c),
        }
    }
}

impl fmt::Display for MetricsDelta {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let live_marker = if self.now_up == 1 { "LIVE" } else { "DOWN" };
        let ready_marker = if self.now_ready == 1 {
            "READY"
        } else {
            "DRAINING"
        };
        writeln!(
            f,
            "============================================================"
        )?;
        writeln!(
            f,
            " proteus-server delta over {:.1}s — {live_marker} / {ready_marker}",
            self.interval_secs,
        )?;
        writeln!(
            f,
            "============================================================"
        )?;
        if self.counter_reset {
            writeln!(
                f,
                " ⚠  counter reset detected between scrapes — likely a process restart"
            )?;
            writeln!(
                f,
                "------------------------------------------------------------"
            )?;
        }

        let interval = if self.interval_secs <= 0.0 {
            1.0
        } else {
            self.interval_secs
        };

        macro_rules! row_rate {
            ($label:expr, $value:expr) => {{
                let rate = $value as f64 / interval;
                writeln!(f, "  {:<32} {:>9} ({:>6.2}/s)", $label, $value, rate)
            }};
        }
        macro_rules! row {
            ($label:expr, $value:expr) => {
                writeln!(f, "  {:<32} {}", $label, $value)
            };
        }

        writeln!(f, " Sessions (delta)")?;
        row!("in_flight_sessions (gauge)", self.now_in_flight)?;
        row_rate!("sessions_accepted", self.sessions_accepted)?;
        row_rate!("handshakes_succeeded", self.handshakes_succeeded)?;
        row_rate!("handshakes_failed", self.handshakes_failed)?;
        row_rate!("handshake_timeouts", self.handshake_timeouts)?;
        writeln!(f)?;

        writeln!(f, " Defense pipeline (rejections delta)")?;
        row_rate!("firewall_denied", self.firewall_denied)?;
        row_rate!("handshake_budget_rejected", self.handshake_budget_rejected)?;
        row_rate!("rate_limited", self.rate_limited)?;
        row_rate!("conn_limit_rejected", self.conn_limit_rejected)?;
        row_rate!("user_rate_rejected", self.user_rate_rejected)?;
        row_rate!("cover_forwards", self.cover_forwards)?;
        row_rate!("probe_anomalies_fired", self.probe_anomalies_fired)?;
        row_rate!("total_rejected", self.total_rejected())?;
        writeln!(f)?;

        writeln!(f, " Session teardown (delta)")?;
        row_rate!("session_idle_reaped", self.session_idle_reaped)?;
        row_rate!(
            "session_byte_budget_exhausted",
            self.session_byte_budget_exhausted
        )?;
        writeln!(f)?;

        writeln!(f, " Throughput (delta)")?;
        let tx_rate = self.tx_bytes as f64 / interval;
        let rx_rate = self.rx_bytes as f64 / interval;
        writeln!(
            f,
            "  {:<32} {:>9} ({}/s)",
            "tx_bytes",
            self.tx_bytes,
            human_bytes_rate(tx_rate)
        )?;
        writeln!(
            f,
            "  {:<32} {:>9} ({}/s)",
            "rx_bytes",
            self.rx_bytes,
            human_bytes_rate(rx_rate)
        )?;
        row_rate!("ratchets", self.ratchets)?;
        row_rate!("aead_drops", self.aead_drops)?;
        writeln!(
            f,
            "============================================================"
        )?;
        Ok(())
    }
}

fn human_bytes_rate(per_sec: f64) -> String {
    const KIB: f64 = 1024.0;
    const MIB: f64 = 1024.0 * KIB;
    const GIB: f64 = 1024.0 * MIB;
    if per_sec >= GIB {
        format!("{:.2} GiB", per_sec / GIB)
    } else if per_sec >= MIB {
        format!("{:.2} MiB", per_sec / MIB)
    } else if per_sec >= KIB {
        format!("{:.2} KiB", per_sec / KIB)
    } else {
        format!("{per_sec:.1} B")
    }
}

/// Driver for `admin diff` — read two saved exposition bodies from
/// disk, compute the delta, print. Both files are expected to be
/// the raw `/metrics` text; the operator captures them with e.g.
/// `proteus-server admin status --raw > /tmp/before` (we don't ship
/// `--raw` today but `curl` works fine).
pub fn run_diff(
    a_path: &Path,
    b_path: &Path,
    interval_secs: f64,
    format: OutputFormat,
) -> Result<(), Box<dyn std::error::Error>> {
    let a_text = std::fs::read_to_string(a_path).map_err(|e| format!("read {a_path:?}: {e}"))?;
    let b_text = std::fs::read_to_string(b_path).map_err(|e| format!("read {b_path:?}: {e}"))?;
    let a = MetricsSnapshot::parse(&a_text);
    let b = MetricsSnapshot::parse(&b_text);
    let d = MetricsDelta::between(&a, &b, interval_secs);
    let rendered = match format {
        OutputFormat::Text => d.to_string(),
        OutputFormat::Json => d.to_json(),
    };
    let _ = std::io::stdout().write_all(rendered.as_bytes());
    Ok(())
}

/// Driver for `admin watch` — loop forever scraping `/metrics` at
/// `interval`, printing deltas between successive scrapes. The
/// FIRST iteration prints the absolute snapshot (no delta source);
/// subsequent iterations print the delta. Ctrl-C exits cleanly.
pub fn run_watch(
    url: &str,
    token: Option<&str>,
    timeout: Duration,
    interval: Duration,
    format: OutputFormat,
) -> Result<(), Box<dyn std::error::Error>> {
    let mut prev: Option<(MetricsSnapshot, std::time::Instant)> = None;
    loop {
        let body = http_get(url, token, timeout)?;
        let now = std::time::Instant::now();
        let cur = MetricsSnapshot::parse(&body);
        // ANSI clear-screen + cursor-home, so `watch`-like output
        // doesn't accumulate. Skipped for JSON (pipes/jq would
        // record the escape codes) and when stdout isn't a TTY.
        if format == OutputFormat::Text && is_tty_stdout() {
            let _ = std::io::stdout().write_all(b"\x1b[2J\x1b[H");
        }
        let rendered = match (&prev, format) {
            (None, OutputFormat::Text) => cur.to_string(),
            (None, OutputFormat::Json) => cur.to_json(),
            (Some((before, t0)), OutputFormat::Text) => {
                let secs = now.duration_since(*t0).as_secs_f64();
                MetricsDelta::between(before, &cur, secs).to_string()
            }
            (Some((before, t0)), OutputFormat::Json) => {
                let secs = now.duration_since(*t0).as_secs_f64();
                MetricsDelta::between(before, &cur, secs).to_json()
            }
        };
        let _ = std::io::stdout().write_all(rendered.as_bytes());
        prev = Some((cur, now));
        std::thread::sleep(interval);
    }
}

fn is_tty_stdout() -> bool {
    // Conservative check: `cargo test` captures stdout, and CI is
    // usually non-TTY. We use `IsTerminal` from std (1.70+) which is
    // already MSRV-clean.
    use std::io::IsTerminal;
    std::io::stdout().is_terminal()
}

#[cfg(test)]
mod tests {
    use super::*;

    const SAMPLE: &str = "\
# HELP proteus_up Server alive.
# TYPE proteus_up gauge
proteus_up 1
# HELP proteus_ready Server ready.
# TYPE proteus_ready gauge
proteus_ready 1
# HELP proteus_in_flight_sessions In-flight sessions.
# TYPE proteus_in_flight_sessions gauge
proteus_in_flight_sessions 7
proteus_sessions_accepted_total 100
proteus_handshakes_succeeded_total 95
proteus_handshakes_failed_total 5
proteus_handshake_timeouts_total 2
proteus_handshake_budget_rejected_total 3
proteus_rate_limited_total 11
proteus_conn_limit_rejected_total 13
proteus_firewall_denied_total 17
proteus_user_rate_rejected_total 19
proteus_cover_forwards_total 23
proteus_tx_bytes_total 1048576
proteus_rx_bytes_total 2097152
proteus_aead_drops_total 0
proteus_ratchets_total 31
proteus_session_idle_reaped_total 37
proteus_session_byte_budget_exhausted_total 41
proteus_some_future_counter_total 43
";

    #[test]
    fn parse_recognizes_every_known_counter() {
        let s = MetricsSnapshot::parse(SAMPLE);
        assert_eq!(s.up, 1);
        assert_eq!(s.ready, 1);
        assert_eq!(s.in_flight_sessions, 7);
        assert_eq!(s.sessions_accepted, 100);
        assert_eq!(s.handshakes_succeeded, 95);
        assert_eq!(s.handshakes_failed, 5);
        assert_eq!(s.handshake_timeouts, 2);
        assert_eq!(s.handshake_budget_rejected, 3);
        assert_eq!(s.rate_limited, 11);
        assert_eq!(s.conn_limit_rejected, 13);
        assert_eq!(s.firewall_denied, 17);
        assert_eq!(s.user_rate_rejected, 19);
        assert_eq!(s.cover_forwards, 23);
        assert_eq!(s.tx_bytes, 1_048_576);
        assert_eq!(s.rx_bytes, 2_097_152);
        assert_eq!(s.aead_drops, 0);
        assert_eq!(s.ratchets, 31);
        assert_eq!(s.session_idle_reaped, 37);
        assert_eq!(s.session_byte_budget_exhausted, 41);
    }

    #[test]
    fn parse_keeps_unknown_counters_under_other() {
        let s = MetricsSnapshot::parse(SAMPLE);
        // Forward-compat: unknown but prefixed-proteus_ counters
        // should land in `other`.
        assert_eq!(s.other.get("proteus_some_future_counter_total"), Some(&43));
    }

    #[test]
    fn parse_ignores_non_proteus_counters() {
        let body = "go_goroutines 42\nproteus_up 1\n";
        let s = MetricsSnapshot::parse(body);
        assert_eq!(s.up, 1);
        assert!(s.other.is_empty());
    }

    #[test]
    fn parse_ignores_label_bearing_series() {
        // We don't currently emit labels, but the parser must not
        // misread them as known counters.
        let body = "proteus_up{foo=\"bar\"} 99\nproteus_up 1\n";
        let s = MetricsSnapshot::parse(body);
        assert_eq!(
            s.up, 1,
            "label-bearing line must NOT override the plain line"
        );
    }

    #[test]
    fn parse_tolerates_malformed_lines() {
        let body = "proteus_up not-a-number\nproteus_ready 1\n\
                    garbage\nproteus_in_flight_sessions 5\n";
        let s = MetricsSnapshot::parse(body);
        assert_eq!(s.ready, 1);
        assert_eq!(s.in_flight_sessions, 5);
        assert_eq!(s.up, 0, "malformed value should leave default");
    }

    #[test]
    fn total_rejected_sums_correctly() {
        let s = MetricsSnapshot::parse(SAMPLE);
        // firewall(17) + budget(3) + rate(11) + conn(13) + user(19) = 63
        assert_eq!(s.total_rejected(), 63);
    }

    #[test]
    fn display_shows_live_when_up_and_ready() {
        let s = MetricsSnapshot::parse(SAMPLE);
        let out = s.to_string();
        assert!(out.contains("LIVE / READY"));
    }

    #[test]
    fn display_shows_down_when_not_up() {
        let s = MetricsSnapshot {
            ready: 1,
            ..MetricsSnapshot::default()
        };
        let out = s.to_string();
        assert!(out.contains("DOWN"));
    }

    #[test]
    fn display_shows_draining_when_not_ready() {
        let s = MetricsSnapshot {
            up: 1,
            ..MetricsSnapshot::default()
        };
        let out = s.to_string();
        assert!(out.contains("DRAINING"));
    }

    #[test]
    fn display_shows_other_section_only_when_nonempty() {
        let s = MetricsSnapshot::default();
        let out = s.to_string();
        assert!(!out.contains("Other"), "should not show empty 'Other'");

        let s = MetricsSnapshot::parse(SAMPLE);
        let out = s.to_string();
        assert!(out.contains("Other"));
    }

    #[test]
    fn display_renders_throughput_human_units() {
        let s = MetricsSnapshot::parse(SAMPLE);
        let out = s.to_string();
        assert!(out.contains("1.00 MiB"));
        assert!(out.contains("2.00 MiB"));
    }

    #[test]
    fn parse_http_url_accepts_well_formed() {
        let (h, p, path) = parse_http_url("http://127.0.0.1:9090/metrics").unwrap();
        assert_eq!(h, "127.0.0.1");
        assert_eq!(p, 9090);
        assert_eq!(path, "/metrics");
    }

    /// Iter-116: HTTPS rejection now includes actionable message.
    #[test]
    fn parse_http_url_rejects_https() {
        let err = parse_http_url("https://example.com:443/metrics").unwrap_err();
        let msg = err.to_string();
        assert!(
            msg.contains("HTTP-only") && msg.contains("loopback"),
            "iter-116 must explain WHY https isn't accepted: {msg}"
        );
    }

    /// Iter-116: missing-port rejection now includes example.
    #[test]
    fn parse_http_url_rejects_missing_port() {
        let err = parse_http_url("http://example.com/metrics").unwrap_err();
        let msg = err.to_string();
        assert!(
            msg.contains(":port") && msg.contains("127.0.0.1:9090"),
            "iter-116 must include the recommended-example: {msg}"
        );
    }

    /// Iter-116: missing-scheme rejection — `127.0.0.1:9090/metrics`
    /// (no `http://`) now produces an actionable message instead
    /// of bare BadUrl(url).
    #[test]
    fn iter116_parse_http_url_rejects_missing_scheme_with_actionable_msg() {
        let err = parse_http_url("127.0.0.1:9090/metrics").unwrap_err();
        let msg = err.to_string();
        assert!(
            msg.contains("http://") && msg.contains("scheme"),
            "iter-116 must explain that the scheme is missing: {msg}"
        );
    }

    /// Iter-116: bad port (non-u16) — `http://host:99999` now
    /// reports the specific bad port string.
    #[test]
    fn iter116_parse_http_url_rejects_bad_port_with_actionable_msg() {
        let err = parse_http_url("http://127.0.0.1:99999/metrics").unwrap_err();
        let msg = err.to_string();
        assert!(
            msg.contains("99999") && msg.contains("u16"),
            "iter-116 must name the bad port + valid range: {msg}"
        );
    }

    #[test]
    fn parse_http_url_defaults_path_to_slash() {
        let (_, _, path) = parse_http_url("http://127.0.0.1:9090").unwrap();
        assert_eq!(path, "/");
    }

    // ---- iter-147: CRLF / NUL / TAB injection rejection ----

    /// Pre-iter-147 the host portion was embedded verbatim into
    /// the Host: header. A URL containing CR/LF in the host
    /// (somehow — e.g. a config-templating tool pulling from an
    /// untrusted source) would smuggle attacker-chosen HTTP
    /// headers into the GET.
    #[test]
    fn iter147_parse_http_url_rejects_crlf_in_host() {
        // We can't write a literal CRLF inside a Rust string
        // literal alongside the prefix matcher, so build the URL
        // by concatenation. host = "evil.com\r\nX-Smuggle: yes"
        for ch in ['\r', '\n', '\t', '\0'] {
            let url = format!("http://evil.com{ch}smuggle.com:9090/metrics");
            let err = parse_http_url(&url).unwrap_err();
            let msg = err.to_string();
            assert!(
                msg.contains("control character"),
                "iter-147: host control byte {ch:?} must be rejected: {msg}"
            );
        }
    }

    /// Iter-147: path control bytes also get rejected (these go
    /// onto the GET request line).
    #[test]
    fn iter147_parse_http_url_rejects_crlf_in_path() {
        for ch in ['\r', '\n', '\t', '\0'] {
            let url = format!("http://127.0.0.1:9090/metrics{ch}smuggle");
            let err = parse_http_url(&url).unwrap_err();
            let msg = err.to_string();
            assert!(
                msg.contains("control character"),
                "iter-147: path control byte {ch:?} must be rejected: {msg}"
            );
        }
    }

    /// Iter-147: whitespace inside the host is also rejected
    /// (a typo `http://example .com:443/` previously produced
    /// confusing downstream behavior).
    #[test]
    fn iter147_parse_http_url_rejects_space_in_host() {
        let err = parse_http_url("http://evil .com:9090/metrics").unwrap_err();
        let msg = err.to_string();
        assert!(
            msg.contains("control character"),
            "iter-147: space in host must be rejected: {msg}"
        );
    }

    /// Iter-147: well-formed URLs still parse — make sure we
    /// didn't accidentally break the positive case.
    #[test]
    fn iter147_well_formed_urls_still_parse_cleanly() {
        for url in [
            "http://127.0.0.1:9090/metrics",
            "http://localhost:9091/healthz",
            "http://[::1]:9090/diagnose",
            "http://example.com:8443/admin/abuse-fires",
        ] {
            assert!(
                parse_http_url(url).is_ok(),
                "iter-147: legit URL {url:?} must still parse cleanly"
            );
        }
    }

    // ---- iter-159: port 0 rejection on admin URL ----

    /// Iter-159 closes a missing-gate on admin URL: port 0 is
    /// invalid as a TCP-connect target (reserved for "any free
    /// port" on bind/listen). Pre-iter-159 `http://127.0.0.1:0`
    /// parsed cleanly and only failed at TCP-connect time with
    /// an OS error, hiding the typo. The cover-endpoint parser
    /// got the same gate in iter-158; this is the matching
    /// admin-URL fix.
    #[test]
    fn iter159_parse_http_url_rejects_port_zero() {
        for url in [
            "http://127.0.0.1:0/metrics",
            "http://[::1]:0/metrics",
            "http://localhost:0/metrics",
        ] {
            let err = parse_http_url(url).unwrap_err();
            let msg = err.to_string();
            assert!(
                msg.contains("port 0 is invalid") || msg.contains("port 0"),
                "iter-159: port 0 in {url:?} must be rejected: {msg}"
            );
        }
    }

    /// Iter-159 regression: well-formed non-zero ports still
    /// parse cleanly (the new gate must not reject anything
    /// legitimate).
    #[test]
    fn iter159_well_formed_ports_still_parse() {
        for url in [
            "http://127.0.0.1:1/metrics",
            "http://127.0.0.1:65535/metrics",
            "http://localhost:9090/metrics",
        ] {
            assert!(
                parse_http_url(url).is_ok(),
                "iter-159: legitimate port in {url:?} must still parse: {:?}",
                parse_http_url(url).err()
            );
        }
    }

    // ---- iter-154: control-byte rejection on the bearer token ----

    /// Iter-154 runtime gate: http_get must reject a token
    /// containing CR / LF / NUL with a clear error. Pre-iter-154
    /// the token was embedded into `Authorization: Bearer {t}\r\n`
    /// verbatim, enabling HTTP request smuggling via the token
    /// source (operator config / env var / k8s ConfigMap).
    #[test]
    fn iter154_http_get_rejects_token_with_crlf() {
        // We don't need an actual server — the iter-154 gate fires
        // before any socket activity. Use a localhost URL that
        // would otherwise fail at connect (no listener).
        for bad in [
            "good-token\r\nX-Smuggle: yes",
            "good-token\nX-Smuggle: yes",
            "good-token\0X-Smuggle: yes",
        ] {
            let err = http_get(
                "http://127.0.0.1:9090/metrics",
                Some(bad),
                Duration::from_millis(100),
            )
            .unwrap_err();
            let msg = err.to_string();
            assert!(
                msg.contains("control byte"),
                "iter-154: token {bad:?} must be rejected with 'control byte' message: {msg}"
            );
        }
    }

    /// Iter-154 sanity: a well-formed token doesn't trigger the
    /// gate. We'll get a connect error (no listener) but it must
    /// NOT be the iter-154 control-byte error.
    #[test]
    fn iter154_http_get_accepts_clean_token() {
        let err = http_get(
            "http://127.0.0.1:9090/metrics",
            Some("legitimate-bearer-token-xyz123"),
            Duration::from_millis(100),
        )
        .unwrap_err();
        let msg = err.to_string();
        assert!(
            !msg.contains("control byte"),
            "iter-154: clean token must not trigger the gate: {msg}"
        );
    }

    #[test]
    fn read_token_file_rejects_empty() {
        let p =
            std::env::temp_dir().join(format!("proteus-admin-empty-token-{}", std::process::id()));
        std::fs::write(&p, b"\n\n  \n").unwrap();
        let r = read_token_file(&p);
        assert!(r.is_err(), "empty/whitespace-only token must fail");
        let _ = std::fs::remove_file(&p);
    }

    // ----- JSON output -----

    #[test]
    fn snapshot_json_emits_every_field() {
        let s = MetricsSnapshot::parse(SAMPLE);
        let j = s.to_json();
        // Sanity: well-formed JSON envelope.
        assert!(j.starts_with('{'), "JSON should start with {{: {j}");
        assert!(j.trim_end().ends_with('}'), "JSON should end with }}: {j}");
        assert!(j.ends_with('\n'), "should end with newline");
        // Each declared counter shows up.
        for (k, v) in [
            ("\"alive\":true", true),
            ("\"ready\":true", true),
            ("\"in_flight_sessions\":7", true),
            ("\"sessions_accepted\":100", true),
            ("\"handshakes_succeeded\":95", true),
            ("\"handshakes_failed\":5", true),
            ("\"handshake_timeouts\":2", true),
            ("\"handshake_budget_rejected\":3", true),
            ("\"rate_limited\":11", true),
            ("\"conn_limit_rejected\":13", true),
            ("\"firewall_denied\":17", true),
            ("\"user_rate_rejected\":19", true),
            ("\"cover_forwards\":23", true),
            ("\"total_rejected\":63", true),
            ("\"tx_bytes\":1048576", true),
            ("\"rx_bytes\":2097152", true),
            ("\"aead_drops\":0", true),
            ("\"ratchets\":31", true),
            ("\"session_idle_reaped\":37", true),
            ("\"session_byte_budget_exhausted\":41", true),
            ("\"other\":{", true),
            ("\"proteus_some_future_counter_total\":43", true),
        ] {
            assert_eq!(j.contains(k), v, "field check {k} mismatch in: {j}");
        }
    }

    #[test]
    fn snapshot_json_emits_alive_false_when_not_up() {
        let s = MetricsSnapshot {
            up: 0,
            ready: 0,
            ..MetricsSnapshot::default()
        };
        let j = s.to_json();
        assert!(j.contains("\"alive\":false"));
        assert!(j.contains("\"ready\":false"));
    }

    #[test]
    fn snapshot_json_other_object_empty_when_no_unknown_counters() {
        let body = "proteus_up 1\nproteus_sessions_accepted_total 7\n";
        let s = MetricsSnapshot::parse(body);
        let j = s.to_json();
        assert!(j.contains("\"other\":{}"), "expected empty other: {j}");
    }

    // ---------- probe-anomaly diagnostic surface ----------

    /// The Prometheus body includes the detector's three new lines —
    /// two flat counters and one labelled gauge per recent fire.
    /// The admin snapshot MUST recognize all three and surface them
    /// as typed fields (not as opaque "Other" entries).
    #[test]
    fn snapshot_parses_probe_anomaly_extension_lines() {
        let body = "\
proteus_up 1\n\
proteus_probe_anomalies_fired_total 3\n\
proteus_probe_anomaly_tracked_prefixes 5\n\
proteus_probe_anomaly_dropped_inserts_total 0\n\
proteus_probe_anomaly_recent_secs{prefix=\"198.51.100.0/24\"} 12\n\
proteus_probe_anomaly_recent_secs{prefix=\"203.0.113.0/24\"} 47\n\
proteus_probe_anomaly_recent_secs{prefix=\"2001:db8::/48\"} 99\n";
        let s = MetricsSnapshot::parse(body);
        assert_eq!(s.probe_anomalies_fired, 3);
        assert_eq!(s.probe_anomaly_tracked, 5);
        assert_eq!(s.probe_anomaly_dropped_inserts, 0);
        assert_eq!(s.probe_anomaly_recent.len(), 3);
        // Order from parse should match emission order; sorting
        // happens in the renderer, not the parser.
        let prefixes: Vec<&str> = s
            .probe_anomaly_recent
            .iter()
            .map(|r| r.prefix.as_str())
            .collect();
        assert_eq!(
            prefixes,
            vec!["198.51.100.0/24", "203.0.113.0/24", "2001:db8::/48"]
        );
        // No detector field should leak into "other" (the parser
        // must recognize them by name, not fall through).
        assert!(
            s.other.is_empty(),
            "detector fields leaked into Other map: {:?}",
            s.other
        );
    }

    /// JSON output emits the recent-fires array sorted freshest-first
    /// (smallest secs_ago first). This is the order an operator
    /// scanning the dashboard cares about first.
    #[test]
    fn snapshot_json_emits_recent_fires_freshest_first() {
        let body = "\
proteus_up 1\n\
proteus_probe_anomaly_recent_secs{prefix=\"10.0.0.0/24\"} 60\n\
proteus_probe_anomaly_recent_secs{prefix=\"10.0.1.0/24\"} 5\n\
proteus_probe_anomaly_recent_secs{prefix=\"10.0.2.0/24\"} 30\n";
        let s = MetricsSnapshot::parse(body);
        let j = s.to_json();
        // Freshest = 5s, then 30s, then 60s.
        let idx_5 = j.find(r#""prefix":"10.0.1.0/24","secs_ago":5"#).unwrap();
        let idx_30 = j.find(r#""prefix":"10.0.2.0/24","secs_ago":30"#).unwrap();
        let idx_60 = j.find(r#""prefix":"10.0.0.0/24","secs_ago":60"#).unwrap();
        assert!(
            idx_5 < idx_30 && idx_30 < idx_60,
            "recent-fires not sorted freshest-first in JSON: {j}",
        );
    }

    /// Empty ring buffer still produces the `probe_anomaly_recent: []`
    /// key — scripts can rely on its presence.
    #[test]
    fn snapshot_json_emits_empty_recent_array_when_no_fires() {
        let body = "proteus_up 1\n";
        let s = MetricsSnapshot::parse(body);
        let j = s.to_json();
        assert!(
            j.contains(r#""probe_anomaly_recent":[]"#),
            "expected empty recent array key in: {j}"
        );
    }

    /// Text output renders the probe-anomaly diagnostic block
    /// ONLY when there's something interesting to show (fires > 0
    /// OR tracked > 0 OR ring non-empty). Quiet by default.
    #[test]
    fn snapshot_text_omits_probe_anomaly_block_when_quiet() {
        let body = "proteus_up 1\nproteus_sessions_accepted_total 7\n";
        let s = MetricsSnapshot::parse(body);
        let t = format!("{s}");
        assert!(
            !t.contains("Probe-anomaly diagnostics"),
            "quiet snapshot should NOT render the diagnostic block:\n{t}",
        );
    }

    /// When the detector has fires, the text block IS rendered and
    /// includes the recent /24 list sorted freshest-first.
    #[test]
    fn snapshot_text_renders_probe_anomaly_block_when_fires_present() {
        let body = "\
proteus_up 1\n\
proteus_probe_anomalies_fired_total 2\n\
proteus_probe_anomaly_tracked_prefixes 1\n\
proteus_probe_anomaly_dropped_inserts_total 0\n\
proteus_probe_anomaly_recent_secs{prefix=\"198.51.100.0/24\"} 8\n\
proteus_probe_anomaly_recent_secs{prefix=\"203.0.113.0/24\"} 2\n";
        let s = MetricsSnapshot::parse(body);
        let t = format!("{s}");
        assert!(
            t.contains("Probe-anomaly diagnostics"),
            "block missing:\n{t}"
        );
        assert!(t.contains("tracked_prefixes_gauge"), "tracked row missing");
        assert!(t.contains("dropped_inserts_total"), "dropped row missing");
        // Freshest first → 203.0.113 (2s) before 198.51.100 (8s).
        let idx_203 = t.find("203.0.113.0/24").expect("203 line missing");
        let idx_198 = t.find("198.51.100.0/24").expect("198 line missing");
        assert!(
            idx_203 < idx_198,
            "recent-fires not sorted freshest-first in text:\n{t}",
        );
        assert!(t.contains("fired 2s ago"));
        assert!(t.contains("fired 8s ago"));
    }

    /// Malformed labelled lines must not crash the parser — they
    /// just get skipped. Defense against future format drift.
    #[test]
    fn snapshot_parser_skips_malformed_recent_secs_lines() {
        let body = "\
proteus_up 1\n\
proteus_probe_anomaly_recent_secs{prefix=\"198.51.100.0/24\"} 12\n\
proteus_probe_anomaly_recent_secs{ notvalid \n\
proteus_probe_anomaly_recent_secs{wrongkey=\"x\"} 5\n\
proteus_probe_anomaly_recent_secs{prefix=missing_quotes} 7\n\
proteus_probe_anomaly_recent_secs{prefix=\"valid/24\"} not_a_number\n\
proteus_probe_anomaly_recent_secs{prefix=\"203.0.113.0/24\"} 47\n";
        let s = MetricsSnapshot::parse(body);
        // Only the two well-formed lines survived.
        assert_eq!(s.probe_anomaly_recent.len(), 2);
        let prefixes: Vec<&str> = s
            .probe_anomaly_recent
            .iter()
            .map(|r| r.prefix.as_str())
            .collect();
        assert_eq!(prefixes, vec!["198.51.100.0/24", "203.0.113.0/24"]);
    }

    // ---------- auto-deny diagnostic surface ----------

    /// All four auto-deny series parse into typed fields (no
    /// leakage to `other`).
    #[test]
    fn snapshot_parses_auto_deny_extension_lines() {
        let body = "\
proteus_up 1\n\
proteus_auto_deny_active_prefixes 4\n\
proteus_auto_deny_inserted_total 12\n\
proteus_auto_deny_refused_inserts_total 3\n\
proteus_auto_deny_remaining_secs{prefix=\"198.51.100.0/24\"} 250\n\
proteus_auto_deny_remaining_secs{prefix=\"203.0.113.0/24\"} 60\n\
proteus_auto_deny_remaining_secs{prefix=\"2001:db8::/48\"} 1800\n";
        let s = MetricsSnapshot::parse(body);
        assert_eq!(s.auto_deny_active, 4);
        assert_eq!(s.auto_deny_inserted_total, 12);
        assert_eq!(s.auto_deny_refused_inserts_total, 3);
        assert_eq!(s.auto_deny_entries.len(), 3);
        let prefixes: Vec<&str> = s
            .auto_deny_entries
            .iter()
            .map(|d| d.prefix.as_str())
            .collect();
        assert_eq!(
            prefixes,
            vec!["198.51.100.0/24", "203.0.113.0/24", "2001:db8::/48"]
        );
        assert!(s.other.is_empty(), "leaked into other: {:?}", s.other);
    }

    /// JSON output emits the auto-deny array sorted soonest-to-
    /// expire first.
    #[test]
    fn snapshot_json_emits_auto_deny_entries_soonest_first() {
        let body = "\
proteus_up 1\n\
proteus_auto_deny_remaining_secs{prefix=\"10.0.0.0/24\"} 600\n\
proteus_auto_deny_remaining_secs{prefix=\"10.0.1.0/24\"} 60\n\
proteus_auto_deny_remaining_secs{prefix=\"10.0.2.0/24\"} 300\n";
        let s = MetricsSnapshot::parse(body);
        let j = s.to_json();
        let idx_60 = j
            .find(r#""prefix":"10.0.1.0/24","expires_in_secs":60"#)
            .unwrap();
        let idx_300 = j
            .find(r#""prefix":"10.0.2.0/24","expires_in_secs":300"#)
            .unwrap();
        let idx_600 = j
            .find(r#""prefix":"10.0.0.0/24","expires_in_secs":600"#)
            .unwrap();
        assert!(
            idx_60 < idx_300 && idx_300 < idx_600,
            "auto_deny_entries not sorted soonest-to-expire first in JSON: {j}",
        );
    }

    /// Empty list still emits the JSON array key.
    #[test]
    fn snapshot_json_emits_empty_auto_deny_entries_array_by_default() {
        let body = "proteus_up 1\n";
        let s = MetricsSnapshot::parse(body);
        let j = s.to_json();
        assert!(
            j.contains(r#""auto_deny_entries":[]"#),
            "expected empty auto_deny_entries array: {j}"
        );
        assert!(j.contains(r#""auto_deny_active":0"#));
        assert!(j.contains(r#""auto_deny_inserted_total":0"#));
        assert!(j.contains(r#""auto_deny_refused_inserts_total":0"#));
    }

    /// Text output omits the block when the auto-deny surface is
    /// quiet (no fires, no refusals, no active entries).
    #[test]
    fn snapshot_text_omits_auto_deny_block_when_quiet() {
        let body = "proteus_up 1\n";
        let s = MetricsSnapshot::parse(body);
        let t = format!("{s}");
        assert!(
            !t.contains("Auto-deny list"),
            "quiet snapshot must omit auto-deny block:\n{t}"
        );
    }

    /// Text output renders the block AND sorts entries soonest-
    /// first when the auto-deny surface is active.
    #[test]
    fn snapshot_text_renders_auto_deny_block_sorted_soonest_first() {
        let body = "\
proteus_up 1\n\
proteus_auto_deny_active_prefixes 2\n\
proteus_auto_deny_inserted_total 5\n\
proteus_auto_deny_refused_inserts_total 0\n\
proteus_auto_deny_remaining_secs{prefix=\"198.51.100.0/24\"} 100\n\
proteus_auto_deny_remaining_secs{prefix=\"203.0.113.0/24\"} 20\n";
        let s = MetricsSnapshot::parse(body);
        let t = format!("{s}");
        assert!(t.contains("Auto-deny list"), "block missing:\n{t}");
        assert!(t.contains("active_prefixes_gauge"));
        assert!(t.contains("inserted_total"));
        assert!(t.contains("refused_inserts_total"));
        // Soonest-to-expire first: 203.0.113 (20s) before 198.51.100 (100s).
        let idx_203 = t.find("203.0.113.0/24").unwrap();
        let idx_198 = t.find("198.51.100.0/24").unwrap();
        assert!(
            idx_203 < idx_198,
            "auto-deny entries not sorted in text:\n{t}"
        );
        assert!(t.contains("expires in 20s"));
        assert!(t.contains("expires in 100s"));
    }

    /// Malformed `remaining_secs` lines are silently skipped.
    #[test]
    fn snapshot_parser_skips_malformed_auto_deny_lines() {
        let body = "\
proteus_up 1\n\
proteus_auto_deny_remaining_secs{prefix=\"198.51.100.0/24\"} 60\n\
proteus_auto_deny_remaining_secs{wrongkey=\"x\"} 5\n\
proteus_auto_deny_remaining_secs{prefix=missing_quotes} 7\n\
proteus_auto_deny_remaining_secs{prefix=\"valid/24\"} not_a_number\n\
proteus_auto_deny_remaining_secs{prefix=\"203.0.113.0/24\"} 30\n";
        let s = MetricsSnapshot::parse(body);
        assert_eq!(s.auto_deny_entries.len(), 2);
        let prefixes: Vec<&str> = s
            .auto_deny_entries
            .iter()
            .map(|d| d.prefix.as_str())
            .collect();
        assert_eq!(prefixes, vec!["198.51.100.0/24", "203.0.113.0/24"]);
    }

    #[test]
    fn delta_json_emits_interval_and_counter_reset() {
        let a = MetricsSnapshot::parse(SAMPLE);
        let b = MetricsSnapshot {
            sessions_accepted: 1,
            ..MetricsSnapshot::default()
        };
        let d = MetricsDelta::between(&a, &b, 30.0);
        let j = d.to_json();
        assert!(j.starts_with('{') && j.trim_end().ends_with('}'));
        assert!(j.contains("\"interval_secs\":30."));
        assert!(j.contains("\"counter_reset\":true"));
    }

    #[test]
    fn delta_json_renders_zero_interval_safely() {
        let a = MetricsSnapshot::default();
        let b = MetricsSnapshot::default();
        let d = MetricsDelta::between(&a, &b, 0.0);
        let j = d.to_json();
        assert!(!j.contains("inf"), "got: {j}");
        assert!(!j.contains("NaN"), "got: {j}");
        assert!(j.contains("\"interval_secs\":0."));
    }

    #[test]
    fn delta_json_emits_every_counter_delta() {
        let a = MetricsSnapshot::default();
        let b = MetricsSnapshot {
            up: 1,
            ready: 1,
            sessions_accepted: 30,
            handshakes_succeeded: 28,
            firewall_denied: 5,
            rate_limited: 7,
            tx_bytes: 1024,
            ..MetricsSnapshot::default()
        };
        let d = MetricsDelta::between(&a, &b, 60.0);
        let j = d.to_json();
        for field in [
            "\"sessions_accepted\":30",
            "\"handshakes_succeeded\":28",
            "\"firewall_denied\":5",
            "\"rate_limited\":7",
            "\"tx_bytes\":1024",
            "\"total_rejected\":12",
            "\"alive\":true",
            "\"ready\":true",
        ] {
            assert!(j.contains(field), "missing {field} in: {j}");
        }
    }

    #[test]
    fn output_format_parses_text_and_json() {
        assert_eq!("text".parse::<OutputFormat>().unwrap(), OutputFormat::Text);
        assert_eq!("human".parse::<OutputFormat>().unwrap(), OutputFormat::Text);
        assert_eq!("json".parse::<OutputFormat>().unwrap(), OutputFormat::Json);
        assert!("yaml".parse::<OutputFormat>().is_err());
    }

    #[test]
    fn json_escape_str_handles_dangerous_chars() {
        let mut out = String::new();
        json_escape_str("foo\"bar\\baz\nq", &mut out);
        assert_eq!(out, "foo\\\"bar\\\\baz\\nq");
    }

    // ----- MetricsDelta -----

    #[test]
    fn delta_subtracts_each_counter() {
        let a = MetricsSnapshot::parse(SAMPLE);
        let mut b = a.clone();
        b.sessions_accepted += 17;
        b.firewall_denied += 3;
        b.tx_bytes += 4096;
        let d = MetricsDelta::between(&a, &b, 10.0);
        assert_eq!(d.sessions_accepted, 17);
        assert_eq!(d.firewall_denied, 3);
        assert_eq!(d.tx_bytes, 4096);
        // Other counters are zero.
        assert_eq!(d.rate_limited, 0);
        assert!(!d.counter_reset);
    }

    #[test]
    fn delta_detects_counter_reset() {
        let a = MetricsSnapshot::parse(SAMPLE);
        // Simulate a process restart: every counter drops to a small
        // fresh value.
        let b = MetricsSnapshot {
            sessions_accepted: 1,
            ..MetricsSnapshot::default()
        };
        let d = MetricsDelta::between(&a, &b, 30.0);
        assert!(d.counter_reset, "must flag counter_reset");
        // Clamped to 0, not wrapping.
        assert_eq!(d.handshakes_succeeded, 0);
        assert_eq!(d.firewall_denied, 0);
    }

    #[test]
    fn delta_carries_current_gauges() {
        let a = MetricsSnapshot::default();
        let b = MetricsSnapshot {
            in_flight_sessions: 42,
            up: 1,
            ready: 1,
            ..MetricsSnapshot::default()
        };
        let d = MetricsDelta::between(&a, &b, 5.0);
        assert_eq!(d.now_in_flight, 42);
        assert_eq!(d.now_up, 1);
        assert_eq!(d.now_ready, 1);
    }

    #[test]
    fn delta_total_rejected_sums_correctly() {
        let a = MetricsSnapshot::default();
        let b = MetricsSnapshot {
            firewall_denied: 3,
            handshake_budget_rejected: 5,
            rate_limited: 7,
            conn_limit_rejected: 11,
            user_rate_rejected: 13,
            ..MetricsSnapshot::default()
        };
        let d = MetricsDelta::between(&a, &b, 1.0);
        assert_eq!(d.total_rejected(), 3 + 5 + 7 + 11 + 13);
    }

    #[test]
    fn delta_display_renders_rates() {
        // 60 sessions accepted over 30s = 2.0/s.
        let a = MetricsSnapshot::default();
        let b = MetricsSnapshot {
            sessions_accepted: 60,
            up: 1,
            ready: 1,
            ..MetricsSnapshot::default()
        };
        let d = MetricsDelta::between(&a, &b, 30.0);
        let out = d.to_string();
        assert!(out.contains("delta over 30.0s"));
        assert!(out.contains("LIVE / READY"));
        // Format is `sessions_accepted   60 (  2.00/s)`.
        assert!(out.contains("2.00/s"), "expected 2.00/s rate: {out}");
    }

    #[test]
    fn delta_display_renders_reset_banner() {
        let a = MetricsSnapshot::parse(SAMPLE);
        let b = MetricsSnapshot::default(); // every counter wiped
        let d = MetricsDelta::between(&a, &b, 30.0);
        let out = d.to_string();
        assert!(
            out.contains("counter reset"),
            "expected reset banner: {out}"
        );
    }

    #[test]
    fn delta_handles_zero_interval_without_dividing_by_zero() {
        let a = MetricsSnapshot::default();
        let b = MetricsSnapshot {
            sessions_accepted: 10,
            ..MetricsSnapshot::default()
        };
        let d = MetricsDelta::between(&a, &b, 0.0);
        // Display must not panic and must not emit `inf`.
        let out = d.to_string();
        assert!(!out.contains("inf"), "got: {out}");
    }

    #[test]
    fn delta_throughput_renders_in_human_units() {
        let a = MetricsSnapshot::default();
        // 10 MiB over 10s → 1.0 MiB/s.
        let b = MetricsSnapshot {
            tx_bytes: 10 * 1024 * 1024,
            up: 1,
            ready: 1,
            ..MetricsSnapshot::default()
        };
        let d = MetricsDelta::between(&a, &b, 10.0);
        let out = d.to_string();
        assert!(out.contains("1.00 MiB/s"), "expected 1 MiB/s: {out}");
    }

    #[test]
    fn read_token_file_strips_trailing_whitespace() {
        let p = std::env::temp_dir().join(format!("proteus-admin-ok-token-{}", std::process::id()));
        std::fs::write(&p, b"abcdef0123\n").unwrap();
        let t = read_token_file(&p).unwrap();
        assert_eq!(t, "abcdef0123");
        let _ = std::fs::remove_file(&p);
    }

    /// Iter-155: tokens with an *embedded* control byte (NUL/CR/LF/
    /// TAB) — not just leading/trailing whitespace that `trim()`
    /// strips — must be rejected at the I/O boundary. This is
    /// belt-and-braces for HTTP request smuggling: if a future
    /// non-HTTP caller (e.g. a new RPC transport) reads the token
    /// via `read_token_file` and does **not** route it through
    /// `http_get`, the iter-154 gate inside `http_get` wouldn't
    /// fire, so the invariant must also live at the file-read
    /// site.
    #[test]
    fn read_token_file_rejects_embedded_control_bytes() {
        for (label, payload) in [
            ("CRLF", b"abc\r\ndef".as_slice()),
            ("LF", b"abc\ndef".as_slice()),
            ("CR", b"abc\rdef".as_slice()),
            ("TAB", b"abc\tdef".as_slice()),
            ("NUL", b"abc\0def".as_slice()),
        ] {
            let p = std::env::temp_dir().join(format!(
                "proteus-admin-bad-token-{}-{}",
                std::process::id(),
                label
            ));
            std::fs::write(&p, payload).unwrap();
            let r = read_token_file(&p);
            let _ = std::fs::remove_file(&p);
            let err = r.unwrap_err();
            let msg = err.to_string();
            assert!(
                msg.contains("control byte"),
                "iter-155: {label} payload must hit the control-byte gate, got: {msg}"
            );
        }
    }

    /// Iter-155: a token whose only "whitespace" is the trailing
    /// newline `trim()` already strips must NOT trigger the new
    /// embedded-control-byte gate. This pins the regression: the
    /// gate must run on the *trimmed* string, not the raw bytes,
    /// otherwise every well-formed `openssl rand -base64 24 >
    /// token` would fail.
    #[test]
    fn read_token_file_accepts_trailing_lf_only() {
        let p = std::env::temp_dir().join(format!(
            "proteus-admin-lf-only-token-{}",
            std::process::id()
        ));
        // base64-ish payload + trailing newline, no internal control
        // bytes — the canonical shape `openssl rand -base64` writes.
        std::fs::write(&p, b"X9k+Lq3pZv2nT0wB8sR4aQ==\n").unwrap();
        let t = read_token_file(&p).unwrap();
        assert_eq!(t, "X9k+Lq3pZv2nT0wB8sR4aQ==");
        let _ = std::fs::remove_file(&p);
    }

    /// Parser surfaces the three TLS observability lines into typed
    /// fields. None of them are required — the parser must still
    /// return a coherent snapshot when only some are present.
    #[test]
    fn snapshot_parses_tls_cert_and_reload_lines() {
        let body = "\
proteus_up 1\n\
proteus_tls_cert_not_after_unix_seconds 1893456000\n\
proteus_tls_reload_attempts_total 4\n\
proteus_tls_reload_succeeded_total 3\n";
        let s = MetricsSnapshot::parse(body);
        assert_eq!(s.tls_cert_not_after_unix, Some(1_893_456_000));
        assert_eq!(s.tls_reload_attempts, Some(4));
        assert_eq!(s.tls_reload_succeeded, Some(3));
    }

    /// All three fields default to `None` when the body has no TLS
    /// lines — the typical LAN test-rig case. Distinguishes "not
    /// configured" from "expired".
    #[test]
    fn snapshot_tls_fields_default_to_none_when_absent() {
        let body = "proteus_up 1\n";
        let s = MetricsSnapshot::parse(body);
        assert_eq!(s.tls_cert_not_after_unix, None);
        assert_eq!(s.tls_reload_attempts, None);
        assert_eq!(s.tls_reload_succeeded, None);
    }

    /// Malformed TLS gauge values (negative, garbage) must NOT panic;
    /// the field stays `None` so downstream alerting doesn't fire on
    /// a parse glitch.
    #[test]
    fn snapshot_parser_skips_malformed_tls_lines() {
        let body = "\
proteus_up 1\n\
proteus_tls_cert_not_after_unix_seconds -1\n\
proteus_tls_cert_not_after_unix_seconds garbage\n\
proteus_tls_reload_attempts_total notanumber\n";
        let s = MetricsSnapshot::parse(body);
        // Negative explicitly rejected (we treat negative as
        // sentinel for "not present").
        assert_eq!(s.tls_cert_not_after_unix, None);
        // Garbage value: parse fails → field unchanged (None).
        assert_eq!(s.tls_reload_attempts, None);
        // The valid `proteus_up 1` still parsed.
        assert_eq!(s.up, 1);
    }

    /// JSON output emits all three TLS fields, using `null` when the
    /// field is absent so scripts can use `(.tls_cert_not_after_unix
    /// // 0)` style guards.
    #[test]
    fn snapshot_json_emits_tls_fields_with_null_when_absent() {
        let body = "proteus_up 1\n";
        let s = MetricsSnapshot::parse(body);
        let j = s.to_json();
        assert!(
            j.contains(r#""tls_cert_not_after_unix":null"#),
            "expected null cert-expiry in: {j}"
        );
        assert!(j.contains(r#""tls_reload_attempts":null"#));
        assert!(j.contains(r#""tls_reload_succeeded":null"#));
    }

    /// JSON output emits the actual numeric values when the fields
    /// are populated. The cert timestamp is emitted as a bare i64,
    /// no JSON-string wrap.
    #[test]
    fn snapshot_json_emits_tls_fields_with_values_when_present() {
        let body = "\
proteus_up 1\n\
proteus_tls_cert_not_after_unix_seconds 1893456000\n\
proteus_tls_reload_attempts_total 7\n\
proteus_tls_reload_succeeded_total 6\n";
        let s = MetricsSnapshot::parse(body);
        let j = s.to_json();
        assert!(j.contains(r#""tls_cert_not_after_unix":1893456000"#), "{j}");
        assert!(j.contains(r#""tls_reload_attempts":7"#), "{j}");
        assert!(j.contains(r#""tls_reload_succeeded":6"#), "{j}");
    }

    /// Text output renders a "TLS cert" block when at least one
    /// field is populated.
    #[test]
    fn snapshot_text_renders_tls_block_when_present() {
        let body = "\
proteus_up 1\n\
proteus_tls_cert_not_after_unix_seconds 9999999999\n\
proteus_tls_reload_attempts_total 1\n\
proteus_tls_reload_succeeded_total 1\n";
        let s = MetricsSnapshot::parse(body);
        let t = format!("{s}");
        assert!(
            t.contains(" TLS cert"),
            "missing 'TLS cert' header in:\n{t}"
        );
        assert!(
            t.contains("not_after_unix_seconds"),
            "missing not_after_unix_seconds row in:\n{t}"
        );
        assert!(
            t.contains("reload_attempts_total"),
            "missing reload_attempts_total row in:\n{t}"
        );
        // 9999999999 is year 2286 — well past 14d so it should NOT
        // be flagged "RENEW NOW".
        assert!(
            !t.contains("RENEW NOW"),
            "should not flag RENEW NOW on a far-future cert:\n{t}"
        );
    }

    /// "RENEW NOW" warning appears when the cert is within 14 days
    /// of expiry. We pick `now + 5 days` to land in the danger zone.
    #[test]
    fn snapshot_text_renders_renew_warning_when_cert_near_expiry() {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64;
        let near = now + 5 * 86_400;
        let body = format!(
            "proteus_up 1\nproteus_tls_cert_not_after_unix_seconds {near}\n\
             proteus_tls_reload_attempts_total 1\n\
             proteus_tls_reload_succeeded_total 1\n"
        );
        let s = MetricsSnapshot::parse(&body);
        let t = format!("{s}");
        assert!(t.contains("RENEW NOW"), "expected RENEW NOW in:\n{t}");
    }

    /// "EXPIRED" warning appears when the cert's notAfter is already
    /// in the past.
    #[test]
    fn snapshot_text_renders_expired_warning_when_cert_in_past() {
        let body = "\
proteus_up 1\n\
proteus_tls_cert_not_after_unix_seconds 1\n\
proteus_tls_reload_attempts_total 1\n\
proteus_tls_reload_succeeded_total 1\n";
        let s = MetricsSnapshot::parse(body);
        let t = format!("{s}");
        assert!(t.contains("EXPIRED"), "expected EXPIRED in:\n{t}");
    }

    /// Failed-reload count surfaces in the text "reload_attempts"
    /// row when `attempts > succeeded`.
    #[test]
    fn snapshot_text_flags_failed_reloads_when_present() {
        let body = "\
proteus_up 1\n\
proteus_tls_cert_not_after_unix_seconds 9999999999\n\
proteus_tls_reload_attempts_total 5\n\
proteus_tls_reload_succeeded_total 3\n";
        let s = MetricsSnapshot::parse(body);
        let t = format!("{s}");
        assert!(t.contains("2 failed"), "expected '2 failed' in:\n{t}");
    }

    /// TLS block is omitted entirely when none of the three fields
    /// are populated — keeps LAN test-rig output uncluttered.
    #[test]
    fn snapshot_text_omits_tls_block_when_not_configured() {
        let body = "proteus_up 1\n";
        let s = MetricsSnapshot::parse(body);
        let t = format!("{s}");
        assert!(
            !t.contains(" TLS cert"),
            "should not show TLS block in:\n{t}"
        );
    }

    // ----- New SIGHUP reload counter tests (firewall + 3 limiters) -----

    /// Parser maps each of the 8 new counter series to the matching
    /// MetricsSnapshot field.
    #[test]
    fn snapshot_parses_all_sighup_reload_counters() {
        let body = "\
proteus_up 1\n\
proteus_firewall_reload_attempts_total 5\n\
proteus_firewall_reload_succeeded_total 4\n\
proteus_rate_limit_reload_attempts_total 5\n\
proteus_rate_limit_reload_succeeded_total 3\n\
proteus_user_rate_limit_reload_attempts_total 5\n\
proteus_user_rate_limit_reload_succeeded_total 5\n\
proteus_handshake_budget_reload_attempts_total 5\n\
proteus_handshake_budget_reload_succeeded_total 0\n";
        let s = MetricsSnapshot::parse(body);
        assert_eq!(s.firewall_reload_attempts, 5);
        assert_eq!(s.firewall_reload_succeeded, 4);
        assert_eq!(s.rate_limit_reload_attempts, 5);
        assert_eq!(s.rate_limit_reload_succeeded, 3);
        assert_eq!(s.user_rate_limit_reload_attempts, 5);
        assert_eq!(s.user_rate_limit_reload_succeeded, 5);
        assert_eq!(s.handshake_budget_reload_attempts, 5);
        assert_eq!(s.handshake_budget_reload_succeeded, 0);
    }

    /// All 8 fields default to 0 when their series are absent (e.g.
    /// scraping an older server). The parser must not insert them
    /// into `other` — they're dedicated fields now.
    #[test]
    fn snapshot_sighup_reload_counters_default_zero_when_absent() {
        let body = "proteus_up 1\n";
        let s = MetricsSnapshot::parse(body);
        assert_eq!(s.firewall_reload_attempts, 0);
        assert_eq!(s.firewall_reload_succeeded, 0);
        assert_eq!(s.rate_limit_reload_attempts, 0);
        assert_eq!(s.rate_limit_reload_succeeded, 0);
        assert_eq!(s.user_rate_limit_reload_attempts, 0);
        assert_eq!(s.user_rate_limit_reload_succeeded, 0);
        assert_eq!(s.handshake_budget_reload_attempts, 0);
        assert_eq!(s.handshake_budget_reload_succeeded, 0);
        assert!(
            !s.other
                .contains_key("proteus_firewall_reload_attempts_total"),
            "reload counters must be dedicated fields, not in 'other'"
        );
    }

    /// JSON output emits all 8 new fields as bare u64 (always
    /// present, never null — distinguishes from the TLS counters
    /// which are Option<u64>).
    #[test]
    fn snapshot_json_always_emits_sighup_reload_counters_as_u64() {
        let body = "proteus_up 1\n";
        let s = MetricsSnapshot::parse(body);
        let j = s.to_json();
        for k in [
            "firewall_reload_attempts",
            "firewall_reload_succeeded",
            "rate_limit_reload_attempts",
            "rate_limit_reload_succeeded",
            "user_rate_limit_reload_attempts",
            "user_rate_limit_reload_succeeded",
            "handshake_budget_reload_attempts",
            "handshake_budget_reload_succeeded",
        ] {
            assert!(
                j.contains(&format!(r#""{k}":0"#)),
                "JSON must contain {k}:0; got: {j}"
            );
        }
    }

    /// JSON reflects parsed values.
    #[test]
    fn snapshot_json_reflects_sighup_reload_values() {
        let body = "\
proteus_up 1\n\
proteus_firewall_reload_attempts_total 12\n\
proteus_firewall_reload_succeeded_total 12\n";
        let s = MetricsSnapshot::parse(body);
        let j = s.to_json();
        assert!(j.contains(r#""firewall_reload_attempts":12"#), "{j}");
        assert!(j.contains(r#""firewall_reload_succeeded":12"#), "{j}");
    }

    /// Text output omits the SIGHUP reload block when no SIGHUP has
    /// happened (steady-state cleanliness — operators who never
    /// reload don't see the section).
    #[test]
    fn snapshot_text_omits_sighup_reload_block_when_no_reloads() {
        let body = "proteus_up 1\n";
        let s = MetricsSnapshot::parse(body);
        let t = format!("{s}");
        assert!(
            !t.contains(" SIGHUP reloads"),
            "quiet snapshot must omit SIGHUP block:\n{t}"
        );
    }

    /// Text output renders the block when any of the 4 sections has
    /// a non-zero attempt counter.
    #[test]
    fn snapshot_text_renders_sighup_reload_block_when_present() {
        let body = "\
proteus_up 1\n\
proteus_firewall_reload_attempts_total 3\n\
proteus_firewall_reload_succeeded_total 3\n\
proteus_rate_limit_reload_attempts_total 3\n\
proteus_rate_limit_reload_succeeded_total 3\n";
        let s = MetricsSnapshot::parse(body);
        let t = format!("{s}");
        assert!(t.contains(" SIGHUP reloads"), "{t}");
        assert!(t.contains("firewall"), "{t}");
        assert!(t.contains("3 (3 ok)"), "{t}");
        // user_rate_limit had zero attempts → not rendered.
        assert!(!t.contains("user_rate_limit"), "{t}");
    }

    // ----- Process-lifecycle parse / render tests -----

    #[test]
    fn snapshot_parses_process_lifecycle_lines() {
        let body = "\
proteus_up 1\n\
proteus_process_start_unix_seconds 1747526400\n\
proteus_process_uptime_seconds 3725\n\
proteus_build_info{version=\"0.1.0\",rustc=\"1.85.0\",target=\"aarch64-apple-darwin\"} 1\n";
        let s = MetricsSnapshot::parse(body);
        assert_eq!(s.process_start_unix_seconds, Some(1_747_526_400));
        assert_eq!(s.process_uptime_seconds, Some(3725));
        let bi = s.process_build_info.unwrap();
        assert_eq!(bi.version, "0.1.0");
        assert_eq!(bi.rustc, "1.85.0");
        assert_eq!(bi.target, "aarch64-apple-darwin");
    }

    #[test]
    fn snapshot_process_lifecycle_defaults_when_absent() {
        let body = "proteus_up 1\n";
        let s = MetricsSnapshot::parse(body);
        assert!(s.process_start_unix_seconds.is_none());
        assert!(s.process_uptime_seconds.is_none());
        assert!(s.process_build_info.is_none());
    }

    #[test]
    fn snapshot_build_info_tolerates_partial_labels() {
        let body = "proteus_up 1\nproteus_build_info{version=\"0.1.0\"} 1\n";
        let s = MetricsSnapshot::parse(body);
        let bi = s.process_build_info.unwrap();
        assert_eq!(bi.version, "0.1.0");
        assert!(bi.rustc.is_empty());
        assert!(bi.target.is_empty());
    }

    #[test]
    fn snapshot_json_emits_process_lifecycle_null_when_absent() {
        let s = MetricsSnapshot::parse("proteus_up 1\n");
        let j = s.to_json();
        assert!(j.contains(r#""process_start_unix_seconds":null"#), "{j}");
        assert!(j.contains(r#""process_uptime_seconds":null"#), "{j}");
        assert!(j.contains(r#""process_build_info":null"#), "{j}");
    }

    #[test]
    fn snapshot_json_emits_process_lifecycle_values_when_present() {
        let body = "\
proteus_up 1\n\
proteus_process_start_unix_seconds 1747526400\n\
proteus_process_uptime_seconds 100\n\
proteus_build_info{version=\"0.2.0\",rustc=\"\",target=\"\"} 1\n";
        let s = MetricsSnapshot::parse(body);
        let j = s.to_json();
        assert!(
            j.contains(r#""process_start_unix_seconds":1747526400"#),
            "{j}"
        );
        assert!(j.contains(r#""process_uptime_seconds":100"#), "{j}");
        assert!(
            j.contains(r#""process_build_info":{"version":"0.2.0","rustc":"","target":""}"#),
            "{j}"
        );
    }

    #[test]
    fn snapshot_text_omits_process_block_when_absent() {
        let s = MetricsSnapshot::parse("proteus_up 1\n");
        let t = format!("{s}");
        assert!(!t.contains(" Process"), "{t}");
    }

    #[test]
    fn snapshot_text_renders_process_block_when_present() {
        let body = "\
proteus_up 1\n\
proteus_process_start_unix_seconds 1747526400\n\
proteus_process_uptime_seconds 3725\n\
proteus_build_info{version=\"0.1.0\",rustc=\"1.85.0\",target=\"x86_64-unknown-linux-gnu\"} 1\n";
        let s = MetricsSnapshot::parse(body);
        let t = format!("{s}");
        assert!(t.contains(" Process"), "{t}");
        assert!(t.contains("start_unix_seconds"), "{t}");
        assert!(t.contains("1747526400"), "{t}");
        // Humanized uptime: 3725s = 1h 2m 5s
        assert!(t.contains("3725s"), "{t}");
        assert!(t.contains("1h"), "{t}");
        // Build line shows version + rustc + target.
        assert!(t.contains("version=0.1.0"), "{t}");
        assert!(t.contains("rustc=1.85.0"), "{t}");
        assert!(t.contains("target=x86_64-unknown-linux-gnu"), "{t}");
    }

    #[test]
    fn snapshot_text_build_block_shows_unset_for_empty_fields() {
        let body = "\
proteus_up 1\n\
proteus_build_info{version=\"0.1.0\",rustc=\"\",target=\"\"} 1\n";
        let s = MetricsSnapshot::parse(body);
        let t = format!("{s}");
        assert!(t.contains("version=0.1.0"), "{t}");
        assert!(t.contains("rustc=(unset)"), "{t}");
        assert!(t.contains("target=(unset)"), "{t}");
    }

    // ----- Config-presence parse / render tests -----

    /// Parser extracts every `proteus_config_section_active` row
    /// where value=1 into the BTreeSet, ignores value=0 rows.
    #[test]
    fn snapshot_parses_config_section_active_lines() {
        let body = "\
proteus_up 1\n\
proteus_config_section_active{section=\"tls\"} 1\n\
proteus_config_section_active{section=\"firewall\"} 1\n\
proteus_config_section_active{section=\"rate_limit\"} 0\n\
proteus_config_section_active{section=\"cover_endpoints\"} 1\n\
proteus_config_cover_endpoint_pool_size 3\n\
proteus_config_client_allowlist_size 5\n";
        let s = MetricsSnapshot::parse(body);
        assert!(s.config_active_sections.contains("tls"));
        assert!(s.config_active_sections.contains("firewall"));
        assert!(s.config_active_sections.contains("cover_endpoints"));
        assert!(!s.config_active_sections.contains("rate_limit"));
        assert_eq!(s.config_cover_endpoint_pool_size, 3);
        assert_eq!(s.config_client_allowlist_size, 5);
    }

    /// Absent series → empty set + zero gauges (back-compat: older
    /// servers + non-v4-wired metrics endpoints).
    #[test]
    fn snapshot_config_presence_defaults_when_absent() {
        let body = "proteus_up 1\n";
        let s = MetricsSnapshot::parse(body);
        assert!(s.config_active_sections.is_empty());
        assert_eq!(s.config_cover_endpoint_pool_size, 0);
        assert_eq!(s.config_client_allowlist_size, 0);
    }

    /// Malformed labelled lines must NOT panic or leak into `other`.
    #[test]
    fn snapshot_parser_skips_malformed_config_section_lines() {
        let body = "\
proteus_up 1\n\
proteus_config_section_active{wrong_label=\"tls\"} 1\n\
proteus_config_section_active{section=missing-quotes} 1\n";
        let s = MetricsSnapshot::parse(body);
        assert!(s.config_active_sections.is_empty());
    }

    /// JSON output sorts the sections (BTreeSet iteration order) so
    /// scripted consumers get stable output.
    #[test]
    fn snapshot_json_emits_config_active_sections_sorted() {
        let body = "\
proteus_up 1\n\
proteus_config_section_active{section=\"tls\"} 1\n\
proteus_config_section_active{section=\"firewall\"} 1\n\
proteus_config_section_active{section=\"cover_endpoints\"} 1\n";
        let s = MetricsSnapshot::parse(body);
        let j = s.to_json();
        let i_cover = j.find(r#""cover_endpoints""#).unwrap();
        let i_fw = j.find(r#""firewall""#).unwrap();
        let i_tls = j.find(r#""tls""#).unwrap();
        // BTreeSet sorts lexically: cover_endpoints < firewall < tls.
        assert!(i_cover < i_fw, "{j}");
        assert!(i_fw < i_tls, "{j}");
    }

    /// JSON output emits an empty array when no sections are
    /// active — scripts can rely on the key's presence.
    #[test]
    fn snapshot_json_emits_empty_config_active_sections_when_absent() {
        let body = "proteus_up 1\n";
        let s = MetricsSnapshot::parse(body);
        let j = s.to_json();
        assert!(j.contains(r#""config_active_sections":[]"#), "{j}");
        assert!(j.contains(r#""config_cover_endpoint_pool_size":0"#), "{j}");
        assert!(j.contains(r#""config_client_allowlist_size":0"#), "{j}");
    }

    /// Text output omits the block entirely when no config-presence
    /// series were on the wire (older server / older metrics
    /// endpoint).
    #[test]
    fn snapshot_text_omits_active_config_block_when_absent() {
        let body = "proteus_up 1\n";
        let s = MetricsSnapshot::parse(body);
        let t = format!("{s}");
        assert!(!t.contains(" Active config sections"), "{t}");
    }

    /// Text output renders the block when at least one section /
    /// pool size / allowlist size is non-zero.
    #[test]
    fn snapshot_text_renders_active_config_block_when_present() {
        let body = "\
proteus_up 1\n\
proteus_config_section_active{section=\"tls\"} 1\n\
proteus_config_section_active{section=\"firewall\"} 1\n\
proteus_config_section_active{section=\"probe_anomaly\"} 1\n\
proteus_config_cover_endpoint_pool_size 4\n\
proteus_config_client_allowlist_size 2\n";
        let s = MetricsSnapshot::parse(body);
        let t = format!("{s}");
        assert!(t.contains(" Active config sections"), "{t}");
        // Sections rendered alphabetically.
        assert!(t.contains("firewall, probe_anomaly, tls"), "{t}");
        assert!(t.contains("cover_endpoint_pool_size"), "{t}");
        assert!(t.contains("4"), "{t}");
    }

    /// Text output flags the "missing" gap when attempts > succeeded
    /// — the silent SIGHUP failure signal operators alert on.
    #[test]
    fn snapshot_text_flags_missing_sighup_reload_outcomes() {
        let body = "\
proteus_up 1\n\
proteus_rate_limit_reload_attempts_total 4\n\
proteus_rate_limit_reload_succeeded_total 0\n";
        let s = MetricsSnapshot::parse(body);
        let t = format!("{s}");
        assert!(
            t.contains("4 (0 ok, 4 missing"),
            "expected '4 (0 ok, 4 missing' marker for silent SIGHUP failure: {t}"
        );
    }
}
