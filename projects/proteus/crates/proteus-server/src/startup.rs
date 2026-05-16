//! Single-source-of-truth startup configuration banner.
//!
//! Operators booting a new Proteus server expect to run
//! `journalctl -u proteus-server -n 30` and see one canonical block
//! that summarizes every loaded knob. Without that, verifying a YAML
//! edit took effect means grepping through scattered info-level
//! lines.
//!
//! [`StartupSummary`] captures every field that materially affects
//! production behavior. The Display impl emits a multi-line aligned
//! block of `key = value` pairs separated by a header and footer
//! ruled line. The block is **stable** across releases — operators
//! script against it (`grep '^  cover_endpoint'`, etc.) so adding
//! new fields is safe but renaming existing ones is breaking.
//!
//! The summary is also keyed-loggable. The binary emits it via a
//! single `info!` macro call so structured-log consumers (Loki,
//! CloudWatch) get one event with all the fields as proper keys,
//! while humans grep the printed banner.
//!
//! Build it via [`StartupSummary::from_config`] which derives every
//! field from the loaded [`crate::config::ServerConfig`]. The
//! function is pure (no side effects) so it can be unit-tested.

use std::fmt;

use crate::config::ServerConfig;

/// Snapshot of operator-visible runtime configuration at startup.
///
/// All fields are derived from the loaded [`ServerConfig`]. They
/// describe **policy**, not state — `in_flight_sessions` and other
/// counters live in [`proteus_transport_alpha::metrics::ServerMetrics`].
#[derive(Debug, Clone)]
pub struct StartupSummary {
    pub version: &'static str,
    pub listen_alpha: String,
    pub listen_beta: Option<String>,
    pub tls_enabled: bool,
    pub tls_cert_chain: Option<String>,
    pub allowlist_users: usize,
    pub cover_endpoint: Option<String>,
    pub rate_limit: Option<(f64, f64)>,
    pub handshake_budget: Option<(f64, f64)>,
    pub user_rate_limit: Option<(f64, f64, usize)>,
    pub firewall_allow_rules: usize,
    pub firewall_deny_rules: usize,
    pub max_connections: Option<usize>,
    pub pow_difficulty: u8,
    pub handshake_deadline_secs: u64,
    pub tcp_keepalive_secs: u64,
    pub session_idle_secs: u64,
    pub max_session_bytes: Option<u64>,
    pub drain_secs: u64,
    pub metrics_listen: Option<String>,
    pub metrics_auth: bool,
    pub access_log: Option<String>,
}

impl StartupSummary {
    /// Build a summary from the loaded config. Pure function — no
    /// I/O, no clock reads, no environment lookups.
    #[must_use]
    pub fn from_config(cfg: &ServerConfig) -> Self {
        Self {
            version: env!("CARGO_PKG_VERSION"),
            listen_alpha: cfg.listen_alpha.clone(),
            listen_beta: cfg.listen_beta.clone(),
            tls_enabled: cfg.tls.is_some(),
            tls_cert_chain: cfg.tls.as_ref().map(|t| t.cert_chain.display().to_string()),
            allowlist_users: cfg.client_allowlist.len(),
            cover_endpoint: cfg.cover_endpoint.clone(),
            rate_limit: cfg.rate_limit.as_ref().map(|r| (r.burst, r.refill_per_sec)),
            handshake_budget: cfg
                .handshake_budget
                .as_ref()
                .map(|r| (r.burst, r.refill_per_sec)),
            user_rate_limit: cfg
                .user_rate_limit
                .as_ref()
                .map(|u| (u.burst, u.refill_per_sec, u.max_users)),
            firewall_allow_rules: cfg.firewall.as_ref().map_or(0, |f| f.allow.len()),
            firewall_deny_rules: cfg.firewall.as_ref().map_or(0, |f| f.deny.len()),
            max_connections: cfg.max_connections,
            pow_difficulty: cfg.pow_difficulty.unwrap_or(0),
            handshake_deadline_secs: cfg.handshake_deadline_secs.unwrap_or(15),
            tcp_keepalive_secs: cfg.tcp_keepalive_secs.unwrap_or(30),
            session_idle_secs: cfg.session_idle_secs.unwrap_or(600),
            max_session_bytes: cfg.max_session_bytes,
            drain_secs: cfg.drain_secs.unwrap_or(30),
            metrics_listen: cfg.metrics_listen.clone(),
            metrics_auth: cfg.metrics_token_file.is_some(),
            access_log: cfg.access_log.as_ref().map(|p| p.display().to_string()),
        }
    }

    /// Are any of the production-required defenses missing? Returns
    /// a list of human-readable warnings the operator should heed.
    /// Empty list = "production-ready by Proteus's checklist".
    #[must_use]
    pub fn warnings(&self) -> Vec<&'static str> {
        let mut out = Vec::new();
        if !self.tls_enabled {
            out.push(
                "tls block is missing — server will run plain TCP; passive DPI will identify the protocol",
            );
        }
        if self.cover_endpoint.is_none() {
            out.push(
                "cover_endpoint is unset — auth-fail connections will be silently dropped instead of byte-spliced to a cover server",
            );
        }
        if self.rate_limit.is_none() {
            out.push(
                "rate_limit is unset — server is vulnerable to per-IP ML-KEM amplification DoS",
            );
        }
        if self.max_connections.is_none() {
            out.push("max_connections is unset — server is vulnerable to accept-flood OOM");
        }
        if self.allowlist_users == 0 {
            out.push(
                "client_allowlist is empty — server accepts any client; only acceptable for testing",
            );
        }
        if self.metrics_listen.is_some() && !self.metrics_auth {
            // Inspecting whether the bind is loopback would require
            // parsing the addr here; the binary already does that and
            // warns separately. Surface the operator-visible fact:
            // metrics is open without auth.
            out.push(
                "metrics_listen is configured but metrics_token_file is not — /metrics is unauthenticated",
            );
        }
        out
    }
}

impl fmt::Display for StartupSummary {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // 60-char rule for the banner; aligned key column.
        writeln!(
            f,
            "============================================================"
        )?;
        writeln!(
            f,
            " proteus-server {} — startup configuration",
            self.version
        )?;
        writeln!(
            f,
            "============================================================"
        )?;

        macro_rules! row {
            ($label:expr, $value:expr) => {
                writeln!(f, "  {:<26} {}", $label, $value)
            };
        }

        row!("listen_alpha", &self.listen_alpha)?;
        match &self.listen_beta {
            Some(b) => row!("listen_beta (QUIC)", b)?,
            None => row!("listen_beta (QUIC)", "<unset>")?,
        }
        row!(
            "tls",
            if self.tls_enabled {
                "enabled"
            } else {
                "DISABLED (insecure)"
            }
        )?;
        if let Some(chain) = &self.tls_cert_chain {
            row!("tls.cert_chain", chain)?;
        }
        row!("allowlist_users", self.allowlist_users)?;
        match &self.cover_endpoint {
            Some(c) => row!("cover_endpoint", c)?,
            None => row!("cover_endpoint", "<unset>")?,
        }
        match &self.rate_limit {
            Some((burst, refill)) => row!(
                "rate_limit (per-IP)",
                format_args!("burst={burst}, refill={refill}/s")
            )?,
            None => row!("rate_limit (per-IP)", "<unset>")?,
        }
        match &self.handshake_budget {
            Some((burst, refill)) => row!(
                "handshake_budget (global)",
                format_args!("burst={burst}, refill={refill}/s")
            )?,
            None => row!("handshake_budget (global)", "<unset>")?,
        }
        match &self.user_rate_limit {
            Some((burst, refill, max)) => row!(
                "rate_limit (per-user)",
                format_args!("burst={burst}, refill={refill}/s, max_users={max}")
            )?,
            None => row!("rate_limit (per-user)", "<unset>")?,
        }
        row!(
            "firewall",
            format_args!(
                "allow_rules={}, deny_rules={}",
                self.firewall_allow_rules, self.firewall_deny_rules
            )
        )?;
        match self.max_connections {
            Some(n) => row!("max_connections", n)?,
            None => row!("max_connections", "<unset>")?,
        }
        row!(
            "pow_difficulty",
            if self.pow_difficulty == 0 {
                "0 (off)".to_string()
            } else {
                format!("{} bits", self.pow_difficulty)
            }
        )?;
        row!(
            "handshake_deadline",
            format_args!("{}s", self.handshake_deadline_secs)
        )?;
        row!(
            "tcp_keepalive",
            format_args!("{}s", self.tcp_keepalive_secs)
        )?;
        row!(
            "session_idle",
            if self.session_idle_secs == 0 {
                "<disabled>".to_string()
            } else {
                format!("{}s", self.session_idle_secs)
            }
        )?;
        match self.max_session_bytes {
            Some(n) => row!(
                "max_session_bytes",
                format_args!("{n} bytes ({})", human_bytes(n))
            )?,
            None => row!("max_session_bytes", "<unset>")?,
        }
        row!("drain", format_args!("{}s", self.drain_secs))?;
        match &self.metrics_listen {
            Some(addr) => row!(
                "metrics_listen",
                format_args!(
                    "{}{}",
                    addr,
                    if self.metrics_auth {
                        " (auth)"
                    } else {
                        " (open)"
                    }
                )
            )?,
            None => row!("metrics_listen", "<unset>")?,
        }
        match &self.access_log {
            Some(p) => row!("access_log", p)?,
            None => row!("access_log", "<unset>")?,
        }

        let warnings = self.warnings();
        if !warnings.is_empty() {
            writeln!(
                f,
                "------------------------------------------------------------"
            )?;
            writeln!(f, " WARNINGS ({}):", warnings.len())?;
            for w in &warnings {
                writeln!(f, "   ⚠  {w}")?;
            }
        }
        writeln!(
            f,
            "============================================================"
        )?;
        Ok(())
    }
}

/// Render `n` as `"X.YZ unit"` (KiB / MiB / GiB / TiB). Display-only;
/// numeric fields keep their raw byte counts.
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{
        FirewallCfg, KeysCfg, RateLimitCfg, ServerConfig, TlsCfg, UserRateLimitCfg,
    };
    use std::path::PathBuf;

    fn empty_cfg() -> ServerConfig {
        ServerConfig {
            listen_alpha: "0.0.0.0:8443".to_string(),
            listen_beta: None,
            beta_cert_chain: None,
            beta_private_key: None,
            keys: KeysCfg {
                mlkem_pk: PathBuf::from("/dev/null"),
                mlkem_sk: PathBuf::from("/dev/null"),
                x25519_pk: PathBuf::from("/dev/null"),
                x25519_sk: PathBuf::from("/dev/null"),
            },
            client_allowlist: Vec::new(),
            cover_endpoint: None,
            metrics_listen: None,
            metrics_token_file: None,
            rate_limit: None,
            handshake_budget: None,
            user_rate_limit: None,
            handshake_deadline_secs: None,
            tcp_keepalive_secs: None,
            tls: None,
            pow_difficulty: None,
            drain_secs: None,
            access_log: None,
            session_idle_secs: None,
            firewall: None,
            max_connections: None,
            max_session_bytes: None,
            abuse_detector: None,
            outbound_filter: None,
        }
    }

    #[test]
    fn empty_config_lists_every_warning() {
        let cfg = empty_cfg();
        let summary = StartupSummary::from_config(&cfg);
        let warnings = summary.warnings();
        // The five "production-required" warnings: tls, cover, rate
        // limit, max_connections, empty allowlist.
        assert_eq!(warnings.len(), 5, "got: {warnings:?}");
        let banner = summary.to_string();
        assert!(banner.contains("DISABLED (insecure)"));
        assert!(banner.contains("WARNINGS (5)"));
    }

    #[test]
    fn fully_loaded_config_has_no_warnings() {
        let mut cfg = empty_cfg();
        cfg.tls = Some(TlsCfg {
            cert_chain: PathBuf::from("/etc/proteus/keys/tls/fullchain.pem"),
            private_key: PathBuf::from("/etc/proteus/keys/tls/privkey.pem"),
        });
        cfg.cover_endpoint = Some("www.cloudflare.com:443".to_string());
        cfg.rate_limit = Some(RateLimitCfg {
            burst: 10.0,
            refill_per_sec: 5.0,
        });
        cfg.max_connections = Some(4096);
        cfg.client_allowlist = vec![crate::config::ClientCfg {
            user_id: "alice001".to_string(),
            ed25519_pk: PathBuf::from("/dev/null"),
        }];
        let summary = StartupSummary::from_config(&cfg);
        assert!(
            summary.warnings().is_empty(),
            "fully-loaded prod config still warned: {:?}",
            summary.warnings()
        );
    }

    #[test]
    fn metrics_without_auth_warns() {
        let mut cfg = empty_cfg();
        cfg.metrics_listen = Some("0.0.0.0:9090".to_string());
        // metrics_token_file left None.
        let summary = StartupSummary::from_config(&cfg);
        assert!(
            summary
                .warnings()
                .iter()
                .any(|w| w.contains("metrics_listen is configured but")),
            "warnings: {:?}",
            summary.warnings()
        );
    }

    #[test]
    fn metrics_with_auth_does_not_warn() {
        let mut cfg = empty_cfg();
        cfg.metrics_listen = Some("0.0.0.0:9090".to_string());
        cfg.metrics_token_file = Some(PathBuf::from("/etc/proteus/metrics.token"));
        let summary = StartupSummary::from_config(&cfg);
        // The metrics-specific warning must NOT appear (other warnings
        // about missing tls / cover etc. may still fire).
        assert!(
            !summary
                .warnings()
                .iter()
                .any(|w| w.contains("metrics_listen is configured but")),
            "should NOT warn when metrics_token_file is set: {:?}",
            summary.warnings()
        );
    }

    #[test]
    fn banner_includes_every_field_label() {
        let mut cfg = empty_cfg();
        cfg.tls = Some(TlsCfg {
            cert_chain: PathBuf::from("/x/fullchain.pem"),
            private_key: PathBuf::from("/x/privkey.pem"),
        });
        cfg.cover_endpoint = Some("cover.example.com:443".to_string());
        cfg.rate_limit = Some(RateLimitCfg {
            burst: 10.0,
            refill_per_sec: 5.0,
        });
        cfg.handshake_budget = Some(RateLimitCfg {
            burst: 500.0,
            refill_per_sec: 100.0,
        });
        cfg.user_rate_limit = Some(UserRateLimitCfg {
            burst: 5.0,
            refill_per_sec: 0.5,
            max_users: 8192,
        });
        cfg.firewall = Some(FirewallCfg {
            allow: vec!["10.0.0.0/8".to_string()],
            deny: vec!["198.51.100.42/32".to_string()],
        });
        cfg.max_connections = Some(4096);
        cfg.pow_difficulty = Some(12);
        cfg.access_log = Some(PathBuf::from("/var/log/proteus/access.log"));
        cfg.metrics_listen = Some("127.0.0.1:9090".to_string());
        cfg.metrics_token_file = Some(PathBuf::from("/etc/proteus/metrics.token"));
        cfg.session_idle_secs = Some(300);

        let banner = StartupSummary::from_config(&cfg).to_string();
        // Verify every label survives renames.
        for label in [
            "listen_alpha",
            "tls.cert_chain",
            "allowlist_users",
            "cover_endpoint",
            "rate_limit (per-IP)",
            "handshake_budget (global)",
            "rate_limit (per-user)",
            "firewall",
            "max_connections",
            "pow_difficulty",
            "handshake_deadline",
            "tcp_keepalive",
            "session_idle",
            "max_session_bytes",
            "drain",
            "metrics_listen",
            "access_log",
        ] {
            assert!(
                banner.contains(label),
                "banner missing label {label:?}:\n{banner}"
            );
        }
        assert!(banner.contains("12 bits"), "pow_difficulty bits");
        assert!(banner.contains("max_users=8192"));
        assert!(banner.contains("allow_rules=1, deny_rules=1"));
        assert!(banner.contains("(auth)"));
    }

    #[test]
    fn pow_difficulty_zero_renders_as_off() {
        let cfg = empty_cfg();
        let banner = StartupSummary::from_config(&cfg).to_string();
        assert!(banner.contains("0 (off)"), "expected 0 (off): {banner}");
    }

    #[test]
    fn session_idle_zero_renders_disabled() {
        let mut cfg = empty_cfg();
        cfg.session_idle_secs = Some(0);
        let banner = StartupSummary::from_config(&cfg).to_string();
        assert!(banner.contains("<disabled>"), "got: {banner}");
    }

    #[test]
    fn human_bytes_renders_units() {
        assert_eq!(human_bytes(0), "0 B");
        assert_eq!(human_bytes(512), "512 B");
        assert_eq!(human_bytes(1024), "1.00 KiB");
        assert_eq!(human_bytes(1024 * 1024), "1.00 MiB");
        assert_eq!(human_bytes(1024 * 1024 * 1024), "1.00 GiB");
        assert_eq!(human_bytes(50 * 1024 * 1024 * 1024), "50.00 GiB");
        assert_eq!(human_bytes(1024_u64.pow(4)), "1.00 TiB");
    }

    #[test]
    fn banner_includes_max_session_bytes_when_set() {
        let mut cfg = empty_cfg();
        cfg.max_session_bytes = Some(50 * 1024 * 1024 * 1024);
        let banner = StartupSummary::from_config(&cfg).to_string();
        assert!(
            banner.contains("max_session_bytes"),
            "missing label: {banner}"
        );
        assert!(
            banner.contains("50.00 GiB"),
            "missing human render: {banner}"
        );
    }

    #[test]
    fn banner_renders_max_session_bytes_unset() {
        let cfg = empty_cfg();
        let banner = StartupSummary::from_config(&cfg).to_string();
        assert!(
            banner.contains("max_session_bytes"),
            "missing label: {banner}"
        );
    }

    #[test]
    fn no_warnings_section_when_clean() {
        let mut cfg = empty_cfg();
        cfg.tls = Some(TlsCfg {
            cert_chain: PathBuf::from("/x/fullchain.pem"),
            private_key: PathBuf::from("/x/privkey.pem"),
        });
        cfg.cover_endpoint = Some("c:443".to_string());
        cfg.rate_limit = Some(RateLimitCfg {
            burst: 10.0,
            refill_per_sec: 5.0,
        });
        cfg.max_connections = Some(4096);
        cfg.client_allowlist = vec![crate::config::ClientCfg {
            user_id: "u".to_string(),
            ed25519_pk: PathBuf::from("/x"),
        }];
        let banner = StartupSummary::from_config(&cfg).to_string();
        assert!(
            !banner.contains("WARNINGS"),
            "clean config should not emit WARNINGS section: {banner}"
        );
    }
}
