//! `proteus-client connect-test` — one-shot handshake smoke test.
//!
//! ## Why this exists
//!
//! After provisioning a fresh `client.yaml` operators routinely
//! want to answer "does this client actually talk to the server?"
//! BEFORE wiring it into their actual workflow. Today the
//! workflow is:
//!
//!   1. `proteus-client run --config client.yaml &`
//!   2. `curl --socks5 127.0.0.1:1080 https://www.example.com/`
//!   3. Was the response real or did SOCKS error?
//!   4. Kill the client, fix the config, repeat.
//!
//! That's three commands + tab-switching + ambiguous failure
//! diagnosis (curl error might be SOCKS5 vs upstream vs DNS).
//!
//! `connect-test` collapses this into one shot:
//!
//!   proteus-client connect-test --config ~/.proteus.yaml
//!
//! Runs the FULL Proteus handshake (α-profile with the
//! operator's actual TLS connector + ed25519 identity +
//! ml-kem768 key) against the configured server, drops the
//! session, prints a timing breakdown + verdict, and exits 0
//! on success / 1 on failure. The failure mode is clean: an
//! AlphaError surface tells the operator exactly which stage
//! broke (`Tls(...)`, `Handshake(...)`, `Io(...)`).
//!
//! ## What it does NOT do
//!
//! - **Doesn't dial any upstream.** The handshake completes,
//!   we send no inner CONNECT, drop the session, exit. The
//!   server sees a session that opens + immediately closes —
//!   one access-log line per `connect-test` invocation. Operators
//!   doing many smoke runs should configure their server's
//!   abuse detectors to tolerate the burst.
//! - **Doesn't drive the SOCKS5 surface.** A separate `socks-test`
//!   or future `--upstream HOST:PORT` flag would cover the full
//!   end-to-end check; this iteration focuses on the most
//!   common failure mode (client identity / server endpoint /
//!   TLS pin misconfig).
//! - **No β-profile path yet.** β handshake test is structurally
//!   identical (just routes through `proteus_transport_beta`);
//!   shipping α first because that's where 95% of operator
//!   configs live. β `connect-test` is a one-screen follow-up.

use std::path::Path;
use std::sync::Arc;
use std::time::{Duration, Instant};

use crate::bootstrap::{resolve_for_client, BootstrapError, Resolved, ResolvedVia};
use crate::config::ClientConfig;

/// Outcome of a single `connect-test` run. Carries per-stage
/// timings so operators can see "DNS was fast, TLS was slow"
/// without re-running with profiling.
#[derive(Debug, Clone)]
pub struct ConnectTestReport {
    pub endpoint: String,
    pub resolved_addr: std::net::SocketAddr,
    pub resolved_via: ResolvedVia,
    pub dns_duration: Duration,
    pub tcp_connect_duration: Duration,
    pub handshake_duration: Duration,
    pub total_duration: Duration,
    pub outcome: ConnectTestOutcome,
}

#[derive(Debug, Clone)]
pub enum ConnectTestOutcome {
    /// Handshake completed cleanly. Session was opened and
    /// immediately dropped.
    Ok,
    /// Some stage failed. The string captures the original
    /// error's Display impl — `Tls(...)`, `Handshake(...)`,
    /// `Io(...)` are the common cases.
    Failed(String),
}

impl ConnectTestReport {
    /// Exit code: 0 on Ok, 1 on Failed.
    #[must_use]
    pub fn exit_code(&self) -> i32 {
        match self.outcome {
            ConnectTestOutcome::Ok => 0,
            ConnectTestOutcome::Failed(_) => 1,
        }
    }

    /// Render as human-readable multiline text.
    pub fn render_text(&self) -> String {
        use std::fmt::Write as _;
        let mut s = String::with_capacity(512);
        let _ = writeln!(s, "Proteus connect-test — α-profile handshake smoke");
        let _ = writeln!(s, "=================================================");
        let _ = writeln!(s, "  endpoint:        {}", self.endpoint);
        let _ = writeln!(s, "  resolved addr:   {}", self.resolved_addr);
        let _ = writeln!(s, "  resolved via:    {:?}", self.resolved_via);
        let _ = writeln!(s);
        let _ = writeln!(s, "  DNS:        {:>8.2} ms", ms(self.dns_duration));
        let _ = writeln!(s, "  TCP connect:{:>8.2} ms", ms(self.tcp_connect_duration));
        let _ = writeln!(s, "  Handshake:  {:>8.2} ms", ms(self.handshake_duration));
        let _ = writeln!(s, "  Total:      {:>8.2} ms", ms(self.total_duration));
        let _ = writeln!(s);
        match &self.outcome {
            ConnectTestOutcome::Ok => {
                let _ = writeln!(s, "  Outcome: OK — handshake completed, exit 0");
            }
            ConnectTestOutcome::Failed(e) => {
                let _ = writeln!(s, "  Outcome: FAILED — {e}");
                let _ = writeln!(s, "           exit 1");
            }
        }
        s
    }

    /// Render as a single-line JSON document for scripted gates.
    /// Append-only schema.
    pub fn render_json(&self) -> String {
        use std::fmt::Write as _;
        let mut s = String::with_capacity(384);
        s.push_str(r#"{"kind":"connect_test""#);
        let _ = write!(s, r#","endpoint":"{}""#, escape(&self.endpoint));
        let _ = write!(s, r#","resolved_addr":"{}""#, self.resolved_addr);
        let _ = write!(s, r#","resolved_via":"{:?}""#, self.resolved_via);
        let _ = write!(
            s,
            r#","dns_ms":{:.2},"tcp_connect_ms":{:.2},"handshake_ms":{:.2},"total_ms":{:.2}"#,
            ms(self.dns_duration),
            ms(self.tcp_connect_duration),
            ms(self.handshake_duration),
            ms(self.total_duration)
        );
        match &self.outcome {
            ConnectTestOutcome::Ok => {
                s.push_str(r#","outcome":"ok","exit_code":0"#);
            }
            ConnectTestOutcome::Failed(e) => {
                let _ = write!(
                    s,
                    r#","outcome":"failed","error":"{}","exit_code":1"#,
                    escape(e)
                );
            }
        }
        s.push('}');
        s
    }
}

fn ms(d: Duration) -> f64 {
    d.as_secs_f64() * 1000.0
}

fn escape(s: &str) -> String {
    s.replace('\\', "\\\\").replace('"', "\\\"")
}

/// Drive a single connect-test cycle. Loads the config, resolves
/// the endpoint, opens TCP, runs the Proteus α handshake, drops
/// the session.
pub async fn run(
    config_path: &Path,
    connect_timeout: Duration,
) -> Result<ConnectTestReport, ConnectTestError> {
    let cfg = Arc::new(ClientConfig::load(config_path).await?);
    let hs_cfg = cfg
        .build_handshake_config()
        .map_err(|e| ConnectTestError::Config(format!("build_handshake_config: {e}")))?;
    let endpoint = cfg.server_endpoint.clone();
    let started = Instant::now();

    // ---- DNS ----
    let dns_t0 = Instant::now();
    let Resolved { addr, via } = match resolve_for_client(&endpoint, &cfg).await {
        Ok(r) => r,
        Err(e) => {
            return Ok(failed_report(
                endpoint,
                "0.0.0.0:0".parse().unwrap(),
                ResolvedVia::SystemResolver,
                dns_t0.elapsed(),
                Duration::ZERO,
                Duration::ZERO,
                started.elapsed(),
                format!("dns: {e}"),
            ));
        }
    };
    let dns_dur = dns_t0.elapsed();

    // ---- TCP connect (bounded) ----
    let tcp_t0 = Instant::now();
    let tcp_result =
        tokio::time::timeout(connect_timeout, tokio::net::TcpStream::connect(addr)).await;
    let tcp = match tcp_result {
        Ok(Ok(s)) => s,
        Ok(Err(e)) => {
            return Ok(failed_report(
                endpoint,
                addr,
                via,
                dns_dur,
                tcp_t0.elapsed(),
                Duration::ZERO,
                started.elapsed(),
                format!("tcp_connect: {e}"),
            ));
        }
        Err(_) => {
            return Ok(failed_report(
                endpoint,
                addr,
                via,
                dns_dur,
                connect_timeout,
                Duration::ZERO,
                started.elapsed(),
                format!("tcp_connect timed out after {}s", connect_timeout.as_secs()),
            ));
        }
    };
    let tcp_dur = tcp_t0.elapsed();

    // ---- Handshake (bounded) ----
    let hs_t0 = Instant::now();
    let hs_result = if let Some(tls_cfg) = cfg.tls.as_ref() {
        let connector = match tls_cfg.trusted_ca.as_ref() {
            Some(ca) => proteus_transport_alpha::tls::build_connector_with_ca(ca)
                .map_err(|e| ConnectTestError::Tls(e.to_string()))?,
            None => proteus_transport_alpha::tls::build_connector_webpki_roots()
                .map_err(|e| ConnectTestError::Tls(e.to_string()))?,
        };
        let h = tokio::time::timeout(
            connect_timeout,
            proteus_transport_alpha::client::handshake_over_tls(
                tcp,
                &connector,
                &tls_cfg.server_name,
                &hs_cfg,
            ),
        )
        .await;
        match h {
            Ok(Ok(session)) => Ok(format!(
                "handshake ok over TLS (SNI={})",
                tls_cfg.server_name
            ))
            .map(|_| {
                drop(session);
            }),
            Ok(Err(e)) => Err(format!("handshake: {e}")),
            Err(_) => Err(format!(
                "handshake timed out after {}s",
                connect_timeout.as_secs()
            )),
        }
    } else {
        let h = tokio::time::timeout(
            connect_timeout,
            proteus_transport_alpha::client::handshake_over_tcp(tcp, &hs_cfg),
        )
        .await;
        match h {
            Ok(Ok(session)) => {
                drop(session);
                Ok(())
            }
            Ok(Err(e)) => Err(format!("handshake: {e}")),
            Err(_) => Err(format!(
                "handshake timed out after {}s",
                connect_timeout.as_secs()
            )),
        }
    };
    let hs_dur = hs_t0.elapsed();

    let outcome = match hs_result {
        Ok(()) => ConnectTestOutcome::Ok,
        Err(msg) => ConnectTestOutcome::Failed(msg),
    };

    Ok(ConnectTestReport {
        endpoint,
        resolved_addr: addr,
        resolved_via: via,
        dns_duration: dns_dur,
        tcp_connect_duration: tcp_dur,
        handshake_duration: hs_dur,
        total_duration: started.elapsed(),
        outcome,
    })
}

#[allow(clippy::too_many_arguments)]
fn failed_report(
    endpoint: String,
    addr: std::net::SocketAddr,
    via: ResolvedVia,
    dns_duration: Duration,
    tcp_connect_duration: Duration,
    handshake_duration: Duration,
    total_duration: Duration,
    error: String,
) -> ConnectTestReport {
    ConnectTestReport {
        endpoint,
        resolved_addr: addr,
        resolved_via: via,
        dns_duration,
        tcp_connect_duration,
        handshake_duration,
        total_duration,
        outcome: ConnectTestOutcome::Failed(error),
    }
}

/// Top-level errors that don't fit the per-stage diagnostic
/// surface (config-load failures, etc.).
#[derive(thiserror::Error, Debug)]
pub enum ConnectTestError {
    #[error("config load: {0}")]
    Config(String),
    #[error("config-derived TLS connector: {0}")]
    Tls(String),
}

impl From<crate::config::ConfigError> for ConnectTestError {
    fn from(e: crate::config::ConfigError) -> Self {
        Self::Config(e.to_string())
    }
}

impl From<BootstrapError> for ConnectTestError {
    fn from(e: BootstrapError) -> Self {
        Self::Config(e.to_string())
    }
}

/// CLI entry. Prints the report in the requested format and
/// returns the exit code.
pub async fn cli_run(
    config_path: &Path,
    connect_timeout_secs: u64,
    format: &str,
) -> std::io::Result<i32> {
    let connect_timeout = Duration::from_secs(connect_timeout_secs);
    let report = match run(config_path, connect_timeout).await {
        Ok(r) => r,
        Err(e) => {
            // Pre-handshake failure (config-level) — emit a
            // minimal report so JSON parsing on the caller's
            // side still works.
            eprintln!("connect-test setup failed: {e}");
            return Ok(2);
        }
    };
    match format {
        "json" => {
            println!("{}", report.render_json());
        }
        _ => {
            print!("{}", report.render_text());
        }
    }
    Ok(report.exit_code())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ms_converts_durations_correctly() {
        assert!((ms(Duration::from_millis(1)) - 1.0).abs() < 0.001);
        assert!((ms(Duration::from_micros(500)) - 0.5).abs() < 0.001);
    }

    #[test]
    fn escape_handles_quotes_and_backslashes() {
        assert_eq!(escape("hello"), "hello");
        assert_eq!(escape(r#"with "quotes""#), r#"with \"quotes\""#);
        assert_eq!(escape(r"a\b"), r"a\\b");
    }

    #[test]
    fn ok_report_renders_text_with_summary_and_exit_zero() {
        let r = ConnectTestReport {
            endpoint: "vps.example.com:8443".to_string(),
            resolved_addr: "198.51.100.42:8443".parse().unwrap(),
            resolved_via: ResolvedVia::IpLiteralInEndpoint,
            dns_duration: Duration::from_micros(50),
            tcp_connect_duration: Duration::from_millis(35),
            handshake_duration: Duration::from_millis(150),
            total_duration: Duration::from_millis(186),
            outcome: ConnectTestOutcome::Ok,
        };
        assert_eq!(r.exit_code(), 0);
        let s = r.render_text();
        for needle in [
            "Proteus connect-test",
            "vps.example.com:8443",
            "198.51.100.42:8443",
            "Outcome: OK",
            "DNS:",
            "TCP connect:",
            "Handshake:",
        ] {
            assert!(s.contains(needle), "missing {needle:?} in:\n{s}");
        }
    }

    #[test]
    fn failed_report_renders_text_with_error_and_exit_one() {
        let r = ConnectTestReport {
            endpoint: "vps.example.com:8443".to_string(),
            resolved_addr: "198.51.100.42:8443".parse().unwrap(),
            resolved_via: ResolvedVia::SystemResolver,
            dns_duration: Duration::from_millis(1),
            tcp_connect_duration: Duration::from_millis(35),
            handshake_duration: Duration::from_millis(15),
            total_duration: Duration::from_millis(51),
            outcome: ConnectTestOutcome::Failed("handshake: BadServerFinished".to_string()),
        };
        assert_eq!(r.exit_code(), 1);
        let s = r.render_text();
        assert!(s.contains("Outcome: FAILED"));
        assert!(s.contains("BadServerFinished"));
    }

    #[test]
    fn json_render_contains_all_fields_and_parseable_structure() {
        let r = ConnectTestReport {
            endpoint: "vps.example.com:8443".to_string(),
            resolved_addr: "198.51.100.42:8443".parse().unwrap(),
            resolved_via: ResolvedVia::PinnedDirectIp,
            dns_duration: Duration::from_micros(100),
            tcp_connect_duration: Duration::from_millis(40),
            handshake_duration: Duration::from_millis(120),
            total_duration: Duration::from_millis(160),
            outcome: ConnectTestOutcome::Ok,
        };
        let j = r.render_json();
        for needle in [
            r#""kind":"connect_test""#,
            r#""endpoint":"vps.example.com:8443""#,
            r#""resolved_addr":"198.51.100.42:8443""#,
            r#""dns_ms":"#,
            r#""tcp_connect_ms":"#,
            r#""handshake_ms":"#,
            r#""total_ms":"#,
            r#""outcome":"ok""#,
            r#""exit_code":0"#,
        ] {
            assert!(j.contains(needle), "missing {needle:?} in:\n{j}");
        }
        assert!(
            !j.ends_with('\n'),
            "render_json must not emit trailing newline"
        );
    }

    #[test]
    fn json_render_failed_includes_error_field() {
        let r = ConnectTestReport {
            endpoint: "vps.example.com:8443".to_string(),
            resolved_addr: "198.51.100.42:8443".parse().unwrap(),
            resolved_via: ResolvedVia::SystemResolver,
            dns_duration: Duration::from_millis(1),
            tcp_connect_duration: Duration::from_millis(35),
            handshake_duration: Duration::ZERO,
            total_duration: Duration::from_millis(36),
            outcome: ConnectTestOutcome::Failed("tcp_connect: refused".to_string()),
        };
        let j = r.render_json();
        assert!(j.contains(r#""outcome":"failed""#));
        assert!(j.contains(r#""error":"tcp_connect: refused""#));
        assert!(j.contains(r#""exit_code":1"#));
    }

    #[test]
    fn json_render_escapes_quotes_in_error_message() {
        let r = ConnectTestReport {
            endpoint: r#"weird"endpoint:8443"#.to_string(),
            resolved_addr: "198.51.100.42:8443".parse().unwrap(),
            resolved_via: ResolvedVia::SystemResolver,
            dns_duration: Duration::ZERO,
            tcp_connect_duration: Duration::ZERO,
            handshake_duration: Duration::ZERO,
            total_duration: Duration::ZERO,
            outcome: ConnectTestOutcome::Failed(r#"err with "quote""#.to_string()),
        };
        let j = r.render_json();
        assert!(j.contains(r#""endpoint":"weird\"endpoint:8443""#));
        assert!(j.contains(r#""error":"err with \"quote\"""#));
    }
}
