//! Configuration preflight (`proteus-client validate <path>`).
//!
//! Catches operator errors BEFORE the SOCKS5 listener binds, so a
//! typo in `client.yaml` doesn't manifest as a silent dial failure
//! at every CONNECT attempt — instead it fails fast at deploy
//! time with a clear diagnostic.
//!
//! Mirrors `proteus-server validate` in scope: pure I/O against
//! the config file and the files it references. Does NOT bind
//! sockets, does NOT dial the upstream server, does NOT call
//! `accept()`. Designed to run inside CI / Ansible / Terraform
//! gates BEFORE the client binary is restarted.
//!
//! Exit code: 0 on all-green; 1 if any check failed.
//!
//! ## Checks performed
//!
//! Required-field presence:
//!   - `server_endpoint` non-empty, parses as `host:port`.
//!   - `socks_listen` non-empty, parses as `host:port`.
//!   - `user_id` non-empty, ≤ 8 bytes (`encode_user_id` truncation
//!     would silently drop the rest — operator must shorten).
//!
//! Key file accessibility + length:
//!   - `keys.server_mlkem_pk` exists, decodes to exactly 1184 bytes
//!     raw OR ~1580-1592 bytes base64 (FIPS-203 §6.1; tightened in
//!     iter-139 — pre-iter-139 the gate was the permissive
//!     "≥ 32 bytes" which let any truncated EK pass validate).
//!   - `keys.server_x25519_pk` exists, decodes to exactly 32 bytes.
//!   - `keys.server_pq_fingerprint` exists, decodes to exactly 32 bytes.
//!   - `keys.client_ed25519_sk` exists, decodes to exactly 32 bytes.
//!
//! TLS:
//!   - When `tls.trusted_ca` is set, the file is readable and
//!     contains at least one PEM CERTIFICATE block.
//!
//! β-profile coherence:
//!   - When `server_endpoint_beta` is set:
//!     - It parses as `host:port`.
//!     - Either `beta_server_name` OR `tls.server_name` must be set
//!       (the β QUIC handshake needs SNI).
//!     - `beta_initial_mtu` is in the [1200, 1500] sanity range.
//!
//! Numeric sanity warnings (Warn, not Fail):
//!   - `pad_quantum` outside {0, 64, 128, 256, 512, 1280} —
//!     unusual; operator should re-check (typo for 1280?).
//!   - `pow_difficulty` > 24 — likely a typo; sustained 24-bit
//!     PoW costs ~1 s on a laptop, anything higher is operator-
//!     hostile.
//!
//! Bootstrap-DNS posture (Warn, not Fail — production decision is
//! the operator's, but the default is dangerous in 2026):
//!   - `server_endpoint` is a hostname AND `bootstrap_dns` is unset
//!     or set to `system` → WARN. The 2026 GFW identifies DoH/DoT
//!     by flow pattern (threat-intel main line 6); a hostname
//!     resolved through the OS resolver may transit DoH and be
//!     identified before any Proteus payload is sent. Production
//!     anti-censorship deploys MUST either embed an IP literal in
//!     `server_endpoint` or set `bootstrap_dns: { direct_ip: ... }`.
//!   - `server_endpoint_beta` hostname under system bootstrap_dns →
//!     same warning, for the β carrier.
//!   - All-IP-literal deploy + still set `bootstrap_dns: direct_ip` →
//!     informational PASS (the direct_ip is ignored — harmless but
//!     the operator should know).

use std::fmt;
use std::io::Write;
use std::path::Path;

use crate::config::ClientConfig;

/// One check result. `Check::Warn` does not fail the preflight; only
/// `Check::Fail` does.
#[derive(Debug, Clone)]
pub enum Check {
    Pass(String),
    Warn(String),
    Fail(String),
}

impl Check {
    fn is_fail(&self) -> bool {
        matches!(self, Check::Fail(_))
    }
}

/// Output of a full preflight run.
#[derive(Debug, Clone, Default)]
pub struct PreflightReport {
    pub checks: Vec<Check>,
}

impl PreflightReport {
    /// True if any [`Check::Fail`] is present.
    #[must_use]
    pub fn has_failures(&self) -> bool {
        self.checks.iter().any(Check::is_fail)
    }

    /// `(passes, warns, fails)` counts.
    #[must_use]
    pub fn counts(&self) -> (usize, usize, usize) {
        let mut p = 0;
        let mut w = 0;
        let mut f = 0;
        for c in &self.checks {
            match c {
                Check::Pass(_) => p += 1,
                Check::Warn(_) => w += 1,
                Check::Fail(_) => f += 1,
            }
        }
        (p, w, f)
    }

    fn push_pass(&mut self, s: impl Into<String>) {
        self.checks.push(Check::Pass(s.into()));
    }
    fn push_warn(&mut self, s: impl Into<String>) {
        self.checks.push(Check::Warn(s.into()));
    }
    fn push_fail(&mut self, s: impl Into<String>) {
        self.checks.push(Check::Fail(s.into()));
    }
}

impl fmt::Display for PreflightReport {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for c in &self.checks {
            match c {
                Check::Pass(s) => writeln!(f, "  PASS  {s}")?,
                Check::Warn(s) => writeln!(f, "  WARN  {s}")?,
                Check::Fail(s) => writeln!(f, "  FAIL  {s}")?,
            }
        }
        let (p, w, fail) = self.counts();
        writeln!(f, "\nsummary: {p} pass, {w} warn, {fail} fail")?;
        Ok(())
    }
}

/// Run the preflight against the YAML at `path`. Returns the report;
/// caller decides exit code based on `has_failures()`.
pub async fn run(path: &Path) -> PreflightReport {
    let mut r = PreflightReport::default();

    // ----- Parse step ----- (any further checks need the parsed cfg).
    let cfg = match ClientConfig::load(path).await {
        Ok(c) => {
            r.push_pass(format!("YAML parses: {}", path.display()));
            c
        }
        Err(e) => {
            r.push_fail(format!("YAML parse failed: {e}"));
            return r;
        }
    };

    // ----- Required fields -----
    if cfg.server_endpoint.is_empty() {
        r.push_fail("server_endpoint is empty");
    } else if parse_host_port(&cfg.server_endpoint).is_some() {
        r.push_pass(format!("server_endpoint = {}", cfg.server_endpoint));
    } else {
        r.push_fail(format!(
            "server_endpoint does not parse as host:port: {:?}",
            cfg.server_endpoint
        ));
    }

    // ----- Multi-VPS HA fallback list (server_endpoints) -----
    //
    // Operator-opt-in; empty by default. When present, every entry
    // must parse as host:port. Repeats of the primary entry are
    // accepted (operator may include it as a deliberate retry
    // anchor). Single-entry list is a hard WARN — equivalent to
    // having no list at all, so the operator probably meant to add
    // more.
    if !cfg.server_endpoints.is_empty() {
        let mut bad = Vec::new();
        for (idx, raw) in cfg.server_endpoints.iter().enumerate() {
            if raw.is_empty() {
                bad.push(format!("[{idx}] empty"));
            } else if parse_host_port(raw).is_none() {
                bad.push(format!("[{idx}]={raw:?}"));
            }
        }
        if bad.is_empty() {
            r.push_pass(format!(
                "server_endpoints pool ({} entries) — multi-VPS HA dispatch wins over \
                 single server_endpoint at runtime",
                cfg.server_endpoints.len()
            ));
        } else {
            r.push_fail(format!(
                "server_endpoints has bad host:port entries: {}",
                bad.join(", ")
            ));
        }
        if cfg.server_endpoints.len() == 1 {
            r.push_warn(
                "server_endpoints has only one entry — equivalent to the single-endpoint \
                 fallback; add ≥2 distinct VPS endpoints to actually get HA (or remove the \
                 field entirely to silence this warning)",
            );
        }
        // Iter-59: duplicate pool entries reduce effective HA
        // breadth. EndpointPool dispatches in declaration order,
        // recording per-entry health. Two identical entries
        // would mark both as suppressed when the underlying VPS
        // dies (correct), but they ALSO occupy two of the N pool
        // slots — the operator who set `[primary, primary, backup]`
        // thinking they had 3-way HA actually has 2-way (primary
        // doubled doesn't add resilience; the backup is still
        // the only true failover). Surface as WARN.
        let mut seen: std::collections::HashSet<&str> =
            std::collections::HashSet::with_capacity(cfg.server_endpoints.len());
        let mut dupes: Vec<&str> = Vec::new();
        for raw in &cfg.server_endpoints {
            if !seen.insert(raw.as_str()) && !dupes.contains(&raw.as_str()) {
                dupes.push(raw.as_str());
            }
        }
        if !dupes.is_empty() {
            r.push_warn(format!(
                "server_endpoints contains duplicate entries: {dupes:?}. Duplicate \
                 entries do NOT add HA — they occupy pool slots but suppress together \
                 when the underlying VPS dies. Replace duplicates with distinct backup \
                 destinations.",
            ));
        }
        // Coherence warn: if server_endpoint is NOT present in the
        // pool, the operator has set up a strange config where the
        // primary they configured isn't in the failover list. Likely
        // intentional in some advanced topologies but suspicious in
        // the common case.
        if !cfg
            .server_endpoints
            .iter()
            .any(|e| e == &cfg.server_endpoint)
        {
            r.push_warn(
                "server_endpoint is not present in server_endpoints — operator has set up a \
                 split-brain pool where the primary is dialed only when the fallback list is \
                 exhausted. If intentional, fine; if accidental, add the primary to \
                 server_endpoints[0]",
            );
        }

        // Iter-43: TLS SNI consistency check.
        //
        // The dispatcher ALWAYS uses `cfg.tls.server_name` as the
        // SNI for cert verification, regardless of which pool entry
        // the connection lands on. That's correct when:
        //   - pool entries are IP literals (operator decoupled
        //     routing-address from cert-identity — every entry's
        //     cert must validate as `tls.server_name`, the IP is
        //     just where to dial); OR
        //   - pool entries are hostnames that happen to match
        //     `tls.server_name` exactly (e.g. all `vps.example.com`
        //     resolving to different A records — pointless without
        //     bootstrap_dns pinning, but valid).
        //
        // It's a real operator-trap when pool entries are
        // *different hostnames* (e.g. `primary.vps.example.com` +
        // `backup.vps.example.com`) than `tls.server_name`. Every
        // dial after the first hostname-mismatch ends in TLS
        // cert-verification failure with no obvious cause.
        //
        // Surface this at validate time, before deploy. The IP-
        // literal case (most common production setup) is silently
        // accepted; only hostname divergence trips the warn.
        if let Some(tls) = cfg.tls.as_ref() {
            let sni = tls.server_name.as_str();
            if !sni.is_empty() {
                let mut diverging = Vec::new();
                for ep in &cfg.server_endpoints {
                    let Some((host, _port)) = parse_host_port(ep) else {
                        continue; // bad entry — already FAIL'd above
                    };
                    // IP literal? Skip — operator decoupled
                    // routing from identity, which is fine.
                    if host.parse::<std::net::IpAddr>().is_ok() {
                        continue;
                    }
                    // Hostname matches SNI exactly? Fine.
                    if host.eq_ignore_ascii_case(sni) {
                        continue;
                    }
                    diverging.push(ep.clone());
                }
                if !diverging.is_empty() {
                    r.push_warn(format!(
                        "server_endpoints contains hostname(s) that don't match \
                         tls.server_name={sni:?}: {diverging:?}. The dispatcher uses \
                         tls.server_name as TLS SNI for EVERY pool entry, so dialing these \
                         entries will fail TLS cert verification (the served cert must \
                         validate as {sni:?}, not the dial-address hostname). If you need \
                         per-entry SNI, use IP literals in server_endpoints and keep \
                         tls.server_name as the operator-chosen cert identity.",
                    ));
                }
            }
        }
    }

    if cfg.socks_listen.is_empty() {
        r.push_fail("socks_listen is empty");
    } else if let Some((socks_host, _)) = parse_host_port(&cfg.socks_listen) {
        r.push_pass(format!("socks_listen = {}", cfg.socks_listen));
        // Iter-71: non-loopback socks_listen is an open-proxy
        // amplifier.
        //
        // The Proteus SOCKS5 inbound implements RFC 1928 with
        // NO authentication (method 0x00). When socks_listen
        // binds to 0.0.0.0 / :: / a LAN IP, ANY device that can
        // reach the address can route arbitrary traffic through
        // the operator's Proteus tunnel. Three failure modes:
        //
        //   1. LAN-share unintended: operator binds 0.0.0.0 to
        //      let their phone use the tunnel, doesn't realize
        //      their neighbor's compromised IoT box on the same
        //      WiFi gets free relay too.
        //   2. Cloud-VPS bind: operator runs proteus-client on a
        //      cloud VPS for "always-on" tunneling, accidentally
        //      binds 0.0.0.0 — now the entire internet has free
        //      Proteus relay. The VPS's egress IP becomes the
        //      attribution target for whatever traffic flows.
        //   3. WireGuard/Tailscale interface: operator binds the
        //      tunnel interface IP for cross-device sharing. This
        //      is legitimate IF the operator trusts every peer on
        //      the tunnel, but worth flagging because the trust
        //      assumption is non-obvious.
        //
        // FAIL on 0.0.0.0/:: (public wildcard); WARN on any other
        // non-loopback bind (operator may have chosen this
        // deliberately for tunnel-mesh sharing).
        let unbracketed = socks_host
            .strip_prefix('[')
            .and_then(|s| s.strip_suffix(']'))
            .unwrap_or(socks_host);
        let is_loopback = unbracketed
            .parse::<std::net::IpAddr>()
            .map(|ip| ip.is_loopback())
            .unwrap_or_else(|_| unbracketed.eq_ignore_ascii_case("localhost"));
        if !is_loopback {
            let is_wildcard = matches!(unbracketed, "0.0.0.0" | "::" | "");
            if is_wildcard {
                r.push_fail(format!(
                    "socks_listen = {} binds the SOCKS5 inbound to the wildcard \
                     interface. SOCKS5 has NO authentication (RFC 1928 method 0x00); \
                     anyone who can reach this address gets free relay through your \
                     Proteus tunnel. On a cloud VPS this makes the entire internet \
                     an open-proxy amplifier targeting your egress IP. Bind 127.0.0.1 \
                     (or an explicit tunnel-interface IP if you want LAN sharing).",
                    cfg.socks_listen,
                ));
            } else {
                r.push_warn(format!(
                    "socks_listen = {} is non-loopback. SOCKS5 has NO authentication \
                     (RFC 1928 method 0x00); any device that can reach this address \
                     gets free relay through your Proteus tunnel. If this is a trusted \
                     tunnel interface (WireGuard / Tailscale), fine; otherwise bind \
                     127.0.0.1.",
                    cfg.socks_listen,
                ));
            }
        }
    } else {
        r.push_fail(format!(
            "socks_listen does not parse as host:port: {:?}",
            cfg.socks_listen
        ));
    }

    // admin_listen is operator-opt-in; validate the format and
    // warn/fail when a non-loopback bind is configured.
    //
    // Iter-73: tiered severity matching iter-71's socks_listen
    // escalation. Wildcard binds are FAIL (anyone on the
    // internet for a cloud VPS deploy can scrape Carrier /
    // EndpointPool state — an inventory of the operator's HA
    // topology + per-endpoint failure rates is a useful
    // attack-prep signal); other non-loopback binds stay WARN
    // (tunnel-interface sharing is a legitimate edge case).
    if let Some(admin_addr) = cfg.admin_listen.as_deref() {
        match parse_host_port(admin_addr) {
            Some((host, _port)) => {
                // Cheap textual loopback check: covers IPv4 127.x.x.x
                // (the conventional `127.0.0.1` and oddballs like
                // `127.0.0.99` that bind to loopback), IPv6 `::1`, and
                // the literal `localhost` (system resolver maps to
                // loopback on every sensible system).
                let unbracketed = host
                    .strip_prefix('[')
                    .and_then(|s| s.strip_suffix(']'))
                    .unwrap_or(host);
                let loopback_ip = unbracketed
                    .parse::<std::net::IpAddr>()
                    .is_ok_and(|ip| ip.is_loopback());
                let is_loopback = loopback_ip || unbracketed.eq_ignore_ascii_case("localhost");
                let is_wildcard = matches!(unbracketed, "0.0.0.0" | "::" | "");
                if is_loopback {
                    r.push_pass(format!("admin_listen = {admin_addr} (loopback, no auth)"));
                } else if is_wildcard {
                    r.push_fail(format!(
                        "admin_listen = {admin_addr} binds the admin endpoint to the \
                         wildcard interface. The endpoint has NO authentication; on a \
                         cloud VPS deploy, anyone on the internet can scrape \
                         /status, /healthz, /metrics — revealing your in-process \
                         CarrierHealth, EndpointPool topology, per-endpoint dial \
                         counters, and TLS-cert expiry timeline. This is an \
                         attack-prep inventory of your HA topology. Bind 127.0.0.1 / \
                         [::1] (or an explicit tunnel-interface IP for legitimate \
                         cross-device monitoring)."
                    ));
                } else {
                    r.push_warn(format!(
                        "admin_listen = {admin_addr} is NON-loopback. The endpoint has no \
                         authentication; bind 127.0.0.1 / [::1] unless you have a specific \
                         operational reason. Anyone who can reach this address can read your \
                         in-process CarrierHealth + EndpointPool state."
                    ));
                }
            }
            None => {
                r.push_fail(format!(
                    "admin_listen does not parse as host:port: {admin_addr:?}"
                ));
            }
        }
    }

    if cfg.user_id.is_empty() {
        r.push_fail("user_id is empty");
    } else if cfg.user_id.len() > 8 {
        r.push_fail(format!(
            "user_id is {} bytes; max is 8 (encode_user_id silently truncates the rest, \
             breaking server allowlist match): {:?}",
            cfg.user_id.len(),
            cfg.user_id,
        ));
    } else if cfg.user_id.trim() != cfg.user_id {
        // Iter-56: YAML quoting around user_ids with trailing
        // whitespace is operator-trap territory. `user_id: "alice "`
        // (quoted, trailing space) gets shipped as the 6-byte
        // string "alice "; the server allowlist's `user_id: "alice"`
        // (no space) never matches. Same shape: lead/trail tab
        // from a copy-paste. Surface as FAIL — silent allowlist
        // mismatch is the failure mode this catches.
        r.push_fail(format!(
            "user_id has leading or trailing whitespace ({:?}) — encode_user_id will \
             include the whitespace bytes in the wire identity; the server allowlist \
             entry (no whitespace) will not match. Fix the YAML: unquote OR strip \
             whitespace explicitly.",
            cfg.user_id,
        ));
    } else if !cfg.user_id.is_ascii() {
        // Iter-56: encode_user_id is byte-oriented. Non-ASCII
        // user_ids (e.g. "アリス") may encode to >8 bytes in UTF-8
        // even though they "look" short. The len>8 check above
        // catches it AFTER the trap fires; flagging non-ASCII
        // explicitly gives the operator a clearer diagnostic.
        // WARN (not FAIL) because some operators may DELIBERATELY
        // use non-ASCII identifiers and rely on the byte
        // representation matching server-side.
        r.push_warn(format!(
            "user_id contains non-ASCII bytes ({:?}); encode_user_id uses raw UTF-8 \
             bytes — make sure the server's allowlist entry uses the SAME byte string \
             (paste, not retype, to avoid silent mismatch).",
            cfg.user_id,
        ));
    } else {
        r.push_pass(format!("user_id = {:?}", cfg.user_id));
    }

    // ----- Key files -----
    //
    // Iter-139: tighten the ML-KEM EK length gate from "≥32 bytes" to
    // "exactly 1184 bytes" (FIPS-203 §6.1). Pre-iter-139 the
    // permissive ≥32-byte check passed validate cleanly even when the
    // operator's `server_mlkem_pk` file was truncated, the wrong
    // file, or a base64 fragment from a half-completed copy-paste.
    // The runtime would then panic on first dial (pre-iter-138) or
    // surface `AlphaError::BadServerKey` (post-iter-138). Either way,
    // the operator-actionable signal was deferred from "validate
    // says no" to "first dial fails" — exactly the trap iter-127 /
    // iter-128 chose to close on the other binaries.
    //
    // Note the file may be base64-encoded on disk (we accept either
    // base64 or raw bytes via decode_b64_or_raw at runtime). The
    // raw-bytes path is 1184; the base64 path is ~1580 chars. We
    // gate on raw-bytes-after-decode below; a base64 file passes
    // the raw-size check trivially because we read the file bytes
    // before decoding. The simpler approach: accept either 1184
    // (raw) OR something that base64-decodes to 1184. We push the
    // logic into `check_key_file` via a tighter predicate.
    check_key_file(
        &mut r,
        "server_mlkem_pk",
        &cfg.keys.server_mlkem_pk,
        |n| n == 1184 || (1580..=1592).contains(&n),
        "exactly 1184 bytes raw OR ~1580-1592 bytes base64 (ML-KEM-768 EK; FIPS-203 §6.1)",
    );
    check_key_file(
        &mut r,
        "server_x25519_pk",
        &cfg.keys.server_x25519_pk,
        |n| n == 32,
        "exactly 32 bytes",
    );
    check_key_file(
        &mut r,
        "server_pq_fingerprint",
        &cfg.keys.server_pq_fingerprint,
        |n| n == 32,
        "exactly 32 bytes (SHA-256)",
    );
    check_key_file(
        &mut r,
        "client_ed25519_sk",
        &cfg.keys.client_ed25519_sk,
        |n| n == 32,
        "exactly 32 bytes (raw seed)",
    );

    // ----- TLS -----
    match &cfg.tls {
        Some(tls) => {
            if tls.server_name.is_empty() {
                r.push_fail("tls.server_name is empty");
            } else {
                r.push_pass(format!("tls.server_name = {}", tls.server_name));
            }
            if let Some(ca) = &tls.trusted_ca {
                match std::fs::read(ca) {
                    Ok(bytes) => {
                        if bytes.windows(11).any(|w| w == b"-----BEGIN ") {
                            r.push_pass(format!("tls.trusted_ca readable: {}", ca.display()));
                            // Iter-47: client-side cert-expiry check for the
                            // trusted_ca bundle. Symmetric with the server-
                            // side iter-46 leaf cert check. A pinned CA
                            // (private PKI / self-signed CA used as a
                            // pinning anchor) that expires causes EVERY
                            // dial to fail — same trap class. The runtime
                            // would surface no warning because the client
                            // doesn't emit `proteus_tls_cert_*` series for
                            // the trusted_ca (those are server-side metrics);
                            // the only way to catch this is at validate
                            // time. Inspects every cert in the bundle;
                            // if ANY entry is expired/near-expiry the
                            // operator gets one fix-cycle.
                            check_ca_bundle_expiry(&mut r, &bytes, ca);
                        } else {
                            r.push_fail(format!(
                                "tls.trusted_ca file does not contain a PEM block: {}",
                                ca.display()
                            ));
                        }
                    }
                    Err(e) => {
                        r.push_fail(format!("tls.trusted_ca unreadable: {} ({e})", ca.display()))
                    }
                }
            }
            if let Some(socket) = &tls.utls_bridge_socket {
                if cfg.knock_psk_file.is_none() {
                    r.push_fail(
                        "tls.utls_bridge_socket is set but knock_psk_file is unset — \
                         browser-profile mode must not silently disable the Path A knock",
                    );
                }
                if !socket.is_absolute() {
                    r.push_fail(format!(
                        "tls.utls_bridge_socket must be absolute: {}",
                        socket.display()
                    ));
                }
                #[cfg(unix)]
                {
                    use std::os::unix::fs::{FileTypeExt as _, PermissionsExt as _};
                    match std::fs::symlink_metadata(socket) {
                        Ok(meta) if meta.file_type().is_symlink() => r.push_fail(format!(
                            "tls.utls_bridge_socket must not be a symlink: {}",
                            socket.display()
                        )),
                        Ok(meta) if !meta.file_type().is_socket() => r.push_fail(format!(
                            "tls.utls_bridge_socket exists but is not a Unix socket: {}",
                            socket.display()
                        )),
                        Ok(meta) if meta.permissions().mode() & 0o077 != 0 => r.push_fail(format!(
                            "tls.utls_bridge_socket permissions are broader than 0600: {}",
                            socket.display()
                        )),
                        Ok(_) => r.push_pass(format!(
                            "tls.utls_bridge_socket is a private Unix socket: {}",
                            socket.display()
                        )),
                        Err(e) if e.kind() == std::io::ErrorKind::NotFound => r.push_warn(format!(
                            "tls.utls_bridge_socket is configured but not running yet: {}",
                            socket.display()
                        )),
                        Err(e) => r.push_fail(format!(
                            "tls.utls_bridge_socket cannot be inspected: {} ({e})",
                            socket.display()
                        )),
                    }
                }
                #[cfg(not(unix))]
                r.push_fail("tls.utls_bridge_socket is supported only on Unix");

                if let Some(ca) = &tls.trusted_ca {
                    r.push_warn(format!(
                        "uTLS bridge mode selected: launch the bridge with \
                         `--trusted-ca {}` so its certificate roots match this client config",
                        ca.display()
                    ));
                }
            }
        }
        None => r.push_warn(
            "tls: block is unset — production deployments MUST set it (server uses TLS 1.3)",
        ),
    }

    // ----- β-profile coherence -----
    if let Some(beta) = &cfg.server_endpoint_beta {
        if parse_host_port(beta).is_some() {
            r.push_pass(format!("server_endpoint_beta = {beta}"));
        } else {
            r.push_fail(format!(
                "server_endpoint_beta does not parse as host:port: {beta:?}"
            ));
        }
        // β SNI must come from somewhere.
        let has_sni = cfg.beta_server_name.is_some()
            || cfg
                .tls
                .as_ref()
                .map(|t| !t.server_name.is_empty())
                .unwrap_or(false);
        if has_sni {
            r.push_pass("β: TLS SNI available (beta_server_name or tls.server_name set)");
        } else {
            r.push_fail(
                "server_endpoint_beta is set but neither beta_server_name nor tls.server_name is — \
                 β QUIC handshake will fail with no SNI",
            );
        }
        if let Some(mtu) = cfg.beta_initial_mtu {
            if (1200..=1500).contains(&mtu) {
                r.push_pass(format!("beta_initial_mtu = {mtu}"));
            } else {
                r.push_fail(format!(
                    "beta_initial_mtu = {mtu} is out of sane range [1200, 1500]"
                ));
            }
        }
        if let Some(minimum) = cfg.beta_minimum_mtu {
            if minimum < 1200 {
                r.push_fail(format!(
                    "beta_minimum_mtu = {minimum} < 1200 (QUIC v1 minimum)"
                ));
            } else if let Some(initial) = cfg.beta_initial_mtu {
                if minimum > initial {
                    r.push_fail(format!(
                        "beta_minimum_mtu = {minimum} is GREATER than \
                         beta_initial_mtu = {initial}. Black-hole recovery cannot \
                         fall back above the configured starting MTU."
                    ));
                } else {
                    r.push_pass(format!("beta_minimum_mtu = {minimum}"));
                }
            } else if minimum > 1350 {
                r.push_fail(format!(
                    "beta_minimum_mtu = {minimum} exceeds the default \
                     beta_initial_mtu = 1350; set beta_initial_mtu explicitly"
                ));
            } else {
                r.push_pass(format!("beta_minimum_mtu = {minimum}"));
            }
        }
        // Iter-92: beta_mtu_upper_bound sanity.
        //
        // The MTU discovery upper bound caps how aggressively
        // quinn probes for jumbo frames. Valid range matches
        // initial_mtu's [1200, 9000] (jumbo-frame paths cap
        // at 9000 by convention; some 10G NICs allow up to
        // 9216 but quinn-udp doesn't probe past 9000).
        if let Some(ub) = cfg.beta_mtu_upper_bound {
            if ub < 1200 {
                r.push_fail(format!(
                    "beta_mtu_upper_bound = {ub} < 1200 (QUIC v1 minimum). MTU \
                     discovery will fail every probe attempt. Recommended: 1452 \
                     (Ethernet under v6+UDP overhead) or 9000 for jumbo-frame paths."
                ));
            } else if ub > 9216 {
                r.push_warn(format!(
                    "beta_mtu_upper_bound = {ub} > 9216 (10G NIC jumbo-frame max). \
                     quinn-udp won't probe past 9000 by default; the value is \
                     accepted but discovery caps below it."
                ));
            } else if let Some(initial) = cfg.beta_initial_mtu {
                if ub < initial {
                    r.push_fail(format!(
                        "beta_mtu_upper_bound = {ub} is LESS than beta_initial_mtu = \
                         {initial}. The probe ceiling is below the starting MTU; \
                         discovery cannot widen and starts above its own cap. Either \
                         raise upper_bound or lower initial_mtu.",
                    ));
                }
            }
        }
        if let (Some(minimum), Some(ub)) = (cfg.beta_minimum_mtu, cfg.beta_mtu_upper_bound) {
            if minimum > ub {
                r.push_fail(format!(
                    "beta_minimum_mtu = {minimum} is GREATER than \
                     beta_mtu_upper_bound = {ub}"
                ));
            }
        }
        // QUIC flow-control and local send-buffer windows. Keep the
        // accepted range bounded: zero deadlocks the carrier, while
        // multi-GiB windows let a small number of pooled carriers
        // consume the whole host under pressure.
        for (name, value) in [
            (
                "beta_stream_receive_window_mib",
                cfg.beta_stream_receive_window_mib,
            ),
            (
                "beta_connection_receive_window_mib",
                cfg.beta_connection_receive_window_mib,
            ),
            ("beta_send_window_mib", cfg.beta_send_window_mib),
        ] {
            if let Some(mib) = value {
                if !(1..=2048).contains(&mib) {
                    r.push_fail(format!("{name} = {mib} is out of sane range [1, 2048] MiB"));
                } else {
                    r.push_pass(format!("{name} = {mib} MiB"));
                }
            }
        }
        let stream_window = cfg.beta_stream_receive_window_mib.unwrap_or(64);
        let connection_window = cfg.beta_connection_receive_window_mib.unwrap_or(256);
        if connection_window < stream_window {
            r.push_fail(format!(
                "beta_connection_receive_window_mib = {connection_window} is LESS than \
                 the effective beta_stream_receive_window_mib = {stream_window}. The \
                 aggregate connection window must cover at least one stream."
            ));
        }
        // Iter-92: beta_ack_eliciting_threshold sanity.
        //
        // RFC 9802 ACK frequency reduction. quinn's default is 1
        // (every ack-eliciting packet → ACK). >1 = bunch up N
        // packets per ACK frame. Operator must opt in
        // explicitly because tight loopback/LAN paths see BBR
        // bandwidth-estimator collapse (107 MiB/s → 0.5 MiB/s
        // measured) when ACKs are held back.
        //
        // 0 is reserved/invalid (would mean "never ACK"). Very
        // high values starve BBR's bandwidth estimator on any
        // path.
        if let Some(thr) = cfg.beta_ack_eliciting_threshold {
            if thr == 0 {
                r.push_fail(
                    "beta_ack_eliciting_threshold = 0 is invalid (would mean 'never \
                     ACK'). Valid values: 1 (default, quinn upstream behavior — every \
                     packet acked) or 2-10 for long-fat-pipe RTT × bandwidth paths \
                     where ACK overhead is meaningful.",
                );
            } else if thr > 100 {
                r.push_warn(format!(
                    "beta_ack_eliciting_threshold = {thr} (>100) is extreme; BBR's \
                     bandwidth estimator may not converge if ACKs are bunched this \
                     much. Recommended: 2-10 for measured long-fat-pipe paths only."
                ));
            }
        }
        if let Some(thr) = cfg.beta_packet_threshold {
            if thr < 3 {
                r.push_fail(format!(
                    "beta_packet_threshold = {thr} is below the RFC recovery minimum 3."
                ));
            } else if thr > 100 {
                r.push_warn(format!(
                    "beta_packet_threshold = {thr} is extreme; real packet loss may \
                     take too long to recover. Use 3 unless reordering is measured."
                ));
            }
        }
        match cfg.beta_congestion.as_deref() {
            None | Some("bbr") => {
                if cfg.beta_brutal_target_mbps.is_some() {
                    r.push_warn(
                        "beta_brutal_target_mbps is set while beta_congestion is BBR; \
                         the target is ignored.",
                    );
                }
            }
            Some("brutal") => match cfg.beta_brutal_target_mbps {
                None | Some(0) => r.push_fail(
                    "beta_congestion = brutal requires a positive \
                     beta_brutal_target_mbps measured for this path.",
                ),
                Some(rate) if rate > 100_000 => r.push_warn(format!(
                    "beta_brutal_target_mbps = {rate} exceeds 100 Gbit/s; verify \
                     units and NIC capacity before enabling it."
                )),
                Some(_) => {}
            },
            Some(other) => r.push_fail(format!(
                "beta_congestion = {other:?} is invalid; expected \"bbr\" or \"brutal\"."
            )),
        }
    }

    // ----- Bootstrap-DNS posture -----
    //
    // Walk both `server_endpoint` and (when set) `server_endpoint_beta`.
    // For each: classify as ip-literal / pinned-direct-ip / system-resolver.
    // Surface a WARN when the operator is still on the system-resolver
    // path — that's the route the 2026 GFW DoH-ID attack rides on.
    // See qa/2026-05-17-gfw-2026-q1q2-threat-intel.md main line 6.
    {
        use crate::bootstrap::endpoint_is_ip_literal;
        let mut audit_endpoint = |label: &str, endpoint: &str| {
            let is_literal = endpoint_is_ip_literal(endpoint);
            match (&cfg.bootstrap_dns, is_literal) {
                (_, true) => r.push_pass(format!(
                    "bootstrap: {label} = {endpoint} is an IP literal — DNS skipped"
                )),
                (Some(b), false) if b.is_direct_ip() => {
                    let ip = b.pinned_ip().expect("is_direct_ip implies pinned_ip");
                    r.push_pass(format!(
                        "bootstrap: {label} hostname is pinned via bootstrap_dns.direct_ip = {ip}"
                    ));
                }
                (_, false) => r.push_warn(format!(
                    "bootstrap: {label} = {endpoint} resolves via OS resolver — \
                     production deploys SHOULD either use an IP literal in {label} \
                     or set `bootstrap_dns: {{ direct_ip: <vps-ip> }}` to defeat \
                     the 2026 GFW DoH/DoT identification attack"
                )),
            }
        };
        audit_endpoint("server_endpoint", &cfg.server_endpoint);
        if let Some(beta) = &cfg.server_endpoint_beta {
            audit_endpoint("server_endpoint_beta", beta);
        }

        // If the operator pinned a direct_ip but BOTH endpoints are
        // already IP literals, the pin is harmless but dead-letter —
        // surface as info so the operator can clean up the config.
        if let Some(b) = &cfg.bootstrap_dns {
            if b.is_direct_ip() {
                let ep_literal = endpoint_is_ip_literal(&cfg.server_endpoint);
                let beta_literal = cfg
                    .server_endpoint_beta
                    .as_ref()
                    .map(|s| endpoint_is_ip_literal(s))
                    .unwrap_or(true);
                if ep_literal && beta_literal {
                    r.push_pass(
                        "bootstrap: bootstrap_dns.direct_ip is set but all endpoints \
                         are already IP literals — the direct_ip pin is unused (harmless; \
                         remove it for clarity if desired)",
                    );
                }

                // Iter-107: direct_ip + multi-VPS pool of hostnames
                // = HA defeat.
                //
                // bootstrap_dns.direct_ip forces ALL hostname dials
                // to the same IP. If the operator configures
                // `server_endpoints: [vps1.example.com:443,
                // vps2.example.com:443, vps3.example.com:443]` AND
                // pins direct_ip, all three pool entries resolve
                // to the same IP — the EndpointPool's per-entry
                // health tracking still works (TCP connect to a
                // single IP), but when vps1's box goes down ALL
                // three entries fail because they're literally the
                // same box. No HA achieved.
                //
                // Detect: pool has ≥2 hostname entries (not IP
                // literals) AND direct_ip is set → WARN.
                let hostname_pool_entries: Vec<&str> = cfg
                    .server_endpoints
                    .iter()
                    .map(String::as_str)
                    .filter(|ep| !endpoint_is_ip_literal(ep))
                    .collect();
                if hostname_pool_entries.len() >= 2 {
                    r.push_warn(format!(
                        "bootstrap_dns.direct_ip is set AND server_endpoints contains \
                         {} hostname entries: {hostname_pool_entries:?}. The direct_ip \
                         pin forces ALL hostname dials to the same IP — the pool \
                         entries become aliases for the same VPS. When that VPS goes \
                         down EVERY pool entry fails together (no HA). Either: (a) use \
                         IP literals in server_endpoints so each entry pins its own IP, \
                         OR (b) remove bootstrap_dns.direct_ip and rely on per-hostname \
                         OS-resolver lookups (re-enables the 2026 GFW DoH-leak risk \
                         iter-70 documents).",
                        hostname_pool_entries.len(),
                    ));
                }
            }

            // Iter-70: bootstrap_dns.direct_ip in private / special-
            // use IP space → WARN. Symmetric with server iter-67/68
            // but client-side. Three failure modes:
            //   1. The operator's "VPS" is actually a LAN box at
            //      192.168.1.100 — they pasted the wrong IP. Every
            //      dial fails when not on that LAN.
            //   2. The IP is 169.254.169.254 (cloud metadata) — the
            //      client tries to authenticate the Proteus
            //      handshake against the cloud metadata service.
            //      Won't work, but the dial attempts leak the
            //      operator's user_id + Ed25519 sig into the
            //      metadata service's logs.
            //   3. CGNAT / link-local — same misconfiguration class.
            // WARN-not-FAIL because some VPN tunneling setups
            // legitimately use private-space VPS reachable only via
            // a parent tunnel (WireGuard etc.) — but flagging is
            // strictly the right default.
            if let Some(ip) = b.pinned_ip() {
                if is_private_or_special_use(ip) {
                    r.push_warn(format!(
                        "bootstrap_dns.direct_ip = {ip} is in a private / special-use IP \
                         range (RFC 1918 / CGNAT / link-local / ULA). Every Proteus dial \
                         will go to this address. Three traps: (1) you may have pasted a \
                         LAN address instead of your VPS public IP; (2) 169.254.169.254 \
                         is the cloud metadata service — the dial leaks your user_id + \
                         Ed25519 sig into its logs; (3) WireGuard-tunneled setups \
                         legitimately use this — if intentional, ignore the warn.",
                    ));
                }
            }
        }
    }

    // ----- Numeric sanity -----
    if let Some(q) = cfg.pad_quantum {
        const COMMON: &[u16] = &[0, 64, 128, 256, 512, 1280];
        if !COMMON.contains(&q) {
            r.push_warn(format!(
                "pad_quantum = {q} is unusual (typical values: {COMMON:?}); \
                 typo for 1280?"
            ));
        } else {
            r.push_pass(format!("pad_quantum = {q}"));
        }
    }
    if let Some(pow) = cfg.pow_difficulty {
        if pow > 24 {
            r.push_fail(format!(
                "pow_difficulty = {pow} is operator-hostile (>24 bits costs ≥1 s of CPU per \
                 client handshake on a modern laptop)"
            ));
        } else {
            r.push_pass(format!("pow_difficulty = {pow}"));
        }
    }
    if let Some(t) = cfg.beta_first_timeout_secs {
        if t == 0 {
            r.push_fail("beta_first_timeout_secs = 0 means β dial returns instantly");
        } else if t > 30 {
            r.push_warn(format!(
                "beta_first_timeout_secs = {t} is high; dual-stack fallback to α will be slow. \
                 The carrier-health back-off (CarrierHealth) caps the cost AFTER \
                 DEFAULT_FAILURE_THRESHOLD = 3 consecutive failures, but each of those \
                 first 3 CONNECTs pays the full timeout"
            ));
        } else {
            r.push_pass(format!(
                "beta_first_timeout_secs = {t}s (CarrierHealth limits the impact to the \
                 first ≤ 3 CONNECTs of any burst before β suppression engages)"
            ));
        }
    }
    if let Some(d) = cfg.drain_secs {
        if d == 0 {
            // Iter-94: client drain_secs = 0 → WARN. SIGTERM tears
            // down in-flight SOCKS5 sessions immediately; the
            // browser/curl waiting on a long-poll sees connection
            // reset mid-stream. Mirror of server iter-88.
            r.push_warn(
                "drain_secs = 0 — graceful drain is disabled. SIGTERM immediately \
                 tears down in-flight SOCKS5 sessions; the local app waiting on \
                 the tunnel sees connection reset mid-stream. Recommended: 5-30s.",
            );
        } else if d > 120 {
            r.push_warn(format!(
                "drain_secs = {d} is high; systemd TimeoutStopSec must be larger"
            ));
        }
    }

    // Iter-91: tcp_keepalive_secs sanity. Same shape as server
    // iter-84. = 0 disables NAT-survival keepalive on outbound
    // client → server dials → long-idle sessions silently die
    // in mid-path NAT translators (returns the iter-14 fix
    // class). WARN-not-FAIL (operator may legitimately disable
    // for a measurement experiment).
    if cfg.tcp_keepalive_secs == Some(0) {
        r.push_warn(
            "tcp_keepalive_secs = 0 disables TCP keepalive on outbound client → server \
             dials. Long-idle Proteus sessions will silently die in mid-path NAT \
             translators (returns the iter-14 silent-NAT-death class). If unset, \
             runtime defaults to 30s.",
        );
    } else if let Some(secs) = cfg.tcp_keepalive_secs {
        if secs > 3600 {
            r.push_warn(format!(
                "tcp_keepalive_secs = {secs} (>1h) is longer than typical NAT idle \
                 timers (300-1800s); the keepalive may not fire often enough to \
                 keep the NAT mapping alive. Recommended: 30-120s.",
            ));
        }
    }

    // Iter-91: alpha_dial_timeout_secs sanity.
    if let Some(secs) = cfg.alpha_dial_timeout_secs {
        if secs == 0 {
            r.push_fail(
                "alpha_dial_timeout_secs = 0 means the α dial returns instantly with \
                 a timeout error. Every CONNECT fails before the TCP handshake even \
                 starts. Recommended: leave unset (defaults to 10s).",
            );
        } else if secs > 60 {
            r.push_warn(format!(
                "alpha_dial_timeout_secs = {secs} (>60s) is high; a single slow dial \
                 holds a max_inflight_sessions slot for {secs}s before reclaim. The \
                 CarrierHealth back-off caps the impact, but the first few CONNECTs \
                 of any burst pay the full timeout. Recommended: ≤30s.",
            ));
        }
    }

    // Iter-91: healthz_staleness_secs sanity. The healthz path
    // reports stale if no successful dial within N seconds.
    // 0 means "never stale" (always reports healthy → useless
    // health check). Very high value misses real outages.
    if let Some(secs) = cfg.healthz_staleness_secs {
        if secs == 0 {
            r.push_warn(
                "healthz_staleness_secs = 0 means the health endpoint never reports \
                 stale — always 200 OK regardless of actual connectivity. The \
                 endpoint becomes useless as a health check. If you want a tight \
                 check, set 30-300s; if you want to disable staleness gating, \
                 remove the field entirely (the runtime default is reasonable).",
            );
        } else if secs > 86400 {
            r.push_warn(format!(
                "healthz_staleness_secs = {secs} (>24h) is excessive — the binary \
                 could be silently broken for an entire day before health flags \
                 stale. Recommended: 60-600s.",
            ));
        }
    }

    // Iter-83: max_inflight_sessions = 0 disables the per-session
    // semaphore (runtime says "not recommended" + warn-logs at
    // startup). FAIL because the consequence is real: on a
    // SOCKS5-from-browser scenario, a flooded fan-out (page load
    // with 50+ images) can cascade into per-CONNECT Proteus
    // session allocations, each with crypto state + buffers,
    // and the proteus-client process OOMs locally. The 1024
    // default sustains a normal browsing burst; we surface the
    // disabled case at preflight so the operator must
    // explicitly understand the risk.
    if let Some(n) = cfg.max_inflight_sessions {
        if n == 0 {
            r.push_fail(
                "max_inflight_sessions = 0 disables the per-session concurrency cap. \
                 Under a SOCKS5 fan-out burst (browser page load with 50+ images), \
                 per-CONNECT Proteus session allocations cascade and the client OOMs \
                 locally. If you genuinely need unbounded sessions (e.g., bench harness), \
                 remove the field entirely to inherit the 1024 default — explicit 0 is \
                 almost always a typo for 'I want a high cap'.",
            );
        } else if n > 16384 {
            r.push_warn(format!(
                "max_inflight_sessions = {n} is very high; each in-flight session reserves \
                 ~16 MiB worst-case (cipher state + scratch + buffers). 16384 sessions \
                 ≈ 256 GiB worst-case memory ceiling. If you genuinely need this, ensure \
                 the host has the RAM.",
            ));
        }
    }

    // Iter-83: socks_request_timeout_secs = 0 disables the
    // slow-loris guard on the SOCKS5 pre-CONNECT phase. A
    // stalled or malicious downstream can occupy a
    // max_inflight_sessions slot indefinitely. FAIL.
    if let Some(t) = cfg.socks_request_timeout_secs {
        if t == 0 {
            r.push_fail(
                "socks_request_timeout_secs = 0 disables the slow-loris guard on SOCKS5 \
                 greeting/method-select/request parse. A stalled or malicious local app \
                 can occupy a max_inflight_sessions slot indefinitely. Recommended: \
                 leave unset (defaults to 10 s) or set explicitly to 5-30 s.",
            );
        } else if t > 60 {
            r.push_warn(format!(
                "socks_request_timeout_secs = {t} is high; a single stalled app holds \
                 a session slot for {t}s before reclaim. Recommended: ≤30 s for production.",
            ));
        }
    }

    r
}

/// Iter-47: inspect a CA bundle PEM file for cert-expiry. The
/// dispatcher uses this trust anchor on every dial; an expired
/// CA breaks every connection. Symmetric with the server-side
/// iter-46 leaf cert check, but for the trust-anchor case the
/// bundle may contain multiple CAs and ANY expiring entry is
/// the actionable signal — we report the EARLIEST notAfter
/// across the bundle.
///
/// `pem_bytes` is the file content; `path` is just for the
/// error/log message. We re-parse from bytes via the
/// transport-alpha `load_cert_chain` helper (which accepts both
/// PEM and a `Path`), but PEM parsing from a slice would
/// duplicate that logic. Instead, write a small wrapper: we use
/// the in-memory `rustls_pemfile::certs` path via the
/// transport-alpha module.
fn check_ca_bundle_expiry(r: &mut PreflightReport, _pem_bytes: &[u8], path: &Path) {
    let chain = match proteus_transport_alpha::tls::load_cert_chain(path) {
        Ok(c) => c,
        Err(e) => {
            r.push_warn(format!(
                "tls.trusted_ca: could not parse cert chain for expiry check ({e}). \
                 PEM-readable but parse failed; expiry surveillance disabled.",
            ));
            return;
        }
    };
    match proteus_transport_alpha::tls::earliest_cert_not_after(&chain) {
        Ok(not_after) => {
            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_secs() as i64)
                .unwrap_or(0);
            let secs_until = not_after.saturating_sub(now);
            if secs_until <= 0 {
                r.push_fail(format!(
                    "tls.trusted_ca: at least one CA in the bundle is EXPIRED \
                     ({} second(s) ago) — every dial will fail TLS cert verification. \
                     Rotate the trust anchor immediately.",
                    -secs_until,
                ));
            } else {
                let days = secs_until / 86_400;
                if days < 14 {
                    r.push_warn(format!(
                        "tls.trusted_ca: earliest CA notAfter in {days} day(s) — within the \
                         14-day renewal window. Rotate the trust anchor before it expires; \
                         operator-managed CAs do NOT auto-renew like Let's Encrypt leafs.",
                    ));
                } else {
                    r.push_pass(format!(
                        "tls.trusted_ca: earliest CA valid for {days} day(s)"
                    ));
                }
            }
        }
        Err(e) => {
            r.push_warn(format!(
                "tls.trusted_ca: could not extract notAfter ({e}); expiry surveillance disabled",
            ));
        }
    }
}

/// Helper: read a key file and run a size predicate.
fn check_key_file(
    r: &mut PreflightReport,
    label: &str,
    path: &Path,
    size_ok: impl Fn(usize) -> bool,
    expected: &str,
) {
    let bytes = match std::fs::read(path) {
        Ok(b) => b,
        Err(e) => {
            r.push_fail(format!("keys.{label}: unreadable {} ({e})", path.display()));
            return;
        }
    };
    // Decode base64 if it looks like base64, else use raw.
    let decoded = base64_or_raw(&bytes);
    if !size_ok(decoded.len()) {
        r.push_fail(format!(
            "keys.{label}: wrong size — got {} bytes after base64 decode, want {}",
            decoded.len(),
            expected
        ));
        return;
    }
    // Iter-48: all-zeros sentinel check. A genuinely-random key has
    // a chance of 2^-(8*N) of being uniformly zero — for N=32 that's
    // ~10^-77. In practice, all-zero key files come from:
    //   - a key-rotation script crashed mid-write
    //   - the operator hand-edited the file and saved an empty one
    //     that got padded by tooling
    //   - the operator used `dd if=/dev/zero` as a placeholder and
    //     forgot to replace it
    // Any of those produces a catastrophic security failure if the
    // file is a SECRET key (server's worst case: trivially-forgeable
    // identity), and a useless config if it's a PUBLIC key (every
    // handshake will fail verify-against-zero with no obvious
    // operator-facing diagnostic).
    if decoded.iter().all(|&b| b == 0) {
        r.push_fail(format!(
            "keys.{label}: ALL-ZERO contents ({} bytes) — this is either a placeholder \
             the operator forgot to replace OR a key-rotation script crashed mid-write. \
             For secret keys, this is a catastrophic security failure (trivially-forgeable \
             identity). Run `proteus-client keygen` to generate a real key.",
            decoded.len(),
        ));
        return;
    }
    // Iter-52: secret-key file mode check (symmetric with server-
    // side iter-52). The client's `client_ed25519_sk` is the
    // long-term identity used to authenticate to the server; a
    // world-readable SK on a shared host is a real exposure. WARN
    // (not FAIL) for the same reason as server: `check-host` is
    // the hard gate; validate is the early-warning surface.
    if label == "client_ed25519_sk" {
        check_secret_file_mode(r, label, path);
    }
    r.push_pass(format!(
        "keys.{label} OK ({} bytes, {})",
        decoded.len(),
        expected
    ));
}

/// Iter-52: Unix-only secret-file mode check. Symmetric with the
/// server-side helper of the same name in
/// proteus-server/src/validate.rs.
#[cfg(unix)]
fn check_secret_file_mode(r: &mut PreflightReport, label: &str, path: &Path) {
    use std::os::unix::fs::PermissionsExt;
    let md = match std::fs::metadata(path) {
        Ok(m) => m,
        Err(_) => return,
    };
    let mode = md.permissions().mode() & 0o777;
    let group_or_other_set = mode & 0o077 != 0;
    if group_or_other_set {
        r.push_warn(format!(
            "keys.{label} {} has mode {mode:#o} — group or world readable. SECRET key \
             exposure on shared hosts. Fix: `chmod 0600 {}`. (validate emits a warn; \
             the harder gate is `proteus-client check-host`.)",
            path.display(),
            path.display(),
        ));
    }
}

#[cfg(not(unix))]
fn check_secret_file_mode(_r: &mut PreflightReport, _label: &str, _path: &Path) {
    // No-op on non-Unix; the world-readable concept doesn't map.
}

/// Iter-70: detect IPs that should never appear as a
/// `bootstrap_dns.direct_ip` pin. Symmetric with the server-
/// side `is_private_or_special_use` helper. Covers IPv4 RFC 1918
/// plus CGNAT plus link-local, IPv6 ULA plus link-local, plus
/// multicast and unspecified.
fn is_private_or_special_use(ip: std::net::IpAddr) -> bool {
    match ip {
        std::net::IpAddr::V4(v4) => {
            let octets = v4.octets();
            v4.is_private()
                || v4.is_link_local()
                || v4.is_multicast()
                || v4.is_unspecified()
                // CGNAT: 100.64.0.0/10
                || (octets[0] == 100 && (octets[1] & 0xc0) == 64)
        }
        std::net::IpAddr::V6(v6) => {
            let seg0 = v6.segments()[0];
            v6.is_multicast()
                || v6.is_unspecified()
                || (seg0 & 0xfe00) == 0xfc00
                || (seg0 & 0xffc0) == 0xfe80
        }
    }
}

fn base64_or_raw(input: &[u8]) -> Vec<u8> {
    use base64::Engine;
    let trimmed: Vec<u8> = input
        .iter()
        .copied()
        .filter(|b| !b.is_ascii_whitespace())
        .collect();
    if let Ok(decoded) = base64::engine::general_purpose::STANDARD.decode(&trimmed) {
        return decoded;
    }
    input.to_vec()
}

fn parse_host_port(s: &str) -> Option<(&str, u16)> {
    // Iter-153: reject port == 0 (mirror of the
    // bootstrap::parse_host_port gate). Port 0 isn't a connectable
    // TCP destination; rejecting at the validate layer surfaces the
    // operator's `vps:0` typo as a clean FAIL row instead of a
    // confusing runtime dial failure.
    // IPv6 literal: `[addr]:port`.
    if let Some(stripped) = s.strip_prefix('[') {
        if let Some(end) = stripped.find(']') {
            let host = &stripped[..end];
            let rest = &stripped[end + 1..];
            if let Some(port) = rest.strip_prefix(':').and_then(|p| p.parse::<u16>().ok()) {
                if port == 0 || host.is_empty() {
                    return None;
                }
                return Some((host, port));
            }
        }
        return None;
    }
    let (host, port) = s.rsplit_once(':')?;
    let port = port.parse::<u16>().ok()?;
    if host.is_empty() || port == 0 {
        return None;
    }
    Some((host, port))
}

/// `proteus-client validate <path>` entry point. Prints the report
/// + sets exit code.
pub async fn cli_run(path: &Path) -> std::io::Result<i32> {
    let report = run(path).await;
    let stdout = std::io::stdout();
    let mut h = stdout.lock();
    write!(h, "{report}")?;
    Ok(if report.has_failures() { 1 } else { 0 })
}
