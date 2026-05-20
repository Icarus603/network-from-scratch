//! Configuration preflight ("`proteus-server validate <path>`").
//!
//! Production deployments need a dry-run check before SIGHUP /
//! systemd-reload, because a typo in `/etc/proteus/server.yaml`:
//!
//! - Silently fails the SIGHUP cert reload (the server keeps the old
//!   cert and logs ERROR — operator doesn't notice).
//! - On first boot would prevent `systemctl start proteus-server` from
//!   coming up cleanly.
//!
//! The preflight runs every cheap-to-verify check up front and prints
//! a coloured pass/fail report. It does NOT bind sockets, talk to the
//! cover endpoint, or call `accept()`. Pure I/O against the config
//! file plus the files it references (TLS cert, private key, key
//! files, metrics token, allowlist Ed25519 pubs, access log
//! writability, firewall CIDR syntax).
//!
//! Exit code: 0 on all-green; 1 if any check failed. Suitable for
//! CI / Ansible / Terraform pre-deploy gating.

use std::fmt;
use std::io::Write;
use std::path::Path;

use crate::config::ServerConfig;

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

    /// Count of (passes, warns, fails).
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
                Check::Pass(m) => writeln!(f, "  [ok]   {m}")?,
                Check::Warn(m) => writeln!(f, "  [warn] {m}")?,
                Check::Fail(m) => writeln!(f, "  [FAIL] {m}")?,
            }
        }
        let (p, w, fail) = self.counts();
        writeln!(f, "  ----")?;
        writeln!(f, "  {p} passed, {w} warnings, {fail} failed")?;
        Ok(())
    }
}

/// Run every preflight check against `cfg` (already parsed) and the
/// referenced filesystem state. Pure: no network I/O.
#[must_use]
pub fn preflight(cfg: &ServerConfig) -> PreflightReport {
    let mut r = PreflightReport::default();

    // 1. listen_alpha parses as SocketAddr (or host:port).
    match cfg.listen_alpha.parse::<std::net::SocketAddr>() {
        Ok(_) => r.push_pass(format!("listen_alpha parses ({})", cfg.listen_alpha)),
        Err(e) => r.push_fail(format!("listen_alpha {:?}: {e}", cfg.listen_alpha)),
    }
    // 1b. listen_beta parses (when set) AND cert/key resolution
    // policy is consistent (β-specific paths take precedence; α tls
    // fallback applies otherwise).
    if let Some(beta) = cfg.listen_beta.as_ref() {
        match beta.parse::<std::net::SocketAddr>() {
            Ok(_) => r.push_pass(format!("listen_beta parses ({beta})")),
            Err(e) => r.push_fail(format!("listen_beta {beta:?}: {e}")),
        }
        // The binary will refuse to start if neither β-specific nor
        // α-tls cert/key paths are available. Surface that here as a
        // FAIL so operators catch it pre-deploy.
        let beta_has_explicit = cfg.beta_cert_chain.is_some() && cfg.beta_private_key.is_some();
        let tls_fallback_available = cfg.tls.is_some();
        if !beta_has_explicit && !tls_fallback_available {
            r.push_fail(
                "listen_beta is set but no cert/key resolution path: \
                 set beta_cert_chain + beta_private_key, OR configure tls block",
            );
        }
        // If β-specific paths are partially set, that's a typo.
        if cfg.beta_cert_chain.is_some() != cfg.beta_private_key.is_some() {
            r.push_fail(
                "beta_cert_chain and beta_private_key must be either both set or both unset",
            );
        }
        // Make sure the resolved cert/key files actually load.
        let (cert_path, key_path) = match (
            cfg.beta_cert_chain.as_ref(),
            cfg.beta_private_key.as_ref(),
            cfg.tls.as_ref(),
        ) {
            (Some(c), Some(k), _) => (Some(c.clone()), Some(k.clone())),
            (_, _, Some(tls)) => (Some(tls.cert_chain.clone()), Some(tls.private_key.clone())),
            _ => (None, None),
        };
        if let (Some(c), Some(k)) = (cert_path, key_path) {
            match proteus_transport_alpha::tls::load_cert_chain(&c) {
                Ok(chain) => {
                    r.push_pass(format!("β cert chain loads ({c:?})"));
                    // Iter-49: β cert-expiry check (symmetric with
                    // iter-46 α cert check). The β QUIC handshake
                    // uses the same TLS 1.3 cert verification path
                    // as α; same expiry trap class applies. When β
                    // shares the α tls block (the common case),
                    // this is REDUNDANT with the α check below —
                    // but the inner-cfg.tls path may not be set
                    // (operator explicitly split α/β cert paths
                    // via beta_cert_chain / beta_private_key) and
                    // we still want expiry coverage.
                    let same_as_alpha =
                        cfg.tls.as_ref().map(|t| t.cert_chain == c).unwrap_or(false);
                    if !same_as_alpha {
                        match proteus_transport_alpha::tls::leaf_cert_not_after(&chain) {
                            Ok(not_after) => {
                                let now = std::time::SystemTime::now()
                                    .duration_since(std::time::UNIX_EPOCH)
                                    .map(|d| d.as_secs() as i64)
                                    .unwrap_or(0);
                                let secs_until = not_after.saturating_sub(now);
                                if secs_until <= 0 {
                                    r.push_fail(format!(
                                        "β cert: leaf EXPIRED ({} seconds ago) — every \
                                         QUIC handshake will fail. Run `certbot renew` for \
                                         the β cert path immediately",
                                        -secs_until,
                                    ));
                                } else {
                                    let days = secs_until / 86_400;
                                    if days < 14 {
                                        r.push_warn(format!(
                                            "β cert: leaf expires in {days} day(s) — \
                                             within the 14-day renewal window",
                                        ));
                                    } else {
                                        r.push_pass(format!(
                                            "β cert: leaf valid for {days} day(s)"
                                        ));
                                    }
                                }
                            }
                            Err(e) => r.push_warn(format!(
                                "β cert: could not extract leaf notAfter ({e})"
                            )),
                        }
                    }
                }
                Err(e) => r.push_fail(format!("β cert chain {c:?}: {e}")),
            }
            match proteus_transport_alpha::tls::load_private_key(&k) {
                Ok(_) => r.push_pass(format!("β private key loads ({k:?})")),
                Err(e) => r.push_fail(format!("β private key {k:?}: {e}")),
            }
        }
    }

    // 2. Server key files exist + readable.
    check_file(&mut r, "keys.mlkem_pk", &cfg.keys.mlkem_pk);
    check_file(&mut r, "keys.mlkem_sk", &cfg.keys.mlkem_sk);
    check_file(&mut r, "keys.x25519_pk", &cfg.keys.x25519_pk);
    check_file(&mut r, "keys.x25519_sk", &cfg.keys.x25519_sk);

    // Iter-144: length-gate the X25519 keys (32 bytes each per
    // RFC 7748 §5). Same defect class as iter-140 (ML-KEM) +
    // iter-143 (ed25519): pre-iter-144 a truncated x25519_sk
    // panicked the server on `StaticSecret::from(arr)` at startup;
    // a truncated x25519_pk loaded successfully but generated
    // wrong DH output, manifesting as "every client handshake
    // fails the Finished MAC" — even harder to diagnose than the
    // ML-KEM case because the server runs fine, it just rejects
    // every client.
    check_x25519_key_len(&mut r, "keys.x25519_pk", &cfg.keys.x25519_pk);
    check_x25519_key_len(&mut r, "keys.x25519_sk", &cfg.keys.x25519_sk);

    // Iter-140: length-gate the ML-KEM-768 keys. FIPS-203 §6.1:
    //   * EK (`mlkem_pk`) = 1184 bytes raw
    //   * DK (`mlkem_sk`) = 2400 bytes raw
    // Mirrors the iter-139 client-side validate gate. Pre-iter-140
    // the server's `check_file` only verified the file existed +
    // wasn't all-zero — a truncated EK or DK passed validate clean,
    // then the server would either fail to start (DK parse panics)
    // or generate a fingerprint that mismatches every client's
    // pinned `server.pq.fingerprint` (silent connectivity loss).
    // Operators running the iter-122 mandatory preflight gate now
    // catch this before deploy.
    //
    // Accept either raw bytes or base64-armored bytes — same
    // decode_b64_or_raw discipline as runtime.
    check_mlkem_key_len(
        &mut r,
        "keys.mlkem_pk",
        &cfg.keys.mlkem_pk,
        1184,
        "ML-KEM-768 EK (FIPS-203 §6.1)",
    );
    check_mlkem_key_len(
        &mut r,
        "keys.mlkem_sk",
        &cfg.keys.mlkem_sk,
        2400,
        "ML-KEM-768 DK (FIPS-203 §6.1)",
    );

    // 3. TLS cert chain + key parse via the actual rustls parser
    //    (catches expired chains, mismatched key types, malformed PEM).
    match cfg.tls.as_ref() {
        Some(tls) => {
            check_file(&mut r, "tls.cert_chain", &tls.cert_chain);
            check_file(&mut r, "tls.private_key", &tls.private_key);
            match proteus_transport_alpha::tls::load_cert_chain(&tls.cert_chain) {
                Ok(chain) => {
                    r.push_pass(format!("tls.cert_chain parses ({} certs)", chain.len()));
                    // Iter-46: cert-expiry validate. The runtime
                    // surfaces `proteus_tls_cert_not_after_unix_seconds`
                    // + `ProteusTlsCertExpiring{Soon,Expired}` alerts,
                    // but those only fire AFTER the binary starts.
                    // Operators running `validate` on a fresh deploy
                    // (or in CI before a config push) deserve the
                    // same warning BEFORE the cert hits production.
                    //
                    // Thresholds mirror the bundled Prometheus alerts:
                    //   - expired (notAfter < now) → FAIL
                    //   - <14 days → WARN
                    //   - ≥14 days → PASS with days-remaining note
                    match proteus_transport_alpha::tls::leaf_cert_not_after(&chain) {
                        Ok(not_after) => {
                            let now = std::time::SystemTime::now()
                                .duration_since(std::time::UNIX_EPOCH)
                                .map(|d| d.as_secs() as i64)
                                .unwrap_or(0);
                            let secs_until = not_after.saturating_sub(now);
                            if secs_until <= 0 {
                                r.push_fail(format!(
                                    "tls.cert_chain: leaf cert EXPIRED ({} seconds ago) — every \
                                     TLS handshake will fail. Run `certbot renew` (or your \
                                     rotation tooling) IMMEDIATELY",
                                    -secs_until,
                                ));
                            } else {
                                let days = secs_until / 86_400;
                                if days < 14 {
                                    r.push_warn(format!(
                                        "tls.cert_chain: leaf cert expires in {days} day(s) — \
                                         within the 14-day renewal window. If Let's Encrypt \
                                         auto-renewal is wired this will recover on the next \
                                         renewal cycle; if not, fix it now",
                                    ));
                                } else {
                                    r.push_pass(format!(
                                        "tls.cert_chain: leaf cert valid for {days} day(s)"
                                    ));
                                }
                            }
                        }
                        Err(e) => r.push_warn(format!(
                            "tls.cert_chain: could not extract leaf notAfter ({e}); the cert \
                             parses but expiry surveillance is disabled. Runtime metric \
                             proteus_tls_cert_not_after_unix_seconds will report sentinel"
                        )),
                    }
                }
                Err(e) => r.push_fail(format!("tls.cert_chain: {e}")),
            }
            match proteus_transport_alpha::tls::load_private_key(&tls.private_key) {
                Ok(_) => r.push_pass("tls.private_key parses"),
                Err(e) => r.push_fail(format!("tls.private_key: {e}")),
            }
            // Final sanity: chain + key actually combine into an
            // acceptor (rustls catches RSA-vs-EC mismatch here).
            if let (Ok(chain), Ok(key)) = (
                proteus_transport_alpha::tls::load_cert_chain(&tls.cert_chain),
                proteus_transport_alpha::tls::load_private_key(&tls.private_key),
            ) {
                match proteus_transport_alpha::tls::build_acceptor(chain, key) {
                    Ok(_) => r.push_pass("tls.acceptor builds (cert/key match)"),
                    Err(e) => r.push_fail(format!("tls.acceptor: {e}")),
                }
            }
        }
        None => r.push_warn(
            "tls block missing — server will run plain TCP; passive DPI will identify the protocol",
        ),
    }

    // 4. Client allowlist files exist.
    if cfg.client_allowlist.is_empty() {
        r.push_warn(
            "client_allowlist is empty — server accepts any client; only acceptable for testing",
        );
    } else {
        for client in &cfg.client_allowlist {
            let pk_label = format!("client_allowlist[{}].ed25519_pk", client.user_id);
            check_file(&mut r, &pk_label, &client.ed25519_pk);
            // Iter-143: enforce ed25519 public-key length (= 32 bytes
            // raw OR ~44 bytes base64). Pre-iter-143 the server's
            // check_file only verified existence + non-all-zero; a
            // truncated pubkey passed validate cleanly and then the
            // server panicked / refused to start at runtime when
            // `ed25519_dalek::VerifyingKey::from_bytes` rejected the
            // malformed key. Surfaces the failure at preflight time
            // with the actionable field name.
            //
            // Skip the check when the file is absent OR empty — those
            // already FAILED via check_file above; double-failing
            // just adds noise.
            if let Ok(raw) = std::fs::read(&client.ed25519_pk) {
                if !raw.is_empty() {
                    let decoded = base64_or_raw_bytes(&raw);
                    let raw_ok = raw.len() == 32;
                    let decoded_ok = decoded.len() == 32;
                    if !raw_ok && !decoded_ok {
                        r.push_fail(format!(
                            "{pk_label}: ed25519 public-key length wrong (got {} bytes \
                             raw / {} bytes after base64-decode; expected exactly 32). \
                             A truncated or wrong-format pubkey causes the server to \
                             reject the key on startup and refuse to bind the listener. \
                             Re-issue with `proteus-client keygen --out keys/` and \
                             copy the resulting `client.ed25519.pk` into place.",
                            raw.len(),
                            decoded.len()
                        ));
                    }
                }
            }
            if client.user_id.is_empty() || client.user_id.len() > 8 {
                r.push_fail(format!(
                    "client_allowlist[{}].user_id must be 1..=8 chars, got len={}",
                    client.user_id,
                    client.user_id.len()
                ));
            } else if client.user_id.trim() != client.user_id {
                // Iter-56: same whitespace trap as the client-side
                // validate. A YAML-quoted allowlist user_id with
                // trailing/leading whitespace becomes a byte-string
                // that no client's `user_id:` (without the
                // whitespace) ever matches.
                r.push_fail(format!(
                    "client_allowlist[{:?}].user_id has leading or trailing whitespace — \
                     the server matches user_ids byte-for-byte; a client whose user_id \
                     doesn't include the same whitespace will never authenticate. Fix \
                     the YAML: unquote OR strip whitespace explicitly.",
                    client.user_id,
                ));
            }
        }
        r.push_pass(format!(
            "client_allowlist has {} users",
            cfg.client_allowlist.len()
        ));
        // Iter-57: duplicate user_id detection. The runtime
        // lookup is `client_allowlist.iter().find(...)` which
        // returns the FIRST match. Duplicate user_ids with
        // DIFFERENT pubkeys = the second-and-later entries are
        // dead code; the client whose pubkey matches the dead
        // entry will fail signature verification and reject.
        // The operator usually intended the second entry as a
        // key rotation; failing to notice means a real client
        // is silently locked out.
        let mut seen: std::collections::HashMap<&str, usize> =
            std::collections::HashMap::with_capacity(cfg.client_allowlist.len());
        let mut dupes: Vec<String> = Vec::new();
        for (idx, client) in cfg.client_allowlist.iter().enumerate() {
            if let Some(prev_idx) = seen.insert(client.user_id.as_str(), idx) {
                dupes.push(format!(
                    "{:?} appears at indices [{prev_idx}] and [{idx}]",
                    client.user_id
                ));
            }
        }
        if !dupes.is_empty() {
            r.push_fail(format!(
                "client_allowlist has duplicate user_id(s): {}. The runtime lookup \
                 returns the FIRST match; any client whose pubkey matches a LATER \
                 duplicate entry will fail signature verification and be rejected. \
                 If this is a key rotation, remove the old entry; if it's a typo, \
                 give each client a distinct user_id.",
                dupes.join("; ")
            ));
        }

        // Iter-142: detect duplicate ed25519_pk BYTES across distinct
        // user_ids. Two user_ids sharing the same pubkey = ONE client
        // SK can authenticate as EITHER user, breaking per-user
        // accounting / quotas / quarantine. This is the worst-case
        // form of operator typo because every check up to runtime
        // passes — the runtime even loads both VerifyingKeys cleanly
        // — but the per-user bandwidth + per-user conn-limit + quota
        // surfaces all silently mis-attribute traffic to whichever
        // user_id sorted first in the allowlist Vec. Validate-time
        // detection catches the typo before operators wonder why
        // alice's quota is being consumed by bob.
        //
        // The check reads every ed25519_pk file (it's a 32-byte
        // public-key file, fine to slurp at validate time) and
        // hashes the bytes into a HashMap keyed on the decoded
        // bytes. Files that already failed `check_file` above
        // (missing, all-zero) get skipped here so we don't emit a
        // spurious duplicate WARN for two missing files.
        let mut pk_bytes_to_users: std::collections::HashMap<Vec<u8>, Vec<&str>> =
            std::collections::HashMap::new();
        for client in &cfg.client_allowlist {
            match std::fs::read(&client.ed25519_pk) {
                Ok(raw) => {
                    // The on-disk file might be either raw 32 bytes
                    // OR base64-armored. Try both: prefer the
                    // base64-decoded form when it's exactly 32 bytes
                    // (operator stored an armored key); otherwise fall
                    // back to the raw on-disk bytes when those are 32
                    // (operator stored raw). Empty/zero/wrong-length
                    // entries get skipped (they're FAILED by other
                    // gates; double-failing here just adds noise).
                    let decoded = base64_or_raw_bytes(&raw);
                    let candidate: Vec<u8> = if decoded.len() == 32 {
                        decoded
                    } else if raw.len() == 32 {
                        raw
                    } else {
                        continue;
                    };
                    if candidate.iter().all(|&b| b == 0) {
                        continue;
                    }
                    pk_bytes_to_users
                        .entry(candidate)
                        .or_default()
                        .push(client.user_id.as_str());
                }
                Err(_) => continue,
            }
        }
        let pk_dupes: Vec<String> = pk_bytes_to_users
            .into_iter()
            .filter_map(|(pk, users)| {
                if users.len() > 1 {
                    let pk_short = pk
                        .iter()
                        .take(8)
                        .map(|b| format!("{b:02x}"))
                        .collect::<String>();
                    Some(format!(
                        "users {users:?} share ed25519_pk (pk[..8]={pk_short}…)"
                    ))
                } else {
                    None
                }
            })
            .collect();
        if !pk_dupes.is_empty() {
            r.push_fail(format!(
                "client_allowlist has duplicate ed25519_pk bytes across distinct user_ids: {}. \
                 ONE client SK can authenticate as EITHER user_id — per-user accounting / \
                 quotas / quarantine all silently mis-attribute traffic to whichever user_id \
                 sorted first in the allowlist. Either (a) re-issue ONE of the user_ids with \
                 a fresh keypair (recommended; the original keypair was probably copied by \
                 accident), or (b) consolidate into a single user_id entry.",
                pk_dupes.join("; ")
            ));
        }
    }

    // 5. Cover endpoint parses (single OR pool — pool wins when set).
    if !cfg.cover_endpoints.is_empty() {
        let mut bad = Vec::new();
        for (idx, raw) in cfg.cover_endpoints.iter().enumerate() {
            if proteus_transport_alpha::cover::parse_cover_endpoint(raw).is_none() {
                bad.push(format!("[{idx}]={raw:?}"));
            }
        }
        if bad.is_empty() {
            r.push_pass(format!(
                "cover_endpoints pool parses ({} entries, per-src-IP /24 affinity)",
                cfg.cover_endpoints.len()
            ));
        } else {
            r.push_fail(format!(
                "cover_endpoints pool has bad host:port entries: {}",
                bad.join(", ")
            ));
        }
        // Pool of size 1 = silently equivalent to cover_endpoint
        // single mode, but operator probably meant to add more.
        if cfg.cover_endpoints.len() == 1 {
            r.push_warn(
                "cover_endpoints has only one entry — equivalent to the cover_endpoint \
                 single-URL shorthand. Add ≥3 distinct destinations to actually defeat \
                 time-series active probing (threat-intel main line 4)",
            );
        }
        // Iter-59: duplicate cover_endpoints reduce the effective
        // pool size and break per-/24 source-IP affinity routing.
        // Affinity is `hash(src_ip /24) % pool.len()`. If two
        // entries are identical, the affinity slot points at the
        // same destination twice — effective diversity drops by
        // 1, and an active prober can compare two "different"
        // entries' upstream behavior and prove they're the same
        // host (defeating the threat-intel main line 4 defense
        // the pool was added for). Surface as WARN with the
        // duplicate list so the operator gets one fix-cycle.
        let mut seen: std::collections::HashSet<&str> =
            std::collections::HashSet::with_capacity(cfg.cover_endpoints.len());
        let mut dupes: Vec<&str> = Vec::new();
        for raw in &cfg.cover_endpoints {
            if !seen.insert(raw.as_str()) && !dupes.contains(&raw.as_str()) {
                dupes.push(raw.as_str());
            }
        }
        // Iter-68: apply the iter-67 private-IP check to every
        // pool entry. The pool has the same exposure: ANY
        // entry in private space leaks unauth probes into the
        // operator's LAN. We check ALL entries (not just the
        // first that's bad) so the operator gets one fix-cycle.
        let mut private_entries: Vec<String> = Vec::new();
        for raw in &cfg.cover_endpoints {
            let host = raw.rsplit_once(':').map_or(raw.as_str(), |(h, _)| h);
            let unbracketed = host
                .strip_prefix('[')
                .and_then(|s| s.strip_suffix(']'))
                .unwrap_or(host);
            if let Ok(ip) = unbracketed.parse::<std::net::IpAddr>() {
                if is_private_or_special_use(ip) {
                    private_entries.push(raw.clone());
                }
            }
        }
        if !private_entries.is_empty() {
            r.push_fail(format!(
                "cover_endpoints contains entries in private / special-use IP ranges: \
                 {private_entries:?}. Same trap as cover_endpoint (iter-67): forwarding \
                 unauthenticated internet traffic to internal addresses is a privacy/\
                 security leak. Use publicly-routable cover hosts only. Note: the \
                 169.254.169.254 cloud-metadata-IP foot-gun applies to every cloud VPS \
                 — pointing cover there lets every probe fetch IAM credentials.",
            ));
        }
        if !dupes.is_empty() {
            r.push_warn(format!(
                "cover_endpoints contains duplicate entries: {dupes:?}. Per-/24 source-IP \
                 affinity routing puts traffic on the same upstream twice, reducing \
                 effective pool diversity. An active prober can correlate two 'different'\
                 entries' upstream behavior to prove they're the same host (defeats the \
                 threat-intel main line 4 defense the pool was added for). Replace \
                 duplicates with distinct cover destinations.",
            ));
        }
        if cfg.cover_endpoint.is_some() {
            r.push_warn(
                "both cover_endpoint AND cover_endpoints are set — cover_endpoint will be \
                 IGNORED at runtime. Remove cover_endpoint from the YAML to silence the \
                 runtime warning",
            );
        }
    } else {
        match cfg.cover_endpoint.as_ref() {
            Some(c) => match proteus_transport_alpha::cover::parse_cover_endpoint(c) {
                Some(parsed) => r.push_pass(format!("cover_endpoint parses ({parsed})")),
                None => r.push_fail(format!("cover_endpoint {c:?}: bad host:port")),
            },
            None => r.push_warn(
                "cover_endpoint / cover_endpoints both unset — auth-fail connections will \
                 be silently dropped",
            ),
        }
    }

    // Iter-141: cover endpoint port sanity. The cover-forward
    // protocol spec §7.5 forwards the raw TLS ClientHello bytes
    // verbatim to the cover endpoint; the cover MUST be an HTTPS
    // (port 443) endpoint OR another TLS-speaking port (8443 etc.)
    // for the bytes to make any sense. Pointing cover at port 80
    // (plaintext HTTP) is a known operator footgun:
    //
    //   * Operator types `www.cloudflare.com` thinking that's
    //     enough; runtime tries to splice the TLS ClientHello to
    //     port 80; the HTTP server returns garbage (it can't parse
    //     TLS bytes as HTTP); the probe sees an immediate non-TLS
    //     response on what should be an HTTPS-looking endpoint;
    //     **THE COVER ARM IS DEFEATED** — the prober immediately
    //     knows this isn't a real HTTPS server.
    //   * Same trap on port 22 / 25 / any non-TLS protocol port.
    //
    // We FAIL on the common-mistake set (80, 21, 22, 23, 25) and
    // WARN on every other non-TLS-canonical port (anything other
    // than 443, 8443, 9443). Operators running real custom-port
    // TLS deployments can ignore the WARN; the FAIL list covers
    // the obvious-mistake set that's never legitimate cover.
    let check_cover_port = |r: &mut PreflightReport, label: &str, endpoint: &str| {
        let port_str = match endpoint.rsplit_once(':') {
            Some((_, p)) => p,
            None => return,
        };
        let port: u16 = match port_str.parse() {
            Ok(p) => p,
            Err(_) => return,
        };
        const HARD_FAIL_PORTS: &[u16] = &[21, 22, 23, 25, 80];
        const CANONICAL_TLS_PORTS: &[u16] = &[443, 8443, 9443];
        if HARD_FAIL_PORTS.contains(&port) {
            r.push_fail(format!(
                "{label} ({endpoint:?}) targets port {port} — a well-known \
                 non-TLS service port (HTTP/FTP/SSH/Telnet/SMTP). The \
                 cover-forward path splices raw TLS ClientHello bytes to \
                 this endpoint; a plaintext-protocol server returns garbage, \
                 which any active prober immediately classifies as 'not a \
                 real HTTPS server' — DEFEATING the entire cover arm. \
                 Point cover_endpoint at an HTTPS endpoint (port 443)."
            ));
        } else if !CANONICAL_TLS_PORTS.contains(&port) {
            r.push_warn(format!(
                "{label} ({endpoint:?}) targets port {port} — not a canonical TLS \
                 port (443/8443/9443). If the cover service speaks TLS on this \
                 port, ignore this WARN. If not, the cover arm is defeated — \
                 raw TLS ClientHello bytes splice to a non-TLS server, and \
                 any active prober classifies the response shape immediately."
            ));
        }
    };
    if let Some(c) = cfg.cover_endpoint.as_deref() {
        check_cover_port(&mut r, "cover_endpoint", c);
    }
    for (idx, raw) in cfg.cover_endpoints.iter().enumerate() {
        check_cover_port(&mut r, &format!("cover_endpoints[{idx}]"), raw);
    }

    // 5b. Probe-anomaly detector config sanity.
    if let Some(pa) = cfg.probe_anomaly.as_ref() {
        if pa.window_secs == 0 {
            r.push_fail("probe_anomaly.window_secs = 0 disables the window entirely");
        } else if pa.window_secs > 86_400 {
            r.push_warn(format!(
                "probe_anomaly.window_secs = {} is > 24h; alert may take a long time to clear \
                 (consider 300-3600)",
                pa.window_secs
            ));
        } else {
            r.push_pass(format!("probe_anomaly.window_secs = {}", pa.window_secs));
        }
        if pa.threshold == 0 {
            r.push_fail("probe_anomaly.threshold = 0 means every cover-forward fires an alert");
        } else if pa.threshold == 1 {
            r.push_warn(
                "probe_anomaly.threshold = 1 fires on every single cover-forward; legitimate \
                 misconfigured clients will keep alerting (consider 3-10)",
            );
        } else {
            r.push_pass(format!("probe_anomaly.threshold = {}", pa.threshold));
        }
        if pa.max_prefixes == 0 {
            r.push_fail("probe_anomaly.max_prefixes = 0 disables tracking");
        } else if pa.max_prefixes < 64 {
            r.push_warn(format!(
                "probe_anomaly.max_prefixes = {} is very small; an IP-sweep attack would \
                 quickly evict legitimate prefixes (consider ≥ 1024)",
                pa.max_prefixes
            ));
        } else {
            r.push_pass(format!(
                "probe_anomaly.max_prefixes = {} (≈ {} KiB bookkeeping)",
                pa.max_prefixes,
                pa.max_prefixes * 64 / 1024
            ));
        }
        // Auto-deny: opt-in policy action.
        if pa.autodeny_minutes == 0 {
            r.push_warn(
                "probe_anomaly.autodeny_minutes = 0 — anomaly fires only ALERT, no automatic \
                 blackhole. Recommended for production: set to 15-60 so sustained probers get \
                 short-circuited at admission for that window",
            );
        } else if pa.autodeny_minutes > 24 * 60 {
            r.push_warn(format!(
                "probe_anomaly.autodeny_minutes = {} is > 24h; false positives on legitimate \
                 clients would take a long time to heal (consider 15-60 first)",
                pa.autodeny_minutes
            ));
        } else {
            r.push_pass(format!(
                "probe_anomaly.autodeny_minutes = {} (fires inject /24 into in-binary deny list \
                 for this window; admission_ok short-circuits)",
                pa.autodeny_minutes
            ));
        }
        if pa.autodeny_max_entries == 0 {
            r.push_fail("probe_anomaly.autodeny_max_entries = 0 disables the deny list");
        } else if pa.autodeny_max_entries < 64 {
            r.push_warn(format!(
                "probe_anomaly.autodeny_max_entries = {} is very small; IP-sweep attacks would \
                 fill the cap and refuse new denies (consider ≥ 1024)",
                pa.autodeny_max_entries
            ));
        }
        // Coherence: anomaly detector without any cover endpoint
        // means there's nothing to count — the detector will sit
        // silent forever.
        if cfg.cover_endpoint.is_none() && cfg.cover_endpoints.is_empty() {
            r.push_warn(
                "probe_anomaly is configured but no cover endpoint is set — the detector \
                 will never see events to count",
            );
        }
    } else if cfg.cover_endpoint.is_some() || !cfg.cover_endpoints.is_empty() {
        r.push_warn(
            "cover endpoint is configured but probe_anomaly is unset — cover-forward bursts \
             will not surface as alerts. Consider enabling the detector for production",
        );
    }

    // 6. Firewall CIDR rules parse — using the same parser the server
    //    will use at runtime.
    if let Some(fw) = cfg.firewall.as_ref() {
        let mut tmp = proteus_transport_alpha::firewall::Firewall::new();
        if let Err(e) = tmp.extend_allow(&fw.allow) {
            r.push_fail(format!("firewall.allow: {e}"));
        }
        if let Err(e) = tmp.extend_deny(&fw.deny) {
            r.push_fail(format!("firewall.deny: {e}"));
        }
        if tmp.is_active() {
            r.push_pass(format!(
                "firewall: {} allow, {} deny rules parse",
                fw.allow.len(),
                fw.deny.len()
            ));
        }
    }

    // 7. Metrics bearer-token file readable + nonempty +
    //    strong enough.
    //
    // Iter-65: pre-iter-65 we only checked nonempty. An operator
    // could put `token` or `changeme` in the file, validate said
    // green, and anyone who scanned the public metrics endpoint
    // with a small wordlist would walk straight through the bearer
    // gate. Three new checks:
    //   - minimum length (32 chars: a base64-encoded 24-byte
    //     random value, what `proteus-server keygen-metrics-token`
    //     would emit if we had one)
    //   - trivial-value blacklist (catches "changeme", "token",
    //     "admin", "password" etc.)
    //   - file mode (secret-file-mode warn, same as iter-52
    //     keys/SK handling)
    if let Some(path) = cfg.metrics_token_file.as_ref() {
        match std::fs::read_to_string(path) {
            Ok(s) if s.trim().is_empty() => {
                r.push_fail(format!("metrics_token_file {path:?} is empty"));
            }
            Ok(s) => {
                let token = s.trim();
                // Iter-154: reject control bytes anywhere in the token.
                // The token gets embedded into the HTTP request line
                // as `Authorization: Bearer {token}\r\n`; any CRLF /
                // NUL / TAB inside would smuggle attacker-chosen
                // headers. Defense-in-depth — operator-supplied
                // content, but config-templating tools (Ansible,
                // k8s ConfigMap) could pull from untrusted sources.
                // Symmetric with iter-147's parse_http_url gate.
                if token
                    .bytes()
                    .any(|b| b == 0 || b == b'\r' || b == b'\n' || b == b'\t')
                {
                    r.push_fail(format!(
                        "metrics_token_file {path:?} contains a control byte (NUL / CR / LF / \
                         TAB). The runtime embeds the token into the HTTP Authorization \
                         header; a control byte would smuggle attacker-chosen headers into \
                         every admin request. Replace with a clean printable secret: \
                         `openssl rand -base64 24 > {path:?}`."
                    ));
                }
                if token.len() < 32 {
                    r.push_warn(format!(
                        "metrics_token_file {path:?} contains a {}-char token; <32 chars is \
                         brute-forceable. Use `openssl rand -base64 24` (32 chars base64) or \
                         longer. The runtime still accepts the short token, but the gate is \
                         weak against scanners.",
                        token.len(),
                    ));
                }
                // Trivial-value blacklist. Case-insensitive prefix
                // match to catch trailing newlines / whitespace
                // that already got trimmed.
                const TRIVIAL: &[&str] = &[
                    "changeme",
                    "change-me",
                    "change_me",
                    "secret",
                    "token",
                    "admin",
                    "password",
                    "test",
                    "default",
                    "proteus",
                ];
                let token_lower = token.to_ascii_lowercase();
                if TRIVIAL.iter().any(|t| token_lower == *t) {
                    r.push_fail(format!(
                        "metrics_token_file {path:?} contains the trivial value \
                         {token_lower:?}. Any attacker scanning the metrics endpoint with a \
                         small wordlist will walk through. Replace with a real secret: \
                         `openssl rand -base64 24 > {path:?}`.",
                    ));
                } else {
                    r.push_pass(format!("metrics_token_file readable ({path:?})"));
                }
                // Secret-file mode (iter-52 helper).
                check_secret_file_mode(&mut r, "metrics_token_file", path);
            }
            Err(e) => r.push_fail(format!("metrics_token_file {path:?}: {e}")),
        }
    } else if let Some(addr) = cfg.metrics_listen.as_ref() {
        if !crate::is_loopback(addr) {
            // Iter-73: tier the severity. Wildcard bind without
            // a token is a hard FAIL — anyone on the internet
            // (cloud VPS deploy) can scrape /metrics, which
            // exposes panic_count, session_count, allowlist_size,
            // cover-forward rate, restart history, TLS cert
            // expiry — an attack-prep inventory of the server's
            // operational state. Other non-loopback binds stay
            // WARN (operator may have a deliberate
            // tunnel-interface monitoring setup).
            let host = addr.rsplit_once(':').map_or(addr.as_str(), |(h, _)| h);
            let unbracketed = host
                .strip_prefix('[')
                .and_then(|s| s.strip_suffix(']'))
                .unwrap_or(host);
            let is_wildcard = matches!(unbracketed, "0.0.0.0" | "::" | "");
            if is_wildcard {
                r.push_fail(format!(
                    "metrics_listen={addr:?} binds the unauthenticated /metrics endpoint \
                     to the wildcard interface. On a cloud VPS deploy, anyone on the \
                     internet can scrape panic_count / session_count / allowlist_size / \
                     cover-forward rate / restart history / TLS cert expiry — an attack-\
                     prep inventory of your operational state. Either bind 127.0.0.1 \
                     (and reach metrics via SSH tunnel) OR set metrics_token_file for \
                     bearer-token auth."
                ));
            } else {
                r.push_warn(format!(
                    "metrics_listen={addr:?} is non-loopback but metrics_token_file is unset; /metrics is unauthenticated"
                ));
            }
        }
    }

    // 8. metrics_listen address parses (when set).
    if let Some(addr) = cfg.metrics_listen.as_ref() {
        match addr.parse::<std::net::SocketAddr>() {
            Ok(_) => r.push_pass(format!("metrics_listen parses ({addr})")),
            Err(e) => r.push_fail(format!("metrics_listen {addr:?}: {e}")),
        }
    }

    // 9. Writable-file paths: probe each parent dir for write
    //    permission. Iter-50 introduced the probe for access_log;
    //    iter-53 extends it to every config-named runtime-written
    //    file so operators don't ship a config that startup-fails
    //    on "Permission denied" hours into the deploy.
    //
    // Covered paths (each runtime-written; missing-write triggers
    // a real production failure):
    //   - access_log                          — log writer, fatal
    //   - restart_state_file                  — shutdown writer,
    //                                            non-fatal at start
    //                                            but unclean-flag
    //                                            tracking breaks
    //   - user_quotas.persistence_path        — periodic flush
    //   - user_quarantine.persistence_path    — auto-quarantine
    //                                            writer
    if let Some(path) = cfg.access_log.as_ref() {
        check_parent_writable(&mut r, "access_log", path);
    }
    if let Some(path) = cfg.restart_state_file.as_ref() {
        check_parent_writable(&mut r, "restart_state_file", path);
    }
    if let Some(uq) = cfg.user_quotas.as_ref() {
        if let Some(path) = uq.persistence_path.as_ref() {
            check_parent_writable(&mut r, "user_quotas.persistence_path", path);
        }
        // Iter-85: user_quotas numeric + override sanity.
        //
        // period_secs = 0 → instant reset; every quota check
        // immediately resets the bucket → no enforcement. FAIL.
        if uq.period_secs == 0 {
            r.push_fail(
                "user_quotas.period_secs = 0 makes the quota window collapse to zero — \
                 buckets reset on every check, so no quota is ever enforced. Either set \
                 a real window (typical 86400 for daily, 2592000 for monthly) or remove \
                 the user_quotas block to disable the system entirely.",
            );
        }
        // max_entries = 0 → no users tracked → no quotas
        // enforced. FAIL.
        if uq.max_entries == 0 {
            r.push_fail(
                "user_quotas.max_entries = 0 disables user tracking — no quotas are \
                 ever enforced. If you want to disable quotas entirely, remove the \
                 user_quotas block.",
            );
        }
        // Override sanity: user_id must be in client_allowlist
        // (or the override is dead code), and each user_id
        // must appear at most once.
        let allowed_uids: std::collections::HashSet<&str> = cfg
            .client_allowlist
            .iter()
            .map(|c| c.user_id.as_str())
            .collect();
        let mut override_seen: std::collections::HashSet<&str> =
            std::collections::HashSet::with_capacity(uq.overrides.len());
        let mut override_dupes: Vec<&str> = Vec::new();
        let mut override_orphans: Vec<&str> = Vec::new();
        for ovr in &uq.overrides {
            let uid = ovr.user_id.as_str();
            if !override_seen.insert(uid) && !override_dupes.contains(&uid) {
                override_dupes.push(uid);
            }
            if !allowed_uids.is_empty() && !allowed_uids.contains(uid) {
                override_orphans.push(uid);
            }
        }
        if !override_dupes.is_empty() {
            r.push_fail(format!(
                "user_quotas.overrides contains duplicate user_id(s): {override_dupes:?}. \
                 The runtime hashmap silently drops the earlier entry; only the LAST \
                 override per user_id wins. Likely a typo — give each user_id one \
                 override line.",
            ));
        }
        if !override_orphans.is_empty() {
            r.push_warn(format!(
                "user_quotas.overrides references user_id(s) not in client_allowlist: \
                 {override_orphans:?}. These overrides are dead code (the user_id can \
                 never authenticate; the override never applies). Likely a typo OR a \
                 pre-rotation entry the operator forgot to delete.",
            ));
        }
    }
    // Iter-93: server-side β-QUIC tuning knobs sanity.
    // Symmetric with client iter-92.
    if let Some(mtu) = cfg.beta_initial_mtu {
        if !(1200..=1500).contains(&mtu) {
            r.push_fail(format!(
                "beta_initial_mtu = {mtu} is out of sane range [1200, 1500]. \
                 Below 1200 is below QUIC v1 minimum; above 1500 exceeds typical \
                 Ethernet MTU and risks IP fragmentation blackhole."
            ));
        }
    }
    if let Some(ub) = cfg.beta_mtu_upper_bound {
        if ub < 1200 {
            r.push_fail(format!(
                "beta_mtu_upper_bound = {ub} < 1200 (QUIC v1 minimum). MTU \
                 discovery will fail every probe attempt."
            ));
        } else if ub > 9216 {
            r.push_warn(format!(
                "beta_mtu_upper_bound = {ub} > 9216 (10G NIC jumbo-frame max). \
                 quinn-udp won't probe past 9000 by default."
            ));
        } else if let Some(initial) = cfg.beta_initial_mtu {
            if ub < initial {
                r.push_fail(format!(
                    "beta_mtu_upper_bound = {ub} is LESS than beta_initial_mtu = \
                     {initial}. Discovery cannot widen; the probe ceiling is below \
                     the starting MTU."
                ));
            }
        }
    }
    if let Some(thr) = cfg.beta_ack_eliciting_threshold {
        if thr == 0 {
            r.push_fail(
                "beta_ack_eliciting_threshold = 0 is invalid (would mean 'never ACK'). \
                 Valid: 1 (default) or 2-10 for measured long-fat-pipe paths.",
            );
        } else if thr > 100 {
            r.push_warn(format!(
                "beta_ack_eliciting_threshold = {thr} (>100) is extreme; BBR's \
                 bandwidth estimator may not converge. Recommended: 2-10."
            ));
        }
    }

    // Iter-96: periodic_self_test_failure_threshold sanity.
    //
    // The threshold = consecutive failures before draining the
    // node from health/LB rotation. Operator foot-guns:
    //   - 0 → effectively "drain on every failure" (no hysteresis;
    //         single-blip drains the node, expensive symptom)
    //   - >10 → so much hysteresis the operator never notices
    //           real failures until a sustained outage
    if let Some(t) = cfg.periodic_self_test_failure_threshold {
        if t == 0 {
            r.push_warn(
                "periodic_self_test_failure_threshold = 0 — single transient blip \
                 (RNG starvation, tokio scheduling hiccup, brief CPU pressure) \
                 immediately drains the node from LB rotation. Symptom (re-add \
                 latency) often dwarfs the cause (single blip). Recommended: 2 \
                 (default; absorbs single blip, drains within 2× interval).",
            );
        } else if t > 10 {
            r.push_warn(format!(
                "periodic_self_test_failure_threshold = {t} (>10) is excessive \
                 hysteresis. Operator won't notice real outages until {t} × \
                 periodic_interval seconds of sustained failures — that's often \
                 longer than the user-facing impact window. Recommended: 2-5.",
            ));
        }
    }

    // Iter-96: tls_cert_watcher_interval_secs sanity.
    //
    // 0 (default) means "watcher disabled" — operator uses
    // SIGHUP-on-rotation instead. > 0 enables mtime polling.
    // Foot-guns:
    //   - 1-5  → stat() every 1-5s is wasteful even though
    //            cheap; recommended ≥30s
    //   - >3600 → cert rotation window > 1h means the
    //             pre-rotation cert might expire before the
    //             watcher picks up the new one
    if let Some(t) = cfg.tls_cert_watcher_interval_secs {
        if t == 0 {
            // Explicit 0 = disabled; same as unset. PASS-with-
            // note only (the watcher is a feature, not a
            // required safety net).
            r.push_pass(
                "tls_cert_watcher_interval_secs = 0 — cert auto-reload watcher \
                 disabled (operator uses SIGHUP on rotation)",
            );
        } else if t < 5 {
            r.push_warn(format!(
                "tls_cert_watcher_interval_secs = {t} (<5s) — the stat() polling \
                 is cheap but every {t}s is wasteful. Recommended: 30-300s; cert \
                 rotation tooling typically has 1+ minute granularity anyway.",
            ));
        } else if t > 3600 {
            r.push_warn(format!(
                "tls_cert_watcher_interval_secs = {t} (>1h) is excessive — if the \
                 pre-rotation cert expires before the watcher picks up the new \
                 one (worst case: {t}s after rotation), every new TLS handshake \
                 fails. Recommended: 60-300s.",
            ));
        }
    }

    // Iter-90: self-test knobs sanity.
    //
    // The startup self-test exercises crypto + relay paths
    // synthetically at boot; the periodic self-test runs the
    // same check on a timer. Misconfiguration silently breaks
    // health-check coverage:
    //
    //   startup_self_test_timeout_secs = 0  → boot self-test
    //     skipped entirely (no signal at startup)
    //   startup_self_test_timeout_secs > 60 → bootstrap stalls
    //     in front of systemd's watchdog
    //   periodic_self_test_interval_secs = 0 → periodic check
    //     disabled (operator loses the "binary still alive +
    //     functional" signal between handshakes)
    //   periodic_self_test_interval_secs < 5 → check runs so
    //     often it becomes its own load
    if let Some(t) = cfg.startup_self_test_timeout_secs {
        if t == 0 {
            r.push_warn(
                "startup_self_test_timeout_secs = 0 → boot self-test is skipped \
                 entirely. The 'binary boots and crypto works' confirmation never \
                 fires. If you want to disable, remove the field; if you want a \
                 valid timeout, set 5-30s.",
            );
        } else if t > 60 {
            r.push_warn(format!(
                "startup_self_test_timeout_secs = {t} (>60s) is excessive; systemd's \
                 default TimeoutStartSec is 90s — boot self-test holding for {t}s \
                 leaves only {} seconds for the rest of startup. Recommended: ≤30s.",
                90_i64.saturating_sub(t as i64),
            ));
        }
    }
    if let Some(t) = cfg.periodic_self_test_interval_secs {
        if t == 0 {
            r.push_warn(
                "periodic_self_test_interval_secs = 0 → periodic check disabled. The \
                 'binary still alive + functional between handshakes' signal never \
                 fires; observability blind-spot during low-traffic windows.",
            );
        } else if t < 5 {
            r.push_warn(format!(
                "periodic_self_test_interval_secs = {t} (<5s) is very tight; the \
                 self-test itself adds load every {t}s. Recommended: 30-300s."
            ));
        }
    }

    // Iter-88: pad_quantum sanity. Mirror of the client-side
    // check. Pre-iter-88 a typo like `pad_quantum: 1300` (the
    // operator meant 1280) silently shipped — the runtime
    // accepts any u16 value but downstream code expects one
    // of the documented common sizes.
    if let Some(q) = cfg.pad_quantum {
        const COMMON: &[u16] = &[0, 64, 128, 256, 512, 1280];
        if !COMMON.contains(&q) {
            r.push_warn(format!(
                "pad_quantum = {q} is unusual (typical values: {COMMON:?}); typo for \
                 1280? The padding boundary affects wire-fingerprint uniformity; \
                 non-standard values may cause subtle observability mismatches with \
                 the documented threat-model coverage."
            ));
        } else {
            r.push_pass(format!("pad_quantum = {q}"));
        }
    }

    // Iter-87: abuse_detector entry sanity (byte_budget +
    // rate_limit). Each sub-block has the same shape; both get
    // the same three-state check via a small inline loop.
    if let Some(ad) = cfg.abuse_detector.as_ref() {
        for (label, entry_opt) in [
            ("abuse_detector.byte_budget", ad.byte_budget.as_ref()),
            ("abuse_detector.rate_limit", ad.rate_limit.as_ref()),
        ] {
            let Some(entry) = entry_opt else { continue };
            if entry.window_secs == 0 {
                r.push_fail(format!(
                    "{label}.window_secs = 0 — the sliding window has no width; \
                     the abuse-fire counter never accumulates and the alert never \
                     fires. Remove the sub-block to disable, or set a real window \
                     (typical: 300s)."
                ));
            } else if entry.window_secs > 86400 {
                r.push_warn(format!(
                    "{label}.window_secs = {} (>24h) is very long; an attacker \
                     spreading exactly under the threshold over a full day evades \
                     detection. Recommended: 60-3600s.",
                    entry.window_secs,
                ));
            }
            if entry.threshold == 0 {
                r.push_fail(format!(
                    "{label}.threshold = 0 means every single qualifying event \
                     fires an alert — every legitimate cap-hit produces a page. \
                     Likely a typo for 'I want to disable threshold'. The \
                     threshold gates abuse vs noise; recommended 3-10."
                ));
            } else if entry.threshold == 1 {
                r.push_warn(format!(
                    "{label}.threshold = 1 fires on every single event — every \
                     legitimate cap-hit produces an alert. Operator should \
                     consider raising to 3 (default) to gate noise."
                ));
            }
        }
    }

    // Iter-86 + iter-95: per_user_bandwidth_rate sanity.
    //
    // Each knob has a runtime default; explicit zero/absurd
    // values silently degrade the detector.
    if let Some(bw) = cfg.per_user_bandwidth_rate.as_ref() {
        // Iter-95: threshold_mb_per_sec sanity. 0 = detector
        // wired but silent (documented "observability-only").
        // Absurdly low values (1-5 MB/s) fire on any modern
        // streaming workload (4K = 25 Mbps = 3.1 MB/s; HD
        // Netflix ≈ 5 Mbps = 0.6 MB/s). Absurdly high values
        // (>10 GB/s) never fire — operator probably set the
        // wrong unit (bits vs bytes confusion).
        if bw.threshold_mb_per_sec == 0 {
            r.push_warn(
                "per_user_bandwidth_rate.threshold_mb_per_sec = 0 — the detector is \
                 wired (gauges emit) but no alert is ever raised. This is the \
                 documented 'observability-only' mode. If you want enforcement, set \
                 a positive threshold (typical: 10-100 MB/s; 50 is reasonable for \
                 personal-VPN, 200+ for bandwidth-heavy use cases like media \
                 servers).",
            );
        } else if bw.threshold_mb_per_sec < 5 {
            r.push_warn(format!(
                "per_user_bandwidth_rate.threshold_mb_per_sec = {} is very low. \
                 4K streaming alone is ~3 MB/s; HD Netflix is ~0.6 MB/s; a single \
                 user reading their email + watching Netflix will trip the threshold. \
                 Recommended: ≥10 for personal-VPN.",
                bw.threshold_mb_per_sec,
            ));
        } else if bw.threshold_mb_per_sec > 10_000 {
            r.push_warn(format!(
                "per_user_bandwidth_rate.threshold_mb_per_sec = {} (>10 GB/s) is \
                 absurdly high — even at 100 Gbps line rate that's 12.5 GB/s. The \
                 detector will likely never fire. Did you mean Mbps (bits) instead \
                 of MB/s (bytes)? Recommended: ≤1000 for personal-VPN.",
                bw.threshold_mb_per_sec,
            ));
        }
        if bw.window_secs == 0 {
            r.push_fail(
                "per_user_bandwidth_rate.window_secs = 0 collapses the sliding-window \
                 average to division-by-zero; every check produces a degenerate value. \
                 Remove the field entirely to inherit the 30s default.",
            );
        } else if bw.window_secs > 3600 {
            r.push_warn(format!(
                "per_user_bandwidth_rate.window_secs = {} (>1h) is unusual; sustained \
                 abuse over a 1+ hour window means the operator's reaction time is \
                 already too late. Recommended: 30-300s.",
                bw.window_secs,
            ));
        }
        if bw.max_users == 0 {
            r.push_fail(
                "per_user_bandwidth_rate.max_users = 0 disables the detector entirely \
                 (every user is silently dropped from sampling). If you want to \
                 disable, remove the per_user_bandwidth_rate block.",
            );
        }
        if !bw.exit_factor.is_finite() || bw.exit_factor < 0.0 || bw.exit_factor > 1.0 {
            r.push_fail(format!(
                "per_user_bandwidth_rate.exit_factor = {} must be in [0.0, 1.0]; the \
                 hysteresis exit factor controls re-arm threshold. Default 0.5.",
                bw.exit_factor,
            ));
        } else if bw.exit_factor > 0.99 {
            r.push_warn(format!(
                "per_user_bandwidth_rate.exit_factor = {} is very close to 1.0 — alert \
                 will flap on tiny rate variations at the threshold boundary. \
                 Recommended: 0.3-0.7.",
                bw.exit_factor,
            ));
        }
    }

    // Iter-86: per_user_conn_limit.max_per_user = 0 is the
    // documented "wired but disabled" mode (no rejection ever
    // happens). WARN-not-FAIL because some operators
    // legitimately use this for SIGHUP-swap observability.
    if let Some(cl) = cfg.per_user_conn_limit.as_ref() {
        if cl.max_per_user == 0 {
            r.push_warn(
                "per_user_conn_limit.max_per_user = 0 — the limiter is wired (gauges \
                 emit) but no session is ever rejected. This is the documented \
                 'observability-only' mode. If you want enforcement, set a positive \
                 value (typical: 4-16 for personal, 100+ for shared deploys).",
            );
        }
    }

    if let Some(uq) = cfg.user_quarantine.as_ref() {
        if let Some(path) = uq.persistence_path.as_ref() {
            check_parent_writable(&mut r, "user_quarantine.persistence_path", path);
        }
        // Iter-85: user_quarantine numeric sanity.
        //
        // ttl_secs = 0 is documented as "list wired but
        // disabled" (no entry ever sticks). PASS-with-note
        // because it's a legitimate operator choice for
        // observability-only deploys; FAIL would be wrong.
        if uq.ttl_secs == 0 {
            r.push_warn(
                "user_quarantine.ttl_secs = 0 — the quarantine list is wired but every \
                 insert immediately expires. This is the documented 'observability-only' \
                 mode (counters fire, no enforcement). If you want enforcement, set a \
                 non-zero TTL (typical 600 for personal, 3600 for stricter).",
            );
        }
        if uq.max_entries == 0 {
            r.push_fail(
                "user_quarantine.max_entries = 0 disables tracking — quarantine inserts \
                 immediately drop. If you want to disable entirely, remove the \
                 user_quarantine block.",
            );
        }
    }

    // 9b. knock_psk_file — FATAL at startup if invalid.
    //
    // Iter-54: pre-iter-54 the operator could ship a config with
    // `knock_psk_file: /etc/proteus/knock.psk` where the file
    // had a typo (4-byte base64 truncation, garbage line, missing
    // newline) and validate said green. The binary would exit at
    // startup with "knock_psk_file load failed: ..." — but the
    // operator had already deployed and was now firefighting.
    //
    // Validate now invokes the same `knock_keygen::load` parser
    // the binary uses, surfacing the same diagnostic at preflight.
    // We also call check_secret_file_mode on it (the PSK is a
    // secret — leaked-readable on shared hosts compromises the
    // probe-resistance gate).
    if let Some(path) = cfg.knock_psk_file.as_ref() {
        match crate::knock_keygen::load(path) {
            Ok(_) => {
                r.push_pass(format!("knock_psk_file loads cleanly ({path:?})"));
                check_secret_file_mode(&mut r, "knock_psk_file", path);
            }
            Err(e) => {
                r.push_fail(format!(
                    "knock_psk_file {path:?}: {e}. Startup will be FATAL. Run \
                     `proteus-server knock-keygen --out {path:?}` to mint a fresh \
                     PSK, OR remove the `knock_psk_file:` line from server.yaml \
                     to disable probe-resistance."
                ));
            }
        }
    }

    // 10. POW difficulty range (config field is u8 so 0..=255 by type;
    //     the server caps to 24 internally, but warn loudly so the
    //     operator doesn't think they got 32-bit difficulty).
    if let Some(d) = cfg.pow_difficulty {
        if d > 24 {
            r.push_warn(format!(
                "pow_difficulty={d} exceeds the in-code cap of 24; runtime will clamp to 24"
            ));
        } else if d > 0 {
            r.push_pass(format!("pow_difficulty = {d} bits"));
        }
    }

    // 11. Rate-limit knobs are positive.
    if let Some(rl) = cfg.rate_limit.as_ref() {
        if rl.burst <= 0.0 || rl.refill_per_sec < 0.0 {
            r.push_fail(format!(
                "rate_limit must have burst>0 and refill_per_sec>=0, got {:?}",
                rl
            ));
        } else {
            r.push_pass(format!(
                "rate_limit: burst={}, refill={}/s",
                rl.burst, rl.refill_per_sec
            ));
        }
    }
    if let Some(rl) = cfg.handshake_budget.as_ref() {
        if rl.burst <= 0.0 || rl.refill_per_sec < 0.0 {
            r.push_fail(format!(
                "handshake_budget must have burst>0 and refill_per_sec>=0, got {:?}",
                rl
            ));
        } else {
            r.push_pass(format!(
                "handshake_budget: burst={}, refill={}/s",
                rl.burst, rl.refill_per_sec
            ));
        }
    }
    if let Some(u) = cfg.user_rate_limit.as_ref() {
        if u.burst <= 0.0 || u.refill_per_sec < 0.0 || u.max_users == 0 {
            r.push_fail(format!(
                "user_rate_limit must have burst>0, refill_per_sec>=0, max_users>0; got {u:?}"
            ));
        } else {
            r.push_pass(format!(
                "user_rate_limit: burst={}, refill={}/s, max_users={}",
                u.burst, u.refill_per_sec, u.max_users
            ));
        }
    }

    // 12+. Cross-field coherence checks: catches policy combinations
    // that pass per-field validation but interact badly at runtime.
    coherence_checks(cfg, &mut r);

    r
}

/// Cross-field coherence: catches typos and policy combinations that
/// look valid in isolation but make every client fail at runtime.
/// Mostly emits [`Check::Warn`] — these are *unlikely* misconfigurations
/// but the operator should see them rather than discover in prod.
fn coherence_checks(cfg: &ServerConfig, r: &mut PreflightReport) {
    // Iter-97: CATASTROPHIC open-relay coherence.
    //
    // Empty client_allowlist (no auth gate) + non-loopback
    // wildcard bind (publicly reachable) + no firewall allow
    // list = the server accepts ANY client from ANY source. On
    // a cloud VPS deploy this means the entire internet has
    // free Proteus relay through the operator's egress IP. The
    // VPS's egress becomes the attribution target for whatever
    // traffic flows; TOS-violation notices from the cloud
    // provider follow within hours.
    //
    // Individually each is documented WARN: empty allowlist is
    // "testing only", wildcard bind is "production normal",
    // no firewall is "no IP allowlist needed". The COMBINATION
    // is the catastrophic case. FAIL with all three named.
    let listen_host = extract_host(&cfg.listen_alpha);
    let listen_is_wildcard = is_wildcard_host(listen_host);
    let firewall_has_allow = cfg
        .firewall
        .as_ref()
        .map(|fw| !fw.allow.is_empty())
        .unwrap_or(false);
    if cfg.client_allowlist.is_empty() && listen_is_wildcard && !firewall_has_allow {
        r.push_fail(format!(
            "CATASTROPHIC OPEN-RELAY: client_allowlist is empty (no auth) AND \
             listen_alpha = {} is the wildcard interface (publicly reachable) AND \
             firewall.allow is empty (no IP gate). The entire internet can route \
             traffic through this server via your egress IP. Fix any one of: \
             (a) populate client_allowlist with at least one ed25519_pk entry, \
             (b) bind listen_alpha to 127.0.0.1 for testing OR an explicit \
             interface IP, (c) populate firewall.allow with an IP allowlist.",
            cfg.listen_alpha,
        ));
    }

    // 12. PoW difficulty × handshake deadline.
    //
    // Rough cost model: at difficulty d, the *expected* SHA-256 hash
    // count to find a solution is 2^d. A modern laptop runs ~10 M
    // SHA-256/sec single-thread (we measured ~9-12 M across recent
    // ARM/Intel cores). Worst-case clients (slow mobiles) are 5-10×
    // slower. Treat 1 M hashes/sec as the floor.
    //
    // If the deadline is shorter than 2× the floor solve time, the
    // operator has probably misconfigured — most legit clients won't
    // finish PoW + KEX + sig in the budget.
    if let Some(d) = cfg.pow_difficulty {
        if d > 0 {
            let deadline = cfg.handshake_deadline_secs.unwrap_or(15);
            let expected_hashes = 1u64.checked_shl(u32::from(d.min(31))).unwrap_or(u64::MAX);
            // Floor: 1 M hashes/sec for the slowest legit clients.
            let floor_solve_secs = expected_hashes / 1_000_000;
            if floor_solve_secs * 2 > deadline {
                r.push_warn(format!(
                    "pow_difficulty={d} bits implies ~{floor_solve_secs}s solve time on slow \
                     mobile clients (1 M hashes/s floor); handshake_deadline_secs={deadline} \
                     leaves no margin. Either lower difficulty or raise the deadline.",
                ));
            } else {
                r.push_pass(format!(
                    "pow_difficulty + deadline coherent (floor solve ≈{floor_solve_secs}s, deadline {deadline}s)",
                ));
            }
        }
    }

    // 13. Per-IP rate-limit burst vs. per-user rate-limit burst.
    // The per-IP limit is supposed to BOUND the per-user limit
    // (multiple users share an IP under CGNAT). If per-user burst
    // exceeds per-IP burst, a single-IP user can never actually
    // reach their per-user quota — the IP limit fires first.
    if let (Some(ip_rl), Some(user_rl)) = (cfg.rate_limit.as_ref(), cfg.user_rate_limit.as_ref()) {
        if user_rl.burst > ip_rl.burst {
            r.push_warn(format!(
                "user_rate_limit.burst={} exceeds rate_limit.burst={} — single-IP users will \
                 never reach their per-user quota because the per-IP limit fires first. \
                 Either raise rate_limit.burst or lower user_rate_limit.burst.",
                user_rl.burst, ip_rl.burst,
            ));
        }
    }

    // 14. drain_secs configured but /metrics + /readyz not bound.
    // The graceful-drain path flips /readyz to 503 on SIGTERM so an
    // upstream load balancer stops sending traffic. Without
    // metrics_listen there's nothing for the LB to poll.
    if let Some(drain) = cfg.drain_secs {
        if drain > 0 && cfg.metrics_listen.is_none() {
            r.push_warn(format!(
                "drain_secs={drain} is set but metrics_listen is unset — no /readyz endpoint \
                 means upstream load balancers can't observe the drain. Either set \
                 metrics_listen or accept that drain is a server-internal flush only.",
            ));
        }
        // Iter-88: drain bound sanity.
        if drain == 0 {
            r.push_warn(
                "drain_secs = 0 — graceful drain is effectively disabled (SIGTERM \
                 immediately tears down accepted sessions). For browser-facing deploys \
                 this drops user requests mid-page-load. Recommended: 15-60s.",
            );
        } else if drain > 600 {
            r.push_warn(format!(
                "drain_secs = {drain} (>10min) is very long; systemd TimeoutStopSec \
                 must be at least {} or the kernel SIGKILLs the binary before drain \
                 completes. Recommended: ≤300s.",
                drain + 30,
            ));
        }
    }

    // 15. session_idle_secs < handshake_deadline_secs.
    // Idle bounds the *steady-state* session lifetime; deadline bounds
    // the *setup*. Idle smaller than deadline is almost certainly a
    // typo — would mean an established session can be reaped faster
    // than its handshake was allowed to take.
    let idle = cfg.session_idle_secs.unwrap_or(600);
    let deadline = cfg.handshake_deadline_secs.unwrap_or(15);
    if idle > 0 && idle < deadline {
        r.push_warn(format!(
            "session_idle_secs={idle} is less than handshake_deadline_secs={deadline}. \
             Sessions would be reaped while still finishing setup. Almost certainly a typo.",
        ));
    }
    // Iter-89: session_idle_secs sanity (explicit zero / absurd).
    if let Some(idle_secs) = cfg.session_idle_secs {
        if idle_secs == 0 {
            r.push_warn(
                "session_idle_secs = 0 disables the per-direction idle reaper. Sessions \
                 with both directions silent (NAT-dead, dead client, dead upstream) \
                 hold FDs + crypto state indefinitely until OS keepalive kicks in \
                 (typically 2 hours on Linux). FD leak under sustained flood. \
                 Recommended: 60-600s.",
            );
        } else if idle_secs > 86400 {
            r.push_warn(format!(
                "session_idle_secs = {idle_secs} (>24h) is excessive — dead sessions \
                 hold resources for {} days before reap. Recommended: ≤3600s.",
                idle_secs / 86400,
            ));
        }
    }
    // Iter-89: max_session_bytes = 0 explicitly disables the
    // per-session byte cap (any one session can consume
    // unbounded bandwidth + memory). Differs from `None`
    // (default = no cap) only in that the operator
    // EXPLICITLY typed 0 — flag the explicit-disable case.
    if cfg.max_session_bytes == Some(0) {
        r.push_warn(
            "max_session_bytes = 0 explicitly disables the per-session byte cap. \
             Each session can consume unbounded bandwidth. The runtime tolerates \
             this (None and Some(0) are equivalent), but the explicit-zero is \
             almost always a typo for 'no cap' which is achieved by removing \
             the field entirely. Remove the field to silence this warn.",
        );
    }

    // 16. max_connections < rate_limit.burst.
    // The per-IP rate limit's burst is the worst-case number of
    // simultaneous in-flight handshakes from one source. If
    // max_connections is smaller, a single source IP can saturate
    // the global cap by itself — defeating both layers.
    if let (Some(max_conn), Some(ip_rl)) = (cfg.max_connections, cfg.rate_limit.as_ref()) {
        let burst = ip_rl.burst.ceil() as usize;
        if max_conn < burst {
            r.push_warn(format!(
                "max_connections={max_conn} is below rate_limit.burst={burst} — one source IP \
                 can saturate the global concurrency cap by itself. Raise max_connections.",
            ));
        }
    }

    // Iter-75: outbound_filter SSRF policy sanity.
    //
    // The OutboundFilter sits between the client's CONNECT and
    // the actual upstream dial; it blocks SSRF-class destinations
    // (RFC 1918 / link-local / loopback / IPv6 ULA / cloud
    // metadata 169.254.169.254) by default. Three operator
    // foot-guns we surface at validate time:
    //
    //   1. `disabled: true` — the operator explicitly turned the
    //      filter OFF. Catastrophic on a public-internet deploy:
    //      any allowlist'd client can CONNECT into the operator's
    //      LAN / cloud metadata service / loopback / etc.
    //      FAIL — operator must intentionally opt in to risk.
    //   2. `replace_default_blocklist: true` WITHOUT a credible
    //      `extra_blocked_cidrs` set. This blanket-removes SSRF
    //      defaults; nearly always a typo for "I want to ADD
    //      blocks, not REPLACE them". FAIL with the recommended
    //      alternative (extra_blocked_cidrs instead).
    //   3. `extra_blocked_cidrs` entries that don't parse as
    //      CIDR. Runtime would log and ignore; validate surfaces
    //      so the operator catches typos at deploy time. FAIL.
    if let Some(of) = cfg.outbound_filter.as_ref() {
        if of.disabled {
            r.push_fail(
                "outbound_filter.disabled = true — SSRF defense is OFF. Any allowlist'd \
                 client can CONNECT into your LAN / cloud-metadata-service \
                 (169.254.169.254 → IAM credentials) / loopback. On a public deploy this \
                 is a catastrophic privilege-escalation surface. If you genuinely run \
                 trusted-LAN-only AND need the filter off (e.g., relaying to internal \
                 services intentionally), set `outbound_filter:` with explicit allowlist \
                 + tight extra_blocked_cidrs instead of the blanket disable.",
            );
        }
        if of.replace_default_blocklist {
            r.push_fail(
                "outbound_filter.replace_default_blocklist = true — the SSRF default \
                 blocklist (RFC 1918 / link-local / cloud-metadata / loopback) is \
                 REPLACED, not ADDED. Almost always a typo for 'I want to add blocks'. \
                 Use `extra_blocked_cidrs` instead (the defaults stay; your entries are \
                 appended). If you genuinely intend to replace, double-check \
                 extra_blocked_cidrs covers every SSRF range.",
            );
        }
        // CIDR parse check — same custom Cidr type used elsewhere
        // in the crate (ip_reputation.rs). Catches typos at deploy
        // time so the runtime doesn't silently ignore them.
        for cidr in &of.extra_blocked_cidrs {
            if cidr.parse::<crate::ip_reputation::Cidr>().is_err() {
                r.push_fail(format!(
                    "outbound_filter.extra_blocked_cidrs has an entry that doesn't parse \
                     as CIDR: {cidr:?}. Runtime ignores unparseable entries silently — \
                     your intended block doesn't apply.",
                ));
            }
        }
        // Sanity: when allowed_hostnames is non-empty, the operator
        // is operating in deny-by-default-allow-listed mode. WARN
        // if `extra_blocked_cidrs` is ALSO non-empty (likely
        // double-config; allowlist is the primary gate).
        if !of.allowed_hostnames.is_empty() && !of.extra_blocked_cidrs.is_empty() {
            r.push_warn(
                "outbound_filter: allowed_hostnames AND extra_blocked_cidrs are BOTH set \
                 — likely double-configuration. The allow_hostnames gate is the primary \
                 deny-by-default surface; CIDR blocks are typically redundant under it. \
                 If you genuinely need both, the order is: hostname-allow → CIDR-block.",
            );
        }
    }

    // Iter-66: cover-forward unboundedness check.
    //
    // The cover-forward path opens a TCP connection to the
    // configured cover endpoint for EVERY auth-fail / probe
    // event. Without a cap, a probe storm (intentional or GFW-
    // triggered) can spawn unbounded cover-forward tasks and
    // exhaust FDs — even with iter-18 EMFILE-survival in place,
    // the binary's effective throughput collapses.
    //
    // Three states:
    //   - max_cover_forwards explicitly set to 0 → FAIL
    //     ("0" is "disabled cap = unbounded", almost never what
    //     the operator meant; if they truly want unbounded they
    //     should leave it unset and accept the runtime warn)
    //   - max_cover_forwards unset AND max_connections unset
    //     → WARN (matches the runtime warn; surface at preflight
    //     too)
    //   - max_cover_forwards explicitly set > 0, OR
    //     max_connections set (runtime derives 4×) → PASS
    match (cfg.max_cover_forwards, cfg.max_connections) {
        (Some(0), _) => {
            r.push_fail(
                "max_cover_forwards = 0 explicitly disables the cover-forward concurrency \
                 cap — a single probe storm can spawn unbounded cover-tunnel tasks and \
                 exhaust FDs. If you genuinely want unbounded (NOT recommended), remove \
                 the field entirely; the runtime then emits a WARN and falls back to the \
                 max_connections × 4 derived bound, or runs uncapped if neither is set.",
            );
        }
        (Some(n), _) if n > 0 => {
            r.push_pass(format!(
                "max_cover_forwards = {n} (cover-forward path bounded)",
            ));
        }
        (None, Some(_n)) => {
            // Will be derived at runtime: max_connections * 4.
        }
        (None, None) => {
            r.push_warn(
                "max_cover_forwards AND max_connections both unset — cover-forward path \
                 is unbounded. Under a probe storm (GFW-triggered or otherwise) the binary \
                 can exhaust FDs even with iter-18 EMFILE-survival. Recommended: set \
                 max_cover_forwards: 4096 in server.yaml (or max_connections: 1024 to \
                 inherit the 4× derived bound).",
            );
        }
        _ => {}
    }

    // Iter-84: handshake_deadline_secs sanity.
    //
    // The handshake deadline is the slow-loris guard on the
    // pre-handshake phase (client connects but never sends
    // ClientHello / takes hours sending bytes one at a time).
    // Runtime default 15s; operator can override via
    // server.yaml. Two foot-guns:
    //
    //   - `handshake_deadline_secs: 0` → instant abort; every
    //     handshake fails. FAIL.
    //   - `handshake_deadline_secs: 1` → tight but plausible
    //     for low-latency LAN; on real internet RTTs the
    //     ML-KEM Decap roundtrip plus PoW (if non-zero)
    //     barely fits. WARN.
    //   - `handshake_deadline_secs > 300` → 5min slow-loris
    //     window is excessive; an attacker can hold a
    //     max_connections slot for 5min per connection.
    //     WARN.
    if let Some(secs) = cfg.handshake_deadline_secs {
        if secs == 0 {
            r.push_fail(
                "handshake_deadline_secs = 0 means every handshake aborts instantly — \
                 every dial fails before the client can send ClientHello. If you want \
                 the runtime default (15s), remove the field entirely.",
            );
        } else if secs == 1 {
            r.push_warn(
                "handshake_deadline_secs = 1 is very tight; on real-internet RTTs the \
                 TLS handshake + ML-KEM Decap roundtrip + any PoW solving barely fits. \
                 Recommended: ≥5s for production, ≥15s if pow_difficulty > 12.",
            );
        } else if secs > 300 {
            r.push_warn(format!(
                "handshake_deadline_secs = {secs} is excessive — slow-loris attackers \
                 can hold a max_connections slot for {secs}s per connection. \
                 Recommended: ≤60s for production.",
            ));
        } else {
            r.push_pass(format!("handshake_deadline_secs = {secs}"));
        }
    }

    // Iter-84: max_connections sanity. The global session
    // semaphore caps total in-flight connections; protects
    // against FD exhaustion. Two foot-guns:
    //
    //   - `max_connections: 0` → cap is zero, every accept
    //     immediately drops. FAIL.
    //   - `max_connections: 1_000_000` → absurd; each
    //     in-flight session has crypto state + buffers;
    //     1M sessions ≈ 16 TB worst-case memory.
    if let Some(n) = cfg.max_connections {
        if n == 0 {
            r.push_fail(
                "max_connections = 0 means the global session semaphore is empty — \
                 every accept immediately drops the connection. If you want unbounded, \
                 remove the field entirely (runtime falls back to OS FD ceiling).",
            );
        } else if n > 65535 {
            r.push_warn(format!(
                "max_connections = {n} is very high; each in-flight session reserves \
                 ~16 MiB worst-case (cipher state + scratch + buffers). {n} sessions \
                 ≈ {} GiB worst-case memory ceiling. Ensure the host has the RAM.",
                (n as u64 * 16) / 1024,
            ));
        }
    }

    // Iter-84: tcp_keepalive_secs = 0 disables TCP keepalive on
    // accepted client streams. The NAT idle-timer reaping class
    // (iter-14 fix) returns: long-idle Proteus sessions die
    // silently in mid-path NAT translators. WARN-not-FAIL (the
    // operator may legitimately disable for a measurement
    // experiment).
    if cfg.tcp_keepalive_secs == Some(0) {
        r.push_warn(
            "tcp_keepalive_secs = 0 disables TCP keepalive on accepted client streams. \
             Long-idle Proteus sessions will silently die in mid-path NAT translators \
             (the iter-14 fix class). If unset, runtime defaults to 30s.",
        );
    }

    // 17. Firewall allow ∩ deny: an IP matching both is denied
    // (deny wins). Likely an operator typo where they thought
    // allow trumps deny.
    if let Some(fw) = cfg.firewall.as_ref() {
        // Naive O(n*m): only realistic for the small N these lists
        // ever have. A real conflict means the operator typoed the
        // same /32 into both lists.
        for d in &fw.deny {
            if fw.allow.contains(d) {
                r.push_warn(format!(
                    "firewall: rule {d:?} appears in both allow and deny — deny wins, so this \
                     IP is blocked. Likely an operator typo.",
                ));
            }
        }
        // Iter-60: within-list duplicates. Operator copy-pastes a
        // CIDR twice into firewall.allow / firewall.deny and the
        // runtime treats them as one rule (the parser dedupes
        // internally) — but the operator now thinks "I have N
        // rules" when they have N-K. Surface so the per-list
        // counts in the config match the operator's intent.
        for (list_name, list) in [("firewall.allow", &fw.allow), ("firewall.deny", &fw.deny)] {
            let mut seen: std::collections::HashSet<&str> =
                std::collections::HashSet::with_capacity(list.len());
            let mut dupes: Vec<&str> = Vec::new();
            for cidr in list {
                if !seen.insert(cidr.as_str()) && !dupes.contains(&cidr.as_str()) {
                    dupes.push(cidr.as_str());
                }
            }
            if !dupes.is_empty() {
                r.push_warn(format!(
                    "{list_name} contains duplicate entries: {dupes:?}. Runtime dedupes them; \
                     the per-list count operators see in their config is misleading.",
                ));
            }
        }
    }

    // 18a. max_session_bytes must be at least 1 MiB.
    // Anything smaller breaks even a single HTTP page load.
    if let Some(cap) = cfg.max_session_bytes {
        if cap < 1024 * 1024 {
            r.push_warn(format!(
                "max_session_bytes={cap} is below 1 MiB — most HTTP pages won't load. \
                 Either set it to a sensible value (~50 GiB for streaming users, \
                 53687091200) or unset it.",
            ));
        }
    }

    // 18. cover_endpoint host == listen_alpha host: would loop
    // auth-fail traffic back into ourselves until both stack-bust.
    if let Some(cover) = cfg.cover_endpoint.as_ref() {
        // Compare host portions only (port may differ — e.g. 8443
        // vs cover on 443). A loopback bind catches the simplest
        // case.
        let listen_host = cfg
            .listen_alpha
            .rsplit_once(':')
            .map_or(cfg.listen_alpha.as_str(), |(h, _)| h);
        let cover_host = cover.rsplit_once(':').map_or(cover.as_str(), |(h, _)| h);
        if !listen_host.is_empty() && listen_host == cover_host {
            r.push_warn(format!(
                "cover_endpoint host {cover_host:?} matches listen_alpha host — auth-fail \
                 traffic would loop back into the server. Configure cover_endpoint to a \
                 distinct external HTTPS service (cloudflare/microsoft/apple).",
            ));
        }
        if listen_host == "0.0.0.0" || listen_host == "::" {
            // listen_alpha binds all interfaces; can't catch the
            // loopback case structurally. Best we can do is flag
            // common foot-guns.
            if cover_host == "127.0.0.1" || cover_host == "localhost" || cover_host == "::1" {
                r.push_warn(format!(
                    "cover_endpoint {cover_host:?} is loopback while listen_alpha binds all \
                     interfaces — auth-fail traffic loops back into ourselves. Configure a \
                     distinct external HTTPS service.",
                ));
            }
        }
        // Iter-67: cover_endpoint in RFC 1918 / RFC 4193 / link-
        // local / CGNAT private ranges → FAIL.
        //
        // An operator who configures cover_endpoint as an IP
        // literal in private address space (10/8, 172.16/12,
        // 192.168/16, 100.64/10 CGNAT, fc00::/7 ULA, fe80::/10
        // link-local) is pointing unauth'd internet traffic
        // at their internal network. Three failure modes:
        //   - The cover destination is an internal mgmt UI
        //     (router admin, NAS web interface) — every probe
        //     from the internet gets a tiny window into the
        //     LAN's surface
        //   - The cover destination doesn't exist on the LAN
        //     anymore → every probe sees connection-refused,
        //     defeating the "looks like a normal HTTPS site"
        //     defense
        //   - On a multi-tenant cloud, the private IP may
        //     belong to ANOTHER tenant — unauth probes flow
        //     into someone else's network
        //
        // FAIL because the security/privacy consequence is
        // severe and there's no legitimate use case (a
        // legitimate "internal" cover endpoint would still
        // need to be a publicly-routable host the operator
        // owns).
        // Strip IPv6 `[...]` brackets if present — `rsplit_once(':')`
        // above keeps them when the source was `[fc00::1]:443`.
        let cover_host_unbracketed = cover_host
            .strip_prefix('[')
            .and_then(|s| s.strip_suffix(']'))
            .unwrap_or(cover_host);
        if let Ok(cover_ip) = cover_host_unbracketed.parse::<std::net::IpAddr>() {
            let is_private = is_private_or_special_use(cover_ip);
            if is_private {
                r.push_fail(format!(
                    "cover_endpoint {cover_host:?} is in a private / special-use IP range \
                     (RFC 1918 / RFC 4193 / link-local / CGNAT). Forwarding unauthenticated \
                     internet traffic to an internal address is a privacy/security leak: \
                     internal services see public-internet payloads, and on multi-tenant \
                     hosts the private IP may belong to another tenant. Use a publicly-\
                     routable cover host (cloudflare.com / microsoft.com / apple.com / your \
                     own legitimate HTTPS site)."
                ));
            }
        }
    }
}

/// Iter-67: detect IPs that should never appear as a public-
/// forwarded `cover_endpoint`. Covers IPv4 RFC 1918 / RFC 6598
/// CGNAT / link-local, and IPv6 ULA / link-local. Loopback is
/// handled by the earlier check; multicast / unspecified are
/// detected via std's helpers.
fn is_private_or_special_use(ip: std::net::IpAddr) -> bool {
    match ip {
        std::net::IpAddr::V4(v4) => {
            // RFC 1918 private, RFC 6598 CGNAT (100.64.0.0/10),
            // link-local (169.254.0.0/16). is_private() covers the
            // RFC 1918 subset; we add the rest explicitly.
            let octets = v4.octets();
            v4.is_private()
                || v4.is_link_local()
                || v4.is_multicast()
                || v4.is_unspecified()
                // CGNAT: 100.64.0.0/10
                || (octets[0] == 100 && (octets[1] & 0xc0) == 64)
        }
        std::net::IpAddr::V6(v6) => {
            // ULA (fc00::/7), link-local (fe80::/10), multicast,
            // unspecified.
            let seg0 = v6.segments()[0];
            v6.is_multicast()
                || v6.is_unspecified()
                // ULA fc00::/7: top 7 bits = 0b1111110x
                || (seg0 & 0xfe00) == 0xfc00
                // Link-local fe80::/10: top 10 bits = 0b1111111010
                || (seg0 & 0xffc0) == 0xfe80
        }
    }
}

/// Iter-97: extract the host portion of a `host:port` string,
/// stripping IPv6 brackets if present.
fn extract_host(addr: &str) -> &str {
    let host = addr.rsplit_once(':').map_or(addr, |(h, _)| h);
    host.strip_prefix('[')
        .and_then(|s| s.strip_suffix(']'))
        .unwrap_or(host)
}

/// Iter-97: detect wildcard listen address. Returns true for
/// `0.0.0.0`, `[::]`, and the empty string (which the OS treats
/// as wildcard for some bind paths).
fn is_wildcard_host(host: &str) -> bool {
    matches!(host, "0.0.0.0" | "::" | "")
}

/// Helper: assert a file exists and is readable by the current
/// process. Records [`Check::Fail`] otherwise.
fn check_file(report: &mut PreflightReport, label: &str, path: &Path) {
    match std::fs::read(path) {
        Ok(bytes) => {
            // Iter-48: all-zeros sentinel check applies to KEY files
            // only. Cert/PEM files are skipped (their parse path
            // already gates content, and a "keys" label is the
            // signal we're looking at raw key material).
            //
            // Iter-55: extend to `client_allowlist[*].ed25519_pk`.
            // An all-zero pubkey in the allowlist means the
            // operator copy-pasted a placeholder OR a keygen
            // script crashed; any client presenting the zero key
            // (trivial to forge) would be auth'd, which is the
            // worst-case-equivalent to no allowlist at all.
            let is_key_file = label.starts_with("keys.") || label.starts_with("client_allowlist[");
            if is_key_file && !bytes.is_empty() {
                // Decode base64 if it looks like base64 to catch the
                // case where the operator stored keys in armored form
                // (the keygen tool's default output).
                let decoded = base64_or_raw_bytes(&bytes);
                if !decoded.is_empty() && decoded.iter().all(|&b| b == 0) {
                    report.push_fail(format!(
                        "{label} {path:?}: ALL-ZERO contents ({} bytes) — placeholder \
                         the operator forgot to replace OR a key-rotation script crashed \
                         mid-write. Catastrophic security failure: secret keys become \
                         trivially-forgeable identities; allowlist pubkeys auth-pass \
                         any client presenting the zero key. Run `proteus-server \
                         keygen` (or copy a real allowlist pubkey from the issuing \
                         operator).",
                        decoded.len(),
                    ));
                    return;
                }
            }
            // Iter-52: secret key files must be 0600 (or stricter).
            // Operators copying SK files between hosts via rsync /
            // scp without `-p` end up with default umask (0644) on
            // the destination. Public PQ keys exposed to the
            // operator's user is bad; exposed to OTHER users on the
            // VPS (shared hosting / chroot escape) is catastrophic.
            // `preflight check-host` already catches this but many
            // operators only run `validate` before deploy — same
            // signal should fire there.
            //
            // Pattern: the file is a "SECRET" if the label ends with
            // `_sk` OR the label is `tls.private_key`. Public keys
            // (`_pk`, `cert_chain`) skip the mode check.
            let is_secret = label.ends_with("_sk") || label == "tls.private_key";
            if is_secret {
                check_secret_file_mode(report, label, path);
            }
            report.push_pass(format!("{label} exists and readable ({path:?})"));
        }
        Err(e) => report.push_fail(format!("{label} {path:?}: {e}")),
    }
}

/// Iter-52: Unix-only secret-file mode check. On non-Unix the
/// check is a no-op (Windows doesn't have the same world-readable
/// concept). The check WARNs (not FAILs) because:
///   - Operators ship in containers with restricted process users
///     where loose modes are still safe in practice
///   - The runtime would happily start with a 0644 SK — emitting a
///     hard FAIL would block deploys that the `preflight check-host`
///     WARN already flagged
///   - `preflight check-host` is the FAIL gate for this class;
///     `validate` is the lighter early-warning surface
#[cfg(unix)]
fn check_secret_file_mode(report: &mut PreflightReport, label: &str, path: &Path) {
    use std::os::unix::fs::PermissionsExt;
    let md = match std::fs::metadata(path) {
        Ok(m) => m,
        Err(_) => return, // existing check_file branch will surface the error
    };
    let mode = md.permissions().mode() & 0o777;
    // 0600 (owner-only) is the canonical safe state. 0400 (owner-
    // read-only) is also safe. Anything with bits in group/other
    // categories is a warn.
    let group_or_other_set = mode & 0o077 != 0;
    if group_or_other_set {
        report.push_warn(format!(
            "{label} {path:?} has mode {mode:#o} — group or world readable. \
             SECRET key exposure on shared hosts. Fix: `chmod 0600 {path:?}`. \
             (validate emits a warn; the harder gate is `proteus-server preflight check-host`.)"
        ));
    }
}

#[cfg(not(unix))]
fn check_secret_file_mode(_report: &mut PreflightReport, _label: &str, _path: &Path) {
    // No-op on non-Unix; the world-readable concept doesn't map.
}

/// Iter-53: probe a runtime-written-file's PARENT directory for
/// write permission. Originally inlined for `access_log` (iter-50);
/// extracted so every config-named writable path can share the
/// same diagnostic.
///
/// We probe the parent (not the target file itself) because the
/// target file:
///   - may not exist yet (first start with a fresh config)
///   - may already exist and contain operator data we mustn't clobber
///
/// A uniquely-named probe file (PID + nanos) sidesteps races with
/// other `validate` invocations sharing the same dir.
fn check_parent_writable(report: &mut PreflightReport, label: &str, path: &Path) {
    let parent = path.parent().unwrap_or_else(|| Path::new("/"));
    match parent.metadata() {
        Ok(md) => {
            if !md.is_dir() {
                report.push_fail(format!("{label} parent {parent:?} is not a directory"));
                return;
            }
            let probe_name = format!(
                ".proteus-validate-probe-{}-{}",
                std::process::id(),
                std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .map(|d| d.as_nanos())
                    .unwrap_or(0),
            );
            let probe_path = parent.join(&probe_name);
            match std::fs::File::create(&probe_path) {
                Ok(_) => {
                    let _ = std::fs::remove_file(&probe_path);
                    report.push_pass(format!(
                        "{label} parent dir exists and is writable ({parent:?})"
                    ));
                }
                Err(e) => {
                    report.push_fail(format!(
                        "{label} parent {parent:?} exists but is NOT writable as the \
                         current user: {e}. Runtime writes to this path will fail at \
                         startup. Check ownership: `sudo chown -R proteus:proteus \
                         {parent:?}` (or the user the systemd unit runs as)."
                    ));
                }
            }
        }
        Err(e) => report.push_fail(format!("{label} parent {parent:?}: {e}")),
    }
}

/// Iter-144: enforce exact length of an X25519 key file (32 bytes
/// raw OR 44 bytes base64-armored per RFC 7748 §5). Used for both
/// the server's static `x25519_pk` and `x25519_sk`. Skips the
/// check when the file is absent or empty — those already FAILED
/// via check_file's existing checks.
///
/// Iter-187: wrap the file-read bytes + decoded bytes in
/// `Zeroizing<Vec<u8>>`. When called against `x25519_sk` the bytes
/// ARE the SK material (or b64-encoded form thereof); pre-iter-187
/// the file-read Vec lingered on the heap after validate exit. The
/// `x25519_pk` path is non-secret; conservatively scrubbing both
/// costs one memset per call and avoids baking "is-this-SK" into
/// the helper signature.
fn check_x25519_key_len(report: &mut PreflightReport, label: &str, path: &Path) {
    use zeroize::Zeroizing;
    let bytes = match std::fs::read(path) {
        Ok(b) if !b.is_empty() => Zeroizing::new(b),
        _ => return,
    };
    let decoded = Zeroizing::new(base64_or_raw_bytes(&bytes));
    if decoded.len() == 32 || bytes.len() == 32 {
        return; // pass — no need for a second OK row
    }
    report.push_fail(format!(
        "{label} {path:?}: X25519 key length wrong (got {} bytes raw / {} bytes \
         after base64-decode; expected exactly 32 per RFC 7748 §5). Truncated key \
         file or wrong-file copy-paste. Re-issue with `proteus-server keygen`.",
        bytes.len(),
        decoded.len()
    ));
}

/// Iter-140: enforce exact length of an ML-KEM-768 key file on the
/// server side. Mirrors the iter-139 client-side gate. Accepts
/// either raw bytes or base64-armored bytes (`base64_or_raw_bytes`
/// handles both).
///
/// `expected_raw_len` is the FIPS-203 §6.1 length of the raw bytes
/// (1184 for EK, 2400 for DK). `description` is the human label
/// embedded in any FAIL message so operators know which spec
/// section to cross-reference.
fn check_mlkem_key_len(
    report: &mut PreflightReport,
    label: &str,
    path: &Path,
    expected_raw_len: usize,
    description: &str,
) {
    // Iter-187: same Zeroizing wrap as `check_x25519_key_len`.
    // For `mlkem_sk` this is decapsulation-key material; for
    // `mlkem_pk` this is non-secret. Conservative scrub on both.
    use zeroize::Zeroizing;
    let bytes = match std::fs::read(path) {
        Ok(b) => Zeroizing::new(b),
        Err(_) => {
            // The check_file call above already pushed a FAIL with
            // the underlying io::Error. Don't double-fail.
            return;
        }
    };
    let decoded = Zeroizing::new(base64_or_raw_bytes(&bytes));
    let raw_len = decoded.len();
    if raw_len == expected_raw_len {
        report.push_pass(format!(
            "{label} length OK ({raw_len} bytes raw, matches {description})"
        ));
        return;
    }
    // Fall back to checking the on-disk raw length (catches the case
    // where the file is raw bytes but base64-decoding produced
    // something else — base64_or_raw_bytes returns the raw bytes
    // when the input doesn't look like base64).
    if bytes.len() == expected_raw_len {
        report.push_pass(format!(
            "{label} length OK ({} bytes raw, matches {description})",
            bytes.len()
        ));
        return;
    }
    report.push_fail(format!(
        "{label} {path:?}: length {raw_len} bytes (after base64 decode if applicable) \
         does NOT match expected {expected_raw_len} for {description}. Operator likely \
         supplied a truncated key, a wrong-file copy-paste, or a key for the wrong \
         ML-KEM variant. Regenerate with `proteus-server keygen` (or copy the original \
         key file from the issuing operator)."
    ));
}

fn base64_or_raw_bytes(input: &[u8]) -> Vec<u8> {
    use base64::Engine;
    use zeroize::Zeroize as _;

    // Iter-187: scrub the intermediate `trimmed` Vec on drop.
    // When validate-time SK length checks call this helper
    // (mlkem_sk, x25519_sk files), `trimmed` is a byte-for-byte
    // copy of the base64-encoded SK material — directly
    // substitutable for the SK via b64-decode. The public-key
    // load paths also exercise this helper; conservatively
    // scrubbing both shapes costs ~one memset per call and
    // avoids baking "is-this-SK" into the helper signature.
    // Mirrors the iter-168 decode_b64_or_raw fix on the
    // runtime key-load paths (config.rs server + client
    // sides).
    let mut trimmed: Vec<u8> = input
        .iter()
        .copied()
        .filter(|b| !b.is_ascii_whitespace())
        .collect();
    let result = if let Ok(decoded) = base64::engine::general_purpose::STANDARD.decode(&trimmed) {
        decoded
    } else {
        input.to_vec()
    };
    trimmed.zeroize();
    result
}

/// Top-level driver for the `validate` subcommand. Loads the YAML
/// file, then runs the rest of [`preflight`].
///
/// Returns `Ok(true)` on all-green (or warnings only), `Ok(false)`
/// if any check failed, and `Err` if even the YAML didn't parse.
pub async fn run(config_path: &Path) -> Result<bool, Box<dyn std::error::Error>> {
    println!("preflight check: {config_path:?}");
    let cfg = ServerConfig::load(config_path)
        .await
        .map_err(|e| format!("config parse: {e}"))?;
    println!("  [ok]   YAML parses");
    let report = preflight(&cfg);
    let _ = std::io::stdout().flush();
    print!("{report}");
    let _ = std::io::stdout().flush();
    Ok(!report.has_failures())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{ClientCfg, FirewallCfg, KeysCfg, RateLimitCfg};
    use std::path::PathBuf;

    fn tmpdir() -> PathBuf {
        // Three discriminators stacked because validate's unit tests
        // run in parallel inside ONE process — PID alone collides
        // across tests in the same binary; nanos alone collides on
        // fast machines that emit two SystemTime::now()s in the same
        // ns; thread id alone is reused across executor parks. The
        // tuple `(pid, nanos, thread_id, atomic_counter)` is
        // belt-and-suspenders against every collision class we've
        // hit. Without this, `negative_rate_limit_fails` (and any
        // other test using `tmpdir()`) intermittently fails under
        // heavy parallel workspace test load when two tests pick the
        // same dir and one trashes the other's placeholder key files
        // mid-flight — manifested as "report did not contain
        // expected FAIL" because the FAIL came from missing files
        // instead of the rate-limit check.
        use std::sync::atomic::{AtomicU64, Ordering};
        static COUNTER: AtomicU64 = AtomicU64::new(0);
        let n = COUNTER.fetch_add(1, Ordering::Relaxed);
        let tid = format!("{:?}", std::thread::current().id());
        let tid_digits: String = tid.chars().filter(|c| c.is_ascii_digit()).collect();
        let p = std::env::temp_dir().join(format!(
            "proteus-preflight-{}-{}-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos(),
            tid_digits,
            n,
        ));
        let _ = std::fs::remove_dir_all(&p);
        std::fs::create_dir_all(&p).unwrap();
        p
    }

    fn write(p: &Path, content: &[u8]) {
        std::fs::write(p, content).unwrap();
    }

    fn minimal_cfg(dir: &Path) -> ServerConfig {
        // Iter-140: ML-KEM key files must be the exact FIPS-203
        // sizes (1184 / 2400 bytes) since the new length gate
        // rejects anything else. Tests that previously used
        // `b"placeholder"` (11 bytes) now use random-byte buffers
        // of the right length. The all-zeros gate still applies —
        // we fill with `0x42` to avoid the iter-48 sentinel.
        write(&dir.join("mlkem.pk"), &vec![0x42u8; 1184]);
        write(&dir.join("mlkem.sk"), &vec![0x42u8; 2400]);
        write(&dir.join("x25519.pk"), &[0x42u8; 32]);
        write(&dir.join("x25519.sk"), &[0x42u8; 32]);
        ServerConfig {
            // Iter-97: bind to a LAN address so the iter-97
            // catastrophic-open-relay coherence check
            // (wildcard listen + empty allowlist + no firewall
            // → FAIL) doesn't fire on every minimal_cfg test.
            // Tests that specifically exercise the wildcard
            // path explicitly set listen_alpha to 0.0.0.0.
            listen_alpha: "192.168.1.100:8443".to_string(),
            listen_beta: None,
            beta_cert_chain: None,
            beta_private_key: None,
            beta_initial_mtu: None,
            beta_pad_quic_to_mtu: None,
            beta_allow_spin_bit: None,
            beta_ack_eliciting_threshold: None,
            beta_mtu_upper_bound: None,
            keys: KeysCfg {
                mlkem_pk: dir.join("mlkem.pk"),
                mlkem_sk: dir.join("mlkem.sk"),
                x25519_pk: dir.join("x25519.pk"),
                x25519_sk: dir.join("x25519.sk"),
            },
            client_allowlist: Vec::new(),
            cover_endpoint: None,
            cover_endpoints: Vec::new(),
            probe_anomaly: None,
            metrics_listen: None,
            metrics_token_file: None,
            rate_limit: None,
            handshake_budget: None,
            user_rate_limit: None,
            handshake_deadline_secs: None,
            tcp_keepalive_secs: None,
            restart_state_file: None,
            knock_psk_file: None,
            tls: None,
            pow_difficulty: None,
            drain_secs: None,
            access_log: None,
            session_idle_secs: None,
            pad_quantum: None,
            firewall: None,
            max_connections: None,
            max_cover_forwards: None,
            max_session_bytes: None,
            abuse_detector: None,
            per_user_bandwidth_rate: None,
            per_user_conn_limit: None,
            user_quarantine: None,
            user_quotas: None,
            startup_self_test_timeout_secs: None,
            periodic_self_test_interval_secs: None,
            periodic_self_test_failure_threshold: None,
            tls_cert_watcher_interval_secs: None,
            outbound_filter: None,
        }
    }

    #[test]
    fn minimal_config_passes_with_warnings() {
        let dir = tmpdir();
        let cfg = minimal_cfg(&dir);
        let report = preflight(&cfg);
        assert!(
            !report.has_failures(),
            "minimal cfg should not fail: {report}"
        );
        let (_, w, _) = report.counts();
        assert!(w > 0, "expected at least one warning, got: {report}");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn missing_key_file_fails() {
        let dir = tmpdir();
        let mut cfg = minimal_cfg(&dir);
        cfg.keys.mlkem_pk = dir.join("does-not-exist");
        let report = preflight(&cfg);
        assert!(report.has_failures(), "expected fail: {report}");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn bad_listen_addr_fails() {
        let dir = tmpdir();
        let mut cfg = minimal_cfg(&dir);
        cfg.listen_alpha = "not-an-addr".to_string();
        let report = preflight(&cfg);
        assert!(report.has_failures(), "expected fail: {report}");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn bad_cover_endpoint_fails() {
        let dir = tmpdir();
        let mut cfg = minimal_cfg(&dir);
        cfg.cover_endpoint = Some("not a host:port at all".to_string());
        let report = preflight(&cfg);
        assert!(report.has_failures(), "expected fail: {report}");
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Iter-60: duplicate CIDRs within firewall.allow → WARN.
    /// Same shape for firewall.deny.
    #[test]
    fn iter60_duplicate_firewall_allow_warns() {
        let dir = tmpdir();
        let mut cfg = minimal_cfg(&dir);
        cfg.firewall = Some(FirewallCfg {
            allow: vec![
                "10.0.0.0/8".to_string(),
                "192.0.2.0/24".to_string(),
                "10.0.0.0/8".to_string(),
            ],
            deny: vec![],
        });
        let report = preflight(&cfg);
        let warn = report.checks.iter().any(|c| match c {
            Check::Warn(s) => s.contains("firewall.allow") && s.contains("duplicate"),
            _ => false,
        });
        assert!(warn, "duplicate firewall.allow MUST WARN: {report}");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn iter60_duplicate_firewall_deny_warns() {
        let dir = tmpdir();
        let mut cfg = minimal_cfg(&dir);
        cfg.firewall = Some(FirewallCfg {
            allow: vec![],
            deny: vec!["198.51.100.0/24".to_string(), "198.51.100.0/24".to_string()],
        });
        let report = preflight(&cfg);
        let warn = report.checks.iter().any(|c| match c {
            Check::Warn(s) => s.contains("firewall.deny") && s.contains("duplicate"),
            _ => false,
        });
        assert!(warn, "duplicate firewall.deny MUST WARN: {report}");
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Iter-59: duplicate cover_endpoints reduce effective
    /// diversity AND defeat the threat-intel main-line-4
    /// active-probing defense the pool was added for. WARN with
    /// the duplicate list.
    #[test]
    fn iter59_duplicate_cover_endpoints_warns() {
        let dir = tmpdir();
        let mut cfg = minimal_cfg(&dir);
        cfg.cover_endpoints = vec![
            "https://a.example.com:443/".to_string(),
            "https://b.example.com:443/".to_string(),
            "https://a.example.com:443/".to_string(), // duplicate of first
        ];
        let report = preflight(&cfg);
        let warn = report.checks.iter().any(|c| match c {
            Check::Warn(s) => {
                s.contains("cover_endpoints")
                    && s.contains("duplicate")
                    && s.contains("a.example.com")
            }
            _ => false,
        });
        assert!(warn, "duplicate cover_endpoints MUST WARN: {report}");
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Iter-59: distinct cover_endpoints → no dupe warn.
    #[test]
    fn iter59_distinct_cover_endpoints_no_dupe_warn() {
        let dir = tmpdir();
        let mut cfg = minimal_cfg(&dir);
        cfg.cover_endpoints = vec![
            "https://a.example.com:443/".to_string(),
            "https://b.example.com:443/".to_string(),
            "https://c.example.com:443/".to_string(),
        ];
        let report = preflight(&cfg);
        let warn = report.checks.iter().any(|c| match c {
            Check::Warn(s) => s.contains("cover_endpoints") && s.contains("duplicate"),
            _ => false,
        });
        assert!(
            !warn,
            "distinct cover_endpoints must NOT trigger dupe warn: {report}"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn bad_firewall_cidr_fails() {
        let dir = tmpdir();
        let mut cfg = minimal_cfg(&dir);
        cfg.firewall = Some(FirewallCfg {
            allow: vec!["10.0.0.0/8".to_string(), "not-a-cidr".to_string()],
            deny: vec![],
        });
        let report = preflight(&cfg);
        assert!(report.has_failures(), "expected fail: {report}");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn empty_metrics_token_file_fails() {
        let dir = tmpdir();
        let token_path = dir.join("metrics.token");
        write(&token_path, b""); // empty
        let mut cfg = minimal_cfg(&dir);
        cfg.metrics_listen = Some("127.0.0.1:9090".to_string());
        cfg.metrics_token_file = Some(token_path);
        let report = preflight(&cfg);
        assert!(report.has_failures(), "expected fail: {report}");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn nonempty_metrics_token_file_passes() {
        let dir = tmpdir();
        let token_path = dir.join("metrics.token");
        // Iter-65: bump fixture to a 32+ char value so the new
        // weak-token WARN doesn't fire on a test that wants to
        // assert "everything green".
        write(&token_path, b"k7nP2vQrL8xJ3hM5wY4zA6bE9cF1uD0i\n");
        let mut cfg = minimal_cfg(&dir);
        cfg.metrics_listen = Some("127.0.0.1:9090".to_string());
        cfg.metrics_token_file = Some(token_path);
        let report = preflight(&cfg);
        assert!(!report.has_failures(), "got: {report}");
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Iter-68: same private-IP trap on cover_endpoints[] pool
    /// entries — applies the iter-67 check to every entry. The
    /// pool has the same exposure as the single endpoint.
    #[test]
    fn iter68_cover_endpoints_pool_with_private_entries_fails() {
        let dir = tmpdir();
        let mut cfg = minimal_cfg(&dir);
        cfg.cover_endpoints = vec![
            "https://microsoft.com:443/".to_string(),
            "10.0.0.1:443".to_string(), // private — should FAIL
            "https://apple.com:443/".to_string(),
        ];
        let report = preflight(&cfg);
        assert!(
            report.has_failures(),
            "private entry in cover_endpoints MUST FAIL: {report}"
        );
        let fail = report.checks.iter().any(|c| match c {
            Check::Fail(s) => {
                s.contains("cover_endpoints") && s.contains("private") && s.contains("10.0.0.1")
            }
            _ => false,
        });
        assert!(fail, "FAIL must list the offending private entry: {report}");
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Iter-68: cloud metadata IP in pool → FAIL (the worst case
    /// — IAM credential exfiltration via cover-forward).
    #[test]
    fn iter68_cover_endpoints_cloud_metadata_ip_fails() {
        let dir = tmpdir();
        let mut cfg = minimal_cfg(&dir);
        cfg.cover_endpoints = vec![
            "https://cloudflare.com:443/".to_string(),
            "169.254.169.254:80".to_string(), // AWS/GCP/Azure/DO metadata
        ];
        let report = preflight(&cfg);
        assert!(
            report.has_failures(),
            "cloud-metadata IP in pool MUST FAIL: {report}"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Iter-68: all-public pool entries → no private FAIL.
    #[test]
    fn iter68_cover_endpoints_pool_all_public_passes() {
        let dir = tmpdir();
        let mut cfg = minimal_cfg(&dir);
        cfg.cover_endpoints = vec![
            "https://microsoft.com:443/".to_string(),
            "https://apple.com:443/".to_string(),
            "198.51.100.1:443".to_string(), // TEST-NET-2, public-routable
        ];
        let report = preflight(&cfg);
        let private_fail = report.checks.iter().any(|c| match c {
            Check::Fail(s) => s.contains("cover_endpoints") && s.contains("private"),
            _ => false,
        });
        assert!(
            !private_fail,
            "all-public pool must NOT trigger iter-68 FAIL: {report}"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Iter-67: cover_endpoint in RFC 1918 → FAIL (forwards
    /// unauth'd internet traffic into LAN).
    #[test]
    fn iter67_cover_endpoint_rfc1918_fails() {
        for victim in [
            "10.0.0.1:443",
            "192.168.1.1:443",
            "172.16.0.1:443",
            "100.64.0.1:443",     // CGNAT
            "169.254.169.254:80", // link-local (cloud metadata!)
        ] {
            let dir = tmpdir();
            let mut cfg = minimal_cfg(&dir);
            cfg.cover_endpoint = Some(victim.to_string());
            let report = preflight(&cfg);
            assert!(
                report.has_failures(),
                "cover_endpoint={victim} MUST FAIL: {report}"
            );
            let fail = report.checks.iter().any(|c| match c {
                Check::Fail(s) => s.contains("cover_endpoint") && s.contains("private"),
                _ => false,
            });
            assert!(
                fail,
                "FAIL must call out 'private' for {victim:?}: {report}"
            );
            let _ = std::fs::remove_dir_all(&dir);
        }
    }

    /// Iter-67: IPv6 ULA + link-local also FAIL.
    #[test]
    fn iter67_cover_endpoint_ipv6_private_fails() {
        for victim in [
            "[fc00::1]:443", // ULA
            "[fe80::1]:443", // link-local
        ] {
            let dir = tmpdir();
            let mut cfg = minimal_cfg(&dir);
            cfg.cover_endpoint = Some(victim.to_string());
            let report = preflight(&cfg);
            assert!(
                report.has_failures(),
                "IPv6 cover_endpoint={victim} MUST FAIL: {report}"
            );
            let _ = std::fs::remove_dir_all(&dir);
        }
    }

    /// Iter-67: hostnames are SKIPPED (we can't resolve at
    /// validate time without spawning DNS; cloud cover hosts
    /// like microsoft.com are always hostnames).
    #[test]
    fn iter67_cover_endpoint_hostname_not_flagged_as_private() {
        let dir = tmpdir();
        let mut cfg = minimal_cfg(&dir);
        cfg.cover_endpoint = Some("microsoft.com:443".to_string());
        let report = preflight(&cfg);
        let any_private_fail = report.checks.iter().any(|c| match c {
            Check::Fail(s) => s.contains("cover_endpoint") && s.contains("private"),
            _ => false,
        });
        assert!(
            !any_private_fail,
            "hostname cover_endpoint must NOT trigger private-IP FAIL: {report}"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Iter-67: public IP literal → OK.
    #[test]
    fn iter67_cover_endpoint_public_ip_passes() {
        let dir = tmpdir();
        let mut cfg = minimal_cfg(&dir);
        cfg.cover_endpoint = Some("198.51.100.1:443".to_string()); // TEST-NET-2, public-routable
        let report = preflight(&cfg);
        let any_private_fail = report.checks.iter().any(|c| match c {
            Check::Fail(s) => s.contains("cover_endpoint") && s.contains("private"),
            _ => false,
        });
        assert!(
            !any_private_fail,
            "public IP cover_endpoint must NOT trigger the iter-67 FAIL: {report}"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Iter-93: server beta_initial_mtu out-of-range → FAIL.
    #[test]
    fn iter93_server_beta_initial_mtu_out_of_range_fails() {
        let dir = tmpdir();
        let mut cfg = minimal_cfg(&dir);
        cfg.beta_initial_mtu = Some(1000);
        let report = preflight(&cfg);
        assert!(report.has_failures(), "MTU=1000 MUST FAIL: {report}");
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Iter-93: server beta_mtu_upper_bound < 1200 → FAIL.
    #[test]
    fn iter93_server_beta_mtu_upper_below_min_fails() {
        let dir = tmpdir();
        let mut cfg = minimal_cfg(&dir);
        cfg.beta_mtu_upper_bound = Some(1000);
        let report = preflight(&cfg);
        assert!(
            report.has_failures(),
            "MTU upper < 1200 MUST FAIL: {report}"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Iter-93: server beta_mtu_upper_bound > 9216 → WARN.
    #[test]
    fn iter93_server_beta_mtu_upper_excessive_warns() {
        let dir = tmpdir();
        let mut cfg = minimal_cfg(&dir);
        cfg.beta_mtu_upper_bound = Some(10000);
        let report = preflight(&cfg);
        let warn = report
            .checks
            .iter()
            .any(|c| matches!(c, Check::Warn(s) if s.contains("beta_mtu_upper_bound = 10000")));
        assert!(warn, "MTU > 9216 must WARN: {report}");
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Iter-93: server beta_mtu_upper_bound < initial → FAIL.
    #[test]
    fn iter93_server_beta_mtu_upper_below_initial_fails() {
        let dir = tmpdir();
        let mut cfg = minimal_cfg(&dir);
        cfg.beta_initial_mtu = Some(1450);
        cfg.beta_mtu_upper_bound = Some(1300);
        let report = preflight(&cfg);
        assert!(report.has_failures(), "upper < initial MUST FAIL: {report}");
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Iter-93: server beta_ack_eliciting_threshold = 0 → FAIL.
    #[test]
    fn iter93_server_beta_ack_zero_fails() {
        let dir = tmpdir();
        let mut cfg = minimal_cfg(&dir);
        cfg.beta_ack_eliciting_threshold = Some(0);
        let report = preflight(&cfg);
        assert!(report.has_failures(), "ack=0 MUST FAIL: {report}");
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Iter-93: server beta_ack_eliciting_threshold > 100 → WARN.
    #[test]
    fn iter93_server_beta_ack_extreme_warns() {
        let dir = tmpdir();
        let mut cfg = minimal_cfg(&dir);
        cfg.beta_ack_eliciting_threshold = Some(500);
        let report = preflight(&cfg);
        let warn = report.checks.iter().any(|c| {
            matches!(c, Check::Warn(s) if s.contains("beta_ack_eliciting_threshold = 500") && s.contains("BBR"))
        });
        assert!(warn, "ack=500 must WARN: {report}");
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Iter-97: catastrophic open-relay coherence (wildcard +
    /// empty allowlist + no firewall) → FAIL.
    #[test]
    fn iter97_catastrophic_open_relay_fails() {
        let dir = tmpdir();
        let mut cfg = minimal_cfg(&dir);
        // Trip all three: wildcard listen + empty allowlist +
        // no firewall.
        cfg.listen_alpha = "0.0.0.0:8443".to_string();
        assert!(cfg.client_allowlist.is_empty());
        assert!(cfg.firewall.is_none());
        let report = preflight(&cfg);
        assert!(
            report.has_failures(),
            "wildcard + empty allowlist + no firewall MUST FAIL: {report}"
        );
        let fail = report.checks.iter().any(|c| {
            matches!(c, Check::Fail(s) if s.contains("CATASTROPHIC OPEN-RELAY") && s.contains("0.0.0.0:8443"))
        });
        assert!(
            fail,
            "FAIL must call out CATASTROPHIC OPEN-RELAY + the wildcard addr: {report}"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Iter-97: wildcard + ALLOWLIST → no FAIL.
    #[test]
    fn iter97_wildcard_plus_allowlist_no_fail() {
        let dir = tmpdir();
        let pk = dir.join("alice.pk");
        std::fs::write(&pk, b"some-non-zero-content").unwrap();
        let mut cfg = minimal_cfg(&dir);
        cfg.listen_alpha = "0.0.0.0:8443".to_string();
        cfg.client_allowlist = vec![ClientCfg {
            user_id: "alice".to_string(),
            ed25519_pk: pk,
        }];
        let report = preflight(&cfg);
        let open_relay_fail = report
            .checks
            .iter()
            .any(|c| matches!(c, Check::Fail(s) if s.contains("CATASTROPHIC OPEN-RELAY")));
        assert!(
            !open_relay_fail,
            "allowlist gates auth — must NOT trigger iter-97 FAIL: {report}"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Iter-97: wildcard + empty-allowlist + FIREWALL.ALLOW → no FAIL.
    #[test]
    fn iter97_wildcard_plus_firewall_allow_no_fail() {
        let dir = tmpdir();
        let mut cfg = minimal_cfg(&dir);
        cfg.listen_alpha = "0.0.0.0:8443".to_string();
        cfg.firewall = Some(FirewallCfg {
            allow: vec!["192.168.0.0/16".to_string()],
            deny: vec![],
        });
        let report = preflight(&cfg);
        let open_relay_fail = report
            .checks
            .iter()
            .any(|c| matches!(c, Check::Fail(s) if s.contains("CATASTROPHIC OPEN-RELAY")));
        assert!(
            !open_relay_fail,
            "firewall.allow gates the source — must NOT trigger iter-97 FAIL: {report}"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Iter-97: LOOPBACK listen + empty-allowlist + no firewall
    /// → no FAIL (testing config; not internet-reachable).
    #[test]
    fn iter97_loopback_listen_no_fail() {
        let dir = tmpdir();
        let mut cfg = minimal_cfg(&dir);
        cfg.listen_alpha = "127.0.0.1:8443".to_string();
        let report = preflight(&cfg);
        let open_relay_fail = report
            .checks
            .iter()
            .any(|c| matches!(c, Check::Fail(s) if s.contains("CATASTROPHIC OPEN-RELAY")));
        assert!(
            !open_relay_fail,
            "loopback listen is testing-only; must NOT trigger iter-97 FAIL: {report}"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Iter-96: periodic_self_test_failure_threshold = 0 → WARN.
    #[test]
    fn iter96_self_test_threshold_zero_warns() {
        let dir = tmpdir();
        let mut cfg = minimal_cfg(&dir);
        cfg.periodic_self_test_failure_threshold = Some(0);
        let report = preflight(&cfg);
        let warn = report.checks.iter().any(|c| {
            matches!(c, Check::Warn(s) if s.contains("periodic_self_test_failure_threshold = 0") && s.contains("blip"))
        });
        assert!(warn, "threshold=0 must WARN: {report}");
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Iter-96: threshold > 10 → WARN (over-hysteresis).
    #[test]
    fn iter96_self_test_threshold_excessive_warns() {
        let dir = tmpdir();
        let mut cfg = minimal_cfg(&dir);
        cfg.periodic_self_test_failure_threshold = Some(20);
        let report = preflight(&cfg);
        let warn = report.checks.iter().any(|c| {
            matches!(c, Check::Warn(s) if s.contains("periodic_self_test_failure_threshold = 20") && s.contains("hysteresis"))
        });
        assert!(warn, "threshold=20 must WARN: {report}");
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Iter-96: tls_cert_watcher_interval_secs = 0 → PASS (disabled is valid).
    #[test]
    fn iter96_cert_watcher_zero_passes() {
        let dir = tmpdir();
        let mut cfg = minimal_cfg(&dir);
        cfg.tls_cert_watcher_interval_secs = Some(0);
        let report = preflight(&cfg);
        let pass = report.checks.iter().any(|c| {
            matches!(c, Check::Pass(s) if s.contains("tls_cert_watcher_interval_secs = 0") && s.contains("disabled"))
        });
        assert!(pass, "watcher=0 must PASS with note: {report}");
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Iter-96: watcher interval < 5 → WARN.
    #[test]
    fn iter96_cert_watcher_too_tight_warns() {
        let dir = tmpdir();
        let mut cfg = minimal_cfg(&dir);
        cfg.tls_cert_watcher_interval_secs = Some(2);
        let report = preflight(&cfg);
        let warn = report.checks.iter().any(|c| {
            matches!(c, Check::Warn(s) if s.contains("tls_cert_watcher_interval_secs = 2") && s.contains("wasteful"))
        });
        assert!(warn, "watcher=2 must WARN: {report}");
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Iter-96: watcher interval > 1h → WARN.
    #[test]
    fn iter96_cert_watcher_excessive_warns() {
        let dir = tmpdir();
        let mut cfg = minimal_cfg(&dir);
        cfg.tls_cert_watcher_interval_secs = Some(7200);
        let report = preflight(&cfg);
        let warn = report.checks.iter().any(|c| {
            matches!(c, Check::Warn(s) if s.contains("tls_cert_watcher_interval_secs = 7200") && s.contains("rotation"))
        });
        assert!(warn, "watcher=7200 must WARN: {report}");
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Iter-90: startup_self_test_timeout_secs = 0 → WARN.
    #[test]
    fn iter90_startup_self_test_zero_warns() {
        let dir = tmpdir();
        let mut cfg = minimal_cfg(&dir);
        cfg.startup_self_test_timeout_secs = Some(0);
        let report = preflight(&cfg);
        let warn = report.checks.iter().any(|c| {
            matches!(c, Check::Warn(s) if s.contains("startup_self_test_timeout_secs = 0") && s.contains("skipped"))
        });
        assert!(warn, "startup self-test=0 must WARN: {report}");
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Iter-90: startup_self_test_timeout_secs > 60 → WARN.
    #[test]
    fn iter90_startup_self_test_excessive_warns() {
        let dir = tmpdir();
        let mut cfg = minimal_cfg(&dir);
        cfg.startup_self_test_timeout_secs = Some(120);
        let report = preflight(&cfg);
        let warn = report.checks.iter().any(|c| {
            matches!(c, Check::Warn(s) if s.contains("startup_self_test_timeout_secs = 120") && s.contains("TimeoutStartSec"))
        });
        assert!(warn, "startup=120 must WARN: {report}");
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Iter-90: periodic_self_test_interval_secs = 0 → WARN.
    #[test]
    fn iter90_periodic_self_test_zero_warns() {
        let dir = tmpdir();
        let mut cfg = minimal_cfg(&dir);
        cfg.periodic_self_test_interval_secs = Some(0);
        let report = preflight(&cfg);
        let warn = report.checks.iter().any(|c| {
            matches!(c, Check::Warn(s) if s.contains("periodic_self_test_interval_secs = 0") && s.contains("disabled"))
        });
        assert!(warn, "periodic self-test=0 must WARN: {report}");
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Iter-90: periodic_self_test_interval_secs < 5 → WARN.
    #[test]
    fn iter90_periodic_self_test_too_tight_warns() {
        let dir = tmpdir();
        let mut cfg = minimal_cfg(&dir);
        cfg.periodic_self_test_interval_secs = Some(2);
        let report = preflight(&cfg);
        let warn = report.checks.iter().any(|c| {
            matches!(c, Check::Warn(s) if s.contains("periodic_self_test_interval_secs = 2") && s.contains("tight"))
        });
        assert!(warn, "periodic=2 must WARN: {report}");
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Iter-89: session_idle_secs = 0 → WARN.
    #[test]
    fn iter89_session_idle_zero_warns() {
        let dir = tmpdir();
        let mut cfg = minimal_cfg(&dir);
        cfg.session_idle_secs = Some(0);
        let report = preflight(&cfg);
        let warn = report.checks.iter().any(|c| {
            matches!(c, Check::Warn(s) if s.contains("session_idle_secs = 0") && s.contains("FD leak"))
        });
        assert!(warn, "session_idle_secs=0 must WARN: {report}");
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Iter-89: session_idle_secs > 24h → WARN.
    #[test]
    fn iter89_session_idle_excessive_warns() {
        let dir = tmpdir();
        let mut cfg = minimal_cfg(&dir);
        cfg.session_idle_secs = Some(259200); // 3 days
        let report = preflight(&cfg);
        let warn = report.checks.iter().any(|c| {
            matches!(c, Check::Warn(s) if s.contains("session_idle_secs = 259200") && s.contains("excessive"))
        });
        assert!(warn, "session_idle_secs=259200 must WARN: {report}");
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Iter-89: max_session_bytes = 0 (explicit zero) → WARN.
    #[test]
    fn iter89_max_session_bytes_zero_warns() {
        let dir = tmpdir();
        let mut cfg = minimal_cfg(&dir);
        cfg.max_session_bytes = Some(0);
        let report = preflight(&cfg);
        let warn = report.checks.iter().any(|c| {
            matches!(c, Check::Warn(s) if s.contains("max_session_bytes = 0") && s.contains("explicitly"))
        });
        assert!(warn, "max_session_bytes=0 must WARN: {report}");
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Iter-88: server pad_quantum unusual value → WARN.
    #[test]
    fn iter88_pad_quantum_unusual_warns() {
        let dir = tmpdir();
        let mut cfg = minimal_cfg(&dir);
        cfg.pad_quantum = Some(1300); // typo for 1280
        let report = preflight(&cfg);
        let warn = report.checks.iter().any(
            |c| matches!(c, Check::Warn(s) if s.contains("pad_quantum") && s.contains("1300")),
        );
        assert!(warn, "unusual pad_quantum must WARN: {report}");
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Iter-88: server pad_quantum common value → PASS.
    #[test]
    fn iter88_pad_quantum_common_passes() {
        let dir = tmpdir();
        let mut cfg = minimal_cfg(&dir);
        cfg.pad_quantum = Some(1280);
        let report = preflight(&cfg);
        let pass = report
            .checks
            .iter()
            .any(|c| matches!(c, Check::Pass(s) if s.contains("pad_quantum = 1280")));
        assert!(pass, "common pad_quantum must PASS: {report}");
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Iter-88: drain_secs = 0 → WARN (graceful drain disabled).
    #[test]
    fn iter88_drain_zero_warns() {
        let dir = tmpdir();
        let mut cfg = minimal_cfg(&dir);
        cfg.drain_secs = Some(0);
        let report = preflight(&cfg);
        let warn = report.checks.iter().any(|c| {
            matches!(c, Check::Warn(s) if s.contains("drain_secs = 0") && s.contains("disabled"))
        });
        assert!(warn, "drain=0 must WARN: {report}");
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Iter-88: drain_secs > 600 → WARN (SIGKILL race).
    #[test]
    fn iter88_drain_excessive_warns() {
        let dir = tmpdir();
        let mut cfg = minimal_cfg(&dir);
        cfg.drain_secs = Some(1200);
        let report = preflight(&cfg);
        let warn = report.checks.iter().any(|c| {
            matches!(c, Check::Warn(s) if s.contains("drain_secs = 1200") && s.contains("TimeoutStopSec"))
        });
        assert!(warn, "drain=1200 must WARN: {report}");
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Iter-87: abuse_detector.byte_budget.window_secs = 0 → FAIL.
    #[test]
    fn iter87_abuse_byte_budget_zero_window_fails() {
        let dir = tmpdir();
        let mut cfg = minimal_cfg(&dir);
        let yaml = "byte_budget:\n  window_secs: 0\n  threshold: 3\n";
        cfg.abuse_detector = Some(serde_yaml::from_str(yaml).expect("AbuseDetectorCfg parse"));
        let report = preflight(&cfg);
        assert!(
            report.has_failures(),
            "byte_budget.window_secs=0 MUST FAIL: {report}"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Iter-87: abuse_detector.byte_budget.window_secs > 24h → WARN.
    #[test]
    fn iter87_abuse_byte_budget_excessive_window_warns() {
        let dir = tmpdir();
        let mut cfg = minimal_cfg(&dir);
        let yaml = "byte_budget:\n  window_secs: 172800\n  threshold: 3\n";
        cfg.abuse_detector = Some(serde_yaml::from_str(yaml).expect("AbuseDetectorCfg parse"));
        let report = preflight(&cfg);
        let warn = report.checks.iter().any(
            |c| matches!(c, Check::Warn(s) if s.contains("abuse_detector.byte_budget.window_secs")),
        );
        assert!(warn, "excessive window must WARN: {report}");
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Iter-87: abuse_detector.rate_limit.threshold = 0 → FAIL.
    #[test]
    fn iter87_abuse_rate_limit_zero_threshold_fails() {
        let dir = tmpdir();
        let mut cfg = minimal_cfg(&dir);
        let yaml = "rate_limit:\n  window_secs: 300\n  threshold: 0\n";
        cfg.abuse_detector = Some(serde_yaml::from_str(yaml).expect("AbuseDetectorCfg parse"));
        let report = preflight(&cfg);
        assert!(
            report.has_failures(),
            "rate_limit.threshold=0 MUST FAIL: {report}"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Iter-87: abuse_detector.byte_budget.threshold = 1 → WARN.
    #[test]
    fn iter87_abuse_threshold_one_warns() {
        let dir = tmpdir();
        let mut cfg = minimal_cfg(&dir);
        let yaml = "byte_budget:\n  window_secs: 300\n  threshold: 1\n";
        cfg.abuse_detector = Some(serde_yaml::from_str(yaml).expect("AbuseDetectorCfg parse"));
        let report = preflight(&cfg);
        let warn = report.checks.iter().any(|c| {
            matches!(c, Check::Warn(s) if s.contains("abuse_detector.byte_budget.threshold") && s.contains("noise"))
        });
        assert!(warn, "threshold=1 must WARN: {report}");
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Iter-87: both sub-blocks misconfigured → both surface
    /// independently.
    #[test]
    fn iter87_abuse_both_sub_blocks_surface_independently() {
        let dir = tmpdir();
        let mut cfg = minimal_cfg(&dir);
        let yaml = "byte_budget:\n  window_secs: 0\n  threshold: 3\nrate_limit:\n  window_secs: 300\n  threshold: 0\n";
        cfg.abuse_detector = Some(serde_yaml::from_str(yaml).expect("AbuseDetectorCfg parse"));
        let report = preflight(&cfg);
        let fails: Vec<_> = report
            .checks
            .iter()
            .filter(|c| matches!(c, Check::Fail(s) if s.contains("abuse_detector")))
            .collect();
        assert_eq!(
            fails.len(),
            2,
            "both sub-blocks must fail independently: {report}"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Iter-95: threshold_mb_per_sec = 0 → WARN (observability-only).
    #[test]
    fn iter95_bw_threshold_zero_warns() {
        let dir = tmpdir();
        let mut cfg = minimal_cfg(&dir);
        let yaml = "window_secs: 30\nthreshold_mb_per_sec: 0\nmax_users: 1000\nexit_factor: 0.5\n";
        cfg.per_user_bandwidth_rate =
            Some(serde_yaml::from_str(yaml).expect("PerUserBandwidthRateCfg parse"));
        let report = preflight(&cfg);
        let warn = report.checks.iter().any(|c| {
            matches!(c, Check::Warn(s) if s.contains("threshold_mb_per_sec = 0") && s.contains("observability-only"))
        });
        assert!(warn, "threshold=0 must WARN: {report}");
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Iter-95: threshold_mb_per_sec < 5 → WARN (fires on
    /// streaming).
    #[test]
    fn iter95_bw_threshold_too_low_warns() {
        let dir = tmpdir();
        let mut cfg = minimal_cfg(&dir);
        let yaml = "window_secs: 30\nthreshold_mb_per_sec: 2\nmax_users: 1000\nexit_factor: 0.5\n";
        cfg.per_user_bandwidth_rate =
            Some(serde_yaml::from_str(yaml).expect("PerUserBandwidthRateCfg parse"));
        let report = preflight(&cfg);
        let warn = report.checks.iter().any(|c| {
            matches!(c, Check::Warn(s) if s.contains("threshold_mb_per_sec = 2") && s.contains("Netflix"))
        });
        assert!(warn, "threshold=2 must WARN: {report}");
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Iter-95: threshold_mb_per_sec > 10000 → WARN
    /// (unit-confusion).
    #[test]
    fn iter95_bw_threshold_absurd_warns() {
        let dir = tmpdir();
        let mut cfg = minimal_cfg(&dir);
        let yaml =
            "window_secs: 30\nthreshold_mb_per_sec: 50000\nmax_users: 1000\nexit_factor: 0.5\n";
        cfg.per_user_bandwidth_rate =
            Some(serde_yaml::from_str(yaml).expect("PerUserBandwidthRateCfg parse"));
        let report = preflight(&cfg);
        let warn = report.checks.iter().any(|c| {
            matches!(c, Check::Warn(s) if s.contains("threshold_mb_per_sec = 50000") && s.contains("Mbps"))
        });
        assert!(warn, "threshold=50000 must WARN: {report}");
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Iter-86: per_user_bandwidth_rate.window_secs = 0 → FAIL.
    #[test]
    fn iter86_bw_window_zero_fails() {
        let dir = tmpdir();
        let mut cfg = minimal_cfg(&dir);
        let yaml = "window_secs: 0\nthreshold_mb_per_sec: 10\nmax_users: 1000\nexit_factor: 0.5\n";
        cfg.per_user_bandwidth_rate =
            Some(serde_yaml::from_str(yaml).expect("PerUserBandwidthRateCfg parse"));
        let report = preflight(&cfg);
        assert!(report.has_failures(), "window_secs=0 MUST FAIL: {report}");
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Iter-86: per_user_bandwidth_rate.window_secs > 1h → WARN.
    #[test]
    fn iter86_bw_window_excessive_warns() {
        let dir = tmpdir();
        let mut cfg = minimal_cfg(&dir);
        let yaml =
            "window_secs: 7200\nthreshold_mb_per_sec: 10\nmax_users: 1000\nexit_factor: 0.5\n";
        cfg.per_user_bandwidth_rate =
            Some(serde_yaml::from_str(yaml).expect("PerUserBandwidthRateCfg parse"));
        let report = preflight(&cfg);
        let warn = report.checks.iter().any(|c| {
            matches!(c, Check::Warn(s) if s.contains("per_user_bandwidth_rate.window_secs") && s.contains("7200"))
        });
        assert!(warn, "window_secs=7200 must WARN: {report}");
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Iter-86: per_user_bandwidth_rate.max_users = 0 → FAIL.
    #[test]
    fn iter86_bw_max_users_zero_fails() {
        let dir = tmpdir();
        let mut cfg = minimal_cfg(&dir);
        let yaml = "window_secs: 30\nthreshold_mb_per_sec: 10\nmax_users: 0\nexit_factor: 0.5\n";
        cfg.per_user_bandwidth_rate =
            Some(serde_yaml::from_str(yaml).expect("PerUserBandwidthRateCfg parse"));
        let report = preflight(&cfg);
        assert!(report.has_failures(), "max_users=0 MUST FAIL: {report}");
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Iter-86: exit_factor out-of-range (1.5) → FAIL.
    #[test]
    fn iter86_bw_exit_factor_out_of_range_fails() {
        let dir = tmpdir();
        let mut cfg = minimal_cfg(&dir);
        let yaml = "window_secs: 30\nthreshold_mb_per_sec: 10\nmax_users: 1000\nexit_factor: 1.5\n";
        cfg.per_user_bandwidth_rate =
            Some(serde_yaml::from_str(yaml).expect("PerUserBandwidthRateCfg parse"));
        let report = preflight(&cfg);
        assert!(report.has_failures(), "exit_factor=1.5 MUST FAIL: {report}");
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Iter-86: exit_factor near 1.0 → WARN (flap).
    #[test]
    fn iter86_bw_exit_factor_near_one_warns() {
        let dir = tmpdir();
        let mut cfg = minimal_cfg(&dir);
        let yaml =
            "window_secs: 30\nthreshold_mb_per_sec: 10\nmax_users: 1000\nexit_factor: 0.995\n";
        cfg.per_user_bandwidth_rate =
            Some(serde_yaml::from_str(yaml).expect("PerUserBandwidthRateCfg parse"));
        let report = preflight(&cfg);
        let warn = report.checks.iter().any(
            |c| matches!(c, Check::Warn(s) if s.contains("exit_factor") && s.contains("flap")),
        );
        assert!(warn, "exit_factor=0.995 must WARN: {report}");
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Iter-86: per_user_conn_limit.max_per_user = 0 → WARN
    /// (legit observability-only).
    #[test]
    fn iter86_conn_limit_zero_warns() {
        let dir = tmpdir();
        let mut cfg = minimal_cfg(&dir);
        cfg.per_user_conn_limit = Some(crate::config::PerUserConnLimitCfg { max_per_user: 0 });
        let report = preflight(&cfg);
        let warn = report.checks.iter().any(|c| {
            matches!(c, Check::Warn(s) if s.contains("per_user_conn_limit.max_per_user") && s.contains("observability-only"))
        });
        assert!(warn, "max_per_user=0 must WARN: {report}");
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Iter-85: user_quotas.period_secs = 0 → FAIL.
    #[test]
    fn iter85_user_quotas_zero_period_fails() {
        let dir = tmpdir();
        let mut cfg = minimal_cfg(&dir);
        let yaml = "period_secs: 0\nmax_entries: 100\ndefault_period_bytes: 0\n";
        cfg.user_quotas = Some(serde_yaml::from_str(yaml).expect("UserQuotasCfg parse"));
        let report = preflight(&cfg);
        assert!(report.has_failures(), "period_secs=0 MUST FAIL: {report}");
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Iter-85: user_quotas.max_entries = 0 → FAIL.
    #[test]
    fn iter85_user_quotas_zero_max_entries_fails() {
        let dir = tmpdir();
        let mut cfg = minimal_cfg(&dir);
        let yaml = "period_secs: 86400\nmax_entries: 0\ndefault_period_bytes: 0\n";
        cfg.user_quotas = Some(serde_yaml::from_str(yaml).expect("UserQuotasCfg parse"));
        let report = preflight(&cfg);
        assert!(report.has_failures(), "max_entries=0 MUST FAIL: {report}");
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Iter-85: duplicate user_id in overrides → FAIL.
    #[test]
    fn iter85_user_quotas_duplicate_override_fails() {
        let dir = tmpdir();
        let mut cfg = minimal_cfg(&dir);
        let yaml = "period_secs: 86400\nmax_entries: 100\ndefault_period_bytes: 0\n\
            overrides:\n  \
                - {user_id: \"alice\", period_bytes: 100}\n  \
                - {user_id: \"alice\", period_bytes: 200}\n";
        cfg.user_quotas = Some(serde_yaml::from_str(yaml).expect("UserQuotasCfg parse"));
        let report = preflight(&cfg);
        assert!(
            report.has_failures(),
            "duplicate override user_id MUST FAIL: {report}"
        );
        let fail = report.checks.iter().any(|c| {
            matches!(c, Check::Fail(s) if s.contains("user_quotas.overrides") && s.contains("duplicate") && s.contains("alice"))
        });
        assert!(fail, "FAIL must name duplicate + offender: {report}");
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Iter-85: override user_id not in client_allowlist → WARN.
    #[test]
    fn iter85_user_quotas_orphan_override_warns() {
        let dir = tmpdir();
        let pk = dir.join("alice.pk");
        std::fs::write(&pk, b"some-non-zero-content").unwrap();
        let mut cfg = minimal_cfg(&dir);
        cfg.client_allowlist = vec![ClientCfg {
            user_id: "alice".to_string(),
            ed25519_pk: pk,
        }];
        let yaml = "period_secs: 86400\nmax_entries: 100\ndefault_period_bytes: 0\n\
            overrides:\n  \
                - {user_id: \"alice\", period_bytes: 100}\n  \
                - {user_id: \"orphan\", period_bytes: 200}\n";
        cfg.user_quotas = Some(serde_yaml::from_str(yaml).expect("UserQuotasCfg parse"));
        let report = preflight(&cfg);
        let warn = report.checks.iter().any(|c| {
            matches!(c, Check::Warn(s) if s.contains("user_quotas.overrides") && s.contains("orphan"))
        });
        assert!(warn, "orphan override must WARN: {report}");
        // Not a FAIL: overrides referencing absent users is just dead code.
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Iter-85: user_quarantine.ttl_secs = 0 → WARN (legit
    /// observability-only mode, but worth surfacing).
    #[test]
    fn iter85_user_quarantine_zero_ttl_warns() {
        let dir = tmpdir();
        let mut cfg = minimal_cfg(&dir);
        let yaml = "ttl_secs: 0\nmax_entries: 100\n";
        cfg.user_quarantine = Some(serde_yaml::from_str(yaml).expect("UserQuarantineCfg parse"));
        let report = preflight(&cfg);
        let warn = report.checks.iter().any(|c| {
            matches!(c, Check::Warn(s) if s.contains("user_quarantine.ttl_secs") && s.contains("observability-only"))
        });
        assert!(warn, "ttl_secs=0 must WARN: {report}");
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Iter-85: user_quarantine.max_entries = 0 → FAIL.
    #[test]
    fn iter85_user_quarantine_zero_max_entries_fails() {
        let dir = tmpdir();
        let mut cfg = minimal_cfg(&dir);
        let yaml = "ttl_secs: 600\nmax_entries: 0\n";
        cfg.user_quarantine = Some(serde_yaml::from_str(yaml).expect("UserQuarantineCfg parse"));
        let report = preflight(&cfg);
        assert!(
            report.has_failures(),
            "user_quarantine.max_entries=0 MUST FAIL: {report}"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Iter-84: handshake_deadline_secs = 0 → FAIL.
    #[test]
    fn iter84_handshake_deadline_zero_fails() {
        let dir = tmpdir();
        let mut cfg = minimal_cfg(&dir);
        cfg.handshake_deadline_secs = Some(0);
        let report = preflight(&cfg);
        assert!(
            report.has_failures(),
            "handshake_deadline=0 MUST FAIL: {report}"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Iter-84: handshake_deadline_secs = 1 → WARN (tight).
    #[test]
    fn iter84_handshake_deadline_tight_warns() {
        let dir = tmpdir();
        let mut cfg = minimal_cfg(&dir);
        cfg.handshake_deadline_secs = Some(1);
        let report = preflight(&cfg);
        let warn = report.checks.iter().any(|c| {
            matches!(c, Check::Warn(s) if s.contains("handshake_deadline_secs") && s.contains("tight"))
        });
        assert!(warn, "handshake_deadline=1 must WARN: {report}");
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Iter-84: handshake_deadline_secs > 300 → WARN (slow-
    /// loris window too long).
    #[test]
    fn iter84_handshake_deadline_excessive_warns() {
        let dir = tmpdir();
        let mut cfg = minimal_cfg(&dir);
        cfg.handshake_deadline_secs = Some(600);
        let report = preflight(&cfg);
        let warn = report.checks.iter().any(|c| {
            matches!(c, Check::Warn(s) if s.contains("handshake_deadline_secs") && s.contains("excessive"))
        });
        assert!(warn, "handshake_deadline=600 must WARN: {report}");
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Iter-84: max_connections = 0 → FAIL.
    #[test]
    fn iter84_max_connections_zero_fails() {
        let dir = tmpdir();
        let mut cfg = minimal_cfg(&dir);
        cfg.max_connections = Some(0);
        let report = preflight(&cfg);
        assert!(
            report.has_failures(),
            "max_connections=0 MUST FAIL: {report}"
        );
        let fail = report.checks.iter().any(|c| {
            matches!(c, Check::Fail(s) if s.contains("max_connections") && s.contains("immediately drops"))
        });
        assert!(fail, "FAIL must explain: {report}");
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Iter-84: max_connections > 65535 → WARN.
    #[test]
    fn iter84_max_connections_absurd_warns() {
        let dir = tmpdir();
        let mut cfg = minimal_cfg(&dir);
        cfg.max_connections = Some(1_000_000);
        let report = preflight(&cfg);
        let warn = report.checks.iter().any(|c| {
            matches!(c, Check::Warn(s) if s.contains("max_connections") && s.contains("1000000"))
        });
        assert!(warn, "absurd max_connections must WARN: {report}");
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Iter-84: tcp_keepalive_secs = 0 → WARN.
    #[test]
    fn iter84_tcp_keepalive_zero_warns() {
        let dir = tmpdir();
        let mut cfg = minimal_cfg(&dir);
        cfg.tcp_keepalive_secs = Some(0);
        let report = preflight(&cfg);
        let warn = report.checks.iter().any(|c| {
            matches!(c, Check::Warn(s) if s.contains("tcp_keepalive_secs") && s.contains("NAT"))
        });
        assert!(warn, "tcp_keepalive=0 must WARN: {report}");
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Iter-75: outbound_filter.disabled = true → FAIL.
    /// Operator must intentionally opt in to SSRF risk.
    #[test]
    fn iter75_outbound_filter_disabled_fails() {
        let dir = tmpdir();
        let mut cfg = minimal_cfg(&dir);
        cfg.outbound_filter = Some(crate::config::OutboundFilterCfg {
            disabled: true,
            ..Default::default()
        });
        let report = preflight(&cfg);
        assert!(
            report.has_failures(),
            "outbound_filter.disabled MUST FAIL: {report}"
        );
        let fail = report.checks.iter().any(|c| match c {
            Check::Fail(s) => s.contains("outbound_filter.disabled") && s.contains("SSRF"),
            _ => false,
        });
        assert!(
            fail,
            "FAIL message must call out SSRF + IAM creds: {report}"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Iter-75: replace_default_blocklist = true → FAIL with
    /// recommendation to use extra_blocked_cidrs instead.
    #[test]
    fn iter75_outbound_filter_replace_blocklist_fails() {
        let dir = tmpdir();
        let mut cfg = minimal_cfg(&dir);
        cfg.outbound_filter = Some(crate::config::OutboundFilterCfg {
            replace_default_blocklist: true,
            ..Default::default()
        });
        let report = preflight(&cfg);
        assert!(
            report.has_failures(),
            "replace_default_blocklist MUST FAIL: {report}"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Iter-75: bad CIDR in extra_blocked_cidrs → FAIL.
    #[test]
    fn iter75_outbound_filter_bad_cidr_fails() {
        let dir = tmpdir();
        let mut cfg = minimal_cfg(&dir);
        cfg.outbound_filter = Some(crate::config::OutboundFilterCfg {
            extra_blocked_cidrs: vec![
                "10.0.0.0/8".to_string(),         // valid
                "this is not a cidr".to_string(), // bad
            ],
            ..Default::default()
        });
        let report = preflight(&cfg);
        assert!(report.has_failures(), "bad CIDR MUST FAIL: {report}");
        let fail = report.checks.iter().any(|c| match c {
            Check::Fail(s) => {
                s.contains("outbound_filter.extra_blocked_cidrs")
                    && s.contains("this is not a cidr")
            }
            _ => false,
        });
        assert!(fail, "FAIL must name the bad entry: {report}");
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Iter-75: legitimate outbound_filter config (just extra
    /// ports / extra blocks) → no FAIL.
    #[test]
    fn iter75_outbound_filter_safe_config_passes() {
        let dir = tmpdir();
        let mut cfg = minimal_cfg(&dir);
        cfg.outbound_filter = Some(crate::config::OutboundFilterCfg {
            extra_ports: vec![853, 993], // DoT, IMAPS
            extra_blocked_cidrs: vec!["203.0.113.0/24".to_string()],
            ..Default::default()
        });
        let report = preflight(&cfg);
        let any_ssrf_fail = report.checks.iter().any(|c| match c {
            Check::Fail(s) => s.contains("outbound_filter"),
            _ => false,
        });
        assert!(
            !any_ssrf_fail,
            "safe outbound_filter config must NOT trigger iter-75 FAIL: {report}"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Iter-66: max_cover_forwards explicitly = 0 → FAIL.
    /// "0" disables the cover-forward concurrency cap (unbounded);
    /// almost never what the operator meant.
    #[test]
    fn iter66_max_cover_forwards_zero_fails() {
        let dir = tmpdir();
        let mut cfg = minimal_cfg(&dir);
        cfg.max_cover_forwards = Some(0);
        let report = preflight(&cfg);
        assert!(
            report.has_failures(),
            "max_cover_forwards=0 MUST FAIL: {report}"
        );
        let fail = report.checks.iter().any(|c| match c {
            Check::Fail(s) => s.contains("max_cover_forwards") && s.contains("disables"),
            _ => false,
        });
        assert!(fail, "FAIL must explain why 0 is bad: {report}");
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Iter-66: explicit max_cover_forwards > 0 → PASS row.
    #[test]
    fn iter66_max_cover_forwards_positive_passes() {
        let dir = tmpdir();
        let mut cfg = minimal_cfg(&dir);
        cfg.max_cover_forwards = Some(4096);
        let report = preflight(&cfg);
        let pass = report.checks.iter().any(|c| match c {
            Check::Pass(s) => s.contains("max_cover_forwards = 4096"),
            _ => false,
        });
        assert!(pass, "iter-66 PASS row missing: {report}");
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Iter-66: max_connections set → no WARN (runtime derives
    /// 4× from it). Validate stays quiet — operator already
    /// chose the cap mechanism.
    #[test]
    fn iter66_max_connections_set_silences_cover_warn() {
        let dir = tmpdir();
        let mut cfg = minimal_cfg(&dir);
        cfg.max_connections = Some(1024);
        let report = preflight(&cfg);
        let warn = report.checks.iter().any(|c| match c {
            Check::Warn(s) => s.contains("max_cover_forwards") && s.contains("unbounded"),
            _ => false,
        });
        assert!(
            !warn,
            "max_connections set must suppress the unbounded WARN: {report}"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Iter-66: both unset → WARN (unbounded cover-forward).
    /// minimal_cfg already exercises this in
    /// minimal_config_passes_with_warnings; this dedicated test
    /// pins the specific WARN message format.
    #[test]
    fn iter66_both_unset_warns_about_unbounded_cover_forward() {
        let dir = tmpdir();
        let cfg = minimal_cfg(&dir);
        let report = preflight(&cfg);
        let warn = report.checks.iter().any(|c| match c {
            Check::Warn(s) => {
                s.contains("max_cover_forwards")
                    && s.contains("max_connections")
                    && s.contains("unbounded")
            }
            _ => false,
        });
        assert!(warn, "iter-66 unbounded-cover WARN missing: {report}");
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Iter-65: short token → WARN but not FAIL. The runtime
    /// still accepts it; we're nudging the operator toward a
    /// strong default.
    #[test]
    fn iter65_short_metrics_token_warns_not_fails() {
        let dir = tmpdir();
        let token_path = dir.join("metrics.token");
        write(&token_path, b"short-token\n");
        let mut cfg = minimal_cfg(&dir);
        cfg.metrics_listen = Some("127.0.0.1:9090".to_string());
        cfg.metrics_token_file = Some(token_path);
        let report = preflight(&cfg);
        assert!(
            !report.has_failures(),
            "short token must WARN not FAIL: {report}"
        );
        let warn = report.checks.iter().any(|c| match c {
            Check::Warn(s) => s.contains("metrics_token_file") && s.contains("brute-forceable"),
            _ => false,
        });
        assert!(
            warn,
            "short token must produce brute-forceable WARN: {report}"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Iter-65: trivial-value token → FAIL. "changeme" / "token"
    /// / "admin" etc. are the first values any scanner tries.
    #[test]
    fn iter65_trivial_metrics_token_fails() {
        let dir = tmpdir();
        let token_path = dir.join("metrics.token");
        write(&token_path, b"changeme\n");
        let mut cfg = minimal_cfg(&dir);
        cfg.metrics_listen = Some("127.0.0.1:9090".to_string());
        cfg.metrics_token_file = Some(token_path);
        let report = preflight(&cfg);
        assert!(report.has_failures(), "trivial token MUST FAIL: {report}");
        let fail = report.checks.iter().any(|c| match c {
            Check::Fail(s) => s.contains("trivial") && s.contains("changeme"),
            _ => false,
        });
        assert!(
            fail,
            "FAIL must name the trivial value + 'trivial': {report}"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Iter-65: trivial-value detection is case-insensitive.
    /// `CHANGEME`, `ChangeMe`, `Changeme` are all bad.
    #[test]
    fn iter65_trivial_metrics_token_case_insensitive() {
        for variant in ["CHANGEME", "ChangeMe", "Token", "ADMIN"] {
            let dir = tmpdir();
            let token_path = dir.join("metrics.token");
            std::fs::write(&token_path, format!("{variant}\n")).unwrap();
            let mut cfg = minimal_cfg(&dir);
            cfg.metrics_listen = Some("127.0.0.1:9090".to_string());
            cfg.metrics_token_file = Some(token_path);
            let report = preflight(&cfg);
            assert!(
                report.has_failures(),
                "case-variant {variant:?} MUST FAIL: {report}"
            );
            let _ = std::fs::remove_dir_all(&dir);
        }
    }

    #[test]
    fn bad_metrics_listen_addr_fails() {
        let dir = tmpdir();
        let mut cfg = minimal_cfg(&dir);
        cfg.metrics_listen = Some("garbage:port".to_string());
        let report = preflight(&cfg);
        assert!(report.has_failures(), "expected fail: {report}");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn nonloopback_metrics_without_token_warns_but_passes() {
        let dir = tmpdir();
        let mut cfg = minimal_cfg(&dir);
        // Iter-73: use a non-loopback NON-wildcard address.
        // 0.0.0.0:9090 now escalates to FAIL (open-prep
        // inventory exposure on cloud VPS); a LAN-interface
        // bind stays WARN (operator may have a tunnel-
        // interface monitoring setup).
        cfg.metrics_listen = Some("192.168.1.100:9090".to_string());
        // metrics_token_file unset
        let report = preflight(&cfg);
        assert!(
            !report.has_failures(),
            "non-loopback w/o token must warn, not fail: {report}"
        );
        assert!(
            report
                .checks
                .iter()
                .any(|c| matches!(c, Check::Warn(m) if m.contains("non-loopback"))),
            "expected a non-loopback warning: {report}"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Iter-73: wildcard metrics_listen without a token → FAIL.
    /// This is the cloud-VPS open-prep-inventory trap.
    #[test]
    fn iter73_wildcard_metrics_listen_without_token_fails() {
        let dir = tmpdir();
        let mut cfg = minimal_cfg(&dir);
        cfg.metrics_listen = Some("0.0.0.0:9090".to_string());
        // metrics_token_file unset
        let report = preflight(&cfg);
        assert!(
            report.has_failures(),
            "wildcard metrics_listen w/o token MUST FAIL: {report}"
        );
        let fail = report.checks.iter().any(|c| match c {
            Check::Fail(s) => s.contains("metrics_listen") && s.contains("wildcard"),
            _ => false,
        });
        assert!(
            fail,
            "FAIL must call out 'wildcard' + provide a recovery hint: {report}"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Iter-73: wildcard metrics_listen WITH a token → no FAIL
    /// (bearer token gates access; the iter-65 token-strength
    /// check covers token quality).
    #[test]
    fn iter73_wildcard_metrics_listen_with_token_no_fail() {
        let dir = tmpdir();
        let token_path = dir.join("metrics.token");
        write(&token_path, b"k7nP2vQrL8xJ3hM5wY4zA6bE9cF1uD0i\n");
        let mut cfg = minimal_cfg(&dir);
        cfg.metrics_listen = Some("0.0.0.0:9090".to_string());
        cfg.metrics_token_file = Some(token_path);
        let report = preflight(&cfg);
        let wildcard_fail = report.checks.iter().any(|c| match c {
            Check::Fail(s) => s.contains("metrics_listen") && s.contains("wildcard"),
            _ => false,
        });
        assert!(
            !wildcard_fail,
            "wildcard + token must NOT FAIL the iter-73 check: {report}"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Iter-52: secret key files with world-readable mode get a
    /// WARN (not FAIL — same severity philosophy as
    /// `preflight check-host` gates this harder; validate is the
    /// early-warning surface).
    #[cfg(unix)]
    #[test]
    fn iter52_world_readable_secret_key_warns() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tmpdir();
        let cfg = minimal_cfg(&dir);
        // Plant a world-readable secret key (mode 0644).
        std::fs::set_permissions(&cfg.keys.mlkem_sk, std::fs::Permissions::from_mode(0o644))
            .unwrap();
        let report = preflight(&cfg);
        eprintln!("world-readable-sk report:\n{report}");
        // Cleanup so tmpdir delete works.
        let _ =
            std::fs::set_permissions(&cfg.keys.mlkem_sk, std::fs::Permissions::from_mode(0o600));
        // Skip on root which ignores write/read bits.
        let is_root = std::env::var("USER").as_deref() == Ok("root")
            || std::env::var("LOGNAME").as_deref() == Ok("root");
        if is_root {
            let _ = std::fs::remove_dir_all(&dir);
            return;
        }
        let warn = report.checks.iter().any(|c| match c {
            Check::Warn(s) => {
                s.contains("mlkem_sk") && (s.contains("0o644") || s.contains("group or world"))
            }
            _ => false,
        });
        assert!(
            warn,
            "world-readable SECRET key must WARN at validate: {report}"
        );
        // Must NOT escalate to FAIL — validate is early-warning,
        // `preflight check-host` is the hard gate.
        assert!(
            !report.has_failures(),
            "iter-52 mode warn must NOT escalate to FAIL: {report}"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Iter-52: 0600 mode key passes cleanly (no warn).
    #[cfg(unix)]
    #[test]
    fn iter52_owner_only_secret_key_passes_silently() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tmpdir();
        let cfg = minimal_cfg(&dir);
        std::fs::set_permissions(&cfg.keys.mlkem_sk, std::fs::Permissions::from_mode(0o600))
            .unwrap();
        let report = preflight(&cfg);
        let any_mode_warn = report.checks.iter().any(|c| match c {
            Check::Warn(s) => s.contains("mlkem_sk") && s.contains("group or world"),
            _ => false,
        });
        assert!(
            !any_mode_warn,
            "0600 mode key must NOT trigger the iter-52 warn: {report}"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Iter-52: public-key file (mlkem_pk) is NOT subject to the
    /// mode check — public artifacts are intentionally readable.
    #[cfg(unix)]
    #[test]
    fn iter52_public_key_world_readable_no_warn() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tmpdir();
        let cfg = minimal_cfg(&dir);
        std::fs::set_permissions(&cfg.keys.mlkem_pk, std::fs::Permissions::from_mode(0o644))
            .unwrap();
        let report = preflight(&cfg);
        let any_pk_warn = report.checks.iter().any(|c| match c {
            Check::Warn(s) => s.contains("mlkem_pk") && s.contains("group or world"),
            _ => false,
        });
        assert!(
            !any_pk_warn,
            "PUBLIC key file mode is intentionally permissive — no warn: {report}"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn access_log_in_nonexistent_dir_fails() {
        let dir = tmpdir();
        let mut cfg = minimal_cfg(&dir);
        cfg.access_log = Some(PathBuf::from("/does/not/exist/access.log"));
        let report = preflight(&cfg);
        assert!(report.has_failures(), "expected fail: {report}");
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Iter-50: access_log parent dir exists AND is writable.
    /// Probe a tmp file under the parent; the PASS message must
    /// say "writable" so the operator knows the new check ran.
    #[test]
    fn iter50_access_log_writable_dir_passes_with_writable_label() {
        let dir = tmpdir();
        let log_path = dir.join("access.log");
        let mut cfg = minimal_cfg(&dir);
        cfg.access_log = Some(log_path);
        let report = preflight(&cfg);
        assert!(
            !report.has_failures(),
            "writable parent must PASS: {report}"
        );
        let writable_pass = report.checks.iter().any(
            |c| matches!(c, Check::Pass(m) if m.contains("access_log") && m.contains("writable")),
        );
        assert!(
            writable_pass,
            "PASS message must call out 'writable' so operator knows the iter-50 check ran: {report}"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Iter-54: knock_psk_file invalid → FAIL with actionable
    /// recovery hint. Pre-iter-54 the operator could ship a typo'd
    /// PSK file (e.g. truncated base64) and validate said green;
    /// startup was fatal with the same message but after deploy.
    #[test]
    fn iter54_knock_psk_file_invalid_fails_validate() {
        let dir = tmpdir();
        let psk_path = dir.join("knock.psk");
        // Plant a garbage PSK file (decoded length != 32 → fails).
        std::fs::write(&psk_path, b"#comment\nnot-valid-base64-and-not-32-bytes\n").unwrap();
        let mut cfg = minimal_cfg(&dir);
        cfg.knock_psk_file = Some(psk_path);
        let report = preflight(&cfg);
        assert!(
            report.has_failures(),
            "invalid knock_psk_file MUST FAIL validate: {report}"
        );
        let knock_fail = report.checks.iter().any(|c| match c {
            Check::Fail(s) => s.contains("knock_psk_file") && s.contains("knock-keygen"),
            _ => false,
        });
        assert!(
            knock_fail,
            "FAIL message must call out knock_psk_file + recovery hint: {report}"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Iter-54: valid knock_psk_file → PASS.
    #[test]
    fn iter54_knock_psk_file_valid_passes_validate() {
        use base64::Engine;
        let dir = tmpdir();
        let psk_path = dir.join("knock.psk");
        let mut psk = [0u8; 32];
        // Non-zero bytes (iter-48 all-zero check would otherwise fire if
        // the value is ever inspected as a key, but knock_psk_file isn't
        // — it's just a parse check).
        for (i, b) in psk.iter_mut().enumerate() {
            *b = (i as u8) ^ 0x5a;
        }
        let armored = base64::engine::general_purpose::STANDARD.encode(psk);
        std::fs::write(&psk_path, format!("# proteus knock PSK\n{armored}\n")).unwrap();
        let mut cfg = minimal_cfg(&dir);
        cfg.knock_psk_file = Some(psk_path);
        let report = preflight(&cfg);
        let pass = report.checks.iter().any(|c| {
            matches!(c, Check::Pass(m) if m.contains("knock_psk_file") && m.contains("loads cleanly"))
        });
        assert!(pass, "valid knock_psk_file must PASS: {report}");
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Iter-53: restart_state_file gets the same write-probe.
    /// Pre-iter-53 the operator could ship a config where
    /// `restart_state_file: /var/lib/proteus/restart.json` but
    /// `/var/lib/proteus` was 0755 root:root — the shutdown
    /// writer would fail silently, breaking unclean-restart
    /// tracking, but validate said green.
    #[test]
    fn iter53_restart_state_file_writable_parent_passes() {
        let dir = tmpdir();
        let mut cfg = minimal_cfg(&dir);
        cfg.restart_state_file = Some(dir.join("restart.json"));
        let report = preflight(&cfg);
        assert!(
            !report.has_failures(),
            "writable parent must PASS: {report}"
        );
        let writable_pass = report.checks.iter().any(|c| {
            matches!(c, Check::Pass(m) if m.contains("restart_state_file") && m.contains("writable"))
        });
        assert!(
            writable_pass,
            "iter-53 must emit PASS row for restart_state_file: {report}"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn iter53_restart_state_file_nonexistent_parent_fails() {
        let dir = tmpdir();
        let mut cfg = minimal_cfg(&dir);
        cfg.restart_state_file = Some(PathBuf::from("/does/not/exist/restart.json"));
        let report = preflight(&cfg);
        assert!(
            report.has_failures(),
            "nonexistent parent must FAIL: {report}"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Iter-53: user_quotas.persistence_path → same probe.
    /// We build via YAML round-trip to avoid coupling to the
    /// struct's exact field layout (defaults handle the rest).
    #[test]
    fn iter53_user_quotas_persistence_path_writable_passes() {
        let dir = tmpdir();
        let mut cfg = minimal_cfg(&dir);
        let yaml = format!(
            "period_secs: 86400\nmax_entries: 1024\npersistence_path: {}\n",
            dir.join("quotas.jsonl").display()
        );
        cfg.user_quotas = Some(serde_yaml::from_str(&yaml).expect("UserQuotasCfg parse"));
        let report = preflight(&cfg);
        let pass = report.checks.iter().any(|c| {
            matches!(c, Check::Pass(m) if m.contains("user_quotas.persistence_path") && m.contains("writable"))
        });
        assert!(pass, "iter-53 user_quotas check missing: {report}");
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Iter-53: user_quarantine.persistence_path → same probe.
    #[test]
    fn iter53_user_quarantine_persistence_path_writable_passes() {
        let dir = tmpdir();
        let mut cfg = minimal_cfg(&dir);
        let yaml = format!(
            "ttl_secs: 600\nmax_entries: 1024\npersistence_path: {}\n",
            dir.join("quarantine.jsonl").display()
        );
        cfg.user_quarantine = Some(serde_yaml::from_str(&yaml).expect("UserQuarantineCfg parse"));
        let report = preflight(&cfg);
        let pass = report.checks.iter().any(|c| {
            matches!(c, Check::Pass(m) if m.contains("user_quarantine.persistence_path") && m.contains("writable"))
        });
        assert!(pass, "iter-53 user_quarantine check missing: {report}");
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Iter-50: access_log parent dir is read-only → FAIL with
    /// an actionable chown hint. Unix-only (chmod is meaningless
    /// on Windows; the bug class is Unix-deploy-specific).
    #[cfg(unix)]
    #[test]
    fn iter50_access_log_readonly_dir_fails_with_chown_hint() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tmpdir();
        let log_dir = dir.join("ro");
        std::fs::create_dir(&log_dir).unwrap();
        // Mode 0500 = readable + executable for owner, no write.
        // Even if we ARE the owner, write() will fail.
        std::fs::set_permissions(&log_dir, std::fs::Permissions::from_mode(0o500)).unwrap();
        let mut cfg = minimal_cfg(&dir);
        cfg.access_log = Some(log_dir.join("access.log"));
        let report = preflight(&cfg);
        // The check should FAIL.
        let writable_fail = report.checks.iter().any(|c| match c {
            Check::Fail(m) => m.contains("access_log") && m.contains("NOT writable"),
            _ => false,
        });
        // Cleanup: restore mode so the tmpdir can be deleted.
        let _ = std::fs::set_permissions(&log_dir, std::fs::Permissions::from_mode(0o755));
        let _ = std::fs::remove_dir_all(&dir);
        // Skip the assertion entirely when running as root —
        // root ignores write-bit and the test would be
        // meaningless. We detect root by checking $USER (cheap,
        // no unsafe block needed; the validate crate forbids
        // unsafe at the lib level).
        let is_root = std::env::var("USER").as_deref() == Ok("root")
            || std::env::var("LOGNAME").as_deref() == Ok("root");
        if !is_root {
            assert!(
                writable_fail,
                "non-writable access_log parent must FAIL with the iter-50 write-probe diagnostic: {report}"
            );
        }
    }

    #[test]
    fn pow_over_cap_warns() {
        let dir = tmpdir();
        let mut cfg = minimal_cfg(&dir);
        cfg.pow_difficulty = Some(50);
        let report = preflight(&cfg);
        assert!(
            report
                .checks
                .iter()
                .any(|c| matches!(c, Check::Warn(m) if m.contains("pow_difficulty"))),
            "expected pow_difficulty warning: {report}"
        );
        assert!(!report.has_failures(), "should warn, not fail: {report}");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn negative_rate_limit_fails() {
        let dir = tmpdir();
        let mut cfg = minimal_cfg(&dir);
        cfg.rate_limit = Some(RateLimitCfg {
            burst: -1.0,
            refill_per_sec: 1.0,
        });
        let report = preflight(&cfg);
        assert!(report.has_failures(), "expected fail: {report}");
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Iter-57: duplicate user_id in allowlist → FAIL. The
    /// runtime returns the FIRST match; subsequent entries with
    /// the same user_id are dead code. If the operator meant
    /// the second entry as a key rotation, the matching client
    /// will fail signature verification against the OLD key and
    /// be silently rejected. Surface as a FAIL with both indices
    /// for fast triage.
    #[test]
    fn iter57_duplicate_user_id_in_allowlist_fails() {
        let dir = tmpdir();
        let pk1 = dir.join("alice1.pk");
        let pk2 = dir.join("alice2.pk");
        std::fs::write(&pk1, b"old-pubkey-bytes").unwrap();
        std::fs::write(&pk2, b"new-pubkey-bytes").unwrap();
        let mut cfg = minimal_cfg(&dir);
        cfg.client_allowlist = vec![
            ClientCfg {
                user_id: "alice".to_string(),
                ed25519_pk: pk1,
            },
            ClientCfg {
                user_id: "alice".to_string(), // same user_id, different pk
                ed25519_pk: pk2,
            },
        ];
        let report = preflight(&cfg);
        assert!(
            report.has_failures(),
            "duplicate allowlist user_id MUST FAIL: {report}"
        );
        let dup_fail = report.checks.iter().any(|c| match c {
            Check::Fail(s) => {
                s.contains("duplicate user_id")
                    && s.contains("alice")
                    && s.contains("[0]")
                    && s.contains("[1]")
            }
            _ => false,
        });
        assert!(
            dup_fail,
            "FAIL must call out duplicate + both indices: {report}"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Iter-57: distinct user_ids → no false positive.
    #[test]
    fn iter57_distinct_user_ids_do_not_fail_dupe_check() {
        let dir = tmpdir();
        let pk1 = dir.join("alice.pk");
        let pk2 = dir.join("bob.pk");
        std::fs::write(&pk1, b"alice-pubkey").unwrap();
        std::fs::write(&pk2, b"bob-pubkey").unwrap();
        let mut cfg = minimal_cfg(&dir);
        cfg.client_allowlist = vec![
            ClientCfg {
                user_id: "alice".to_string(),
                ed25519_pk: pk1,
            },
            ClientCfg {
                user_id: "bob".to_string(),
                ed25519_pk: pk2,
            },
        ];
        let report = preflight(&cfg);
        let dup_fail = report.checks.iter().any(|c| match c {
            Check::Fail(s) => s.contains("duplicate user_id"),
            _ => false,
        });
        assert!(
            !dup_fail,
            "distinct user_ids must not trigger dup-check: {report}"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Iter-56: server-side symmetric check — allowlist user_id
    /// with trailing whitespace will never match a clean client
    /// `user_id:`. Bytes-don't-match silent-mismatch trap.
    #[test]
    fn iter56_server_allowlist_user_id_with_whitespace_fails() {
        let dir = tmpdir();
        let pk = dir.join("alice.pk");
        // Non-zero content so the iter-48/55 check doesn't trip.
        std::fs::write(&pk, b"some-non-zero-content").unwrap();
        let mut cfg = minimal_cfg(&dir);
        cfg.client_allowlist = vec![ClientCfg {
            user_id: "alice ".to_string(), // trailing space
            ed25519_pk: pk,
        }];
        let report = preflight(&cfg);
        assert!(
            report.has_failures(),
            "trailing-whitespace allowlist user_id MUST FAIL: {report}"
        );
        let ws_fail = report.checks.iter().any(|c| match c {
            Check::Fail(s) => s.contains("client_allowlist") && s.contains("whitespace"),
            _ => false,
        });
        assert!(ws_fail, "FAIL message must mention 'whitespace': {report}");
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Iter-55: all-zero allowlist pubkey → FAIL (catastrophic
    /// auth-passes-trivially case). Pre-iter-55 the check only
    /// applied to `keys.*` labels; the allowlist's
    /// `client_allowlist[<user>].ed25519_pk` was silently
    /// accepted.
    #[test]
    fn iter55_all_zero_allowlist_pubkey_fails() {
        let dir = tmpdir();
        let pk = dir.join("alice.pk");
        // Plant an all-zero 32-byte pubkey.
        std::fs::write(&pk, [0u8; 32]).unwrap();
        let mut cfg = minimal_cfg(&dir);
        cfg.client_allowlist = vec![ClientCfg {
            user_id: "alice".to_string(),
            ed25519_pk: pk,
        }];
        let report = preflight(&cfg);
        assert!(
            report.has_failures(),
            "all-zero allowlist pubkey MUST FAIL: {report}"
        );
        let zero_fail = report.checks.iter().any(|c| match c {
            Check::Fail(s) => {
                s.contains("client_allowlist[alice].ed25519_pk") && s.contains("ALL-ZERO")
            }
            _ => false,
        });
        assert!(
            zero_fail,
            "FAIL must call out the allowlist entry + ALL-ZERO: {report}"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn long_user_id_fails() {
        let dir = tmpdir();
        let pk = dir.join("client.pk");
        write(&pk, b"x");
        let mut cfg = minimal_cfg(&dir);
        cfg.client_allowlist = vec![ClientCfg {
            user_id: "this-is-way-too-long".to_string(),
            ed25519_pk: pk,
        }];
        let report = preflight(&cfg);
        assert!(report.has_failures(), "expected fail: {report}");
        let _ = std::fs::remove_dir_all(&dir);
    }

    // ----- coherence checks -----

    #[test]
    fn pow_aggressive_vs_short_deadline_warns() {
        let dir = tmpdir();
        let mut cfg = minimal_cfg(&dir);
        cfg.pow_difficulty = Some(22); // ~4s floor solve
        cfg.handshake_deadline_secs = Some(2);
        let report = preflight(&cfg);
        assert!(!report.has_failures(), "should warn, not fail: {report}");
        assert!(
            report
                .checks
                .iter()
                .any(|c| matches!(c, Check::Warn(m) if m.contains("solve time"))),
            "expected pow/deadline coherence warning: {report}"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn pow_coherent_with_default_deadline_passes() {
        let dir = tmpdir();
        let mut cfg = minimal_cfg(&dir);
        cfg.pow_difficulty = Some(16); // ~65 ms floor — fine for 15s default
        let report = preflight(&cfg);
        assert!(!report.has_failures(), "got: {report}");
        assert!(
            !report
                .checks
                .iter()
                .any(|c| matches!(c, Check::Warn(m) if m.contains("solve time"))),
            "should NOT warn at d=16: {report}"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn user_burst_exceeding_ip_burst_warns() {
        let dir = tmpdir();
        let mut cfg = minimal_cfg(&dir);
        cfg.rate_limit = Some(RateLimitCfg {
            burst: 5.0,
            refill_per_sec: 1.0,
        });
        cfg.user_rate_limit = Some(crate::config::UserRateLimitCfg {
            burst: 50.0,
            refill_per_sec: 1.0,
            max_users: 1024,
        });
        let report = preflight(&cfg);
        assert!(
            report.checks.iter().any(
                |c| matches!(c, Check::Warn(m) if m.contains("never reach their per-user quota"))
            ),
            "expected user-vs-ip-burst warning: {report}"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn drain_without_metrics_warns() {
        let dir = tmpdir();
        let mut cfg = minimal_cfg(&dir);
        cfg.drain_secs = Some(30);
        // metrics_listen unset
        let report = preflight(&cfg);
        assert!(
            report
                .checks
                .iter()
                .any(|c| matches!(c, Check::Warn(m) if m.contains("/readyz"))),
            "expected drain-without-metrics warning: {report}"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn drain_with_metrics_does_not_warn() {
        let dir = tmpdir();
        let mut cfg = minimal_cfg(&dir);
        cfg.drain_secs = Some(30);
        cfg.metrics_listen = Some("127.0.0.1:9090".to_string());
        let report = preflight(&cfg);
        assert!(
            !report
                .checks
                .iter()
                .any(|c| matches!(c, Check::Warn(m) if m.contains("/readyz"))),
            "should not warn when metrics_listen is set: {report}"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn idle_smaller_than_deadline_warns() {
        let dir = tmpdir();
        let mut cfg = minimal_cfg(&dir);
        cfg.session_idle_secs = Some(5);
        cfg.handshake_deadline_secs = Some(15);
        let report = preflight(&cfg);
        assert!(
            report
                .checks
                .iter()
                .any(|c| matches!(c, Check::Warn(m) if m.contains("less than handshake_deadline"))),
            "expected idle<deadline warning: {report}"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn max_conn_below_burst_warns() {
        let dir = tmpdir();
        let mut cfg = minimal_cfg(&dir);
        cfg.max_connections = Some(3);
        cfg.rate_limit = Some(RateLimitCfg {
            burst: 50.0,
            refill_per_sec: 5.0,
        });
        let report = preflight(&cfg);
        assert!(
            report
                .checks
                .iter()
                .any(|c| matches!(c, Check::Warn(m) if m.contains("can saturate the global concurrency cap"))),
            "expected max_conn<burst warning: {report}"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn firewall_allow_deny_overlap_warns() {
        let dir = tmpdir();
        let mut cfg = minimal_cfg(&dir);
        cfg.firewall = Some(FirewallCfg {
            allow: vec!["10.0.0.0/8".to_string(), "192.0.2.42/32".to_string()],
            deny: vec!["192.0.2.42/32".to_string()],
        });
        let report = preflight(&cfg);
        assert!(
            report
                .checks
                .iter()
                .any(|c| matches!(c, Check::Warn(m) if m.contains("both allow and deny"))),
            "expected allow/deny overlap warning: {report}"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn cover_loopback_with_wildcard_listen_warns() {
        let dir = tmpdir();
        let mut cfg = minimal_cfg(&dir);
        cfg.listen_alpha = "0.0.0.0:8443".to_string();
        cfg.cover_endpoint = Some("127.0.0.1:443".to_string());
        let report = preflight(&cfg);
        assert!(
            report
                .checks
                .iter()
                .any(|c| matches!(c, Check::Warn(m) if m.contains("loops back into ourselves"))),
            "expected loopback-cover warning: {report}"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn cover_same_host_as_listen_warns() {
        let dir = tmpdir();
        let mut cfg = minimal_cfg(&dir);
        cfg.listen_alpha = "203.0.113.7:8443".to_string();
        cfg.cover_endpoint = Some("203.0.113.7:443".to_string());
        let report = preflight(&cfg);
        assert!(
            report
                .checks
                .iter()
                .any(|c| matches!(c, Check::Warn(m) if m.contains("matches listen_alpha host"))),
            "expected same-host-cover warning: {report}"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn tiny_max_session_bytes_warns() {
        let dir = tmpdir();
        let mut cfg = minimal_cfg(&dir);
        cfg.max_session_bytes = Some(512); // < 1 MiB
        let report = preflight(&cfg);
        assert!(
            report
                .checks
                .iter()
                .any(|c| matches!(c, Check::Warn(m) if m.contains("below 1 MiB"))),
            "expected tiny-cap warning: {report}"
        );
        assert!(!report.has_failures(), "should warn, not fail");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn reasonable_max_session_bytes_does_not_warn() {
        let dir = tmpdir();
        let mut cfg = minimal_cfg(&dir);
        cfg.max_session_bytes = Some(50 * 1024 * 1024 * 1024); // 50 GiB
        let report = preflight(&cfg);
        assert!(
            !report
                .checks
                .iter()
                .any(|c| matches!(c, Check::Warn(m) if m.contains("below 1 MiB"))),
            "should not warn at 50 GiB: {report}"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn coherent_default_config_has_no_coherence_warnings() {
        // A "normal" prod config — sensible knobs that don't trip any
        // coherence rule.
        let dir = tmpdir();
        let mut cfg = minimal_cfg(&dir);
        cfg.pow_difficulty = Some(8);
        cfg.handshake_deadline_secs = Some(15);
        cfg.session_idle_secs = Some(600);
        cfg.max_connections = Some(4096);
        cfg.rate_limit = Some(RateLimitCfg {
            burst: 10.0,
            refill_per_sec: 5.0,
        });
        cfg.user_rate_limit = Some(crate::config::UserRateLimitCfg {
            burst: 5.0,
            refill_per_sec: 1.0,
            max_users: 1024,
        });
        cfg.metrics_listen = Some("127.0.0.1:9090".to_string());
        cfg.drain_secs = Some(30);
        cfg.cover_endpoint = Some("www.cloudflare.com:443".to_string());
        cfg.listen_alpha = "0.0.0.0:8443".to_string();

        let report = preflight(&cfg);
        // Filter to coherence-class warnings only (those introduced by
        // coherence_checks). The minimal_cfg may still emit warnings
        // from the per-field checks (e.g. tls missing).
        let coherence_warns: Vec<_> = report
            .checks
            .iter()
            .filter_map(|c| match c {
                Check::Warn(m)
                    if m.contains("solve time")
                        || m.contains("never reach their per-user quota")
                        || m.contains("/readyz")
                        || m.contains("less than handshake_deadline")
                        || m.contains("can saturate the global concurrency cap")
                        || m.contains("both allow and deny")
                        || m.contains("matches listen_alpha")
                        || m.contains("loops back into ourselves") =>
                {
                    Some(m.clone())
                }
                _ => None,
            })
            .collect();
        assert!(
            coherence_warns.is_empty(),
            "coherent config tripped a coherence rule: {coherence_warns:?}"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn counts_render_consistently() {
        let dir = tmpdir();
        let cfg = minimal_cfg(&dir);
        let report = preflight(&cfg);
        let (p, w, f) = report.counts();
        let rendered = report.to_string();
        assert!(rendered.contains(&format!("{p} passed")));
        assert!(rendered.contains(&format!("{w} warnings")));
        assert!(rendered.contains(&format!("{f} failed")));
        let _ = std::fs::remove_dir_all(&dir);
    }

    // ---- iter-141: cover endpoint port sanity ----

    /// `cover_endpoint` pointing at port 80 → FAIL. Plaintext HTTP
    /// can't be a cover for raw TLS ClientHello bytes; an active
    /// prober gets immediate confirmation that the proxy is fake.
    #[test]
    fn iter141_cover_endpoint_port_80_fails() {
        let dir = tmpdir();
        let mut cfg = minimal_cfg(&dir);
        cfg.cover_endpoint = Some("www.example.com:80".to_string());
        let report = preflight(&cfg);
        assert!(
            report.has_failures(),
            "iter-141: cover_endpoint:80 MUST FAIL: {report}"
        );
        let fail = report.checks.iter().any(|c| match c {
            Check::Fail(s) => s.contains("cover_endpoint") && s.contains("port 80"),
            _ => false,
        });
        assert!(
            fail,
            "iter-141: FAIL must name the field AND the port: {report}"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Iter-141: every common-mistake non-TLS port should FAIL.
    #[test]
    fn iter141_cover_endpoint_other_plaintext_ports_fail() {
        for victim_port in [21u16, 22, 23, 25, 80] {
            let dir = tmpdir();
            let mut cfg = minimal_cfg(&dir);
            cfg.cover_endpoint = Some(format!("www.example.com:{victim_port}"));
            let report = preflight(&cfg);
            assert!(
                report.has_failures(),
                "iter-141: cover_endpoint port {victim_port} MUST FAIL: {report}"
            );
            let _ = std::fs::remove_dir_all(&dir);
        }
    }

    /// Iter-141: canonical TLS ports (443, 8443, 9443) pass without
    /// triggering the iter-141 port-sanity FAIL.
    #[test]
    fn iter141_cover_endpoint_canonical_tls_ports_pass() {
        for port in [443u16, 8443, 9443] {
            let dir = tmpdir();
            let mut cfg = minimal_cfg(&dir);
            cfg.cover_endpoint = Some(format!("www.example.com:{port}"));
            let report = preflight(&cfg);
            let port_fail = report.checks.iter().any(|c| match c {
                Check::Fail(s) => {
                    s.contains("cover_endpoint")
                        && (s.contains("port 21")
                            || s.contains("port 22")
                            || s.contains("port 23")
                            || s.contains("port 25")
                            || s.contains("port 80"))
                }
                _ => false,
            });
            assert!(
                !port_fail,
                "iter-141: cover_endpoint:{port} MUST NOT trigger iter-141 port FAIL: {report}"
            );
            let _ = std::fs::remove_dir_all(&dir);
        }
    }

    /// Iter-141: non-canonical-but-not-blacklisted port produces WARN
    /// (the operator might run TLS on a custom port; we don't have
    /// the info to know for sure).
    #[test]
    fn iter141_cover_endpoint_unusual_port_warns() {
        let dir = tmpdir();
        let mut cfg = minimal_cfg(&dir);
        cfg.cover_endpoint = Some("www.example.com:7777".to_string());
        let report = preflight(&cfg);
        let warn = report.checks.iter().any(|c| match c {
            Check::Warn(s) => s.contains("cover_endpoint") && s.contains("port 7777"),
            _ => false,
        });
        assert!(
            warn,
            "iter-141: unusual cover_endpoint port MUST WARN: {report}"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    // ---- iter-142: duplicate ed25519_pk-bytes across user_ids ----

    /// Two distinct user_ids sharing the SAME 32-byte ed25519_pk
    /// content → FAIL. One client SK can authenticate as either
    /// user_id; per-user accounting / quotas / quarantine all
    /// silently mis-attribute traffic.
    #[test]
    fn iter142_duplicate_ed25519_pk_bytes_across_user_ids_fails() {
        let dir = tmpdir();
        let shared_pk_bytes: [u8; 32] =
            std::array::from_fn(|i| (i as u8).wrapping_mul(7).wrapping_add(1));
        let pk1 = dir.join("alice.pk");
        let pk2 = dir.join("bob.pk");
        std::fs::write(&pk1, shared_pk_bytes).unwrap();
        std::fs::write(&pk2, shared_pk_bytes).unwrap();
        let mut cfg = minimal_cfg(&dir);
        cfg.client_allowlist = vec![
            ClientCfg {
                user_id: "alice".to_string(),
                ed25519_pk: pk1,
            },
            ClientCfg {
                user_id: "bob".to_string(),
                ed25519_pk: pk2,
            },
        ];
        let report = preflight(&cfg);
        assert!(
            report.has_failures(),
            "iter-142: shared ed25519_pk MUST FAIL: {report}"
        );
        let dup_fail = report.checks.iter().any(|c| match c {
            Check::Fail(s) => {
                s.contains("duplicate ed25519_pk") && s.contains("alice") && s.contains("bob")
            }
            _ => false,
        });
        assert!(dup_fail, "iter-142: FAIL must list both user_ids: {report}");
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Iter-142: distinct ed25519_pk bytes → no false positive.
    #[test]
    fn iter142_distinct_ed25519_pk_bytes_do_not_fail() {
        let dir = tmpdir();
        let pk1_bytes: [u8; 32] =
            std::array::from_fn(|i| (i as u8).wrapping_mul(7).wrapping_add(1));
        let pk2_bytes: [u8; 32] =
            std::array::from_fn(|i| (i as u8).wrapping_mul(11).wrapping_add(3));
        let pk1 = dir.join("alice.pk");
        let pk2 = dir.join("bob.pk");
        std::fs::write(&pk1, pk1_bytes).unwrap();
        std::fs::write(&pk2, pk2_bytes).unwrap();
        let mut cfg = minimal_cfg(&dir);
        cfg.client_allowlist = vec![
            ClientCfg {
                user_id: "alice".to_string(),
                ed25519_pk: pk1,
            },
            ClientCfg {
                user_id: "bob".to_string(),
                ed25519_pk: pk2,
            },
        ];
        let report = preflight(&cfg);
        let dup_fail = report.checks.iter().any(|c| match c {
            Check::Fail(s) => s.contains("duplicate ed25519_pk"),
            _ => false,
        });
        assert!(
            !dup_fail,
            "iter-142: distinct pubkeys MUST NOT trigger FAIL: {report}"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Iter-142: three-way share → FAIL must name ALL THREE users.
    #[test]
    fn iter142_three_way_shared_pk_lists_all_users() {
        let dir = tmpdir();
        let shared_bytes: [u8; 32] = [0x42u8; 32];
        let pk1 = dir.join("a.pk");
        let pk2 = dir.join("b.pk");
        let pk3 = dir.join("c.pk");
        std::fs::write(&pk1, shared_bytes).unwrap();
        std::fs::write(&pk2, shared_bytes).unwrap();
        std::fs::write(&pk3, shared_bytes).unwrap();
        let mut cfg = minimal_cfg(&dir);
        cfg.client_allowlist = vec![
            ClientCfg {
                user_id: "alice".to_string(),
                ed25519_pk: pk1,
            },
            ClientCfg {
                user_id: "bob".to_string(),
                ed25519_pk: pk2,
            },
            ClientCfg {
                user_id: "carol".to_string(),
                ed25519_pk: pk3,
            },
        ];
        let report = preflight(&cfg);
        assert!(
            report.has_failures(),
            "iter-142 three-way share must FAIL: {report}"
        );
        let dup_fail = report.checks.iter().any(|c| match c {
            Check::Fail(s) => {
                s.contains("duplicate ed25519_pk")
                    && s.contains("alice")
                    && s.contains("bob")
                    && s.contains("carol")
            }
            _ => false,
        });
        assert!(
            dup_fail,
            "iter-142: three-way share must list all three: {report}"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    // ---- iter-143: ed25519_pk length gate in allowlist ----

    /// Iter-143: an allowlist entry whose pubkey file is shorter
    /// than 32 bytes (truncation, base64-partial, wrong file copied)
    /// MUST FAIL validate. Pre-iter-143 the file passed existence
    /// AND non-all-zero checks; the server then refused to start at
    /// runtime when `VerifyingKey::from_bytes` rejected the malformed
    /// key, leaving operators no actionable preflight signal.
    #[test]
    fn iter143_truncated_allowlist_pk_fails() {
        let dir = tmpdir();
        let pk = dir.join("alice.pk");
        std::fs::write(&pk, [0x42u8; 10]).unwrap(); // 10 bytes, well below 32
        let mut cfg = minimal_cfg(&dir);
        cfg.client_allowlist = vec![ClientCfg {
            user_id: "alice".to_string(),
            ed25519_pk: pk,
        }];
        let report = preflight(&cfg);
        assert!(
            report.has_failures(),
            "iter-143: truncated allowlist pk MUST FAIL: {report}"
        );
        let fail = report.checks.iter().any(|c| match c {
            Check::Fail(s) => {
                s.contains("client_allowlist[alice].ed25519_pk")
                    && s.contains("expected exactly 32")
            }
            _ => false,
        });
        assert!(
            fail,
            "iter-143: FAIL must name the field + the expected length: {report}"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Iter-143: an oversized pubkey (e.g. ed25519 SK leaked into
    /// the slot — 64 bytes for the dalek private-key wire form)
    /// MUST also FAIL. This is the worst-case "operator copied the
    /// wrong file" trap.
    #[test]
    fn iter143_oversized_allowlist_pk_fails() {
        let dir = tmpdir();
        let pk = dir.join("alice.pk");
        std::fs::write(&pk, [0x42u8; 64]).unwrap(); // 64 bytes
        let mut cfg = minimal_cfg(&dir);
        cfg.client_allowlist = vec![ClientCfg {
            user_id: "alice".to_string(),
            ed25519_pk: pk,
        }];
        let report = preflight(&cfg);
        assert!(
            report.has_failures(),
            "iter-143: oversized allowlist pk MUST FAIL: {report}"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Iter-143: a real 32-byte pubkey passes the length gate.
    /// (May still fail other gates — we just verify the iter-143
    /// gate doesn't fire on a correctly-sized file.)
    #[test]
    fn iter143_correct_length_allowlist_pk_passes_length_gate() {
        let dir = tmpdir();
        let pk = dir.join("alice.pk");
        let pk_bytes: [u8; 32] =
            std::array::from_fn(|i| (i as u8).wrapping_mul(13).wrapping_add(5));
        std::fs::write(&pk, pk_bytes).unwrap();
        let mut cfg = minimal_cfg(&dir);
        cfg.client_allowlist = vec![ClientCfg {
            user_id: "alice".to_string(),
            ed25519_pk: pk,
        }];
        let report = preflight(&cfg);
        // No FAIL row for iter-143's length gate.
        let length_fail = report.checks.iter().any(|c| match c {
            Check::Fail(s) => {
                s.contains("client_allowlist[alice].ed25519_pk")
                    && s.contains("expected exactly 32")
            }
            _ => false,
        });
        assert!(
            !length_fail,
            "iter-143: 32-byte pubkey MUST NOT trip the iter-143 length gate: {report}"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    // ---- iter-144: X25519 key length gates ----

    /// Iter-144: a truncated `x25519_pk` (RFC 7748 §5 → 32 bytes)
    /// MUST FAIL. Pre-iter-144 the validate path only checked
    /// existence + non-all-zero; the runtime would load the wrong
    /// bytes and silently produce mis-matched DH output on every
    /// client handshake. The server runs fine but rejects every
    /// client — even harder to diagnose than a startup-panic.
    #[test]
    fn iter144_truncated_x25519_pk_fails() {
        let dir = tmpdir();
        let cfg = minimal_cfg(&dir);
        // Overwrite the pk file with a 10-byte truncated blob.
        std::fs::write(&cfg.keys.x25519_pk, [0x55u8; 10]).unwrap();
        let report = preflight(&cfg);
        assert!(
            report.has_failures(),
            "iter-144: truncated x25519_pk MUST FAIL: {report}"
        );
        let fail = report.checks.iter().any(|c| match c {
            Check::Fail(s) => s.contains("keys.x25519_pk") && s.contains("expected exactly 32"),
            _ => false,
        });
        assert!(
            fail,
            "iter-144: FAIL must name the field AND the expected length: {report}"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Iter-144: same gate on the secret-key side.
    #[test]
    fn iter144_truncated_x25519_sk_fails() {
        let dir = tmpdir();
        let cfg = minimal_cfg(&dir);
        std::fs::write(&cfg.keys.x25519_sk, [0x55u8; 10]).unwrap();
        let report = preflight(&cfg);
        let fail = report.checks.iter().any(|c| match c {
            Check::Fail(s) => s.contains("keys.x25519_sk") && s.contains("expected exactly 32"),
            _ => false,
        });
        assert!(
            fail,
            "iter-144: truncated x25519_sk MUST FAIL with field-named message: {report}"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Iter-144: an oversized x25519 key (e.g. 64 bytes — operator
    /// copied an ed25519 keypair into the slot) → FAIL.
    #[test]
    fn iter144_oversized_x25519_pk_fails() {
        let dir = tmpdir();
        let cfg = minimal_cfg(&dir);
        std::fs::write(&cfg.keys.x25519_pk, [0x55u8; 64]).unwrap();
        let report = preflight(&cfg);
        assert!(
            report.has_failures(),
            "iter-144: oversized x25519_pk MUST FAIL: {report}"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Iter-144: correct 32-byte key file → no iter-144 FAIL.
    #[test]
    fn iter144_correct_length_x25519_passes_length_gate() {
        let dir = tmpdir();
        let cfg = minimal_cfg(&dir);
        // minimal_cfg already writes 32-byte all-0x42 keys; assert
        // they don't trip iter-144's length gate.
        let report = preflight(&cfg);
        let length_fail = report.checks.iter().any(|c| match c {
            Check::Fail(s) => {
                (s.contains("keys.x25519_pk") || s.contains("keys.x25519_sk"))
                    && s.contains("expected exactly 32")
            }
            _ => false,
        });
        assert!(
            !length_fail,
            "iter-144: 32-byte x25519 key MUST NOT trip the length gate: {report}"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Iter-141: pool entries hit the same gate.
    #[test]
    fn iter141_cover_endpoints_pool_port_80_fails() {
        let dir = tmpdir();
        let mut cfg = minimal_cfg(&dir);
        cfg.cover_endpoints = vec![
            "https-host.example.com:443".to_string(),
            "broken.example.com:80".to_string(),
        ];
        let report = preflight(&cfg);
        assert!(
            report.has_failures(),
            "iter-141: pool with port:80 entry MUST FAIL: {report}"
        );
        let fail = report.checks.iter().any(|c| match c {
            Check::Fail(s) => s.contains("cover_endpoints[1]") && s.contains("port 80"),
            _ => false,
        });
        assert!(
            fail,
            "iter-141: pool FAIL must index the bad entry: {report}"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }
}
