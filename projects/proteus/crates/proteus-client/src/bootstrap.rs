//! Bootstrap-DNS resolution policy.
//!
//! The 2026 GFW threat-intel (see `qa/2026-05-17-gfw-2026-q1q2-threat-intel.md`
//! main line 6) confirms the GFW now identifies DoH / DoT traffic by
//! flow pattern, not just by IP. Any client whose OS resolver hops
//! through a DoH endpoint can have its **bootstrap** flagged before
//! any Proteus payload is sent — at which point the connection is
//! dead at the L3 layer, our protocol never gets a chance.
//!
//! Defense: let the operator pin the server's IP directly, skipping
//! all DNS resolution. SNI / cert verification continue to use the
//! hostname (so X.509 chains, cover-URL coherence, and the JA4
//! profile stay intact); only the network-layer A/AAAA lookup is
//! eliminated.
//!
//! ## Two equivalent ways to bypass DNS
//!
//! 1. Write the IP literal into `server_endpoint` directly:
//!    ```yaml
//!    server_endpoint: "198.51.100.42:8443"
//!    tls:
//!      server_name: "vps.example.com"   # for SNI / cert verification
//!    ```
//! 2. Keep the hostname in `server_endpoint` and pin via
//!    `bootstrap_dns: { direct_ip: ... }`:
//!    ```yaml
//!    server_endpoint: "vps.example.com:8443"
//!    bootstrap_dns:
//!      direct_ip: 198.51.100.42
//!    tls:
//!      server_name: "vps.example.com"
//!    ```
//!
//! Form 2 exists because some operators prefer to keep the hostname
//! visible in the endpoint field for readability — it's the same
//! string they'd see in their TLS cert / cover-URL plan / DNS
//! provider's web UI. Both forms produce identical wire behavior:
//! the client opens a TCP / UDP socket directly to the IP, never
//! consults DNS.
//!
//! ## What this module does NOT solve
//!
//! - **First-time bootstrap via a hostname-only deploy**: the operator
//!   must learn the VPS IP out-of-band (their cloud console, an
//!   activation email, a one-shot CLI). This module assumes the IP is
//!   already known and pinned in `client.yaml`.
//! - **IP-level GFW blocking**: if the GFW has already burned the
//!   VPS IP (commercial-node cross-deployment blocklist, see
//!   threat-intel main line 1), bypassing DNS doesn't help. The
//!   companion defense is `proteus-server preflight
//!   --check-ip-reputation` (separate P0 deliverable).
//! - **First-flight IP discovery for failover endpoints**: when
//!   multi-VPS HA lands (M3), pinned IPs need to be supplied for
//!   every endpoint in the rotation list.

use std::net::{IpAddr, SocketAddr};

use crate::config::{BootstrapDnsCfg, ClientConfig, SystemKind};

/// Outcome of resolving a `host:port` endpoint under a bootstrap-DNS
/// policy.
///
/// Carries the resolved [`SocketAddr`] plus a discriminator so the
/// caller can log which path was taken (useful for ops debugging:
/// "I configured direct_ip, why am I still seeing DNS queries?").
#[derive(Debug, Clone, Copy)]
pub struct Resolved {
    pub addr: SocketAddr,
    pub via: ResolvedVia,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ResolvedVia {
    /// The endpoint string was already an IP literal (`198.51.100.42:8443`).
    /// No DNS was consulted regardless of the bootstrap_dns policy.
    IpLiteralInEndpoint,
    /// `bootstrap_dns: direct_ip: X` matched a hostname endpoint
    /// (`vps.example.com:8443`) and we used `X:port` directly.
    PinnedDirectIp,
    /// `bootstrap_dns: system` (default) — went through tokio's
    /// `lookup_host` which transits the OS resolver chain (and
    /// possibly a DoH server the GFW now identifies).
    SystemResolver,
}

/// Errors from bootstrap resolution.
#[derive(thiserror::Error, Debug)]
pub enum BootstrapError {
    #[error("endpoint did not parse as host:port: {0:?}")]
    BadEndpoint(String),
    #[error("endpoint host is an IP literal but does not parse: {0:?}")]
    BadIpLiteral(String),
    #[error("system resolver returned no addresses for {0:?}")]
    NoSystemAddresses(String),
    /// System resolver did not answer within
    /// [`SYSTEM_RESOLVER_TIMEOUT_SECS`]. Likely cause: poisoned /
    /// wedged recursive nameserver. Surfaces as a distinct
    /// error variant so callers can present a clear diagnostic
    /// instead of a generic Io / timeout.
    #[error("system resolver timed out after {0}s on {1:?} — recursive nameserver may be wedged; set bootstrap_dns.direct_ip in client.yaml to bypass")]
    SystemResolverTimeout(u64, String),
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
}

/// Hard ceiling on the system-resolver lookup in the bootstrap
/// path. Matches the server-side
/// [`proteus_transport_alpha::outbound_filter::DEFAULT_DNS_LOOKUP_TIMEOUT_SECS`]
/// for symmetry. Without this, a wedged recursive nameserver
/// during early-startup endpoint resolution would block the
/// client's main loop indefinitely — no SOCKS5 listener bind,
/// no error, no metrics signal.
pub const SYSTEM_RESOLVER_TIMEOUT_SECS: u64 = 5;

/// Resolve a `host:port` endpoint under a bootstrap-DNS policy.
///
/// Behavior matrix:
/// - **`endpoint` is an IP literal** (`198.51.100.42:8443` or
///   `[::1]:8443`): parse directly, return [`ResolvedVia::IpLiteralInEndpoint`].
///   The `bootstrap_dns` field is ignored — there's nothing to resolve.
/// - **`endpoint` is a hostname AND `bootstrap_dns: direct_ip: X` is set**:
///   pair `X` with the port from `endpoint`, return
///   [`ResolvedVia::PinnedDirectIp`]. No DNS query is made.
/// - **`endpoint` is a hostname AND `bootstrap_dns` is `system` / unset**:
///   call [`tokio::net::lookup_host`] (default OS resolver path).
///   Return [`ResolvedVia::SystemResolver`].
pub async fn resolve_endpoint(
    endpoint: &str,
    policy: Option<&BootstrapDnsCfg>,
) -> Result<Resolved, BootstrapError> {
    let (host, port) = parse_host_port(endpoint)
        .ok_or_else(|| BootstrapError::BadEndpoint(endpoint.to_string()))?;

    // Case 1: host is already an IP literal. Skip DNS unconditionally.
    if let Some(ip) = parse_ip_literal(host) {
        return Ok(Resolved {
            addr: SocketAddr::new(ip, port),
            via: ResolvedVia::IpLiteralInEndpoint,
        });
    }

    // Case 2: hostname + pinned direct_ip → combine.
    if let Some(BootstrapDnsCfg::DirectIp { direct_ip }) = policy {
        return Ok(Resolved {
            addr: SocketAddr::new(*direct_ip, port),
            via: ResolvedVia::PinnedDirectIp,
        });
    }

    // Case 3 (default): system resolver, bounded by
    // SYSTEM_RESOLVER_TIMEOUT_SECS so a wedged recursive
    // nameserver can't pin the caller indefinitely. Surfaces
    // as a distinct error variant so the caller can recommend
    // the operator switch to bootstrap_dns.direct_ip.
    let lookup_fut = tokio::net::lookup_host(endpoint);
    let addrs = match tokio::time::timeout(
        std::time::Duration::from_secs(SYSTEM_RESOLVER_TIMEOUT_SECS),
        lookup_fut,
    )
    .await
    {
        Ok(Ok(a)) => a,
        Ok(Err(e)) => return Err(BootstrapError::Io(e)),
        Err(_) => {
            return Err(BootstrapError::SystemResolverTimeout(
                SYSTEM_RESOLVER_TIMEOUT_SECS,
                endpoint.to_string(),
            ));
        }
    };
    let addr = addrs
        .into_iter()
        .next()
        .ok_or_else(|| BootstrapError::NoSystemAddresses(endpoint.to_string()))?;
    Ok(Resolved {
        addr,
        via: ResolvedVia::SystemResolver,
    })
}

/// Convenience wrapper that pulls the policy from a [`ClientConfig`].
pub async fn resolve_for_client(
    endpoint: &str,
    cfg: &ClientConfig,
) -> Result<Resolved, BootstrapError> {
    resolve_endpoint(endpoint, cfg.bootstrap_dns.as_ref()).await
}

/// Best-effort `host:port` splitter that handles IPv6 bracket form.
///
/// Iter-153: reject `port == 0` at the parser layer. Port 0 is not
/// a connectable TCP destination (it has special meaning in
/// `bind()` — "pick a random ephemeral" — but as a `connect()`
/// destination it surfaces a confusing `EADDRNOTAVAIL` from the
/// socket layer). The pre-iter-153 parser would accept
/// `vps.example.com:0` cleanly, then the dial would fail
/// 5 seconds later with a misleading "network unreachable"
/// error and no hint that the `client.yaml`'s port field is the
/// root cause. Symmetric with the iter-146 server-side
/// `parse_connect` gate and the iter-151 SOCKS5-boundary gate.
pub fn parse_host_port(s: &str) -> Option<(&str, u16)> {
    // Iter-160: reject control bytes (NUL/CR/LF/TAB) anywhere in the
    // endpoint string. `parse_host_port` is the boundary validator for
    // `server_endpoint` (config-loaded, but third-party config-
    // templating tools may pull from untrusted sources) and for the
    // tokio `lookup_host(endpoint)` call below, which on Linux flows
    // into libc's `getaddrinfo`. Standard libc resolvers historically
    // have NOT validated control bytes inside an FQDN (RFC 8482 §3
    // forbids them, but enforcement is on the consumer). A hostname
    // containing CR/LF in particular can corrupt DNS-over-UDP query
    // packets — see the long history of resolver-input smuggling
    // (CVE-2008-1447 cache-poisoning patterns, CVE-2018-1000007).
    // Mirrors the iter-147 / iter-158 control-byte gates at every
    // other host-bearing boundary in the codebase.
    if s.bytes()
        .any(|b| b == 0 || b == b'\r' || b == b'\n' || b == b'\t')
    {
        return None;
    }
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

/// Try to interpret `host` as a literal IPv4 or IPv6 address. Returns
/// `None` for hostnames (anything containing a non-IP character).
pub fn parse_ip_literal(host: &str) -> Option<IpAddr> {
    host.parse::<IpAddr>().ok()
}

/// True iff the `host` portion of `endpoint` is a literal IP (no DNS
/// needed). Used by the `validate` subcommand to decide whether to
/// warn about the system-resolver bootstrap path.
pub fn endpoint_is_ip_literal(endpoint: &str) -> bool {
    parse_host_port(endpoint)
        .map(|(host, _)| parse_ip_literal(host).is_some())
        .unwrap_or(false)
}

/// Suppress unused-variant warning when `BootstrapDnsCfg::System` is
/// the default-handled path.
#[allow(dead_code)]
fn _force_use_system_kind(_k: SystemKind) {}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    #[tokio::test]
    async fn ipv4_literal_endpoint_skips_dns_regardless_of_policy() {
        let r = resolve_endpoint("203.0.113.7:8443", None).await.unwrap();
        assert_eq!(r.via, ResolvedVia::IpLiteralInEndpoint);
        assert_eq!(r.addr.port(), 8443);
        assert_eq!(r.addr.ip(), IpAddr::V4(Ipv4Addr::new(203, 0, 113, 7)));

        let policy = BootstrapDnsCfg::DirectIp {
            direct_ip: IpAddr::V4(Ipv4Addr::new(198, 51, 100, 1)),
        };
        let r2 = resolve_endpoint("203.0.113.7:8443", Some(&policy))
            .await
            .unwrap();
        assert_eq!(r2.via, ResolvedVia::IpLiteralInEndpoint);
        // direct_ip is IGNORED when the endpoint already has a literal;
        // we don't override what the operator wrote.
        assert_eq!(r2.addr.ip(), IpAddr::V4(Ipv4Addr::new(203, 0, 113, 7)));
    }

    #[tokio::test]
    async fn ipv6_literal_endpoint_skips_dns() {
        let r = resolve_endpoint("[2001:db8::1]:8443", None).await.unwrap();
        assert_eq!(r.via, ResolvedVia::IpLiteralInEndpoint);
        assert_eq!(r.addr.port(), 8443);
    }

    #[tokio::test]
    async fn hostname_with_direct_ip_uses_pinned_addr() {
        let policy = BootstrapDnsCfg::DirectIp {
            direct_ip: IpAddr::V4(Ipv4Addr::new(198, 51, 100, 42)),
        };
        let r = resolve_endpoint("vps.example.com:8443", Some(&policy))
            .await
            .unwrap();
        assert_eq!(r.via, ResolvedVia::PinnedDirectIp);
        assert_eq!(r.addr.port(), 8443);
        assert_eq!(r.addr.ip(), IpAddr::V4(Ipv4Addr::new(198, 51, 100, 42)));
    }

    #[tokio::test]
    async fn hostname_with_no_policy_uses_system_resolver_for_localhost() {
        // localhost is universally resolvable without external DNS,
        // so this works in CI sandboxes.
        let r = resolve_endpoint("localhost:8443", None).await.unwrap();
        assert_eq!(r.via, ResolvedVia::SystemResolver);
        assert_eq!(r.addr.port(), 8443);
        assert!(r.addr.ip().is_loopback());
    }

    #[tokio::test]
    async fn bad_endpoint_reports_error() {
        let err = resolve_endpoint("not_a_host_port", None).await;
        assert!(matches!(err, Err(BootstrapError::BadEndpoint(_))));
    }

    #[test]
    fn system_resolver_timeout_constant_is_finite() {
        // Sanity: the timeout must be a number a wedged resolver
        // can't outwait but a healthy one can comfortably meet.
        // Anything > 0 and < 30 is acceptable. const-asserted so a
        // future revision that accidentally zeros the constant
        // fails at compile time.
        const _OK_LOWER: () = assert!(SYSTEM_RESOLVER_TIMEOUT_SECS > 0);
        const _OK_UPPER: () = assert!(SYSTEM_RESOLVER_TIMEOUT_SECS < 30);
    }

    #[test]
    fn system_resolver_timeout_error_message_includes_actionable_hint() {
        // The error's Display impl must point operators at the
        // bootstrap_dns.direct_ip fix — otherwise a wedged-resolver
        // FAIL becomes a head-scratcher.
        let e = BootstrapError::SystemResolverTimeout(5, "vps.example.com:8443".to_string());
        let msg = format!("{e}");
        assert!(
            msg.contains("bootstrap_dns.direct_ip"),
            "error must point at the direct_ip fix: {msg}"
        );
        assert!(msg.contains("vps.example.com:8443"));
    }

    #[test]
    fn endpoint_is_ip_literal_recognizes_both_families() {
        assert!(endpoint_is_ip_literal("198.51.100.42:8443"));
        assert!(endpoint_is_ip_literal("[2001:db8::1]:8443"));
        assert!(!endpoint_is_ip_literal("vps.example.com:8443"));
        assert!(!endpoint_is_ip_literal("not_a_thing"));
    }

    #[test]
    fn bootstrap_dns_cfg_yaml_round_trips() {
        // Tagged-mapping form: `direct_ip: 198.51.100.42`.
        let y = "direct_ip: 198.51.100.42\n";
        let cfg: BootstrapDnsCfg = serde_yaml::from_str(y).unwrap();
        assert!(cfg.is_direct_ip());
        assert_eq!(
            cfg.pinned_ip(),
            Some(IpAddr::V4(Ipv4Addr::new(198, 51, 100, 42)))
        );

        // String form: `system`.
        let y2 = "system\n";
        let cfg2: BootstrapDnsCfg = serde_yaml::from_str(y2).unwrap();
        assert!(!cfg2.is_direct_ip());
        assert_eq!(cfg2.pinned_ip(), None);
    }

    #[test]
    fn ipv6_direct_ip_round_trip() {
        let y = "direct_ip: \"2001:db8::1\"\n";
        let cfg: BootstrapDnsCfg = serde_yaml::from_str(y).unwrap();
        assert!(cfg.is_direct_ip());
        match cfg.pinned_ip() {
            Some(IpAddr::V6(_)) => (),
            other => panic!("expected IPv6 pinned_ip, got {other:?}"),
        }
    }

    // ---- iter-153: parse_host_port rejects port 0 ----

    #[test]
    fn iter153_parse_host_port_rejects_port_zero_v4() {
        assert!(parse_host_port("vps.example.com:0").is_none());
        assert!(parse_host_port("198.51.100.42:0").is_none());
    }

    #[test]
    fn iter153_parse_host_port_rejects_port_zero_v6() {
        assert!(parse_host_port("[2001:db8::1]:0").is_none());
    }

    /// Iter-153: positive cases still parse. Quick smoke test that
    /// the port-0 gate didn't accidentally reject common-port shapes.
    #[test]
    fn iter153_common_ports_still_parse() {
        for ep in [
            "vps.example.com:443",
            "vps.example.com:8443",
            "198.51.100.42:443",
            "[2001:db8::1]:443",
            "[::1]:9090",
        ] {
            assert!(
                parse_host_port(ep).is_some(),
                "iter-153: well-formed endpoint {ep:?} must still parse"
            );
        }
    }

    /// Iter-160: control bytes (NUL/CR/LF/TAB) in the endpoint
    /// string must be rejected at parse time. The string flows
    /// into tokio's `lookup_host`, which on Linux is libc's
    /// getaddrinfo; CR/LF in particular can corrupt DNS-over-UDP
    /// query packets. The pre-iter-160 parser would happily
    /// extract `("vps.example.com\n", 443)` and hand the broken
    /// hostname to the resolver. Symmetric with the iter-147
    /// (admin URL host) + iter-158 (cover endpoint host) +
    /// iter-151 (SOCKS5 hostname) gates.
    #[test]
    fn iter160_parse_host_port_rejects_control_bytes() {
        for ep in [
            "vps.example.com\n:443",
            "vps.example.com\r:443",
            "vps.example.com\t:443",
            "vps.example.com\0:443",
            "\nvps.example.com:443",
            "vps.example.com:443\n",
            "vps.example.com:4\n43",
            "198.51.100.42\n:443",
            "[2001:db8::1]\n:443",
        ] {
            assert!(
                parse_host_port(ep).is_none(),
                "iter-160: control byte in {ep:?} must be rejected"
            );
        }
    }

    /// Iter-160 regression: legit non-control hostnames still parse.
    /// Specifically exercises the underscore + hyphen FQDN characters
    /// (the gate must NOT over-reject — only NUL/CR/LF/TAB).
    #[test]
    fn iter160_legit_hostnames_still_parse_after_control_byte_gate() {
        for ep in [
            "vps-east-1.example.com:443",
            "vps_internal.example.com:443", // technically RFC-illegal but resolver-accepted
            "a.b.c.d.e.f.example.com:443",
            "xn--bcher-kva.example.com:443", // IDN punycode
        ] {
            assert!(
                parse_host_port(ep).is_some(),
                "iter-160: legit endpoint {ep:?} must still parse"
            );
        }
    }
}
