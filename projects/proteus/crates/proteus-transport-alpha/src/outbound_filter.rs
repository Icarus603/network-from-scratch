//! Outbound destination filter — SSRF defense for the relay's
//! upstream-dial step.
//!
//! Without this, any client with a valid credential can ask the
//! Proteus server to dial:
//!
//!   - `169.254.169.254:80` — AWS/GCP/Azure metadata endpoint
//!     (returns IAM creds, machine identity, kernel access tokens)
//!   - `127.0.0.1:5432` — local Postgres, Redis, etc.
//!   - `10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16` — RFC 1918
//!     internal networks
//!   - `fd00::/8`, `fe80::/10` — IPv6 ULA / link-local
//!   - `[::1]:5432` — IPv6 loopback variants
//!
//! Every production proxy must filter these. This module is the
//! single source of truth: every relay-side dial path checks here
//! before opening the upstream socket.
//!
//! Two layers:
//!
//! 1. **Port allowlist** — by default we allow `[80, 443]` (the
//!    overwhelming majority of legitimate proxy traffic). Operators
//!    can extend (e.g. add `22, 53, 587, 993`) or replace.
//! 2. **CIDR denylist** — by default ALL the SSRF-relevant ranges
//!    above are blocked. Operators can extend (e.g. block their own
//!    `10.0.0.0/8` egress) but the defaults already cover the
//!    standard attack surface.
//!
//! DNS resolution happens HERE, not in the dial. We resolve the host
//! to every A/AAAA, check each against the denylist, and only THEN
//! pass the IP to `TcpStream::connect`. This closes the DNS-rebinding
//! gap where a malicious resolver could answer with a public IP for
//! the policy check then swap to an internal IP for the dial.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use crate::firewall::CidrRule;

/// Decision returned by [`OutboundPolicy::check`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Decision {
    /// The destination passed every check. Carries the resolved IP
    /// the caller should dial (closes the DNS-rebinding window).
    Allow(IpAddr),
    /// Port is not in the allow list.
    DeniedPort(u16),
    /// At least one resolved IP matches a denylist CIDR; we return
    /// the offending IP for log triage.
    DeniedHost(IpAddr),
    /// DNS lookup failed or returned no addresses.
    UnresolvableHost,
}

/// Outbound destination filter. Cheap to clone (Arc<Vec<…>>'s of
/// CidrRule are small) but the relay usually wraps this in
/// `Arc<OutboundPolicy>` since one instance is shared by every
/// session.
#[derive(Debug, Clone)]
pub struct OutboundPolicy {
    allowed_ports: Vec<u16>,
    blocked_cidrs: Vec<CidrRule>,
    /// When `true`, hosts that fail DNS lookup are denied. When
    /// `false` we leave the dial path to fail naturally with a
    /// connection error. Default `true` — fail-closed.
    deny_unresolvable: bool,
}

impl Default for OutboundPolicy {
    /// Sensible production default: ports 80/443 only, SSRF CIDRs
    /// all blocked, unresolvable hosts denied.
    fn default() -> Self {
        Self {
            allowed_ports: vec![80, 443],
            blocked_cidrs: default_ssrf_blocklist(),
            deny_unresolvable: true,
        }
    }
}

impl OutboundPolicy {
    /// Empty policy (admit everything). Used by tests + the
    /// no-filter opt-out path.
    #[must_use]
    pub fn permissive() -> Self {
        Self {
            allowed_ports: Vec::new(),
            blocked_cidrs: Vec::new(),
            deny_unresolvable: false,
        }
    }

    /// Replace the allowed-port list. Empty = no port restriction.
    #[must_use]
    pub fn with_allowed_ports(mut self, ports: Vec<u16>) -> Self {
        self.allowed_ports = ports;
        self
    }

    /// Extend the allowed-port list with `additional`.
    #[must_use]
    pub fn extend_allowed_ports<I: IntoIterator<Item = u16>>(mut self, additional: I) -> Self {
        self.allowed_ports.extend(additional);
        self
    }

    /// Append additional CIDRs to block. Errors on the first invalid
    /// string. Use to extend the SSRF default list (e.g. block your
    /// own egress prefix).
    pub fn extend_blocked_cidrs<I, S>(&mut self, rules: I) -> Result<(), String>
    where
        I: IntoIterator<Item = S>,
        S: AsRef<str>,
    {
        for s in rules {
            self.blocked_cidrs.push(s.as_ref().parse()?);
        }
        Ok(())
    }

    /// Clear the entire CIDR blocklist (including the SSRF defaults).
    /// Caller MUST re-add only the rules they want. Useful when the
    /// operator wants a fully custom blocklist.
    #[must_use]
    pub fn with_no_default_blocklist(mut self) -> Self {
        self.blocked_cidrs.clear();
        self
    }

    /// Override the unresolvable-host policy. Default is `true`
    /// (fail-closed).
    #[must_use]
    pub fn with_deny_unresolvable(mut self, deny: bool) -> Self {
        self.deny_unresolvable = deny;
        self
    }

    /// Hot-path port check. Returns true if the port is allowed (or
    /// if no port restriction is configured).
    #[must_use]
    pub fn port_allowed(&self, port: u16) -> bool {
        self.allowed_ports.is_empty() || self.allowed_ports.contains(&port)
    }

    /// Check a single resolved IP against the CIDR blocklist.
    #[must_use]
    pub fn ip_allowed(&self, ip: IpAddr) -> bool {
        !self.blocked_cidrs.iter().any(|r| r.matches(ip))
    }

    /// Full check: port + every resolved IP. The caller passes a
    /// list of resolved IPs (e.g. from `tokio::net::lookup_host`).
    /// We return [`Decision::Allow`] with the FIRST allowed IP — the
    /// caller dials this exact IP so a malicious resolver can't swap
    /// it for an internal one between policy check and dial.
    ///
    /// If `resolved` is empty, returns [`Decision::UnresolvableHost`]
    /// (when `deny_unresolvable`) — but the caller may also choose
    /// to short-circuit with this themselves on a `lookup_host` error.
    #[must_use]
    pub fn check(&self, port: u16, resolved: &[IpAddr]) -> Decision {
        if !self.port_allowed(port) {
            return Decision::DeniedPort(port);
        }
        if resolved.is_empty() {
            return if self.deny_unresolvable {
                Decision::UnresolvableHost
            } else {
                // Caller wanted fail-open; surface as port-allow
                // failure since we have no IP to give back.
                Decision::UnresolvableHost
            };
        }
        // Reject if ANY resolved IP is on the blocklist. DNS rebind
        // returning a mix would still hit this check because the
        // returned addresses ALL need to be vetted (an attacker
        // could pick the unsafe one for the dial otherwise — but
        // we control which IP we dial below).
        for ip in resolved {
            if !self.ip_allowed(*ip) {
                return Decision::DeniedHost(*ip);
            }
        }
        // Every resolved IP is acceptable. Dial the first one to
        // avoid the rebind window. (Callers that need round-robin
        // can implement it themselves — this is a security policy
        // gate, not a load balancer.)
        Decision::Allow(resolved[0])
    }
}

/// The SSRF default blocklist. Returns the CIDR rules every
/// production deployment should be running with. Operator can
/// supplement but should rarely remove.
///
/// Coverage: IPv4 loopback, link-local, multicast, broadcast,
/// RFC 1918 private, CGNAT (RFC 6598), TEST-NET-1/2/3, AWS/GCP/Azure
/// metadata; IPv6 loopback, ULA, link-local, multicast, mapped-v4.
#[must_use]
pub fn default_ssrf_blocklist() -> Vec<CidrRule> {
    [
        // IPv4
        "0.0.0.0/8",          // current network ("this network")
        "10.0.0.0/8",         // RFC 1918 private
        "100.64.0.0/10",      // RFC 6598 carrier-grade NAT
        "127.0.0.0/8",        // loopback
        "169.254.0.0/16",     // link-local (includes cloud metadata)
        "172.16.0.0/12",      // RFC 1918 private
        "192.0.0.0/24",       // IETF reserved
        "192.0.2.0/24",       // TEST-NET-1
        "192.88.99.0/24",     // 6to4 anycast (deprecated)
        "192.168.0.0/16",     // RFC 1918 private
        "198.18.0.0/15",      // benchmark
        "198.51.100.0/24",    // TEST-NET-2
        "203.0.113.0/24",     // TEST-NET-3
        "224.0.0.0/4",        // multicast (Class D)
        "240.0.0.0/4",        // reserved (Class E)
        "255.255.255.255/32", // broadcast
        // IPv6
        "::/128",        // unspecified
        "::1/128",       // loopback
        "::ffff:0:0/96", // IPv4-mapped — closes the bypass where
        //   ::ffff:10.0.0.1 sneaks past v4 rules
        "64:ff9b::/96", // NAT64 well-known prefix
        "fc00::/7",     // ULA (unique local) — covers fc00–fdff
        "fe80::/10",    // link-local
        "ff00::/8",     // multicast
    ]
    .into_iter()
    .map(|s| s.parse().expect("default SSRF CIDR must parse"))
    .collect()
}

/// Resolve `host:port` to a list of IPs via `tokio::net::lookup_host`.
/// Returns an empty Vec on lookup failure (caller decides whether
/// that's fail-open or fail-closed via [`OutboundPolicy::check`]).
pub async fn resolve_host(host: &str, port: u16) -> Vec<IpAddr> {
    // Fast path: host is already a literal IP. Skip the resolver to
    // avoid a meaningless syscall (and to ensure a literal-form
    // CONNECT goes through the same policy gate as a name-form one).
    if let Ok(ip) = host.parse::<IpAddr>() {
        return vec![ip];
    }
    match tokio::net::lookup_host((host, port)).await {
        Ok(addrs) => addrs.map(|sa| sa.ip()).collect(),
        Err(_) => Vec::new(),
    }
}

// Re-export the standard-library is_loopback / is_link_local etc.
// so the test module can spot-check without re-implementing.
#[allow(dead_code)]
fn classify(addr: IpAddr) -> Option<&'static str> {
    match addr {
        IpAddr::V4(v) if v.is_loopback() => Some("v4-loopback"),
        IpAddr::V4(v) if v.is_private() => Some("v4-private"),
        IpAddr::V4(v) if v.is_link_local() => Some("v4-link-local"),
        IpAddr::V4(Ipv4Addr::BROADCAST) => Some("v4-broadcast"),
        IpAddr::V6(v) if v.is_loopback() => Some("v6-loopback"),
        IpAddr::V6(Ipv6Addr::UNSPECIFIED) => Some("v6-unspecified"),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    #[test]
    fn default_policy_blocks_aws_metadata() {
        let p = OutboundPolicy::default();
        let d = p.check(80, &[ip("169.254.169.254")]);
        assert!(matches!(d, Decision::DeniedHost(_)), "got: {d:?}");
    }

    #[test]
    fn default_policy_blocks_v4_loopback() {
        let p = OutboundPolicy::default();
        for addr in ["127.0.0.1", "127.0.0.42", "127.255.255.255"] {
            assert!(
                matches!(p.check(443, &[ip(addr)]), Decision::DeniedHost(_)),
                "{addr} should be blocked"
            );
        }
    }

    #[test]
    fn default_policy_blocks_rfc1918() {
        let p = OutboundPolicy::default();
        for addr in ["10.0.0.1", "172.16.0.1", "172.31.255.255", "192.168.1.1"] {
            assert!(
                matches!(p.check(443, &[ip(addr)]), Decision::DeniedHost(_)),
                "{addr} should be blocked"
            );
        }
    }

    #[test]
    fn default_policy_blocks_v6_loopback_and_ula() {
        let p = OutboundPolicy::default();
        for addr in ["::1", "fc00::1", "fd12:3456:789a::1", "fe80::1"] {
            assert!(
                matches!(p.check(443, &[ip(addr)]), Decision::DeniedHost(_)),
                "{addr} should be blocked"
            );
        }
    }

    #[test]
    fn default_policy_blocks_v4_mapped_v6_bypass() {
        // Bypass-attempt: ::ffff:10.0.0.1 wraps a private v4 in a v6
        // address. Many naive filters check v4 rules against IpAddr::V4
        // and IPv6 rules against IpAddr::V6 — but std::net parses
        // `::ffff:a.b.c.d` as Ipv6Addr. The default blocklist covers
        // `::ffff:0:0/96` exactly to close this.
        let p = OutboundPolicy::default();
        let d = p.check(443, &[ip("::ffff:10.0.0.1")]);
        assert!(matches!(d, Decision::DeniedHost(_)), "got: {d:?}");
    }

    #[test]
    fn default_policy_allows_public_ip() {
        let p = OutboundPolicy::default();
        let d = p.check(443, &[ip("1.1.1.1")]);
        assert_eq!(d, Decision::Allow(ip("1.1.1.1")));
    }

    #[test]
    fn default_policy_blocks_non_80_443_ports() {
        let p = OutboundPolicy::default();
        assert!(matches!(
            p.check(22, &[ip("1.1.1.1")]),
            Decision::DeniedPort(22)
        ));
        assert!(matches!(
            p.check(25, &[ip("1.1.1.1")]),
            Decision::DeniedPort(25)
        ));
        assert!(matches!(
            p.check(8080, &[ip("1.1.1.1")]),
            Decision::DeniedPort(8080)
        ));
    }

    #[test]
    fn default_policy_allows_80_and_443() {
        let p = OutboundPolicy::default();
        for port in [80, 443] {
            assert!(matches!(
                p.check(port, &[ip("1.1.1.1")]),
                Decision::Allow(_)
            ));
        }
    }

    #[test]
    fn extend_allowed_ports_works() {
        let p = OutboundPolicy::default().extend_allowed_ports([22, 587]);
        assert!(matches!(p.check(22, &[ip("1.1.1.1")]), Decision::Allow(_)));
        assert!(matches!(p.check(587, &[ip("1.1.1.1")]), Decision::Allow(_)));
        // Default ports still allowed.
        assert!(matches!(p.check(443, &[ip("1.1.1.1")]), Decision::Allow(_)));
        // Unlisted port still denied.
        assert!(matches!(
            p.check(8080, &[ip("1.1.1.1")]),
            Decision::DeniedPort(8080)
        ));
    }

    #[test]
    fn empty_port_list_means_unrestricted() {
        let p = OutboundPolicy::default().with_allowed_ports(Vec::new());
        assert!(matches!(
            p.check(8080, &[ip("1.1.1.1")]),
            Decision::Allow(_)
        ));
        assert!(matches!(p.check(22, &[ip("1.1.1.1")]), Decision::Allow(_)));
    }

    #[test]
    fn permissive_policy_admits_everything() {
        let p = OutboundPolicy::permissive();
        assert!(matches!(
            p.check(22, &[ip("127.0.0.1")]),
            Decision::Allow(_)
        ));
        assert!(matches!(p.check(0, &[ip("::1")]), Decision::Allow(_)));
    }

    #[test]
    fn extend_blocked_cidrs_propagates_parse_error() {
        let mut p = OutboundPolicy::default();
        assert!(p.extend_blocked_cidrs(["totally-not-a-cidr"]).is_err());
    }

    #[test]
    fn custom_blocklist_replaces_defaults() {
        // Operator decides to use ONLY their own blocklist.
        let mut p = OutboundPolicy::default().with_no_default_blocklist();
        p.extend_blocked_cidrs(["198.51.100.0/24"]).unwrap();
        // No longer in default blocklist → loopback now passes.
        assert!(matches!(
            p.check(443, &[ip("127.0.0.1")]),
            Decision::Allow(_)
        ));
        // Custom rule still fires.
        assert!(matches!(
            p.check(443, &[ip("198.51.100.42")]),
            Decision::DeniedHost(_)
        ));
    }

    #[test]
    fn any_resolved_ip_on_blocklist_triggers_denial() {
        // Defense against DNS rebind that returns a mix of public +
        // private IPs: a single private IP in the resolved set must
        // deny the whole destination.
        let p = OutboundPolicy::default();
        let resolved = [ip("1.1.1.1"), ip("10.0.0.1")];
        let d = p.check(443, &resolved);
        assert_eq!(d, Decision::DeniedHost(ip("10.0.0.1")));
    }

    #[test]
    fn unresolvable_host_denied_by_default() {
        let p = OutboundPolicy::default();
        assert_eq!(p.check(443, &[]), Decision::UnresolvableHost);
    }

    #[test]
    fn allow_returns_first_resolved_ip() {
        let p = OutboundPolicy::default();
        let resolved = [ip("1.1.1.1"), ip("8.8.8.8")];
        assert_eq!(p.check(443, &resolved), Decision::Allow(ip("1.1.1.1")));
    }

    #[tokio::test(flavor = "current_thread")]
    async fn resolve_host_fast_path_for_literal_ipv4() {
        let v = resolve_host("1.1.1.1", 80).await;
        assert_eq!(v, vec![ip("1.1.1.1")]);
    }

    #[tokio::test(flavor = "current_thread")]
    async fn resolve_host_fast_path_for_literal_ipv6() {
        let v = resolve_host("::1", 80).await;
        assert_eq!(v, vec![ip("::1")]);
    }

    #[tokio::test(flavor = "current_thread")]
    async fn resolve_host_returns_empty_or_blocked_ip_on_dns_failure() {
        // `.invalid` is a reserved TLD that, per RFC 2606, MUST not
        // resolve. In practice some captive-portal / corporate
        // resolvers (including some macOS configs) return sentinel
        // IPs in 198.18.0.0/15 instead of NXDOMAIN. Either is fine
        // for our purposes — the sentinel will be blocked by the
        // default SSRF list. The point of the test is: the function
        // does not panic and does not throw, AND any IP it returns
        // is denied by the default policy.
        let p = OutboundPolicy::default();
        let v = resolve_host("this-host-does-not-exist.invalid", 80).await;
        for addr in &v {
            assert!(
                !p.ip_allowed(*addr),
                "lying resolver returned {addr}, which should be in the SSRF blocklist"
            );
        }
    }
}
