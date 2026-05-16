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

/// A hostname suffix pattern. Two flavors:
///
/// - `"example.com"` matches `example.com` exactly and any subdomain
///   (`foo.example.com`, `a.b.example.com`).
/// - `"*.example.com"` matches **only** strict subdomains, not the
///   apex (`foo.example.com` matches, `example.com` does not).
///
/// Comparisons are case-insensitive (DNS labels are not case-
/// sensitive). Trailing dots in either the pattern or the candidate
/// hostname are stripped before matching.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HostPattern {
    /// The pattern with any leading `*.` stripped and lowercased.
    suffix: String,
    /// True when the pattern was `*.…` (subdomain-only). False means
    /// "match the suffix or any subdomain of it".
    strict_subdomain: bool,
}

impl HostPattern {
    /// Parse a string into a [`HostPattern`]. Rejects empty strings,
    /// patterns with embedded wildcards (`a.*.b`), and patterns
    /// containing characters other than alphanum / dot / hyphen /
    /// the leading `*.`.
    pub fn parse(s: &str) -> Result<Self, String> {
        let s = s.trim().trim_end_matches('.');
        if s.is_empty() {
            return Err("empty hostname pattern".to_string());
        }
        let (suffix, strict) = if let Some(rest) = s.strip_prefix("*.") {
            (rest, true)
        } else {
            (s, false)
        };
        if suffix.is_empty() {
            return Err(format!("pattern {s:?}: bare wildcard with no suffix"));
        }
        // Forbid embedded wildcards (`foo.*.bar`) — they're a common
        // operator mistake and aren't worth the parser complexity.
        if suffix.contains('*') {
            return Err(format!(
                "pattern {s:?}: embedded `*` not supported; use leading `*.suffix` form"
            ));
        }
        // Every label must be valid LDH (letters, digits, hyphens)
        // plus the dot separator.
        for label in suffix.split('.') {
            if label.is_empty() {
                return Err(format!("pattern {s:?}: empty label (consecutive dots)"));
            }
            if !label.chars().all(|c| c.is_ascii_alphanumeric() || c == '-') {
                return Err(format!("pattern {s:?}: invalid char in label {label:?}"));
            }
            if label.starts_with('-') || label.ends_with('-') {
                return Err(format!(
                    "pattern {s:?}: label {label:?} starts/ends with hyphen"
                ));
            }
        }
        Ok(Self {
            suffix: suffix.to_ascii_lowercase(),
            strict_subdomain: strict,
        })
    }

    /// Does this pattern cover `host`? Case-insensitive; trailing
    /// dots stripped from `host`.
    #[must_use]
    pub fn matches(&self, host: &str) -> bool {
        let host = host.trim_end_matches('.').to_ascii_lowercase();
        if host == self.suffix {
            return !self.strict_subdomain;
        }
        // Subdomain match: host must end with `.{self.suffix}`. We
        // explicitly check the boundary dot to avoid `evilexample.com`
        // matching pattern `example.com`.
        if let Some(prefix_len) = host.len().checked_sub(self.suffix.len()) {
            if prefix_len == 0 {
                return false; // host shorter than suffix (or empty prefix already handled)
            }
            // host has the right length; verify the boundary char +
            // suffix match.
            let (left, right) = host.split_at(prefix_len);
            if !left.ends_with('.') {
                return false;
            }
            return right == self.suffix;
        }
        false
    }
}

impl std::str::FromStr for HostPattern {
    type Err = String;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::parse(s)
    }
}

/// Decision returned by [`OutboundPolicy::check`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Decision {
    /// The destination passed every check. Carries the resolved IP
    /// the caller should dial (closes the DNS-rebinding window).
    Allow(IpAddr),
    /// Port is not in the allow list.
    DeniedPort(u16),
    /// Hostname matched a deny pattern.
    DeniedHostname,
    /// Hostname does NOT match the non-empty allow pattern list.
    HostnameNotAllowed,
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
///
/// **Decision pipeline** (first failure wins):
///
/// 1. Port allowlist (default `[80, 443]`).
/// 2. Hostname **deny** patterns (e.g. ban known abuse domains).
/// 3. Hostname **allow** patterns — if non-empty, the host must
///    match at least one. Empty = no hostname allowlist policy
///    (any hostname can proceed to the CIDR check).
/// 4. DNS resolution.
/// 5. CIDR blocklist applied to every resolved IP.
#[derive(Debug, Clone)]
pub struct OutboundPolicy {
    allowed_ports: Vec<u16>,
    blocked_cidrs: Vec<CidrRule>,
    /// When `true`, hosts that fail DNS lookup are denied. When
    /// `false` we leave the dial path to fail naturally with a
    /// connection error. Default `true` — fail-closed.
    deny_unresolvable: bool,
    /// Optional hostname allowlist. When non-empty, the candidate
    /// host MUST match one of these patterns. Operator uses this
    /// for "only let users reach our CDN + a couple of known APIs".
    allowed_hostnames: Vec<HostPattern>,
    /// Hostname denylist. Always applied; takes precedence over
    /// the allowlist.
    blocked_hostnames: Vec<HostPattern>,
}

impl Default for OutboundPolicy {
    /// Sensible production default: ports 80/443 only, SSRF CIDRs
    /// all blocked, unresolvable hosts denied, hostname allow/deny
    /// lists empty (no hostname policy).
    fn default() -> Self {
        Self {
            allowed_ports: vec![80, 443],
            blocked_cidrs: default_ssrf_blocklist(),
            deny_unresolvable: true,
            allowed_hostnames: Vec::new(),
            blocked_hostnames: Vec::new(),
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
            allowed_hostnames: Vec::new(),
            blocked_hostnames: Vec::new(),
        }
    }

    /// Append patterns to the hostname allowlist. When the allowlist
    /// is non-empty, only candidate hosts matching one of these
    /// patterns survive the hostname gate. Errors on the first
    /// invalid pattern string.
    pub fn extend_allowed_hostnames<I, S>(&mut self, patterns: I) -> Result<(), String>
    where
        I: IntoIterator<Item = S>,
        S: AsRef<str>,
    {
        for s in patterns {
            self.allowed_hostnames.push(HostPattern::parse(s.as_ref())?);
        }
        Ok(())
    }

    /// Append patterns to the hostname denylist. Always applied,
    /// takes precedence over the allowlist.
    pub fn extend_blocked_hostnames<I, S>(&mut self, patterns: I) -> Result<(), String>
    where
        I: IntoIterator<Item = S>,
        S: AsRef<str>,
    {
        for s in patterns {
            self.blocked_hostnames.push(HostPattern::parse(s.as_ref())?);
        }
        Ok(())
    }

    /// Apply hostname-level patterns. Returns None if the host
    /// passes (either no policy or matched an allow + not denied),
    /// or Some(Decision) describing the rejection. Public so the
    /// relay can run the same logic on hostnames that ALSO appear
    /// as IP literals (we treat literal IPs as "no hostname policy
    /// applies" — they go straight to the CIDR check).
    ///
    /// Three short-circuits skip the gate entirely:
    /// - Empty `host` (caller has no name to check).
    /// - Literal IPv4/IPv6 string (no DNS hostname involved).
    #[must_use]
    pub fn check_hostname(&self, host: &str) -> Option<Decision> {
        if host.is_empty() {
            return None;
        }
        // Literal IPs aren't hostnames; skip the hostname gate.
        if host.parse::<IpAddr>().is_ok() {
            return None;
        }
        if self.blocked_hostnames.iter().any(|p| p.matches(host)) {
            return Some(Decision::DeniedHostname);
        }
        if !self.allowed_hostnames.is_empty()
            && !self.allowed_hostnames.iter().any(|p| p.matches(host))
        {
            return Some(Decision::HostnameNotAllowed);
        }
        None
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

    /// Full check: port + hostname + every resolved IP. The caller
    /// passes the original host (e.g. `"foo.example.com"` or
    /// `"203.0.113.10"`) and the resolved IP list from
    /// `tokio::net::lookup_host`. We return [`Decision::Allow`] with
    /// the FIRST allowed IP — the caller dials that exact IP so a
    /// malicious resolver can't swap it for an internal one between
    /// policy check and dial.
    ///
    /// Pass `host = ""` (or a literal IP) when the hostname gate
    /// shouldn't apply.
    #[must_use]
    pub fn check(&self, host: &str, port: u16, resolved: &[IpAddr]) -> Decision {
        if !self.port_allowed(port) {
            return Decision::DeniedPort(port);
        }
        if let Some(d) = self.check_hostname(host) {
            return d;
        }
        if resolved.is_empty() {
            return Decision::UnresolvableHost;
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
        let d = p.check("", 80, &[ip("169.254.169.254")]);
        assert!(matches!(d, Decision::DeniedHost(_)), "got: {d:?}");
    }

    #[test]
    fn default_policy_blocks_v4_loopback() {
        let p = OutboundPolicy::default();
        for addr in ["127.0.0.1", "127.0.0.42", "127.255.255.255"] {
            assert!(
                matches!(p.check("", 443, &[ip(addr)]), Decision::DeniedHost(_)),
                "{addr} should be blocked"
            );
        }
    }

    #[test]
    fn default_policy_blocks_rfc1918() {
        let p = OutboundPolicy::default();
        for addr in ["10.0.0.1", "172.16.0.1", "172.31.255.255", "192.168.1.1"] {
            assert!(
                matches!(p.check("", 443, &[ip(addr)]), Decision::DeniedHost(_)),
                "{addr} should be blocked"
            );
        }
    }

    #[test]
    fn default_policy_blocks_v6_loopback_and_ula() {
        let p = OutboundPolicy::default();
        for addr in ["::1", "fc00::1", "fd12:3456:789a::1", "fe80::1"] {
            assert!(
                matches!(p.check("", 443, &[ip(addr)]), Decision::DeniedHost(_)),
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
        let d = p.check("", 443, &[ip("::ffff:10.0.0.1")]);
        assert!(matches!(d, Decision::DeniedHost(_)), "got: {d:?}");
    }

    #[test]
    fn default_policy_allows_public_ip() {
        let p = OutboundPolicy::default();
        let d = p.check("", 443, &[ip("1.1.1.1")]);
        assert_eq!(d, Decision::Allow(ip("1.1.1.1")));
    }

    #[test]
    fn default_policy_blocks_non_80_443_ports() {
        let p = OutboundPolicy::default();
        assert!(matches!(
            p.check("", 22, &[ip("1.1.1.1")]),
            Decision::DeniedPort(22)
        ));
        assert!(matches!(
            p.check("", 25, &[ip("1.1.1.1")]),
            Decision::DeniedPort(25)
        ));
        assert!(matches!(
            p.check("", 8080, &[ip("1.1.1.1")]),
            Decision::DeniedPort(8080)
        ));
    }

    #[test]
    fn default_policy_allows_80_and_443() {
        let p = OutboundPolicy::default();
        for port in [80, 443] {
            assert!(matches!(
                p.check("", port, &[ip("1.1.1.1")]),
                Decision::Allow(_)
            ));
        }
    }

    #[test]
    fn extend_allowed_ports_works() {
        let p = OutboundPolicy::default().extend_allowed_ports([22, 587]);
        assert!(matches!(
            p.check("", 22, &[ip("1.1.1.1")]),
            Decision::Allow(_)
        ));
        assert!(matches!(
            p.check("", 587, &[ip("1.1.1.1")]),
            Decision::Allow(_)
        ));
        // Default ports still allowed.
        assert!(matches!(
            p.check("", 443, &[ip("1.1.1.1")]),
            Decision::Allow(_)
        ));
        // Unlisted port still denied.
        assert!(matches!(
            p.check("", 8080, &[ip("1.1.1.1")]),
            Decision::DeniedPort(8080)
        ));
    }

    #[test]
    fn empty_port_list_means_unrestricted() {
        let p = OutboundPolicy::default().with_allowed_ports(Vec::new());
        assert!(matches!(
            p.check("", 8080, &[ip("1.1.1.1")]),
            Decision::Allow(_)
        ));
        assert!(matches!(
            p.check("", 22, &[ip("1.1.1.1")]),
            Decision::Allow(_)
        ));
    }

    #[test]
    fn permissive_policy_admits_everything() {
        let p = OutboundPolicy::permissive();
        assert!(matches!(
            p.check("", 22, &[ip("127.0.0.1")]),
            Decision::Allow(_)
        ));
        assert!(matches!(p.check("", 0, &[ip("::1")]), Decision::Allow(_)));
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
            p.check("", 443, &[ip("127.0.0.1")]),
            Decision::Allow(_)
        ));
        // Custom rule still fires.
        assert!(matches!(
            p.check("", 443, &[ip("198.51.100.42")]),
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
        let d = p.check("", 443, &resolved);
        assert_eq!(d, Decision::DeniedHost(ip("10.0.0.1")));
    }

    #[test]
    fn unresolvable_host_denied_by_default() {
        let p = OutboundPolicy::default();
        assert_eq!(p.check("", 443, &[]), Decision::UnresolvableHost);
    }

    #[test]
    fn allow_returns_first_resolved_ip() {
        let p = OutboundPolicy::default();
        let resolved = [ip("1.1.1.1"), ip("8.8.8.8")];
        assert_eq!(p.check("", 443, &resolved), Decision::Allow(ip("1.1.1.1")));
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

    // ----- HostPattern parsing -----

    #[test]
    fn host_pattern_rejects_empty() {
        assert!(HostPattern::parse("").is_err());
        assert!(HostPattern::parse("   ").is_err());
    }

    #[test]
    fn host_pattern_rejects_embedded_wildcard() {
        assert!(HostPattern::parse("foo.*.bar").is_err());
        assert!(HostPattern::parse("*").is_err()); // bare wildcard
        assert!(HostPattern::parse("*.").is_err());
    }

    #[test]
    fn host_pattern_rejects_invalid_label_chars() {
        assert!(HostPattern::parse("foo bar.com").is_err());
        assert!(HostPattern::parse("under_score.com").is_err());
        assert!(HostPattern::parse("-foo.com").is_err());
        assert!(HostPattern::parse("foo-.com").is_err());
    }

    #[test]
    fn host_pattern_rejects_consecutive_dots() {
        assert!(HostPattern::parse("foo..com").is_err());
    }

    #[test]
    fn host_pattern_apex_matches_self_and_subdomains() {
        let p = HostPattern::parse("example.com").unwrap();
        assert!(p.matches("example.com"));
        assert!(p.matches("foo.example.com"));
        assert!(p.matches("a.b.c.example.com"));
        // Boundary check: evilexample.com must NOT match.
        assert!(!p.matches("evilexample.com"));
        assert!(!p.matches("example.com.evil.com"));
    }

    #[test]
    fn host_pattern_strict_subdomain_excludes_apex() {
        let p = HostPattern::parse("*.example.com").unwrap();
        assert!(!p.matches("example.com"));
        assert!(p.matches("foo.example.com"));
        assert!(p.matches("a.b.example.com"));
    }

    #[test]
    fn host_pattern_is_case_insensitive() {
        let p = HostPattern::parse("Example.COM").unwrap();
        assert!(p.matches("example.com"));
        assert!(p.matches("FOO.example.com"));
        assert!(p.matches("FOO.EXAMPLE.COM"));
    }

    #[test]
    fn host_pattern_strips_trailing_dots() {
        let p = HostPattern::parse("example.com.").unwrap();
        assert!(p.matches("example.com"));
        assert!(p.matches("example.com."));
    }

    // ----- hostname allow/deny pipeline -----

    #[test]
    fn hostname_denylist_blocks_match() {
        let mut p = OutboundPolicy::permissive();
        p.extend_blocked_hostnames(["badsite.example"]).unwrap();
        let d = p.check("badsite.example", 443, &[ip("1.1.1.1")]);
        assert_eq!(d, Decision::DeniedHostname);
        // Subdomain also blocked.
        let d = p.check("api.badsite.example", 443, &[ip("1.1.1.1")]);
        assert_eq!(d, Decision::DeniedHostname);
    }

    #[test]
    fn hostname_denylist_takes_precedence_over_allowlist() {
        let mut p = OutboundPolicy::permissive();
        p.extend_allowed_hostnames(["*.example.com"]).unwrap();
        p.extend_blocked_hostnames(["bad.example.com"]).unwrap();
        // Subdomain allowed by allowlist, but explicitly denied.
        let d = p.check("bad.example.com", 443, &[ip("1.1.1.1")]);
        assert_eq!(d, Decision::DeniedHostname);
    }

    #[test]
    fn hostname_allowlist_blocks_non_match() {
        let mut p = OutboundPolicy::permissive();
        p.extend_allowed_hostnames(["example.com"]).unwrap();
        let d = p.check("other.example.org", 443, &[ip("1.1.1.1")]);
        assert_eq!(d, Decision::HostnameNotAllowed);
    }

    #[test]
    fn hostname_allowlist_admits_match() {
        let mut p = OutboundPolicy::permissive();
        p.extend_allowed_hostnames(["*.cdn.example.net", "api.example.com"])
            .unwrap();
        let d = p.check("foo.cdn.example.net", 443, &[ip("1.1.1.1")]);
        assert_eq!(d, Decision::Allow(ip("1.1.1.1")));
        let d = p.check("api.example.com", 443, &[ip("1.1.1.1")]);
        assert_eq!(d, Decision::Allow(ip("1.1.1.1")));
    }

    #[test]
    fn literal_ip_host_skips_hostname_gate() {
        // When the operator's allowlist is `example.com` and the
        // client CONNECTs to a literal IP (no SNI / DNS involved),
        // the hostname gate must NOT fire — only the CIDR check
        // matters for IP-literal traffic. (Operator-style: use the
        // CIDR blocklist to control IP-literal access.)
        let mut p = OutboundPolicy::default();
        p.extend_allowed_hostnames(["example.com"]).unwrap();
        // Public IP literal — hostname gate skipped; CIDR allows it;
        // port allowed.
        let d = p.check("1.1.1.1", 443, &[ip("1.1.1.1")]);
        assert_eq!(d, Decision::Allow(ip("1.1.1.1")));
    }

    #[test]
    fn empty_hostname_skips_gate() {
        // Caller passes "" when there's no hostname (literal IP path).
        let mut p = OutboundPolicy::permissive();
        p.extend_allowed_hostnames(["example.com"]).unwrap();
        // Empty host means "no hostname policy applies" — the literal-
        // IP branch in check_hostname returns None.
        let d = p.check("", 443, &[ip("1.1.1.1")]);
        assert_eq!(d, Decision::Allow(ip("1.1.1.1")));
    }

    #[test]
    fn port_check_runs_before_hostname() {
        // Disallowed port should win over a hostname allow.
        let mut p = OutboundPolicy::default();
        p.extend_allowed_hostnames(["example.com"]).unwrap();
        let d = p.check("example.com", 22, &[ip("1.1.1.1")]);
        assert_eq!(d, Decision::DeniedPort(22));
    }

    #[test]
    fn extend_allowed_hostnames_propagates_parse_error() {
        let mut p = OutboundPolicy::permissive();
        assert!(p.extend_allowed_hostnames(["bad pattern!!"]).is_err());
    }
}
