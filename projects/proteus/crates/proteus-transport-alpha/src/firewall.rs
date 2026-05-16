//! Coarse-grained IP allow/deny firewall layer.
//!
//! This runs **before** the per-IP rate limiter and proof-of-work check.
//! Use it for:
//! - Blocking known-bad source CIDRs (Tor exits, abuse-tracker lists,
//!   geofence wholesale-blocks).
//! - Restricting access to an allowlist of operator IPs / management
//!   networks (useful for early closed-beta deployments).
//!
//! Semantics — evaluated in this order, first match wins:
//! 1. If `deny_cidrs` matches → **deny**.
//! 2. Else if `allow_cidrs` is non-empty and matches → **allow**.
//! 3. Else if `allow_cidrs` is non-empty and DOES NOT match → **deny**.
//! 4. Else (no allowlist configured) → **allow**.
//!
//! Denied connections are still byte-spliced to `cover_endpoint` so an
//! attacker cannot distinguish "you're blocked" from a generic HTTPS
//! proxy. This preserves the REALITY-grade indistinguishability
//! property of the rest of the stack.
//!
//! CIDR parsing is hand-rolled (zero new dependencies) and handles
//! both v4 and v6. `0.0.0.0/0` and `::/0` work and mean "everything".
//!
//! The data structure is a flat `Vec` — fine up to a few thousand
//! rules per direction. Operators with larger lists should prefer a
//! firewall (nftables / pf) in front of the binary.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::str::FromStr;

/// One CIDR rule (v4 or v6).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CidrRule {
    /// IPv4 network: (address, mask-length in bits).
    V4(Ipv4Addr, u8),
    /// IPv6 network: (address, mask-length in bits).
    V6(Ipv6Addr, u8),
}

impl CidrRule {
    /// Does this rule cover `peer`?
    #[must_use]
    pub fn matches(&self, peer: IpAddr) -> bool {
        match (self, peer) {
            (CidrRule::V4(net, prefix), IpAddr::V4(addr)) => v4_prefix_match(*net, *prefix, addr),
            (CidrRule::V6(net, prefix), IpAddr::V6(addr)) => v6_prefix_match(*net, *prefix, addr),
            _ => false, // family mismatch — never matches
        }
    }
}

impl FromStr for CidrRule {
    type Err = String;

    /// Parse a `host/prefix` string. Accepts bare addresses
    /// (interpreted as `/32` for v4 or `/128` for v6) for ergonomics.
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let (host_part, prefix_part) = match s.find('/') {
            Some(idx) => (&s[..idx], Some(&s[idx + 1..])),
            None => (s, None),
        };
        let ip: IpAddr = host_part
            .parse()
            .map_err(|e| format!("invalid IP {host_part:?}: {e}"))?;
        match (ip, prefix_part) {
            (IpAddr::V4(addr), Some(p)) => {
                let prefix: u8 = p.parse().map_err(|e| format!("invalid prefix /{p}: {e}"))?;
                if prefix > 32 {
                    return Err(format!("v4 prefix out of range: /{prefix}"));
                }
                Ok(CidrRule::V4(canonicalize_v4(addr, prefix), prefix))
            }
            (IpAddr::V4(addr), None) => Ok(CidrRule::V4(addr, 32)),
            (IpAddr::V6(addr), Some(p)) => {
                let prefix: u8 = p.parse().map_err(|e| format!("invalid prefix /{p}: {e}"))?;
                if prefix > 128 {
                    return Err(format!("v6 prefix out of range: /{prefix}"));
                }
                Ok(CidrRule::V6(canonicalize_v6(addr, prefix), prefix))
            }
            (IpAddr::V6(addr), None) => Ok(CidrRule::V6(addr, 128)),
        }
    }
}

fn v4_prefix_match(net: Ipv4Addr, prefix: u8, peer: Ipv4Addr) -> bool {
    if prefix == 0 {
        return true;
    }
    let mask: u32 = if prefix == 32 {
        u32::MAX
    } else {
        u32::MAX << (32 - prefix)
    };
    (u32::from(peer) & mask) == (u32::from(net) & mask)
}

fn v6_prefix_match(net: Ipv6Addr, prefix: u8, peer: Ipv6Addr) -> bool {
    if prefix == 0 {
        return true;
    }
    let mask: u128 = if prefix == 128 {
        u128::MAX
    } else {
        u128::MAX << (128 - prefix)
    };
    (u128::from(peer) & mask) == (u128::from(net) & mask)
}

fn canonicalize_v4(addr: Ipv4Addr, prefix: u8) -> Ipv4Addr {
    if prefix == 0 {
        return Ipv4Addr::new(0, 0, 0, 0);
    }
    let mask: u32 = if prefix == 32 {
        u32::MAX
    } else {
        u32::MAX << (32 - prefix)
    };
    Ipv4Addr::from(u32::from(addr) & mask)
}

fn canonicalize_v6(addr: Ipv6Addr, prefix: u8) -> Ipv6Addr {
    if prefix == 0 {
        return Ipv6Addr::UNSPECIFIED;
    }
    let mask: u128 = if prefix == 128 {
        u128::MAX
    } else {
        u128::MAX << (128 - prefix)
    };
    Ipv6Addr::from(u128::from(addr) & mask)
}

/// Bundle of allow + deny rules. Empty by default — admits everything.
#[derive(Debug, Clone, Default)]
pub struct Firewall {
    allow: Vec<CidrRule>,
    deny: Vec<CidrRule>,
}

impl Firewall {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Parse a list of strings into [`CidrRule`] and add to the
    /// allowlist. Returns an error on the first invalid string.
    pub fn extend_allow<I, S>(&mut self, rules: I) -> Result<(), String>
    where
        I: IntoIterator<Item = S>,
        S: AsRef<str>,
    {
        for s in rules {
            self.allow.push(s.as_ref().parse()?);
        }
        Ok(())
    }

    /// As [`Self::extend_allow`] but for the denylist.
    pub fn extend_deny<I, S>(&mut self, rules: I) -> Result<(), String>
    where
        I: IntoIterator<Item = S>,
        S: AsRef<str>,
    {
        for s in rules {
            self.deny.push(s.as_ref().parse()?);
        }
        Ok(())
    }

    /// Apply the firewall policy. `true` = admit.
    ///
    /// Order: deny rules win over allow rules. An empty allowlist
    /// means "no allowlist policy" (admit unless denied); a non-empty
    /// allowlist that doesn't match means "denied".
    #[must_use]
    pub fn admit(&self, peer: IpAddr) -> bool {
        if self.deny.iter().any(|r| r.matches(peer)) {
            return false;
        }
        if self.allow.is_empty() {
            return true;
        }
        self.allow.iter().any(|r| r.matches(peer))
    }

    /// Number of rules (sum of allow + deny). Useful for tests and
    /// startup logging.
    #[must_use]
    pub fn rule_count(&self) -> usize {
        self.allow.len() + self.deny.len()
    }

    /// True if at least one rule is configured. Empty firewalls are
    /// effectively no-ops on the hot path.
    #[must_use]
    pub fn is_active(&self) -> bool {
        !self.allow.is_empty() || !self.deny.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn p(s: &str) -> CidrRule {
        s.parse().unwrap()
    }

    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    #[test]
    fn v4_exact_match() {
        let r = p("192.0.2.5/32");
        assert!(r.matches(ip("192.0.2.5")));
        assert!(!r.matches(ip("192.0.2.6")));
    }

    #[test]
    fn v4_subnet_match() {
        let r = p("192.0.2.0/24");
        assert!(r.matches(ip("192.0.2.0")));
        assert!(r.matches(ip("192.0.2.255")));
        assert!(!r.matches(ip("192.0.3.0")));
    }

    #[test]
    fn v4_zero_prefix_matches_everything() {
        let r = p("0.0.0.0/0");
        assert!(r.matches(ip("1.2.3.4")));
        assert!(r.matches(ip("198.51.100.255")));
    }

    #[test]
    fn v4_bare_address_is_slash_32() {
        let r = p("198.51.100.7");
        assert!(r.matches(ip("198.51.100.7")));
        assert!(!r.matches(ip("198.51.100.8")));
    }

    #[test]
    fn v6_loopback_match() {
        let r = p("::1/128");
        assert!(r.matches(ip("::1")));
        assert!(!r.matches(ip("::2")));
    }

    #[test]
    fn v6_subnet_match() {
        let r = p("2001:db8::/32");
        assert!(r.matches(ip("2001:db8::1")));
        assert!(r.matches(ip("2001:db8:dead:beef::1")));
        assert!(!r.matches(ip("2001:db9::1")));
    }

    #[test]
    fn v6_zero_prefix_matches_everything() {
        let r = p("::/0");
        assert!(r.matches(ip("::1")));
        assert!(r.matches(ip("2001:db8::1")));
    }

    #[test]
    fn family_mismatch_never_matches() {
        let v4 = p("0.0.0.0/0");
        let v6 = p("::/0");
        assert!(!v4.matches(ip("::1")));
        assert!(!v6.matches(ip("1.2.3.4")));
    }

    #[test]
    fn rejects_invalid_prefix() {
        assert!("1.2.3.4/33".parse::<CidrRule>().is_err());
        assert!("::1/129".parse::<CidrRule>().is_err());
        assert!("1.2.3/24".parse::<CidrRule>().is_err());
        assert!("not-an-ip/24".parse::<CidrRule>().is_err());
    }

    #[test]
    fn firewall_empty_admits_everything() {
        let fw = Firewall::new();
        assert!(fw.admit(ip("1.2.3.4")));
        assert!(fw.admit(ip("::1")));
        assert!(!fw.is_active());
    }

    #[test]
    fn firewall_deny_overrides_allow() {
        let mut fw = Firewall::new();
        fw.extend_allow(["192.0.2.0/24"]).unwrap();
        fw.extend_deny(["192.0.2.42/32"]).unwrap();
        assert!(fw.admit(ip("192.0.2.1")));
        assert!(!fw.admit(ip("192.0.2.42"))); // denied even though allowed
        assert!(!fw.admit(ip("203.0.113.1"))); // outside allowlist
        assert!(fw.is_active());
    }

    #[test]
    fn firewall_allowlist_only() {
        let mut fw = Firewall::new();
        fw.extend_allow(["10.0.0.0/8", "2001:db8::/32"]).unwrap();
        assert!(fw.admit(ip("10.1.2.3")));
        assert!(fw.admit(ip("2001:db8::1")));
        assert!(!fw.admit(ip("8.8.8.8")));
        assert!(!fw.admit(ip("::1")));
    }

    #[test]
    fn firewall_denylist_only() {
        let mut fw = Firewall::new();
        fw.extend_deny(["192.0.2.0/24", "2001:db8::/32"]).unwrap();
        assert!(!fw.admit(ip("192.0.2.1")));
        assert!(!fw.admit(ip("2001:db8::1")));
        assert!(fw.admit(ip("10.0.0.1")));
        assert!(fw.admit(ip("::1")));
    }

    #[test]
    fn firewall_extend_allow_propagates_parse_error() {
        let mut fw = Firewall::new();
        let r = fw.extend_allow(["bogus/24"]);
        assert!(r.is_err());
    }
}
