//! Offline IP-reputation classifier for Proteus server preflight.
//!
//! ## Problem this solves
//!
//! 2026 GFW threat-intel main lines 1 + 4: the Geedge/Tiangou
//! commercial DPI maintains a **cross-deployment shared blocklist**
//! of VPN/proxy/Tor exit IPs. An IP burned in (say) the Myanmar
//! deployment is propagated to all Geedge customers including
//! mainland Chinese provincial GFW supplements. Operators who buy
//! a fresh VPS may unknowingly receive an IP that's been in
//! commercial-proxy rotation for a year — already on the blocklist,
//! already silently degraded at the GFW.
//!
//! This module does what we CAN do offline at preflight time: flag
//! IPs that fall in classes well-known to be over-represented on
//! such shared blocklists. We CANNOT claim "this IP is blocked
//! right now" — no public authoritative GFW blocklist exists, and
//! probing the GFW from outside is not a deploy-time check. What
//! we CAN do is surface "this IP is in a class the GFW preferentially
//! collects from", so the operator makes an informed deployment
//! decision rather than discovering breakage after the first user
//! report.
//!
//! ## Classification taxonomy
//!
//! - **`Special`** — RFC 5735 / 6890 special-use ranges (loopback,
//!   multicast, link-local, documentation ranges, IPv6 ULA, etc).
//!   Binding a public proxy to one of these is a **config error**:
//!   either the operator wrote `127.0.0.1` thinking it was the public
//!   IP, or the listener is bound to `0.0.0.0` and the discovered
//!   public IP is wrong. → **FAIL**.
//!
//! - **`LikelyCommercialCloud { provider }`** — IP falls in a CIDR
//!   range matching a major cloud provider known to be heavily used
//!   by commercial proxy services. The Geedge shared blocklist
//!   over-samples these ranges because they're cheap to enumerate
//!   (the provider's published IP ranges) and yield high precision
//!   per probe. → **WARN** (operator may proceed if the VPS is new,
//!   but should know the IP is in a high-risk class).
//!
//! - **`LikelyResidential`** — IP doesn't match any commercial-cloud
//!   range and doesn't match a special-use range. We're conservative:
//!   the absence of a cloud match doesn't *prove* residential, but
//!   it's the best signal we have offline. → **PASS**.
//!
//! - **`OperatorBlocked { reason }`** — operator supplied an explicit
//!   blocklist (e.g. their own known-burned ranges from past
//!   deployments) and the IP matches one of them. → **FAIL**.
//!
//! ## Why offline-only is the right scope
//!
//! - **No public Tiangou feed exists.** Any "live GFW check" would
//!   itself reveal the operator's interest in this IP to whatever
//!   service we queried.
//! - **External lookups at preflight time leak metadata.** An HTTP
//!   probe to "is-this-ip-burned.example" before service start would
//!   tie the deploying operator's source-IP to the about-to-be-
//!   deployed proxy IP. That's an operator-OPSEC problem the
//!   preflight tool MUST NOT create.
//! - **The operator can layer on more checks separately.** If they
//!   want to plug in a paid IP-reputation API, they do it outside
//!   the preflight (e.g. in their Terraform/Ansible). We provide the
//!   `operator-blocklist` hook so the result of that external check
//!   can be fed back as a static file.
//!
//! ## Honest limitations
//!
//! - The cloud-prefix table is **not exhaustive**. Smaller cloud
//!   providers (Hetzner-derivative resellers, regional VPS shops,
//!   bulletproof hosting) won't match. Absence of a WARN does NOT
//!   mean "definitely clean".
//! - The Geedge blocklist composition is partly inferred from OSINT +
//!   community reports, not from a leaked authoritative list. Our
//!   `"high-risk cloud"` classification is a heuristic, not a verified
//!   property of the IP — see threat-intel main line 1 caveats.
//! - For the user's stated scenario ("we have a clean VPS, personal
//!   direct-dial node, not relay"), the preflight catches the most
//!   common operator mistakes (wrong-bind detection, IP from a
//!   well-known overpopulated range) but cannot replace ongoing
//!   measurement.

use std::fmt;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

/// Result of classifying a single IP.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Classification {
    pub ip: IpAddr,
    pub class: IpClass,
    /// One-line human rationale referencing the rule that fired.
    pub rationale: String,
}

/// Reputation class for a single IP.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum IpClass {
    /// RFC 5735 / 6890 special-use range. Binding a public proxy
    /// here is a config error. **FAIL**.
    Special { kind: &'static str },
    /// IP matches a commercial-cloud CIDR known to be over-sampled
    /// on shared GFW-class blocklists. **WARN**.
    LikelyCommercialCloud { provider: &'static str },
    /// No special-use match, no cloud-prefix match. Best available
    /// signal that the IP is residential or on a less-collected
    /// provider. **PASS**.
    LikelyResidential,
    /// Operator's explicit blocklist matched. **FAIL**.
    OperatorBlocked { reason: String },
}

impl IpClass {
    /// Map the class to a [`Severity`] for the preflight report.
    #[must_use]
    pub fn severity(&self) -> Severity {
        match self {
            IpClass::Special { .. } | IpClass::OperatorBlocked { .. } => Severity::Fail,
            IpClass::LikelyCommercialCloud { .. } => Severity::Warn,
            IpClass::LikelyResidential => Severity::Pass,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Severity {
    Pass,
    Warn,
    Fail,
}

impl fmt::Display for Severity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Severity::Pass => "PASS",
            Severity::Warn => "WARN",
            Severity::Fail => "FAIL",
        })
    }
}

/// A single operator-supplied watchlist rule.
#[derive(Debug, Clone)]
pub struct WatchlistRule {
    pub cidr: Cidr,
    pub reason: String,
}

/// Minimal CIDR type — small enough that pulling in the `ipnet` crate
/// would be over-engineering for the dozens of prefixes we match.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Cidr {
    pub net: IpAddr,
    pub prefix_len: u8,
}

impl Cidr {
    pub fn contains(&self, ip: &IpAddr) -> bool {
        match (self.net, ip) {
            (IpAddr::V4(net), IpAddr::V4(target)) => {
                let prefix = self.prefix_len.min(32);
                let net_bits = u32::from(net);
                let target_bits = u32::from(*target);
                let shift = 32u32.saturating_sub(prefix as u32);
                if shift == 32 {
                    return true; // /0 — match all
                }
                let mask = u32::MAX.wrapping_shl(shift);
                (net_bits & mask) == (target_bits & mask)
            }
            (IpAddr::V6(net), IpAddr::V6(target)) => {
                let prefix = self.prefix_len.min(128);
                let net_bits = u128::from(net);
                let target_bits = u128::from(*target);
                let shift = 128u32.saturating_sub(prefix as u32);
                if shift == 128 {
                    return true;
                }
                let mask = u128::MAX.wrapping_shl(shift);
                (net_bits & mask) == (target_bits & mask)
            }
            _ => false, // family mismatch
        }
    }
}

impl std::str::FromStr for Cidr {
    type Err = CidrParseError;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let (ip_str, len_str) = s
            .split_once('/')
            .ok_or_else(|| CidrParseError::Format(s.to_string()))?;
        let net: IpAddr = ip_str
            .parse()
            .map_err(|_| CidrParseError::BadIp(ip_str.to_string()))?;
        let prefix_len: u8 = len_str
            .parse()
            .map_err(|_| CidrParseError::BadPrefix(len_str.to_string()))?;
        let max = if net.is_ipv4() { 32 } else { 128 };
        if prefix_len > max {
            return Err(CidrParseError::PrefixTooLarge {
                got: prefix_len,
                max,
            });
        }
        Ok(Cidr { net, prefix_len })
    }
}

#[derive(thiserror::Error, Debug)]
pub enum CidrParseError {
    #[error("not a CIDR (missing /): {0}")]
    Format(String),
    #[error("bad IP literal: {0}")]
    BadIp(String),
    #[error("bad prefix length: {0}")]
    BadPrefix(String),
    #[error("prefix length {got} > {max}")]
    PrefixTooLarge { got: u8, max: u8 },
}

/// Curated table of (Cidr literal, provider name) for cloud ranges
/// well-known to be over-sampled on commercial-proxy blocklists.
///
/// **This table is intentionally not exhaustive.** It targets the
/// "top 20 hits" — providers where community-reported VPN/proxy
/// burn rates are documented and where the published IP ranges
/// make enumeration cheap for the adversary. A non-match here is
/// NOT a clean bill of health; it just means the deployment isn't
/// hitting a known high-density target.
///
/// Sources:
/// - DigitalOcean published ranges (`https://digitalocean.com/geo/google.csv`)
/// - Vultr published ranges (`https://geofeed.constant.com/`)
/// - Linode published ranges (`https://geoip.linode.com/`)
/// - Hetzner Cloud (community-documented; not a comprehensive feed)
/// - OVH (subset; OVH has hundreds of /16s, we ship a fraction)
///
/// These were sampled rather than enumerated. Adding the full
/// provider feeds is a future deliverable that needs an offline
/// data-fetch pipeline (not run at user runtime — leaks metadata).
///
/// The hard truth: shipping a *static* table guarantees staleness.
/// A future iteration should add a separate `proteus-server
/// update-ip-feed` subcommand that the operator runs on a *non-
/// production* host, producing a versioned blob the production
/// server consumes. That's deferred until we have a clean offline
/// data pipeline.
const CLOUD_PREFIX_TABLE: &[(&str, &str)] = &[
    // DigitalOcean — heavily used by SS / V2Ray budget deployments,
    // historically the #1 burn target. Sample of widely-cited /14 - /16s.
    ("104.131.0.0/16", "DigitalOcean"),
    ("104.236.0.0/16", "DigitalOcean"),
    ("138.197.0.0/16", "DigitalOcean"),
    ("138.68.0.0/16", "DigitalOcean"),
    ("139.59.0.0/16", "DigitalOcean"),
    ("142.93.0.0/16", "DigitalOcean"),
    ("143.198.0.0/16", "DigitalOcean"),
    ("159.65.0.0/16", "DigitalOcean"),
    ("159.89.0.0/16", "DigitalOcean"),
    ("161.35.0.0/16", "DigitalOcean"),
    ("164.90.0.0/16", "DigitalOcean"),
    ("164.92.0.0/16", "DigitalOcean"),
    ("167.71.0.0/16", "DigitalOcean"),
    ("167.99.0.0/16", "DigitalOcean"),
    ("178.62.0.0/16", "DigitalOcean"),
    ("188.166.0.0/16", "DigitalOcean"),
    ("206.189.0.0/16", "DigitalOcean"),
    ("209.97.128.0/17", "DigitalOcean"),
    ("64.225.0.0/16", "DigitalOcean"),
    ("68.183.0.0/16", "DigitalOcean"),
    // Vultr — second-tier budget VPS, similar burn profile.
    ("45.32.0.0/16", "Vultr"),
    ("45.63.0.0/16", "Vultr"),
    ("45.76.0.0/16", "Vultr"),
    ("45.77.0.0/16", "Vultr"),
    ("66.42.32.0/19", "Vultr"),
    ("104.156.224.0/19", "Vultr"),
    ("108.61.0.0/16", "Vultr"),
    ("136.244.0.0/16", "Vultr"),
    ("139.180.128.0/17", "Vultr"),
    ("140.82.0.0/18", "Vultr"),
    ("149.28.0.0/16", "Vultr"),
    ("155.138.128.0/17", "Vultr"),
    ("199.247.0.0/16", "Vultr"),
    ("207.246.64.0/18", "Vultr"),
    ("207.148.0.0/16", "Vultr"),
    // Linode (now Akamai Cloud).
    ("45.33.0.0/16", "Linode/Akamai"),
    ("45.56.64.0/18", "Linode/Akamai"),
    ("45.79.0.0/16", "Linode/Akamai"),
    ("50.116.0.0/16", "Linode/Akamai"),
    ("66.175.208.0/20", "Linode/Akamai"),
    ("69.164.192.0/19", "Linode/Akamai"),
    ("96.126.96.0/19", "Linode/Akamai"),
    ("139.144.0.0/16", "Linode/Akamai"),
    ("172.104.0.0/15", "Linode/Akamai"),
    ("173.255.192.0/18", "Linode/Akamai"),
    ("192.155.80.0/20", "Linode/Akamai"),
    ("194.195.112.0/20", "Linode/Akamai"),
    ("198.58.96.0/19", "Linode/Akamai"),
    ("213.52.128.0/18", "Linode/Akamai"),
    // Hetzner Cloud — popular with European users for VPN.
    ("46.4.0.0/16", "Hetzner"),
    ("78.46.0.0/16", "Hetzner"),
    ("88.198.0.0/16", "Hetzner"),
    ("116.202.0.0/16", "Hetzner"),
    ("136.243.0.0/16", "Hetzner"),
    ("142.132.128.0/17", "Hetzner"),
    ("144.76.0.0/16", "Hetzner"),
    ("148.251.0.0/16", "Hetzner"),
    ("159.69.0.0/16", "Hetzner"),
    ("167.235.0.0/16", "Hetzner"),
    ("168.119.0.0/16", "Hetzner"),
    ("176.9.0.0/16", "Hetzner"),
    ("178.63.0.0/16", "Hetzner"),
    ("188.40.0.0/16", "Hetzner"),
    ("213.133.96.0/19", "Hetzner"),
    ("213.239.192.0/18", "Hetzner"),
    // OVH (sample — full OVH allocations are vast).
    ("51.38.0.0/16", "OVH"),
    ("51.79.0.0/16", "OVH"),
    ("51.81.0.0/16", "OVH"),
    ("51.83.0.0/16", "OVH"),
    ("51.89.0.0/16", "OVH"),
    ("51.91.0.0/16", "OVH"),
    ("51.195.0.0/16", "OVH"),
    ("51.222.0.0/16", "OVH"),
    ("51.255.0.0/16", "OVH"),
    ("54.36.0.0/16", "OVH"),
    ("54.37.0.0/16", "OVH"),
    ("54.38.0.0/16", "OVH"),
    ("54.39.0.0/16", "OVH"),
    ("87.98.128.0/17", "OVH"),
    ("141.94.0.0/16", "OVH"),
    ("141.95.0.0/16", "OVH"),
    ("142.44.128.0/17", "OVH"),
    ("145.239.0.0/16", "OVH"),
    ("147.135.0.0/16", "OVH"),
    ("149.202.0.0/16", "OVH"),
    ("151.80.0.0/16", "OVH"),
    ("164.132.0.0/16", "OVH"),
    ("167.114.0.0/16", "OVH"),
    ("176.31.0.0/16", "OVH"),
    ("178.32.0.0/16", "OVH"),
    ("178.33.0.0/16", "OVH"),
    ("198.50.128.0/17", "OVH"),
    ("198.245.49.0/24", "OVH"),
    ("213.32.0.0/16", "OVH"),
    ("213.186.32.0/19", "OVH"),
    ("213.251.128.0/18", "OVH"),
    // RamNode, BandwagonHost, smaller bulletproof — known burn-heavy.
    ("23.226.224.0/19", "RamNode"),
    ("104.207.128.0/17", "BandwagonHost/IT7"),
    ("162.244.80.0/20", "BandwagonHost/IT7"),
    ("23.252.99.0/24", "BandwagonHost/IT7"),
];

/// Classify a single IP. Operator watchlist is consulted FIRST so
/// an explicit operator decision overrides any heuristic.
pub fn classify(ip: IpAddr, watchlist: &[WatchlistRule]) -> Classification {
    // 1. Operator watchlist — highest priority.
    for rule in watchlist {
        if rule.cidr.contains(&ip) {
            return Classification {
                ip,
                class: IpClass::OperatorBlocked {
                    reason: rule.reason.clone(),
                },
                rationale: format!(
                    "matches operator watchlist {}/{}: {}",
                    rule.cidr.net, rule.cidr.prefix_len, rule.reason
                ),
            };
        }
    }

    // 2. RFC 5735 / 6890 special-use ranges — config error.
    if let Some(kind) = special_use_kind(&ip) {
        return Classification {
            ip,
            class: IpClass::Special { kind },
            rationale: format!(
                "{ip} is a {kind} address (RFC 5735/6890) — binding a public proxy here is \
                 a config error (operator likely wrote the wrong address or `listen_alpha` is \
                 `0.0.0.0` with a misdetected public IP)"
            ),
        };
    }

    // 3. Commercial-cloud prefix table — likely Tiangou shared-blocklist sample.
    if let Some(provider) = match_cloud_provider(&ip) {
        return Classification {
            ip,
            class: IpClass::LikelyCommercialCloud { provider },
            rationale: format!(
                "{ip} falls in a published {provider} CIDR — \
                 commercial-proxy services concentrate here, the Geedge/Tiangou shared \
                 blocklist over-samples these ranges (threat-intel main line 1). A clean \
                 *individual* IP in this range may still work, but the IP class is high-risk; \
                 operators should plan for IP rotation under sustained censorship pressure"
            ),
        };
    }

    // 4. Best-available signal: residential / less-collected.
    Classification {
        ip,
        class: IpClass::LikelyResidential,
        rationale: format!(
            "{ip} did not match any special-use range or known commercial-cloud prefix in our \
             curated (non-exhaustive) table — best-available signal that the IP is residential \
             or on a less-collected provider"
        ),
    }
}

/// Recognize RFC 5735 / 6890 special-use ranges. Returns a short
/// label suitable for the rationale string.
pub fn special_use_kind(ip: &IpAddr) -> Option<&'static str> {
    match ip {
        IpAddr::V4(v4) => special_use_kind_v4(v4),
        IpAddr::V6(v6) => special_use_kind_v6(v6),
    }
}

fn special_use_kind_v4(ip: &Ipv4Addr) -> Option<&'static str> {
    if ip.is_loopback() {
        return Some("loopback (127.0.0.0/8)");
    }
    if ip.is_unspecified() {
        return Some("unspecified (0.0.0.0)");
    }
    if ip.is_link_local() {
        return Some("link-local (169.254.0.0/16)");
    }
    if ip.is_multicast() {
        return Some("multicast (224.0.0.0/4)");
    }
    if ip.is_broadcast() {
        return Some("broadcast (255.255.255.255)");
    }
    if ip.is_documentation() {
        return Some("documentation (192.0.2/24, 198.51.100/24, 203.0.113/24)");
    }
    if ip.is_private() {
        return Some("private (RFC 1918)");
    }
    let octets = ip.octets();
    // 100.64.0.0/10 — RFC 6598 (CGNAT). Not covered by is_private().
    if octets[0] == 100 && (octets[1] & 0xc0) == 64 {
        return Some("CGNAT (100.64.0.0/10, RFC 6598)");
    }
    // 192.0.0.0/24 — IETF protocol assignments
    if octets[0] == 192 && octets[1] == 0 && octets[2] == 0 {
        return Some("IETF protocol assignments (192.0.0.0/24)");
    }
    // 192.88.99.0/24 — 6to4 anycast (deprecated)
    if octets[0] == 192 && octets[1] == 88 && octets[2] == 99 {
        return Some("6to4 anycast (192.88.99.0/24, deprecated)");
    }
    // 198.18.0.0/15 — benchmark tests
    if octets[0] == 198 && (octets[1] == 18 || octets[1] == 19) {
        return Some("benchmark (198.18.0.0/15)");
    }
    // 240.0.0.0/4 — reserved
    if octets[0] >= 240 && !ip.is_broadcast() {
        return Some("reserved (240.0.0.0/4)");
    }
    None
}

fn special_use_kind_v6(ip: &Ipv6Addr) -> Option<&'static str> {
    if ip.is_loopback() {
        return Some("loopback (::1)");
    }
    if ip.is_unspecified() {
        return Some("unspecified (::)");
    }
    if ip.is_multicast() {
        return Some("multicast (ff00::/8)");
    }
    let segments = ip.segments();
    // Link-local fe80::/10
    if segments[0] & 0xffc0 == 0xfe80 {
        return Some("link-local (fe80::/10)");
    }
    // Unique-local fc00::/7
    if segments[0] & 0xfe00 == 0xfc00 {
        return Some("unique-local (fc00::/7, RFC 4193)");
    }
    // Documentation 2001:db8::/32
    if segments[0] == 0x2001 && segments[1] == 0x0db8 {
        return Some("documentation (2001:db8::/32, RFC 3849)");
    }
    None
}

/// Match against the curated [`CLOUD_PREFIX_TABLE`].
fn match_cloud_provider(ip: &IpAddr) -> Option<&'static str> {
    for (cidr_str, provider) in CLOUD_PREFIX_TABLE {
        let cidr: Cidr = cidr_str.parse().expect("static cloud table well-formed");
        if cidr.contains(ip) {
            return Some(provider);
        }
    }
    None
}

/// Load operator watchlist from a text file. Format: one entry per
/// line, `CIDR  reason text` (whitespace separated). `#` comments
/// and blank lines are skipped.
///
/// Example file:
/// ```text
/// # IPs we already burned in past deployments
/// 198.51.100.0/24  burned 2026-03 in deploy alpha
/// 203.0.113.42/32  reported broken by user X on 2026-04
/// ```
pub fn load_watchlist_from_file(
    path: &std::path::Path,
) -> Result<Vec<WatchlistRule>, WatchlistError> {
    let text =
        std::fs::read_to_string(path).map_err(|e| WatchlistError::Io(path.to_path_buf(), e))?;
    parse_watchlist(&text)
}

pub fn parse_watchlist(text: &str) -> Result<Vec<WatchlistRule>, WatchlistError> {
    let mut out = Vec::new();
    for (lineno, raw) in text.lines().enumerate() {
        let line = raw.split('#').next().unwrap_or("").trim();
        if line.is_empty() {
            continue;
        }
        let mut parts = line.splitn(2, char::is_whitespace);
        let cidr_part = parts.next().ok_or_else(|| WatchlistError::Format {
            line: lineno + 1,
            content: raw.to_string(),
        })?;
        let reason_part = parts.next().unwrap_or("").trim();
        let cidr: Cidr =
            cidr_part
                .parse()
                .map_err(|e: CidrParseError| WatchlistError::BadCidr {
                    line: lineno + 1,
                    content: raw.to_string(),
                    err: e.to_string(),
                })?;
        out.push(WatchlistRule {
            cidr,
            reason: reason_part.to_string(),
        });
    }
    Ok(out)
}

#[derive(thiserror::Error, Debug)]
pub enum WatchlistError {
    #[error("io reading {0}: {1}")]
    Io(std::path::PathBuf, std::io::Error),
    #[error("line {line}: bad CIDR ({err}) in: {content:?}")]
    BadCidr {
        line: usize,
        content: String,
        err: String,
    },
    #[error("line {line}: bad format in: {content:?}")]
    Format { line: usize, content: String },
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    #[test]
    fn cidr_contains_v4_handles_boundaries() {
        let c: Cidr = "10.0.0.0/8".parse().unwrap();
        assert!(c.contains(&ip("10.0.0.0")));
        assert!(c.contains(&ip("10.255.255.255")));
        assert!(c.contains(&ip("10.1.2.3")));
        assert!(!c.contains(&ip("11.0.0.0")));
        assert!(!c.contains(&ip("9.255.255.255")));

        // /32 = single host
        let host: Cidr = "1.2.3.4/32".parse().unwrap();
        assert!(host.contains(&ip("1.2.3.4")));
        assert!(!host.contains(&ip("1.2.3.5")));

        // /0 = match all
        let all: Cidr = "0.0.0.0/0".parse().unwrap();
        assert!(all.contains(&ip("8.8.8.8")));
        assert!(all.contains(&ip("203.0.113.7")));
    }

    #[test]
    fn cidr_contains_v6_handles_boundaries() {
        let c: Cidr = "2001:db8::/32".parse().unwrap();
        assert!(c.contains(&ip("2001:db8::1")));
        assert!(c.contains(&ip("2001:db8:ffff::1")));
        assert!(!c.contains(&ip("2001:db9::1")));
    }

    #[test]
    fn cidr_family_mismatch_never_contains() {
        let c: Cidr = "10.0.0.0/8".parse().unwrap();
        assert!(!c.contains(&ip("::1")));
    }

    #[test]
    fn classify_special_use_v4_fails() {
        let cls = classify(ip("127.0.0.1"), &[]);
        assert!(matches!(cls.class, IpClass::Special { .. }));
        assert_eq!(cls.class.severity(), Severity::Fail);
    }

    #[test]
    fn classify_cgnat_recognized_as_special() {
        let cls = classify(ip("100.64.1.1"), &[]);
        assert!(matches!(cls.class, IpClass::Special { .. }));
        assert!(cls.rationale.contains("CGNAT"));
    }

    #[test]
    fn classify_rfc1918_is_special() {
        for s in ["10.0.0.1", "172.16.0.1", "192.168.1.1"] {
            let cls = classify(ip(s), &[]);
            assert!(
                matches!(cls.class, IpClass::Special { .. }),
                "{s} should be special-use",
            );
        }
    }

    #[test]
    fn classify_unspecified_is_special() {
        let cls = classify(ip("0.0.0.0"), &[]);
        assert!(matches!(cls.class, IpClass::Special { .. }));
    }

    #[test]
    fn classify_known_digitalocean_ip_warns() {
        // 138.197.x.x is in the DO table.
        let cls = classify(ip("138.197.42.42"), &[]);
        assert!(matches!(
            cls.class,
            IpClass::LikelyCommercialCloud { provider } if provider == "DigitalOcean"
        ));
        assert_eq!(cls.class.severity(), Severity::Warn);
    }

    #[test]
    fn classify_known_vultr_ip_warns() {
        // 45.32.x.x is in the Vultr table.
        let cls = classify(ip("45.32.100.100"), &[]);
        assert!(matches!(
            cls.class,
            IpClass::LikelyCommercialCloud { provider } if provider == "Vultr"
        ));
    }

    #[test]
    fn classify_arbitrary_public_v4_is_likely_residential() {
        // 8.8.8.8 is Google but isn't in our cloud table (Google
        // isn't widely used for budget-VPN because of price).
        let cls = classify(ip("8.8.8.8"), &[]);
        assert!(matches!(cls.class, IpClass::LikelyResidential));
        assert_eq!(cls.class.severity(), Severity::Pass);
    }

    #[test]
    fn watchlist_overrides_residential_classification() {
        let watch = vec![WatchlistRule {
            cidr: "8.8.8.0/24".parse().unwrap(),
            reason: "operator says blocked".to_string(),
        }];
        let cls = classify(ip("8.8.8.8"), &watch);
        match cls.class {
            IpClass::OperatorBlocked { reason } => assert_eq!(reason, "operator says blocked"),
            other => panic!("expected OperatorBlocked, got {other:?}"),
        }
    }

    #[test]
    fn watchlist_overrides_cloud_classification_too() {
        // Operator watchlist beats the heuristic even when the
        // heuristic would only warn.
        let watch = vec![WatchlistRule {
            cidr: "138.197.0.0/16".parse().unwrap(),
            reason: "burned in past deploy".to_string(),
        }];
        let cls = classify(ip("138.197.42.42"), &watch);
        assert_eq!(cls.class.severity(), Severity::Fail);
    }

    #[test]
    fn parse_watchlist_skips_comments_and_blanks() {
        let text = "# header\n\
                    \n\
                    198.51.100.0/24  past burn\n\
                    # trailing comment\n\
                    203.0.113.42/32\n";
        let rules = parse_watchlist(text).unwrap();
        assert_eq!(rules.len(), 2);
        assert_eq!(rules[0].reason, "past burn");
        assert_eq!(rules[1].reason, "");
    }

    #[test]
    fn parse_watchlist_rejects_bad_cidr() {
        let err = parse_watchlist("not-a-cidr reason\n").unwrap_err();
        assert!(matches!(err, WatchlistError::BadCidr { line: 1, .. }));
    }

    #[test]
    fn ipv6_loopback_is_special() {
        let cls = classify(ip("::1"), &[]);
        assert!(matches!(cls.class, IpClass::Special { .. }));
    }

    #[test]
    fn ipv6_documentation_range_is_special() {
        let cls = classify(ip("2001:db8::1"), &[]);
        assert!(matches!(cls.class, IpClass::Special { .. }));
        assert!(cls.rationale.contains("documentation"));
    }

    #[test]
    fn cloud_table_all_entries_parse() {
        // Sanity: every static-table entry parses correctly. If a
        // typo sneaks into CLOUD_PREFIX_TABLE this test will fire
        // BEFORE any classify() call would.
        for (cidr_str, provider) in CLOUD_PREFIX_TABLE {
            let parsed: Cidr = cidr_str.parse().unwrap_or_else(|e| {
                panic!("CLOUD_PREFIX_TABLE has bad entry {cidr_str} ({provider}): {e}")
            });
            assert!(
                parsed.prefix_len <= 32,
                "table entry must be IPv4: {cidr_str}"
            );
        }
    }

    #[test]
    fn cloud_table_no_overlapping_providers_for_same_ip() {
        // Walk the table — for each entry, ensure no LATER entry
        // ALSO contains the network address. Helps catch accidental
        // double-listing under different provider names. (Same
        // provider on overlapping /16+/17 is fine, different
        // provider is the bug we want to catch.)
        for i in 0..CLOUD_PREFIX_TABLE.len() {
            let (cidr_i, prov_i) = CLOUD_PREFIX_TABLE[i];
            let net_i: Cidr = cidr_i.parse().unwrap();
            for (cidr_j, prov_j) in &CLOUD_PREFIX_TABLE[i + 1..] {
                let net_j: Cidr = cidr_j.parse().unwrap();
                if net_i.contains(&net_j.net) && prov_i != *prov_j {
                    panic!(
                        "cloud table overlap: {cidr_j} ({prov_j}) is inside {cidr_i} ({prov_i})"
                    );
                }
            }
        }
    }
}
