//! `proteus-server gencert` — emit a self-signed TLS cert + key pair
//! suitable for the `tls:` config block.
//!
//! For production you should replace these files with a Let's Encrypt
//! `fullchain.pem` + `privkey.pem`; the on-disk format is identical so
//! the swap is a no-op.

use std::fs;
use std::net::IpAddr;
use std::path::Path;

/// Iter-129: validate `--dns-name` BEFORE handing it to rcgen.
/// Pre-iter-129 rcgen accepted literally anything as a SAN string
/// — empty string, "...", "Hello World" all silently produced a
/// "successful" cert that no TLS client would ever validate. An
/// operator typing `gencert --dns-name vps.example..com` (typo:
/// double dot) saw "✓ TLS cert written" then every connect failed
/// with the opaque rustls error `NotValidForName` and no hint that
/// the cert itself was the problem.
///
/// Accept rules (must match TLS SAN semantics):
///   - IP literal: parses via `IpAddr::from_str` → embed as
///     SubjectAltName::IpAddress (we don't, but the operator
///     could re-mint with the right SAN type; here we just let
///     it through because rcgen's generate_simple_self_signed
///     auto-detects).
///   - DNS hostname: 1-253 chars total, each label 1-63 chars,
///     LDH (letters/digits/hyphens) per RFC 1035 §2.3.1, no
///     leading/trailing hyphen on labels, no empty labels
///     ("foo..bar" rejected), no leading/trailing dot
///     (wildcard `*.example.com` allowed as the leftmost label).
///
/// Rejection produces exit 2 (operator error) with a message
/// naming the specific class of failure so the operator can fix.
pub fn validate_dns_name(name: &str) -> Result<(), String> {
    if name.is_empty() {
        return Err(
            "--dns-name is empty. A TLS cert with no SAN won't validate \
             against any hostname or IP — every client connect fails with \
             NotValidForName. Provide either a hostname (`vps.example.com`) \
             or an IP literal (`203.0.113.42`)."
                .to_string(),
        );
    }
    if name.len() > 253 {
        return Err(format!(
            "--dns-name is {} chars; RFC 1035 caps DNS names at 253 chars",
            name.len()
        ));
    }
    // IP literal? Accept (rcgen detects + emits IPAddress SAN).
    if name.parse::<IpAddr>().is_ok() {
        return Ok(());
    }
    // Trim leading wildcard label `*.` once — allowed by RFC 6125
    // §6.4.3 for wildcard certs.
    let body = name.strip_prefix("*.").unwrap_or(name);
    if body.is_empty() {
        return Err(format!(
            "--dns-name {name:?} is just `*.` with no domain; provide a \
             real hostname after the wildcard label (e.g. `*.example.com`)"
        ));
    }
    if body.starts_with('.') || body.ends_with('.') {
        return Err(format!(
            "--dns-name {name:?} has a leading or trailing dot — TLS \
             clients reject this as an empty DNS label (RFC 1035 §3.1)"
        ));
    }
    for label in body.split('.') {
        if label.is_empty() {
            return Err(format!(
                "--dns-name {name:?} contains an empty label (consecutive \
                 dots — e.g. `vps.example..com` typo). RFC 1035 §3.1 \
                 forbids empty labels; every TLS client rejects this cert \
                 with NotValidForName."
            ));
        }
        if label.len() > 63 {
            return Err(format!(
                "--dns-name {name:?} contains label of {} chars; RFC 1035 \
                 §2.3.1 caps DNS labels at 63 chars",
                label.len()
            ));
        }
        if label.starts_with('-') || label.ends_with('-') {
            return Err(format!(
                "--dns-name {name:?} has a label starting or ending with \
                 a hyphen — RFC 1035 §2.3.1 LDH rule forbids this"
            ));
        }
        for c in label.chars() {
            if !(c.is_ascii_alphanumeric() || c == '-') {
                return Err(format!(
                    "--dns-name {name:?} contains non-LDH character \
                     {c:?} (RFC 1035 §2.3.1 allows only letters, digits, \
                     hyphens). Spaces, underscores, unicode all rejected \
                     by TLS clients with NotValidForName."
                ));
            }
        }
    }
    Ok(())
}

pub fn run(dns_name: &str, out_dir: &Path) -> Result<(), Box<dyn std::error::Error>> {
    // Iter-129: belt-and-braces. The CLI dispatcher in main.rs
    // calls validate_dns_name() up front (so it can exit 2 on
    // operator error), but we re-check here so any other caller
    // (a future test, a future scripting hook) can't bypass the
    // gate by going straight to gencert::run().
    validate_dns_name(dns_name).map_err(|e| -> Box<dyn std::error::Error> { e.into() })?;
    fs::create_dir_all(out_dir)?;
    let ck = rcgen::generate_simple_self_signed(vec![dns_name.to_string()])?;
    let cert_pem = ck.cert.pem();
    let key_pem = ck.key_pair.serialize_pem();
    let cert_path = out_dir.join("fullchain.pem");
    let key_path = out_dir.join("privkey.pem");
    fs::write(&cert_path, cert_pem)?;
    fs::write(&key_path, key_pem)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mut perm = fs::metadata(&key_path)?.permissions();
        perm.set_mode(0o600);
        fs::set_permissions(&key_path, perm)?;
        let mut cperm = fs::metadata(&cert_path)?.permissions();
        cperm.set_mode(0o644);
        fs::set_permissions(&cert_path, cperm)?;
    }
    println!("✓ TLS cert written to {}", cert_path.display());
    println!("✓ TLS key  written to {}", key_path.display());
    println!();
    println!("Add to /etc/proteus/server.yaml:");
    println!("  tls:");
    println!("    cert_chain: {}", cert_path.display());
    println!("    private_key: {}", key_path.display());
    println!();
    println!(
        "Distribute {} as `trusted_ca` to client side",
        cert_path.display()
    );
    println!("(or, recommended: get a real Let's Encrypt cert and skip this).");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::validate_dns_name;

    /// Iter-129: every shape an operator might reasonably try
    /// that we want to ACCEPT.
    #[test]
    fn iter129_accepts_realistic_san_strings() {
        for ok in [
            // Bare hostnames.
            "vps.example.com",
            "example.com",
            "a.b.c.d.e.example.com",
            "single-label",
            "with-hyphens-in-middle.example.com",
            "digits-123.example.com",
            "123start-digit.example.com",
            // Wildcard certs (RFC 6125 §6.4.3).
            "*.example.com",
            "*.sub.example.com",
            // IP literals (rcgen detects + emits IPAddress SAN).
            "127.0.0.1",
            "203.0.113.42",
            "::1",
            "2001:db8::1",
            // Edge: max label length (63 chars).
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa.example.com",
        ] {
            assert!(
                validate_dns_name(ok).is_ok(),
                "must accept {ok:?}: {:?}",
                validate_dns_name(ok)
            );
        }
    }

    /// Iter-129: shapes that rcgen accepted pre-iter-129 but
    /// produce certs no TLS client validates.
    #[test]
    fn iter129_rejects_empty_string() {
        let e = validate_dns_name("").unwrap_err();
        assert!(e.contains("is empty"), "{e}");
        assert!(e.contains("NotValidForName"), "must explain the failure mode: {e}");
    }

    #[test]
    fn iter129_rejects_just_dots() {
        let e = validate_dns_name(".").unwrap_err();
        assert!(e.contains("leading or trailing dot"), "{e}");
    }

    #[test]
    fn iter129_rejects_consecutive_dots() {
        let e = validate_dns_name("vps.example..com").unwrap_err();
        assert!(e.contains("empty label"), "{e}");
        assert!(e.contains("NotValidForName"), "{e}");
    }

    #[test]
    fn iter129_rejects_trailing_dot() {
        let e = validate_dns_name("vps.example.com.").unwrap_err();
        assert!(e.contains("trailing dot"), "{e}");
    }

    #[test]
    fn iter129_rejects_leading_dot() {
        let e = validate_dns_name(".example.com").unwrap_err();
        assert!(e.contains("leading or trailing dot"), "{e}");
    }

    #[test]
    fn iter129_rejects_space_in_name() {
        let e = validate_dns_name("Hello World").unwrap_err();
        assert!(e.contains("non-LDH"), "{e}");
        // Case-sensitive: validator says "Spaces" (the
        // operator-facing plural in the trailing examples list).
        assert!(e.contains("Spaces"), "must call out spaces specifically: {e}");
    }

    #[test]
    fn iter129_rejects_underscore() {
        // Underscores appear in some internal-DNS schemes (SRV
        // records) but TLS hostname-verification rejects them per
        // RFC 6125 §6.4.2. rcgen would have minted a cert with the
        // underscore SAN and every client would have failed.
        let e = validate_dns_name("vps_internal.example.com").unwrap_err();
        assert!(e.contains("non-LDH"), "{e}");
    }

    #[test]
    fn iter129_rejects_unicode() {
        let e = validate_dns_name("vps.例如.com").unwrap_err();
        assert!(e.contains("non-LDH"), "{e}");
    }

    #[test]
    fn iter129_rejects_leading_hyphen_label() {
        let e = validate_dns_name("-leading.example.com").unwrap_err();
        assert!(e.contains("starting or ending with a hyphen"), "{e}");
    }

    #[test]
    fn iter129_rejects_trailing_hyphen_label() {
        let e = validate_dns_name("trailing-.example.com").unwrap_err();
        assert!(e.contains("starting or ending with a hyphen"), "{e}");
    }

    #[test]
    fn iter129_rejects_overlong_label() {
        let label64 = "a".repeat(64);
        let bad = format!("{label64}.example.com");
        let e = validate_dns_name(&bad).unwrap_err();
        assert!(e.contains("63 chars"), "{e}");
    }

    #[test]
    fn iter129_rejects_overlong_total() {
        let label = "a".repeat(50);
        let bad = format!("{label}.{label}.{label}.{label}.{label}.{label}");
        // 50*6 + 5 dots = 305 > 253
        assert!(bad.len() > 253);
        let e = validate_dns_name(&bad).unwrap_err();
        assert!(e.contains("253 chars"), "{e}");
    }

    #[test]
    fn iter129_rejects_bare_wildcard() {
        let e = validate_dns_name("*.").unwrap_err();
        assert!(e.contains("just `*.`"), "{e}");
    }

    #[test]
    fn iter129_rejects_wildcard_with_garbage_body() {
        let e = validate_dns_name("*.foo..bar").unwrap_err();
        assert!(e.contains("empty label"), "{e}");
    }
}
