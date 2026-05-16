//! `proteus-server gencert` — emit a self-signed TLS cert + key pair
//! suitable for the `tls:` config block.
//!
//! For production you should replace these files with a Let's Encrypt
//! `fullchain.pem` + `privkey.pem`; the on-disk format is identical so
//! the swap is a no-op.

use std::fs;
use std::path::Path;

pub fn run(dns_name: &str, out_dir: &Path) -> Result<(), Box<dyn std::error::Error>> {
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
