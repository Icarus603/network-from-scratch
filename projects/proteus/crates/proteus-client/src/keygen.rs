//! `proteus-client keygen`.

use std::fs;
use std::path::Path;

use base64::Engine;
use rand_core::{OsRng, RngCore};

#[allow(dead_code)] // stable lib surface; binary calls run_with_force
pub fn run(out_dir: &Path) -> Result<(), Box<dyn std::error::Error>> {
    run_with_force(out_dir, false)
}

/// Iter-130: anti-clobber wrapper. Same semantics as the
/// server-side keygen — refuse to overwrite by default, require
/// explicit `--force` to deliberately rotate. The client SK is
/// the long-term identity the server allowlists by public key;
/// overwriting it without coordinating with the server admin
/// means the client immediately stops being able to authenticate.
pub fn run_with_force(out_dir: &Path, force: bool) -> Result<(), Box<dyn std::error::Error>> {
    let targets = [
        out_dir.join("client.ed25519.sk"),
        out_dir.join("client.ed25519.pk"),
    ];
    if !force {
        for p in &targets {
            if p.exists() {
                return Err(format!(
                    "refusing to overwrite existing key file {}. Your current \
                     client.ed25519.pk is allowlisted on the server; \
                     clobbering the keypair means the server will reject \
                     every future handshake with 'unknown client_id' until \
                     you re-share the new .pk with the server admin AND they \
                     re-add it to the allowlist. If you ARE deliberately \
                     rotating: 1) generate a new bundle elsewhere with \
                     `--out ./new-keys`, 2) share new client.ed25519.pk with \
                     server admin, 3) wait for confirmation it's allowlisted, \
                     4) swap the file paths in client.yaml. If you're not \
                     rotating, pick a different `--out` directory or remove \
                     the existing files first.",
                    p.display()
                )
                .into());
            }
        }
    }
    fs::create_dir_all(out_dir)?;
    let mut rng = OsRng;
    let mut sk = [0u8; 32];
    rng.fill_bytes(&mut sk);
    let signing = ed25519_dalek::SigningKey::from_bytes(&sk);
    let vk = signing.verifying_key();

    write_b64(&out_dir.join("client.ed25519.sk"), &sk)?;
    write_b64(&out_dir.join("client.ed25519.pk"), vk.as_bytes())?;

    println!("✓ client identity written to {}", out_dir.display());
    println!("  Share client.ed25519.pk with the server admin to add to allowlist.");
    Ok(())
}

fn write_b64(path: &Path, bytes: &[u8]) -> std::io::Result<()> {
    let b64 = base64::engine::general_purpose::STANDARD.encode(bytes);
    fs::write(path, format!("{b64}\n"))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mut perm = fs::metadata(path)?.permissions();
        perm.set_mode(0o600);
        fs::set_permissions(path, perm)?;
    }
    Ok(())
}
