//! `proteus-client keygen`.

use std::fs;
use std::path::Path;

use base64::Engine;
use rand_core::{OsRng, RngCore};

pub fn run(out_dir: &Path) -> Result<(), Box<dyn std::error::Error>> {
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
