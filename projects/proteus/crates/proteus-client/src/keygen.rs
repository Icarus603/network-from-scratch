//! `proteus-client keygen`.

use std::fs;
use std::path::Path;

use base64::Engine;
use rand_core::{OsRng, RngCore};
use zeroize::Zeroizing;

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
    // Iter-167: wrap the Ed25519 seed in Zeroizing so the 32-byte
    // identity-key material is scrubbed on drop. Same defect class
    // as iter-166 (sig::generate) closed for the client-side keygen
    // entry point. ed25519_dalek's `SigningKey` impls ZeroizeOnDrop,
    // but the bare `[u8; 32]` seed array does not — pre-iter-167 it
    // lingered in this function's stack frame after `run_with_force`
    // returned, until later activity overwrites it.
    //
    // Higher-stakes context than iter-166: this code path writes
    // the seed to a file (mode-0600), so the seed's lifetime
    // spans the b64-encode step + the fs syscall. A coredump
    // taken during the syscall window can recover the full
    // identity key.
    let mut rng = OsRng;
    let mut sk = Zeroizing::new([0u8; 32]);
    rng.fill_bytes(&mut *sk);
    let signing = ed25519_dalek::SigningKey::from_bytes(&sk);
    let vk = signing.verifying_key();

    write_b64(&out_dir.join("client.ed25519.sk"), &*sk)?;
    write_b64(&out_dir.join("client.ed25519.pk"), vk.as_bytes())?;

    println!("✓ client identity written to {}", out_dir.display());
    println!("  Share client.ed25519.pk with the server admin to add to allowlist.");
    Ok(())
}

fn write_b64(path: &Path, bytes: &[u8]) -> std::io::Result<()> {
    use zeroize::Zeroize as _;

    // Iter-167: the base64 encoding of an identity-key seed is
    // ALSO secret (it's directly substitutable for the seed via
    // base64::decode), so the intermediate `b64` and `body`
    // Strings need their backing buffers scrubbed on drop. The
    // public-key path also goes through this helper, where the
    // b64 is genuinely non-secret — but conservatively scrubbing
    // both costs ~44 bytes of memset per call and prevents the
    // "is this caller secret-keyed" question from leaking into
    // every keygen call site.
    let mut b64 = base64::engine::general_purpose::STANDARD.encode(bytes);
    let mut body = format!("{b64}\n");
    // Iter-152: atomic-mode-0600 + fsync — mirror of the
    // server-side `proteus_server::keygen::write_b64` fix. The
    // client's ed25519 secret-key file is the long-term identity
    // material; a write-then-chmod race window on a shared host
    // is a real identity-compromise vector. Same fsync rationale
    // as the iter-148 / iter-149 persist paths.
    let result = (|| -> std::io::Result<()> {
        #[cfg(unix)]
        {
            use std::io::Write;
            use std::os::unix::fs::OpenOptionsExt;
            let mut f = fs::OpenOptions::new()
                .write(true)
                .create(true)
                .truncate(true)
                .mode(0o600)
                .open(path)?;
            f.write_all(body.as_bytes())?;
            f.sync_all()?;
        }
        #[cfg(not(unix))]
        {
            fs::write(path, body.as_bytes())?;
        }
        if let Some(parent) = path.parent() {
            if !parent.as_os_str().is_empty() {
                if let Ok(parent_f) = fs::File::open(parent) {
                    let _ = parent_f.sync_all();
                }
            }
        }
        Ok(())
    })();
    // Scrub intermediate buffers regardless of write outcome.
    b64.zeroize();
    body.zeroize();
    result
}
