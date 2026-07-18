//! Safe on-host RFC 9849 ECH material generation.

use std::fs;
use std::io::{self, Write as _};
use std::path::Path;

use base64::Engine as _;

pub fn run(
    public_name: &str,
    config_id: u8,
    max_name_length: u8,
    out_dir: &Path,
    force: bool,
) -> Result<(), Box<dyn std::error::Error>> {
    let generated = proteus_ech::generate_ech_key(config_id, public_name, max_name_length)?;
    fs::create_dir_all(out_dir)?;

    let prefix = format!("ech-{config_id}");
    let config_path = out_dir.join(format!("{prefix}.config"));
    let list_path = out_dir.join(format!("{prefix}.config-list"));
    let list_b64_path = out_dir.join(format!("{prefix}.config-list.b64"));
    let key_path = out_dir.join(format!("{prefix}.key"));
    let paths = [&config_path, &list_path, &list_b64_path, &key_path];
    if !force {
        if let Some(existing) = paths.iter().find(|path| path.exists()) {
            return Err(io::Error::new(
                io::ErrorKind::AlreadyExists,
                format!(
                    "{} already exists; choose a fresh --config-id or pass --force deliberately",
                    existing.display()
                ),
            )
            .into());
        }
    }

    // Write the secret first with its final mode at open time. If a
    // later public-file write fails, the partial state leaks no key and
    // can be retried explicitly with --force.
    write_file(&key_path, &generated.key.private_key, 0o600, force)?;
    write_file(&config_path, &generated.key.ech_config, 0o644, force)?;
    write_file(&list_path, &generated.config_list, 0o644, force)?;
    let encoded = base64::engine::general_purpose::STANDARD.encode(&generated.config_list) + "\n";
    write_file(&list_b64_path, encoded.as_bytes(), 0o644, force)?;

    if let Ok(directory) = fs::File::open(out_dir) {
        let _ = directory.sync_all();
    }

    println!("✓ ECH config       {}", config_path.display());
    println!("✓ ECH config list  {}", list_path.display());
    println!("✓ ECH list base64  {}", list_b64_path.display());
    println!("✓ ECH private key  {} (mode 0600)", key_path.display());
    println!();
    println!("Publish the binary config list through DNS HTTPS `ech=` only");
    println!("after every server instance has the matching private key.");
    Ok(())
}

fn write_file(path: &Path, bytes: &[u8], mode: u32, force: bool) -> io::Result<()> {
    let mut options = fs::OpenOptions::new();
    options.write(true);
    if force {
        options.create(true).truncate(true);
    } else {
        options.create_new(true);
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        options.mode(mode);
    }
    let mut file = options.open(path)?;
    file.write_all(bytes)?;
    file.sync_all()?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        let mut permissions = file.metadata()?.permissions();
        permissions.set_mode(mode);
        file.set_permissions(permissions)?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    struct TempDir(PathBuf);

    impl TempDir {
        fn new(label: &str) -> Self {
            let path = std::env::temp_dir()
                .join(format!("proteus-ech-keygen-{label}-{}", std::process::id()));
            let _ = fs::remove_dir_all(&path);
            fs::create_dir(&path).unwrap();
            Self(path)
        }
    }

    impl Drop for TempDir {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    #[test]
    fn writes_loadable_versioned_material_and_refuses_overwrite() {
        let temp = TempDir::new("material");
        run("public.example", 17, 64, &temp.0, false).unwrap();
        let config = fs::read(temp.0.join("ech-17.config")).unwrap();
        let key = fs::read(temp.0.join("ech-17.key")).unwrap();
        let list = fs::read(temp.0.join("ech-17.config-list")).unwrap();
        assert_eq!(key.len(), 32);
        assert_eq!(&list[2..], config);
        let decoded = base64::engine::general_purpose::STANDARD
            .decode(
                fs::read_to_string(temp.0.join("ech-17.config-list.b64"))
                    .unwrap()
                    .trim(),
            )
            .unwrap();
        assert_eq!(decoded, list);
        assert!(run("public.example", 17, 64, &temp.0, false).is_err());

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            assert_eq!(
                fs::metadata(temp.0.join("ech-17.key"))
                    .unwrap()
                    .permissions()
                    .mode()
                    & 0o777,
                0o600
            );
        }
    }
}
