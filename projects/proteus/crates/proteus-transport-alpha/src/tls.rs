//! TLS 1.3 outer wrapper for the α-profile (spec §4.2).
//!
//! The bare-TCP variant (`server::handshake_over_tcp` /
//! `client::handshake_over_tcp`) is useful for testing and trusted-LAN
//! deployments, but a public-Internet Proteus server MUST run inside a
//! real TLS 1.3 record stream so that:
//!
//! 1. A passive DPI / ML classifier sees the standard TLS 1.3 handshake
//!    pattern (ClientHello → ServerHello → Finished → encrypted records)
//!    that ~95% of the internet uses. Our typed framing is hidden inside
//!    `application_data` records.
//! 2. The cover-forward path (spec §7.5) can run *inside* TLS by
//!    deferring Proteus authentication to the first inner record — the
//!    outer TLS handshake completes regardless, so a probing attacker
//!    sees a valid TLS cert chain matching the server's domain.
//!
//! ## Configuration
//!
//! Server: load a PEM cert chain + PEM PKCS8 key (Let's Encrypt by
//! default in deploy guide).
//! Client: trust a CA bundle (webpki-roots by default; user can supply
//! a custom anchor when the server uses self-signed certs in testing).

use std::path::Path;
use std::sync::Arc;

use rustls::crypto::CryptoProvider;
use rustls::{
    pki_types::{CertificateDer, PrivateKeyDer, ServerName},
    ClientConfig, RootCertStore, ServerConfig,
};
use tokio::net::TcpStream;
use tokio_rustls::client::TlsStream as ClientTlsStream;
use tokio_rustls::server::TlsStream as ServerTlsStream;
use tokio_rustls::{TlsAcceptor, TlsConnector};

/// Build a CryptoProvider whose `cipher_suites` list is ordered to
/// approximate a Chrome 124 ClientHello.
///
/// Rationale: JA4 cipher_hash is computed over the SORTED cipher list,
/// so the order on the wire doesn't move the hash by itself. BUT it
/// also determines the visible cipher_count (count of non-GREASE
/// ciphers in the ClientHello) — and we want that count to look like
/// a real browser, NOT like the rustls default that DPI classifiers
/// have learned. We use the maximal rustls cipher set (9 suites,
/// matching what rustls 0.23 with TLS 1.2 fallback compiled in
/// supports) ordered to match Chrome's preference for AEAD over
/// AES-CBC, AES-GCM over CHACHA20-POLY1305 on AES-NI hardware, and
/// ECDSA before RSA — exactly the rationale Chrome uses since 2019.
///
/// Wire-fingerprint goal: this is **one step** toward matching Chrome.
/// Full uTLS-grade replay requires also matching extension order,
/// signature_algorithms list, and grease injection — which need rustls
/// patching. This is what we can achieve via the public rustls API.
/// Chrome 124's signature_algorithms list on the wire (8 schemes,
/// IN ORDER) — captured from a real Chrome ClientHello.
///
/// This is the `mapping` field of `WebPkiSupportedAlgorithms`. The
/// order is wire-significant per rustls's docs: "The first mapping
/// is our highest preference." So the order on the wire becomes the
/// order of this static array.
///
/// `all` holds the verification algorithm pool used during cert
/// chain validation — we keep rustls's default `all` so we can still
/// validate certs that use schemes we don't advertise (matching
/// browser behavior: browsers validate widely, advertise narrowly).
static CHROME_SIG_ALGS: rustls::crypto::WebPkiSupportedAlgorithms =
    rustls::crypto::WebPkiSupportedAlgorithms {
        all: &[
            webpki::ring::ECDSA_P256_SHA256,
            webpki::ring::ECDSA_P256_SHA384,
            webpki::ring::ECDSA_P384_SHA256,
            webpki::ring::ECDSA_P384_SHA384,
            webpki::ring::ED25519,
            webpki::ring::RSA_PSS_2048_8192_SHA256_LEGACY_KEY,
            webpki::ring::RSA_PSS_2048_8192_SHA384_LEGACY_KEY,
            webpki::ring::RSA_PSS_2048_8192_SHA512_LEGACY_KEY,
            webpki::ring::RSA_PKCS1_2048_8192_SHA256,
            webpki::ring::RSA_PKCS1_2048_8192_SHA384,
            webpki::ring::RSA_PKCS1_2048_8192_SHA512,
        ],
        mapping: &[
            // Chrome 124 wire order, verified against captured PCAPs:
            //
            //   ecdsa_secp256r1_sha256  0x0403
            //   rsa_pss_rsae_sha256     0x0804
            //   rsa_pkcs1_sha256        0x0401
            //   ecdsa_secp384r1_sha384  0x0503
            //   rsa_pss_rsae_sha384     0x0805
            //   rsa_pkcs1_sha384        0x0501
            //   rsa_pss_rsae_sha512     0x0806
            //   rsa_pkcs1_sha512        0x0601
            //
            // Note: Chrome does NOT advertise ed25519 (0x0807) — rustls
            // does by default. Removing it shifts JA4 ext_hash toward
            // Chrome's signature.
            (
                rustls::SignatureScheme::ECDSA_NISTP256_SHA256,
                &[
                    webpki::ring::ECDSA_P256_SHA256,
                    webpki::ring::ECDSA_P384_SHA256,
                ],
            ),
            (
                rustls::SignatureScheme::RSA_PSS_SHA256,
                &[webpki::ring::RSA_PSS_2048_8192_SHA256_LEGACY_KEY],
            ),
            (
                rustls::SignatureScheme::RSA_PKCS1_SHA256,
                &[webpki::ring::RSA_PKCS1_2048_8192_SHA256],
            ),
            (
                rustls::SignatureScheme::ECDSA_NISTP384_SHA384,
                &[
                    webpki::ring::ECDSA_P384_SHA384,
                    webpki::ring::ECDSA_P256_SHA384,
                ],
            ),
            (
                rustls::SignatureScheme::RSA_PSS_SHA384,
                &[webpki::ring::RSA_PSS_2048_8192_SHA384_LEGACY_KEY],
            ),
            (
                rustls::SignatureScheme::RSA_PKCS1_SHA384,
                &[webpki::ring::RSA_PKCS1_2048_8192_SHA384],
            ),
            (
                rustls::SignatureScheme::RSA_PSS_SHA512,
                &[webpki::ring::RSA_PSS_2048_8192_SHA512_LEGACY_KEY],
            ),
            (
                rustls::SignatureScheme::RSA_PKCS1_SHA512,
                &[webpki::ring::RSA_PKCS1_2048_8192_SHA512],
            ),
        ],
    };

fn proteus_chrome_provider() -> CryptoProvider {
    use rustls::crypto::ring::cipher_suite::*;
    let mut p = rustls::crypto::ring::default_provider();
    // Chrome 124's cipher preference: TLS 1.3 first (128 → 256 →
    // CHACHA20), then TLS 1.2 ECDSA-before-RSA within each AEAD group.
    // The workspace ships rustls with the `tls12` feature enabled
    // (see top-level Cargo.toml), so all 9 cipher constants below
    // resolve.
    p.cipher_suites = vec![
        TLS13_AES_128_GCM_SHA256,
        TLS13_AES_256_GCM_SHA384,
        TLS13_CHACHA20_POLY1305_SHA256,
        TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
        TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
        TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
        TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
        TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,
        TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
    ];
    // Chrome-shaped signature_algorithms on the wire (8 schemes vs
    // rustls's 9 — drops ed25519 which Chrome doesn't advertise).
    p.signature_verification_algorithms = CHROME_SIG_ALGS;
    p
}

/// Server-side TLS-wrapped TCP stream.
pub type ServerStream = ServerTlsStream<TcpStream>;

/// Client-side TLS-wrapped TCP stream.
pub type ClientStream = ClientTlsStream<TcpStream>;

/// Server handshake: drive the TLS 1.3 handshake on `stream`, returning
/// the encrypted stream ready for the inner Proteus framing.
pub async fn server_handshake(
    acceptor: &TlsAcceptor,
    stream: TcpStream,
) -> Result<ServerStream, TlsError> {
    Ok(acceptor.accept(stream).await?)
}

/// Client handshake: drive the TLS 1.3 handshake against `server_name`.
pub async fn client_handshake(
    connector: &TlsConnector,
    server_name: ServerName<'static>,
    stream: TcpStream,
) -> Result<ClientStream, TlsError> {
    Ok(connector.connect(server_name, stream).await?)
}

/// Errors surfaced by the TLS layer.
#[derive(Debug, thiserror::Error)]
pub enum TlsError {
    #[error("io: {0}")]
    Io(#[from] std::io::Error),

    #[error("rustls: {0}")]
    Rustls(#[from] rustls::Error),

    #[error("invalid PEM in {path}: {msg}")]
    BadPem { path: String, msg: String },

    #[error("no certificate found in {path}")]
    NoCert { path: String },

    #[error("no private key found in {path}")]
    NoKey { path: String },

    #[error("invalid server name: {0}")]
    BadServerName(String),
}

/// Load a PEM-encoded certificate chain.
///
/// Migrated from the now-unmaintained `rustls-pemfile` crate
/// (RUSTSEC-2025-0134) to `rustls_pki_types::pem::PemObject`, which
/// owns the same parsing code and is shipped as part of rustls itself.
pub fn load_cert_chain(path: &Path) -> Result<Vec<CertificateDer<'static>>, TlsError> {
    use rustls::pki_types::pem::PemObject;
    let certs: Result<Vec<_>, _> = CertificateDer::pem_file_iter(path)
        .map_err(|e| TlsError::BadPem {
            path: path.display().to_string(),
            msg: e.to_string(),
        })?
        .collect();
    let certs = certs.map_err(|e| TlsError::BadPem {
        path: path.display().to_string(),
        msg: e.to_string(),
    })?;
    if certs.is_empty() {
        return Err(TlsError::NoCert {
            path: path.display().to_string(),
        });
    }
    Ok(certs)
}

/// Load a single PEM-encoded private key (PKCS8 / PKCS1 / SEC1 accepted).
pub fn load_private_key(path: &Path) -> Result<PrivateKeyDer<'static>, TlsError> {
    use rustls::pki_types::pem::PemObject;
    PrivateKeyDer::from_pem_file(path).map_err(|e| TlsError::BadPem {
        path: path.display().to_string(),
        msg: e.to_string(),
    })
}

/// Build a server-side TLS 1.3 acceptor from a cert chain + key.
///
/// Only TLS 1.3 is negotiated (no TLS 1.2 fallback) so the wire stays
/// uniform. Cipher suite list is rustls's default (TLS_AES_128_GCM,
/// TLS_AES_256_GCM, TLS_CHACHA20_POLY1305) which matches what
/// modern browsers offer first.
pub fn build_acceptor(
    cert_chain: Vec<CertificateDer<'static>>,
    key: PrivateKeyDer<'static>,
) -> Result<TlsAcceptor, TlsError> {
    // Rustls 0.23 needs an installed CryptoProvider before any config build.
    install_default_crypto_provider();
    let mut config = ServerConfig::builder_with_protocol_versions(&[&rustls::version::TLS13])
        .with_no_client_auth()
        .with_single_cert(cert_chain, key)?;
    // ALPN: claim h2 + http/1.1, exactly what modern HTTPS servers
    // advertise. This is what the wire-level fingerprint MUST look like
    // (spec §4.7).
    config.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
    Ok(TlsAcceptor::from(Arc::new(config)))
}

/// Build a `ClientConfig` with the Chrome-ordered cipher provider, TLS 1.3
/// only, ALPN h2+http/1.1, and the given root store. This is the
/// internal builder used by every public `build_connector_*` entry
/// point so the wire-fingerprint stays consistent across deployment
/// modes (webpki roots, pinned CA file, pinned CA DER).
fn build_chrome_shaped_client_config(roots: RootCertStore) -> Result<ClientConfig, TlsError> {
    let provider = Arc::new(proteus_chrome_provider());
    let mut config = ClientConfig::builder_with_provider(provider)
        .with_protocol_versions(&[&rustls::version::TLS13])
        .map_err(|e| TlsError::BadServerName(format!("bad TLS provider config: {e}")))?
        .with_root_certificates(roots)
        .with_no_client_auth();
    config.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
    Ok(config)
}

/// Build a client-side TLS 1.3 connector trusting the webpki root CAs.
pub fn build_connector_webpki_roots() -> Result<TlsConnector, TlsError> {
    install_default_crypto_provider();
    let mut roots = RootCertStore::empty();
    roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
    let config = build_chrome_shaped_client_config(roots)?;
    Ok(TlsConnector::from(Arc::new(config)))
}

/// Build a client-side TLS 1.3 connector that pins a single CA (used
/// for self-signed deployments).
pub fn build_connector_with_ca(ca_path: &Path) -> Result<TlsConnector, TlsError> {
    install_default_crypto_provider();
    let mut roots = RootCertStore::empty();
    let chain = load_cert_chain(ca_path)?;
    for cert in chain {
        roots.add(cert)?;
    }
    let config = build_chrome_shaped_client_config(roots)?;
    Ok(TlsConnector::from(Arc::new(config)))
}

/// Build a client-side TLS 1.3 connector that pins a single CA passed
/// as a DER-encoded `CertificateDer`. Same as `build_connector_with_ca`
/// but skips the PEM-on-disk step — useful for tests that mint a
/// cert in-memory via rcgen.
pub fn build_connector_with_ca_der(ca: CertificateDer<'static>) -> Result<TlsConnector, TlsError> {
    install_default_crypto_provider();
    let mut roots = RootCertStore::empty();
    roots.add(ca)?;
    let config = build_chrome_shaped_client_config(roots)?;
    Ok(TlsConnector::from(Arc::new(config)))
}

/// Parse a server-name string into the rustls type. Wraps the awkward
/// `ServerName::try_from` API.
pub fn server_name(s: &str) -> Result<ServerName<'static>, TlsError> {
    ServerName::try_from(s.to_string()).map_err(|_| TlsError::BadServerName(s.to_string()))
}

/// Reloadable wrapper around a [`TlsAcceptor`].
///
/// Production deployments using Let's Encrypt see certificate renewal
/// every ~60 days, and the operator absolutely **cannot** afford to
/// restart the server to pick up the new cert — every in-flight
/// session would tear down. With [`ReloadableAcceptor`] the operator
/// just calls [`Self::reload`] (typically from a SIGHUP handler) and
/// every connection accepted *after* the reload uses the new cert
/// while sessions opened before keep their existing TLS keys.
///
/// Implementation: a `std::sync::RwLock<TlsAcceptor>`. The inner
/// `TlsAcceptor` is a thin `Arc<ServerConfig>` so cloning it on every
/// accept is essentially free (one atomic increment). The lock is
/// acquired in read mode on the hot path (accept) and write mode only
/// on reload, which is a rare operator action.
#[derive(Clone)]
pub struct ReloadableAcceptor {
    inner: Arc<std::sync::RwLock<TlsAcceptor>>,
}

impl ReloadableAcceptor {
    /// Wrap an initial acceptor.
    #[must_use]
    pub fn new(initial: TlsAcceptor) -> Self {
        Self {
            inner: Arc::new(std::sync::RwLock::new(initial)),
        }
    }

    /// Clone the current acceptor. Hot-path call — cheap.
    #[must_use]
    pub fn current(&self) -> TlsAcceptor {
        // `expect` is safe: the only way the lock gets poisoned is if
        // a writer panics while holding the write lock, which would
        // mean the server is in an unrecoverable state anyway.
        self.inner
            .read()
            .expect("ReloadableAcceptor lock poisoned")
            .clone()
    }

    /// Swap in a new acceptor. Any future accept will use the new
    /// cert; in-flight sessions keep their existing TLS state.
    pub fn reload(&self, new_acceptor: TlsAcceptor) {
        *self
            .inner
            .write()
            .expect("ReloadableAcceptor lock poisoned") = new_acceptor;
    }
}

impl From<TlsAcceptor> for ReloadableAcceptor {
    fn from(a: TlsAcceptor) -> Self {
        Self::new(a)
    }
}

/// Install rustls's default ring-backed crypto provider exactly once.
/// Calling multiple times is a no-op.
fn install_default_crypto_provider() {
    use std::sync::Once;
    static INSTALL: Once = Once::new();
    INSTALL.call_once(|| {
        // `install_default` returns `Result<_, _>`; if another caller
        // already installed one we silently keep theirs.
        let _ = rustls::crypto::ring::default_provider().install_default();
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn server_name_round_trip() {
        let sn = server_name("example.com").unwrap();
        assert!(matches!(sn, ServerName::DnsName(_)));
    }

    #[test]
    fn server_name_rejects_garbage() {
        assert!(server_name("not a hostname!!!").is_err());
    }

    #[test]
    fn install_default_crypto_is_idempotent() {
        install_default_crypto_provider();
        install_default_crypto_provider();
        install_default_crypto_provider();
    }

    #[test]
    fn reloadable_acceptor_swaps_cheaply() {
        use rcgen::generate_simple_self_signed;
        use rustls::pki_types::{PrivateKeyDer, PrivatePkcs8KeyDer};

        let mk = || {
            let ck = generate_simple_self_signed(vec!["localhost".to_string()]).unwrap();
            let cert = CertificateDer::from(ck.cert.der().to_vec());
            let key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(ck.key_pair.serialize_der()));
            build_acceptor(vec![cert], key).unwrap()
        };

        let initial = mk();
        let reloadable = ReloadableAcceptor::new(initial);

        // Cloning current() is cheap (Arc clone) — repeat many times.
        for _ in 0..1024 {
            let _ = reloadable.current();
        }
        // Reload — same operation that SIGHUP triggers in production.
        reloadable.reload(mk());
        for _ in 0..1024 {
            let _ = reloadable.current();
        }
        reloadable.reload(mk());
    }
}
