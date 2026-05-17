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
use tokio_rustls::TlsAcceptor;
// `TlsConnector` is re-exported as `pub use` below so binaries
// can name the type without depending on `tokio-rustls` directly.
pub use tokio_rustls::TlsConnector;

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

/// Server-side TLS-wrapped Path-A `PrependedStream`. The
/// gated accept loop yields this concrete type instead of
/// the legacy `ServerStream` so the binary doesn't need a
/// direct `tokio-rustls` dependency just to spell the type.
pub type GatedServerStream = ServerTlsStream<crate::knock_dispatch::PrependedStream>;

// (`TlsConnector` is `pub use`d at the top of this module so
// binaries can name the type via `proteus_transport_alpha::tls::
// TlsConnector` without depending on `tokio-rustls` directly.
// Symmetric to the `GatedServerStream` alias above.)

/// Server handshake: drive the TLS 1.3 handshake on `stream`, returning
/// the encrypted stream ready for the inner Proteus framing.
pub async fn server_handshake(
    acceptor: &TlsAcceptor,
    stream: TcpStream,
) -> Result<ServerStream, TlsError> {
    Ok(acceptor.accept(stream).await?)
}

/// Generic server-handshake variant that accepts any
/// AsyncRead+AsyncWrite IO. Lets the Path-A
/// `PrependedStream` (a `TcpStream` with a peeked-bytes
/// prefix) flow through rustls just like a bare `TcpStream`.
///
/// Returns a `ServerTlsStream<S>` parameterized on the
/// caller-supplied IO type rather than the legacy
/// `ServerStream = ServerTlsStream<TcpStream>` alias.
/// Downstream consumers that need the legacy alias continue
/// using `server_handshake`; the new Path-A path uses this
/// variant.
pub async fn server_handshake_io<S>(
    acceptor: &TlsAcceptor,
    stream: S,
) -> Result<tokio_rustls::server::TlsStream<S>, TlsError>
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static,
{
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
    // Chrome 124 advertises the `early_data` (0x002a) extension on
    // every ClientHello, regardless of whether the session can
    // actually send 0-RTT. Setting this to `true` tells rustls to
    // include the extension in the ClientHello (the extension's
    // payload is empty when no PSK is offered, so we don't actually
    // open a 0-RTT attack surface — we just paint one more
    // Chrome-shaped extension byte onto the wire). Closes one
    // ext_count gap toward Chrome and SHIFTS the JA4 ext_hash;
    // operators see the new baseline in the JA4 regression test.
    //
    // This is a wire-fingerprint-only change. We do NOT actually
    // attempt 0-RTT in production (no `prepare_resumption_data`
    // path, no exposed API for callers to pre-stuff data). rustls'
    // own session cache is in-process per the existing default and
    // we don't reuse sessions across connections in the Proteus
    // dispatcher today.
    config.enable_early_data = true;
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

/// Extract the leaf certificate's `notAfter` field as a Unix timestamp
/// (seconds since 1970-01-01 00:00:00 UTC).
///
/// Production operators monitor cert expiry — Let's Encrypt issues
/// 90-day certs (60-day renewal cadence). A cert that silently expires
/// while the operator's certbot timer is broken means the server
/// quietly rejects every new TLS handshake. This helper feeds the
/// `proteus_tls_cert_not_after_unix_seconds` Prometheus gauge so a
/// PromQL alert like `(proteus_tls_cert_not_after_unix_seconds - time())
/// < 14 * 86400` pages the operator before the cert dies.
///
/// `chain[0]` is the leaf (RFC 5246 §7.4.2): the first cert in the
/// chain is the end-entity cert presented to the client. Intermediates
/// follow. We only look at the leaf because:
///   - The leaf is what gates connections (intermediates almost never
///     expire in normal Let's Encrypt operation — they're rolled out by
///     the CA every few years, and certbot's renewal hook does NOT
///     update them).
///   - The visible-to-the-operator metric should be the actionable one:
///     "will my cert expire?" — that's the leaf.
///
/// Returns `Err` if the chain is empty (caller already validates this
/// in `load_cert_chain`, so this is a defense-in-depth check) or if
/// the DER fails to parse.
pub fn leaf_cert_not_after(chain: &[CertificateDer<'_>]) -> Result<i64, TlsError> {
    use x509_parser::prelude::*;
    let leaf = chain.first().ok_or_else(|| TlsError::NoCert {
        path: "<in-memory chain>".to_string(),
    })?;
    let (_, parsed) = X509Certificate::from_der(leaf.as_ref()).map_err(|e| TlsError::BadPem {
        path: "<leaf cert>".to_string(),
        msg: format!("DER parse: {e}"),
    })?;
    Ok(parsed.validity().not_after.timestamp())
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
///
/// Observability: `ReloadableAcceptor` tracks the leaf cert's
/// `notAfter` timestamp (seconds since UNIX epoch) so the metrics
/// surface can emit `proteus_tls_cert_not_after_unix_seconds` for
/// PromQL alerting. The timestamp is updated whenever [`Self::reload`]
/// or [`Self::new_with_expiry`] is called with a fresh chain. Use
/// [`Self::leaf_not_after`] to read the current value.
#[derive(Clone)]
pub struct ReloadableAcceptor {
    inner: Arc<std::sync::RwLock<TlsAcceptor>>,
    /// Leaf cert `notAfter` as Unix seconds. `i64::MIN` sentinel means
    /// "not tracked" (legacy `new` path, kept for tests that don't
    /// supply a chain).
    leaf_not_after: Arc<std::sync::atomic::AtomicI64>,
    /// SIGHUP reload counters.
    ///
    /// - `reload_attempts`: incremented on every `reload` call,
    ///   whether the cert verification succeeded or not.
    /// - `reload_succeeded`: incremented only when `reload_with_expiry`
    ///   was passed a fresh chain that parsed.
    ///
    /// The two counters together let operators compute reload-failure
    /// ratio in PromQL: `1 - (succeeded / attempts)`.
    reload_attempts: Arc<std::sync::atomic::AtomicU64>,
    reload_succeeded: Arc<std::sync::atomic::AtomicU64>,
}

impl ReloadableAcceptor {
    /// Wrap an initial acceptor without expiry tracking. Use
    /// [`Self::new_with_expiry`] in production so the cert-expiry
    /// gauge is meaningful.
    #[must_use]
    pub fn new(initial: TlsAcceptor) -> Self {
        Self {
            inner: Arc::new(std::sync::RwLock::new(initial)),
            leaf_not_after: Arc::new(std::sync::atomic::AtomicI64::new(i64::MIN)),
            reload_attempts: Arc::new(std::sync::atomic::AtomicU64::new(0)),
            reload_succeeded: Arc::new(std::sync::atomic::AtomicU64::new(0)),
        }
    }

    /// Wrap an initial acceptor AND record the leaf cert's `notAfter`
    /// timestamp so the cert-expiry gauge is populated immediately.
    ///
    /// If the chain parses cleanly the gauge starts at the leaf's real
    /// expiry. If parsing fails (operator supplied a malformed PEM)
    /// the gauge stays at `i64::MIN` sentinel — caller is expected to
    /// have already validated the chain via `load_cert_chain` so this
    /// almost never fires in practice; we keep the soft failure mode
    /// so observability doesn't take down the server.
    #[must_use]
    pub fn new_with_expiry(initial: TlsAcceptor, chain: &[CertificateDer<'_>]) -> Self {
        let leaf_ts = leaf_cert_not_after(chain).unwrap_or(i64::MIN);
        Self {
            inner: Arc::new(std::sync::RwLock::new(initial)),
            leaf_not_after: Arc::new(std::sync::atomic::AtomicI64::new(leaf_ts)),
            reload_attempts: Arc::new(std::sync::atomic::AtomicU64::new(0)),
            reload_succeeded: Arc::new(std::sync::atomic::AtomicU64::new(0)),
        }
    }

    /// Clone the current acceptor. Hot-path call — cheap.
    #[must_use]
    pub fn current(&self) -> TlsAcceptor {
        // Iter-25: recover from a poisoned lock rather than
        // re-panicking. Pre-iter-24 (`panic = abort`) a writer
        // panic killed the whole process so this `.expect`
        // was unreachable; post-iter-24 (`panic = unwind`) a
        // panic in any task that touches this lock poisons
        // it, and EVERY subsequent accept would die on the
        // `.expect` — cascading into a slow-but-total accept
        // failure across the server. The `TlsAcceptor` inside
        // is a `Clone` reference into rustls's config Arc; a
        // partial write that triggered the poison still leaves
        // a complete value in the slot. Reading it after
        // recovery is safe.
        match self.inner.read() {
            Ok(g) => g.clone(),
            Err(poisoned) => {
                // Best-effort observability — counts as one
                // failed reload-attempt so operators see the
                // anomaly via `proteus_tls_reload_attempts -
                // proteus_tls_reload_succeeded`.
                self.reload_attempts
                    .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                tracing::warn!(
                    "ReloadableAcceptor RwLock was poisoned by a prior panic — \
                     recovering and continuing to serve the last-known-good acceptor"
                );
                poisoned.into_inner().clone()
            }
        }
    }

    /// Swap in a new acceptor. Any future accept will use the new
    /// cert; in-flight sessions keep their existing TLS state.
    ///
    /// This call DOES bump `reload_attempts` (so a SIGHUP that resorts
    /// to `reload` without a chain still shows up in counters) but
    /// CANNOT update the expiry gauge or `reload_succeeded` because no
    /// chain was supplied. Prefer [`Self::reload_with_expiry`] in
    /// production so the gauge tracks the new cert.
    pub fn reload(&self, new_acceptor: TlsAcceptor) {
        self.reload_attempts
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        // Iter-25: poisoned-lock recovery (see `current()` for
        // the rationale). Writing a fresh acceptor over a
        // poisoned slot is safe — it replaces whatever was
        // there, and the new operator-supplied acceptor is by
        // construction valid.
        let mut g = match self.inner.write() {
            Ok(g) => g,
            Err(poisoned) => {
                tracing::warn!(
                    "ReloadableAcceptor RwLock was poisoned during reload — \
                     recovering and installing the new acceptor anyway"
                );
                poisoned.into_inner()
            }
        };
        *g = new_acceptor;
    }

    /// Swap in a new acceptor AND refresh the cert-expiry gauge from
    /// the new chain's leaf. Bumps both `reload_attempts` and (on
    /// successful chain parse) `reload_succeeded`.
    ///
    /// Returns `Err` only if leaf-cert DER parsing failed — the
    /// acceptor IS still swapped in either way, because a fresh
    /// acceptor that the operator has trusted enough to build must
    /// not be rejected by a downstream observability concern. The
    /// expiry gauge in that case is left at its previous value so
    /// PromQL doesn't see a confusing zero/MIN dip; the parse-error
    /// path is reflected in the `attempts - succeeded` gap.
    pub fn reload_with_expiry(
        &self,
        new_acceptor: TlsAcceptor,
        chain: &[CertificateDer<'_>],
    ) -> Result<(), TlsError> {
        self.reload_attempts
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let parse_result = leaf_cert_not_after(chain);
        // Iter-25: same poisoned-lock recovery as `reload`.
        let mut g = match self.inner.write() {
            Ok(g) => g,
            Err(poisoned) => {
                tracing::warn!(
                    "ReloadableAcceptor RwLock was poisoned during reload_with_expiry — \
                     recovering and installing the new acceptor anyway"
                );
                poisoned.into_inner()
            }
        };
        *g = new_acceptor;
        match parse_result {
            Ok(ts) => {
                self.leaf_not_after
                    .store(ts, std::sync::atomic::Ordering::Relaxed);
                self.reload_succeeded
                    .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                Ok(())
            }
            Err(e) => Err(e),
        }
    }

    /// Test/fixture-only constructor: wrap an initial acceptor AND
    /// stamp the `leaf_not_after` gauge with a caller-supplied
    /// timestamp, bypassing X.509 parsing. Useful for /healthz
    /// expiry-gate tests that want to drive the gauge to a known
    /// past/future timestamp without having to mint a cert with
    /// matching wall-clock expiry.
    ///
    /// `#[doc(hidden)]` because this is **not** a production API —
    /// production paths must use [`Self::new_with_expiry`] so the
    /// gauge reflects the real cert. Kept `pub` (not `pub(crate)`)
    /// so cross-crate test fixtures (e.g. proteus-server's
    /// integration tests) can use it.
    #[doc(hidden)]
    #[must_use]
    pub fn with_leaf_not_after_for_testing(initial: TlsAcceptor, leaf_not_after: i64) -> Self {
        Self {
            inner: Arc::new(std::sync::RwLock::new(initial)),
            leaf_not_after: Arc::new(std::sync::atomic::AtomicI64::new(leaf_not_after)),
            reload_attempts: Arc::new(std::sync::atomic::AtomicU64::new(0)),
            reload_succeeded: Arc::new(std::sync::atomic::AtomicU64::new(0)),
        }
    }

    /// Current leaf cert `notAfter` as Unix seconds, or `None` if
    /// expiry tracking is not active (the `new` constructor was used
    /// instead of `new_with_expiry` / `reload_with_expiry`).
    ///
    /// Caller renders this as the `proteus_tls_cert_not_after_unix_seconds`
    /// Prometheus gauge AND the `admin status` "Cert" block.
    #[must_use]
    pub fn leaf_not_after(&self) -> Option<i64> {
        let ts = self
            .leaf_not_after
            .load(std::sync::atomic::Ordering::Relaxed);
        if ts == i64::MIN {
            None
        } else {
            Some(ts)
        }
    }

    /// Number of `reload`/`reload_with_expiry` calls received so far.
    #[must_use]
    pub fn reload_attempts(&self) -> u64 {
        self.reload_attempts
            .load(std::sync::atomic::Ordering::Relaxed)
    }

    /// Number of `reload_with_expiry` calls whose chain parsed cleanly.
    /// `reload_attempts() - reload_succeeded()` is the failure count
    /// (chain parse error OR the legacy `reload` path that doesn't
    /// supply a chain).
    #[must_use]
    pub fn reload_succeeded(&self) -> u64 {
        self.reload_succeeded
            .load(std::sync::atomic::Ordering::Relaxed)
    }

    /// Emit the cert / reload-counter Prometheus block. Returns an
    /// empty string when expiry tracking is not active AND no reloads
    /// have happened (the legacy code path that didn't wire any of
    /// this up — nothing useful to show).
    #[must_use]
    pub fn prometheus_extension(&self) -> String {
        let attempts = self.reload_attempts();
        let succeeded = self.reload_succeeded();
        let leaf = self.leaf_not_after();
        if attempts == 0 && leaf.is_none() {
            return String::new();
        }
        let mut out = String::new();
        if let Some(ts) = leaf {
            use std::fmt::Write;
            let _ = write!(
                out,
                "# HELP proteus_tls_cert_not_after_unix_seconds Leaf TLS cert's notAfter as Unix seconds (alert when (this - time()) < 14*86400).\n\
                 # TYPE proteus_tls_cert_not_after_unix_seconds gauge\n\
                 proteus_tls_cert_not_after_unix_seconds {ts}\n"
            );
        }
        use std::fmt::Write;
        let _ = write!(
            out,
            "# HELP proteus_tls_reload_attempts_total SIGHUP-style TLS reload attempts.\n\
             # TYPE proteus_tls_reload_attempts_total counter\n\
             proteus_tls_reload_attempts_total {attempts}\n\
             # HELP proteus_tls_reload_succeeded_total TLS reloads that swapped the acceptor AND parsed the new leaf cert.\n\
             # TYPE proteus_tls_reload_succeeded_total counter\n\
             proteus_tls_reload_succeeded_total {succeeded}\n"
        );
        out
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

    /// Builds a self-signed leaf cert + chain + acceptor for the
    /// cert-expiry / reload-counter test suite below.
    #[cfg(test)]
    fn mint_chain_and_acceptor() -> (Vec<CertificateDer<'static>>, TlsAcceptor) {
        use rcgen::generate_simple_self_signed;
        use rustls::pki_types::{PrivateKeyDer, PrivatePkcs8KeyDer};
        let ck = generate_simple_self_signed(vec!["localhost".to_string()]).unwrap();
        let cert = CertificateDer::from(ck.cert.der().to_vec());
        let key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(ck.key_pair.serialize_der()));
        let chain = vec![cert];
        let acceptor = build_acceptor(chain.clone(), key).unwrap();
        (chain, acceptor)
    }

    #[test]
    fn leaf_cert_not_after_extracts_a_sensible_timestamp() {
        let (chain, _) = mint_chain_and_acceptor();
        let ts = leaf_cert_not_after(&chain).unwrap();
        // rcgen default validity is "now ± a couple of years" — we
        // expect a timestamp that's in the future and not absurdly
        // far (e.g. >100 years out which would mean we parsed an
        // unrelated DER field).
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64;
        assert!(
            ts > now,
            "leaf notAfter {ts} should be in the future (> {now})"
        );
        // rcgen defaults to year-4096 notAfter (~2070yr out); allow up
        // to 3000 years so the test catches "we accidentally parsed the
        // wrong DER field" while staying tolerant of rcgen defaults.
        let three_thousand_years = 3000 * 365 * 86_400_i64;
        assert!(
            ts - now < three_thousand_years,
            "leaf notAfter {ts} suspiciously far from now ({now}): diff > 3000yr"
        );
    }

    #[test]
    fn leaf_cert_not_after_rejects_empty_chain() {
        let chain: Vec<CertificateDer<'_>> = vec![];
        assert!(leaf_cert_not_after(&chain).is_err());
    }

    #[test]
    fn leaf_cert_not_after_rejects_garbage_der() {
        // Construct a "cert" that's just random bytes — must not panic,
        // must surface BadPem.
        let chain = vec![CertificateDer::from(vec![0xFFu8; 64])];
        let err = leaf_cert_not_after(&chain).unwrap_err();
        match err {
            TlsError::BadPem { .. } => {}
            other => panic!("expected BadPem, got {other:?}"),
        }
    }

    #[test]
    fn reloadable_acceptor_legacy_new_has_no_expiry_tracking() {
        let (_, acceptor) = mint_chain_and_acceptor();
        let r = ReloadableAcceptor::new(acceptor);
        assert!(
            r.leaf_not_after().is_none(),
            "legacy new() must not track expiry"
        );
        assert_eq!(r.reload_attempts(), 0);
        assert_eq!(r.reload_succeeded(), 0);
    }

    #[test]
    fn reloadable_acceptor_new_with_expiry_records_leaf_timestamp() {
        let (chain, acceptor) = mint_chain_and_acceptor();
        let r = ReloadableAcceptor::new_with_expiry(acceptor, &chain);
        let ts = r.leaf_not_after().expect("expiry should be tracked");
        let expected = leaf_cert_not_after(&chain).unwrap();
        assert_eq!(ts, expected);
    }

    #[test]
    fn reload_with_expiry_bumps_both_counters_on_success() {
        let (chain1, acceptor1) = mint_chain_and_acceptor();
        let r = ReloadableAcceptor::new_with_expiry(acceptor1, &chain1);
        let ts1 = r.leaf_not_after().unwrap();

        let (chain2, acceptor2) = mint_chain_and_acceptor();
        r.reload_with_expiry(acceptor2, &chain2).unwrap();

        assert_eq!(r.reload_attempts(), 1);
        assert_eq!(r.reload_succeeded(), 1);
        let ts2 = r.leaf_not_after().unwrap();
        // Both certs minted "now ± Xyr" so timestamps should be close
        // (within a few seconds for the rcgen minting time).
        assert!((ts2 - ts1).abs() < 60, "ts1={ts1} ts2={ts2}");
    }

    #[test]
    fn legacy_reload_bumps_attempts_but_not_succeeded() {
        let (chain, acceptor) = mint_chain_and_acceptor();
        let r = ReloadableAcceptor::new_with_expiry(acceptor, &chain);

        let (_, acceptor2) = mint_chain_and_acceptor();
        r.reload(acceptor2);

        assert_eq!(r.reload_attempts(), 1);
        assert_eq!(
            r.reload_succeeded(),
            0,
            "legacy reload() must not bump _succeeded — no chain was supplied"
        );
        // expiry gauge unchanged (no chain → no parse → no update).
        assert!(r.leaf_not_after().is_some());
    }

    #[test]
    fn reload_with_expiry_bumps_attempts_even_when_parse_fails() {
        let (chain, acceptor) = mint_chain_and_acceptor();
        let r = ReloadableAcceptor::new_with_expiry(acceptor, &chain);
        let before_ts = r.leaf_not_after().unwrap();

        let (_, acceptor2) = mint_chain_and_acceptor();
        let bad_chain = vec![CertificateDer::from(vec![0xAAu8; 32])];
        let err = r.reload_with_expiry(acceptor2, &bad_chain).unwrap_err();
        match err {
            TlsError::BadPem { .. } => {}
            other => panic!("expected BadPem, got {other:?}"),
        }

        // Attempts went up; succeeded did NOT.
        assert_eq!(r.reload_attempts(), 1);
        assert_eq!(r.reload_succeeded(), 0);
        // Expiry gauge held its previous value (no confusing dip).
        assert_eq!(r.leaf_not_after(), Some(before_ts));
    }

    #[test]
    fn prometheus_extension_is_empty_in_legacy_mode() {
        let (_, acceptor) = mint_chain_and_acceptor();
        let r = ReloadableAcceptor::new(acceptor);
        assert_eq!(r.prometheus_extension(), "");
    }

    #[test]
    fn prometheus_extension_emits_cert_and_counters() {
        let (chain, acceptor) = mint_chain_and_acceptor();
        let r = ReloadableAcceptor::new_with_expiry(acceptor, &chain);
        let (chain2, acceptor2) = mint_chain_and_acceptor();
        r.reload_with_expiry(acceptor2, &chain2).unwrap();

        let p = r.prometheus_extension();
        assert!(
            p.contains("proteus_tls_cert_not_after_unix_seconds"),
            "missing cert-expiry gauge in: {p}"
        );
        assert!(
            p.contains("proteus_tls_reload_attempts_total 1"),
            "missing/wrong attempts counter in: {p}"
        );
        assert!(
            p.contains("proteus_tls_reload_succeeded_total 1"),
            "missing/wrong succeeded counter in: {p}"
        );
        // Every series must have HELP + TYPE rows.
        let help_lines = p.lines().filter(|l| l.starts_with("# HELP")).count();
        let type_lines = p.lines().filter(|l| l.starts_with("# TYPE")).count();
        assert_eq!(help_lines, 3, "expected 3 HELP rows in: {p}");
        assert_eq!(type_lines, 3, "expected 3 TYPE rows in: {p}");
    }

    #[test]
    fn prometheus_extension_emits_only_counters_when_expiry_untracked() {
        // Edge case: someone calls reload() (no chain) on a
        // legacy-constructed acceptor. We should still emit counters
        // because reload_attempts > 0 — operator wants to see SIGHUP
        // activity even without expiry data.
        let (_, acceptor) = mint_chain_and_acceptor();
        let r = ReloadableAcceptor::new(acceptor);
        let (_, acceptor2) = mint_chain_and_acceptor();
        r.reload(acceptor2);

        let p = r.prometheus_extension();
        assert!(
            !p.contains("proteus_tls_cert_not_after_unix_seconds"),
            "should NOT emit cert gauge when untracked: {p}"
        );
        assert!(p.contains("proteus_tls_reload_attempts_total 1"));
        assert!(p.contains("proteus_tls_reload_succeeded_total 0"));
    }
}
