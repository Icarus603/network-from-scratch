//! RFC 9849 Encrypted ClientHello termination for Proteus.
//!
//! This crate deliberately keeps ECH in the same process and after the
//! existing Path-A knock gate.  BoringSSL owns the TLS transcript, ECH
//! decryption, acceptance confirmation, and exporter.  Proteus consumes
//! only the authenticated plaintext stream and exporter bytes.
//!
//! The data plane is fail-closed: [`EchAcceptor::accept_required`] returns
//! no usable stream unless BoringSSL reports a TLS 1.3 handshake with ECH
//! accepted.  GREASE, stale keys, and an active downgrade therefore cannot
//! silently enter the inner Proteus handshake.

use std::path::Path;

use boring::hpke::HpkeKey;
use boring::pkey::{PKey, Private};
use boring::ssl::{SslAcceptor, SslEchKeys, SslFiletype, SslMethod, SslVersion};
use boring::x509::X509;
use rand_core::OsRng;
use tokio::io::{AsyncRead, AsyncWrite};
use x25519_dalek::{PublicKey, StaticSecret};
use zeroize::Zeroizing;

/// TLS exporter label shared with the Proteus α client and server.
pub const EXPORTER_LABEL: &str = "EXPORTER-Proteus-Channel-Binding-v1";

/// Length of the exporter mixed into the inner Proteus transcript.
pub const EXPORTER_LEN: usize = 32;

/// BoringSSL-backed TLS stream exposed without making consumers name
/// the implementation crate directly.
pub type EchTlsStream<S> = tokio_boring::SslStream<S>;

/// One server ECHConfig and its matching X25519 HPKE private key.
///
/// `ech_config` is a single RFC 9849 `ECHConfig`, without the outer
/// two-byte `ECHConfigList` length.  `private_key` is the raw 32-byte
/// X25519 private key emitted by `bssl generate-ech`.
#[derive(Clone)]
pub struct EchKey {
    pub ech_config: Vec<u8>,
    pub private_key: Zeroizing<Vec<u8>>,
    pub retry_config: bool,
}

/// Fresh RFC 9849 server material ready for disk publication.
#[derive(Debug)]
pub struct GeneratedEchKey {
    /// Single server config and matching private key.
    pub key: EchKey,
    /// Length-prefixed ECHConfigList published through DNS HTTPS.
    pub config_list: Vec<u8>,
}

/// Generate an X25519 ECHConfig and matching private key.
///
/// The config advertises HKDF-SHA256 with AES-128-GCM and
/// ChaCha20-Poly1305, the mandatory-to-implement ECH cipher suites.
/// The returned key is marked as a retry config; operators retaining
/// an old overlap key must explicitly set that old key's flag false.
pub fn generate_ech_key(
    config_id: u8,
    public_name: &str,
    max_name_length: u8,
) -> Result<GeneratedEchKey, EchError> {
    validate_public_name(public_name)?;
    if max_name_length == 0 {
        return Err(EchError::BadMaxNameLength);
    }

    let secret = StaticSecret::random_from_rng(OsRng);
    let public = PublicKey::from(&secret);
    let mut contents = Vec::with_capacity(64 + public_name.len());
    contents.push(config_id);
    contents.extend_from_slice(&0x0020u16.to_be_bytes()); // DHKEM(X25519, HKDF-SHA256)
    contents.extend_from_slice(&32u16.to_be_bytes());
    contents.extend_from_slice(public.as_bytes());
    contents.extend_from_slice(&8u16.to_be_bytes());
    contents.extend_from_slice(&0x0001u16.to_be_bytes()); // HKDF-SHA256
    contents.extend_from_slice(&0x0001u16.to_be_bytes()); // AES-128-GCM
    contents.extend_from_slice(&0x0001u16.to_be_bytes()); // HKDF-SHA256
    contents.extend_from_slice(&0x0003u16.to_be_bytes()); // ChaCha20-Poly1305
    contents.push(max_name_length);
    contents.push(public_name.len() as u8);
    contents.extend_from_slice(public_name.as_bytes());
    contents.extend_from_slice(&0u16.to_be_bytes()); // ECHConfig extensions

    let mut config = Vec::with_capacity(contents.len() + 4);
    config.extend_from_slice(&0xfe0du16.to_be_bytes());
    config.extend_from_slice(&(contents.len() as u16).to_be_bytes());
    config.extend_from_slice(&contents);
    let mut config_list = Vec::with_capacity(config.len() + 2);
    config_list.extend_from_slice(&(config.len() as u16).to_be_bytes());
    config_list.extend_from_slice(&config);

    Ok(GeneratedEchKey {
        key: EchKey {
            ech_config: config,
            private_key: Zeroizing::new(secret.to_bytes().to_vec()),
            retry_config: true,
        },
        config_list,
    })
}

fn validate_public_name(name: &str) -> Result<(), EchError> {
    if name.is_empty() || name.len() > 253 || !name.is_ascii() {
        return Err(EchError::BadPublicName);
    }
    for label in name.split('.') {
        if label.is_empty()
            || label.len() > 63
            || label.starts_with('-')
            || label.ends_with('-')
            || !label
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
        {
            return Err(EchError::BadPublicName);
        }
    }
    Ok(())
}

impl std::fmt::Debug for EchKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("EchKey")
            .field("ech_config_len", &self.ech_config.len())
            .field("private_key", &"[REDACTED]")
            .field("retry_config", &self.retry_config)
            .finish()
    }
}

/// A completed, ECH-authenticated TLS connection.
pub struct Accepted<S> {
    pub stream: tokio_boring::SslStream<S>,
    pub exporter: Zeroizing<[u8; EXPORTER_LEN]>,
}

/// Reloadable BoringSSL server context.
///
/// BoringSSL reference-counts the underlying `SSL_CTX`; cloning the
/// acceptor is cheap and safe across concurrent Tokio tasks.
#[derive(Clone)]
pub struct EchAcceptor {
    inner: SslAcceptor,
}

impl EchAcceptor {
    /// Build an ECH-required TLS 1.3 acceptor from PEM files.
    pub fn from_pem_files(
        cert_chain: &Path,
        private_key: &Path,
        keys: &[EchKey],
    ) -> Result<Self, EchError> {
        let mut builder = base_builder(keys)?;
        builder.set_certificate_chain_file(cert_chain)?;
        builder.set_private_key_file(private_key, SslFiletype::PEM)?;
        builder.check_private_key()?;
        Ok(Self {
            inner: builder.build(),
        })
    }

    /// Build from already parsed certificate material.
    ///
    /// This is also the narrow seam used by in-memory integration tests.
    pub fn from_certificate(
        leaf: X509,
        chain: Vec<X509>,
        private_key: PKey<Private>,
        keys: &[EchKey],
    ) -> Result<Self, EchError> {
        let mut builder = base_builder(keys)?;
        builder.set_certificate(&leaf)?;
        for cert in chain {
            builder.add_extra_chain_cert(cert)?;
        }
        builder.set_private_key(&private_key)?;
        builder.check_private_key()?;
        Ok(Self {
            inner: builder.build(),
        })
    }

    /// Terminate TLS and require an authenticated ECH acceptance.
    ///
    /// A successfully authenticated outer-only or GREASE handshake is
    /// still rejected.  This is intentional: once the operator enables
    /// this backend, cleartext SNI is a policy failure, not a fallback.
    pub async fn accept_required<S>(&self, io: S) -> Result<Accepted<S>, EchError>
    where
        S: AsyncRead + AsyncWrite + Unpin,
    {
        let stream = tokio_boring::accept(&self.inner, io)
            .await
            .map_err(|error| EchError::Handshake(error.to_string()))?;
        if stream.ssl().version2() != Some(SslVersion::TLS1_3) {
            return Err(EchError::TlsVersion);
        }
        if !stream.ssl().ech_accepted() {
            return Err(EchError::NotAccepted);
        }
        let mut exporter = Zeroizing::new([0u8; EXPORTER_LEN]);
        stream
            .ssl()
            .export_keying_material(&mut exporter[..], EXPORTER_LABEL, None)?;
        Ok(Accepted { stream, exporter })
    }
}

fn base_builder(keys: &[EchKey]) -> Result<boring::ssl::SslAcceptorBuilder, EchError> {
    if keys.is_empty() {
        return Err(EchError::NoKeys);
    }
    if !keys.iter().any(|key| key.retry_config) {
        return Err(EchError::NoRetryKey);
    }

    let mut ech_keys = SslEchKeys::builder()?;
    for item in keys {
        if item.private_key.len() != 32 {
            return Err(EchError::BadPrivateKeyLength(item.private_key.len()));
        }
        let key = HpkeKey::dhkem_p256_sha256(&item.private_key)?;
        ech_keys.add_key(item.retry_config, &item.ech_config, key)?;
    }
    let ech_keys = ech_keys.build();

    // The legacy `mozilla_modern` helper in the OpenSSL-compatible API
    // explicitly disables TLS 1.3.  `mozilla_intermediate_v5` keeps it
    // enabled; the exact min/max bounds below then remove every older
    // version.
    let mut builder = SslAcceptor::mozilla_intermediate_v5(SslMethod::tls())?;
    builder.set_min_proto_version(Some(SslVersion::TLS1_3))?;
    builder.set_max_proto_version(Some(SslVersion::TLS1_3))?;
    builder.set_ech_keys(&ech_keys)?;
    Ok(builder)
}

#[derive(Debug, thiserror::Error)]
pub enum EchError {
    #[error("BoringSSL: {0}")]
    Boring(#[from] boring::error::ErrorStack),
    #[error("ECH TLS handshake: {0}")]
    Handshake(String),
    #[error("ECH requires at least one configured key")]
    NoKeys,
    #[error("ECH requires at least one retry config")]
    NoRetryKey,
    #[error("ECH X25519 private key must be 32 bytes, got {0}")]
    BadPrivateKeyLength(usize),
    #[error("ECH public_name must be a 1..253-byte ASCII DNS name with valid labels")]
    BadPublicName,
    #[error("ECH max_name_length must be in 1..255")]
    BadMaxNameLength,
    #[error("ECH backend negotiated a TLS version other than TLS 1.3")]
    TlsVersion,
    #[error("ECH was not accepted; refusing cleartext-SNI fallback")]
    NotAccepted,
}

#[cfg(test)]
mod tests {
    use std::pin::Pin;
    use std::sync::{Arc, Mutex};
    use std::task::{Context, Poll};

    use super::*;
    use boring::ssl::{SslConnector, SslVerifyMode};
    use rand_core::OsRng;
    use rcgen::{CertificateParams, KeyPair};
    use x25519_dalek::{PublicKey, StaticSecret};

    const PUBLIC_NAME: &str = "public.example";
    const INNER_NAME: &str = "secret.example";

    #[derive(Debug)]
    struct RecordingIo {
        inner: tokio::io::DuplexStream,
        written: Arc<Mutex<Vec<u8>>>,
    }

    impl AsyncRead for RecordingIo {
        fn poll_read(
            mut self: Pin<&mut Self>,
            cx: &mut Context<'_>,
            buffer: &mut tokio::io::ReadBuf<'_>,
        ) -> Poll<std::io::Result<()>> {
            Pin::new(&mut self.inner).poll_read(cx, buffer)
        }
    }

    impl AsyncWrite for RecordingIo {
        fn poll_write(
            mut self: Pin<&mut Self>,
            cx: &mut Context<'_>,
            bytes: &[u8],
        ) -> Poll<std::io::Result<usize>> {
            match Pin::new(&mut self.inner).poll_write(cx, bytes) {
                Poll::Ready(Ok(written)) => {
                    self.written
                        .lock()
                        .unwrap_or_else(std::sync::PoisonError::into_inner)
                        .extend_from_slice(&bytes[..written]);
                    Poll::Ready(Ok(written))
                }
                other => other,
            }
        }

        fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
            Pin::new(&mut self.inner).poll_flush(cx)
        }

        fn poll_shutdown(
            mut self: Pin<&mut Self>,
            cx: &mut Context<'_>,
        ) -> Poll<std::io::Result<()>> {
            Pin::new(&mut self.inner).poll_shutdown(cx)
        }
    }

    fn contains_bytes(haystack: &[u8], needle: &[u8]) -> bool {
        haystack
            .windows(needle.len())
            .any(|window| window == needle)
    }

    fn material(config_id: u8) -> (EchKey, Vec<u8>) {
        let secret = StaticSecret::random_from_rng(OsRng);
        let public = PublicKey::from(&secret);
        let mut contents = Vec::new();
        contents.push(config_id);
        contents.extend_from_slice(&0x0020u16.to_be_bytes());
        contents.extend_from_slice(&32u16.to_be_bytes());
        contents.extend_from_slice(public.as_bytes());
        contents.extend_from_slice(&8u16.to_be_bytes());
        contents.extend_from_slice(&0x0001u16.to_be_bytes());
        contents.extend_from_slice(&0x0001u16.to_be_bytes());
        contents.extend_from_slice(&0x0001u16.to_be_bytes());
        contents.extend_from_slice(&0x0003u16.to_be_bytes());
        contents.push(INNER_NAME.len() as u8);
        contents.push(PUBLIC_NAME.len() as u8);
        contents.extend_from_slice(PUBLIC_NAME.as_bytes());
        contents.extend_from_slice(&0u16.to_be_bytes());

        let mut config = Vec::new();
        config.extend_from_slice(&0xfe0du16.to_be_bytes());
        config.extend_from_slice(&(contents.len() as u16).to_be_bytes());
        config.extend_from_slice(&contents);

        let mut list = Vec::new();
        list.extend_from_slice(&(config.len() as u16).to_be_bytes());
        list.extend_from_slice(&config);
        (
            EchKey {
                ech_config: config,
                private_key: Zeroizing::new(secret.to_bytes().to_vec()),
                retry_config: true,
            },
            list,
        )
    }

    fn certificate() -> (X509, PKey<Private>) {
        let key = KeyPair::generate().unwrap();
        let params =
            CertificateParams::new(vec![INNER_NAME.to_owned(), PUBLIC_NAME.to_owned()]).unwrap();
        let cert = params.self_signed(&key).unwrap();
        (
            X509::from_der(cert.der().as_ref()).unwrap(),
            PKey::private_key_from_der(&key.serialize_der()).unwrap(),
        )
    }

    #[tokio::test]
    async fn real_ech_acceptance_and_exporter_match() {
        let (key, list) = material(7);
        let (cert, private_key) = certificate();
        let acceptor =
            EchAcceptor::from_certificate(cert.clone(), vec![], private_key, &[key]).unwrap();

        let mut connector = SslConnector::builder(SslMethod::tls()).unwrap();
        connector
            .set_min_proto_version(Some(SslVersion::TLS1_3))
            .unwrap();
        connector
            .set_max_proto_version(Some(SslVersion::TLS1_3))
            .unwrap();
        // The test certificate is a self-signed leaf, not a CA.  Disable
        // WebPKI only in this in-memory test; ECH acceptance and exporter
        // equality remain cryptographically exercised by BoringSSL.
        connector.set_verify(SslVerifyMode::NONE);
        let connector = connector.build();
        let mut client = connector.configure().unwrap();
        client.set_verify_hostname(true);
        client.set_ech_config_list(&list).unwrap();

        let (client_io, server_io) = tokio::io::duplex(16 * 1024);
        let wire = Arc::new(Mutex::new(Vec::new()));
        let client_io = RecordingIo {
            inner: client_io,
            written: Arc::clone(&wire),
        };
        let (client_result, server_result) = tokio::join!(
            tokio_boring::connect(client, INNER_NAME, client_io),
            acceptor.accept_required(server_io)
        );
        let accepted = server_result.unwrap();
        let client_stream = client_result.unwrap();
        assert!(client_stream.ssl().ech_accepted());
        let captured = wire
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        assert!(
            contains_bytes(&captured, PUBLIC_NAME.as_bytes()),
            "ClientHelloOuter must carry the ECH public name"
        );
        assert!(
            !contains_bytes(&captured, INNER_NAME.as_bytes()),
            "the real inner SNI must never appear in cleartext on the wire"
        );
        let mut client_exporter = [0u8; EXPORTER_LEN];
        client_stream
            .ssl()
            .export_keying_material(&mut client_exporter, EXPORTER_LABEL, None)
            .unwrap();

        assert_eq!(&*accepted.exporter, &client_exporter);
    }

    #[tokio::test]
    async fn grease_or_plain_client_cannot_enter_data_plane() {
        let (key, _list) = material(9);
        let (cert, private_key) = certificate();
        let acceptor =
            EchAcceptor::from_certificate(cert.clone(), vec![], private_key, &[key]).unwrap();

        let mut connector = SslConnector::builder(SslMethod::tls()).unwrap();
        connector.set_verify(SslVerifyMode::NONE);
        let connector = connector.build();
        let client = connector.configure().unwrap();

        let (client_io, server_io) = tokio::io::duplex(16 * 1024);
        let (client_result, server_result) = tokio::join!(
            tokio_boring::connect(client, INNER_NAME, client_io),
            acceptor.accept_required(server_io)
        );
        assert!(client_result.is_ok(), "{client_result:?}");
        assert!(matches!(server_result, Err(EchError::NotAccepted)));
    }

    #[test]
    fn key_set_requires_retry_config_and_exact_x25519_key() {
        let (mut key, _) = material(1);
        key.retry_config = false;
        let err = base_builder(&[key.clone()])
            .err()
            .expect("non-retry key must fail");
        assert!(matches!(err, EchError::NoRetryKey));

        key.retry_config = true;
        key.private_key = Zeroizing::new(vec![0u8; 31]);
        let err = base_builder(&[key])
            .err()
            .expect("short X25519 key must fail");
        assert!(matches!(err, EchError::BadPrivateKeyLength(31)));
    }

    #[test]
    fn generated_material_is_accepted_and_dns_list_is_exact() {
        let generated = generate_ech_key(42, PUBLIC_NAME, 64).unwrap();
        assert_eq!(
            &generated.config_list[2..],
            generated.key.ech_config.as_slice()
        );
        assert_eq!(
            usize::from(u16::from_be_bytes(
                generated.config_list[..2].try_into().unwrap()
            )),
            generated.key.ech_config.len()
        );
        let (cert, private_key) = certificate();
        EchAcceptor::from_certificate(cert, vec![], private_key, &[generated.key]).unwrap();
    }

    #[test]
    fn generation_rejects_non_dns_names_and_zero_padding_limit() {
        for name in [
            "",
            "-bad.example",
            "bad-.example",
            "bad..example",
            "例.example",
        ] {
            assert!(matches!(
                generate_ech_key(1, name, 64),
                Err(EchError::BadPublicName)
            ));
        }
        assert!(matches!(
            generate_ech_key(1, PUBLIC_NAME, 0),
            Err(EchError::BadMaxNameLength)
        ));
    }
}
