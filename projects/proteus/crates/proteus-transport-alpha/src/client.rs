//! α-profile client driver.

use std::time::{SystemTime, UNIX_EPOCH};

use ml_kem::kem::EncapsulationKey;
use ml_kem::{EncodedSizeUser, MlKem768Params};
use proteus_crypto::{
    aead, kex,
    key_schedule::{self, Transcript},
    sig,
};
use proteus_handshake::auth_tag;
use proteus_spec::{HMAC_TAG_LEN, PROTEUS_VERSION_V10};
use proteus_wire::{alpha, AuthExtension, ProfileHint};
use rand_core::OsRng;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

use crate::error::{AlphaError, AlphaResult};
use crate::session::AlphaSession;

/// Configuration handed to the client driver.
pub struct ClientConfig {
    /// Server's long-term ML-KEM-768 public-key bytes.
    pub server_mlkem_pk_bytes: Vec<u8>,
    /// Server's long-term X25519 public key (32 bytes).
    pub server_x25519_pub: [u8; 32],
    /// Server PQ fingerprint (= SHA-256 of `server_mlkem_pk_bytes`).
    pub server_pq_fingerprint: [u8; 32],
    /// Client's Ed25519 signing key (long-term identity).
    pub client_id_sk: ed25519_dalek::SigningKey,
    /// Per-user identifier (8 bytes — embedded into `client_id` AEAD-encrypted).
    pub user_id: [u8; 8],
    /// Server-advertised proof-of-work difficulty (out-of-band, e.g.
    /// distributed via the same channel as the keys). 0 = no work.
    /// spec §8.3.
    pub pow_difficulty: u8,
    /// Profile-hint byte the client embeds in its AuthExtension.
    /// Defaults to `ProfileHint::Alpha` for backward compatibility;
    /// the proteus-transport-beta crate overrides this to
    /// `ProfileHint::Beta`. spec §4.1.
    pub profile_hint: ProfileHint,
}

impl ClientConfig {
    /// Constructor for callers who don't yet model PoW.
    #[must_use]
    pub fn new(
        server_mlkem_pk_bytes: Vec<u8>,
        server_x25519_pub: [u8; 32],
        server_pq_fingerprint: [u8; 32],
        client_id_sk: ed25519_dalek::SigningKey,
        user_id: [u8; 8],
    ) -> Self {
        Self {
            server_mlkem_pk_bytes,
            server_x25519_pub,
            server_pq_fingerprint,
            client_id_sk,
            user_id,
            pow_difficulty: 0,
            profile_hint: ProfileHint::Alpha,
        }
    }
}

/// Drive a profile-α handshake to `target`, returning a ready
/// [`AlphaSession`].
pub async fn connect(target: &str, config: &ClientConfig) -> AlphaResult<AlphaSession> {
    let stream = TcpStream::connect(target).await?;
    handshake_over_tcp(stream, config).await
}

/// As [`connect`], but takes an already-established TCP socket. Useful
/// for testing.
pub async fn handshake_over_tcp(
    stream: TcpStream,
    config: &ClientConfig,
) -> AlphaResult<AlphaSession> {
    stream.set_nodelay(true)?;
    let (read, write) = stream.into_split();
    handshake_over_split(read, write, config).await
}

/// Run a Proteus α handshake over a TLS 1.3 outer wrapper. The
/// `server_dns_name` MUST match the server's TLS certificate's SAN.
pub async fn handshake_over_tls(
    stream: TcpStream,
    connector: &tokio_rustls::TlsConnector,
    server_dns_name: &str,
    config: &ClientConfig,
) -> AlphaResult<
    AlphaSession<
        tokio::io::ReadHalf<crate::tls::ClientStream>,
        tokio::io::WriteHalf<crate::tls::ClientStream>,
    >,
> {
    stream.set_nodelay(true)?;
    let sn = crate::tls::server_name(server_dns_name)
        .map_err(|e| AlphaError::Io(std::io::Error::other(e.to_string())))?;
    let tls_stream = crate::tls::client_handshake(connector, sn, stream)
        .await
        .map_err(|e| AlphaError::Io(std::io::Error::other(e.to_string())))?;
    let (read, write) = tokio::io::split(tls_stream);
    handshake_over_split(read, write, config).await
}

/// Inner handshake driver, generic over any AsyncRead/AsyncWrite split.
pub async fn handshake_over_split<R, W>(
    read: R,
    write: W,
    config: &ClientConfig,
) -> AlphaResult<AlphaSession<R, W>>
where
    R: tokio::io::AsyncRead + Unpin,
    W: tokio::io::AsyncWrite + Unpin,
{
    // ----- 1. Build the auth extension -----
    let mut rng = OsRng;

    // Parse the server's ML-KEM-768 EK into the in-memory type.
    let ek_array = ml_kem::array::Array::<u8, _>::try_from(&config.server_mlkem_pk_bytes[..])
        .expect("mlkem pk");
    let server_mlkem_pk = EncapsulationKey::<MlKem768Params>::from_bytes(&ek_array);

    let client_eph = kex::client_ephemeral(&mut rng, &server_mlkem_pk)?;
    let combined_dh = kex::client_combine(&client_eph, &config.server_x25519_pub)?;

    // shape/cover/identity flags — all zeroes for M1, will be populated in M3.
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);

    // client_id = AEAD(K_cid, n=client_nonce[..12], ad="proteus-cid-v1", pt=user_id||flags)
    // K_cid = HKDF-Expand(server_pq_fingerprint, "proteus-cid-key-v1", 32)
    let mut client_nonce = [0u8; 16];
    rand_core::RngCore::fill_bytes(&mut rng, &mut client_nonce);

    let mut cid_key = [0u8; 32];
    proteus_crypto::kdf::expand_label(
        &config.server_pq_fingerprint,
        b"proteus-cid-key-v1",
        b"",
        &mut cid_key,
    )?;
    let mut cid_n = [0u8; 12];
    cid_n.copy_from_slice(&client_nonce[..12]);
    let mut cid_pt = [0u8; 16];
    cid_pt[..8].copy_from_slice(&config.user_id);
    // flags zeroed (M1)
    let cid_ct = aead::seal(&cid_key, &[0u8; 12], 0, b"proteus-cid-v1", &cid_pt)?;
    // Truncate the 32-byte ciphertext to 24 bytes (spec §5.7.1).
    let mut client_id = [0u8; 24];
    client_id.copy_from_slice(&cid_ct[..24]);
    // Silence unused-warning on cid_n (kept for future spec-strict use of
    // a unique nonce per client).
    let _ = cid_n;

    // Build the signature over (version || nonce || x25519_pub || mlkem_ct).
    let mut sig_msg = Vec::with_capacity(1 + 16 + 32 + 1088);
    sig_msg.push(PROTEUS_VERSION_V10);
    sig_msg.extend_from_slice(&client_nonce);
    sig_msg.extend_from_slice(&client_eph.x25519_pub);
    sig_msg.extend_from_slice(&client_eph.mlkem_ct);
    let sig_bytes = sig::sign(&config.client_id_sk, &sig_msg);

    // Solve the server-advertised proof-of-work puzzle (spec §8.3).
    // For difficulty 0 (default) this returns [0; 7] in O(1).
    let pow_solution = crate::pow::solve(
        &config.server_pq_fingerprint,
        &client_nonce,
        config.pow_difficulty,
    )
    .ok_or_else(|| {
        AlphaError::Io(std::io::Error::other(
            "anti-DoS puzzle search space exhausted",
        ))
    })?;

    let mut ext = AuthExtension {
        version: PROTEUS_VERSION_V10,
        profile_hint: config.profile_hint,
        client_nonce,
        client_x25519_pub: client_eph.x25519_pub,
        client_mlkem768_ct: client_eph.mlkem_ct,
        client_id,
        timestamp_unix_seconds: now,
        cover_profile_id: proteus_spec::COVER_PROFILE_API_POLL,
        shape_seed: 0x4242_4242,
        anti_dos_difficulty: config.pow_difficulty,
        anti_dos_solution: pow_solution,
        client_kex_sig: sig_bytes,
        client_kex_sig_pq: [0u8; 96], // M1: PQ-sig deferred to M2
        auth_tag: [0u8; HMAC_TAG_LEN],
    };

    // Compute HMAC auth_tag.
    let auth_key = auth_tag::derive_auth_key(
        &config.server_pq_fingerprint,
        &ext.client_x25519_pub,
        &ext.client_nonce,
    );
    let mac_input = ext.auth_mac_input();
    let tag = auth_tag::compute(&auth_key, &mac_input);
    ext.auth_tag = tag;

    // ----- 2. Send ClientHello frame -----
    let ch_payload = ext.encode_payload();
    let ch_frame = alpha::encode_handshake(alpha::FRAME_CLIENT_HELLO, &ch_payload);
    let mut write = write;
    write.write_all(&ch_frame).await?;

    let mut transcript = Transcript::new();
    transcript.update(&ch_payload);

    // ----- 3. Read ServerHello -----
    let mut read = read;
    let mut rx_buf: Vec<u8> = Vec::with_capacity(256);
    let sh_frame = read_frame(&mut read, &mut rx_buf).await?;
    if sh_frame.kind != alpha::FRAME_SERVER_HELLO {
        return Err(AlphaError::Closed);
    }
    if sh_frame.body.len() != 32 {
        return Err(AlphaError::Closed);
    }
    let mut server_x25519_pub = [0u8; 32];
    server_x25519_pub.copy_from_slice(&sh_frame.body);
    transcript.update(&sh_frame.body);
    let th_ch_sh = transcript.snapshot();

    // ----- 4. Derive hybrid shared + key schedule -----
    let mut hybrid_shared = [0u8; 64];
    hybrid_shared[..32].copy_from_slice(&combined_dh[..32]);
    hybrid_shared[32..].copy_from_slice(&combined_dh[32..]);

    // Receive ServerFinished and verify before we accept the keys.
    let sf_frame = read_frame(&mut read, &mut rx_buf).await?;
    if sf_frame.kind != alpha::FRAME_SERVER_FINISHED {
        return Err(AlphaError::Closed);
    }
    if sf_frame.body.len() != 32 {
        return Err(AlphaError::BadServerFinished);
    }
    let received_server_finished: [u8; 32] = (&sf_frame.body[..]).try_into().unwrap();

    // Server's Finished MAC is over the transcript hash so far (ch || sh).
    // We do not append the SF bytes themselves to the transcript before
    // computing client_finished — RFC 8446 §4.4.4 binds CF to transcript(SF).
    let th_ch_sf = key_schedule::sha256(&{
        let mut h = Vec::new();
        h.extend_from_slice(&ch_payload);
        h.extend_from_slice(&sh_frame.body);
        h.extend_from_slice(&sf_frame.body);
        h
    });

    // For the resumption-master-secret derivation we also need a hash
    // including ClientFinished. We compute it after we build CF below.

    // Pre-derive provisional secrets to validate the ServerFinished MAC.
    // The ServerFinished MAC is HMAC-SHA-256(finished_key_server, th_ch_sh)
    // where finished_key_server = HKDF-Expand-Label(s_ap_secret_provisional, "finished", "", 32).
    // To avoid a circular dependency we use the hs-stage server traffic
    // secret derived from a separate label.
    let provisional = key_schedule::derive(
        &client_nonce,
        &hybrid_shared,
        &th_ch_sh,
        &th_ch_sh, // for finished key purposes — pre-CF
        &th_ch_sh,
    )?;

    let mut server_finished_key = [0u8; 32];
    proteus_crypto::kdf::expand_label(
        &provisional.s_ap_secret,
        b"finished",
        b"",
        &mut server_finished_key,
    )?;
    let expected_sf = hmac_sha256(&server_finished_key, &th_ch_sh);
    if !ct_eq(&expected_sf, &received_server_finished) {
        return Err(AlphaError::BadServerFinished);
    }

    // ----- 5. Send ClientFinished -----
    let mut client_finished_key = [0u8; 32];
    proteus_crypto::kdf::expand_label(
        &provisional.c_ap_secret,
        b"finished",
        b"",
        &mut client_finished_key,
    )?;
    let cf_mac = hmac_sha256(&client_finished_key, &th_ch_sf);
    let cf_frame = alpha::encode_handshake(alpha::FRAME_CLIENT_FINISHED, &cf_mac);
    write.write_all(&cf_frame).await?;

    // ----- 6. Final secrets (rebind to th_ch_cf for resumption_master_secret) -----
    let th_ch_cf = key_schedule::sha256(&{
        let mut h = Vec::new();
        h.extend_from_slice(&ch_payload);
        h.extend_from_slice(&sh_frame.body);
        h.extend_from_slice(&sf_frame.body);
        h.extend_from_slice(&cf_mac);
        h
    });
    let final_secrets = key_schedule::derive(
        &client_nonce,
        &hybrid_shared,
        &th_ch_sh,
        &th_ch_sf,
        &th_ch_cf,
    )?;

    let (c_keys, s_keys) = final_secrets.direction_keys()?;
    // Client sends with c_ap_secret keys; receives with s_ap_secret keys.
    // Any tail bytes left over in rx_buf are post-handshake DATA records
    // that arrived coalesced with SF — pass them to the receiver.
    Ok(AlphaSession::with_prefix(
        write,
        read,
        c_keys,
        s_keys,
        final_secrets.c_ap_secret.clone(),
        final_secrets.s_ap_secret.clone(),
        rx_buf,
    ))
}

/// Read one frame, draining bytes from a **persistent** receive buffer
/// owned by the caller. This is critical: TCP coalesces small adjacent
/// writes, so a single `read()` may surface multiple frames at once.
/// Using a fresh buffer per call would discard any tail past the first
/// frame and cause the next call to block forever.
async fn read_frame<R: tokio::io::AsyncRead + Unpin>(
    read: &mut R,
    buf: &mut Vec<u8>,
) -> AlphaResult<OwnedFrame> {
    loop {
        if !buf.is_empty() {
            match alpha::decode_frame(buf) {
                Ok((frame, consumed)) => {
                    let body = frame.body.to_vec();
                    let kind = frame.kind;
                    buf.drain(..consumed);
                    return Ok(OwnedFrame { kind, body });
                }
                Err(proteus_wire::WireError::Short { .. }) => {}
                Err(e) => return Err(e.into()),
            }
        }
        let mut tmp = [0u8; 4096];
        let n = read.read(&mut tmp).await?;
        if n == 0 {
            return Err(AlphaError::Closed);
        }
        buf.extend_from_slice(&tmp[..n]);
    }
}

/// An owned-bytes copy of a decoded α-profile frame.
struct OwnedFrame {
    kind: u8,
    body: Vec<u8>,
}

fn hmac_sha256(key: &[u8; 32], data: &[u8]) -> [u8; 32] {
    use hmac::{Hmac, Mac};
    use sha2::Sha256;
    let mut mac = Hmac::<Sha256>::new_from_slice(key).expect("HMAC accepts any key length");
    mac.update(data);
    let out = mac.finalize().into_bytes();
    let mut tag = [0u8; 32];
    tag.copy_from_slice(&out);
    tag
}

fn ct_eq(a: &[u8; 32], b: &[u8; 32]) -> bool {
    use subtle::ConstantTimeEq;
    bool::from(a.ct_eq(b))
}

// Glue: pull in hmac/sha2 here even though they're only used by helpers.
use hmac as _;
use sha2 as _;
use subtle as _;
