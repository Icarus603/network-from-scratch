//! Byte-exact encoders/decoders for the Proteus wire format.
//!
//! All data structures here correspond one-to-one with `assets/spec/proteus-v1.0.md` §4.
//! Decoders are **fail-closed**: any layout anomaly returns
//! [`WireError`] rather than mutating state. Callers (the handshake state
//! machine) translate parse errors into "forward to cover" per spec §7.5.

#![deny(missing_docs)]

use core::convert::TryFrom;

use proteus_spec::{
    ANTI_DOS_SOLUTION_LEN, AUTH_EXT_LEN_V10, AUTH_EXT_TYPE, CLIENT_ID_LEN, CLIENT_NONCE_LEN,
    COVER_PROFILE_ID_LEN, ED25519_SIG_LEN, EPOCH_BITS, HMAC_TAG_LEN, ML_DSA_65_SIG_TRUNCATED_LEN,
    ML_KEM_768_CT_LEN, PROFILE_HINT_ALPHA, PROFILE_HINT_BETA, PROFILE_HINT_GAMMA,
    PROTEUS_VERSION_V10, SEQNUM_BITS, SEQNUM_MAX, SHAPE_SEED_LEN, TIMESTAMP_LEN, X25519_PUB_LEN,
};
use thiserror::Error;
use zeroize::Zeroize as _;

pub mod alpha;
pub mod varint;

/// Errors raised by the wire layer.
///
/// All variants are recoverable from the protocol's point of view: per spec
/// §7.5, any parse failure on the server side triggers a forward to the cover
/// URL; on the client side, any parse failure triggers a profile-ladder
/// escalation (γ→β→α).
#[derive(Debug, Error, PartialEq, Eq)]
pub enum WireError {
    /// Buffer ended before the required bytes were consumed.
    #[error("short read: need {needed} bytes, have {have}")]
    Short {
        /// Bytes required.
        needed: usize,
        /// Bytes available.
        have: usize,
    },

    /// `version` byte did not match a supported Proteus version.
    #[error("unsupported version: 0x{0:02x}")]
    BadVersion(u8),

    /// `profile_hint` byte was not one of {α, β, γ}.
    #[error("unknown profile_hint: 0x{0:02x}")]
    BadProfileHint(u8),

    /// The `reserved` 16-bit field was non-zero (strict-then-loose per spec §4.1.4).
    #[error("reserved field non-zero: 0x{0:04x}")]
    ReservedNonZero(u16),

    /// AuthExtension total length did not match `AUTH_EXT_LEN_V10`.
    #[error("auth_ext length mismatch: expected {expected}, got {got}")]
    AuthExtLengthMismatch {
        /// Expected length (= `AUTH_EXT_LEN_V10`).
        expected: usize,
        /// Length observed in the buffer.
        got: usize,
    },

    /// Inner-packet seqnum exceeded the 40-bit allocation.
    #[error("seqnum overflow: {0}")]
    SeqnumOverflow(u64),

    /// Inner-packet epoch exceeded the 24-bit allocation.
    #[error("epoch overflow: {0}")]
    EpochOverflow(u32),

    /// Inner-packet header marked `PATH_ID_PRESENT` but no path_id followed.
    #[error("path_id flag set but field missing")]
    MissingPathId,

    /// QUIC varint encoding rejected (e.g., out-of-range or undecodable).
    #[error("varint decode error")]
    Varint,
}

// =============================================================================
// §1 — ProteusAuthExtension (spec §4.1)
// =============================================================================

/// Profile selector carried inside the auth extension's `profile_hint` byte.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProfileHint {
    /// Profile α — TLS 1.3 over TCP/443 last-resort.
    Alpha,
    /// Profile β — raw QUIC + DATAGRAM, ALPN `proteus-β-v1`.
    Beta,
    /// Profile γ — MASQUE / H3 over QUIC (primary).
    Gamma,
}

impl ProfileHint {
    /// Decode from a `profile_hint` byte. spec §4.1.1.
    pub const fn from_byte(b: u8) -> Result<Self, WireError> {
        match b {
            PROFILE_HINT_GAMMA => Ok(Self::Gamma),
            PROFILE_HINT_BETA => Ok(Self::Beta),
            PROFILE_HINT_ALPHA => Ok(Self::Alpha),
            other => Err(WireError::BadProfileHint(other)),
        }
    }

    /// Encode to a `profile_hint` byte.
    #[must_use]
    pub const fn to_byte(self) -> u8 {
        match self {
            Self::Alpha => PROFILE_HINT_ALPHA,
            Self::Beta => PROFILE_HINT_BETA,
            Self::Gamma => PROFILE_HINT_GAMMA,
        }
    }
}

/// Decoded form of the `ProteusAuthExtension` (spec §4.1.1).
///
/// Fixed-size arrays mirror the wire layout exactly; no allocation is required.
/// Sensitive fields are zeroized on drop via the explicit
/// [`AuthExtension::zeroize`] method (callers MUST invoke after consuming
/// the secrets).
#[derive(Debug, Clone)]
pub struct AuthExtension {
    /// Protocol version (`0x10` for v1.0).
    pub version: u8,
    /// Requested transport profile.
    pub profile_hint: ProfileHint,
    /// Fresh CSPRNG nonce, doubles as KDF salt.
    pub client_nonce: [u8; CLIENT_NONCE_LEN],
    /// Ephemeral X25519 share (RFC 7748 little-endian Montgomery encoding).
    pub client_x25519_pub: [u8; X25519_PUB_LEN],
    /// ML-KEM-768 ciphertext encapsulating to the server's PQ public key.
    pub client_mlkem768_ct: [u8; ML_KEM_768_CT_LEN],
    /// AEAD-encrypted pseudonymous user identifier. spec §5.7.
    pub client_id: [u8; CLIENT_ID_LEN],
    /// Big-endian unix-seconds timestamp.
    pub timestamp_unix_seconds: u64,
    /// Cover profile selector (`COVER_PROFILE_*` constants).
    pub cover_profile_id: u16,
    /// 32-bit shape-shift PRG seed.
    pub shape_seed: u32,
    /// Anti-DDoS difficulty echo from the server's HTTPS RR.
    pub anti_dos_difficulty: u8,
    /// Anti-DDoS partial-preimage solution.
    pub anti_dos_solution: [u8; ANTI_DOS_SOLUTION_LEN],
    /// Ed25519 signature with the client's long-term identity key.
    pub client_kex_sig: [u8; ED25519_SIG_LEN],
    /// Truncated ML-DSA-65 signature prefix. spec §5.3.
    pub client_kex_sig_pq: [u8; ML_DSA_65_SIG_TRUNCATED_LEN],
    /// HMAC-SHA-256 tag over all preceding fields.
    pub auth_tag: [u8; HMAC_TAG_LEN],
}

impl AuthExtension {
    /// Zeroize sensitive fields. Call after the handshake has consumed them.
    pub fn zeroize_secrets(&mut self) {
        self.client_nonce.zeroize();
        self.client_x25519_pub.zeroize();
        self.client_mlkem768_ct.zeroize();
        self.client_id.zeroize();
        self.auth_tag.zeroize();
    }

    /// Encode the extension payload (does **not** include the 4-byte
    /// `(extension_type, extension_length)` TLS header).
    ///
    /// Output length is always [`AUTH_EXT_LEN_V10`].
    pub fn encode_payload(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(AUTH_EXT_LEN_V10);
        out.push(self.version);
        out.push(self.profile_hint.to_byte());
        out.extend_from_slice(&[0u8, 0u8]); // reserved
        out.extend_from_slice(&self.client_nonce);
        out.extend_from_slice(&self.client_x25519_pub);
        out.extend_from_slice(&self.client_mlkem768_ct);
        out.extend_from_slice(&self.client_id);
        out.extend_from_slice(&self.timestamp_unix_seconds.to_be_bytes());
        out.extend_from_slice(&self.cover_profile_id.to_be_bytes());
        out.extend_from_slice(&self.shape_seed.to_be_bytes());
        out.push(self.anti_dos_difficulty);
        out.extend_from_slice(&self.anti_dos_solution);
        out.extend_from_slice(&self.client_kex_sig);
        out.extend_from_slice(&self.client_kex_sig_pq);
        out.extend_from_slice(&self.auth_tag);
        debug_assert_eq!(out.len(), AUTH_EXT_LEN_V10);
        out
    }

    /// Encode the extension including TLS header `(ext_type=0xfe0d, ext_len)`.
    pub fn encode_with_tls_header(&self) -> Vec<u8> {
        let payload = self.encode_payload();
        let mut out = Vec::with_capacity(4 + payload.len());
        out.extend_from_slice(&AUTH_EXT_TYPE.to_be_bytes());
        out.extend_from_slice(
            &u16::try_from(payload.len())
                .expect("len fits u16")
                .to_be_bytes(),
        );
        out.extend_from_slice(&payload);
        out
    }

    /// Decode the **payload** (without TLS header) from a byte slice.
    pub fn decode_payload(buf: &[u8]) -> Result<Self, WireError> {
        if buf.len() != AUTH_EXT_LEN_V10 {
            return Err(WireError::AuthExtLengthMismatch {
                expected: AUTH_EXT_LEN_V10,
                got: buf.len(),
            });
        }
        let mut cur = Cursor::new(buf);

        let version = cur.read_u8()?;
        if version != PROTEUS_VERSION_V10 {
            return Err(WireError::BadVersion(version));
        }
        let profile_hint = ProfileHint::from_byte(cur.read_u8()?)?;
        let reserved = cur.read_u16_be()?;
        if reserved != 0 {
            return Err(WireError::ReservedNonZero(reserved));
        }
        let client_nonce = cur.read_array::<CLIENT_NONCE_LEN>()?;
        let client_x25519_pub = cur.read_array::<X25519_PUB_LEN>()?;
        let client_mlkem768_ct = cur.read_array::<ML_KEM_768_CT_LEN>()?;
        let client_id = cur.read_array::<CLIENT_ID_LEN>()?;
        let timestamp_unix_seconds = cur.read_u64_be()?;
        let cover_profile_id = cur.read_u16_be()?;
        let shape_seed = cur.read_u32_be()?;
        let anti_dos_difficulty = cur.read_u8()?;
        let anti_dos_solution = cur.read_array::<ANTI_DOS_SOLUTION_LEN>()?;
        let client_kex_sig = cur.read_array::<ED25519_SIG_LEN>()?;
        let client_kex_sig_pq = cur.read_array::<ML_DSA_65_SIG_TRUNCATED_LEN>()?;
        let auth_tag = cur.read_array::<HMAC_TAG_LEN>()?;

        debug_assert_eq!(cur.pos, buf.len(), "decode consumed exactly the payload");

        Ok(Self {
            version,
            profile_hint,
            client_nonce,
            client_x25519_pub,
            client_mlkem768_ct,
            client_id,
            timestamp_unix_seconds,
            cover_profile_id,
            shape_seed,
            anti_dos_difficulty,
            anti_dos_solution,
            client_kex_sig,
            client_kex_sig_pq,
            auth_tag,
        })
    }

    /// Bytes covered by the HMAC `auth_tag` (= everything in the payload
    /// **except** `auth_tag` itself; spec §4.1.3).
    pub fn auth_mac_input(&self) -> Vec<u8> {
        let full = self.encode_payload();
        let cut = full.len() - HMAC_TAG_LEN;
        full[..cut].to_vec()
    }
}

const _: () = {
    // Static guard: ensure spec-derived lengths sum to the documented total.
    let actual = 1
        + 1
        + 2
        + CLIENT_NONCE_LEN
        + X25519_PUB_LEN
        + ML_KEM_768_CT_LEN
        + CLIENT_ID_LEN
        + TIMESTAMP_LEN
        + COVER_PROFILE_ID_LEN
        + SHAPE_SEED_LEN
        + 1
        + ANTI_DOS_SOLUTION_LEN
        + ED25519_SIG_LEN
        + ML_DSA_65_SIG_TRUNCATED_LEN
        + HMAC_TAG_LEN;
    assert!(actual == AUTH_EXT_LEN_V10);
};

// =============================================================================
// §2 — ProteusInnerPacket header (spec §4.5)
// =============================================================================

/// Decoded form of the 8-byte inner-packet header (spec §4.5).
///
/// `epoch` occupies bits [63..40] of the on-wire 64-bit `(hi||lo)` field,
/// `seqnum` occupies bits [39..0]. Both must respect [`EPOCH_BITS`] /
/// [`SEQNUM_BITS`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct InnerHeader {
    /// Packet type (`type` field).
    pub r#type: u8,
    /// Flag bits (see `proteus_spec::inner_flags::*`).
    pub flags: u8,
    /// Epoch counter (24-bit), bumped on every KEYUPDATE.
    pub epoch: u32,
    /// Per-epoch monotonic sequence number (40-bit).
    pub seqnum: u64,
}

impl InnerHeader {
    /// Construct a header, validating the epoch/seqnum widths.
    pub fn new(r#type: u8, flags: u8, epoch: u32, seqnum: u64) -> Result<Self, WireError> {
        if epoch >= (1u32 << EPOCH_BITS) {
            return Err(WireError::EpochOverflow(epoch));
        }
        if seqnum > SEQNUM_MAX {
            return Err(WireError::SeqnumOverflow(seqnum));
        }
        Ok(Self {
            r#type,
            flags,
            epoch,
            seqnum,
        })
    }

    /// Encode the header into the canonical 10-byte wire layout
    /// `[type(1) | flags(1) | epoch_seqnum(8, big-endian)]` per spec §4.5.
    ///
    /// `epoch_seqnum` packs `(epoch:24 || seqnum:40)` into a single 64-bit
    /// big-endian word. Multi-path implementations append a 1-byte `path_id`
    /// when `flags & PATH_ID_PRESENT != 0`; that byte is **not** part of this
    /// fixed header and is appended by the caller after the AAD boundary.
    #[must_use]
    pub fn encode_wire(&self) -> [u8; 10] {
        let combined: u64 = (u64::from(self.epoch) << SEQNUM_BITS) | self.seqnum;
        let mut buf = [0u8; 10];
        buf[0] = self.r#type;
        buf[1] = self.flags;
        buf[2..=9].copy_from_slice(&combined.to_be_bytes());
        buf
    }

    /// Decode the 10-byte canonical wire layout.
    pub fn decode_wire(buf: &[u8]) -> Result<Self, WireError> {
        if buf.len() < 10 {
            return Err(WireError::Short {
                needed: 10,
                have: buf.len(),
            });
        }
        let r#type = buf[0];
        let flags = buf[1];
        let combined = u64::from_be_bytes(<[u8; 8]>::try_from(&buf[2..=9]).expect("8 bytes"));
        let epoch = u32::try_from(combined >> SEQNUM_BITS).expect("24 bits");
        let seqnum = combined & SEQNUM_MAX;
        Self::new(r#type, flags, epoch, seqnum)
    }
}

// =============================================================================
// §3 — small reader helper
// =============================================================================

struct Cursor<'a> {
    buf: &'a [u8],
    pos: usize,
}

impl<'a> Cursor<'a> {
    fn new(buf: &'a [u8]) -> Self {
        Self { buf, pos: 0 }
    }

    fn read_u8(&mut self) -> Result<u8, WireError> {
        let v = *self.buf.get(self.pos).ok_or(WireError::Short {
            needed: self.pos + 1,
            have: self.buf.len(),
        })?;
        self.pos += 1;
        Ok(v)
    }

    fn read_u16_be(&mut self) -> Result<u16, WireError> {
        let end = self.pos + 2;
        let bytes = self.buf.get(self.pos..end).ok_or(WireError::Short {
            needed: end,
            have: self.buf.len(),
        })?;
        self.pos = end;
        Ok(u16::from_be_bytes([bytes[0], bytes[1]]))
    }

    fn read_u32_be(&mut self) -> Result<u32, WireError> {
        let end = self.pos + 4;
        let bytes = self.buf.get(self.pos..end).ok_or(WireError::Short {
            needed: end,
            have: self.buf.len(),
        })?;
        self.pos = end;
        Ok(u32::from_be_bytes(<[u8; 4]>::try_from(bytes).unwrap()))
    }

    fn read_u64_be(&mut self) -> Result<u64, WireError> {
        let end = self.pos + 8;
        let bytes = self.buf.get(self.pos..end).ok_or(WireError::Short {
            needed: end,
            have: self.buf.len(),
        })?;
        self.pos = end;
        Ok(u64::from_be_bytes(<[u8; 8]>::try_from(bytes).unwrap()))
    }

    fn read_array<const N: usize>(&mut self) -> Result<[u8; N], WireError> {
        let end = self.pos + N;
        let bytes = self.buf.get(self.pos..end).ok_or(WireError::Short {
            needed: end,
            have: self.buf.len(),
        })?;
        self.pos = end;
        let mut out = [0u8; N];
        out.copy_from_slice(bytes);
        Ok(out)
    }
}

// =============================================================================
// §4 — tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    fn fixture_auth() -> AuthExtension {
        AuthExtension {
            version: PROTEUS_VERSION_V10,
            profile_hint: ProfileHint::Gamma,
            client_nonce: [0x11; CLIENT_NONCE_LEN],
            client_x25519_pub: [0x22; X25519_PUB_LEN],
            client_mlkem768_ct: [0x33; ML_KEM_768_CT_LEN],
            client_id: [0x44; CLIENT_ID_LEN],
            timestamp_unix_seconds: 0x0123_4567_89ab_cdef,
            cover_profile_id: proteus_spec::COVER_PROFILE_STREAMING,
            shape_seed: 0xdead_beef,
            anti_dos_difficulty: 0,
            anti_dos_solution: [0x55; ANTI_DOS_SOLUTION_LEN],
            client_kex_sig: [0x66; ED25519_SIG_LEN],
            client_kex_sig_pq: [0x77; ML_DSA_65_SIG_TRUNCATED_LEN],
            auth_tag: [0x88; HMAC_TAG_LEN],
        }
    }

    #[test]
    fn auth_ext_round_trip() {
        let original = fixture_auth();
        let encoded = original.encode_payload();
        assert_eq!(encoded.len(), AUTH_EXT_LEN_V10);
        let decoded = AuthExtension::decode_payload(&encoded).expect("decode ok");
        assert_eq!(decoded.version, original.version);
        assert_eq!(decoded.profile_hint, original.profile_hint);
        assert_eq!(decoded.client_nonce, original.client_nonce);
        assert_eq!(decoded.client_x25519_pub, original.client_x25519_pub);
        assert_eq!(decoded.client_mlkem768_ct, original.client_mlkem768_ct);
        assert_eq!(decoded.client_id, original.client_id);
        assert_eq!(
            decoded.timestamp_unix_seconds,
            original.timestamp_unix_seconds
        );
        assert_eq!(decoded.cover_profile_id, original.cover_profile_id);
        assert_eq!(decoded.shape_seed, original.shape_seed);
        assert_eq!(decoded.anti_dos_difficulty, original.anti_dos_difficulty);
        assert_eq!(decoded.anti_dos_solution, original.anti_dos_solution);
        assert_eq!(decoded.client_kex_sig, original.client_kex_sig);
        assert_eq!(decoded.client_kex_sig_pq, original.client_kex_sig_pq);
        assert_eq!(decoded.auth_tag, original.auth_tag);
    }

    #[test]
    fn auth_ext_with_tls_header_is_four_bytes_longer() {
        let ext = fixture_auth();
        let wire = ext.encode_with_tls_header();
        assert_eq!(wire.len(), AUTH_EXT_LEN_V10 + 4);
        // TLS extension header: type(2) || length(2)
        assert_eq!(&wire[0..2], &AUTH_EXT_TYPE.to_be_bytes());
        assert_eq!(
            u16::from_be_bytes([wire[2], wire[3]]),
            u16::try_from(AUTH_EXT_LEN_V10).unwrap()
        );
    }

    #[test]
    fn auth_ext_rejects_bad_version() {
        let mut wire = fixture_auth().encode_payload();
        wire[0] = 0x99; // bogus version
        match AuthExtension::decode_payload(&wire) {
            Err(WireError::BadVersion(0x99)) => {}
            other => panic!("expected BadVersion, got {other:?}"),
        }
    }

    #[test]
    fn auth_ext_rejects_bad_profile() {
        let mut wire = fixture_auth().encode_payload();
        wire[1] = 0x42; // not α/β/γ
        match AuthExtension::decode_payload(&wire) {
            Err(WireError::BadProfileHint(0x42)) => {}
            other => panic!("expected BadProfileHint, got {other:?}"),
        }
    }

    #[test]
    fn auth_ext_rejects_nonzero_reserved() {
        let mut wire = fixture_auth().encode_payload();
        wire[2] = 0x00;
        wire[3] = 0x01;
        match AuthExtension::decode_payload(&wire) {
            Err(WireError::ReservedNonZero(1)) => {}
            other => panic!("expected ReservedNonZero, got {other:?}"),
        }
    }

    #[test]
    fn auth_ext_rejects_wrong_length() {
        let mut wire = fixture_auth().encode_payload();
        wire.pop(); // chop a byte off
        match AuthExtension::decode_payload(&wire) {
            Err(WireError::AuthExtLengthMismatch {
                expected: AUTH_EXT_LEN_V10,
                got,
            }) => {
                assert_eq!(got, AUTH_EXT_LEN_V10 - 1);
            }
            other => panic!("expected length mismatch, got {other:?}"),
        }
    }

    #[test]
    fn auth_mac_input_excludes_tag() {
        let ext = fixture_auth();
        let mac_input = ext.auth_mac_input();
        assert_eq!(mac_input.len(), AUTH_EXT_LEN_V10 - HMAC_TAG_LEN);
        // The MAC input must NOT contain the tag bytes.
        assert!(!mac_input.windows(HMAC_TAG_LEN).any(|w| w == ext.auth_tag));
    }

    #[test]
    fn inner_header_round_trip() {
        let h = InnerHeader::new(0x01, 0b1000_0000, 0x12_3456, 0x00_ffee_ddcc).unwrap();
        let wire = h.encode_wire();
        let h2 = InnerHeader::decode_wire(&wire).unwrap();
        assert_eq!(h, h2);
    }

    #[test]
    fn inner_header_rejects_epoch_overflow() {
        let r = InnerHeader::new(0x01, 0, 1u32 << EPOCH_BITS, 0);
        assert!(matches!(r, Err(WireError::EpochOverflow(_))));
    }

    #[test]
    fn inner_header_rejects_seqnum_overflow() {
        let r = InnerHeader::new(0x01, 0, 0, SEQNUM_MAX + 1);
        assert!(matches!(r, Err(WireError::SeqnumOverflow(_))));
    }

    #[test]
    fn inner_header_accepts_seqnum_max() {
        let h = InnerHeader::new(0x01, 0, 0, SEQNUM_MAX).unwrap();
        let wire = h.encode_wire();
        let h2 = InnerHeader::decode_wire(&wire).unwrap();
        assert_eq!(h, h2);
        assert_eq!(h2.seqnum, SEQNUM_MAX);
    }
}
