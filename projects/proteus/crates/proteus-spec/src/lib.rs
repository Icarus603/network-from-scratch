//! Proteus protocol constants.
//!
//! This crate is **pure data**: it mirrors `assets/spec/proteus-v1.0.md`
//! §4 (wire format), §6 (cryptographic suite), and §26 (codepoint registry).
//! Any change to a constant here MUST be paired with a spec amendment.
//!
//! No allocation, no `unsafe`, `#![no_std]`-compatible.

#![no_std]
#![deny(missing_docs)]

// =============================================================================
// §1 — version & profile codepoints
// =============================================================================

/// Proteus protocol version 1.0 — value of [`ProteusAuthExtension::version`].
///
/// v0.1 used `0x01`; v1.0 uses `0x10`. v1.1+ will increment from here.
pub const PROTEUS_VERSION_V10: u8 = 0x10;

/// Transport profile γ (MASQUE / H3 / QUIC over UDP/443). spec §3.
pub const PROFILE_HINT_GAMMA: u8 = 0x03;

/// Transport profile β (raw QUIC + DATAGRAM, ALPN `proteus-β-v1`). spec §3.
pub const PROFILE_HINT_BETA: u8 = 0x02;

/// Transport profile α (TLS 1.3 over TCP/443 last-resort). spec §3.
pub const PROFILE_HINT_ALPHA: u8 = 0x01;

// =============================================================================
// §2 — auth-extension byte layout (spec §4.1)
// =============================================================================

/// TLS ExtensionType for the Proteus auth extension. spec §4.1.
pub const AUTH_EXT_TYPE: u16 = 0xfe0d;

/// Length of the `client_nonce` field. spec §4.1.1.
pub const CLIENT_NONCE_LEN: usize = 16;

/// Length of the X25519 ephemeral public-key share. RFC 7748 §6 / spec §4.1.1.
pub const X25519_PUB_LEN: usize = 32;

/// Length of the ML-KEM-768 ciphertext. FIPS-203 §7.2 / spec §4.1.1.
pub const ML_KEM_768_CT_LEN: usize = 1088;

/// Length of the pseudonymous `client_id`. spec §4.1.1 / §5.7.
pub const CLIENT_ID_LEN: usize = 24;

/// Length of the wall-clock timestamp (big-endian unix seconds). spec §4.1.1.
pub const TIMESTAMP_LEN: usize = 8;

/// Length of the cover_profile_id. spec §4.1.1.
pub const COVER_PROFILE_ID_LEN: usize = 2;

/// Length of the shape_seed (high + low halves). spec §4.1.1.
pub const SHAPE_SEED_LEN: usize = 4;

/// Length of the anti-DDoS puzzle solution. spec §4.1.1 / §8.3.
pub const ANTI_DOS_SOLUTION_LEN: usize = 7;

/// Length of an Ed25519 signature. RFC 8032 / spec §4.1.1.
pub const ED25519_SIG_LEN: usize = 64;

/// Length of the truncated ML-DSA-65 prefix. spec §4.1.1 / §5.3.
pub const ML_DSA_65_SIG_TRUNCATED_LEN: usize = 96;

/// Length of the HMAC-SHA-256 auth tag. spec §4.1.1.
pub const HMAC_TAG_LEN: usize = 32;

/// Total `ProteusAuthExtension` payload length for v1.0.
///
/// Sum: `1 + 1 + 2 + 16 + 32 + 1088 + 24 + 8 + 2 + 2 + 2 + 1 + 7 + 64 + 96 + 32 = 1378`.
pub const AUTH_EXT_LEN_V10: usize = 1 + 1 + 2
    + CLIENT_NONCE_LEN
    + X25519_PUB_LEN
    + ML_KEM_768_CT_LEN
    + CLIENT_ID_LEN
    + TIMESTAMP_LEN
    + COVER_PROFILE_ID_LEN
    + SHAPE_SEED_LEN
    + 1 // anti_dos_difficulty
    + ANTI_DOS_SOLUTION_LEN
    + ED25519_SIG_LEN
    + ML_DSA_65_SIG_TRUNCATED_LEN
    + HMAC_TAG_LEN;

// =============================================================================
// §3 — cell padding sizes (spec §4.6)
// =============================================================================

/// Cell sizes for profile γ (matches measured Cloudflare/Apple H3 MASQUE distribution).
pub const CELL_SIZES_GAMMA: &[u16] = &[1252, 1280, 1452];

/// Cell sizes for profile β (matches WireGuard / generic QUIC default).
pub const CELL_SIZES_BETA: &[u16] = &[1200, 1252, 1280];

/// Cell sizes for profile α (matches Chrome TLS 1.3 record min/max).
pub const CELL_SIZES_ALPHA: &[u16] = &[1372, 1448];

// =============================================================================
// §4 — cover profile IDs (spec §22.4)
// =============================================================================

/// Streaming cover shape (Netflix/YouTube-like asymmetric burst).
pub const COVER_PROFILE_STREAMING: u16 = 0;

/// API-poll cover shape (1–10 Hz small request/response).
pub const COVER_PROFILE_API_POLL: u16 = 1;

/// Video-call cover shape (bidirectional medium-packet low-jitter).
pub const COVER_PROFILE_VIDEO_CALL: u16 = 2;

/// File-download cover shape (server→client sustained large packets).
pub const COVER_PROFILE_FILE_DL: u16 = 3;

/// Web-browse cover shape (request-bursty client→server light, server→client heavy).
pub const COVER_PROFILE_WEB_BROWSE: u16 = 4;

// =============================================================================
// §5 — inner packet types (spec §4.5.1)
// =============================================================================

/// Inner-packet type IDs. spec §4.5.1.
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[allow(missing_docs)] // documented in spec
pub enum InnerPacketType {
    Data = 0x01,
    Ack = 0x02,
    NewStream = 0x03,
    ResetStream = 0x04,
    Ping = 0x05,
    KeyUpdate = 0x06,
    Padding = 0x07,
    Close = 0x08,
    PathChallenge = 0x09,
    PathResponse = 0x0a,
    PathAbandon = 0x0b,
    ShapeProbe = 0x0c,
    ShapeAck = 0x0d,
    FlowBudget = 0x0e,
    Telemetry = 0x0f,
}

impl InnerPacketType {
    /// Decode from byte, returning `None` for reserved (0x10–0xef) and ignored
    /// extension (0xf0–0xff) ranges. Callers MUST handle unknown types per
    /// spec §4.5.1 "silently ignore" rule.
    #[must_use]
    pub const fn from_u8(b: u8) -> Option<Self> {
        match b {
            0x01 => Some(Self::Data),
            0x02 => Some(Self::Ack),
            0x03 => Some(Self::NewStream),
            0x04 => Some(Self::ResetStream),
            0x05 => Some(Self::Ping),
            0x06 => Some(Self::KeyUpdate),
            0x07 => Some(Self::Padding),
            0x08 => Some(Self::Close),
            0x09 => Some(Self::PathChallenge),
            0x0a => Some(Self::PathResponse),
            0x0b => Some(Self::PathAbandon),
            0x0c => Some(Self::ShapeProbe),
            0x0d => Some(Self::ShapeAck),
            0x0e => Some(Self::FlowBudget),
            0x0f => Some(Self::Telemetry),
            _ => None,
        }
    }

    /// Whether the type ID lies in the private-extension range `0xf0..=0xff`
    /// (spec §12.2 — implementations MUST silently ignore).
    #[must_use]
    pub const fn is_private_extension(b: u8) -> bool {
        b >= 0xf0
    }
}

// =============================================================================
// §6 — inner-packet flag bits (spec §4.5)
// =============================================================================

/// `flags` bit definitions for [`InnerPacketType`]. spec §4.5.
pub mod inner_flags {
    /// Bit 7 — set after CONNECTED state; payload is AEAD-encrypted.
    pub const ENCRYPTED: u8 = 0b1000_0000;
    /// Bit 6 — payload is followed by a PADDING trailer.
    pub const PADDING_TRAILER_PRESENT: u8 = 0b0100_0000;
    /// Bit 5 — `path_id` field is present (multipath).
    pub const PATH_ID_PRESENT: u8 = 0b0010_0000;
    /// Bit 4 — stream FIN.
    pub const FIN: u8 = 0b0001_0000;
    /// Bit 3 — shape-shift transition tick.
    pub const SHAPE_TICK: u8 = 0b0000_1000;
}

// =============================================================================
// §7 — AEAD nonce, epoch / seqnum layout (spec §4.5, §4.5.2)
// =============================================================================

/// AEAD nonce length for both ChaCha20-Poly1305 and AES-256-GCM. spec §4.5.2.
pub const AEAD_NONCE_LEN: usize = 12;

/// AEAD tag length. spec §6.
pub const AEAD_TAG_LEN: usize = 16;

/// Width of the AEAD key, normalized for both supported ciphers. spec §6.
pub const AEAD_KEY_LEN: usize = 32;

/// Width of the epoch counter (in bits). spec §4.5.
pub const EPOCH_BITS: u32 = 24;

/// Width of the per-epoch seqnum (in bits). spec §4.5.
pub const SEQNUM_BITS: u32 = 40;

/// Maximum representable seqnum within one epoch (= `2^40 - 1`).
pub const SEQNUM_MAX: u64 = (1u64 << SEQNUM_BITS) - 1;

// =============================================================================
// §8 — anti-replay / timestamp guard (spec §8)
// =============================================================================

/// Maximum allowed clock skew between client `timestamp` and server `now`,
/// in seconds. spec §8.2.
pub const TIMESTAMP_WINDOW_SECS: u64 = 90;

/// Sliding-Bloom window for replay protection. spec §8.1.
pub const REPLAY_WINDOW_SECS: u64 = 3600;

// =============================================================================
// §9 — CLOSE error codes (spec §26.1)
// =============================================================================

/// CLOSE error codes carried in `0x08 CLOSE` inner-packet payloads. spec §26.1.
pub mod close_error {
    #![allow(missing_docs)] // self-evident
    pub const NO_ERROR: u8 = 0x00;
    pub const PROTOCOL_VIOLATION: u8 = 0x01;
    pub const INTERNAL_ERROR: u8 = 0x02;
    pub const RESERVED_FIELD_VIOLATION: u8 = 0x10;
    pub const AUTH_REPLAY: u8 = 0x20;
    pub const AUTH_EXPIRED: u8 = 0x21;
    pub const AUTH_FAILED: u8 = 0x22;
    pub const FLOW_CONTROL_LIMIT: u8 = 0x30;
    pub const KEYUPDATE_FAILED: u8 = 0x40;
    pub const MULTIPATH_PATH_INVALID: u8 = 0x50;
    pub const SHAPE_MISMATCH: u8 = 0x60;
    pub const DOS_BUDGET_EXCEEDED: u8 = 0x70;
    pub const UNKNOWN: u8 = 0xff;
}

// =============================================================================
// §10 — HKDF labels (spec §5.2)
// =============================================================================

/// HKDF-Expand labels used by the Proteus key schedule. spec §5.2.
pub mod hkdf_label {
    #![allow(missing_docs)]
    pub const C_AP_TRAFFIC: &[u8] = b"c ap traffic";
    pub const S_AP_TRAFFIC: &[u8] = b"s ap traffic";
    pub const EXPORTER: &[u8] = b"exp master";
    pub const RESUMPTION: &[u8] = b"res master";
    pub const KEY: &[u8] = b"key";
    pub const IV: &[u8] = b"iv";
    pub const HP: &[u8] = b"hp";
    pub const RATCHET: &[u8] = b"proteus ratchet v1";
    pub const PATH: &[u8] = b"p path";
    pub const CID_KEY: &[u8] = b"proteus-cid-key-v1";
    pub const TELEMETRY: &[u8] = b"proteus telemetry";
    pub const DERIVED: &[u8] = b"derived";
    pub const C_HS_TRAFFIC: &[u8] = b"c hs traffic";
    pub const S_HS_TRAFFIC: &[u8] = b"s hs traffic";
}

// =============================================================================
// §11 — compile-time sanity tests
// =============================================================================

// Hard assertion: the documented "1378 bytes" in spec §4.1.1 must equal the
// programmatic sum.
const _: () = assert!(AUTH_EXT_LEN_V10 == 1378, "spec §4.1.1 byte sum drift");
const _: () = assert!(SEQNUM_MAX == 0x0000_00ff_ffff_ffff);
const _: () = assert!(
    EPOCH_BITS + SEQNUM_BITS == 64,
    "epoch||seqnum must fit in 64 bits"
);

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn auth_ext_byte_sum_matches_spec() {
        // Match spec §4.1.1 by hand-summed total.
        let by_hand: usize = 1   // version
            + 1                   // profile_hint
            + 2                   // reserved
            + 16                  // client_nonce
            + 32                  // client_x25519_pub
            + 1088                // client_mlkem768_ct
            + 24                  // client_id
            + 8                   // timestamp
            + 2                   // cover_profile_id
            + 4                   // shape_seed_hi||shape_seed_lo
            + 1                   // anti_dos_difficulty
            + 7                   // anti_dos_solution
            + 64                  // client_kex_sig (Ed25519)
            + 96                  // client_kex_sig_pq (truncated ML-DSA-65)
            + 32; // auth_tag (HMAC-SHA-256)
        assert_eq!(by_hand, 1378);
        assert_eq!(by_hand, AUTH_EXT_LEN_V10);
    }

    #[test]
    fn inner_packet_type_round_trip() {
        for v in 0x01u8..=0x0f {
            let t = InnerPacketType::from_u8(v);
            assert!(t.is_some(), "type {v:#x} should decode");
            assert_eq!(t.unwrap() as u8, v);
        }
    }

    #[test]
    fn inner_packet_type_reserved_range_rejected() {
        for v in 0x10u8..=0xef {
            assert!(
                InnerPacketType::from_u8(v).is_none(),
                "type {v:#x} reserved"
            );
            assert!(!InnerPacketType::is_private_extension(v));
        }
    }

    #[test]
    fn inner_packet_type_private_extension_range() {
        for v in 0xf0u8..=0xff {
            // Private extensions decode to None but are marked as extensions.
            assert!(InnerPacketType::from_u8(v).is_none());
            assert!(InnerPacketType::is_private_extension(v));
        }
    }

    #[test]
    fn cell_sizes_are_sorted_ascending() {
        for set in [CELL_SIZES_GAMMA, CELL_SIZES_BETA, CELL_SIZES_ALPHA] {
            for w in set.windows(2) {
                assert!(w[0] < w[1], "cell sizes must be strictly ascending");
            }
        }
    }
}
