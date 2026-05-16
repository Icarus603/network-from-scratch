//! Profile-α framing (spec §4.2).
//!
//! Profile-α runs over a real TLS 1.3 connection by default. For the M1
//! reference impl we run a **simplified handshake frame layer directly
//! over TCP** so we can demonstrate end-to-end key derivation + AEAD echo
//! without pulling in a full rustls fork. The framing is compatible with
//! the spec's `ProteusAlphaRecord` (a typed, length-prefixed envelope)
//! and the byte-exact TLS 1.3 binding will replace the raw-TCP carrier
//! in M2.
//!
//! ## Handshake frames (this module)
//!
//! ```text
//! ProteusAlphaHandshake
//!   uint8   frame_type;        // 0x01=ClientHello, 0x02=ServerHello,
//!                              // 0x03=ServerFinished, 0x04=ClientFinished
//!   varint  body_len;
//!   opaque  body[body_len];
//! ```
//!
//! After the handshake completes, all subsequent frames are
//! [`AlphaRecord`]s carrying AEAD-encrypted [`ProteusInnerPacket`] bytes
//! (spec §4.5). Records are also typed + length-prefixed:
//!
//! ```text
//! AlphaRecord
//!   uint8   capsule_type;      // 0x10 = DATA_RECORD
//!   varint  capsule_length;
//!   opaque  capsule_value[];    // AEAD ciphertext (= inner_packet + 16-byte tag)
//! ```

use crate::{varint, WireError};

/// Frame type for `ClientHello`-equivalent (handshake start).
pub const FRAME_CLIENT_HELLO: u8 = 0x01;

/// Frame type for `ServerHello`-equivalent.
pub const FRAME_SERVER_HELLO: u8 = 0x02;

/// Frame type for `ServerFinished`-equivalent.
pub const FRAME_SERVER_FINISHED: u8 = 0x03;

/// Frame type for `ClientFinished`-equivalent.
pub const FRAME_CLIENT_FINISHED: u8 = 0x04;

/// Record type for post-handshake AEAD-protected DATA records.
pub const RECORD_DATA: u8 = 0x10;

/// Record type announcing a key ratchet (new epoch). Body is the AEAD
/// ciphertext of the 4-byte big-endian new-epoch number, encrypted under
/// the *old* direction key with the sentinel `seqnum = SEQNUM_MAX`.
pub const RECORD_RATCHET: u8 = 0x11;

/// Record type announcing a clean session close (spec §4.5.1 / §26.1).
/// Body is the AEAD ciphertext of `(error_code: u8 | reason_phrase_len: u8 | reason_phrase[])`
/// under the current direction key. After sending CLOSE the peer MUST
/// NOT send any further records on this direction.
pub const RECORD_CLOSE: u8 = 0x12;

/// Record type for AEAD-protected DATA records whose plaintext was
/// padded to a per-session length quantum BEFORE encryption (spec §4.6).
///
/// Padded-plaintext layout (inside the AEAD):
///
/// ```text
/// pt[0..4]            = real_payload_len: u32 big-endian
/// pt[4..4+real_len]   = real_payload
/// pt[4+real_len..]    = zero-padding to next multiple of session quantum
/// ```
///
/// On the wire the ciphertext length is always
/// `quantum × k + 16 (Poly1305 tag)` for some integer k ≥ 1, so a passive
/// observer measuring record lengths learns only "which quantum bucket",
/// not the exact payload size. Distinct from `RECORD_DATA` so legacy
/// peers refuse padded sessions cleanly (silently ignored as an unknown
/// record type per spec §12.2).
///
/// Receivers MUST treat truncated / sub-4-byte / over-length prefix
/// values as protocol errors (silent drop, like AEAD failures —
/// spec §11.16). They MUST NOT trust the on-wire length prefix to
/// exceed the AEAD-decrypted plaintext size; the parser validates this.
pub const RECORD_DATA_PADDED: u8 = 0x13;

/// Encode a handshake frame.
pub fn encode_handshake(frame_type: u8, body: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(1 + 8 + body.len());
    out.push(frame_type);
    varint::encode(body.len() as u64, &mut out);
    out.extend_from_slice(body);
    out
}

/// Encode a post-handshake AEAD-protected data record.
pub fn encode_record(record_type: u8, ciphertext: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(1 + 8 + ciphertext.len());
    out.push(record_type);
    varint::encode(ciphertext.len() as u64, &mut out);
    out.extend_from_slice(ciphertext);
    out
}

/// A decoded α-profile frame (handshake or post-handshake), with the
/// type byte and the body slice.
#[derive(Debug, Clone)]
pub struct Frame<'a> {
    /// Frame type byte (`FRAME_*` or `RECORD_*`).
    pub kind: u8,
    /// Body slice (does not include the type byte or the length prefix).
    pub body: &'a [u8],
}

/// Decode the next frame from `buf`. Returns `(frame, bytes_consumed)`.
pub fn decode_frame(buf: &[u8]) -> Result<(Frame<'_>, usize), WireError> {
    if buf.is_empty() {
        return Err(WireError::Short { needed: 1, have: 0 });
    }
    let kind = buf[0];
    let (len, varint_len) = varint::decode(&buf[1..])?;
    let header_len = 1 + varint_len;
    let body_len = usize::try_from(len).map_err(|_| WireError::Varint)?;
    let total = header_len + body_len;
    if buf.len() < total {
        return Err(WireError::Short {
            needed: total,
            have: buf.len(),
        });
    }
    Ok((
        Frame {
            kind,
            body: &buf[header_len..total],
        },
        total,
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn handshake_round_trip() {
        let body = b"\x10\x20\x30\x40";
        let wire = encode_handshake(FRAME_CLIENT_HELLO, body);
        let (frame, consumed) = decode_frame(&wire).unwrap();
        assert_eq!(consumed, wire.len());
        assert_eq!(frame.kind, FRAME_CLIENT_HELLO);
        assert_eq!(frame.body, body);
    }

    #[test]
    fn record_round_trip() {
        let ct = vec![0x42u8; 1280];
        let wire = encode_record(RECORD_DATA, &ct);
        let (frame, consumed) = decode_frame(&wire).unwrap();
        assert_eq!(consumed, wire.len());
        assert_eq!(frame.kind, RECORD_DATA);
        assert_eq!(frame.body, ct.as_slice());
    }

    #[test]
    fn short_buffer_errors() {
        // header says length=10 but we only have 3 bytes after the header.
        let mut wire = Vec::new();
        wire.push(FRAME_CLIENT_HELLO);
        varint::encode(10, &mut wire);
        wire.extend_from_slice(b"abc");
        let err = decode_frame(&wire).unwrap_err();
        assert!(matches!(err, WireError::Short { .. }));
    }

    #[test]
    fn two_frames_back_to_back() {
        let mut buf = encode_handshake(FRAME_CLIENT_HELLO, b"first");
        buf.extend_from_slice(&encode_handshake(FRAME_SERVER_HELLO, b"second"));
        let (f1, n1) = decode_frame(&buf).unwrap();
        assert_eq!(f1.body, b"first");
        let (f2, n2) = decode_frame(&buf[n1..]).unwrap();
        assert_eq!(f2.body, b"second");
        assert_eq!(n1 + n2, buf.len());
    }

    #[test]
    fn large_body_uses_4byte_varint() {
        let body = vec![0u8; 200_000];
        let wire = encode_handshake(FRAME_CLIENT_HELLO, &body);
        // 4-byte varint range = [16384, 2^30): 200_000 sits in that range.
        // Header = 1 byte kind + 4 byte varint.
        assert_eq!(wire.len(), 1 + 4 + 200_000);
        let (frame, consumed) = decode_frame(&wire).unwrap();
        assert_eq!(consumed, wire.len());
        assert_eq!(frame.body.len(), body.len());
    }
}
