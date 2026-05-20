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

/// Write the record header (type byte + varint length) for `body_len`
/// bytes of body to `out`, without copying the body. Used by the
/// no-alloc α data path: caller writes the header to `out`, then
/// appends ciphertext (or has already AEAD-sealed the body into a
/// separate buffer and writes both buffers with a single vectored
/// syscall).
///
/// Why this exists: the old `encode_record(type, &ct)` path
/// allocates a fresh `Vec` per record to concatenate header + body.
/// The α hot loop processes one record per cell; at quantum = 1280
/// on a 16 MiB record that's ~13 000 records per logical send, each
/// paying for a heap allocation purely to glue 1 type byte + a
/// 2-byte varint onto a freshly-AEAD-sealed buffer. With this
/// helper, the sender writes the 3-ish byte header into a reused
/// scratch buffer first, then has the cipher in-place into a second
/// reused buffer — two stable allocations for the lifetime of the
/// session.
///
/// The header is bounded to 9 bytes (1 type + up to 8 byte varint
/// for body_len, though α records cap body_len well under 2^14 so
/// the varint is usually 1-2 bytes).
pub fn write_record_header_to(out: &mut Vec<u8>, record_type: u8, body_len: usize) {
    out.push(record_type);
    varint::encode(body_len as u64, out);
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
    // Iter-175: `1 + varint_len + body_len` overflows `usize` if a
    // peer ships a varint that decodes to ~`usize::MAX`. On 64-bit
    // hosts the upper bound is 2^62 - 1 (varint max) + 9 bytes of
    // header, well under `usize::MAX = 2^64 - 1` — safe. On 32-bit
    // hosts the same value EXCEEDS `usize::MAX = 2^32 - 1`, so the
    // `header_len + body_len` would wrap and the subsequent
    // `buf.len() < total` check would compare against a tiny
    // wrapped `total`, accepting a frame whose declared body length
    // is far larger than the buffer. The slicing `&buf[header_len..
    // total]` would then panic on the out-of-bounds index.
    //
    // The `usize::try_from(len)` above already rejects values too
    // large to fit in `usize`; this `checked_add` closes the
    // remaining `header_len + body_len` add. Same fail-closed
    // class as the iter-156 sniffer peek_limit fix — refuse to
    // process attacker-controlled length fields that overflow our
    // arithmetic.
    let total = header_len.checked_add(body_len).ok_or(WireError::Varint)?;
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

    /// `write_record_header_to(&mut hdr, type, ct.len())` followed by
    /// `out.extend(hdr); out.extend(ct)` MUST produce the same wire
    /// bytes as `encode_record(type, &ct)`. If this diverges, the
    /// new no-alloc α data path becomes wire-incompatible with peers
    /// using the old encoder.
    #[test]
    fn write_record_header_to_matches_encode_record() {
        for body_len in [0usize, 1, 16, 127, 128, 1280, 16 * 1024, 65_531] {
            let ct = vec![0xA5u8; body_len];
            let legacy = encode_record(RECORD_DATA_PADDED, &ct);

            let mut split: Vec<u8> = Vec::new();
            write_record_header_to(&mut split, RECORD_DATA_PADDED, body_len);
            split.extend_from_slice(&ct);

            assert_eq!(split, legacy, "wire mismatch at body_len={body_len}");
        }
    }

    /// The header writer MUST be no-alloc when the caller pre-reserves
    /// enough capacity. We can't directly assert "no alloc" without
    /// allocator hooks, but we can assert capacity behavior: writing
    /// the header into a sufficiently-large pre-allocated buffer
    /// must not grow capacity.
    #[test]
    fn write_record_header_to_does_not_grow_pre_reserved_buffer() {
        let mut buf: Vec<u8> = Vec::with_capacity(16);
        let cap_before = buf.capacity();
        write_record_header_to(&mut buf, RECORD_DATA_PADDED, 1280);
        assert!(buf.len() <= 16);
        assert_eq!(buf.capacity(), cap_before, "header writer grew the buffer");
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

    /// Iter-175: a peer that declares the maximum possible varint
    /// body length (2^62 - 1) MUST surface as a `WireError::Varint`
    /// (or `Short` for the partial-data branch), not a panic.
    /// Pre-iter-175 the `let total = header_len + body_len;` add
    /// could overflow `usize` on 32-bit hosts (max 2^32 - 1),
    /// wrapping `total` to a small value that passes the
    /// `buf.len() < total` check, leading to an out-of-bounds
    /// slice + panic.
    ///
    /// The test crafts a frame with a maximum-encoded varint
    /// (8-byte form, value = 2^62 - 1) followed by zero body
    /// bytes. The decoder must error cleanly without panicking.
    #[test]
    fn iter175_decode_frame_handles_maximum_varint_body_length() {
        let mut wire = Vec::with_capacity(1 + 8 + 1);
        wire.push(FRAME_CLIENT_HELLO);
        // Encode varint = 2^62 - 1 (varint MAX). Per RFC 9000 §16
        // the 8-byte form is `0xc0 | (top byte of value)` then 7
        // more value bytes. The value 2^62 - 1 in 8 bytes
        // big-endian is `0x3f ff ff ff ff ff ff ff` — top bits
        // are `0011_1111`. Adding the 2-bit length tag (`11`) in
        // the high 2 bits gives `0xff` as the first byte, then
        // `ff ff ff ff ff ff ff` for the rest.
        wire.extend_from_slice(&[0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff]);
        wire.push(0u8); // 1 byte of "body" — far short of declared length
        let err = decode_frame(&wire).unwrap_err();
        // Either Varint (overflow path, on 32-bit hosts where
        // header_len + body_len > usize::MAX) or Short (on
        // 64-bit hosts where the add succeeds but buf.len() is
        // tiny relative to the declared body length). Both are
        // fail-closed; neither is a panic.
        assert!(
            matches!(err, WireError::Varint | WireError::Short { .. }),
            "iter-175: max-varint frame must error cleanly, got {err:?}"
        );
    }

    /// Iter-175: regression sanity — a frame whose declared body
    /// length exceeds the buffer's remaining capacity but stays
    /// within `usize` bounds still surfaces `Short`. This is the
    /// PRE-iter-175 hot path (no overflow); confirms the new
    /// `checked_add` doesn't break the common-case "wait for
    /// more bytes" branch.
    #[test]
    fn iter175_short_frame_still_surfaces_short_error() {
        let mut wire = Vec::with_capacity(6);
        wire.push(FRAME_CLIENT_HELLO);
        varint::encode(1024, &mut wire); // declares 1024-byte body
        wire.extend_from_slice(b"abc"); // delivers 3 bytes
        let err = decode_frame(&wire).unwrap_err();
        assert!(
            matches!(err, WireError::Short { .. }),
            "iter-175: legitimate short-buffer case must still surface Short, got {err:?}"
        );
    }
}
