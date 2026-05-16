//! QUIC variable-length integer encoding (RFC 9000 §16) used throughout the
//! Proteus wire format.
//!
//! The encoding packs a 62-bit value plus a 2-bit length tag in the most
//! significant bits of the first byte:
//!
//! | Tag | Total bytes | Value range |
//! |-----|-------------|-------------|
//! | 00  | 1           | 0..=63 |
//! | 01  | 2           | 0..=16383 |
//! | 10  | 4           | 0..=2^30 − 1 |
//! | 11  | 8           | 0..=2^62 − 1 |

use crate::WireError;

/// Largest representable varint value (62 bits all set).
pub const MAX: u64 = (1u64 << 62) - 1;

/// Encode `value` into `out`, returning the number of bytes written.
///
/// Panics if `value > MAX` (caller must clamp first).
pub fn encode(value: u64, out: &mut Vec<u8>) -> usize {
    assert!(value <= MAX, "varint value out of range: {value:#x}");
    if value < 1 << 6 {
        out.push(value as u8);
        1
    } else if value < 1 << 14 {
        let v = value as u16 | 0x4000;
        out.extend_from_slice(&v.to_be_bytes());
        2
    } else if value < 1 << 30 {
        let v = (value as u32) | 0x8000_0000;
        out.extend_from_slice(&v.to_be_bytes());
        4
    } else {
        let v = value | 0xc000_0000_0000_0000;
        out.extend_from_slice(&v.to_be_bytes());
        8
    }
}

/// Decode the next varint from `buf`, returning `(value, bytes_consumed)`.
pub fn decode(buf: &[u8]) -> Result<(u64, usize), WireError> {
    let first = *buf.first().ok_or(WireError::Short { needed: 1, have: 0 })?;
    let tag = first >> 6;
    let len = 1usize << tag; // 1, 2, 4, 8
    if buf.len() < len {
        return Err(WireError::Short {
            needed: len,
            have: buf.len(),
        });
    }
    let mut bytes = [0u8; 8];
    bytes[8 - len..].copy_from_slice(&buf[..len]);
    let mut value = u64::from_be_bytes(bytes);
    // mask out the 2-bit length tag (the top 2 bits of the first byte after
    // left-aligning into the 8-byte buffer).
    let mask = !(0b11u64 << (len as u64 * 8 - 2));
    value &= mask;
    Ok((value, len))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trip_boundary_values() {
        let cases: &[u64] = &[
            0,
            1,
            63,
            64,
            16_383,
            16_384,
            (1 << 30) - 1,
            1 << 30,
            (1 << 62) - 1,
        ];
        for &v in cases {
            let mut buf = Vec::new();
            let written = encode(v, &mut buf);
            assert_eq!(buf.len(), written);
            let (decoded, consumed) = decode(&buf).unwrap();
            assert_eq!(consumed, written);
            assert_eq!(decoded, v, "varint round-trip failed for {v:#x}");
        }
    }

    #[test]
    fn length_tag_matches_rfc9000() {
        let mut buf = Vec::new();
        encode(63, &mut buf);
        assert_eq!(buf, [63u8]);

        buf.clear();
        encode(64, &mut buf);
        assert_eq!(buf, [0x40, 0x40]);

        buf.clear();
        encode(16_383, &mut buf);
        assert_eq!(buf, [0x7f, 0xff]);

        buf.clear();
        encode(16_384, &mut buf);
        assert_eq!(buf, [0x80, 0x00, 0x40, 0x00]);
    }

    #[test]
    fn short_buffer_errors() {
        let buf = [0x40u8]; // claims 2-byte varint but only 1 byte present
        assert!(matches!(
            decode(&buf),
            Err(WireError::Short { needed: 2, have: 1 })
        ));
    }
}
