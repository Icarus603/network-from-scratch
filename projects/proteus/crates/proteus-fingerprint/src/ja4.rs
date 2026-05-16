//! JA4 fingerprint extractor (FoxIO 2023 specification).
//!
//! ## JA4 format
//!
//! `q_AB_CC_DD_EE_hashA_hashB` where:
//!
//! - `q`: transport — `t` for TCP, `q` for QUIC, `d` for DTLS.
//! - `AB`: 2-char TLS-version label (e.g. `13` for TLS 1.3, `12`
//!   for TLS 1.2). We derive the negotiated version from the
//!   `supported_versions` extension when present, else from the
//!   legacy `client_hello.version` field.
//! - `D` (3rd char of the AB block, but conventionally written as
//!   a single char between AB and CC): `d` if SNI is present
//!   (server_name extension), `i` if absent.
//! - `CC`: count of cipher suites, 2 decimal digits, capped at 99.
//!   GREASE values excluded.
//! - `DD`: count of extensions, 2 decimal digits, capped at 99.
//!   GREASE values excluded.
//! - `EE`: 2-character ALPN tag — the first/last characters of the
//!   FIRST ALPN value. `00` if no ALPN extension is present.
//! - `hashA`: SHA-256 first 12 hex chars over the
//!   lowercase-hex-encoded cipher list, sorted ascending, comma-
//!   joined. GREASE excluded.
//! - `hashB`: SHA-256 first 12 hex chars over
//!   `sorted_ext_ids_joined_by_comma + "_" + sig_algs_joined_by_comma`.
//!   GREASE excluded.
//!
//! The whole format is `q + AB + D + CC + DD + EE + "_" + hashA + "_" + hashB`,
//! e.g. `t13d1517h2_8daaf6152771_b0da82dd1658` (Chrome 124).
//!
//! Reference: <https://blog.foxio.io/ja4%2B-network-fingerprinting>

use sha2::{Digest, Sha256};
use std::fmt;
use thiserror::Error;

/// Errors from JA4 parsing.
#[derive(Debug, Error)]
pub enum Ja4Error {
    /// Buffer too short for the field being parsed (offset, want).
    #[error("buffer truncated at offset {offset}, wanted {wanted}")]
    Truncated {
        /// Byte offset where the read failed.
        offset: usize,
        /// Number of bytes needed.
        wanted: usize,
    },
    /// Not a ClientHello.
    #[error("not a ClientHello (handshake type = {0})")]
    NotClientHello(u8),
    /// Bad TLS record header.
    #[error("bad TLS record header: {0}")]
    BadRecord(&'static str),
}

/// GREASE values (RFC 8701). These cipher suites / extensions /
/// versions are RANDOM PLACEHOLDERS that real browsers insert to
/// ensure middleboxes don't ossify; any JA4-compliant fingerprint
/// MUST ignore them.
pub const GREASE_VALUES: &[u16] = &[
    0x0a0a, 0x1a1a, 0x2a2a, 0x3a3a, 0x4a4a, 0x5a5a, 0x6a6a, 0x7a7a, 0x8a8a, 0x9a9a, 0xaaaa, 0xbaba,
    0xcaca, 0xdada, 0xeaea, 0xfafa,
];

fn is_grease(v: u16) -> bool {
    GREASE_VALUES.contains(&v)
}

/// Computed JA4 fingerprint.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Ja4 {
    /// Transport char: 't' / 'q' / 'd'.
    pub transport: char,
    /// "13" or "12" or "11" or "10".
    pub version: String,
    /// 'd' if SNI present, 'i' otherwise.
    pub sni: char,
    /// Count of ciphers (post-GREASE-filter), capped at 99.
    pub cipher_count: u8,
    /// Count of extensions (post-GREASE-filter), capped at 99.
    pub ext_count: u8,
    /// First/last char of first ALPN, or "00".
    pub alpn_tag: String,
    /// 12 hex chars: SHA-256 prefix over sorted ciphers.
    pub cipher_hash: String,
    /// 12 hex chars: SHA-256 prefix over sorted extensions + sig algs.
    pub ext_hash: String,
}

impl fmt::Display for Ja4 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{}{}{}{:02}{:02}{}_{}_{}",
            self.transport,
            self.version,
            self.sni,
            self.cipher_count,
            self.ext_count,
            self.alpn_tag,
            self.cipher_hash,
            self.ext_hash,
        )
    }
}

/// Parse a TLS 1.2/1.3 ClientHello from a raw byte stream and
/// compute its JA4 fingerprint.
///
/// `record_bytes` must begin with the TLS record-layer header (5
/// bytes: `content_type | legacy_version_2 | length_2`). The
/// `content_type` MUST be `0x16` (handshake), the inner handshake
/// MUST be type `0x01` (ClientHello).
///
/// `transport` is `'t'` for TCP-based TLS, `'q'` for QUIC's TLS-in-
/// CRYPTO frame, `'d'` for DTLS. Caller picks based on context.
pub fn parse_client_hello(record_bytes: &[u8], transport: char) -> Result<Ja4, Ja4Error> {
    // ----- TLS record header -----
    if record_bytes.len() < 5 {
        return Err(Ja4Error::Truncated {
            offset: 0,
            wanted: 5,
        });
    }
    if record_bytes[0] != 0x16 {
        return Err(Ja4Error::BadRecord("content_type != handshake (0x16)"));
    }
    let record_len = u16::from_be_bytes([record_bytes[3], record_bytes[4]]) as usize;
    if record_bytes.len() < 5 + record_len {
        return Err(Ja4Error::Truncated {
            offset: 5,
            wanted: record_len,
        });
    }
    let hs = &record_bytes[5..5 + record_len];

    // ----- Handshake header (1 byte type + 3 byte length) -----
    if hs.len() < 4 {
        return Err(Ja4Error::Truncated {
            offset: 0,
            wanted: 4,
        });
    }
    if hs[0] != 0x01 {
        return Err(Ja4Error::NotClientHello(hs[0]));
    }
    let hs_len = u32::from_be_bytes([0, hs[1], hs[2], hs[3]]) as usize;
    if hs.len() < 4 + hs_len {
        return Err(Ja4Error::Truncated {
            offset: 4,
            wanted: hs_len,
        });
    }
    let ch = &hs[4..4 + hs_len];

    // ----- ClientHello body -----
    let mut cur = Cursor::new(ch);
    let legacy_version = cur.read_u16_be()?; // 2 bytes
    let _random = cur.read_n(32)?; // 32 bytes
    let sid_len = cur.read_u8()? as usize;
    let _sid = cur.read_n(sid_len)?;

    // Cipher suites.
    let ciphers_len = cur.read_u16_be()? as usize;
    let ciphers_bytes = cur.read_n(ciphers_len)?;
    let mut ciphers = Vec::with_capacity(ciphers_len / 2);
    for chunk in ciphers_bytes.chunks_exact(2) {
        let c = u16::from_be_bytes([chunk[0], chunk[1]]);
        if !is_grease(c) {
            ciphers.push(c);
        }
    }

    // Compression methods (skip).
    let comp_len = cur.read_u8()? as usize;
    let _comp = cur.read_n(comp_len)?;

    // Extensions.
    let mut ext_ids: Vec<u16> = Vec::new();
    let mut sig_algs: Vec<u16> = Vec::new();
    let mut sni_present = false;
    let mut first_alpn: Option<Vec<u8>> = None;
    let mut sup_versions_max: Option<u16> = None;
    if cur.remaining() >= 2 {
        let ext_total = cur.read_u16_be()? as usize;
        let ext_bytes = cur.read_n(ext_total)?;
        let mut ec = Cursor::new(ext_bytes);
        while ec.remaining() >= 4 {
            let ext_type = ec.read_u16_be()?;
            let ext_len = ec.read_u16_be()? as usize;
            let ext_data = ec.read_n(ext_len)?;
            if is_grease(ext_type) {
                continue;
            }
            ext_ids.push(ext_type);
            match ext_type {
                0x0000 => {
                    // server_name (SNI). Present means 'd'.
                    sni_present = true;
                }
                0x000d => {
                    // signature_algorithms. Format: u16 length, then list of u16 algs.
                    let mut sec = Cursor::new(ext_data);
                    if sec.remaining() >= 2 {
                        let list_len = sec.read_u16_be()? as usize;
                        let list = sec.read_n(list_len)?;
                        for ch in list.chunks_exact(2) {
                            let a = u16::from_be_bytes([ch[0], ch[1]]);
                            if !is_grease(a) {
                                sig_algs.push(a);
                            }
                        }
                    }
                }
                0x0010 => {
                    // application_layer_protocol_negotiation (ALPN).
                    // Format: u16 list_len, then [u8 len | bytes] entries.
                    let mut sec = Cursor::new(ext_data);
                    if sec.remaining() >= 2 {
                        let _list_len = sec.read_u16_be()?;
                        if sec.remaining() >= 1 {
                            let one_len = sec.read_u8()? as usize;
                            let one = sec.read_n(one_len)?;
                            first_alpn = Some(one.to_vec());
                        }
                    }
                }
                0x002b => {
                    // supported_versions. Format: u8 list_len, then list of u16.
                    // Pick the highest non-GREASE value as the negotiated.
                    let mut sec = Cursor::new(ext_data);
                    if sec.remaining() >= 1 {
                        let list_len = sec.read_u8()? as usize;
                        let list = sec.read_n(list_len)?;
                        for ch in list.chunks_exact(2) {
                            let v = u16::from_be_bytes([ch[0], ch[1]]);
                            if !is_grease(v) {
                                sup_versions_max = Some(match sup_versions_max {
                                    Some(cur_max) => cur_max.max(v),
                                    None => v,
                                });
                            }
                        }
                    }
                }
                _ => {}
            }
        }
    }

    // Negotiated version: prefer supported_versions, fall back to legacy.
    let neg_version = sup_versions_max.unwrap_or(legacy_version);
    let version_str = match neg_version {
        0x0304 => "13",
        0x0303 => "12",
        0x0302 => "11",
        0x0301 => "10",
        _ => "00",
    };

    let sni = if sni_present { 'd' } else { 'i' };

    // ALPN tag: 2-char tag from the first ALPN string.
    let alpn_tag = match first_alpn {
        Some(ref a) if !a.is_empty() => {
            // JA4 spec: first and last char of the ALPN. e.g. "h2" → "h2",
            // "http/1.1" → "h1", "h3-29" → "h9".
            let first = a[0];
            let last = a[a.len() - 1];
            // If either is non-printable, fall back to a hex-of-first-byte
            // formulation. JA4 reference impl uses ASCII only; we mirror.
            let to_char = |b: u8| -> char {
                if b.is_ascii_graphic() {
                    b as char
                } else {
                    '9' // arbitrary stable fallback
                }
            };
            format!("{}{}", to_char(first), to_char(last))
        }
        _ => "00".to_string(),
    };

    let cipher_count = ciphers.len().min(99) as u8;
    let ext_count = ext_ids.len().min(99) as u8;

    // Hashes: sort ascending, lowercase-hex-encode each, comma-join, SHA-256, first 12 hex chars.
    let mut sorted_ciphers = ciphers.clone();
    sorted_ciphers.sort_unstable();
    let cipher_str = sorted_ciphers
        .iter()
        .map(|c| format!("{c:04x}"))
        .collect::<Vec<_>>()
        .join(",");
    let cipher_hash = sha256_prefix_12(cipher_str.as_bytes());

    // For the extension hash, JA4 spec excludes the SNI (0x0000) AND
    // ALPN (0x0010) from the SORTED extension list because they vary
    // per-domain and would otherwise destroy the fingerprint's
    // domain-independence. signature_algorithms list is appended
    // after a literal '_' separator, IN ORDER (NOT sorted — sig_algs
    // are positional in the original ClientHello).
    let mut sorted_exts: Vec<u16> = ext_ids
        .iter()
        .copied()
        .filter(|&e| e != 0x0000 && e != 0x0010)
        .collect();
    sorted_exts.sort_unstable();
    let ext_str = sorted_exts
        .iter()
        .map(|e| format!("{e:04x}"))
        .collect::<Vec<_>>()
        .join(",");
    let sig_str = sig_algs
        .iter()
        .map(|a| format!("{a:04x}"))
        .collect::<Vec<_>>()
        .join(",");
    let ext_hash_input = format!("{ext_str}_{sig_str}");
    let ext_hash = sha256_prefix_12(ext_hash_input.as_bytes());

    Ok(Ja4 {
        transport,
        version: version_str.to_string(),
        sni,
        cipher_count,
        ext_count,
        alpn_tag,
        cipher_hash,
        ext_hash,
    })
}

fn sha256_prefix_12(data: &[u8]) -> String {
    let mut h = Sha256::new();
    h.update(data);
    let out = h.finalize();
    // 6 bytes → 12 hex chars
    out.iter()
        .take(6)
        .map(|b| format!("{b:02x}"))
        .collect::<String>()
}

struct Cursor<'a> {
    buf: &'a [u8],
    pos: usize,
}

impl<'a> Cursor<'a> {
    fn new(buf: &'a [u8]) -> Self {
        Self { buf, pos: 0 }
    }

    fn remaining(&self) -> usize {
        self.buf.len().saturating_sub(self.pos)
    }

    fn read_u8(&mut self) -> Result<u8, Ja4Error> {
        if self.remaining() < 1 {
            return Err(Ja4Error::Truncated {
                offset: self.pos,
                wanted: 1,
            });
        }
        let v = self.buf[self.pos];
        self.pos += 1;
        Ok(v)
    }

    fn read_u16_be(&mut self) -> Result<u16, Ja4Error> {
        if self.remaining() < 2 {
            return Err(Ja4Error::Truncated {
                offset: self.pos,
                wanted: 2,
            });
        }
        let v = u16::from_be_bytes([self.buf[self.pos], self.buf[self.pos + 1]]);
        self.pos += 2;
        Ok(v)
    }

    fn read_n(&mut self, n: usize) -> Result<&'a [u8], Ja4Error> {
        if self.remaining() < n {
            return Err(Ja4Error::Truncated {
                offset: self.pos,
                wanted: n,
            });
        }
        let s = &self.buf[self.pos..self.pos + n];
        self.pos += n;
        Ok(s)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn grease_table_is_correct_per_rfc_8701() {
        // RFC 8701 §2 lists exactly 16 GREASE values, each of form 0xXaXa.
        assert_eq!(GREASE_VALUES.len(), 16);
        for &g in GREASE_VALUES {
            let bytes = g.to_be_bytes();
            assert_eq!(bytes[0] & 0x0f, 0x0a);
            assert_eq!(bytes[1] & 0x0f, 0x0a);
            assert_eq!(bytes[0] >> 4, bytes[1] >> 4);
        }
    }

    #[test]
    fn rejects_non_handshake_record() {
        let bytes = [0x17, 0x03, 0x03, 0x00, 0x05, 0xde, 0xad, 0xbe, 0xef, 0x00];
        let r = parse_client_hello(&bytes, 't');
        assert!(matches!(r, Err(Ja4Error::BadRecord(_))));
    }

    #[test]
    fn rejects_truncated_record() {
        let bytes = [0x16, 0x03, 0x03]; // record header truncated mid-way
        let r = parse_client_hello(&bytes, 't');
        assert!(matches!(r, Err(Ja4Error::Truncated { .. })));
    }

    #[test]
    fn display_format_matches_spec() {
        // Hand-construct a JA4 and verify the format produced by Display
        // matches the canonical 't13d1517h2_<6>_<6>' shape.
        let ja4 = Ja4 {
            transport: 't',
            version: "13".to_string(),
            sni: 'd',
            cipher_count: 15,
            ext_count: 17,
            alpn_tag: "h2".to_string(),
            cipher_hash: "8daaf6152771".to_string(),
            ext_hash: "b0da82dd1658".to_string(),
        };
        assert_eq!(ja4.to_string(), "t13d1517h2_8daaf6152771_b0da82dd1658");
    }

    #[test]
    fn sha256_prefix_12_is_first_6_bytes_hex() {
        // Verify our hasher matches what the JA4 spec requires:
        // first 12 lowercase hex chars of SHA-256.
        let out = sha256_prefix_12(b"hello");
        // SHA-256("hello") = 2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824
        assert_eq!(out, "2cf24dba5fb0");
    }
}
