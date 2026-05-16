//! Parser-correctness tests using hand-constructed ClientHello byte
//! strings. These lock in the JA4 spec interpretation (FoxIO 2023)
//! against fresh-eye misimplementations.

use proteus_fingerprint::ja4::{parse_client_hello, GREASE_VALUES};

/// Build a minimal but spec-correct TLS 1.3 ClientHello byte stream.
///
/// Layout (matches RFC 8446 + RFC 5246 record layer):
///
/// ```text
/// TLS record header (5 bytes):
///   0x16                  content_type = handshake
///   0x03 0x03             legacy_version = TLS 1.2 (always)
///   <u16 BE>              record length
///
/// Handshake header (4 bytes):
///   0x01                  type = ClientHello
///   <u24 BE>              handshake length
///
/// ClientHello body:
///   0x03 0x03             legacy_version (TLS 1.2)
///   <32 bytes>            random
///   <u8 len><bytes>       legacy_session_id (often 32 random bytes)
///   <u16 len><bytes>      cipher_suites (each entry is 2 bytes)
///   <u8 len><bytes>       legacy_compression_methods (always [0])
///   <u16 len><bytes>      extensions
/// ```
fn build_hello(ciphers: &[u16], extensions: &[(u16, Vec<u8>)]) -> Vec<u8> {
    let mut ch_body: Vec<u8> = Vec::new();
    ch_body.extend_from_slice(&[0x03, 0x03]); // legacy_version
    ch_body.extend_from_slice(&[0u8; 32]); // random
    ch_body.push(0); // empty session id
                     // ciphers
    ch_body.extend_from_slice(&((ciphers.len() * 2) as u16).to_be_bytes());
    for c in ciphers {
        ch_body.extend_from_slice(&c.to_be_bytes());
    }
    ch_body.push(1); // compression methods length
    ch_body.push(0); // null compression
                     // extensions
    let mut ext_bytes = Vec::new();
    for (et, ed) in extensions {
        ext_bytes.extend_from_slice(&et.to_be_bytes());
        ext_bytes.extend_from_slice(&(ed.len() as u16).to_be_bytes());
        ext_bytes.extend_from_slice(ed);
    }
    ch_body.extend_from_slice(&(ext_bytes.len() as u16).to_be_bytes());
    ch_body.extend_from_slice(&ext_bytes);

    let mut hs = Vec::new();
    hs.push(0x01); // ClientHello
    let body_len = ch_body.len() as u32;
    hs.extend_from_slice(&[
        (body_len >> 16) as u8,
        (body_len >> 8) as u8,
        body_len as u8,
    ]);
    hs.extend_from_slice(&ch_body);

    let mut rec = Vec::new();
    rec.extend_from_slice(&[0x16, 0x03, 0x03]); // record header
    rec.extend_from_slice(&(hs.len() as u16).to_be_bytes());
    rec.extend_from_slice(&hs);
    rec
}

#[test]
fn grease_values_are_filtered_from_cipher_count() {
    let ciphers = &[
        GREASE_VALUES[0], // GREASE — should be filtered
        0x1301,           // TLS_AES_128_GCM_SHA256
        0x1302,           // TLS_AES_256_GCM_SHA384
        GREASE_VALUES[5], // GREASE — should be filtered
        0x1303,           // TLS_CHACHA20_POLY1305_SHA256
    ];
    let bytes = build_hello(ciphers, &[]);
    let ja4 = parse_client_hello(&bytes, 't').unwrap();
    assert_eq!(ja4.cipher_count, 3, "GREASE values must be filtered out");
}

#[test]
fn grease_values_are_filtered_from_extension_count() {
    let exts: Vec<(u16, Vec<u8>)> = vec![
        (GREASE_VALUES[2], vec![]),             // GREASE
        (0x002b, vec![0x02, 0x03, 0x04]),       // supported_versions
        (GREASE_VALUES[7], vec![]),             // GREASE
        (0x000a, vec![0x00, 0x02, 0x00, 0x1d]), // supported_groups
    ];
    let bytes = build_hello(&[0x1301], &exts);
    let ja4 = parse_client_hello(&bytes, 't').unwrap();
    assert_eq!(ja4.ext_count, 2, "GREASE extensions must be filtered out");
}

#[test]
fn sni_presence_distinguishes_d_vs_i() {
    // With SNI extension.
    let exts_with: Vec<(u16, Vec<u8>)> = vec![(0x0000, vec![0u8; 10])];
    let bytes = build_hello(&[0x1301], &exts_with);
    let ja4 = parse_client_hello(&bytes, 't').unwrap();
    assert_eq!(ja4.sni, 'd');

    // Without SNI extension.
    let exts_without: Vec<(u16, Vec<u8>)> = vec![(0x002b, vec![0x02, 0x03, 0x04])];
    let bytes = build_hello(&[0x1301], &exts_without);
    let ja4 = parse_client_hello(&bytes, 't').unwrap();
    assert_eq!(ja4.sni, 'i');
}

#[test]
fn alpn_extension_is_parsed_with_first_last_char_tag() {
    // ALPN extension carrying "h2" (2 chars → tag "h2") and a second entry.
    let alpn = {
        let mut buf = Vec::new();
        // First ALPN entry: "h2".
        buf.push(2);
        buf.extend_from_slice(b"h2");
        // Second entry: "http/1.1" — should NOT be picked.
        buf.push(8);
        buf.extend_from_slice(b"http/1.1");
        // Wrap with list_len prefix.
        let mut wrapped = Vec::new();
        wrapped.extend_from_slice(&(buf.len() as u16).to_be_bytes());
        wrapped.extend_from_slice(&buf);
        wrapped
    };
    let exts: Vec<(u16, Vec<u8>)> = vec![(0x0010, alpn)];
    let bytes = build_hello(&[0x1301], &exts);
    let ja4 = parse_client_hello(&bytes, 't').unwrap();
    assert_eq!(ja4.alpn_tag, "h2");
}

#[test]
fn alpn_tag_is_first_and_last_char_not_just_first_two() {
    // ALPN value "http/1.1" should yield tag "h1" (first 'h', last '1').
    let alpn = {
        let mut buf = Vec::new();
        buf.push(8);
        buf.extend_from_slice(b"http/1.1");
        let mut wrapped = Vec::new();
        wrapped.extend_from_slice(&(buf.len() as u16).to_be_bytes());
        wrapped.extend_from_slice(&buf);
        wrapped
    };
    let exts: Vec<(u16, Vec<u8>)> = vec![(0x0010, alpn)];
    let bytes = build_hello(&[0x1301], &exts);
    let ja4 = parse_client_hello(&bytes, 't').unwrap();
    assert_eq!(
        ja4.alpn_tag, "h1",
        "JA4 spec: ALPN tag is first+last char of FIRST ALPN value"
    );
}

#[test]
fn no_alpn_extension_yields_00_tag() {
    let exts: Vec<(u16, Vec<u8>)> = vec![(0x002b, vec![0x02, 0x03, 0x04])];
    let bytes = build_hello(&[0x1301], &exts);
    let ja4 = parse_client_hello(&bytes, 't').unwrap();
    assert_eq!(ja4.alpn_tag, "00");
}

#[test]
fn supported_versions_overrides_legacy_version() {
    // legacy_version in body is 0x0303 (TLS 1.2), but supported_versions
    // advertises 0x0304 (TLS 1.3). JA4 must report "13".
    let sup_ver = vec![0x02, 0x03, 0x04]; // u8 list_len=2, then 0x0304
    let exts: Vec<(u16, Vec<u8>)> = vec![(0x002b, sup_ver)];
    let bytes = build_hello(&[0x1301], &exts);
    let ja4 = parse_client_hello(&bytes, 't').unwrap();
    assert_eq!(ja4.version, "13");
}

#[test]
fn cipher_count_caps_at_99() {
    let ciphers: Vec<u16> = (1..=150).collect();
    let bytes = build_hello(&ciphers, &[]);
    let ja4 = parse_client_hello(&bytes, 't').unwrap();
    assert_eq!(ja4.cipher_count, 99, "JA4 caps cipher_count at 99");
}

#[test]
fn extension_hash_excludes_sni_and_alpn() {
    // Two ClientHellos that differ ONLY in SNI value and ALPN list
    // contents must produce the SAME ext_hash. JA4 deliberately excludes
    // SNI + ALPN from the ext hash so the fingerprint is domain-
    // independent.
    let sni_a = {
        let mut sn = Vec::new();
        sn.extend_from_slice(&(7u16).to_be_bytes()); // list len
        sn.push(0); // name type = host_name
        sn.extend_from_slice(&(4u16).to_be_bytes()); // host name len
        sn.extend_from_slice(b"a.io");
        sn
    };
    let sni_b = {
        let mut sn = Vec::new();
        sn.extend_from_slice(&(11u16).to_be_bytes());
        sn.push(0);
        sn.extend_from_slice(&(8u16).to_be_bytes());
        sn.extend_from_slice(b"longer.io");
        sn[..2].copy_from_slice(&(11u16).to_be_bytes());
        sn
    };
    let alpn_a = {
        let mut a = Vec::new();
        a.push(2);
        a.extend_from_slice(b"h2");
        let mut w = Vec::new();
        w.extend_from_slice(&(a.len() as u16).to_be_bytes());
        w.extend_from_slice(&a);
        w
    };
    let alpn_b = {
        let mut a = Vec::new();
        a.push(8);
        a.extend_from_slice(b"http/1.1");
        let mut w = Vec::new();
        w.extend_from_slice(&(a.len() as u16).to_be_bytes());
        w.extend_from_slice(&a);
        w
    };

    let exts_a: Vec<(u16, Vec<u8>)> = vec![
        (0x0000, sni_a),
        (0x0010, alpn_a),
        (0x002b, vec![0x02, 0x03, 0x04]),
        (0x000a, vec![0x00, 0x02, 0x00, 0x1d]),
    ];
    let exts_b: Vec<(u16, Vec<u8>)> = vec![
        (0x0000, sni_b),
        (0x0010, alpn_b),
        (0x002b, vec![0x02, 0x03, 0x04]),
        (0x000a, vec![0x00, 0x02, 0x00, 0x1d]),
    ];
    let ja4_a = parse_client_hello(&build_hello(&[0x1301], &exts_a), 't').unwrap();
    let ja4_b = parse_client_hello(&build_hello(&[0x1301], &exts_b), 't').unwrap();
    assert_eq!(
        ja4_a.ext_hash, ja4_b.ext_hash,
        "ext_hash must be domain- AND ALPN-independent"
    );
    // But the alpn_tag itself IS captured separately in the JA4_a
    // segment, so the full JA4 still differs.
    assert_ne!(
        ja4_a.alpn_tag, ja4_b.alpn_tag,
        "alpn_tag itself MUST differ when ALPN differs"
    );
}
