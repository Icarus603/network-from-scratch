# Proteus Protocol Specification v0.1

> **Status**: Internal draft. Authored during course `learn/` Part 11. Not for IETF submission; will be IETF-aligned post Part 12 implementation feedback.
> **Codename**: Proteus —— 名取自希臘神話海神 Πρωτεύς（Homer, *Odyssey* IV.385），以能隨意變形避捕著稱。對照本協議在 ML traffic classifier 下隨機 cover-shape，在 GFW blanket port block 下隨機 transport profile（γ/β/α）切換，命名直譯其行為。
> **Date**: 2026-05-16 (course author timestamp).
> **License**: see repo LICENSE.

## §1. Introduction

### 1.1 Purpose

Proteus is an anti-censorship transport protocol designed for two simultaneous goals:

1. **Censorship resistance**: indistinguishable from popular cover protocol traffic at flow-level under SOTA detectors, and indistinguishable from the cover server during active probing.
2. **High performance**: matching SOTA QUIC-based proxies (Hysteria2, TUIC v5) in goodput, latency, and CPU.

### 1.2 Non-goals

See `lessons/part-11-design/11.2 §6`. Briefly: GPA-level unlinkability, NAT traversal hole punching, application-level anonymity, DNS-level censorship circumvention, side-channel hardening for shared-cloud hosts.

### 1.3 Threat model summary

Detailed threat model in §11. Capabilities C1–C13 are taxonomized; C1–C7, C9–C12 are in-scope; C8 (endpoint compromise), C13 (shared-cloud side channel) are out-of-scope.

### 1.4 Comparison to existing protocols

| Property | Proteus v0.1 | VLESS+REALITY | Hysteria2 | TUIC v5 | WireGuard |
|---|---|---|---|---|---|
| Transport | MASQUE/H3-on-QUIC (primary), QUIC, TCP-TLS fallback | TCP-TLS | QUIC | QUIC | UDP |
| Hybrid PQ | yes | no | no | no | optional |
| TLS-in-TLS architectural defense | yes (CONNECT-UDP) | no | yes (QUIC) | yes | yes (no TLS) |
| Active probing defense | REALITY-style + cover forward | REALITY | partial | partial | none |
| PCS | weak (Tamarin-verified) | none | none | none | none |
| Formal verification | TLA+ + ProVerif + Tamarin | none | none | none | partial |

## §2. Conventions

The key words **MUST**, **MUST NOT**, **REQUIRED**, **SHALL**, **SHALL NOT**, **SHOULD**, **SHOULD NOT**, **RECOMMENDED**, **NOT RECOMMENDED**, **MAY**, and **OPTIONAL** are to be interpreted as described in BCP 14 (RFC 2119, RFC 8174) when, and only when, they appear in all capitals.

All byte sequences are big-endian unless stated otherwise. Variable-length integers use QUIC varint encoding (RFC 9000 §16).

## §3. Architecture overview

```
+--------+    UDP/443 H3 (with Proteus ext in ClientHello)   +-----------------+
| Client | ----------------------------------------------> | Proteus Server (ProteusS) |
+--------+                                                +-----------------+
                                                                   |
                                                                   | if auth fails
                                                                   v
                                                            +-------------+
                                                            | Cover Server |
                                                            +-------------+
```

Proteus has three transport mode profiles in priority order:

- **Primary** (Proteus-γ): MASQUE CONNECT-UDP over H3 over QUIC over UDP/443.
- **Fallback** (Proteus-β): raw QUIC + REALITY-on-QUIC.
- **Last resort** (Proteus-α): TLS 1.3 over TCP/443 + REALITY-on-TCP + inner padding mode.

Servers MUST support primary mode. Servers MAY additionally listen for fallback/last-resort modes.

## §4. Wire format

Detailed in `lessons/part-11-design/11.5`. Summary:

### §4.1 ClientHello Proteus authentication extension

```
extension_type = 0xfe0d
extension_data = ProteusAuthExtension (1186 bytes)

struct ProteusAuthExtension {
    opaque   client_nonce[16];
    opaque   client_x25519_pub[32];
    opaque   client_mlkem768_ct[1088];
    opaque   client_id[16];
    uint16   timestamp_unix_minutes;
    opaque   auth_tag[32];
};
```

`auth_tag = HMAC-SHA-256(auth_key, concat(client_nonce, client_x25519_pub, client_mlkem768_ct, client_id, timestamp))`

`auth_key = HKDF-Extract(salt=server_pq_fingerprint, IKM=client_x25519_pub || client_nonce)`

### §4.2 Inner packet format

After H3 + MASQUE CONNECT-UDP capsule, inner stream is Proteus packets:

```
struct ProteusInnerHeader {
    uint8   type;        // 0x01=DATA, 0x02=ACK, 0x03=NEW_STREAM, etc.
    uint8   flags;
    uint16  reserved;     // MUST be zero; receiver MUST reject if not
    uint64  seqnum;
};
```

Inner packet types and payloads: see lesson 11.5 §3.

### §4.3 Cell padding

Each outgoing UDP datagram MUST be padded to 1280 bytes using type-0x07 PADDING inner packets, EXCEPT during handshake (which follows cover protocol natural shape) and during KEYUPDATE/CLOSE (which MAY be sent without padding).

## §5. Handshake

Detailed in `lessons/part-11-design/11.6`.

### §5.1 State machine

The handshake state machine has 11 states: INIT, AUTH_PENDING, VERIFY, DECAPS, SECRET_DERIVED, HANDSHAKE_DONE, CONNECTED, KEYUPDATE_PENDING, FALLBACK, FALLBACK_FORWARDING, CLOSED.

See lesson 11.6 §2 for full state transition table.

### §5.2 Key schedule

Proteus uses TLS 1.3's HKDF key schedule (RFC 8446 §7.1) with the following modification: the DH input is the concatenation of K_classic = X25519(c_sk, s_pk) and K_pq = ML-KEM-768.Decaps(server_kemsk, client_mlkem768_ct):

```
DH_input = K_classic || K_pq         (64 bytes total)
Early Secret    = HKDF-Extract(salt=0,                        IKM=client_nonce)
Handshake Secret = HKDF-Extract(salt=Derive-Secret(ES, "derived", ""), IKM=DH_input)
Master Secret    = HKDF-Extract(salt=Derive-Secret(HS, "derived", ""), IKM=0)
```

All `Derive-Secret(...)` and `HKDF-Expand-Label(...)` operations follow RFC 8446 §7.1 exactly.

### §5.3 KEYUPDATE ratchet

Trigger: either party sends KEYUPDATE packet (type=0x06) when one of:
- ≥ 2^32 packets sent since last ratchet,
- ≥ 24 hours since last ratchet,
- application-explicit request,
- received from peer.

Action: `new_secret = HKDF-Expand-Label(old_secret, "proteus ratchet", "", 32)`. KEYUPDATE payload contains `next_epoch` and `transcript_hash_at_connected`.

## §6. Cryptographic algorithms (fixed)

- **AEAD**: ChaCha20-Poly1305 (RFC 8439, default) OR AES-256-GCM (RFC 5116).
- **Hash**: SHA-256 (RFC 6234) for TLS 1.3 transcript; BLAKE3 for Proteus-internal KDF where labelled.
- **ECDH**: X25519 (RFC 7748).
- **KEM**: ML-KEM-768 (NIST FIPS-203).
- **Signature** (TLS cert): Ed25519 (RFC 8032). ML-DSA-65 SHALL be added in v0.2.
- **KDF**: HKDF-SHA-256 (RFC 5869).

No negotiation of these in v0.1. v0.2+ uses extension code points 0xfe1d onwards.

## §7. Cover protocol pinning

The server MUST be configured with one or more `cover_url` values pointing to globally popular HTTPS sites (Alexa top 10k or Tranco top 100k). The server MUST forward any QUIC Initial whose `0xfe0d` extension fails authentication (HMAC mismatch, timestamp out of window, replay, KEM decapsulation failure, or client_id decryption failure) byte-verbatim to one of the configured `cover_url` endpoints. The cover URL chosen for forwarding MAY be deterministic (per source IP hash) or random.

Forward operation MUST complete with < 1ms p99 additional RTT inflation relative to direct fetch. Server implementations SHOULD use kernel-bypass or SO_REUSEPORT+eBPF for forward path.

## §8. Anti-replay

Server MUST maintain a sliding Bloom filter (or equivalent) of seen `(client_nonce, timestamp)` pairs, window = 1 hour, target false-positive rate ≤ 10^-9.

Server MUST reject `0xfe0d` if `|now - timestamp|` (mod 65536, after sign correction) > 30 minutes.

0-RTT (if enabled) MUST use single-use resumption tickets with independent ticket-decryption key rotated ≥ every 24 hours. 0-RTT replay protection uses a second Bloom filter keyed on `(psk_identity, client_nonce)`.

0-RTT is **OFF by default**. Operators enabling 0-RTT MUST document the relaxation in their deployment Security Considerations.

## §9. Padding and shaping

Padding budget α ≤ 0.30, computed as `(padding_bytes / data_bytes) over a rolling 10-second window`. Server impls MAY exceed budget instantaneously but MUST converge within 10 seconds.

Cover-IAT shaping profile is per-cover-URL (configured). At minimum two profiles MUST be supported: `streaming` (large, mostly-asymmetric bursts) and `api-poll` (small, periodic).

Idle (no application data for > 5 seconds) MUST NOT send dummy padding. Application-level PING SHOULD be sparse.

## §10. Connection migration & multi-path

Connection migration is governed by QUIC (RFC 9000 §9). Proteus servers SHOULD set QUIC transport parameter `disable_active_migration = true` (i.e., only peer-initiated NAT rebinding allowed). Multi-path is currently unsupported (deferred to v0.2+ pending IETF QUIC MULTIPATH WG maturation).

## §11. Security Considerations

§§11.1–11.16 follow lesson 11.7 verbatim. Key clauses:

- §11.3 Forward secrecy: ProVerif phase 1 + Tamarin `fs_after_ltk_reveal` verified.
- §11.4 KCI resistance: ProVerif Q2/Q3 verified.
- §11.5 Replay: sliding Bloom + 30-min window.
- §11.6 No downgrade: cipher/KEM locked.
- §11.10 Anti-active-probing: REALITY-style fallback.
- §11.11 Anti-fingerprint padding: 1280B cell + cover IAT shaping.
- §11.12 PQ: hybrid X25519+ML-KEM-768.
- §11.16 Known unattenuated risks (long-term aggregation, censor blocking whole CDN range).

## §12. Extensibility

§12.1 Extension framework as in lesson 11.8: handshake-layer extensions use `0xfe00–0xfeff` codespace; inner-data-layer extensions use packet types `0xf0–0xff`. Unknown extensions MUST be silently ignored.

§12.2 GREASE: clients MUST insert 1–2 random GREASE extension code points in ClientHello (per RFC 8701 conventions).

§12.3 Version negotiation: v0.1 has no explicit version field. v0.2+ will use additional extension type codepoints (e.g., 0xfe1d for v0.2 auth) signaled by client; server picks highest version supported.

§12.4 Cipher / KEM agility: deferred to v0.2.

## §13. Conformance summary

- §13.1 Wire format conformance: byte-level exact per §4 and lesson 11.5.
- §13.2 Handshake conformance: state machine per §5 and lesson 11.6.
- §13.3 Crypto: §6 algorithms only.
- §13.4 v0.1 compliance test vectors: to be published with reference implementation (Part 12).

## §14. IANA considerations

This document does not require IANA actions at this stage. Future versions targeted for IETF submission will register `0xfe0d` and successor extension type codepoints in the TLS ExtensionType registry, and define an ALPN identifier `proteus/0.1` (if needed; v0.1 inherits `h3` ALPN).

## §15. References

### §15.1 Normative

- RFC 2119 / 8174 (BCP 14)
- RFC 5116 AEAD
- RFC 5869 HKDF
- RFC 7748 X25519
- RFC 8032 Ed25519
- RFC 8439 ChaCha20-Poly1305
- RFC 8446 TLS 1.3
- RFC 9000 QUIC
- RFC 9001 TLS in QUIC
- RFC 9114 HTTP/3
- RFC 9297 HTTP Datagrams and the Capsule Protocol
- RFC 9298 Proxying UDP in HTTP
- NIST FIPS-203 ML-KEM
- BLAKE3 specification (Aumasson et al., 2020)

### §15.2 Informative

- RFC 8701 GREASE
- RFC 9170 Protocol extensibility
- draft-ietf-tls-hybrid-design-11 Hybrid KE in TLS 1.3
- Krawczyk, SIGMA, CRYPTO 2003
- Cohn-Gordon et al., Post-Compromise Security, JoC 2016
- Donenfeld, WireGuard, NDSS 2017
- Cremers et al., TLS 1.3 Tamarin, CCS 2017
- Bhargavan et al., TLS 1.3 ProVerif, S&P 2017
- Tschantz et al., FOCI 2016
- Frolov et al., FOCI 2020, NDSS 2020
- Houmansadr et al., Parrot is dead, S&P 2013
- Bock et al., CCS 2020
- Wu et al., USENIX 2023 (FEP)
- Xue et al., USENIX 2024 (TLS-in-TLS)
- Wang et al., USENIX 2024 (TunnelVision)
- Mosca's theorem, S&P 2018

## §16. Implementation notes (informative)

Reference implementation will use:

- Rust (primary) with `rustls`, `quinn`, `RustCrypto/aead`, `RustCrypto/ml-kem`.
- Go reference client embedded in sing-box plugin.
- BBRv3 congestion control (or fallback to RFC 9002 NewReno).
- Linux server: SO_REUSEPORT + eBPF for forward-path low-latency.

See Part 12 lessons for implementation details.

## §17. Changes from v0.0

Compared to draft v0.0 (lessons 11.5–11.8):

1. Forward path latency budget now normative (§7).
2. Cover URL array support now normative (§7).
3. ClientHello browser profile now normative `chrome-130+` (§4.1).
4. 0-RTT ticket key rotation policy now normative (§8).
5. Padding budget clarified as 10-second-window time-average (§9).
6. Connection migration `disable_active_migration` now recommended (§10).
7. Aggressive CC variants now opt-in only (§6 informative).
8. Per-cover-URL traffic profile (`streaming`/`api-poll`) now normative (§9).
9. ACK frequency profile configurable (§4.2).
10. TunnelVision (Xue 2024) noted in §11.14 with binding recommendation.

---

End of Proteus v0.1.
