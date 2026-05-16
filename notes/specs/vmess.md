# VMess — wire-format spec
**Source**: https://www.v2fly.org/developer/protocols/vmess.html · v2fly/v2ray-core (proxy/vmess/encoding)
**Fetched**: 2026-05-16 (for lessons 7.5, 7.7, 7.8, 7.9)
**Status**: full (covers both legacy MD5-Auth and the post-2021 VMessAEAD upgrade)

## Wire format

VMess can run on raw TCP, TLS, WS, mKCP, etc. Below is the inner stream layout.

### Request header — VMessAEAD (current default)

```
| EAuID | ALength | Nonce | AHeader (encrypted command) | Data |
| 16 B  | 18 B    | 8 B   | variable                    | …    |
```

- **EAuID (16 B)** = AES-128-ECB-encrypted under `KDF(CmdKey, "AES Auth ID Encryption")[:16]` of:
  - Timestamp `8 B BE` (Unix seconds)
  - Rand `4 B`
  - CRC32 `4 B` over Timestamp+Rand
- **ALength (18 B)** = 2-byte plaintext length + 16-byte GCM tag, key = `KDF(CmdKey, "VMess Header AEAD Key_Length", EAuID, Nonce)[:16]`
- **Nonce (8 B)** = random
- **AHeader** = AES-128-GCM-encrypted command section, key = `KDF(CmdKey, "VMess Header AEAD Key", EAuID, Nonce)[:16]`

### Command section (inside AHeader)

| Offset | Size | Field |
|---|---|---|
| 0 | 1 B | Version (`0x01`) |
| 1 | 16 B | Body Encryption IV |
| 17 | 16 B | Body Encryption Key |
| 33 | 1 B | Response Auth `V` |
| 34 | 1 B | Options `Opt` |
| 35 | 4 b | Padding length `P` |
| 35.5 | 4 b | Security (`0x03` AES-128-GCM, `0x04` ChaCha20-Poly1305, `0x05` None, `0x06` Zero) |
| 36 | 1 B | Reserved |
| 37 | 1 B | Cmd (`0x01` TCP, `0x02` UDP) |
| 38 | 2 B | Port (BE) |
| 40 | 1 B | Address type |
| 41 | var | Address |
| … | P | Padding |
| … | 4 B | FNV1a-32 checksum over command |

`CmdKey = MD5(UUID || "c48619fe-8f02-49e0-b9e9-edf763e17e21")`.

### Response header

```
| V (1 B) | Opt (1 B) | Cmd (1 B) | M (1 B) | CmdContent (M B) | Body |
```

Encrypted with AEAD using `ResponseKey = SHA256(RequestKey)[:16]`, `ResponseIV = SHA256(RequestIV)[:16]`.

## Auth model

16-byte UUID + (deprecated) `alterID`. UUID seeds `CmdKey` via the legacy MD5 derivation. In legacy mode a per-user pool of `alterID+1` HMAC-MD5 hashes was published over a 60-second sliding window — VMessAEAD removes alterID by carrying the AuthID inside an AES-encrypted block keyed from `CmdKey`.

## Anti-replay

- **Timestamp window**: AuthID embeds an 8-byte UTC timestamp; the server rejects anything outside ±30 s (legacy ±90 s).
- **AuthID cache**: server keeps a Bloom/LRU of recently-seen AuthIDs to reject exact replays inside the window.
- **Failure mode**: if the client clock drifts beyond ±30 s the connection is silently dropped — historically the #1 source of "VMess works locally but not on this VPS" tickets, hence the requirement for NTP / chrony on both ends.

## Encryption / AEAD

- Header: AES-128-GCM (after the AuthID upgrade).
- Body: selectable per Security byte — `AES-128-GCM`, `ChaCha20-Poly1305`, `none`, `zero`. GCM and ChaCha20 derive nonces as `(2-byte BE counter || 10-byte derived IV)` so the per-record counter is implicit.
- Each body chunk is `| 2-byte length | ciphertext | 16-byte tag |`.

## Key design quirks worth flagging

- **MD5 everywhere** in the legacy era: HMAC-MD5 for AuthID, MD5 for `CmdKey` derivation. Even after the AEAD upgrade, `CmdKey` derivation still uses MD5 of `UUID || magic-string`. Cryptographically embarrassing but not exploitable in itself given AES-GCM on top.
- **2020 active-probe vuln** (the "VMess server detection" disclosure): the legacy MD5-Auth + AES-128-CFB header, lacking integrity, let probers send a tampered header and observe whether the server hung / closed at the right point — distinguishing VMess from background TLS noise. **VMessAEAD (2021) was the direct response**: the GCM tag fails authentication before any state changes and the server now closes "like a black hole."
- **No traffic shaping.** VMess does not pad records to disguise length, has the textbook `length || ciphertext || tag` chunked stream — easily fingerprinted on plain TCP. In production it relies on outer TLS/WS for cover, the same way Trojan/VLESS do.
- **`alterID` is dead.** Anything > 0 has been deprecated since 2021; modern Xray/sing-box always negotiate VMessAEAD with `alterID = 0`.

## Source of truth (code citation)

- `v2fly/v2ray-core/proxy/vmess/aead/encrypt.go` — `SealVMessAEADHeader`, `OpenVMessAEADHeader`.
- `v2fly/v2ray-core/proxy/vmess/encoding/auth.go` — KDF chain.
- `v2fly/v2ray-core/proxy/vmess/encoding/server.go` — AuthID replay cache.
- 2020 disclosure: github.com/v2ray/v2ray-core/issues/2523 (CVE-class behaviour, no CVE assigned).
