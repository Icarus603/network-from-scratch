# The security impact of a new cryptographic library
**Venue / Year**: LATINCRYPT 2012（NaCl design 2008-2009; this paper as manifesto）
**Authors**: Daniel J. Bernstein, Tanja Lange, Peter Schwabe
**Read on**: 2026-05-14 (in lesson 3.14)
**Status**: full PDF (`assets/papers/bernstein-nacl-2009.pdf`)
**One-line**: NaCl (Networking and Cryptography Library) 的設計 manifesto——提出 「Operations not algorithms」、「Hard to misuse」、「Constant-time inside」、「Hyperoptimized」四原則；徹底重新定義 cryptographic library API，影響 libsodium、ring、monocypher 等所有 modern crypto libraries。

## Problem
2009 年 cryptographic library 主流是 OpenSSL：
- API 包含 thousands of functions。
- 鼓勵 user 直接 manage cipher state, MAC, padding 等 low-level details。
- 預設 insecure (e.g., random nonce 從 user 端來，user 可能弄錯)。
- Heartbleed (2014) 等 catastrophic bugs 後續驗證 API surface 過大 → impossible to audit。

Bernstein 等問：「如果重新設計 cryptographic API，要怎麼做？」

## Contribution
1. **NaCl design philosophy** (four pillars):
   - **Operations not algorithms**: API 不問 user 用 AES 還是 ChaCha20。`crypto_secretbox` 直接做 authenticated encryption。
   - **Hard to misuse**: API 設計使 nonce reuse / 算法錯選 impossible。
   - **Constant-time inside**: 所有 primitive impl 內部 constant-time。
   - **Hyperoptimized**: SIMD, ARX, asm where appropriate。
2. **具體 API 範例**:
   - `crypto_secretbox(c, m, mlen, nonce, key)` — 直接 AEAD。內部 XSalsa20-Poly1305。
   - `crypto_box(c, m, mlen, nonce, pk_recipient, sk_sender)` — 直接 ECDH + AEAD。內部 Curve25519 + XSalsa20-Poly1305。
   - `crypto_sign(sm, m, mlen, sk)` — Ed25519 signature。
3. **Performance**: NaCl primitive 在當時 Pentium / Core 2 上 best in class — proves "secure + fast" 不矛盾。
4. **影響 libsodium (2013+)** 為 NaCl 的 cross-platform fork，至今 NaCl-API-compatible。
5. **後續 ring (Rust)** 在 NaCl 哲學上加 Rust type safety。

## Method (illustrate via crypto_box)
**NaCl API**:
```c
int crypto_box(
    unsigned char *c,           // ciphertext output
    const unsigned char *m,     // plaintext
    unsigned long long mlen,
    const unsigned char *nonce, // 24 byte
    const unsigned char *pk,    // recipient pk (32 byte)
    const unsigned char *sk     // sender sk (32 byte)
);
```

**Internal (opaque to user)**:
```text
1. Compute shared = X25519(sk, pk)
2. Derive symmetric_key = HSalsa20(shared, zero_nonce)
3. Encrypt + auth via XSalsa20-Poly1305(symmetric_key, nonce, m)
4. Output c
```

User 完全不需要選 algorithm; 內部 hard-coded "right answers"。

## Results
- **libsodium widespread adoption**: dozens of language bindings, Signal Protocol, WireGuard helpers, Monero 等部署。
- **ring (Rust)** 採 NaCl-style minimal API。
- **monocypher** single-file C NaCl-compatible library。
- **Influence on TLS 1.3 API design**: AEAD-only, no manual padding management。
- **Latacora "Cryptographic Right Answers"** 直接 echo NaCl philosophy。

## Limitations / what they don't solve
- **NaCl 不 support algorithm agility**: 完全 hard-coded XSalsa20-Poly1305 + Curve25519。若 future migration to PQ, 需要新 library version。
- **NaCl 不 support traditional algorithms** (AES, RSA): user 想用 hardware AES-NI 需要 libsodium 額外 functions or boringssl。
- **No formal verification**: NaCl 是 hand-coded; HACL\* 才提供 verified impl。
- **NaCl-style API 對 multi-step protocols 不夠**: TLS-style stateful API 仍需要 libsodium 提供 secretstream 等 streaming abstractions。

## How it informs our protocol design
- **G6 API 借鑑 NaCl 哲學**:
  - User-facing config: 不 expose cipher choice。
  - Plugin API: protocol-level operations, no raw crypto。
  - Internal: 用 ring (Rust NaCl-spirit)。
- **G6 hard-coded ciphers per version**: 同 NaCl ergonomic / WireGuard reasoning。
- **G6 PQ migration via new spec version**: 不 negotiate, 不 fallback. Follows NaCl version-based agility。
- **G6 教訓**: API design 是 cryptographic security 的 first line — 比 implementation correctness 更早決定 security baseline。

## Open questions
- **Verified NaCl-compatible API**: HACL\* / EverCrypt 在嘗試 verified equivalent of NaCl primitives。Performance gap 仍 closing。
- **PQ NaCl extensions**: 如何 cleanly extend NaCl API for hybrid X25519+Kyber 場景？
- **NaCl for stateful streaming protocols**: nacl::secretstream 等 仍是 active design。

## References worth following
- Bernstein *NaCl original site* (nacl.cr.yp.to) — primary docs。
- libsodium documentation (libsodium.gitbook.io)。
- Bernstein *Curve25519* (PKC 2006), *Ed25519* (CHES 2011), *Poly1305* (FSE 2005) — primitive papers。
- Aumasson *Serious Cryptography* 第 14 章 — modern crypto eng。
