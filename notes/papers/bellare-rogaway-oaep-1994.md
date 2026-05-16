# Optimal Asymmetric Encryption — How to Encrypt with RSA
**Venue / Year**: EUROCRYPT 1994
**Authors**: Mihir Bellare, Phillip Rogaway
**Read on**: 2026-05-14 (in lesson 3.4)
**Status**: full PDF (`assets/papers/bellare-rogaway-oaep-1994.pdf`)
**One-line**: RSA-OAEP（Optimal Asymmetric Encryption Padding）的 paper——把 textbook RSA 用 hash + random padding 包裝成 IND-CCA2-secure scheme；雖然後 Shoup 2001 證明原 proof 有缺陷需要 stronger assumption (partial-domain one-way RSA)，但 PKCS#1 v2.0 採用至今。

## Problem
1994 年 PKCS#1 v1.5 仍是 RSA encryption 標準，但已有警告其 ad-hoc 設計（後 Bleichenbacher 1998 證實 catastrophic）。需要 IND-CCA2-secure RSA encryption with provable security。

## Contribution
1. **OAEP padding 結構**：用兩個 hash function G, H 與 random seed 混入 plaintext，使得 (a) plaintext 與 randomness 在 padding 後均勻分布全 message space；(b) IND-CCA2 secure under ROM + RSA Problem。
2. **形式化證明**：給 ROM-based reduction 從 IND-CCA2-OAEP 到 RSA Problem。
3. **效能**：padding 開銷 fixed-size (typically 2 × hash_len + 1)，relative to message O(1)。

## Method
```text
Inputs: message M (≤ n_byte_len - 2k_0 - 1 bytes), public exponent e
        Hash functions: G : {0,1}^k_0 → {0,1}^(n - k_0)
                        H : {0,1}^(n - k_0) → {0,1}^k_0

OAEP-Encode(M, label):
    lHash = Hash(label)         // label often empty
    PS = zero padding
    dataBlock = lHash ‖ PS ‖ 0x01 ‖ M    // length = n_byte_len - k_0 - 1
    seed = random (k_0 bytes)
    dbMask = MGF(seed, n_byte_len - k_0 - 1)
    maskedDB = dataBlock XOR dbMask
    seedMask = MGF(maskedDB, k_0)
    maskedSeed = seed XOR seedMask
    EM = 0x00 ‖ maskedSeed ‖ maskedDB

RSA-OAEP-Enc:
    c = EM^e mod n      // EM treated as integer 0 ≤ EM < n

RSA-OAEP-Dec:
    EM = c^d mod n
    parse EM = 0x00 ‖ maskedSeed ‖ maskedDB
    seedMask = MGF(maskedDB, k_0)
    seed = maskedSeed XOR seedMask
    dbMask = MGF(seed, ...)
    dataBlock = maskedDB XOR dbMask
    Verify lHash matches; find 0x01 separator; output M.
```

`MGF` (Mask Generation Function) 是基於 hash 的 expansion（HKDF-style）。

**Reduction sketch (BR 1994 original)**: assume A breaks IND-CCA2-OAEP with non-negligible advantage. Construct B that solves RSA Problem (c = m^e, find m): B simulates ROM for G and H, observes A's queries; from A's chosen-ciphertext queries to OAEP decryption oracle, B can extract m.

**Shoup 2001 缺陷**: BR 1994 reduction 有 gap; OAEP IND-CCA2 不能 reduced 從 plain RSA Problem，而要 **Partial-Domain One-Way RSA** 或 **Set Partial-Domain One-Way RSA**（assume RSA partial inversion 也難）。Fujisaki-Okamoto-Pointcheval-Stern 2001 用 stronger assumption 重證 OAEP IND-CCA2。

## Results
- **PKCS#1 v2.0 (1998)** 採用 OAEP。
- **TLS 1.2** 部分支持 OAEP；TLS 1.3 完全廢 RSA KEX。
- **IETF RFC 8017 (PKCS#1 v2.2)** 包含 OAEP spec。
- **HSM、TPM、Web Crypto API** 都實作 OAEP。

## Limitations / what they don't solve
- **Implementation pitfalls**：OAEP decode 必須 constant-time 否則仍可能 padding-oracle-like（雖然比 v1.5 難 exploit）。
- **Quantum**: RSA 整體 Shor-vulnerable。OAEP 不解此問題。
- **Padding overhead**: 2 × hash_len + 1 byte。對 short messages 比例顯著。

## How it informs our protocol design
- **Proteus 不用 RSA-OAEP**：理由——key exchange 改用 X25519 ECDH，比 RSA-OAEP 快且 size 小 8×。
- **Proteus 必須能 verify 與 RSA-OAEP cert 互通的 PKI chain**：但實務 cert verification 用 PSS signature，OAEP encryption 不常見。
- **Proteus 教訓 #1**：「padding 設計要有 reduction proof」——避免 ad-hoc。
- **Proteus 教訓 #2**：「ROM proof 不等於真實安全」——Shoup 2001 證明 BR 1994 reduction 有缺陷，提醒我們對 ROM-based proof 保持戒心，Proteus 盡量 standard-model。

## Open questions
- OAEP 在 quantum random oracle model 下的 IND-CCA2 bound 仍 active。
- 是否存在 better-than-OAEP padding for RSA with stronger reduction in standard model？

## References worth following
- Shoup *OAEP Reconsidered* (CRYPTO 2001) — 指出 BR 1994 proof gap。
- Fujisaki, Okamoto, Pointcheval, Stern *RSA-OAEP is Secure Under the RSA Assumption* (CRYPTO 2001) — patch。
- Coron *Optimal Security Proofs for PSS and Other Signature Schemes* (EUROCRYPT 2002) — tight PSS reduction。
- RFC 8017 — PKCS#1 v2.2 OAEP spec。
