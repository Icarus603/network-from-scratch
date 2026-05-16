# Timing Attacks on Implementations of Diffie-Hellman, RSA, DSS, and Other Systems
**Venue / Year**: CRYPTO 1996
**Authors**: Paul C. Kocher
**Read on**: 2026-05-14 (in lesson 3.13)
**Status**: full PDF (`assets/papers/kocher-timing-1996.pdf`)
**One-line**: 開創 side-channel cryptanalysis 領域——測量 cryptographic operation 時間 leak secret key bits；證明 naive RSA / DH / DSA implementations 可被 remote timing attack 完全破；驅動整個 constant-time programming 領域誕生。

## Problem
1990 年代 cryptographic implementations 主要 design goal 是 「正確 + 快」。沒人系統性問：「實作 timing 是否 leak 秘密 key 資訊？」Kocher 假設：是。並 demo。

## Contribution
1. **Timing attack on RSA / DH**:
   - Modular exponentiation `m = c^d mod n` 用 square-and-multiply。
   - Time depends on Hamming weight of d (number of 1 bits)。
   - 收集 many decrypt times for chosen ciphertexts → statistical correlation 推 bits of d。
2. **Concrete attack** 對 known RSA implementations (TI's RSAREF, BSAFE pre-3.0): demonstration of practical key recovery in days using <thousands measurements.
3. **修補建議**:
   - **Constant-time exponentiation**: always multiply (mask to discard if bit=0)。
   - **Montgomery ladder**: every iteration same operations。
   - **RSA blinding**: c' = c · r^e mod n → m' = c'^d = m · r → m = m' / r。Time pattern uncorrelated with d。
4. **泛化到所有 secret-dependent operations**: 影響 DSA nonce generation、AES key schedule 等。

## Method (簡化)
**Attack outline**:
```text
Target: RSA private key d (unknown)
Observable: time to decrypt ciphertext c.

For each candidate bit d_i (from MSB):
    Choose set of ciphertexts {c_j}.
    Measure decrypt time for each.
    If hypothesis "d_i = 1": predict timing pattern T_1.
    If hypothesis "d_i = 0": predict timing pattern T_0.
    
Use correlation analysis: measured time correlates better with T_b
    → d_i = b.

After enough measurements (~thousands per bit), recover full d.
```

詳細 attack 用 conditional reduction step in Montgomery multiplication 作為 timing signal — reduction needed iff intermediate > modulus, occurring with prob related to specific d bits.

## Results
- 對 unprotected RSA / DH / DSA implementations practical attack。
- **驅動 OpenSSL 加入 RSA blinding** (2003+，after Brumley-Boneh 2005 remote attack)。
- **影響後續 SP 800-90A DRBG design** (constant-time requirement)。
- 開創 side-channel cryptanalysis 整個 sub-field — CHES conference founded 1999。

## Limitations / what they don't solve
- 只處理 timing；power analysis (Kocher 1999 DPA), cache-timing (Bernstein 2005), Spectre (2018) 等 later 加入。
- 攻擊條件: 可 measure 多次 decrypt times。real-world 對 server 可能仍可行 (Brumley-Boneh 2005 remote attack)。
- 不涵蓋 Spectre-class 對 even constant-time code 的 leak。

## How it informs our protocol design
- **Proteus 所有 crypto operations 必須 constant-time**：
  - Curve25519 X25519 Montgomery ladder 已是 constant-time。
  - Ed25519 sign/verify constant-time (deterministic + canonical encoding)。
  - ChaCha20-Poly1305 inherently constant-time (ARX, 無 table lookup)。
- **Proteus implementation 必須 audit with ctgrind / dudect**。
- **Proteus 教訓**: timing attack 是 cryptographic implementation 的 baseline 風險；任何 deployment 必須 constant-time。

## Open questions
- **Generic constant-time guarantee for PQ schemes**: lattice rejection sampling 等 inherently variable-time; making it constant-time without performance disaster？
- **Hertzbleed (2022)**: even constant-time impl 受 CPU frequency scaling 影響 → 「constant-time」 itself 不夠 in modern microarch。

## References worth following
- Brumley-Boneh *Remote Timing Attacks are Practical* (USENIX Security 2003) — Kocher 攻擊在 network 環境的擴展。
- Boneh-Brumley *Remote Timing Attack on RSA Implementations of SSL* (USENIX Security 2005)。
- Mangard-Oswald-Popp *Power Analysis Attacks* (Springer 2007) — 後續 power analysis textbook。
- Aciiçmez 等 *On the Power of Simple Branch Prediction Analysis* (AsiaCCS 2007)。
