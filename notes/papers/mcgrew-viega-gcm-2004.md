# The Galois/Counter Mode of Operation (GCM)
**Venue / Year**: NIST submission 2004（後 NIST SP 800-38D 2007 標準化）
**Authors**: David A. McGrew, John Viega
**Read on**: 2026-05-14 (in lesson 3.2)
**Status**: abstract-only（IACR ePrint mirror Cloudflare 阻擋；NIST archive 部分檔案需 referer）。引用內容綜合自 NIST SP 800-38D + 訓練資料 + IETF RFC 5116 引文。
**One-line**: 將 AES-CTR 加密與 GHASH（GF(2^128) 多項式評估認證）合成 single-key AEAD，硬體加速友善（PCLMULQDQ + AES-NI）；2026 年仍是 TLS 1.3 / IPsec ESP / SSH 主力 cipher，但因 nonce-misuse catastrophic 而需嚴格 nonce 管理。

## Problem
2003-2004 NIST 在 SP 800-38C 標準化 CCM (Counter + CBC-MAC)，但 CCM 是 two-pass（先算 CBC-MAC 再 CTR encrypt），效能低於 single-pass。需要一個 single-pass、parallel-friendly、能用硬體 carryless multiply 加速的 AEAD。

## Contribution
1. **CTR-mode encryption + GHASH authentication 合成**：CTR 提供 IND-CPA；GHASH 提供 INT-CTXT；組合達 IND-CCA2 + INT-CTXT (per Bellare-Namprempre 2000)。
2. **GHASH = GF(2^128) polynomial evaluation**：將 ciphertext + AAD 視為 GF(2^128) 元素序列，evaluate at hash key H = AES_K(0)；輸出與 AES_K(J_0) XOR 為 tag。
3. **Hardware acceleration friendly**：GF(2^128) multiplication 透過 PCLMULQDQ (Intel 2010) / PMULL (ARMv8) instruction 一個 cycle 完成；AES-NI 加速 CTR；合計 ~0.6 cycles/byte。
4. **Parallel block independent**：CTR keystream 各 block 獨立可並行；GHASH 用 Horner's rule 但可 batched 為多個 polynomial chunks 平行算。
5. **Provably secure**：在 PRP/PRF 假設下 IND-CCA2 + INT-CTXT，bound 為 birthday + tag-length terms。

## Method (just enough to reproduce mentally)
```text
GCM-Enc(K, IV, A, P):
    H = AES_K(0^128)
    if |IV| == 96: J_0 = IV ‖ 0^31 ‖ 1
    else:          J_0 = GHASH_H(0, IV, len(IV))
    C = AES-CTR_K(P, starting at inc(J_0))
    T = GHASH_H(A, C, len(A) ‖ len(C)) XOR AES_K(J_0)
    return (C, T[:τ])    where τ ∈ {32,64,96,104,112,120,128}

GCM-Dec(K, IV, A, C, T):
    recompute H, J_0, expected T'
    if T ≠ T'[:τ]: return ⊥    (constant-time compare)
    P = AES-CTR_K(C, starting at inc(J_0))
    return P
```

**GHASH details**：
```text
GHASH_H(X_1, X_2, ..., X_m) = Σ_{i=1}^m X_i · H^{m-i+1}  (in GF(2^128))
```
其中 GF(2^128) 用 polynomial x^128 + x^7 + x^2 + x + 1 表示。

## Results
- **NIST SP 800-38D (2007)** 標準化。
- **TLS 1.2 (RFC 5288)**、**TLS 1.3 (RFC 8446)** 採用 AES-128/256-GCM。
- **IPsec ESP (RFC 4106)** 採用。
- **SSH** 透過 `aes128-gcm@openssh.com`、`aes256-gcm@openssh.com` cipher 採用。
- **Hardware 普及**：所有 Intel/AMD/ARM modern CPU 加速。

## Limitations / what they don't solve
- **Nonce-misuse catastrophic**：Joux 2006 forbidden attack。任何 implementation bug 重用 (key, IV) → 全 key recovery。
- **Tag truncation 風險**：允許 32-bit tag 但 forge probability 2^-32 太弱；NIST 建議 ≥ 96-bit tag。
- **GHASH 線性**：H 在 GF(2^128) 下，多項式評估的線性性質讓 forbidden attack 可行（同 key 同 IV → polynomial system → solve H）。
- **Single-key advantage cap**：multi-user setting 下 advantage 隨 user 數惡化（Bellare-Tackmann 2016）。

## How it informs our protocol design
- **Proteus hardware-fast path 用 AES-256-GCM**：在 AES-NI + PCLMULQDQ 環境下達 ~80 Gbps single core。
- **Proteus 強制 96-bit nonce（IETF 變體）**：避免任意長度 IV 引入的 GHASH J_0 derivation 複雜性。
- **Proteus 強制 128-bit tag**：禁止 truncation。
- **Proteus nonce 結構 = epoch ‖ direction ‖ counter**：deterministic、不靠 RNG，避免 forbidden attack 在野實例（Bock 等 2016 USENIX WOOT 觀察過）。
- **Proteus 0-RTT 改用 GCM-SIV**：0-RTT 重送可能無意 reuse nonce，SIV 結構安全 fallback。

## Open questions
- Multi-user GCM 在 100M+ users 場景的 tight bound？Bellare-Tackmann 2016 仍是當前最強。
- Quantum cryptanalysis：Grover 對 AES-256 key 仍 128-bit security；對 GHASH H 找碰撞？
- 後 PQ 時代是否仍用 GCM 結構，或改 sponge-based AEAD？

## References worth following
- NIST SP 800-38D — GCM standard。
- Joux *Authentication Failures in NIST GCM* (2006) — forbidden attack。本 lesson 已 precis。
- Bellare, Tackmann *Multi-User Security of AES-GCM in TLS 1.3* (CRYPTO 2016) — multi-user bound。
- Bock 等 *Nonce-Disrespecting Adversaries: Practical Forgery on GCM in TLS* (USENIX WOOT 2016) — 在野實證。
- Gueron, Lindell *GCM-SIV* (CCS 2015) — misuse-resistant 替代。
