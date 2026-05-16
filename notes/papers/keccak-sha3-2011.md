# The Keccak Reference (v3.0)
**Venue / Year**: NIST SHA-3 Competition Round 3 submission, January 2011（後 FIPS 202 SHA-3 Standard, 2015）
**Authors**: Guido Bertoni, Joan Daemen, Michaël Peeters, Gilles Van Assche
**Read on**: 2026-05-14 (in lesson 3.3)
**Status**: full PDF (`assets/papers/keccak-sha3-2011.pdf`)
**One-line**: 用 sponge construction + Keccak-f[1600] permutation 構造的 hash function；2012 年 NIST SHA-3 競賽勝出，徹底擺脫 Merkle-Damgård 的 length-extension 缺陷；XOF 內建讓 KDF / MAC / hash / random oracle 統一。

## Problem
SHA-1 在 2005 Wang-Yin-Yu collision 攻擊後可信度動搖；SHA-2 雖然 still secure 但與 SHA-1 同 Merkle-Damgård 結構，潛在類似攻擊 worry。NIST 2007 啟動 SHA-3 公開競賽，要求新 hash:
- 不基於 Merkle-Damgård（避免 length-extension + 結構類同 SHA-1 / SHA-2 風險）。
- ≥ SHA-2 的 security level。
- 軟體 + 硬體效能可接受。
- 提供額外 functionality（如 XOF）。

## Contribution
1. **Sponge construction（Bertoni 等先前 ECRYPT 2007 提出）**：把 hash 視為 absorb + squeeze；state size > output size，capacity c bits 永遠不外露 → no length-extension。
2. **Keccak-f permutation**：state 1600-bit 排成 5×5×64 lanes；24 rounds；每 round 用 θ ρ π χ ι 五個 step（純 bit-level operations + lane rotations + XOR）。
3. **可調 (rate, capacity) 給不同 output 長度與 security**：
   - SHA3-224: r=1152, c=448 (112-bit collision security)
   - SHA3-256: r=1088, c=512 (128-bit)
   - SHA3-384: r=832,  c=768 (192-bit)
   - SHA3-512: r=576,  c=1024 (256-bit)
4. **XOF (Extendable Output Function)**：SHAKE128 (c=256), SHAKE256 (c=512) 可 squeeze 任意長 output；天然 KDF / DRBG / random oracle。
5. **Indifferentiable from random oracle**（Bertoni 等 2008 證明）：sponge 構造在 PRP 假設下 indifferentiable，給強 RO-like 安全性。

## Method (just enough to reproduce mentally)
**Sponge framework**：
```text
State S = 0^b   (b = r + c)
Padding: m → m ‖ pad10*1 (multi-rate padding)
Split into r-bit blocks M_1, ..., M_n

Absorb:
    For i = 1..n:
        S = f(S XOR (M_i ‖ 0^c))    // f = Keccak-f[1600]

Squeeze:
    Z = empty
    Repeat:
        Z = Z ‖ S[0:r]
        S = f(S)
    Until |Z| ≥ requested length
```

**Keccak-f[1600] round (五步)**：

```text
Round R applied to state A[5][5][64]:
    θ (theta):   diffusion across columns
        C[x] = A[x][0] ⊕ A[x][1] ⊕ A[x][2] ⊕ A[x][3] ⊕ A[x][4]
        D[x] = C[x-1] ⊕ ROT(C[x+1], 1)
        A[x][y] ⊕= D[x]
    
    ρ (rho):     lane rotations (各 lane rotate by triangular table value)
    π (pi):      permute lane positions
    χ (chi):     non-linear (only 非 linear step):
        A[x][y] = A[x][y] ⊕ ((¬A[x+1][y]) ∧ A[x+2][y])
    ι (iota):    XOR a round constant into A[0][0]
```

24 rounds of f → diffusion 完整 + 對 differential / linear cryptanalysis 有 wide margin（Daemen wide-trail strategy）。

**為什麼 sponge 沒 length-extension**：output 只取 state[0:r]，capacity[r:b] 永遠 hidden。對手知道 hash digest H(M)，不知 hidden capacity；無法繼續 absorb extension。

## Results
- **NIST FIPS 202 (2015)** 標準化為 SHA-3。
- **SHAKE128/256** 為 XOF 標準，被 NIST PQ 標準（Kyber、Dilithium）內部用作 random oracle。
- **Ascon** (NIST LWC 2023) 採用 sponge 思想但更輕量。
- **Keccak (round count 不同) 在區塊鏈** 廣泛使用：Ethereum 用 Keccak-256（pre-FIPS 202 變體）。

## Limitations / what they don't solve
- 軟體效能不及 SHA-2 / BLAKE3：純軟體 SHA3-256 ~12 cycles/byte，SHA-256 ~5 c/b，BLAKE3 ~0.5 c/b。
- 1600-bit state 對嵌入式 / IoT 偏重；Ascon 是 lightweight 替代。
- 部分硬體加速指令 (Intel SHA Extensions) 只支援 SHA-1/2，不支援 SHA-3。

## How it informs our protocol design
- **Proteus future-proof option**：spec 預留 hash_id field 支援 SHA-3 升級；hash agility 重要。
- **Proteus cover-traffic padding 用 SHAKE128**：任意長 PRG-style output 適合產生 plausible-looking padding。
- **Proteus 不 default SHA-3**：軟體效能 + library 普及度 + TLS 1.3 互通 三因素仍偏 SHA-256。
- **Proteus 設計取捨**：若 future PQ 主導讓 hash-agnostic 重要，會 migrate 到 SHA-3 / SHAKE。

## Open questions
- Quantum cryptanalysis of Keccak-f[1600]：BHT 量子 collision 達 2^128 操作；對 SHA3-256 仍提供 ~85-bit quantum collision security。是否 sufficient？
- Keccak-based AEAD (Ketje, Keyak, Ascon) 與 ChaCha20-Poly1305 / AES-GCM 在 protocol context 的 trade-off 仍 active。
- Lightweight Keccak variant (Keccak-p[400]) 安全 margin 仍 monitoring。

## References worth following
- Bertoni 等 *Cryptographic Sponge Functions* (ECRYPT report 2011) — sponge 設計專書。
- Bertoni 等 *On the Indifferentiability of the Sponge Construction* (EUROCRYPT 2008) — RO-equivalence 證明。
- NIST FIPS 202 — SHA-3 標準。
- Aumasson *Serious Cryptography* (NSP 2018) — sponge 與 KDF 章節適合 modern intro。
