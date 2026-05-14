# The Poly1305-AES Message-Authentication Code
**Venue / Year**: Fast Software Encryption (FSE) 2005
**Authors**: Daniel J. Bernstein
**Read on**: 2026-05-14 (in lesson 3.2)
**Status**: full PDF (`assets/papers/bernstein-poly1305-2005.pdf`)
**One-line**: 在質數 p = 2^130 - 5 上做多項式評估的 Carter-Wegman MAC——比 HMAC 快 3-5 倍，secure with provable ε-AXU bound；後與 ChaCha20 結合成 IETF AEAD 標準 (RFC 8439)，是 G6 預設 record-layer 認證。

## Problem
2005 年的 MAC 主流：
- **HMAC** (Bellare-Canetti-Krawczyk 1996, RFC 2104)：基於 hash function；`HMAC = H(K' ⊕ opad ‖ H(K' ⊕ ipad ‖ m))`。安全好但慢（兩次完整 hash），對長 message 約 ~5-10 cycles/byte。
- **CBC-MAC**：基於 block cipher；序列化（不可平行），慢。
- **Universal hash families** (Carter-Wegman 1979, 1981)：理論上很快但缺優雅 deployment——直到 Bernstein 端出 Poly1305。

## Contribution
1. **質數選擇 p = 2^130 - 5**：恰好讓 16-byte block (128 bits) + 1 carry bit 仍 < p，避免 reduction 邊界 case；同時 p - 5 結構讓 reduction 用 (a · 2^130) → (a · 5) mod p 簡化。
2. **r 的 16-bit mask 設計**：確保 r 的 4 個 limb 各 ≤ 2^28，內部運算不 overflow 64-bit register。
3. **One-time MAC + nonce**：Poly1305 本身是 ε-AXU；要當 MAC 用必須對每 message 用**新的** (r, s)。原 paper 用 AES_K(N) 產生 (r, s)；後 IETF 8439 改用 ChaCha20_K(N, ctr=0) 產生 32-byte one-time key 拆 r ‖ s。
4. **可證明安全**：對任何不同 messages m, m'，碰撞機率 ≤ ⌈L/16⌉ · 8 / 2^106 (L = max message length in bytes)。
5. **效能**：1.5-2 cycles/byte (Pentium 4, 2005); 現代 SIMD 實作 ~0.5 cycles/byte (Skylake AVX-512)。

## Method (just enough to reproduce mentally)
```text
Input: 32-byte key (split into r ‖ s, 各 16 byte); message m (任意長度)
Output: 16-byte tag

Step 1: Mask r
    r[3] &= 15; r[7] &= 15; r[11] &= 15; r[15] &= 15
    r[4] &= 252; r[8] &= 252; r[12] &= 252

Step 2: Split m into 16-byte blocks m_1, ..., m_q (last possibly partial)
    For each block m_i:
        m_i' = m_i with appended 0x01 byte (and zero-padded to 17 bytes if partial)
        treat m_i' as little-endian integer in [0, 2^130)

Step 3: Polynomial evaluation
    acc = 0
    For i = 1..q:
        acc = (acc + m_i') * r mod p     // p = 2^130 - 5

Step 4: Add s and reduce
    tag = (acc + s) mod 2^128
```

**為什麼 ε-AXU**：對任何 m ≠ m'，MAC 差 = (Poly_r(m) - Poly_r(m')) mod p。把它當 r 的多項式，degree ≤ q（block 數）。多項式在隨機 r 下取任一固定值的機率 ≤ q/p ≤ q · 2^-130。考慮 8 carry possibilities，最終 ε ≤ 8L / 2^106。

**Carter-Wegman 框架**：用 universal hash + one-time pad 構成 MAC。優勢：MAC computation 可平行（每 block 獨立計算 prefix sum），不像 CBC-MAC 序列化。

## Results
- **ChaCha20-Poly1305 (RFC 8439)** 成為 modern AEAD 標準，TLS 1.3 mandatory。
- **AES-GCM 的 GHASH 結構**也採用類似 polynomial-evaluation 思路（在 GF(2^128) 而非 Z_p）。
- **WireGuard、Signal、QUIC** record layer 全用 Poly1305 變體。
- **libsodium、ring、BoringSSL** 內建。

## Limitations / what they don't solve
- **One-time key 必須**：每 message 一新的 (r, s)；nonce 重用 → MAC forge（Joux-style attack on Poly1305 too）。
- **不是 PRF**：Poly1305 的 output 不是 pseudo-random；要當 PRF 用需先 hash output。
- **長度上限**：q ≤ 2^32 blocks ≈ 64 GB per message，超過後 advantage 不可忽略。

## How it informs our protocol design
- **G6 用 RFC 8439 ChaCha20-Poly1305**：one-time key 自動 derived from per-record nonce + ChaCha20 counter=0。
- **G6 spec 限制 record size ≤ 16 KB**：遠低於 Poly1305 limit；給 implementation 寬裕。
- **G6 tag verify constant-time**：用 `crypto_verify_16` (libsodium) 或等價，避免 timing-based forgery oracle。

## Open questions
- Multi-key Poly1305 的 tight bound？
- Quantum cryptanalysis：Grover 對 forge probability 的 quadratic speedup 在 ε-AXU 結構上的精確 implication 仍 active。

## References worth following
- Carter, Wegman *Universal Classes of Hash Functions* (JCSS 1979) — Carter-Wegman framework。
- Wegman, Carter *New Hash Functions and Their Use in Authentication and Set Equality* (JCSS 1981) — UMAC 範式。
- Krovetz *Message Authentication on 64-bit Architectures* (SAC 2006) — UMAC implementation。
- Procter *A Security Analysis of the Composition of ChaCha20 and Poly1305* (2014) — composition 安全性 explicit proof。
