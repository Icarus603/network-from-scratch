# OCB: A Block-Cipher Mode of Operation for Efficient Authenticated Encryption
**Venue / Year**: ACM Transactions on Information and System Security (TISSEC) 2003（preliminary CCS 2001）
**Authors**: Phillip Rogaway, Mihir Bellare, John Black
**Read on**: 2026-05-14 (in lesson 3.2)
**Status**: full PDF (`assets/papers/rogaway-ocb-2003.pdf`)
**One-line**: 第一個提供 single-pass、parallel、block-cipher-based AEAD 的設計——比 GCM/CCM 快 ~30%；但因專利歷史拖延部署 20 年，2021 patent 過期但 IETF 文化保守，實務仍少用；本論文是 modern AEAD design 的設計典範。

## Problem
2001 年的 AEAD 都是雙 pass（CCM = MAC 一次 + Enc 一次）或非並行（CBC-MAC 序列化）。理論最低成本是 single-pass + parallel：每 block 一次 block cipher call + 簡單 XOR + 累加。OCB 達到此理論最低。

## Contribution
1. **Single-pass AEAD**：每 plaintext block 只呼叫一次 block cipher (encryption)；驗證 tag 不需第二次 pass。比 CCM 省一半 block cipher call。
2. **Parallel-friendly**：每 block 之間獨立可同時計算（除 final tag）；GPU/SIMD/multi-core 極大加速。
3. **Tweakable block cipher 抽象**：用 LFSR-based offset (Δ_i) tweak 每個 AES call，避免 ECB-style 重複。Rogaway 後續用此抽象設計 XEX、XEX*、TWEAKEY。
4. **Provably secure**：在 PRP 假設下證明 IND-CPA + INT-CTXT，bound `q²/2^128`（典型 birthday）。
5. **Misuse-aware**：OCB3 加 nonce、IV 等 robust 設計避免 forbidden-attack-like 災難。

## Method
**OCB3 (RFC 7253) 簡化版**：
```text
Setup: K → AES key; H_K = AES_K(0)（hash key for AAD）
Δ_i = LFSR-derive(H_K, i, nonce)（per-block offset）

For each plaintext block P_i (i = 1..m):
    C_i = AES_K(Δ_i XOR P_i) XOR Δ_i

Final block (possibly partial):
    handle separately with length encoding

Tag computation:
    Σ = XOR_{i=1}^m P_i
    Auth = encrypt(Σ XOR final_offset)
    HashAAD = absorb associated data via Carter-Wegman polynomial
    Tag = Auth XOR HashAAD
```

**為什麼 single-pass 仍 INT-CTXT**：tag 同時 encode 全 plaintext (透過 XOR sum) 與 AES output (確保不能 random forge)。對手要構造 valid (C', T')：
- 改任一 C_i → 對應 P_i' 改變 → Σ 改 → Auth 改 → tag 改。
- 改 tag → 直接 verify fail。
- 構造 valid tag without knowing K → 等價解 PRP forging，2^-128 negligible。

## Results
- **OCB1 (2001) → OCB2 (2004) → OCB3 (2011 RFC 7253)**：迭代精煉，OCB3 是當前 standard。
- **效能**：~0.5 cycles/byte on Skylake (with AES-NI)，是已知最快 AEAD 之一。
- **CAESAR Competition (2014-2019) round 3 finalist**。
- **被部分 IPsec / SSH 實作支援** 但 TLS 1.3 沒納入（IPR 顧慮 + GCM 已標準化）。

## Limitations / what they don't solve
- **專利歷史拖部署**：Rogaway 持有 OCB 專利至 2021 才全 expire；IETF 在 RFC 7253 給 academic-only license。即使現在 patent-free，IETF 與工業界文化保守。
- **不是 misuse-resistant**：nonce 重用仍 catastrophic（同 GCM）。
- **沒原生 streaming**：要算 final tag 必須等到末 block；對 streaming AEAD 場景需另設計。

## How it informs our protocol design
- **Proteus 不選 OCB**：理由純 IPR conservatism（2026 年仍對 patent-encumbered legacy 敏感）+ implementation library 少（boringssl 沒、ring 沒）。
- **Proteus 借鑑 OCB 的 design 思想**：tweakable offset 概念在我們設計 cover-traffic packet structure 時可能用上。
- **Proteus 觀察 OCB 的 single-pass 教訓**：未來 V2 spec 若要 throughput 極限可考慮 AEGIS-128L（同樣 single-pass + AES-NI 友善 + 無 patent）。

## Open questions
- 是否能設計同時 single-pass + misuse-resistant + streaming 的 AEAD？目前三者只能取二（OCB single-pass 但無 MR；GCM-SIV MR 但 two-pass；ChaCha20-Poly1305 streaming 但 two-pass）。
- OCB3 在 PQ-quantum 下的 bound 仍 active。

## References worth following
- Rogaway *Efficient Instantiations of Tweakable Blockciphers and Refinements to Modes OCB and PMAC* (ASIACRYPT 2004) — OCB2。
- Krovetz, Rogaway *The Software Performance of Authenticated-Encryption Modes* (FSE 2011) — OCB3 vs GCM 比較。
- RFC 7253 — OCB3 spec。
- Wu, Preneel *AEGIS: A Fast Authenticated Encryption Algorithm* (SAC 2013) — AEGIS-128L，patent-free 替代。
