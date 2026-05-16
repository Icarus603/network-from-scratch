# Finding Collisions in the Full SHA-1
**Venue / Year**: CRYPTO 2005
**Authors**: Xiaoyun Wang, Yiqun Lisa Yin, Hongbo Yu
**Read on**: 2026-05-14 (in lesson 3.3)
**Status**: full PDF (`assets/papers/wang-sha1-2005.pdf`)
**One-line**: 第一個對 full 80-round SHA-1 給 collision attack of complexity 2^69（vs 2^80 brute force），打破 SHA-1 nominal security；雖 2005 仍 computational infeasible，啟動 SHA-1 deprecation 與 SHA-3 競賽。

## Problem
SHA-1 (1995) 給 80-round Merkle-Damgård 構造，期望 collision security 2^80。Wang 在 2004 已破 MD5 (CRYPTO 2004) + SHA-0 (CRYPTO 2004 兩篇)；後續鎖定 SHA-1。

## Contribution
1. **2^69 collision attack**：比 brute force 快 2^11 倍；雖然 2005 年仍 infeasible (~$10M cost on then-hardware)，但證明 SHA-1 「在數學上 broken」。
2. **使用 differential cryptanalysis**：找到 SHA-1 message expansion 中的 high-probability differential characteristic，組合成 multi-block collision。
3. **Multi-block 方法**：先找 near-collision in first block，第二 block 用 specific message difference 抵消第一 block 的 chaining value 差異。
4. **影響：NIST 即刻啟動 SHA-3 competition** (2007)，並 2011 起逐步 deprecate SHA-1。

## Method (high-level)
**Differential characteristic 構造**：
- 找 message difference Δm 使 SHA-1 round function 在多 round 後仍保持 controlled difference in chaining state。
- 用 message modification techniques（Wang 的 signature 技術）強制 specific bits in chaining state。
- 兩個 message m, m' = m + Δm 經 SHA-1 後 chaining state 差異 cancel out → collision。

**複雜度分析**：找一個 collision 需要 ~2^69 SHA-1 invocations。對比 brute force birthday 是 2^80。

## Results
- **2005**: 攻擊複雜度 2^69 (此論文)。
- **2005-2017 一系列改進**：
  - 2005 Wang, Yao, Yao: 2^63 (improvement)。
  - 2009: 2^52 (Manuel)。
  - 2017: SHAttered (Stevens 等)：first practical full SHA-1 collision; ~2^63.1, $110k cloud cost.
  - 2020: SHA-1 chosen-prefix collision (Leurent, Peyrin) practical at $45k.
- **NIST SP 800-131A** 從 2014 起逐步 disallow SHA-1。
- **CA/B Forum** 2017 全 web PKI 棄用 SHA-1 cert。
- **Git 仍用 SHA-1**（2020 Linus 論述切換到 SHA-256 進行中；2026 仍 partial migration）。

## Limitations / what they don't solve
- 不是 preimage attack（仍需 ~2^160 brute force）；只是 collision。
- 不打破 HMAC-SHA1（HMAC 需要的是 PRF 性質，collision 不直接 imply HMAC break）。
- 影響範圍限於需要 collision-resistance 的 application（簽章、CA cert、commitment）。

## How it informs our protocol design
- **Proteus 絕不用 SHA-1**：transcript hash、KDF、HMAC base 全用 SHA-256+。
- **Proteus 必須有 hash agility**：spec 內定義 hash_id field，預留升級到 SHA-3 / BLAKE3 路徑。
- **Proteus 教訓 #1**：「security margin 是時間單位」——SHA-1 從 1995 設計到 2005 broken in theory 到 2017 broken in practice，22 年。我們設計 Proteus hash 選擇要假設 256-bit security 至少 30 年內安全。
- **Proteus 教訓 #2**：collision 比 preimage 早死：design protocol 時要謹慎 hash 在哪些 path 需要 collision-resistance vs preimage-only。

## Open questions
- 對 SHA-256 是否存在類似 differential characteristic？至 2026 年最強 attack 對 SHA-256 round-reduced 是 ~46/64 round。Full 64-round 仍安全 margin 充足。
- Wang 的攻擊 framework 對 quantum adversary 加 Grover 的 implication 仍 active。

## References worth following
- Wang, Lai, Feng, Chen, Yu *Cryptanalysis of the Hash Functions MD4 and RIPEMD* (EUROCRYPT 2005) — Wang 系列另一篇。
- Wang, Yu *How to Break MD5 and Other Hash Functions* (EUROCRYPT 2005) — MD5 破解。
- Stevens 等 *The First Collision for Full SHA-1* (CRYPTO 2017) — SHAttered。
- Leurent, Peyrin *SHA-1 is a Shambles: First Chosen-Prefix Collision on SHA-1 and Application to the PGP Web of Trust* (USENIX Security 2020)。
