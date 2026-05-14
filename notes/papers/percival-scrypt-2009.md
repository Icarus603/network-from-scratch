# Stronger Key Derivation via Sequential Memory-Hard Functions
**Venue / Year**: BSDCan 2009
**Authors**: Colin Percival
**Read on**: 2026-05-14 (in lesson 3.3)
**Status**: full PDF (`assets/papers/percival-scrypt-2009.pdf`)
**One-line**: 第一個 sequential memory-hard function（scrypt），引入「memory-hard」概念對抗 password cracking 的 GPU/ASIC 攻擊；雖然後被 Argon2 超越，但開創 memory-hard 設計範式並影響 PoW、KDF、PHC competition。

## Problem
2008-2009 GPU 開始普及，比特幣 mining 預示 ASIC 時代。Password cracking 用 GPU 比 CPU 快 100-1000×。傳統 PBKDF2 (RFC 2898) 增加 iteration 數但對 GPU 沒額外阻力（GPU 可平行算 thousands of passwords）。需要新 KDF 讓 attacker 的硬體優勢失效。

## Contribution
1. **Memory-hard function 概念**：design function whose computation requires large amount of memory; GPU/ASIC have parallel cores but limited memory bandwidth and size.
2. **scrypt 具體建構**：
   - Step 1: PBKDF2-HMAC-SHA256 expand (P, S) into B[]。
   - Step 2: ROMix(B): 用 large array V[] 做 sequential operations；V[i] depends on V[i-1]。
   - Step 3: PBKDF2 final到 desired output length。
3. **Sequential memory-hard 的精確定義**：computing function with M memory in T time has TA-product = M · T = Ω(N²)；對手減 M 必加倍 T，無 free lunch。
4. **參數 (N, r, p)**：
   - N: CPU/memory cost (must be power of 2)
   - r: block size factor
   - p: parallelization factor

## Method
**ROMix core**:
```text
ROMix(B, N):
    X = B
    For i = 0..N-1:
        V[i] = X
        X = BlockMix(X)
    For i = 0..N-1:
        j = Integerify(X) mod N
        X = BlockMix(X XOR V[j])
    return X

BlockMix(B): chain Salsa20/8 cores
```

**TA-cost analysis**：
- Honest: M = O(N), T = O(N), TA = O(N²)
- Adversary saving memory by recompute: M = O(N/k), T = O(kN), TA = O(N²)
- 證明 (sketch): adversary 必須重新計算 V[] 中 evicted entries; recompute cost lower-bounded by N²/M。

## Results
- **scrypt** 被 Litecoin (2011) 採用為 PoW，後 ASIC 終究勝過（雖然延遲 ASIC 出現幾年）。
- **影響 PHC competition**：所有 24 候選都聲稱 memory-hard；許多基於 scrypt 改進。
- **RFC 7914 (2016)** 標準化 scrypt。
- **Tarsnap** (Percival's company) 用 scrypt 為 backup encryption 的 KDF。

## Limitations / what they don't solve
- **TMTO not optimal**：Alwen-Serbinenko 2014 證明 scrypt 的 cumulative memory complexity (CMC) 沒達到 lower bound；Argon2id 改進。
- **Sequential ⇒ defender 也慢**：無法 trivially 平行 (p>1 是 weak 平行)。
- **參數調 tricky**：N 對 RAM、p 對 thread 都要調；不友善 deployment。
- **Side-channel weak**：data-dependent memory access (Integrify) 洩 password bits to cache-monitoring adversary。

## How it informs our protocol design
- **G6 不選 scrypt** as primary password KDF; 選 Argon2id (newer, better TMTO)。
- **scrypt 仍是 backup option** if 環境無 Argon2 library。
- **memory-hard 設計思想對 G6 PoW-style anti-DoS**：未來若 G6 加 client puzzle 防 DoS，可借鑑 memory-hard 思想讓 botnet 平行攻擊昂貴。

## Open questions
- scrypt 在 quantum adversary 下的 bound 仍少有研究。
- TMTO lower bound for memory-hard functions 仍 active（Alwen-Blocki 2016 等）。

## References worth following
- Percival *scrypt original paper* (this paper).
- RFC 7914 — scrypt IETF spec。
- Alwen, Serbinenko *High Parallel Complexity Graphs and Memory-Hard Functions* (STOC 2015) — TMTO 分析。
- Biryukov 等 *Argon2* (EuroS&P 2016) — scrypt 後繼者。
