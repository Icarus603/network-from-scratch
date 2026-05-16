# BLAKE2: simpler, smaller, fast as MD5
**Venue / Year**: ACNS 2013（spec evolved through 2013-2018）
**Authors**: Jean-Philippe Aumasson, Samuel Neves, Zooko Wilcox-O'Hearn, Christian Winnerlein
**Read on**: 2026-05-14 (in lesson 3.3)
**Status**: full PDF (`assets/papers/blake2-2013.pdf`)
**One-line**: 把 BLAKE (SHA-3 final round candidate) 簡化為 BLAKE2，提供 BLAKE2b/2s 兩個變體；速度比 SHA-3 快 4×、比 SHA-256 快 30%；WireGuard、Argon2、libsodium 全採用，是現代 ARX hash 的事實標準（直到 BLAKE3）。

## Problem
SHA-3 競賽 2012 結束，Keccak 勝出但軟體效能拖後腿（~12 cycles/byte）。BLAKE 是 SHA-3 final round 五位之一，落選但軟體最快（~7 c/b）。Aumasson 等決定不靠 NIST 重新優化 BLAKE → BLAKE2，目標：**比 MD5 快**（即 ~3-5 c/b 純軟體）+ feature-rich（內建 keyed mode、salt、tree mode）。

## Contribution
1. **減少 round 數**：BLAKE 16 round → BLAKE2 12 round (BLAKE2b) / 10 round (BLAKE2s)。安全 margin 仍 ample（最佳已知 attack 對 BLAKE2 是 round-reduced ≤ 7）。
2. **簡化 message schedule**：去除 BLAKE 的部分 padding 開銷。
3. **內建 keyed hashing**：BLAKE2(K, m) 直接是 MAC，不需 HMAC 包裝（性能 gain 1.5-2×）。
4. **內建 salt + personalization**：可定義 application-specific separation 不靠 KDF。
5. **內建 tree hashing**：可平行 hash 大檔案。
6. **兩個變體**：
   - **BLAKE2b**: 64-bit word, output ≤ 512 bit, optimized for 64-bit CPUs。
   - **BLAKE2s**: 32-bit word, output ≤ 256 bit, optimized for 32-bit / embedded。
7. **效能**：BLAKE2b ~3 cycles/byte (Skylake)、BLAKE2s ~5 c/b。

## Method
**Compression function (BLAKE2b 簡化版)**：
```text
state v[16] (each 64-bit) initialized:
    v[0..7] = h[0..7]                  // chaining
    v[8..15] = IV[0..7] XOR (counter, finalization flags)

For round r = 1..12:
    G(v, 0, 4,  8, 12, m[s[r][0]], m[s[r][1]])    // column G
    G(v, 1, 5,  9, 13, m[s[r][2]], m[s[r][3]])
    G(v, 2, 6, 10, 14, m[s[r][4]], m[s[r][5]])
    G(v, 3, 7, 11, 15, m[s[r][6]], m[s[r][7]])
    G(v, 0, 5, 10, 15, m[s[r][8]], m[s[r][9]])    // diagonal G
    G(v, 1, 6, 11, 12, m[s[r][10]], m[s[r][11]])
    G(v, 2, 7,  8, 13, m[s[r][12]], m[s[r][13]])
    G(v, 3, 4,  9, 14, m[s[r][14]], m[s[r][15]])

Final:
    h[i] = h[i] XOR v[i] XOR v[i+8]   for i = 0..7

G(v, a, b, c, d, x, y):
    v[a] += v[b] + x
    v[d] = ROT_R(v[d] XOR v[a], 32)
    v[c] += v[d]
    v[b] = ROT_R(v[b] XOR v[c], 24)
    v[a] += v[b] + y
    v[d] = ROT_R(v[d] XOR v[a], 16)
    v[c] += v[d]
    v[b] = ROT_R(v[b] XOR v[c], 63)
```

**G function 直接從 ChaCha20 quarter-round 借鑑**——同 ARX 範式。

## Results
- **WireGuard** (Donenfeld 2017) 用 BLAKE2s 為 hash + MAC base（noise-helpers.go）。
- **Argon2** (PHC 2015 winner) 用 BLAKE2b 為內部 hash。
- **libsodium** 標配 BLAKE2b。
- **Zcash** zk-SNARK 系統用 BLAKE2 變體。
- **IETF RFC 7693** 標準化 BLAKE2。

## Limitations / what they don't solve
- 仍是 Merkle-Damgård 結構（理論上 length-extension vulnerable，但 spec 用 finalization flag 防止）。
- 沒有 XOF mode（BLAKE3 補上）。
- 樹 mode 規範但實作少（BLAKE3 productionize）。
- 軟體還可更快——BLAKE3 達 ~0.5 c/b。

## How it informs our protocol design
- **Proteus secondary hash 候選**：BLAKE2s 用作 noise-style mixhash（若採用 Noise framework）。
- **Proteus keyed-MAC 可用 BLAKE2-MAC** 替代 HMAC-SHA256，節省一層 HMAC 開銷；但為了 TLS 1.3 互通仍偏 HMAC-SHA256。
- **Proteus password hashing 內部**：Argon2id 用 BLAKE2b，間接受益。

## Open questions
- BLAKE2 的 quantum cryptanalysis bound 與 SHA-2 / SHA-3 比較？
- Keyed BLAKE2 vs HMAC-SHA256 在 multi-user / multi-key setting 的 tight bound？

## References worth following
- Aumasson, Henzen, Meier, Phan *SHA-3 proposal BLAKE* (2008) — BLAKE 原 spec。
- RFC 7693 — BLAKE2 IETF 標準。
- O'Connor 等 *BLAKE3 paper* (2020) — BLAKE2 後繼者。
- Aumasson *Serious Cryptography* (NSP 2018) — modern hash 章節。
