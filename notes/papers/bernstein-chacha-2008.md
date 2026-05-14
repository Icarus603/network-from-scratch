# ChaCha, a variant of Salsa20
**Venue / Year**: SASC (State of the Art of Stream Ciphers) Workshop 2008
**Authors**: Daniel J. Bernstein
**Read on**: 2026-05-14 (in lesson 3.2)
**Status**: full PDF (`assets/papers/bernstein-chacha-2008.pdf`)
**One-line**: ChaCha 是 Salsa20 (eSTREAM portfolio) 的小幅修改，把 quarter-round 重排以加快 diffusion；以同樣 round 數提供更強 cryptanalytic margin，且軟體效能略快——成為 RFC 8439、TLS 1.3、WireGuard、Signal 的對稱加密核心。

## Problem
Salsa20 (Bernstein 2005) 是 eSTREAM portfolio finalist，用 ARX (add-rotate-xor) 設計，無 S-box，constant-time。但 cryptanalysis 顯示 Salsa20 的 quarter-round 在 differential attack 下 diffusion 不夠快（截至 2007 年最強 attack 對 8 round Salsa20 是 2^151）。Bernstein 想在保持 ARX 純度的前提下提升 round 內 diffusion。

## Contribution
1. **修改 quarter-round**：Salsa20 的 QR 是 `b ⊕= ROT(a+d, 7); c ⊕= ROT(b+a, 9); ...`。ChaCha 改為 `a += b; d ^= a; d <<<= 16; c += d; b ^= c; b <<<= 12; ...`——每個 word 在 QR 內被更新 2 次而非 1 次，diffusion 加倍。
2. **重排 state matrix**：constants/key/counter/nonce 在 4×4 grid 的位置略改，讓 column round 與 diagonal round 的 word 集合不重複。
3. **同樣 20 round 達更強 margin**：對 ChaCha 已知最強 attack 達到 7 round（複雜度 ~2^248）；對 Salsa20 達 8 round。ChaCha 的 13-round margin (vs Salsa 12-round) 在 paper 後續 cryptanalysis (Aumasson-Fischer-Khazaei-Meier-Rechberger 2008) 確認。
4. **效能略勝**：在 Pentium 4、Athlon、Core 2 上 ChaCha20 比 Salsa20/20 快 5-15%；ARM 上更明顯。

## Method (just enough to reproduce mentally)
**State**：4×4 of 32-bit words = 16 words = 512 bits。

```text
+------+------+------+------+
| C0   | C1   | C2   | C3   |
+------+------+------+------+
| K0   | K1   | K2   | K3   |
+------+------+------+------+
| K4   | K5   | K6   | K7   |
+------+------+------+------+
| Ctr  | N0   | N1   | N2   |
+------+------+------+------+
```

C0..C3 = ASCII "expa" "nd 3" "2-by" "te k"。

**Quarter-round (QR)**：
```text
QR(a, b, c, d):
    a += b;  d ^= a;  d <<<= 16;
    c += d;  b ^= c;  b <<<= 12;
    a += b;  d ^= a;  d <<<= 8;
    c += d;  b ^= c;  b <<<= 7;
```

**Round (column / diagonal 交替)**：
- 偶數 round (column): QR on (s[0],s[4],s[8],s[12]); QR on (s[1],s[5],s[9],s[13]); ... × 4 columns
- 奇數 round (diagonal): QR on (s[0],s[5],s[10],s[15]); QR on (s[1],s[6],s[11],s[12]); ...

20 round = 10 column + 10 diagonal 交替。最後 working state += original state，serialize 為 64-byte keystream block。

加密 = plaintext XOR keystream（CTR mode in spirit）；counter 自增到下一 block。

## Results
- **eSTREAM 之外**取得更廣泛採用：Adam Langley 2013 把 ChaCha20-Poly1305 加進 OpenSSL；Google 在 Chrome+Android 部署用作 TLS 1.2 cipher。
- **RFC 7539 (2015) → RFC 8439 (2018)**：IETF 標準化 ChaCha20-Poly1305 AEAD，96-bit nonce 版本。
- **TLS 1.3 (RFC 8446)** 將 `TLS_CHACHA20_POLY1305_SHA256` 列為 mandatory cipher suite。
- **WireGuard、Signal、libsodium、Tor、SSH (`chacha20-poly1305@openssh.com`)** 全部採用。

## Limitations / what they don't solve
- 仍是 stream cipher，**nonce 必須唯一**；重用 catastrophic（兩 ciphertext XOR = 兩 plaintext XOR）。
- 256-bit key 對抗量子 Grover 只有 128-bit security。
- 無原生 misuse-resistance；要 MRAE 需用 XChaCha20（24-byte nonce）+ deterministic IV 或改用 SIV-style construction。
- counter 32-bit 在 IETF 版意味著單 (key, nonce) 對最多 2^32 × 64 byte = 256 GB——大但 finite。

## How it informs our protocol design
- **G6 default AEAD = ChaCha20-Poly1305**。理由：
  - 軟體實作 universal fast（無 AES-NI 也快）。
  - 天然 constant-time（無 cache-timing risk，避免 Bernstein 2005 cache-timing attack）。
  - CFRG-blessed (RFC 8439)。
- **G6 nonce 結構**：採用 12-byte 的 IETF 變體（`epoch ‖ direction ‖ counter`）。

## Open questions
- 是否存在 round-reduced ChaCha 的 attack 改善？目前 7-round 是 best；若降到 8/9-round 仍安全 margin 充足，但能否 cleanly 擴 differential framework？
- ChaCha 的 differential-linear attack（Beierle-Leander-Todo 2020 等）對 full-round 是否真的 negligible？

## References worth following
- Bernstein *Salsa20 Specification* (2005) — 原版。
- Aumasson-Fischer-Khazaei-Meier-Rechberger *New Features of Latin Dances: Analysis of Salsa, ChaCha, and Rumba* (FSE 2008) — best ChaCha cryptanalysis to date。
- RFC 8439 — IETF AEAD spec。
- Krovetz-Rogaway *The Software Performance of AE Modes* (FSE 2011) — 各 AEAD 效能比較。
- Bernstein *XSalsa20* (2008) → XChaCha20 — 24-byte nonce 變體，避碰撞。
