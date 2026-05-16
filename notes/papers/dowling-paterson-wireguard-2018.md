# A Cryptographic Analysis of the WireGuard Protocol
**Venue / Year**: ACNS 2018 (LNCS 10892, Springer)（**校正**：搜尋結果指 ACNS 不是 EuroS&P；老引用混淆需修正）
**Authors**: Benjamin Dowling, Kenneth G. Paterson (Royal Holloway, U. London)
**Read on**: 2026-05-16 (in lesson 6.3)
**Status**: full PDF (`assets/papers/dowling-paterson-wireguard-2018.pdf`); 並有 IACR ePrint 2018/080 全版本
**One-line**: 對 WireGuard handshake 在 standard model + standard assumptions 下做 game-based computational proof —— 同時揭露一個 modular proof barrier（第一封 data packet 兼任 key confirmation 使 KE 與 record layer 不能 cleanly 分離證明）。

## Problem
Donenfeld 2017 NDSS 給的是 Tamarin 的 symbolic-level proof。學界要的是 computational proof（在 cryptographic assumptions 下做 reduction）。但 WireGuard 的 5-DH + 雙身分隱藏 + AEAD record 一體設計，需要 careful 模型化。

## Contribution
1. **形式化 security model**：extend Cremers-Feltz 2012 model，**支援 PSK option**，並把 KCI、forward secrecy、key indistinguishability 統一在單一 game。
2. **觀察 modular proof barrier**：WireGuard 的 KE 完成於收到 handshake response 之後，但 mutual authentication 在收到第一封 data packet（AEAD-authenticated）之後才完成。傳統 KE proof framework 假設 KE 與 record layer 可分離，但 WireGuard 這裡耦合。
3. **解法 #1 (本文採用)**：給 KE 加一個 explicit confirmation message，做出一個「**modified WireGuard**」並對其做 proof，論證 modification 對 protocol 行為的影響極小。
4. **量化攻擊面**：給出 concrete security bound——把 advantage 表達為 DDH advantage + AEAD security + collision resistance 的代數和。

## Method
Game-based reduction in standard model：
- **Game 1**：full WireGuard authentication & key indistinguishability。
- **Hybrid 1**: 把 random oracle 換成 random function。
- **Hybrid 2**: 把 DDH(eph_i, eph_r) 視為 random。
- **Hybrid 3**: 把 DDH(static_i, static_r) 視為 random。
- ...
- **Game N**：trivial。
每個 hop bound by AEAD / DDH / collision resistance。

## Results
- WireGuard handshake **(with the suggested confirmation tweak)** is provably secure in standard model under reasonable assumptions。
- 對 PSK option 的存在不破壞 main proof，PSK absent 與 present 都有對應 theorem。
- KCI resistance 嚴格成立。

## Limitations / what they don't solve
- 沒對 **as-deployed WireGuard**（沒有 confirmation tweak）做 full proof，只 informal argue 行為等價。
- 沒處理 **timing side channels** 或 implementation 層攻擊。
- 沒處理 PQ。

## How it informs our protocol design
1. **Proteus 必須 day-1 加 explicit key confirmation**——避免 Dowling-Paterson barrier。可以是一封極小（< 32 bytes）的 finished-like message，或像 TLS 1.3 用 Finished MAC。
2. **Proteus spec 必須附 game-based proof**（[Part 11.10] 設計階段直接寫）——不能只靠 Tamarin。
3. **5-DH 混合**對 KCI / FS 至關重要——Proteus 沿用但要加 PQ hybrid。

## Open questions
- 對 deployed WireGuard（無 explicit confirmation）的完整 proof 仍 open——可能需要新 framework。
- 把此分析延伸到 PQ-WireGuard 變體（Hülsing 2021）的 modular structure，是 active research。

## References worth following
- Cremers-Feltz 2012 *Beyond eCK*（KE security model framework）
- Lipp-Beurdouche-Blanchet-Bhargavan 2019 EuroS&P（mechanised proof，採取不同路徑）
- Hülsing et al. 2021 *Post-Quantum WireGuard*（PQ variant 分析）
