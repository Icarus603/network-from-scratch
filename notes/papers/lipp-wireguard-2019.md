# A Mechanised Cryptographic Proof of the WireGuard VPN Protocol
**Venue / Year**: IEEE EuroS&P 2019
**Authors**: Benjamin Lipp (Inria Paris), Bruno Blanchet (Inria Paris), Karthikeyan Bhargavan (Inria Paris)
**Read on**: 2026-05-16 (referenced from lesson 5.7 + 6.3 + 11.10)
**Status**: full PDF (`assets/papers/lipp-wireguard-2019.pdf`, 54 pages from HAL)
**One-line**: 用 ProVerif + CryptoVerif 把 WireGuard handshake 整段做端到端機器驗證——首個對部署級 VPN handshake 的 mechanised symbolic + computational proof，奠定 G6 spec 必須附 mechanised proof 的研究先例。

## Problem
Donenfeld 2017 NDSS 給的是 Tamarin 的 symbolic-level proof；Dowling-Paterson 2018 給的是手算 game-based proof（且為 proof tractability 加了 explicit confirmation tweak）。Lipp et al. 想要：對 **as-deployed** WireGuard（不加 tweak）做機器可檢驗的 symbolic + computational proof。

## Contribution
1. **完整 ProVerif model**：把 WireGuard handshake 在 applied pi-calculus 完整 encode（含 5-DH、AEAD、MAC1/MAC2、optional PSK）。
2. **CryptoVerif companion**：computational-level game-hopping proof，每步 reduce 到 cryptographic assumption（DDH on Curve25519、IND-CCA of ChaCha20-Poly1305、collision resistance of BLAKE2s）。
3. **新 proof technique**：解決 Dowling-Paterson barrier——利用 CryptoVerif 自動 game-hopping，對 KE + record layer 一體 reduce。
4. **驗證的安全性質**：
   - Secrecy of session keys
   - Mutual authentication for all handshake messages（含第一封 data packet）
   - Forward secrecy
   - KCI (Key Compromise Impersonation) resistance
   - Initiator identity hiding
   - PSK 變體下強化 confidentiality（防 PQ-era passive decryption）
5. **Implementation-level link**：透過 F* / KaRaMeL 工具鏈雛形——可投射成 C 實作的 functional correctness proof（雖然完整 verified impl 不在主文中）。
6. **發現 PSK absence 的 subtle corner case**：若 PSK 為全零（default 無 PSK），forward secrecy 條件略有不同（仍成立，但 proof 要分 case）。
7. **Source code（.pv + .cv 檔）公開**：給後續 protocol 設計者 reuse。

## Method
- 把 WireGuard spec 手翻為 ProVerif 的 applied pi-calculus syntax（~1000 行）。
- 對應 CryptoVerif input 寫 computational model。
- 由 ProVerif 自動 prove symbolic queries；由 CryptoVerif 自動跑 game-hop sequence，每步綁 cryptographic assumption。
- 最終 reduce 到 trivial game。
- proof 自動生成 ~50 GB intermediate state、跑時數小時。
- 與 Donenfeld 合作，過程中發現幾處 minor spec ambiguity 並修訂。

## Results
- WireGuard handshake 在標準假設下 mechanically verified（**對 as-deployed WireGuard**，不依賴 Dowling-Paterson 的 confirmation tweak）：
  - mutual authentication
  - forward secrecy
  - resistance to PSK key compromise
  - resistance to KCI
  - secrecy of session keys
- 確認 Noise IK 是 reasonable "off-the-shelf" handshake。
- 為後續 PQ-WireGuard 變體（Hülsing 2021）的分析提供 baseline framework。

## Limitations / what they don't solve
- **不對 implementation 本身做 proof**——只對 spec。implementation bug（如 timing leak、memory zeroization 失敗）超出範圍。
- 不涵蓋 cookie / MAC2 重啟攻擊面。
- 不涵蓋 PQ。
- Symbolic ProVerif 假設 perfect crypto；computational CryptoVerif 假設 standard reductions。

## How it informs our protocol design
1. **G6 spec 必須一開始就寫 ProVerif + CryptoVerif input**——不是事後補。Lipp 證明這對 NDSS 級 VPN protocol 完全可行。
2. **PSK 為零的 corner case** 提醒：G6 設計 PQ hybrid 時，"hybrid-default-off" 配置不能變成 silent downgrade。
3. **Mechanised proof 對 spec 的反饋**：寫 ProVerif / CryptoVerif 時會逼著你想清楚每個 message 的 invariants——是極好的 spec quality 工具。
4. **G6 ProVerif model（[11.10](../../lessons/part-11-design/11.10-proverif-tamarin.md) `G6Handshake.pv`）** 的結構直接 inspired by this work。
5. **Cross-tool composition（ProVerif + CryptoVerif）** 設定了 G6 future v0.2 同時做 symbolic + computational 驗證的先例。
6. 啟發 G6 spec 對 Noise IK 候選的最終評估（Part 11.6 在 Noise IK 與 TLS 1.3-borrowed 之間取捨時引用此 paper 的 confidence）。

## Open questions
- 把 CryptoVerif proof 推到 F*-verified implementation 的完整工具鏈，仍是 active 工程問題。
- PQ-WireGuard 變體（Hülsing 2021）的 CryptoVerif mechanised proof，尚未完成。
- 對含 cookie/MAC2 的 full state machine 的 mechanised proof，尚未完成。
- CryptoVerif library for hybrid PQ KEM？尚未成熟。
- Compositional reasoning across ProVerif + Tamarin？目前 manual。

## References worth following
- Blanchet 2008 IEEE S&P *CryptoVerif*（工具本身）
- Blanchet CSFW 2001（ProVerif foundation）
- Donenfeld NDSS 2017（WireGuard original spec）
- Donenfeld-Milner 2018 technical report（formal verification informal predecessor）
- Dowling-Paterson 2018 ACNS（同 protocol 的 game-based 對應）
- Donenfeld 2018 *Formal Verification of WireGuard* (Tamarin)（symbolic 對應）
- Kobeissi-Bhargavan EuroS&P 2017 / 2019（Noise Explorer 系列）
- Bhargavan et al. *miTLS / Project Everest*（F\* verified TLS）
- Hülsing-Ning-Schwabe-Weber 2021 *Post-quantum WireGuard*（PQ variant）
