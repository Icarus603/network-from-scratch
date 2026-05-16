# How the Great Firewall of China Detects and Blocks Fully Encrypted Traffic
**Venue / Year**: USENIX Security 2023 (Best Practical Paper at FOCI '23, CSAW first place)
**Authors**: Mingshi Wu, Jackson Sippe, Danesh Sivakumar, Jack Burg, Peter Anderson, Xiaokang Wang, Kevin Bock, Amir Houmansadr, Dave Levin, Eric Wustrow
**Read on**: 2026-05-16 (in lesson 6.7)
**Status**: full PDF (`assets/papers/wu-fully-encrypted-2023.pdf`)
**One-line**: 揭露 GFW 自 2021 起部署的 entropy-based passive detection——對「看起來像 random bytes」的 fully encrypted traffic 用簡單啟發式即可批量識別並 block，影響 Shadowsocks / VMess / Obfs4 / WireGuard 一票協議；催生整個 anti-censorship 圈對 first-byte 與 first-bytes 統計屬性的重新設計浪潮。

## Problem
2021 年 11 月起，中國境內大量 fully-encrypted protocols（SS/VMess/Obfs4）開始 broken。社群一度認為是 active probing 升級，但作者證明：GFW 部署了一個**全 passive** 的 entropy-based filter，對所有 TCP/UDP 流量做即時統計，能識別「看起來像隨機」的流。

## Contribution
1. **GFW 偵測規則 reverse engineer**：透過從中國境內向自家受控 server 發精心構造的 payload，觀察哪些被 block，反推 GFW 的 detection rule。發現核心 rule（簡化版）：
   - **Rule 1**：前 6 bytes 中至少 5 bytes 必須是 ASCII printable（即 entropy 不夠高）
   - **Rule 2**：前 byte popcount（1-bit 數量）落在 3.4~4.6 範圍會被視為「隨機」
   - **Rule 3**：明文跳脫常見 protocol header（HTTP/TLS/SSH 等）的 will be flagged
2. **詳細的 fuzz framework**：對若干 byte position 與 distribution 系統地測試 GFW 反應。
3. **實證 affected protocols**：
   - Shadowsocks（streamcipher 與 AEAD-256-GCM 兩個版本）
   - VMess (V2Ray)
   - Obfs4 (Tor pluggable transport)
   - WireGuard（部分 fingerprint）
   - 任何 fully-encrypted 流
4. **直接觸發 anti-censorship 圈大規模 spec patch**：作者直接 commit 補丁到 Shadowsocks / Outline / V2Ray / Conjure / Psiphon 主流 fork。
5. **量化評估**：在校園網路鏡像流量上 simulate inferred rule，**false positive rate 與 GFW 觀察一致**——強證據作者 reverse engineer 對。

## Method
- **黑盒探測**：從中國境內 host 向控制下的境外 server 發 payload。
- **bit-flipping experiment**：對每個 byte position 翻轉，觀察是否觸發 block。
- **N-gram statistics**：統計 first-N bytes 的 popcount / ASCII ratio。
- **inference**：把觀察組合成 decision tree，模擬 GFW 行為。
- **驗證**：在 ISP-mirror 流量上 run inferred rule，confusion matrix 對比實際 GFW 行為。

## Results
- GFW 的 detection 是**極簡單**的 entropy 啟發式——不是 ML，不是 deep DPI。
- 但**對 fully-encrypted protocol family 殺傷力極大**——把所有「看起來像 random」的 UDP/TCP payload 都掃了。
- 作者推動的補丁（modifies first bytes to look like HTTP/TLS/SSH headers）已在主流翻牆協議落地。

## Limitations / what they don't solve
- 不確定 GFW 是否還有 ML-based / behaviour-based 偵測作為 backup（高機率有，但本研究只觸發 passive heuristic）。
- 不破任何密碼學——只破 protocol identifiability。
- 對 protocol-borrowing（REALITY / Conjure / domain fronting）不直接適用——但這些自己另有 fingerprint surface。

## How it informs our protocol design
**Proteus 必須滿足的 first-bytes hard constraint**（直接來自此論文）：
1. **第一 byte 不能是常見 protocol header**（避開 HTTP/TLS/SSH 簽名）——這是廢的，Proteus 要更強。
2. **第一 6 bytes 必須通過 ASCII printable 5/6 比例的 OR 反轉**：要嘛全 printable 看起來像 HTTP，要嘛 entropy 完全 random 但配合 ranged padding 偽裝成其他協議的 first bytes（更難達成）。
3. **popcount distribution must avoid 3.4~4.6 cluster**（如果走 fully-encrypted 路線）。
4. **更好做法**：Proteus day-1 走 **protocol-borrowing**——把握手包進 real TLS / QUIC / HTTP envelope（[Part 7.10 REALITY](../../lessons/part-7-proxy-protocols/)），完全跳過 fully-encrypted heuristic。

## Open questions
- GFW 未來的偵測升級會走 ML 還是仍堅持 heuristic？目前無公開證據。
- 此 entropy rule 與 traffic-analysis rule 的組合，能否打 protocol-borrowing 協議？
- post-quantum 階段（KEM 公鑰大 → 第一封 packet 必為大且高 entropy），是否會觸發新的 GFW 反應？這是 [Part 3.11 PQC](../../lessons/part-3-cryptography/3.11-post-quantum.md) 的未解問題。

## References worth following
- Xue 2022 USENIX Sec OpenVPN（precursor）
- Frolov-Wustrow 2019 NDSS *Use of TLS in Censorship Circumvention*
- Ensafi-Crandall-Winter 2015 IMC（GFW active probing 起源）
- Conjure (Frolov 2019 USENIX Sec)
- Shadowsocks 補丁 commit history：https://github.com/shadowsocks/shadowsocks-rust/pulls?q=fully-encrypted
