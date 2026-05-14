# Replay Attacks on Zero Round-Trip Time: The Case of the TLS 1.3 Handshake Candidates
**Venue / Year**: IEEE EuroS&P 2017
**Authors**: Marc Fischlin（TU Darmstadt）, Felix Günther（TU Darmstadt → ETH Zürich）
**Read on**: 2026-05-14 (in lesson 4.5)
**Status**: ePrint 2017/082 開放下載；PDF 已存 `assets/papers/eurosp-2017-fischlin-replay.pdf`
**One-line**: 0-RTT 在 TLS 1.3 draft 階段就被證明「沒辦法同時擁有 zero round trip + forward secrecy + replay resilience」——三者選二是密碼學定律，不是 implementation 細節。

## Problem
- 0-RTT 把 application data 跟 ClientHello 一起送出，**讓 client 不等 ServerHello 就傳 request**
- 攻擊者截獲 0-RTT data 並 replay → server 二次處理 → 可能對 idempotent 操作無害，對非 idempotent（POST /buy）災難
- Multi-Stage Key Exchange (MSKE) framework 對 1-RTT 已建立；0-RTT 需擴充模型才能談 secrecy

## Contribution
1. **形式化 MSKE-for-0-RTT 模型**：增加「early stage」key + replay capability
2. **分析 draft-12 DH-based 0-RTT** 與 **draft-14 PSK-based 0-RTT** 兩個 candidate
3. **證明 0-RTT data 在當時 spec 下**：
   - 不可能達到 forward secrecy on first flight（FS 與 0-RTT 結構性矛盾）
   - 不可能達到 replay resilience without server state (anti-replay cache 必要)
4. **記錄 IETF TLS WG 內 Daniel Kahn Gillmor 提出的 replay 場景**：「0-RTT request 可能是 `POST /buy-something`」這個現實 application 影響
5. **Inspire 後續工作**：Aviram-Gellert-Jager 用 puncturable PRF 達成 forward-secret 0-RTT（理論可行但 implementation 重）

## Method (just enough to reproduce mentally)
- 把 1-RTT MSKE adversary game 擴充：給 adversary 一個 `0RTT-Send(m)` oracle 多次 query 同一 session ticket
- 安全屬性拆成兩條：
  - $\text{Sec}^{\text{0-RTT}}$: 0-RTT 階段 key 對 passive adversary indistinguishable
  - $\text{ReplayRes}$: server 不會在沒 explicit anti-replay state 下接受同一 0-RTT 兩次
- 證明：draft-12 DH-based 對 $\text{Sec}^{\text{0-RTT}}$ 達標但對 $\text{ReplayRes}$ 失敗；draft-14 PSK-based 同樣
- 推導出「0-RTT data 的 forward secrecy 只能對 server 信任邊界內保證」

## Results
- 0-RTT data 的 forward secrecy 證偽（在當時 spec 下）
- 0-RTT data 對任意 idempotent application semantics **必然** vulnerable to replay
- 推動 RFC 8446 §8「Anti-Replay」 + §2.3「Zero-RTT Data」明確警語：「Servers MUST NOT use 0-RTT data for any application unless replay is acceptable」

## Limitations / what they don't solve
- 對 puncturable PRF / forward-secret 0-RTT 構造（Derler 2017, Aviram-Gellert-Jager 2019）未涵蓋
- 對 quantum-secure 0-RTT 未討論
- 對 ECH + 0-RTT 互動未討論（Cremers 2022 後續 follow-up）

## How it informs our protocol design
- **我們協議的 0-RTT 永遠 opt-in**，且 spec 明確限制 application semantics（GET / idempotent only）
- **Anti-replay cache 由 spec 強制**：採 Bloom-filter-based replay window，size 與 session ticket lifetime 嚴格綁定（RFC 8446 §8.1 同樣 path）
- **0-RTT key 是 session-specific**：server 收到後立刻 derive 進 1-RTT key schedule，不重用 derive 路徑
- **永遠 disclose 0-RTT 是否被接受**：透過 EncryptedExtensions 的 early_data extension 明確 signal
- **Optionally**：採用 Aviram-Gellert-Jager 2019 的 PPRF-based forward-secret 0-RTT（trade implementation complexity for stronger guarantee）

## Open questions
- Puncturable PRF / hierarchical ID-based encryption 構造的 0-RTT 是否能 production-ready？目前無大規模部署
- 0-RTT + post-quantum 是否有額外 game theoretical trade-off？
- 在 anti-censorship context，0-RTT 的 traffic pattern 是否獨特到變成 fingerprint？

## References worth following
- Derler, Jager, Slamanig, Striecks. *0-RTT Key Exchange with Full Forward Secrecy*. ePrint 2017/223
- Aviram, Gellert, Jager. *Session Resumption Protocols and Efficient Forward Security for TLS 1.3 0-RTT*. ePrint 2018/967 / J. Cryptology 2021
- Dowling, Fischlin, Günther, Stebila. *A Cryptographic Analysis of the TLS 1.3 Handshake Protocol*. J. Cryptology 2021

---

**用於課程**：Part 4.5（0-RTT 核心）、Part 5.7（MSKE formal model）、Part 11.7（我們協議的 0-RTT 設計取捨）
